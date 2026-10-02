use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::AppError;

pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Correlates every log line belonging to one request. Also echoed back as the
/// `x-request-id` response header, which is how a caller ties a 4xx body to
/// the server-side logs.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Adopts an inbound `x-request-id` when a proxy set one, otherwise mints a
/// new one, and makes it available to downstream middleware.
pub async fn attach(mut request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    request.extensions_mut().insert(RequestId(id.clone()));

    let mut response = next.run(request).await;
    if let Ok(value) = id.parse() {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

#[derive(Debug, Clone, Copy)]
struct Window {
    used: u32,
    resets_at: Instant,
}

/// A fixed-window rate limiter keyed by client IP.
///
/// A fixed window is a deliberate simplification: it lets a caller spend the
/// whole allowance at the end of one window and again at the start of the next.
/// That is acceptable for throttling credential stuffing and is far cheaper
/// than a sliding window, which this does not need to be.
#[derive(Debug)]
pub struct RateLimiter {
    windows: Mutex<HashMap<IpAddr, Window>>,
    limit: u32,
    window: Duration,
}

/// Above this many tracked keys, expired windows are swept on the next request.
const SWEEP_THRESHOLD: usize = 10_000;

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            limit,
            window,
        }
    }

    /// Records a hit for `key`, returning whether it was allowed.
    pub async fn check(&self, key: IpAddr) -> bool {
        let now = Instant::now();
        let mut windows = self.windows.lock().await;

        if windows.len() > SWEEP_THRESHOLD {
            windows.retain(|_, w| w.resets_at > now);
        }

        match windows.get_mut(&key) {
            Some(window) if window.resets_at > now => {
                if window.used >= self.limit {
                    return false;
                }
                window.used += 1;
                true
            }
            _ => {
                windows.insert(
                    key,
                    Window {
                        used: 1,
                        resets_at: now + self.window,
                    },
                );
                true
            }
        }
    }
}

const UNKNOWN_CLIENT: &str = "0.0.0.0";

/// Rejects callers that have exhausted their allowance, in the same error
/// envelope as every other failure.
pub async fn rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or_else(|| UNKNOWN_CLIENT.parse().expect("valid literal"));

    if limiter.check(peer).await {
        return next.run(request).await;
    }

    AppError::RateLimited.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[tokio::test]
    async fn requests_within_the_allowance_pass() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(limiter.check(ip(1)).await);
        }
    }

    #[tokio::test]
    async fn the_request_after_the_allowance_is_rejected() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check(ip(1)).await);
        assert!(limiter.check(ip(1)).await);
        assert!(!limiter.check(ip(1)).await);
        assert!(!limiter.check(ip(1)).await);
    }

    #[tokio::test]
    async fn clients_are_limited_independently() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check(ip(1)).await);
        assert!(!limiter.check(ip(1)).await);
        // A different client is unaffected.
        assert!(limiter.check(ip(2)).await);
    }

    #[tokio::test]
    async fn the_allowance_recovers_after_the_window() {
        let limiter = RateLimiter::new(1, Duration::from_millis(30));
        assert!(limiter.check(ip(1)).await);
        assert!(!limiter.check(ip(1)).await);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(limiter.check(ip(1)).await, "allowance should reset");
    }
}
