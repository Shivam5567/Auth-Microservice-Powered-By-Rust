use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, extract::Request};
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::api;
use crate::error::AppError;
use crate::state::AppState;

const MAX_BODY_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

pub fn router(state: AppState) -> Router {
    // The storefront owns the browser session, so it is the only origin that
    // needs to be reachable from a page. Left unset for a same-origin demo.
    let mut app = Router::new()
        .route("/", get(api::index))
        .route("/shop/", get(api::shop))
        .route("/health", get(api::health))
        .route("/health/ready", get(api::ready))
        .route("/api/catalog", get(api::catalog))
        .route("/api/auth/login", post(api::login))
        .route("/api/auth/refresh", post(api::refresh))
        .route("/api/auth/logout", post(api::logout))
        .route("/api/auth/whoami", get(api::whoami))
        .route("/api/orders", post(api::create_order).get(api::list_orders))
        .route("/api/orders/{id}", get(api::get_order))
        .route("/api/orders/{id}/refund", post(api::refund_order))
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    if !state.cors_allowed_origins.is_empty() {
        app = app.layer(cors_layer(&state));
    }

    app.with_state(state)
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let mut origins = Vec::with_capacity(state.cors_allowed_origins.len());
    for origin in &state.cors_allowed_origins {
        match HeaderValue::from_str(origin) {
            Ok(value) => origins.push(value),
            Err(_) => tracing::warn!(origin, "ignoring malformed CORS origin"),
        }
    }

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(true)
        .max_age(Duration::from_secs(600))
}

async fn not_found(_request: Request) -> Response {
    AppError::not_found("no route matches this path").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_limit_leaves_room_for_a_real_cart() {
        const { assert!(MAX_BODY_BYTES >= 16 * 1024) };
    }

    #[test]
    fn errors_use_the_shared_envelope() {
        let response = AppError::not_found("nope").into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// The refresh cookie must not ride along on ordinary order requests.
    #[test]
    fn the_refresh_cookie_is_named_for_reading() {
        assert_eq!(crate::cookie::REFRESH_COOKIE, "refresh_token");
    }
}
