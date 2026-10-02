use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use super::handlers;
use super::middleware::{self, RateLimiter};
use crate::error::AppError;
use crate::state::AppState;

/// Upper bound on a request body. Auth payloads are small, so this is generous.
const MAX_BODY_BYTES: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Failed login and registration attempts allowed per client per minute.
const AUTH_ATTEMPTS_PER_MINUTE: u32 = 10;

pub fn router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(handlers::register))
        .route("/login", post(handlers::login))
        .route("/refresh", post(handlers::refresh))
        .route("/logout", post(handlers::logout))
        .route("/me", get(handlers::me))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::new(RateLimiter::new(
                AUTH_ATTEMPTS_PER_MINUTE,
                Duration::from_secs(60),
            )),
            middleware::rate_limit,
        ));

    let mut app = Router::new()
        .route("/health", get(handlers::health))
        .route("/health/ready", get(handlers::ready))
        .nest("/api/v1/auth", auth_routes)
        .fallback(not_found)
        .layer(axum::middleware::from_fn(middleware::attach))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    if !state.config.cors_allowed_origins.is_empty() {
        app = app.layer(cors_layer(&state));
    }

    app.with_state(state)
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let mut origins = Vec::with_capacity(state.config.cors_allowed_origins.len());
    for origin in &state.config.cors_allowed_origins {
        match HeaderValue::from_str(origin) {
            Ok(value) => origins.push(value),
            Err(_) => tracing::warn!(origin, "ignoring malformed CORS origin"),
        }
    }

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(600))
}

async fn not_found(_request: Request) -> Response {
    AppError::not_found("no route matches this path").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;

    #[test]
    fn a_parser_built_config_without_origins_produces_no_cors_layer() {
        let pairs = [("DATABASE_URL", "postgres://u:p@localhost:5432/auth")];
        let get = |key: &str| pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| (*v).to_owned());
        let cfg = crate::config::Config::from_source(&get).unwrap();
        assert!(cfg.cors_allowed_origins.is_empty());
    }

    #[test]
    fn the_body_limit_is_small_enough_to_reject_absurd_payloads() {
        assert!(MAX_BODY_BYTES <= 64 * 1024);
    }

    #[test]
    fn a_request_id_round_trips_through_a_header_value() {
        let id = uuid::Uuid::new_v4().to_string();
        let value = id.parse::<HeaderValue>().unwrap();
        assert_eq!(value.to_str().unwrap(), id);
    }

    #[test]
    fn the_error_envelope_is_json_with_the_right_status() {
        let err = AppError::not_found("nope");
        let response = (err.status_code(), Json(err.envelope())).into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
