use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, http::header::USER_AGENT};

use super::dto::{self, AuthResponse, HealthResponse, UserResponse};
use super::extract::AuthUser;
use crate::error::AppResult;
use crate::service::{self, SessionContext};
use crate::state::AppState;

/// Longest user agent recorded against a session.
const MAX_USER_AGENT_LEN: usize = 512;

fn session_context(headers: &HeaderMap, peer: Option<SocketAddr>) -> SessionContext {
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|agent| agent.chars().take(MAX_USER_AGENT_LEN).collect());

    SessionContext::new(user_agent, peer.map(|addr| addr.ip()))
}

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(payload): Json<dto::RegisterRequest>,
) -> AppResult<impl IntoResponse> {
    super::extract::validate(&payload)?;

    let profile = service::register(&state, &payload.email, &payload.password).await?;

    tracing::info!(user_id = %profile.id, peer = %peer.ip(), "account registered");
    Ok((StatusCode::CREATED, Json(UserResponse::from(profile))).into_response())
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<dto::LoginRequest>,
) -> AppResult<impl IntoResponse> {
    super::extract::validate(&payload)?;

    let ctx = session_context(&headers, Some(peer));
    let pair = service::login(&state, &payload.email, &payload.password, ctx).await?;

    tracing::info!(user_id = %pair.user.id, peer = %peer.ip(), "user signed in");
    Ok(Json(AuthResponse::from(pair)).into_response())
}

pub async fn refresh(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<dto::RefreshRequest>,
) -> AppResult<impl IntoResponse> {
    super::extract::validate(&payload)?;

    let ctx = session_context(&headers, Some(peer));
    let pair = service::refresh(&state, &payload.refresh_token, ctx).await?;

    Ok(Json(AuthResponse::from(pair)).into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<dto::LogoutRequest>,
) -> AppResult<StatusCode> {
    service::logout(&state, &payload.refresh_token, payload.all_devices).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn me(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<UserResponse>> {
    Ok(Json(UserResponse::from(service::me(&state, user.id).await?)))
}

/// Liveness: answers as long as the process is running.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "auth-service",
        database: None,
        checked_at: None,
    })
}

/// Readiness: confirms the database answers, so an orchestrator does not route
/// traffic to a process that cannot serve a login.
pub async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, Response> {
    match crate::db::ping(&state.pool).await {
        Ok(checked_at) => Ok(Json(HealthResponse {
            status: "ok",
            service: "auth-service",
            database: Some("connected"),
            checked_at: Some(checked_at),
        })),
        Err(err) => {
            tracing::error!(error = %err, "readiness probe failed");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "unavailable",
                    service: "auth-service",
                    database: Some("unreachable"),
                    checked_at: None,
                }),
            )
                .into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[tokio::test]
    async fn health_reports_ok_without_touching_the_database() {
        let Json(body) = health().await;
        assert_eq!(body.status, "ok");
        assert!(body.database.is_none());
    }

    #[test]
    fn a_very_long_user_agent_is_truncated() {
        let mut headers = HeaderMap::new();
        let long = "x".repeat(5000);
        headers.insert(USER_AGENT, HeaderValue::from_str(&long).unwrap());
        let ctx = session_context(&headers, None);
        assert_eq!(ctx.user_agent.as_ref().unwrap().len(), MAX_USER_AGENT_LEN);
    }

    #[test]
    fn a_missing_user_agent_becomes_none() {
        let ctx = session_context(&HeaderMap::new(), None);
        assert!(ctx.user_agent.is_none());
    }
}
