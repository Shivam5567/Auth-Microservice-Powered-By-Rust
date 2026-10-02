use std::borrow::Cow;

use axum::http::StatusCode;
use serde::Serialize;

/// A service-agnostic error type that renders as a stable JSON envelope.
///
/// The contract is that the `message` surfaced to clients is safe to show a
/// user. Anything operationally sensitive goes to the tracing log instead,
/// correlated by `request_id`.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    Validation(String),

    #[error("{0}")]
    Unauthorized(String),

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("too many requests")]
    RateLimited,

    #[error("{0}")]
    Internal(String),
}

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Stable, machine-readable discriminator for clients.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Validation(_) => "validation_failed",
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::RateLimited => "rate_limited",
            Self::Internal(_) => "internal_error",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The message safe to return to an untrusted caller.
    ///
    /// Internal errors are replaced wholesale so that database, filesystem or
    /// host detail never leaks; the full text is still available via
    /// [`std::fmt::Display`] for the logs.
    fn public_message(&self) -> Cow<'_, str> {
        match self {
            Self::Internal(_) => Cow::Borrowed("an internal error occurred"),
            Self::RateLimited => Cow::Borrowed("too many requests"),
            other => Cow::Owned(other.to_string()),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
}

impl AppError {
    pub fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            error: ErrorBody {
                code: self.code(),
                message: self.public_message().into_owned(),
                request_id: None,
                details: None,
            },
        }
    }
}

/// Renders the error as the shared JSON envelope with the matching status.
///
/// Implemented here rather than in each service so that `AppError: IntoResponse`
/// holds everywhere, which is what lets handlers return `AppResult<T>` and lets
/// custom extractors use `AppError` as their rejection type.
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        if status.is_server_error() {
            tracing::error!(error = %self, "request failed");
        } else {
            tracing::debug!(error = %self, code = self.code(), "request rejected");
        }

        (status, axum::Json(self.envelope())).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_detail() {
        let err = AppError::internal("connection to 10.0.0.5:5432 refused");
        assert_eq!(err.status_code(), 500);
        assert_eq!(
            err.envelope().error.message,
            "an internal error occurred",
            "client-visible message must be generic"
        );
        // The full detail is still available for the logs.
        assert!(err.to_string().contains("10.0.0.5"));
    }

    #[test]
    fn client_errors_keep_their_message() {
        let err = AppError::unauthorized("invalid credentials");
        assert_eq!(err.status_code(), 401);
        assert_eq!(err.envelope().error.message, "invalid credentials");
    }

    #[test]
    fn status_codes_map_to_the_expected_family() {
        assert_eq!(AppError::validation("bad").status_code(), 400);
        assert_eq!(AppError::forbidden("nope").status_code(), 403);
        assert_eq!(AppError::not_found("nope").status_code(), 404);
        assert_eq!(AppError::conflict("nope").status_code(), 409);
        assert_eq!(AppError::RateLimited.status_code(), 429);
    }

    #[test]
    fn envelope_serializes_a_stable_shape() {
        let json = serde_json::to_value(AppError::conflict("email taken").envelope()).unwrap();
        assert_eq!(json["error"]["code"], "conflict");
        assert_eq!(json["error"]["message"], "email taken");
        // Absent optional fields are omitted rather than serialized as null.
        assert!(json["error"].get("request_id").is_none());
        assert!(json["error"].get("details").is_none());
    }
}
