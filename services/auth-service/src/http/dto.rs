use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::service::TokenPair;

/// Longest password accepted. Argon2 is deliberately slow, so an unbounded
/// password is a cheap way to burn server CPU.
pub const MAX_PASSWORD_LEN: u64 = 256;
pub const MIN_PASSWORD_LEN: u64 = 12;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "must be a valid email address"))]
    pub email: String,
    #[validate(length(
        min = MIN_PASSWORD_LEN,
        max = MAX_PASSWORD_LEN,
        message = "must be between 12 and 256 characters"
    ))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 1, max = MAX_PASSWORD_LEN, message = "is required"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshRequest {
    #[validate(length(min = 1, max = 512, message = "is required"))]
    pub refresh_token: String,}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
    /// When true, every session for the user is ended and outstanding access
    /// tokens are invalidated. Defaults to signing out of one session only.
    #[serde(default)]
    pub all_devices: bool,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: uuid::Uuid,
    pub email: String,
    pub roles: Vec<String>,
    pub created_at: time::OffsetDateTime,
}

impl From<crate::db::user::UserProfile> for UserResponse {
    fn from(p: crate::db::user::UserProfile) -> Self {
        Self {
            id: p.id,
            email: p.email,
            roles: p.roles,
            created_at: p.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: UserResponse,
}

impl From<TokenPair> for AuthResponse {
    fn from(p: TokenPair) -> Self {
        Self {
            access_token: p.access_token,
            refresh_token: p.refresh_token,
            token_type: p.token_type.to_owned(),
            expires_in: p.expires_in,
            user: p.user.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<time::OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    fn valid_register() -> RegisterRequest {
        RegisterRequest {
            email: "alice@example.com".into(),
            password: "correct horse battery".into(),
        }
    }

    #[test]
    fn a_well_formed_registration_validates() {
        assert!(valid_register().validate().is_ok());
    }

    #[test]
    fn a_malformed_email_is_rejected() {
        let mut req = valid_register();
        req.email = "not-an-email".into();
        let errors = req.validate().unwrap_err();
        assert!(errors.field_errors().contains_key("email"));
    }

    #[test]
    fn a_short_password_is_rejected() {
        let mut req = valid_register();
        req.password = "short".into();
        let errors = req.validate().unwrap_err();
        assert!(errors.field_errors().contains_key("password"));
    }

    #[test]
    fn an_absurdly_long_password_is_rejected() {
        let mut req = valid_register();
        req.password = "x".repeat(MAX_PASSWORD_LEN as usize + 1);
        assert!(req.validate().is_err());
    }

    #[test]
    fn an_empty_password_is_rejected_for_login() {
        let req = LoginRequest {
            email: "alice@example.com".into(),
            password: String::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn logout_defaults_to_a_single_session() {
        let req: LogoutRequest =
            serde_json::from_str(r#"{"refresh_token":"abc"}"#).unwrap();
        assert!(!req.all_devices);
    }

    #[test]
    fn logout_accepts_all_devices() {
        let req: LogoutRequest =
            serde_json::from_str(r#"{"refresh_token":"abc","all_devices":true}"#).unwrap();
        assert!(req.all_devices);
    }

    #[test]
    fn health_omits_absent_optional_fields() {
        let json = serde_json::to_value(HealthResponse {
            status: "ok",
            service: "auth-service",
            database: None,
            checked_at: None,
        })
        .unwrap();
        assert_eq!(json["status"], "ok");
        assert!(json.get("database").is_none());
    }
}
