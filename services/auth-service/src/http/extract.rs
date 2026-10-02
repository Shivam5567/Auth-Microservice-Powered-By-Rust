use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::domain::{access_token, claims::Claims};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// The caller behind a request, resolved from a verified access token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub roles: Vec<String>,
    pub token_version: i32,
}

impl AuthUser {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Rejects any request that does not carry a valid, unexpired access token.
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| AppError::unauthorized("expected a Bearer token"))?;

        let claims: Claims =
            access_token::verify(&state.keys, state.tokens.metadata(), token)?;

        let id = claims
            .user_id()
            .map_err(|_| AppError::unauthorized("invalid token subject"))?;

        // A token signed before a forced logout or a password change must stop
        // working even though it has not expired yet.
        let current = crate::db::user::User::find_by_id(&state.pool, id)
            .await?
            .ok_or_else(|| AppError::unauthorized("account no longer exists"))?;

        if !current.is_active {
            return Err(AppError::forbidden("this account is disabled"));
        }

        if current.token_version != claims.ver {
            return Err(AppError::unauthorized("token has been revoked"));
        }

        Ok(Self {
            id,
            roles: claims.roles,
            token_version: claims.ver,
        })
    }
}

/// Rejects any request whose token lacks a required role.
pub fn require_role(user: &AuthUser, role: &str) -> AppResult<()> {
    if user.has_role(role) {
        Ok(())
    } else {
        Err(AppError::forbidden(format!(
            "this action requires the '{role}' role"
        )))
    }
}

/// Flattens validator errors into a list of human-readable messages.
pub fn describe_validation(errors: validator::ValidationErrors) -> AppResult<()> {
    let messages = errors
        .field_errors()
        .into_iter()
        .flat_map(|(field, errors)| {
            errors
                .into_iter()
                .map(move |e| format!("{field}: {}", describe(&e)))
        })
        .collect::<Vec<_>>();

    Err(AppError::validation(messages.join("; ")))
}

fn describe(error: &validator::ValidationError) -> String {
    // `ValidationError` renders the `message = "..."` from the derive
    // attribute where one was given, and a generic phrase otherwise.
    let rendered = error.to_string();
    if rendered.is_empty() {
        "is invalid".to_owned()
    } else {
        rendered
    }
}

/// Validates a request, converting failures into a 400.
pub fn validate<T: validator::Validate>(payload: &T) -> AppResult<()> {
    match payload.validate() {
        Ok(()) => Ok(()),
        Err(errors) => describe_validation(errors),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_with(roles: &[&str]) -> AuthUser {
        AuthUser {
            id: Uuid::new_v4(),
            roles: roles.iter().map(|s| (*s).to_owned()).collect(),
            token_version: 0,
        }
    }

    #[test]
    fn role_matching_is_exact() {
        let user = user_with(&["user", "admin"]);
        assert!(user.has_role("admin"));
        assert!(user.has_role("user"));
        assert!(!user.has_role("admi"));
        assert!(!user.has_role("Admin"));
    }

    #[test]
    fn require_role_allows_a_permitted_caller() {
        assert!(require_role(&user_with(&["admin"]), "admin").is_ok());
    }

    #[test]
    fn require_role_rejects_others_with_a_403() {
        let err = require_role(&user_with(&["user"]), "admin").unwrap_err();
        assert_eq!(err.status_code(), 403);
    }

    #[test]
    fn a_privileged_caller_can_never_act_without_the_role() {
        // A user carrying every ordinary role still cannot pass the admin gate.
        let err = require_role(&user_with(&["user", "editor", "owner"]), "admin").unwrap_err();
        assert_eq!(err.code(), "forbidden");
    }

    #[test]
    fn validation_errors_name_the_offending_field() {
        let req = crate::http::dto::RegisterRequest {
            email: "nope".into(),
            password: "x".into(),
        };
        let err = validate(&req).unwrap_err();
        assert_eq!(err.status_code(), 400);
        let msg = err.envelope().error.message;
        assert!(msg.contains("email"), "got: {msg}");
        assert!(msg.contains("password"), "got: {msg}");
    }
}
