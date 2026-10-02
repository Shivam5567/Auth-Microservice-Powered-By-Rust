use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::auth::Caller;
use crate::error::AppError;
use crate::state::AppState;

/// The authenticated caller.
///
/// Handlers take this as a parameter and therefore cannot be reached by an
/// anonymous caller: if the token is missing or unusable, the request never
/// arrives.
pub struct CurrentUser(pub Caller);

impl std::ops::Deref for CurrentUser {
    type Target = Caller;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("sign in to continue"))?;

        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| AppError::unauthorized("expected a Bearer token"))?;

        let caller = state.auth.caller(token).await?;
        Ok(Self(caller))
    }
}
