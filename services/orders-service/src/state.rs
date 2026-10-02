use std::sync::Arc;

use sqlx::PgPool;

use crate::auth::{AuthClient, CheckMode};
use crate::config::Config;
use crate::error::AppResult;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth: Arc<AuthClient>,
    pub refresh_cookie_ttl: std::time::Duration,
    pub cors_allowed_origins: Vec<String>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("token_check", &self.auth.mode())
            .finish_non_exhaustive()
    }
}

/// Opens the database and builds the auth client.
///
/// Returns an error rather than panicking, because a cold start may reach this
/// before Postgres is accepting connections.
pub async fn build(config: Config) -> AppResult<AppState> {
    let auth = AuthClient::new(
        config.auth_base_url,
        config.auth_issuer,
        config.auth_audience,
        config.token_check,
    );

    let pool = crate::db::connect(&config.database_url, config.database_max_connections).await?;

    Ok(AppState {
        pool,
        auth: Arc::new(auth),
        refresh_cookie_ttl: config.refresh_cookie_ttl,
        cors_allowed_origins: config.cors_allowed_origins,
    })
}

pub fn mode_of(state: &AppState) -> CheckMode {
    state.auth.mode()
}
