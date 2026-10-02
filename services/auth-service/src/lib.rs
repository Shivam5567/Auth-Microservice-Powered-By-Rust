//! Auth microservice: registration, login, and token lifecycle.

pub mod config;
pub mod db;
pub mod domain;
pub mod error;
pub mod http;
pub mod service;
pub mod state;

use std::sync::Arc;
use std::time::Duration;

use common::AppError;
use config::Config;
use state::{AppState, TokenConfig};

/// Interval between sweeps of expired refresh tokens.
const PURGE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Builds the fully wired application state, ready to be served.
pub async fn build_state(config: Config) -> Result<AppState, AppError> {
    let keys = Arc::new(domain::keys::SigningKeys::load_or_generate(
        &config.jwt_private_key_path,
        &config.jwt_public_key_path,
    )?);

    let pool = db::connect(
        config.database_url.expose(),
        config.database_max_connections,
    )
    .await?;

    if config.run_migrations {
        db::migrate(&pool).await?;
        tracing::info!("database migrations are up to date");
    }

    let tokens = TokenConfig {
        issuer: config.jwt_issuer.clone(),
        audience: config.jwt_audience.clone(),
        access_ttl: config.access_token_ttl,
    };

    Ok(AppState {
        pool,
        keys,
        tokens,
        config: Arc::new(config),
    })
}

/// Background task that prunes expired refresh tokens.
pub fn spawn_purge_task(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PURGE_INTERVAL);
        // The first tick fires immediately; skip it so startup stays cheap.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            match service::purge_stale_tokens(&state).await {
                Ok(removed) if removed > 0 => {
                    tracing::info!(removed, "purged expired refresh tokens");
                }
                Ok(_) => {}
                Err(err) => tracing::error!(error = %err, "failed to purge expired tokens"),
            }
        }
    })
}
