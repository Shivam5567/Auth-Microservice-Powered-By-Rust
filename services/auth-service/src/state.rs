use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

use crate::config::Config;
use crate::domain::access_token::TokenMetadata;
use crate::domain::keys::SigningKeys;

/// Owned token settings, so that `AppState` can hand out short-lived borrows
/// of the metadata the signing functions expect.
#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub issuer: String,
    pub audience: String,
    pub access_ttl: Duration,
}

impl TokenConfig {
    pub fn metadata(&self) -> TokenMetadata<'_> {
        TokenMetadata {
            issuer: &self.issuer,
            audience: &self.audience,
            ttl: self.access_ttl,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub keys: Arc<SigningKeys>,
    pub tokens: TokenConfig,
    pub config: Arc<Config>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("tokens", &self.tokens)
            .finish_non_exhaustive()
    }
}
