use std::net::SocketAddr;
use std::time::Duration;

use crate::auth::CheckMode;
use crate::error::ConfigError;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    /// Where the auth service lives, on the compose network.
    pub auth_base_url: String,
    pub auth_issuer: String,
    pub auth_audience: String,
    /// Whether tokens are checked locally or by asking the issuer.
    pub token_check: CheckMode,
    /// How long a browser's refresh cookie lives.
    pub refresh_cookie_ttl: Duration,
    /// Origins allowed to call this service from a browser. Empty means none.
    pub cors_allowed_origins: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let parse = |name: &'static str, default: &str| -> Result<String, ConfigError> {
            Ok(std::env::var(name).unwrap_or_else(|_| default.to_owned()))
        };

        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| ConfigError::Missing("DATABASE_URL"))?;

        // The error types are named explicitly: chained `parse().map_err()`
        // gives the compiler nothing to infer the closure parameter from.
        let bind_addr_raw = parse("BIND_ADDR", "0.0.0.0:8081")?;
        let bind_addr: SocketAddr =
            bind_addr_raw
                .trim()
                .parse()
                .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                    name: "BIND_ADDR",
                    reason: e.to_string(),
                })?;

        let pool_raw = parse("DATABASE_MAX_CONNECTIONS", "10")?;
        let database_max_connections: u32 =
            pool_raw
                .trim()
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Invalid {
                    name: "DATABASE_MAX_CONNECTIONS",
                    reason: e.to_string(),
                })?;

        let ttl_raw = parse("REFRESH_COOKIE_TTL_SECONDS", "2592000")?;
        let refresh_cookie_ttl: u64 =
            ttl_raw
                .trim()
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Invalid {
                    name: "REFRESH_COOKIE_TTL_SECONDS",
                    reason: e.to_string(),
                })?;

        let cors_allowed_origins = std::env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();

        Ok(Self {
            bind_addr,
            database_url,
            database_max_connections,
            auth_base_url: parse("AUTH_BASE_URL", "http://auth-service:8080")?,
            auth_issuer: parse("AUTH_ISSUER", "auth-service")?,
            auth_audience: parse("AUTH_AUDIENCE", "auth-service-clients")?,
            token_check: CheckMode::parse(&parse("TOKEN_CHECK", "local")?),
            refresh_cookie_ttl: Duration::from_secs(refresh_cookie_ttl),
            cors_allowed_origins,
        })
    }
}
