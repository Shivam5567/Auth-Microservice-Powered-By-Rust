use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// A string that must never appear in logs or `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub service_name: &'static str,
    pub bind_addr: SocketAddr,
    pub database_url: Secret,
    pub database_max_connections: u32,
    pub jwt_private_key_path: PathBuf,
    pub jwt_public_key_path: PathBuf,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub cors_allowed_origins: Vec<String>,
    pub run_migrations: bool,
    /// Failed auth attempts allowed per client IP per minute.
    pub auth_rate_limit_per_minute: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("environment variable {name} has invalid value: {reason}")]
    Invalid { name: &'static str, reason: String },
}

impl Config {
    /// Builds the configuration from the process environment, failing fast on
    /// anything missing or malformed so a misconfigured deployment never starts.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(&|key| std::env::var(key).ok())
    }

    /// Builds the configuration from an arbitrary lookup, so tests can supply
    /// their own values without mutating the process environment.
    pub fn from_source_with(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        Self::from_source(get)
    }

    pub fn from_source(
        get: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let database_url =
            Secret(get("DATABASE_URL").ok_or(ConfigError::Missing("DATABASE_URL"))?);

        let bind_addr = parse_or("BIND_ADDR", get("BIND_ADDR"), "0.0.0.0:8080")?;
        let database_max_connections = parse_or(
            "DATABASE_MAX_CONNECTIONS",
            get("DATABASE_MAX_CONNECTIONS"),
            "10",
        )?;
        let access_token_ttl_secs: u64 = parse_or(
            "ACCESS_TOKEN_TTL_SECONDS",
            get("ACCESS_TOKEN_TTL_SECONDS"),
            "900",
        )?;
        let refresh_token_ttl_secs: u64 = parse_or(
            "REFRESH_TOKEN_TTL_SECONDS",
            get("REFRESH_TOKEN_TTL_SECONDS"),
            "2592000",
        )?;
        let run_migrations = parse_or("RUN_MIGRATIONS", get("RUN_MIGRATIONS"), "true")?;
        let auth_rate_limit_per_minute = parse_or(
            "AUTH_RATE_LIMIT_PER_MINUTE",
            get("AUTH_RATE_LIMIT_PER_MINUTE"),
            "10",
        )?;

        if access_token_ttl_secs == 0 {
            return Err(ConfigError::Invalid {
                name: "ACCESS_TOKEN_TTL_SECONDS",
                reason: "must be greater than zero".into(),
            });
        }
        if refresh_token_ttl_secs <= access_token_ttl_secs {
            return Err(ConfigError::Invalid {
                name: "REFRESH_TOKEN_TTL_SECONDS",
                reason: "must be longer than ACCESS_TOKEN_TTL_SECONDS".into(),
            });
        }

        let cors_allowed_origins = get("CORS_ALLOWED_ORIGINS")
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            service_name: "auth-service",
            bind_addr,
            database_url,
            database_max_connections,
            jwt_private_key_path: PathBuf::from(
                get("JWT_PRIVATE_KEY_PATH").unwrap_or_else(|| "keys/private.pem".into()),
            ),
            jwt_public_key_path: PathBuf::from(
                get("JWT_PUBLIC_KEY_PATH").unwrap_or_else(|| "keys/public.pem".into()),
            ),
            jwt_issuer: get("JWT_ISSUER").unwrap_or_else(|| "auth-service".into()),
            jwt_audience: get("JWT_AUDIENCE").unwrap_or_else(|| "auth-service-clients".into()),
            access_token_ttl: Duration::from_secs(access_token_ttl_secs),
            refresh_token_ttl: Duration::from_secs(refresh_token_ttl_secs),
            cors_allowed_origins,
            run_migrations,
            auth_rate_limit_per_minute,
        })
    }
}

fn parse_or<T>(name: &'static str, raw: Option<String>, default: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let raw = raw.unwrap_or_else(|| default.to_owned());
    raw.trim().parse::<T>().map_err(|e| ConfigError::Invalid {
        name,
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn source(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    fn valid() -> Vec<(&'static str, &'static str)> {
        vec![("DATABASE_URL", "postgres://u:p@localhost:5432/auth")]
    }

    #[test]
    fn requires_a_database_url() {
        let err = Config::from_source(&source(&[])).unwrap_err();
        assert!(matches!(err, ConfigError::Missing("DATABASE_URL")));
    }

    #[test]
    fn applies_documented_defaults() {
        let cfg = Config::from_source(&source(&valid())).unwrap();
        assert_eq!(cfg.bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(cfg.database_max_connections, 10);
        assert_eq!(cfg.access_token_ttl, Duration::from_secs(900));
        assert_eq!(cfg.refresh_token_ttl, Duration::from_secs(2_592_000));
        assert_eq!(cfg.jwt_issuer, "auth-service");
        assert!(cfg.run_migrations);
    }

    #[test]
    fn overrides_are_applied() {
        let mut pairs = valid();
        pairs.extend([
            ("BIND_ADDR", "127.0.0.1:9000"),
            ("ACCESS_TOKEN_TTL_SECONDS", "60"),
            ("REFRESH_TOKEN_TTL_SECONDS", "120"),
            ("CORS_ALLOWED_ORIGINS", "http://a.test, http://b.test ,"),
            ("RUN_MIGRATIONS", "false"),
        ]);
        let cfg = Config::from_source(&source(&pairs)).unwrap();
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:9000");
        assert_eq!(cfg.access_token_ttl, Duration::from_secs(60));
        assert_eq!(cfg.cors_allowed_origins, ["http://a.test", "http://b.test"]);
        assert!(!cfg.run_migrations);
    }

    #[test]
    fn rejects_refresh_ttl_shorter_than_access_ttl() {
        let mut pairs = valid();
        pairs.extend([
            ("ACCESS_TOKEN_TTL_SECONDS", "600"),
            ("REFRESH_TOKEN_TTL_SECONDS", "300"),
        ]);
        let err = Config::from_source(&source(&pairs)).unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid { name, .. } if name == "REFRESH_TOKEN_TTL_SECONDS")
        );
    }

    #[test]
    fn rejects_malformed_values() {
        let mut pairs = valid();
        pairs.push(("DATABASE_MAX_CONNECTIONS", "plenty"));
        let err = Config::from_source(&source(&pairs)).unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid { name, .. } if name == "DATABASE_MAX_CONNECTIONS")
        );
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let cfg = Config::from_source(&source(&valid())).unwrap();
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("postgres://"), "got: {rendered}");
        assert!(rendered.contains("redacted"));
    }
}
