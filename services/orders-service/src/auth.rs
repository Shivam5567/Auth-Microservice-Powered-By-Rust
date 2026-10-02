//! Client for the auth service, and the two ways to turn a bearer token into
//! an identity.
//!
//! This module is the part worth copying if you build a real service. It shows
//! the trade-off between verifying a token locally and asking the issuer, and
//! it keeps that decision in one place.

use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// Clock skew tolerated when checking `exp`/`nbf`, in seconds.
const LEEWAY_SECS: u64 = 5;

/// How long a fetched public key is reused before being refreshed.
const DEFAULT_KEY_TTL: Duration = Duration::from_secs(300);

/// Which downstream service this one registers as. Tokens minted for it are
/// revoked if this service is removed from the registry.
const SERVICE_NAME: &str = "orders-service";

/// How the caller behind a token is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckMode {
    /// Verify the RS256 signature with the issuer's public key. No network
    /// call, so it stays fast, but it cannot see revocations: a token the
    /// issuer has since withdrawn still verifies here.
    Local,
    /// Ask the issuer who the caller is on every request. Costs a network hop
    /// per request, but honours revocations and disabled accounts immediately.
    Introspect,
}

impl CheckMode {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "introspect" => Self::Introspect,
            _ => Self::Local,
        }
    }
}

/// The identity behind a request.
#[derive(Debug, Clone)]
pub struct Caller {
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub established_by: CheckMode,
}

impl Caller {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn require_role(&self, role: &str) -> AppResult<()> {
        if self.has_role(role) {
            Ok(())
        } else {
            Err(AppError::forbidden(format!(
                "this action requires the '{role}' role"
            )))
        }
    }
}

/// The subset of the auth service's claim set that this service relies on.
///
/// Deliberately declared here rather than imported from `auth-service`: a
/// service boundary is a contract, and coupling to another crate's structs
/// would make every claim change a breaking change for every consumer. Unknown
/// fields are ignored by serde, so the issuer can add claims freely.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    roles: Vec<String>,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(default)]
    svc: Option<String>,
}

/// The token pair handed to the browser. Only `access_token` reaches it; the
/// refresh token belongs in an httpOnly cookie.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct PublicKeyResponse {
    pem: String,
    kid: String,
}

struct CachedKey {
    decoding: DecodingKey,
    kid: String,
    fetched_at: std::time::Instant,
}

pub struct AuthClient {
    base_url: String,
    http: reqwest::Client,
    issuer: String,
    audience: String,
    key_ttl: Duration,
    mode: CheckMode,
    key: RwLock<Option<CachedKey>>,
}

impl AuthClient {
    pub fn new(base_url: String, issuer: String, audience: String, mode: CheckMode) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build auth http client");

        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http,
            issuer,
            audience,
            key_ttl: DEFAULT_KEY_TTL,
            mode,
            key: RwLock::new(None),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Creates an account, treating an existing address as success.
    ///
    /// Proxied through this service so the browser only ever talks to one
    /// origin, which keeps the auth service's CORS configuration out of the
    /// picture entirely.
    pub async fn register(&self, email: &str, password: &str) -> AppResult<()> {
        let response = self
            .http
            .post(self.url("/api/v1/auth/register"))
            .json(&serde_json::json!({ "email": email, "password": password }))
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "auth service unreachable");
                AppError::internal("could not reach the auth service")
            })?;

        match response.status().as_u16() {
            // Created, or already registered, which is the state we wanted.
            201 | 409 => Ok(()),
            400 => Err(AppError::validation("that email or password was rejected")),
            status => {
                tracing::warn!(status, "registration was refused");
                Err(AppError::internal("could not create that account"))
            }
        }
    }

    /// Logs a user in, optionally binding the session to this service.
    ///
    /// The binding is what lets an operator revoke everything issued to this
    /// service in one move, by removing it from the registry.
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        bind_to_service: bool,
    ) -> AppResult<TokenPair> {
        let body = serde_json::json!({
            "email": email,
            "password": password,
            "service": bind_to_service.then_some(SERVICE_NAME),
        });

        let response = self
            .http
            .post(self.url("/api/v1/auth/login"))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "auth service unreachable");
                AppError::internal("could not reach the auth service")
            })?;

        decode_pair(response).await
    }

    /// Exchanges a refresh token for a new pair.
    ///
    /// Callers must not do this concurrently for one session: the auth service
    /// treats a second use of the same refresh token as theft and revokes the
    /// whole family. The browser in `assets/index.html` demonstrates both the
    /// correct single-flight pattern and what goes wrong without it.
    pub async fn refresh(&self, refresh_token: &str) -> AppResult<TokenPair> {
        let response = self
            .http
            .post(self.url("/api/v1/auth/refresh"))
            .json(&serde_json::json!({ "refresh_token": refresh_token }))
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "auth service unreachable");
                AppError::internal("could not reach the auth service")
            })?;

        decode_pair(response).await
    }

    pub async fn logout(&self, refresh_token: &str) -> AppResult<()> {
        let response = self
            .http
            .post(self.url("/api/v1/auth/logout"))
            .json(&serde_json::json!({ "refresh_token": refresh_token }))
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "auth service unreachable on logout");
                AppError::internal("could not reach the auth service")
            })?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::internal("logout failed"))
        }
    }

    /// Establishes who is behind a bearer token, per the configured mode.
    pub async fn caller(&self, token: &str) -> AppResult<Caller> {
        match self.mode {
            CheckMode::Local => self.verify_locally(token).await,
            CheckMode::Introspect => self.introspect(token).await,
        }
    }

    /// Verifies the signature against the issuer's cached public key.
    async fn verify_locally(&self, token: &str) -> AppResult<Caller> {
        if let Some(caller) = self.try_verify(token).await {
            return Ok(caller);
        }

        // Either the key is missing, stale, or the token was signed with a key
        // that replaced ours. Fetch once and try again before giving up.
        let before = self.cached_kid().await;
        self.fetch_key(true).await?;

        if let (Some(old), Some(new)) = (before, self.cached_kid().await)
            && old != new
        {
            tracing::warn!(old_kid = %old, new_kid = %new, "auth signing key rotated");
        }

        self.try_verify(token)
            .await
            .ok_or_else(|| AppError::unauthorized("invalid or expired access token"))
    }

    async fn cached_kid(&self) -> Option<String> {
        self.key.read().await.as_ref().map(|c| c.kid.clone())
    }

    async fn try_verify(&self, token: &str) -> Option<Caller> {
        let guard = self.key.read().await;
        let cached = guard.as_ref()?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;

        let claims = decode::<Claims>(token, &cached.decoding, &validation)
            .ok()?
            .claims;

        let user_id = Uuid::parse_str(&claims.sub).ok()?;

        Some(Caller {
            user_id,
            roles: claims.roles,
            established_by: CheckMode::Local,
        })
    }

    /// Asks the issuer who the caller is, on every request.
    ///
    /// Slower, and it puts the auth service on the hot path of every request
    /// this service serves. What it buys is immediacy: a withdrawn token or a
    /// disabled account stops working at once, which local verification cannot
    /// know about.
    async fn introspect(&self, token: &str) -> AppResult<Caller> {
        let response = self
            .http
            .get(self.url("/api/v1/auth/me"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "auth service unreachable");
                AppError::internal("could not reach the auth service")
            })?;

        match response.status().as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.map_err(|e| {
                    tracing::error!(error = %e, "malformed auth response");
                    AppError::internal("malformed response from the auth service")
                })?;

                let user_id = body
                    .get("id")
                    .and_then(|v| v.as_str())
                    .and_then(|v| Uuid::parse_str(v).ok())
                    .ok_or_else(|| {
                        tracing::error!("auth response had no usable id");
                        AppError::internal("malformed response from the auth service")
                    })?;

                let roles = body
                    .get("roles")
                    .and_then(|v| v.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(Caller {
                    user_id,
                    roles,
                    established_by: CheckMode::Introspect,
                })
            }
            401 | 403 => Err(AppError::unauthorized("invalid or expired access token")),
            // A 5xx from the issuer is our outage, not the caller's fault, so it
            // must not be reported as bad credentials.
            status => {
                tracing::error!(%status, "unexpected status from the auth service");
                Err(AppError::internal("the auth service is unhealthy"))
            }
        }
    }

    /// Downloads the issuer's public key, at most once per TTL.
    async fn fetch_key(&self, force: bool) -> AppResult<()> {
        {
            let guard = self.key.read().await;
            if !force
                && let Some(cached) = guard.as_ref()
                && cached.fetched_at.elapsed() < self.key_ttl
            {
                return Ok(());
            }
        }

        let response = self
            .http
            .get(self.url("/public-key"))
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "could not fetch the auth public key");
                AppError::internal("could not reach the auth service")
            })?;

        let key: PublicKeyResponse = response.json().await.map_err(|e| {
            tracing::error!(error = %e, "malformed public key response");
            AppError::internal("malformed public key response")
        })?;

        let decoding = DecodingKey::from_rsa_pem(key.pem.as_bytes()).map_err(|e| {
            tracing::error!(error = %e, "auth public key was not usable");
            AppError::internal("the auth service published an unusable key")
        })?;

        tracing::info!(kid = %key.kid, "loaded the auth service public key");
        *self.key.write().await = Some(CachedKey {
            decoding,
            kid: key.kid,
            fetched_at: std::time::Instant::now(),
        });
        Ok(())
    }

    /// Warms the key cache at startup so the first real request is not the one
    /// that pays for the fetch.
    pub async fn prefetch_key(&self) -> AppResult<()> {
        self.fetch_key(true).await
    }

    pub fn mode(&self) -> CheckMode {
        self.mode
    }
}

/// The error envelope the auth service returns, reused rather than guessed at.
#[derive(Debug, Deserialize)]
struct RemoteError {
    error: RemoteErrorBody,
}

#[derive(Debug, Deserialize)]
struct RemoteErrorBody {
    code: String,
    message: String,
}

/// Maps a login or refresh response.
///
/// The issuer's rejection has to reach the caller intact. Turning its 403 into
/// a 500 here would tell a shopper that the storefront is broken when the truth
/// is that the service they were signing in to has been decommissioned.
async fn decode_pair(response: reqwest::Response) -> AppResult<TokenPair> {
    let status = response.status().as_u16();

    if (200..300).contains(&status) {
        return response.json::<TokenPair>().await.map_err(|e| {
            tracing::warn!(error = %e, "unexpected token payload from the auth service");
            AppError::internal("the auth service returned something unexpected")
        });
    }

    let remote = response
        .json::<RemoteError>()
        .await
        .map_err(|_| AppError::internal("the auth service returned something unexpected"))?;

    tracing::debug!(
        status,
        code = %remote.error.code,
        "auth service refused: {}",
        remote.error.message
    );

    Err(map_remote_error(&remote.error, status))
}

/// Preserves the issuer's status and message where the code is a known one,
/// and falls back to a generic error for anything unexpected.
fn map_remote_error(body: &RemoteErrorBody, status: u16) -> AppError {
    let message = body.message.clone();

    match body.code.as_str() {
        "unauthorized" => AppError::unauthorized(message),
        "forbidden" => AppError::forbidden(message),
        "validation_failed" => AppError::validation(message),
        "conflict" => AppError::conflict(message),
        "not_found" => AppError::not_found(message),
        "rate_limited" => AppError::RateLimited,
        // A 5xx from the issuer is our outage, not the caller's fault, so it
        // must not be reported as bad credentials.
        _ if status >= 500 => AppError::internal("the auth service is unhealthy"),
        _ => AppError::internal("the auth service refused the request"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_mode_defaults_to_local() {
        assert_eq!(CheckMode::parse("local"), CheckMode::Local);
        assert_eq!(CheckMode::parse(""), CheckMode::Local);
        assert_eq!(CheckMode::parse("nonsense"), CheckMode::Local);
    }

    #[test]
    fn check_mode_is_case_insensitive() {
        assert_eq!(CheckMode::parse("INTROSPECT"), CheckMode::Introspect);
        assert_eq!(CheckMode::parse(" Introspect "), CheckMode::Introspect);
    }

    #[test]
    fn a_caller_reports_its_roles() {
        let caller = Caller {
            user_id: Uuid::new_v4(),
            roles: vec!["user".into(), "admin".into()],
            established_by: CheckMode::Local,
        };
        assert!(caller.has_role("admin"));
        assert!(!caller.has_role("superuser"));
        assert!(caller.require_role("user").is_ok());
    }

    #[test]
    fn a_missing_role_is_a_403() {
        let caller = Caller {
            user_id: Uuid::new_v4(),
            roles: vec!["user".into()],
            established_by: CheckMode::Local,
        };
        assert_eq!(caller.require_role("admin").unwrap_err().status_code(), 403);
    }

    /// A claim set carrying fields this service does not know about must still
    /// decode, or an issuer adding a claim would break every consumer.
    #[test]
    fn unknown_claims_are_ignored() {
        let json = serde_json::json!({
            "sub": "8f14e45f-ea5f-4b2c-9a3d-1c2b3a4d5e6f",
            "roles": ["user"],
            "iss": "auth-service",
            "aud": "auth-service-clients",
            "exp": 1_900_000_000,
            "iat": 1_899_999_100,
            "jti": "abc",
            "something_new": {"nested": true}
        });
        let claims: Claims = serde_json::from_value(json).unwrap();
        assert_eq!(claims.roles, ["user"]);
    }

    /// A claim set from before the service-binding fields existed must decode.
    #[test]
    fn a_legacy_claim_set_still_decodes() {
        let json = serde_json::json!({
            "sub": "8f14e45f-ea5f-4b2c-9a3d-1c2b3a4d5e6f",
            "iss": "auth-service",
            "aud": "auth-service-clients",
            "exp": 1_900_000_000,
            "iat": 1_899_999_100
        });
        let claims: Claims = serde_json::from_value(json).unwrap();
        assert!(claims.roles.is_empty());
        assert!(claims.svc.is_none());
    }

    #[test]
    fn a_claim_set_without_roles_is_tolerated() {
        let json = serde_json::json!({
            "sub": "8f14e45f-ea5f-4b2c-9a3d-1c2b3a4d5e6f",
            "iss": "auth-service",
            "aud": "auth-service-clients",
            "exp": 1_900_000_000,
            "iat": 1_899_999_100
        });
        assert!(serde_json::from_value::<Claims>(json).is_ok());
    }

    #[test]
    fn a_token_pair_needs_the_fields_we_rely_on() {
        let pair: TokenPair = serde_json::from_str(
            r#"{"access_token":"a","refresh_token":"r","token_type":"Bearer","expires_in":900}"#,
        )
        .unwrap();
        assert_eq!(pair.access_token, "a");
        assert_eq!(pair.expires_in, 900);
    }

    /// A refusal from the issuer has to arrive at our caller with its status
    /// intact, or a decommissioned service looks like a broken storefront.
    #[test]
    fn an_issuer_refusal_keeps_its_status_and_message() {
        let body = RemoteErrorBody {
            code: "forbidden".into(),
            message: "the service 'orders-service' has been decommissioned".into(),
        };
        let err = map_remote_error(&body, 403);
        assert_eq!(err.status_code(), 403);
        assert!(
            err.envelope().error.message.contains("decommissioned"),
            "the issuer's reason should reach the caller"
        );
    }

    #[test]
    fn every_known_code_maps_to_its_own_status() {
        let cases = [
            ("unauthorized", 401),
            ("forbidden", 403),
            ("validation_failed", 400),
            ("conflict", 409),
            ("not_found", 404),
        ];
        for (code, expected) in cases {
            let body = RemoteErrorBody {
                code: code.into(),
                message: "refused".into(),
            };
            assert_eq!(
                map_remote_error(&body, expected).status_code(),
                expected,
                "code {code}"
            );
        }
    }

    #[test]
    fn throttling_from_the_issuer_surfaces_as_429() {
        let body = RemoteErrorBody {
            code: "rate_limited".into(),
            message: "too many requests".into(),
        };
        assert_eq!(map_remote_error(&body, 429).status_code(), 429);
    }

    /// The issuer being down is our outage, not bad credentials. Reporting it as
    /// a 401 would tell the user to retype their password.
    #[test]
    fn an_issuer_outage_is_never_reported_as_bad_credentials() {
        let body = RemoteErrorBody {
            code: "internal_error".into(),
            message: "database error".into(),
        };
        let err = map_remote_error(&body, 503);
        assert_eq!(err.status_code(), 500);
        assert!(!err.envelope().error.message.contains("password"));
    }

    #[test]
    fn an_unrecognised_code_does_not_leak_the_issuers_wording() {
        let body = RemoteErrorBody {
            code: "something_new".into(),
            message: "connection to 10.0.0.5:5432 refused".into(),
        };
        let err = map_remote_error(&body, 418);
        assert_eq!(err.status_code(), 500);
        assert!(!err.envelope().error.message.contains("10.0.0.5"));
    }
}
