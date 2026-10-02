use std::time::Duration;

use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::claims::Claims;
use super::keys::SigningKeys;
use crate::error::AppError;

/// Clock skew tolerated when checking `exp`/`nbf`, in seconds.
const LEEWAY_SECS: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub expires_in: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct TokenMetadata<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub ttl: Duration,
}

pub fn issue(
    keys: &SigningKeys,
    meta: TokenMetadata<'_>,
    user_id: Uuid,
    roles: Vec<String>,
    token_version: i32,
) -> Result<AccessToken, AppError> {
    let now = OffsetDateTime::now_utc();
    let ttl = meta.ttl;

    let claims = Claims {
        sub: user_id.to_string(),
        roles,
        ver: token_version,
        iss: meta.issuer.to_owned(),
        aud: meta.audience.to_owned(),
        iat: now.unix_timestamp(),
        exp: (now + ttl).unix_timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.kid().to_owned());

    let token = encode(&header, &claims, keys.encoding())
        .map_err(|e| AppError::internal(format!("failed to sign access token: {e}")))?;

    Ok(AccessToken {
        token,
        expires_in: ttl.as_secs(),
    })
}

/// Verifies signature, algorithm, issuer, audience and expiry.
///
/// Every failure is reported as the same opaque error so a caller cannot use
/// the message to learn whether a token merely expired or was never valid.
pub fn verify(
    keys: &SigningKeys,
    meta: TokenMetadata<'_>,
    token: &str,
) -> Result<Claims, AppError> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[meta.issuer]);
    validation.set_audience(&[meta.audience]);
    validation.leeway = LEEWAY_SECS;
    // Without this, a token signed with `alg: none` would be accepted.
    validation.validate_exp = true;

    decode::<Claims>(token, keys.decoding(), &validation)
        .map(|data| data.claims)
        .map_err(|_| AppError::unauthorized("invalid or expired access token"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    static KEYS: std::sync::LazyLock<SigningKeys> = std::sync::LazyLock::new(|| {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        SigningKeys::from_pem(
            &private.to_pkcs1_pem(LineEnding::LF).unwrap(),
            &public.to_public_key_pem(LineEnding::LF).unwrap(),
        )
        .unwrap()
    });

    fn meta(ttl: Duration) -> TokenMetadata<'static> {
        TokenMetadata {
            issuer: "auth-service",
            audience: "auth-service-clients",
            ttl,
        }
    }

    #[test]
    fn a_freshly_issued_token_verifies_and_carries_its_claims() {
        let user = Uuid::new_v4();
        let issued = issue(
            &KEYS,
            meta(Duration::from_secs(900)),
            user,
            vec!["user".into()],
            3,
        )
        .unwrap();

        let claims = verify(&KEYS, meta(Duration::from_secs(900)), &issued.token).unwrap();
        assert_eq!(claims.user_id().unwrap(), user);
        assert_eq!(claims.roles, ["user"]);
        assert_eq!(claims.ver, 3);
        assert_eq!(claims.iss, "auth-service");
        assert_eq!(issued.expires_in, 900);
    }

    #[test]
    fn the_header_advertises_rs256_and_the_key_id() {
        let issued = issue(
            &KEYS,
            meta(Duration::from_secs(900)),
            Uuid::new_v4(),
            vec![],
            0,
        )
        .unwrap();
        let header = jsonwebtoken::decode_header(&issued.token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some(KEYS.kid()));
    }

    #[test]
    fn an_expired_token_is_rejected() {
        // A zero-length window makes exp == iat, which is expired on arrival.
        let expired = issue(
            &KEYS,
            meta(Duration::from_secs(0)),
            Uuid::new_v4(),
            vec![],
            0,
        )
        .unwrap();
        let err = verify(&KEYS, meta(Duration::from_secs(900)), &expired.token).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[test]
    fn a_token_from_another_issuer_is_rejected() {
        let issued = issue(
            &KEYS,
            meta(Duration::from_secs(900)),
            Uuid::new_v4(),
            vec![],
            0,
        )
        .unwrap();
        let other = TokenMetadata {
            issuer: "someone-else",
            audience: "auth-service-clients",
            ttl: Duration::from_secs(900),
        };
        assert!(verify(&KEYS, other, &issued.token).is_err());
    }

    #[test]
    fn a_token_for_another_audience_is_rejected() {
        let issued = issue(
            &KEYS,
            meta(Duration::from_secs(900)),
            Uuid::new_v4(),
            vec![],
            0,
        )
        .unwrap();
        let other = TokenMetadata {
            issuer: "auth-service",
            audience: "some-other-api",
            ttl: Duration::from_secs(900),
        };
        assert!(verify(&KEYS, other, &issued.token).is_err());
    }

    #[test]
    fn a_token_signed_by_another_key_is_rejected() {
        static OTHER: std::sync::LazyLock<SigningKeys> = std::sync::LazyLock::new(|| {
            let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
            let public = RsaPublicKey::from(&private);
            SigningKeys::from_pem(
                &private.to_pkcs1_pem(LineEnding::LF).unwrap(),
                &public.to_public_key_pem(LineEnding::LF).unwrap(),
            )
            .unwrap()
        });

        let forged = issue(&OTHER, meta(Duration::from_secs(900)), Uuid::new_v4(), vec![], 0)
            .unwrap();
        let err = verify(&KEYS, meta(Duration::from_secs(900)), &forged.token).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[test]
    fn garbage_input_is_rejected_without_panicking() {
        for bad in ["", "not.a.jwt", "a.b.c", "...."] {
            assert!(verify(&KEYS, meta(Duration::from_secs(900)), bad).is_err());
        }
    }
}
