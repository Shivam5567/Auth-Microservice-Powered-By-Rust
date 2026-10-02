use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The payload of an access token.
///
/// Deliberately minimal: everything here is readable by anyone holding the
/// token, so it carries identifiers and authorisation context only, never
/// profile data or secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Subject: the user's UUID.
    pub sub: String,
    /// Role names granted at issue time.
    pub roles: Vec<String>,
    /// Mirrors `users.token_version`; lets the service invalidate live tokens.
    pub ver: i32,
    pub iss: String,
    pub aud: String,
    /// Expiry, seconds since the Unix epoch.
    pub exp: i64,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Unique token id, for audit and future denylisting.
    pub jti: String,
    /// Downstream service this token was minted for, if any.
    ///
    /// Optional and absent by default: a token issued for the shared audience
    /// is not tied to one service, and so is not affected by that service
    /// being removed from the registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svc: Option<String>,
    /// The service's `token_version` at issue time. Disabling or restoring the
    /// service bumps it, which is how tokens already in flight stop verifying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sver: Option<i32>,
}

impl Claims {
    pub fn user_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Claims {
        Claims {
            sub: "8f14e45f-ea5f-4b2c-9a3d-1c2b3a4d5e6f".into(),
            roles: vec!["user".into()],
            ver: 0,
            iss: "auth-service".into(),
            aud: "auth-service-clients".into(),
            exp: 1_900_000_000,
            iat: 1_899_999_100,
            jti: Uuid::new_v4().to_string(),
            svc: None,
            sver: None,
        }
    }

    #[test]
    fn round_trips_through_json() {
        let claims = sample();
        let json = serde_json::to_string(&claims).unwrap();
        assert_eq!(serde_json::from_str::<Claims>(&json).unwrap(), claims);
    }

    #[test]
    fn an_unbound_token_omits_the_service_claims_entirely() {
        let json = serde_json::to_value(sample()).unwrap();
        assert!(json.get("svc").is_none(), "got: {json}");
        assert!(json.get("sver").is_none(), "got: {json}");
    }

    #[test]
    fn a_bound_token_carries_its_service_and_version() {
        let mut claims = sample();
        claims.svc = Some("billing-api".into());
        claims.sver = Some(4);

        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["svc"], "billing-api");
        assert_eq!(json["sver"], 4);
        assert_eq!(serde_json::from_value::<Claims>(json).unwrap(), claims);
    }

    /// A token issued before these fields existed must still decode, otherwise
    /// adding them would invalidate every outstanding token on deploy.
    #[test]
    fn a_token_without_the_service_claims_still_decodes() {
        let legacy = serde_json::json!({
            "sub": "8f14e45f-ea5f-4b2c-9a3d-1c2b3a4d5e6f",
            "roles": ["user"],
            "ver": 0,
            "iss": "auth-service",
            "aud": "auth-service-clients",
            "exp": 1_900_000_000,
            "iat": 1_899_999_100,
            "jti": "abc"
        });
        let claims: Claims = serde_json::from_value(legacy).unwrap();
        assert_eq!(claims.svc, None);
        assert_eq!(claims.sver, None);
    }

    #[test]
    fn subject_parses_as_a_uuid() {
        assert!(sample().user_id().is_ok());
        let mut broken = sample();
        broken.sub = "not-a-uuid".into();
        assert!(broken.user_id().is_err());
    }
}
