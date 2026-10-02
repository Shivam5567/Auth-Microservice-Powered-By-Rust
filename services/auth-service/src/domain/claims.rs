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
        }
    }

    #[test]
    fn round_trips_through_json() {
        let claims = sample();
        let json = serde_json::to_string(&claims).unwrap();
        assert_eq!(serde_json::from_str::<Claims>(&json).unwrap(), claims);
    }

    #[test]
    fn subject_parses_as_a_uuid() {
        assert!(sample().user_id().is_ok());
        let mut broken = sample();
        broken.sub = "not-a-uuid".into();
        assert!(broken.user_id().is_err());
    }
}
