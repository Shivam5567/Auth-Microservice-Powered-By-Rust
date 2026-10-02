use std::fmt;

use serde::{Deserialize, Serialize};

/// Shortest and longest permitted service names.
pub const MIN_NAME_LEN: usize = 3;
pub const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Active,
    Disabled,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated service name.
///
/// Enforced as a type so a name that reached the database some other way cannot
/// end up inside a token claim or a URL path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

impl ServiceName {
    /// Normalises and validates a candidate name.
    ///
    /// Accepts what an operator would naturally type (`"Billing API"`,
    /// `"billing_api"`) and reduces it to a single canonical form, so
    /// registering `Billing API` cannot produce a second row for the same
    /// service spelled `billing-api`.
    pub fn parse(raw: &str) -> Result<Self, InvalidName> {
        let normalized = raw.trim().to_lowercase();
        let replaced: Vec<char> = normalized
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();

        // Collapse runs of separators and trim them from both ends.
        let mut slug = String::with_capacity(replaced.len());
        let mut previous_separator = true;
        for c in replaced {
            if c == '-' {
                if !previous_separator {
                    slug.push(c);
                }
                previous_separator = true;
            } else {
                slug.push(c);
                previous_separator = false;
            }
        }
        let slug = slug.trim_matches('-').to_owned();

        if slug.len() < MIN_NAME_LEN {
            return Err(InvalidName::TooShort);
        }
        if slug.len() > MAX_NAME_LEN {
            return Err(InvalidName::TooLong);
        }
        Ok(Self(slug))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ServiceName {
    type Error = InvalidName;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ServiceName> for String {
    fn from(name: ServiceName) -> Self {
        name.0
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidName {
    #[error("a service name must be at least {MIN_NAME_LEN} characters")]
    TooShort,
    #[error("a service name must be at most {MAX_NAME_LEN} characters")]
    TooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_normalised_to_a_slug() {
        assert_eq!(
            ServiceName::parse("Billing API").unwrap().as_str(),
            "billing-api"
        );
        assert_eq!(
            ServiceName::parse("  user_service  ").unwrap().as_str(),
            "user-service"
        );
        assert_eq!(
            ServiceName::parse("OrderService").unwrap().as_str(),
            "orderservice"
        );
    }

    #[test]
    fn repeated_separators_collapse() {
        assert_eq!(
            ServiceName::parse("billing___api").unwrap().as_str(),
            "billing-api"
        );
        assert_eq!(ServiceName::parse("-billing-").unwrap().as_str(), "billing");
    }

    #[test]
    fn the_same_name_always_normalises_identically() {
        let a = ServiceName::parse("Billing API").unwrap();
        let b = ServiceName::parse("billing-api").unwrap();
        let c = ServiceName::parse("BILLING_API").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn names_must_be_long_enough() {
        assert_eq!(ServiceName::parse("ab").unwrap_err(), InvalidName::TooShort);
        assert!(ServiceName::parse("abc").is_ok());
    }

    #[test]
    fn names_must_be_bounded() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        assert_eq!(ServiceName::parse(&long).unwrap_err(), InvalidName::TooLong);
    }

    #[test]
    fn a_name_of_pure_punctuation_is_rejected() {
        assert!(ServiceName::parse("---").is_err());
        assert!(ServiceName::parse("   ").is_err());
    }

    #[test]
    fn non_ascii_is_collapsed_to_separators() {
        // The service is "bills" plus a non-latin word, which normalises away.
        assert_eq!(ServiceName::parse("bills 平台").unwrap().as_str(), "bills");
    }

    #[test]
    fn status_round_trips_through_json() {
        let json = serde_json::to_string(&Status::Active).unwrap();
        assert_eq!(json, "\"active\"");
        assert_eq!(
            serde_json::from_str::<Status>("\"disabled\"").unwrap(),
            Status::Disabled
        );
    }
}
