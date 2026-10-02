pub mod access_token;
pub mod claims;
pub mod keys;
pub mod password;
pub mod refresh_token;

/// Canonical form of an email address for storage and lookup.
///
/// Callers may send any casing, so normalising on the way in is what keeps a
/// single user from registering twice as `A@x.com` and `a@x.com`.
pub fn normalize_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_trimmed_and_lowercased() {
        assert_eq!(normalize_email("  Alice@Example.COM "), "alice@example.com");
        assert_eq!(normalize_email("ALICE@EXAMPLE.COM"), "alice@example.com");
    }

    #[test]
    fn normalisation_is_idempotent() {
        let once = normalize_email(" Bob@Example.com ");
        assert_eq!(normalize_email(&once), once);
    }
}
