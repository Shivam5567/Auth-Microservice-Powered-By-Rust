use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Number of random bytes behind each refresh token. 32 bytes = 256 bits,
/// which is far beyond the point of brute-force resistance.
const TOKEN_ENTROPY_BYTES: usize = 32;

/// A refresh token and the digest persisted alongside it.
pub struct IssuedRefreshToken {
    /// The value handed to the client. Never stored.
    pub token: String,
    /// SHA-256 of `token`, stored in `refresh_tokens.token_hash`.
    pub hash: Vec<u8>,
}

/// Generates a fresh opaque refresh token and its storage digest.
///
/// These are deliberately *not* JWTs. Keeping the refresh token opaque is
/// what makes server-side rotation, revocation and reuse detection possible;
/// a self-contained token could not be withdrawn before it expires.
pub fn generate() -> IssuedRefreshToken {
    let mut raw = [0u8; TOKEN_ENTROPY_BYTES];
    OsRng.fill_bytes(&mut raw);

    let token = URL_SAFE_NO_PAD.encode(raw);
    let hash = digest(&token);
    IssuedRefreshToken { token, hash }
}

/// The digest used to look a token up by its exact value.
pub fn digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn tokens_carry_256_bits_of_entropy() {
        let issued = generate();
        // 32 bytes base64url without padding is 43 characters.
        assert_eq!(issued.token.len(), 43);
        assert_eq!(issued.hash.len(), 32);
    }

    #[test]
    fn tokens_are_url_safe_and_unpadded() {
        let issued = generate();
        assert!(!issued.token.contains('='), "padding breaks header transport");
        assert!(
            issued
                .token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn the_stored_digest_is_the_digest_of_the_token() {
        let issued = generate();
        assert_eq!(issued.hash, digest(&issued.token));
    }

    #[test]
    fn the_plaintext_token_is_not_recoverable_from_the_digest() {
        let issued = generate();
        assert!(!issued.hash.windows(issued.token.len()).any(|w| w == issued.token.as_bytes()));
    }

    #[test]
    fn generated_tokens_do_not_collide() {
        let tokens: HashSet<String> = (0..1_000).map(|_| generate().token).collect();
        assert_eq!(tokens.len(), 1_000);
    }

    #[test]
    fn digests_differ_for_different_tokens() {
        assert_ne!(digest("a"), digest("b"));
        assert_eq!(digest("a"), digest("a"));
    }
}
