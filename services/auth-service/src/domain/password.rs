use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::AppError;

/// OWASP-recommended Argon2id parameters: 19 MiB of memory, 2 iterations,
/// 1 degree of parallelism. The defaults bundled with the crate use only
/// 16 KiB, which is far too weak for password storage.
const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

fn hasher() -> Result<Argon2<'static>, AppError> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .map_err(|e| AppError::internal(format!("invalid argon2 params: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::internal(format!("password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verifies a password against a stored PHC string.
///
/// A malformed stored hash yields `false` rather than an error, because for
/// the caller the two cases are indistinguishable and both mean "no match".
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    hasher()
        .and_then(|h| {
            h.verify_password(password.as_bytes(), &parsed)
                .map_err(|e| AppError::internal(format!("password verification failed: {e}")))
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_verifies_against_its_own_password() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
    }

    #[test]
    fn a_wrong_password_does_not_verify() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(!verify_password("Correct horse battery staple", &hash));
        assert!(!verify_password("", &hash));
    }

    #[test]
    fn hashes_are_salted_so_equal_passwords_differ() {
        let a = hash_password("same-password").unwrap();
        let b = hash_password("same-password").unwrap();
        assert_ne!(a, b, "identical passwords must not produce identical hashes");
        assert!(verify_password("same-password", &a));
        assert!(verify_password("same-password", &b));
    }

    #[test]
    fn stored_hash_records_the_argon2id_parameters() {
        let hash = hash_password("x").unwrap();
        assert!(hash.starts_with("$argon2id$"), "got: {hash}");
        assert!(hash.contains("m=19456"), "memory cost not recorded: {hash}");
    }

    #[test]
    fn a_corrupt_stored_hash_fails_closed() {
        assert!(!verify_password("anything", "not-a-phc-string"));
        assert!(!verify_password("anything", ""));
    }
}
