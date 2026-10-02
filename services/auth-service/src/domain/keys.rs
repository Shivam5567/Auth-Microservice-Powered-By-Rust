use std::fs;
use std::path::Path;

use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::error::AppError;

const RSA_BITS: usize = 2048;

/// The RSA keypair used to sign and verify access tokens.
///
/// Only the private key can mint tokens; the public half is what other
/// services in the platform need in order to verify them.
pub struct SigningKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    kid: String,
}

impl SigningKeys {
    /// Loads the keypair from disk, generating and persisting one on first run.
    ///
    /// Persisting matters: a freshly generated key on every boot would
    /// silently invalidate every token already in circulation.
    pub fn load_or_generate(
        private_path: &Path,
        public_path: &Path,
    ) -> Result<Self, AppError> {
        if !private_path.exists() {
            generate_keypair(private_path, public_path)?;
        }

        let private_pem = fs::read_to_string(private_path).map_err(|e| {
            AppError::internal(format!("cannot read {}: {e}", private_path.display()))
        })?;
        let public_pem = fs::read_to_string(public_path).map_err(|e| {
            AppError::internal(format!("cannot read {}: {e}", public_path.display()))
        })?;

        Self::from_pem(&private_pem, &public_pem)
    }

    pub fn from_pem(private_pem: &str, public_pem: &str) -> Result<Self, AppError> {
        let encoding = EncodingKey::from_rsa_pem(private_pem)
            .map_err(|e| AppError::internal(format!("invalid private key: {e}")))?;
        let decoding = DecodingKey::from_rsa_pem(public_pem)
            .map_err(|e| AppError::internal(format!("invalid public key: {e}")))?;

        // The key id is a digest of the public key, so rotating the keypair
        // automatically produces a distinct `kid` for downstream caches.
        let kid = hex(&Sha256::digest(public_pem.as_bytes())[..16]);

        Ok(Self {
            encoding,
            decoding,
            kid,
        })
    }

    pub fn encoding(&self) -> &EncodingKey {
        &self.encoding
    }

    pub fn decoding(&self) -> &DecodingKey {
        &self.decoding
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }
}

fn generate_keypair(private_path: &Path, public_path: &Path) -> Result<(), AppError> {
    let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, RSA_BITS)
        .map_err(|e| AppError::internal(format!("RSA key generation failed: {e}")))?;
    let public = RsaPublicKey::from(&private);

    if let Some(parent) = private_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            AppError::internal(format!("cannot create {}: {e}", parent.display()))
        })?;
    }

    // PKCS#1 for the private key, SPKI for the public key: these are the two
    // encodings `jsonwebtoken` accepts for RSA.
    fs::write(private_path, private.to_pkcs1_pem(LineEnding::LF).as_bytes())
        .map_err(|e| AppError::internal(format!("cannot write {}: {e}", private_path.display())))?;
    fs::write(
        public_path,
        public
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| AppError::internal(format!("cannot encode public key: {e}")))?,
    )
    .map_err(|e| AppError::internal(format!("cannot write {}: {e}", public_path.display())))?;

    tracing::warn!(
        private = %private_path.display(),
        public = %public_path.display(),
        "generated a new RSA signing keypair; mount persistent keys in production so \
         tokens survive restarts"
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generating an RSA-2048 key is slow even with the dev profile tweak, so
    /// the generated key is shared across the tests in this module.
    static KEYPAIR: std::sync::LazyLock<(String, String)> = std::sync::LazyLock::new(|| {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, RSA_BITS).unwrap();
        let public = RsaPublicKey::from(&private);
        (
            private.to_pkcs1_pem(LineEnding::LF).unwrap().to_string(),
            public.to_public_key_pem(LineEnding::LF).unwrap(),
        )
    });

    #[test]
    fn both_pem_encodings_are_accepted_by_the_jwt_library() {
        let (private, public) = &*KEYPAIR;
        assert!(SigningKeys::from_pem(private, public).is_ok());
    }

    #[test]
    fn key_id_is_derived_from_the_public_key() {
        let (private, public) = &*KEYPAIR;
        let a = SigningKeys::from_pem(private, public).unwrap();
        let b = SigningKeys::from_pem(private, public).unwrap();
        assert_eq!(a.kid(), b.kid());
        assert_eq!(a.kid().len(), 32);
    }

    #[test]
    fn the_key_id_changes_when_the_keypair_changes() {
        let (private, public) = &*KEYPAIR;
        let other_private = RsaPrivateKey::new(&mut rand::rngs::OsRng, RSA_BITS).unwrap();
        let other_public = RsaPublicKey::from(&other_private)
            .to_public_key_pem(LineEnding::LF)
            .unwrap();

        let original = SigningKeys::from_pem(private, public).unwrap();
        let rotated = SigningKeys::from_pem(private, &other_public).unwrap();
        assert_ne!(original.kid(), rotated.kid());
    }
}
