use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::error::AppError;

const RSA_BITS: usize = 2048;

/// How long to wait for another process to finish publishing the key before
/// giving up. Generous, because RSA key generation on a loaded machine is slow.
const PUBLISH_WAIT: Duration = Duration::from_secs(30);
const PUBLISH_POLL: Duration = Duration::from_millis(50);

/// The RSA keypair used to sign and verify access tokens.
///
/// Only the private key can mint tokens; the public half is what other
/// services in the platform need in order to verify them.
pub struct SigningKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    kid: String,
    public_pem: String,
}

impl SigningKeys {
    /// Loads the signing key, generating and persisting one on first run.
    ///
    /// Persisting matters: a freshly generated key on every boot would silently
    /// invalidate every token already in circulation.
    ///
    /// The private key is the single source of truth. The public key is derived
    /// from it rather than trusted from a second file, so the two can never
    /// disagree. First-run generation is safe to race: creation uses
    /// `create_new`, so exactly one process writes the key and the rest wait for
    /// it and adopt what landed. Without that, replicas starting together on a
    /// shared volume would each mint their own key and invalidate one another's
    /// tokens.
    pub fn load_or_generate(private_path: &Path, public_path: &Path) -> Result<Self, AppError> {
        match fs::read_to_string(private_path) {
            Ok(pem) => {
                let keys = Self::from_private_pem(&pem)?;
                keys.publish_public(public_path);
                return Ok(keys);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::internal(format!(
                    "cannot read {}: {err}",
                    private_path.display()
                )));
            }
        }

        Self::create_private_key(private_path)?;
        let keys = Self::wait_for_key(private_path)?;
        keys.publish_public(public_path);
        Ok(keys)
    }

    /// Builds the key material from a PKCS#1 private key PEM, deriving the
    /// public half from it.
    pub fn from_private_pem(private_pem: &str) -> Result<Self, AppError> {
        let private =
            RsaPrivateKey::from_pkcs1_pem(private_pem).map_err(|e| invalid("private key", e))?;
        let public_pem = RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| invalid("public key", e))?;

        let encoding = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|e| invalid("private key", e))?;
        let decoding = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| invalid("public key", e))?;

        // The key id is a digest of the public key, so rotating the keypair
        // automatically produces a distinct `kid` for downstream caches.
        let kid = hex(&Sha256::digest(public_pem.as_bytes())[..16]);

        Ok(Self {
            encoding,
            decoding,
            kid,
            public_pem,
        })
    }

    /// Writes a brand new private key, but only if nobody else has yet.
    ///
    /// Returns without error when the key already exists; the caller re-reads
    /// in that case.
    fn create_private_key(path: &Path) -> Result<(), AppError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::internal(format!("cannot create {}: {e}", parent.display()))
            })?;
        }

        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, RSA_BITS)
            .map_err(|e| AppError::internal(format!("RSA key generation failed: {e}")))?;
        let pem = private
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| invalid("private key", e))?;

        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                file.write_all(pem.as_bytes()).map_err(|e| {
                    AppError::internal(format!("cannot write {}: {e}", path.display()))
                })?;
                tracing::warn!(
                    path = %path.display(),
                    "generated a new RSA signing key; mount persistent keys in production \
                     so tokens survive restarts"
                );
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(AppError::internal(format!(
                "cannot create {}: {err}",
                path.display()
            ))),
        }
    }

    /// Waits for a key to become readable, covering the case where another
    /// process won the race to create it.
    fn wait_for_key(path: &Path) -> Result<Self, AppError> {
        let deadline = std::time::Instant::now() + PUBLISH_WAIT;
        let mut last: Option<AppError> = None;

        while std::time::Instant::now() < deadline {
            match fs::read_to_string(path) {
                Ok(pem) => match Self::from_private_pem(&pem) {
                    Ok(keys) => return Ok(keys),
                    // A partially written file; keep waiting.
                    Err(err) => last = Some(err),
                },
                Err(err) => last = Some(AppError::internal(format!("cannot read key: {err}"))),
            }
            std::thread::sleep(PUBLISH_POLL);
        }

        Err(last.unwrap_or_else(|| {
            AppError::internal("timed out waiting for the signing key to be published")
        }))
    }

    /// Best-effort copy of the public key for other services to consume. A
    /// failure here is not fatal: the running service already holds the key.
    fn publish_public(&self, public_path: &Path) {
        if let Some(parent) = public_path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(err) = publish_atomically(public_path, self.public_pem.as_bytes()) {
            tracing::warn!(
                path = %public_path.display(),
                error = %err,
                "could not publish the public key for downstream services"
            );
        }
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

    /// The public key, for handing to other services that verify tokens.
    pub fn public_pem(&self) -> &str {
        &self.public_pem
    }
}

fn invalid(which: &str, err: impl std::fmt::Display) -> AppError {
    AppError::internal(format!("invalid {which}: {err}"))
}

/// Writes by renaming a fully written temporary file over the target, so a
/// reader never observes a partial file.
fn publish_atomically(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(&temp);

    fs::write(&temp, contents)?;
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&temp);
            // Losing the race is fine: the other writer's key is equivalent.
            if path.exists() { Ok(()) } else { Err(err) }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generating an RSA-2048 key is slow, so the generated key is shared
    /// across the tests in this module.
    static PRIVATE_PEM: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, RSA_BITS).unwrap();
        private.to_pkcs1_pem(LineEnding::LF).unwrap().to_string()
    });

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keys-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn both_pem_encodings_are_accepted_by_the_jwt_library() {
        assert!(SigningKeys::from_private_pem(&PRIVATE_PEM).is_ok());
    }

    #[test]
    fn key_id_is_derived_from_the_public_key() {
        let a = SigningKeys::from_private_pem(&PRIVATE_PEM).unwrap();
        let b = SigningKeys::from_private_pem(&PRIVATE_PEM).unwrap();
        assert_eq!(a.kid(), b.kid());
        assert_eq!(a.kid().len(), 32);
    }

    #[test]
    fn the_public_key_is_derived_not_trusted_from_disk() {
        let keys = SigningKeys::from_private_pem(&PRIVATE_PEM).unwrap();
        assert!(keys.public_pem().starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn the_key_id_changes_when_the_keypair_changes() {
        let other = RsaPrivateKey::new(&mut rand::rngs::OsRng, RSA_BITS)
            .unwrap()
            .to_pkcs1_pem(LineEnding::LF)
            .unwrap()
            .to_string();

        let original = SigningKeys::from_private_pem(&PRIVATE_PEM).unwrap();
        let rotated = SigningKeys::from_private_pem(&other).unwrap();
        assert_ne!(original.kid(), rotated.kid());
    }

    #[test]
    fn a_corrupt_key_is_rejected() {
        assert!(SigningKeys::from_private_pem("not a pem").is_err());
    }

    #[test]
    fn first_run_generates_a_persistable_keypair() {
        let dir = scratch_dir();
        let keys = SigningKeys::load_or_generate(&dir.join("private.pem"), &dir.join("public.pem"))
            .expect("generate keys");

        assert!(dir.join("private.pem").exists());
        assert!(dir.join("public.pem").exists());

        // A second load must reuse what is on disk.
        let again =
            SigningKeys::load_or_generate(&dir.join("private.pem"), &dir.join("public.pem"))
                .expect("reload keys");
        assert_eq!(keys.kid(), again.kid());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Concurrent first starts must converge on one keypair, otherwise each
    /// replica would invalidate the tokens the others just issued.
    #[test]
    fn concurrent_first_starts_agree_on_one_keypair() {
        let dir = scratch_dir();
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (p, q) = (dir.join("private.pem"), dir.join("public.pem"));
                std::thread::spawn(move || {
                    SigningKeys::load_or_generate(&p, &q).map(|k| k.kid().to_owned())
                })
            })
            .collect();

        let kids: Vec<String> = handles
            .into_iter()
            .map(|h| h.join().expect("thread").expect("keys loaded"))
            .collect();

        assert_eq!(
            kids.iter().collect::<std::collections::HashSet<_>>().len(),
            1,
            "every process must adopt the same key, got {kids:?}"
        );

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("read key dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left temp files: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
