//! `spectre-vault`: import, storage, and at-rest encryption for spectre-upgrade.
//!
//! The vault holds site metadata plus the handful of stored ("stateful")
//! secrets. It is encrypted on disk with a key derived from the Spectre master
//! key (see [`crypto`]). This crate does no derivation itself; callers pass the
//! already-derived 64-byte master key.

mod crypto;
mod mpjson;
mod models;

pub use models::{Site, User, Vault, STATEFUL_CLASS};
pub use mpjson::{export_mpjson_string, import_mpjson, import_mpjson_str};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

/// Errors from vault operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("decryption failed (wrong master password or corrupted vault)")]
    Decrypt,
    #[error("unsupported vault file: {0}")]
    Format(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

const MAGIC: &str = "spectre-upgrade-vault";
const VERSION: u32 = 1;

/// On-disk wrapper. Only non-secret metadata and the base64 ciphertext are
/// stored in the clear.
#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    magic: String,
    version: u32,
    cipher: String,
    kdf: String,
    nonce: String,
    ciphertext: String,
}

impl Vault {
    /// Serialize and encrypt the vault into the on-disk file bytes.
    pub fn to_encrypted_bytes(&self, master_key: &[u8; 64]) -> Result<Vec<u8>> {
        let mut plaintext = serde_json::to_vec(self)?;
        let (nonce, ciphertext) = crypto::encrypt(master_key, &plaintext);
        plaintext.zeroize();

        let file = EncryptedFile {
            magic: MAGIC.to_string(),
            version: VERSION,
            cipher: "xchacha20poly1305".to_string(),
            kdf: "hkdf-sha256(scrypt-v3-masterkey)".to_string(),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        };

        Ok(serde_json::to_vec_pretty(&file)?)
    }

    /// Decrypt and deserialize a vault from on-disk file bytes.
    pub fn from_encrypted_bytes(bytes: &[u8], master_key: &[u8; 64]) -> Result<Vault> {
        let file: EncryptedFile = serde_json::from_slice(bytes)?;

        if file.magic != MAGIC {
            return Err(VaultError::Format(format!("not a vault file (magic {})", file.magic)));
        }

        if file.version != VERSION {
            return Err(VaultError::Format(format!("unsupported version {}", file.version)));
        }

        let nonce = STANDARD.decode(file.nonce.as_bytes())?;
        let ciphertext = STANDARD.decode(file.ciphertext.as_bytes())?;
        let mut plaintext = crypto::decrypt(master_key, &nonce, &ciphertext)?;

        let vault: Vault = serde_json::from_slice(&plaintext)?;
        plaintext.zeroize();

        Ok(vault)
    }

    /// Encrypt and write the vault to `path`.
    pub fn save_encrypted(&self, path: impl AsRef<Path>, master_key: &[u8; 64]) -> Result<()> {
        let bytes = self.to_encrypted_bytes(master_key)?;
        std::fs::write(path, bytes)?;

        Ok(())
    }

    /// Read and decrypt a vault from `path`.
    pub fn load_encrypted(path: impl AsRef<Path>, master_key: &[u8; 64]) -> Result<Vault> {
        let bytes = std::fs::read(path)?;

        Vault::from_encrypted_bytes(&bytes, master_key)
    }

    /// Record a use of `site`: bump the counter and set the last-used timestamp.
    /// The caller supplies the timestamp (ISO-8601) so this crate stays free of
    /// a wall-clock dependency.
    pub fn mark_used(&mut self, site: &str, now_iso: &str) {
        if let Some(entry) = self.sites.get_mut(site) {
            entry.uses = entry.uses.saturating_add(1);
            entry.last_used = now_iso.to_string();
        }
    }

    /// Iterate the stored ("stateful") sites that cannot be derived.
    pub fn stateful_sites(&self) -> impl Iterator<Item = (&String, &Site)> {
        self.sites.iter().filter(|(_, site)| site.is_stateful())
    }
}
