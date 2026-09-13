//! At-rest encryption for the vault.
//!
//! The vault key is derived from the 64-byte Spectre master key via HKDF-SHA256
//! (a distinct info string, so it never equals the master key itself), then used
//! with XChaCha20-Poly1305. A fresh 24-byte random nonce is generated per write.

use crate::VaultError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const HKDF_INFO: &[u8] = b"spectre-upgrade.vault.v1";

/// Length of the XChaCha20-Poly1305 nonce, in bytes.
pub const NONCE_LEN: usize = 24;

/// Derive the 32-byte vault key from the master key.
fn derive_key(master_key: &[u8; 64]) -> Key {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm).expect("32 is a valid HKDF length");

    let key = Key::clone_from_slice(&okm);
    okm.zeroize();

    key
}

/// Encrypt `plaintext`, returning the random nonce and ciphertext (with tag).
pub fn encrypt(master_key: &[u8; 64], plaintext: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let key = derive_key(master_key);
    let cipher = XChaCha20Poly1305::new(&key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).expect("system RNG available");
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("XChaCha20-Poly1305 encryption does not fail for valid input");

    (nonce_bytes, ciphertext)
}

/// Decrypt ciphertext produced by [`encrypt`]. Returns [`VaultError::Decrypt`]
/// on a wrong key or tampered data.
pub fn decrypt(
    master_key: &[u8; 64],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if nonce_bytes.len() != NONCE_LEN {
        return Err(VaultError::Format("invalid nonce length".to_string()));
    }

    let key = derive_key(master_key);
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Decrypt)
}
