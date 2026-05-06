//! Cryptographic primitives for Ferrox.
//!
//! ## SSE-S3 (AES-256-GCM)
//!
//! Encryption model:
//! - A **Key Encryption Key** (KEK) is derived from the configured 32-byte master
//!   key and is the same for every object on a given server.
//! - A fresh 32-byte **Data Encryption Key** (DEK) is randomly generated per
//!   `put`.  The DEK is wrapped (encrypted) with the KEK using AES-256-GCM and
//!   stored alongside the object as hex-encoded metadata.
//! - Object data is encrypted under the DEK.  Both the wrapped DEK and the
//!   ciphertext carry their own random 96-bit nonces prepended to the data.
//!
//! Wire format (on disk):
//! - Object ciphertext blob: `nonce (12 B) || ciphertext || GCM tag (16 B)`.
//! - Encrypted DEK blob (hex):
//!   `nonce (12 B) || encrypted DEK (32 B) || GCM tag (16 B)` = 60 B = 120 hex chars.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod sse_c;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ferrox_error::FerroxError;

pub use crate::sse_c::CustomerKey;

/// A 32-byte Key Encryption Key used to wrap per-object DEKs.
///
/// Constructed from the server's configured master key (e.g. from an env var or
/// config file).  Must not be stored inside any object.
///
/// # Example
///
/// ```
/// use ferrox_crypto::SseMasterKey;
/// let key = SseMasterKey::from_hex(
///     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
/// ).unwrap();
/// ```
#[derive(Clone)]
pub struct SseMasterKey([u8; 32]);

impl std::fmt::Debug for SseMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SseMasterKey(<redacted>)")
    }
}

impl SseMasterKey {
    /// Construct from a raw 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse from a 64-char lowercase hex string.
    pub fn from_hex(s: &str) -> Result<Self, FerroxError> {
        let bytes = hex::decode(s)
            .map_err(|e| FerroxError::InvalidRequest(format!("bad sse master key hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| FerroxError::InvalidRequest("sse master key must be 32 bytes".into()))?;
        Ok(Self(arr))
    }
}

/// Encrypt `plaintext` under a freshly generated DEK, wrapping the DEK with
/// `kek`.
///
/// Returns `(ciphertext_blob, encrypted_dek_hex)`.
///
/// - `ciphertext_blob` = `nonce (12 B) || ciphertext || GCM tag (16 B)`.
/// - `encrypted_dek_hex` = hex of `nonce (12 B) || encrypted DEK (32 B) || tag (16 B)`.
pub fn encrypt(kek: &SseMasterKey, plaintext: &[u8]) -> Result<(Vec<u8>, String), FerroxError> {
    // Generate a fresh DEK.
    let dek_bytes = Aes256Gcm::generate_key(OsRng);

    // Encrypt the plaintext under the DEK.
    let data_cipher = Aes256Gcm::new(&dek_bytes);
    let data_nonce = Aes256Gcm::generate_nonce(OsRng);
    let mut ciphertext_blob = data_nonce.to_vec();
    let ciphertext = data_cipher
        .encrypt(&data_nonce, plaintext)
        .map_err(|e| FerroxError::Internal(format!("SSE-S3 encrypt failed: {e}")))?;
    ciphertext_blob.extend_from_slice(&ciphertext);

    // Wrap the DEK with the KEK.
    let kek_key = Key::<Aes256Gcm>::from_slice(&kek.0);
    let kek_cipher = Aes256Gcm::new(kek_key);
    let kek_nonce = Aes256Gcm::generate_nonce(OsRng);
    let mut encrypted_dek = kek_nonce.to_vec();
    let wrapped = kek_cipher
        .encrypt(&kek_nonce, dek_bytes.as_slice())
        .map_err(|e| FerroxError::Internal(format!("SSE-S3 DEK wrap failed: {e}")))?;
    encrypted_dek.extend_from_slice(&wrapped);

    Ok((ciphertext_blob, hex::encode(encrypted_dek)))
}

/// Decrypt `ciphertext_blob` using the DEK unwrapped from `encrypted_dek_hex`
/// via `kek`.
///
/// `ciphertext_blob` must be in the format produced by [`encrypt`].
pub fn decrypt(
    kek: &SseMasterKey,
    ciphertext_blob: &[u8],
    encrypted_dek_hex: &str,
) -> Result<Vec<u8>, FerroxError> {
    // Unwrap the DEK.
    let encrypted_dek = hex::decode(encrypted_dek_hex)
        .map_err(|e| FerroxError::Internal(format!("SSE-S3 bad encrypted DEK hex: {e}")))?;
    if encrypted_dek.len() < 12 {
        return Err(FerroxError::Internal(
            "SSE-S3 encrypted DEK too short".into(),
        ));
    }
    let kek_nonce = Nonce::from_slice(&encrypted_dek[..12]);
    let kek_key = Key::<Aes256Gcm>::from_slice(&kek.0);
    let kek_cipher = Aes256Gcm::new(kek_key);
    let dek_bytes = kek_cipher
        .decrypt(kek_nonce, &encrypted_dek[12..])
        .map_err(|e| FerroxError::Internal(format!("SSE-S3 DEK unwrap failed: {e}")))?;

    // Decrypt the ciphertext.
    if ciphertext_blob.len() < 12 {
        return Err(FerroxError::Internal("SSE-S3 ciphertext too short".into()));
    }
    let data_nonce = Nonce::from_slice(&ciphertext_blob[..12]);
    let dek_key = Key::<Aes256Gcm>::from_slice(&dek_bytes);
    let data_cipher = Aes256Gcm::new(dek_key);
    data_cipher
        .decrypt(data_nonce, &ciphertext_blob[12..])
        .map_err(|e| FerroxError::Internal(format!("SSE-S3 decrypt failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SseMasterKey {
        SseMasterKey::new([0xABu8; 32])
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let kek = test_key();
        let plaintext = b"hello, SSE-S3!";
        let (ciphertext, dek_hex) = encrypt(&kek, plaintext).unwrap();
        let recovered = decrypt(&kek, &ciphertext, &dek_hex).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let kek = test_key();
        let plain = b"secret data";
        let (ct, _) = encrypt(&kek, plain).unwrap();
        assert_ne!(ct, plain.as_slice());
    }

    #[test]
    fn test_wrong_kek_returns_error() {
        let kek = test_key();
        let (ct, dek_hex) = encrypt(&kek, b"data").unwrap();
        let wrong_kek = SseMasterKey::new([0x00u8; 32]);
        assert!(decrypt(&wrong_kek, &ct, &dek_hex).is_err());
    }

    #[test]
    fn test_from_hex_bad_length_returns_error() {
        assert!(SseMasterKey::from_hex("deadbeef").is_err());
    }

    #[test]
    fn test_from_hex_invalid_chars_returns_error() {
        assert!(SseMasterKey::from_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn test_each_encrypt_produces_unique_ciphertext() {
        let kek = test_key();
        let plain = b"same plaintext";
        let (ct1, _) = encrypt(&kek, plain).unwrap();
        let (ct2, _) = encrypt(&kek, plain).unwrap();
        // Different nonces → different ciphertexts.
        assert_ne!(ct1, ct2);
    }
}
