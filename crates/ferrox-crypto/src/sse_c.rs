//! SSE-C: caller-supplied AES-256-GCM keys.
//!
//! The customer key is supplied per request via three headers:
//! - `x-amz-server-side-encryption-customer-algorithm: AES256`
//! - `x-amz-server-side-encryption-customer-key: base64(32-byte key)`
//! - `x-amz-server-side-encryption-customer-key-MD5: base64(md5(key))`
//!
//! The raw key is **never** stored, logged, or returned. Instead, an
//! HMAC-SHA256 of the key is persisted with each object so subsequent reads
//! can verify the same key was supplied.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ferrox_error::FerroxError;
use hmac::{Hmac, Mac};
use md5::Digest as _;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain-separation salt for the SSE-C key fingerprint HMAC.
const FINGERPRINT_SALT: &[u8] = b"ferrox.sse-c.fingerprint.v1";

/// 32-byte caller-supplied key. Auto-zeroes on drop. Never `Display`-able.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CustomerKey([u8; 32]);

impl std::fmt::Debug for CustomerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustomerKey(<redacted>)")
    }
}

impl CustomerKey {
    /// Decode a base64 key and verify the supplied MD5 matches.
    ///
    /// Returns `InvalidRequest` (→ HTTP 400) if either header is malformed,
    /// the key isn't 32 bytes, or MD5 mismatches. The raw bytes are zeroed
    /// when the returned value is dropped.
    pub fn from_headers(key_b64: &str, key_md5_b64: &str) -> Result<Self, FerroxError> {
        let key_bytes = B64
            .decode(key_b64.as_bytes())
            .map_err(|_| FerroxError::InvalidRequest("SSE-C key not valid base64".into()))?;
        if key_bytes.len() != 32 {
            return Err(FerroxError::InvalidRequest(format!(
                "SSE-C key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }
        let supplied_md5 = B64
            .decode(key_md5_b64.as_bytes())
            .map_err(|_| FerroxError::InvalidRequest("SSE-C key-MD5 not valid base64".into()))?;
        let computed = md5::Md5::digest(&key_bytes);
        if computed.as_slice() != supplied_md5.as_slice() {
            // Defensive: zero the buffer before returning the error.
            let mut z = key_bytes;
            z.zeroize();
            return Err(FerroxError::InvalidRequest(
                "SSE-C key-MD5 does not match supplied key".into(),
            ));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&key_bytes);
        Ok(Self(buf))
    }

    /// Hex-encoded HMAC-SHA256 of the key (used to verify the same key is
    /// presented on subsequent GETs). Constant length, never reveals the key.
    pub fn fingerprint(&self) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(FINGERPRINT_SALT)
            .expect("HMAC accepts any key length");
        mac.update(&self.0);
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Encrypt `plaintext` with the customer key. Returns `nonce || ciphertext || tag`.
pub fn encrypt(key: &CustomerKey, plaintext: &[u8]) -> Result<Vec<u8>, FerroxError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| FerroxError::Internal(format!("SSE-C encrypt failed: {e}")))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `nonce || ciphertext || tag` blob with the customer key.
pub fn decrypt(key: &CustomerKey, blob: &[u8]) -> Result<Vec<u8>, FerroxError> {
    if blob.len() < 12 {
        return Err(FerroxError::Internal("SSE-C ciphertext too short".into()));
    }
    let nonce = Nonce::from_slice(&blob[..12]);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|_| FerroxError::AuthFailed("SSE-C key does not match stored object".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_key_headers() -> (String, String) {
        let key = [0x42u8; 32];
        let md5 = md5::Md5::digest(key);
        (B64.encode(key), B64.encode(md5))
    }

    #[test]
    fn test_from_headers_valid_round_trip() {
        let (k_b64, md5_b64) = good_key_headers();
        let ck = CustomerKey::from_headers(&k_b64, &md5_b64).unwrap();
        let ct = encrypt(&ck, b"secret").unwrap();
        let pt = decrypt(&ck, &ct).unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn test_wrong_md5_rejected() {
        let (k_b64, _) = good_key_headers();
        let bad = B64.encode([0xffu8; 16]);
        assert!(CustomerKey::from_headers(&k_b64, &bad).is_err());
    }

    #[test]
    fn test_short_key_rejected() {
        let key = [0x01u8; 16];
        let md5 = md5::Md5::digest(key);
        assert!(CustomerKey::from_headers(&B64.encode(key), &B64.encode(md5)).is_err());
    }

    #[test]
    fn test_decrypt_with_different_key_fails() {
        let key1 = CustomerKey([0x11u8; 32]);
        let key2 = CustomerKey([0x22u8; 32]);
        let ct = encrypt(&key1, b"data").unwrap();
        assert!(decrypt(&key2, &ct).is_err());
    }

    #[test]
    fn test_fingerprint_stable_for_same_key() {
        let k1 = CustomerKey([0x77u8; 32]);
        let k2 = CustomerKey([0x77u8; 32]);
        assert_eq!(k1.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn test_debug_does_not_leak_key() {
        let k = CustomerKey([0xAAu8; 32]);
        let dbg = format!("{:?}", k);
        assert!(!dbg.contains("AA"), "debug must not leak bytes");
    }
}
