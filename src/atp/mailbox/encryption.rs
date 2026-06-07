//! ATP Mailbox Encryption - Cryptographic primitives for secure mailbox operations.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

const MAILBOX_AEAD_AAD: &[u8] = b"atp-mailbox-v1";

/// Encryption key for mailbox operations.
#[derive(Clone)]
pub struct MailboxKey {
    /// Key material for AES-256-GCM.
    key_material: [u8; 32],
}

impl MailboxKey {
    /// Generate a new random mailbox key.
    #[must_use]
    pub fn generate() -> Self {
        let mut key_material = [0u8; 32];
        getrandom::fill(&mut key_material).expect("OS entropy unavailable for mailbox key");
        Self { key_material }
    }

    /// Create key from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key_material: bytes,
        }
    }

    /// Get key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key_material
    }
}

impl fmt::Debug for MailboxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxKey")
            .field("key_material", &"[redacted]")
            .finish()
    }
}

impl Drop for MailboxKey {
    fn drop(&mut self) {
        self.key_material.zeroize();
    }
}

/// Encrypted chunk of data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedChunk {
    /// Encrypted data
    pub data: Vec<u8>,

    /// Nonce used for encryption
    pub nonce: ChunkNonce,

    /// Authentication tag
    pub tag: [u8; 16],
}

/// Nonce for chunk encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkNonce {
    /// Nonce bytes
    pub bytes: [u8; 12],
}

impl ChunkNonce {
    /// Generate a new random nonce.
    pub fn generate() -> Result<Self, String> {
        let mut bytes = [0u8; 12];
        getrandom::fill(&mut bytes)
            .map_err(|err| format!("OS entropy unavailable for mailbox nonce: {err}"))?;
        Ok(Self { bytes })
    }
}

impl EncryptedChunk {
    /// Encrypt data with the given key.
    pub fn encrypt(data: &[u8], key: &MailboxKey) -> Result<Self, String> {
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|err| format!("invalid mailbox key: {err}"))?;
        let nonce = ChunkNonce::generate()?;
        let mut encrypted = data.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce.bytes),
                MAILBOX_AEAD_AAD,
                &mut encrypted,
            )
            .map_err(|err| format!("mailbox encryption failed: {err}"))?;
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());

        Ok(Self {
            data: encrypted,
            nonce,
            tag: tag_bytes,
        })
    }

    /// Decrypt chunk with the given key.
    pub fn decrypt(&self, key: &MailboxKey) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce, Tag};

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|err| format!("invalid mailbox key: {err}"))?;
        let mut decrypted = self.data.clone();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.nonce.bytes),
                MAILBOX_AEAD_AAD,
                &mut decrypted,
                Tag::from_slice(&self.tag),
            )
            .map_err(|_| "mailbox authentication failed".to_string())?;
        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mailbox_key_generation() {
        let key = MailboxKey::generate();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn mailbox_key_debug_redacts_key_material() {
        let key = MailboxKey::from_bytes([0xab; 32]);
        let debug = format!("{key:?}");

        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("abababab"));
    }

    #[test]
    fn test_encryption_roundtrip() {
        let key = MailboxKey::generate();
        let data = b"test data";

        let encrypted = EncryptedChunk::encrypt(data, &key).unwrap();
        let decrypted = encrypted.decrypt(&key).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_chunk_nonce_generation() {
        let nonce = ChunkNonce::generate().unwrap();
        assert_eq!(nonce.bytes.len(), 12);
    }
}
