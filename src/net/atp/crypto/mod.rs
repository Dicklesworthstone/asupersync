//! ATP encryption module for policy-driven encryption with verification transparency.
//!
//! This module implements encryption transforms for ATP objects while maintaining
//! clear verification boundaries and relay/mailbox privacy semantics. Supports
//! object-level encryption domains with capability-based access control.
//!
//! Key design principles:
//! - Encryption domains define privacy boundaries
//! - Relay and mailbox privacy levels are explicitly specified
//! - Key rotation and object-level grants are supported
//! - Metadata leakage is explicitly documented
//! - Verification boundaries are preserved across transforms

use crate::atp::manifest::{
    EncryptionAlgorithm, EncryptionDomain, EncryptionMetadata, EncryptionPolicy, KeyDerivation,
    KeyDerivationFunction, ObjectKind, PrivacyLevel, TransformOrder, TransformType,
};
use std::collections::BTreeMap;

pub mod policy;

pub use policy::*;

/// Encryption result with metadata for verification.
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptionResult {
    /// Encrypted data.
    pub ciphertext: Vec<u8>,
    /// Encryption metadata for manifest.
    pub metadata: EncryptionMetadata,
    /// Original plaintext hash (for verification boundary).
    pub plaintext_hash: [u8; 32],
    /// Ciphertext hash.
    pub ciphertext_hash: [u8; 32],
    /// Authentication tag (if AEAD).
    pub auth_tag: Vec<u8>,
}

/// Decryption result with verification data.
#[derive(Debug, Clone, PartialEq)]
pub struct DecryptionResult {
    /// Decrypted plaintext.
    pub plaintext: Vec<u8>,
    /// Verified plaintext hash.
    pub plaintext_hash: [u8; 32],
    /// Whether authentication succeeded.
    pub authenticated: bool,
}

/// Encryption error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionError {
    /// Policy violation.
    PolicyViolation(String),
    /// Unsupported algorithm.
    UnsupportedAlgorithm(EncryptionAlgorithm),
    /// Encryption failed.
    EncryptionFailed(String),
    /// Decryption failed.
    DecryptionFailed(String),
    /// Key derivation failed.
    KeyDerivationFailed(String),
    /// Authentication failed.
    AuthenticationFailed,
    /// Invalid encryption metadata.
    InvalidMetadata(String),
    /// Invalid key material.
    InvalidKey(String),
    /// Transform order violation.
    TransformOrderViolation(String),
    /// Encryption domain violation.
    DomainViolation(String),
    /// Privacy level violation.
    PrivacyViolation(String),
    /// Metadata leakage violation.
    MetadataLeakage(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyViolation(msg) => write!(f, "encryption policy violation: {msg}"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported encryption algorithm: {alg:?}")
            }
            Self::EncryptionFailed(msg) => write!(f, "encryption failed: {msg}"),
            Self::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            Self::KeyDerivationFailed(msg) => write!(f, "key derivation failed: {msg}"),
            Self::AuthenticationFailed => write!(f, "authentication failed"),
            Self::InvalidMetadata(msg) => write!(f, "invalid encryption metadata: {msg}"),
            Self::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            Self::TransformOrderViolation(msg) => write!(f, "transform order violation: {msg}"),
            Self::DomainViolation(msg) => write!(f, "encryption domain violation: {msg}"),
            Self::PrivacyViolation(msg) => write!(f, "privacy level violation: {msg}"),
            Self::MetadataLeakage(msg) => write!(f, "metadata leakage: {msg}"),
        }
    }
}

impl std::error::Error for EncryptionError {}

/// Key material for encryption operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMaterial {
    /// Encryption key bytes.
    pub key: Vec<u8>,
    /// Key identifier for rotation.
    pub key_id: String,
    /// Key version for rotation tracking.
    pub version: u32,
    /// Key derivation information.
    pub derivation: KeyDerivation,
}

impl KeyMaterial {
    /// Create new key material with derivation.
    pub fn new(key: Vec<u8>, key_id: String, version: u32, derivation: KeyDerivation) -> Self {
        Self {
            key,
            key_id,
            version,
            derivation,
        }
    }

    /// Validate key material for algorithm.
    pub fn validate_for_algorithm(
        &self,
        algorithm: EncryptionAlgorithm,
    ) -> Result<(), EncryptionError> {
        let expected_key_size = match algorithm {
            EncryptionAlgorithm::None => 0,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32, // 256-bit key
            EncryptionAlgorithm::Aes256Gcm => 32,        // 256-bit key
        };

        if self.key.len() != expected_key_size {
            return Err(EncryptionError::InvalidKey(format!(
                "expected {expected_key_size} bytes, got {}",
                self.key.len()
            )));
        }

        Ok(())
    }
}

/// ATP encryption engine with policy enforcement.
pub struct EncryptionEngine;

impl EncryptionEngine {
    const CHACHA20POLY1305_NONCE_LEN: usize = 12;
    const CHACHA20POLY1305_TAG_LEN: usize = 16;
    const AES256GCM_NONCE_LEN: usize = 12;
    const AES256GCM_TAG_LEN: usize = 16;

    /// Apply encryption according to policy and domain.
    pub fn encrypt(
        data: &[u8],
        object_kind: ObjectKind,
        policy: &EncryptionPolicy,
        domain: Option<&EncryptionDomain>,
        key_material: &KeyMaterial,
        transform_order: Option<&TransformOrder>,
    ) -> Result<EncryptionResult, EncryptionError> {
        // Validate encryption is allowed for this object kind
        if !policy.apply_to_kinds.contains(&object_kind) {
            return Err(EncryptionError::PolicyViolation(format!(
                "encryption not allowed for object kind {object_kind:?}"
            )));
        }

        // Validate encryption domain if specified
        if let Some(domain) = domain {
            Self::validate_domain_compatibility(policy, domain)?;
        }

        // Validate transform order if specified
        if let Some(order) = transform_order {
            Self::validate_transform_position(order)?;
        }

        // Validate key material
        key_material.validate_for_algorithm(policy.algorithm)?;

        // Compute plaintext hash before encryption
        let plaintext_hash = Self::compute_hash(data);

        // Apply encryption
        let (ciphertext, auth_tag, metadata) = match policy.algorithm {
            EncryptionAlgorithm::None => (
                data.to_vec(),
                vec![],
                EncryptionMetadata {
                    algorithm: EncryptionAlgorithm::None,
                    iv: vec![],
                    auth_tag: vec![],
                    key_derivation: key_material.derivation.clone(),
                },
            ),
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                Self::encrypt_chacha20poly1305(data, key_material)?
            }
            EncryptionAlgorithm::Aes256Gcm => Self::encrypt_aes256gcm(data, key_material)?,
        };

        // Compute ciphertext hash
        let ciphertext_hash = Self::compute_hash(&ciphertext);

        Ok(EncryptionResult {
            ciphertext,
            metadata,
            plaintext_hash,
            ciphertext_hash,
            auth_tag,
        })
    }

    /// Decrypt data according to metadata.
    pub fn decrypt(
        ciphertext: &[u8],
        metadata: &EncryptionMetadata,
        key_material: &KeyMaterial,
    ) -> Result<DecryptionResult, EncryptionError> {
        // Validate key material
        key_material.validate_for_algorithm(metadata.algorithm)?;

        // Validate key derivation matches
        if key_material.derivation != metadata.key_derivation {
            return Err(EncryptionError::KeyDerivationFailed(
                "key derivation mismatch".to_string(),
            ));
        }

        let (plaintext, authenticated) = match metadata.algorithm {
            EncryptionAlgorithm::None => (ciphertext.to_vec(), true),
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                Self::decrypt_chacha20poly1305(ciphertext, metadata, key_material)?
            }
            EncryptionAlgorithm::Aes256Gcm => {
                Self::decrypt_aes256gcm(ciphertext, metadata, key_material)?
            }
        };

        let plaintext_hash = Self::compute_hash(&plaintext);

        Ok(DecryptionResult {
            plaintext,
            plaintext_hash,
            authenticated,
        })
    }

    /// Check if encryption is enabled for object type in policy.
    pub fn is_encryption_enabled(policy: &EncryptionPolicy, object_kind: ObjectKind) -> bool {
        !matches!(policy.algorithm, EncryptionAlgorithm::None)
            && policy.apply_to_kinds.contains(&object_kind)
    }

    /// Validate domain compatibility with policy.
    fn validate_domain_compatibility(
        policy: &EncryptionPolicy,
        domain: &EncryptionDomain,
    ) -> Result<(), EncryptionError> {
        // Check if KDF is allowed in domain
        if !domain.allowed_kdfs.contains(&policy.key_derivation.kdf) {
            return Err(EncryptionError::DomainViolation(format!(
                "KDF {:?} not allowed in domain {}",
                policy.key_derivation.kdf, domain.domain_id
            )));
        }

        Ok(())
    }

    /// Validate transform position in the transform order.
    fn validate_transform_position(
        transform_order: &TransformOrder,
    ) -> Result<(), EncryptionError> {
        let encryption_pos = transform_order
            .transforms
            .iter()
            .position(|&t| t == TransformType::Encryption);

        if let Some(pos) = encryption_pos {
            // Encryption should come after compression and chunking
            if let Some(comp_pos) = transform_order
                .transforms
                .iter()
                .position(|&t| t == TransformType::Compression)
            {
                if pos <= comp_pos {
                    return Err(EncryptionError::TransformOrderViolation(
                        "encryption must come after compression".to_string(),
                    ));
                }
            }

            if let Some(chunk_pos) = transform_order
                .transforms
                .iter()
                .position(|&t| t == TransformType::Chunking)
            {
                if pos <= chunk_pos {
                    return Err(EncryptionError::TransformOrderViolation(
                        "encryption must come after chunking".to_string(),
                    ));
                }
            }

            // Encryption should come before error correction
            if let Some(ec_pos) = transform_order
                .transforms
                .iter()
                .position(|&t| t == TransformType::ErrorCorrection)
            {
                if pos >= ec_pos {
                    return Err(EncryptionError::TransformOrderViolation(
                        "encryption must come before error correction".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Generate secure random IV/nonce.
    fn generate_iv(size: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut iv = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut iv);
        iv
    }

    /// Compute SHA-256 hash.
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Encrypt using ChaCha20Poly1305 AEAD.
    fn encrypt_chacha20poly1305(
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>, EncryptionMetadata), EncryptionError> {
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};

        let cipher = ChaCha20Poly1305::new_from_slice(&key_material.key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let nonce_bytes = Self::generate_iv(Self::CHACHA20POLY1305_NONCE_LEN);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let metadata = EncryptionMetadata {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            iv: nonce_bytes,
            auth_tag: tag.to_vec(),
            key_derivation: key_material.derivation.clone(),
        };

        Ok((buffer, tag.to_vec(), metadata))
    }

    /// Decrypt using ChaCha20Poly1305 AEAD.
    fn decrypt_chacha20poly1305(
        ciphertext: &[u8],
        metadata: &EncryptionMetadata,
        key_material: &KeyMaterial,
    ) -> Result<(Vec<u8>, bool), EncryptionError> {
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};

        let cipher = ChaCha20Poly1305::new_from_slice(&key_material.key)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        if metadata.iv.len() != Self::CHACHA20POLY1305_NONCE_LEN {
            return Err(EncryptionError::InvalidMetadata(format!(
                "ChaCha20-Poly1305 nonce must be {} bytes, got {}",
                Self::CHACHA20POLY1305_NONCE_LEN,
                metadata.iv.len(),
            )));
        }
        if metadata.auth_tag.len() != Self::CHACHA20POLY1305_TAG_LEN {
            return Err(EncryptionError::InvalidMetadata(format!(
                "ChaCha20-Poly1305 auth tag must be {} bytes, got {}",
                Self::CHACHA20POLY1305_TAG_LEN,
                metadata.auth_tag.len(),
            )));
        }

        let nonce = Nonce::from_slice(&metadata.iv);
        let tag = Tag::from_slice(&metadata.auth_tag);

        let mut buffer = ciphertext.to_vec();
        match cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag) {
            Ok(()) => Ok((buffer, true)),
            Err(_) => Err(EncryptionError::AuthenticationFailed),
        }
    }

    /// Encrypt using AES-256-GCM AEAD.
    fn encrypt_aes256gcm(
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>, EncryptionMetadata), EncryptionError> {
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let cipher = Aes256Gcm::new_from_slice(&key_material.key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let nonce_bytes = Self::generate_iv(Self::AES256GCM_NONCE_LEN);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let metadata = EncryptionMetadata {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            iv: nonce_bytes,
            auth_tag: tag.to_vec(),
            key_derivation: key_material.derivation.clone(),
        };

        Ok((buffer, tag.to_vec(), metadata))
    }

    /// Decrypt using AES-256-GCM AEAD.
    fn decrypt_aes256gcm(
        ciphertext: &[u8],
        metadata: &EncryptionMetadata,
        key_material: &KeyMaterial,
    ) -> Result<(Vec<u8>, bool), EncryptionError> {
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce, Tag};

        let cipher = Aes256Gcm::new_from_slice(&key_material.key)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        if metadata.iv.len() != Self::AES256GCM_NONCE_LEN {
            return Err(EncryptionError::InvalidMetadata(format!(
                "AES-256-GCM nonce must be {} bytes, got {}",
                Self::AES256GCM_NONCE_LEN,
                metadata.iv.len(),
            )));
        }
        if metadata.auth_tag.len() != Self::AES256GCM_TAG_LEN {
            return Err(EncryptionError::InvalidMetadata(format!(
                "AES-256-GCM auth tag must be {} bytes, got {}",
                Self::AES256GCM_TAG_LEN,
                metadata.auth_tag.len(),
            )));
        }

        let nonce = Nonce::from_slice(&metadata.iv);
        let tag = Tag::from_slice(&metadata.auth_tag);

        let mut buffer = ciphertext.to_vec();
        match cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag) {
            Ok(()) => Ok((buffer, true)),
            Err(_) => Err(EncryptionError::AuthenticationFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_material_validation() {
        let key = vec![0u8; 32]; // 256-bit key
        let derivation = KeyDerivation {
            kdf: KeyDerivationFunction::Direct,
            salt: vec![],
            iterations: None,
        };

        let key_material = KeyMaterial::new(key, "test-key".to_string(), 1, derivation);

        assert!(key_material
            .validate_for_algorithm(EncryptionAlgorithm::ChaCha20Poly1305)
            .is_ok());
        assert!(key_material
            .validate_for_algorithm(EncryptionAlgorithm::Aes256Gcm)
            .is_ok());

        // Wrong key size
        let bad_key_material = KeyMaterial::new(
            vec![0u8; 16], // Too small
            "test-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );

        assert!(matches!(
            bad_key_material.validate_for_algorithm(EncryptionAlgorithm::ChaCha20Poly1305),
            Err(EncryptionError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let test_data = b"Hello, world! This is a test string for encryption.";
        let key_material = KeyMaterial::new(
            vec![1u8; 32], // Test key
            "test-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );

        let policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: key_material.derivation.clone(),
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let result = EncryptionEngine::encrypt(
            test_data,
            ObjectKind::FileObject,
            &policy,
            None,
            &key_material,
            None,
        )
        .unwrap();

        assert_eq!(
            result.metadata.algorithm,
            EncryptionAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(result.metadata.iv.len(), 12); // ChaCha20Poly1305 nonce size
        assert!(!result.auth_tag.is_empty());

        let decrypted =
            EncryptionEngine::decrypt(&result.ciphertext, &result.metadata, &key_material).unwrap();

        assert_eq!(decrypted.plaintext, test_data);
        assert!(decrypted.authenticated);
    }

    #[test]
    fn test_aes256gcm_roundtrip() {
        let test_data = b"authenticated AES-256-GCM payload";
        let key_material = KeyMaterial::new(
            vec![9u8; 32],
            "aes-test-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );

        let policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            key_derivation: key_material.derivation.clone(),
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let result = EncryptionEngine::encrypt(
            test_data,
            ObjectKind::FileObject,
            &policy,
            None,
            &key_material,
            None,
        )
        .unwrap();

        assert_eq!(result.metadata.algorithm, EncryptionAlgorithm::Aes256Gcm);
        assert_eq!(
            result.metadata.iv.len(),
            EncryptionEngine::AES256GCM_NONCE_LEN
        );
        assert_eq!(result.auth_tag.len(), EncryptionEngine::AES256GCM_TAG_LEN);
        assert_ne!(result.ciphertext, test_data);

        let decrypted =
            EncryptionEngine::decrypt(&result.ciphertext, &result.metadata, &key_material).unwrap();

        assert_eq!(decrypted.plaintext, test_data);
        assert!(decrypted.authenticated);
    }

    #[test]
    fn aes256gcm_decrypt_rejects_tampered_ciphertext() {
        let test_data = b"tamper-resistant payload";
        let key_material = KeyMaterial::new(
            vec![9u8; 32],
            "aes-test-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );
        let policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            key_derivation: key_material.derivation.clone(),
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let mut result = EncryptionEngine::encrypt(
            test_data,
            ObjectKind::FileObject,
            &policy,
            None,
            &key_material,
            None,
        )
        .unwrap();
        result.ciphertext[0] ^= 0x80;

        let err = EncryptionEngine::decrypt(&result.ciphertext, &result.metadata, &key_material)
            .unwrap_err();

        assert_eq!(err, EncryptionError::AuthenticationFailed);
    }

    #[test]
    fn chacha20poly1305_decrypt_rejects_malformed_nonce_lengths() {
        let test_data = b"metadata length validation";
        let key_material = KeyMaterial::new(
            vec![1u8; 32],
            "test-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );
        let policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: key_material.derivation.clone(),
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let result = EncryptionEngine::encrypt(
            test_data,
            ObjectKind::FileObject,
            &policy,
            None,
            &key_material,
            None,
        )
        .unwrap();

        for invalid_nonce in [Vec::new(), vec![0u8; 11], vec![0u8; 13]] {
            let mut metadata = result.metadata.clone();
            metadata.iv = invalid_nonce;

            let err = EncryptionEngine::decrypt(&result.ciphertext, &metadata, &key_material)
                .unwrap_err();

            assert!(matches!(err, EncryptionError::InvalidMetadata(_)));
        }
    }

    #[test]
    fn chacha20poly1305_decrypt_rejects_malformed_auth_tag_lengths() {
        let test_data = b"metadata length validation";
        let key_material = KeyMaterial::new(
            vec![1u8; 32],
            "test-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );
        let policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: key_material.derivation.clone(),
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let result = EncryptionEngine::encrypt(
            test_data,
            ObjectKind::FileObject,
            &policy,
            None,
            &key_material,
            None,
        )
        .unwrap();

        for invalid_tag in [Vec::new(), vec![0u8; 15], vec![0u8; 17]] {
            let mut metadata = result.metadata.clone();
            metadata.auth_tag = invalid_tag;

            let err = EncryptionEngine::decrypt(&result.ciphertext, &metadata, &key_material)
                .unwrap_err();

            assert!(matches!(err, EncryptionError::InvalidMetadata(_)));
        }
    }

    #[test]
    fn test_encryption_disabled_for_wrong_object_kind() {
        let test_data = b"Hello, world!";
        let key_material = KeyMaterial::new(
            vec![1u8; 32],
            "test-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );

        let policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: key_material.derivation.clone(),
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let result = EncryptionEngine::encrypt(
            test_data,
            ObjectKind::Directory, // Not in apply_to_kinds
            &policy,
            None,
            &key_material,
            None,
        );

        assert!(matches!(result, Err(EncryptionError::PolicyViolation(_))));
    }
}
