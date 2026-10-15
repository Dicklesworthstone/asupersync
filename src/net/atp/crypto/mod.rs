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
    TransformOrder, TransformType,
};
use crate::atp::object::ObjectKind;

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
        // Validate the policy before any passthrough or domain decision can use it.
        EncryptionPolicyEngine::validate_policy(policy)?;

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
            Self::validate_transform_position(
                order,
                !matches!(policy.algorithm, EncryptionAlgorithm::None),
            )?;
        }

        // Validate key material
        key_material.validate_for_algorithm(policy.algorithm)?;
        Self::validate_key_derivation_match(policy, key_material)?;

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
        // Reject malformed metadata before trusting the declared algorithm.
        Self::validate_metadata_shape(metadata)?;

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

    fn validate_key_derivation_match(
        policy: &EncryptionPolicy,
        key_material: &KeyMaterial,
    ) -> Result<(), EncryptionError> {
        if key_material.derivation != policy.key_derivation {
            return Err(EncryptionError::KeyDerivationFailed(
                "key material derivation does not match encryption policy".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_metadata_shape(metadata: &EncryptionMetadata) -> Result<(), EncryptionError> {
        EncryptionPolicyEngine::validate_key_derivation(&metadata.key_derivation)?;

        match metadata.algorithm {
            EncryptionAlgorithm::None => {
                if !metadata.iv.is_empty() {
                    return Err(EncryptionError::InvalidMetadata(format!(
                        "none algorithm must not carry an IV, got {} bytes",
                        metadata.iv.len(),
                    )));
                }
                if !metadata.auth_tag.is_empty() {
                    return Err(EncryptionError::InvalidMetadata(format!(
                        "none algorithm must not carry an auth tag, got {} bytes",
                        metadata.auth_tag.len(),
                    )));
                }
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
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
            }
            EncryptionAlgorithm::Aes256Gcm => {
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
            }
        }

        Ok(())
    }

    /// Validate transform position in the transform order.
    fn validate_transform_position(
        transform_order: &TransformOrder,
        has_encryption: bool,
    ) -> Result<(), EncryptionError> {
        let encryption_pos = transform_order
            .transforms
            .iter()
            .position(|&t| t == TransformType::Encryption);

        if has_encryption != encryption_pos.is_some() {
            return Err(EncryptionError::TransformOrderViolation(
                "encryption presence doesn't match transform order".to_string(),
            ));
        }

        let Some(pos) = encryption_pos else {
            return Ok(());
        };

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

        Ok(())
    }

    /// Generate secure random IV/nonce.
    fn generate_iv(size: usize) -> Result<Vec<u8>, EncryptionError> {
        crate::util::check_ambient_entropy("atp-crypto-nonce");
        let mut iv = vec![0u8; size];
        getrandom::fill(&mut iv).map_err(|err| {
            EncryptionError::EncryptionFailed(format!("OS entropy unavailable for nonce: {err}"))
        })?;
        Ok(iv)
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
        use chacha20poly1305::aead::{AeadInOut, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = ChaCha20Poly1305::new_from_slice(&key_material.key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let nonce_bytes = Self::generate_iv(Self::CHACHA20POLY1305_NONCE_LEN)?;
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| EncryptionError::EncryptionFailed("invalid nonce length".to_string()))?;

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_inout_detached(&nonce, b"", buffer.as_mut_slice().into())
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
        use chacha20poly1305::aead::{AeadInOut, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};

        let cipher = ChaCha20Poly1305::new_from_slice(&key_material.key)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::try_from(metadata.iv.as_slice())
            .map_err(|_| EncryptionError::DecryptionFailed("invalid nonce length".to_string()))?;
        let tag = Tag::try_from(metadata.auth_tag.as_slice())
            .map_err(|_| EncryptionError::DecryptionFailed("invalid tag length".to_string()))?;

        let mut buffer = ciphertext.to_vec();
        match cipher.decrypt_inout_detached(&nonce, b"", buffer.as_mut_slice().into(), &tag) {
            Ok(()) => Ok((buffer, true)),
            Err(_) => Err(EncryptionError::AuthenticationFailed),
        }
    }

    /// Encrypt using AES-256-GCM AEAD.
    fn encrypt_aes256gcm(
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>, EncryptionMetadata), EncryptionError> {
        use aes_gcm::aead::{AeadInOut, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let cipher = Aes256Gcm::new_from_slice(&key_material.key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let nonce_bytes = Self::generate_iv(Self::AES256GCM_NONCE_LEN)?;
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| EncryptionError::EncryptionFailed("invalid nonce length".to_string()))?;

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_inout_detached(&nonce, b"", buffer.as_mut_slice().into())
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
        use aes_gcm::aead::{AeadInOut, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce, Tag};

        let cipher = Aes256Gcm::new_from_slice(&key_material.key)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::try_from(metadata.iv.as_slice())
            .map_err(|_| EncryptionError::DecryptionFailed("invalid nonce length".to_string()))?;
        let tag = Tag::try_from(metadata.auth_tag.as_slice())
            .map_err(|_| EncryptionError::DecryptionFailed("invalid tag length".to_string()))?;

        let mut buffer = ciphertext.to_vec();
        match cipher.decrypt_inout_detached(&nonce, b"", buffer.as_mut_slice().into(), &tag) {
            Ok(()) => Ok((buffer, true)),
            Err(_) => Err(EncryptionError::AuthenticationFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::KeyDerivationFunction;

    #[test]
    fn test_key_material_validation() {
        let key = vec![0u8; 32]; // 256-bit key
        let derivation = KeyDerivation {
            kdf: KeyDerivationFunction::Direct,
            salt: vec![],
            iterations: None,
        };

        let key_material = KeyMaterial::new(key, "test-key".to_string(), 1, derivation);

        assert!(
            key_material
                .validate_for_algorithm(EncryptionAlgorithm::ChaCha20Poly1305)
                .is_ok()
        );
        assert!(
            key_material
                .validate_for_algorithm(EncryptionAlgorithm::Aes256Gcm)
                .is_ok()
        );

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
    fn encrypt_rejects_key_derivation_that_differs_from_policy() {
        let test_data = b"policy derivation must match actual key material";
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
            key_derivation: KeyDerivation {
                kdf: KeyDerivationFunction::HkdfSha256,
                salt: b"policy-salt".to_vec(),
                iterations: None,
            },
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let result = EncryptionEngine::encrypt(
            test_data,
            ObjectKind::FileObject,
            &policy,
            Some(&EncryptionPolicyEngine::relay_privacy_domain()),
            &key_material,
            None,
        );

        assert!(matches!(
            result,
            Err(EncryptionError::KeyDerivationFailed(message))
                if message.contains("key material derivation")
        ));
    }

    #[test]
    fn encrypt_rejects_invalid_none_policy_before_passthrough() {
        let key_material = KeyMaterial::new(
            vec![],
            "no-encryption-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );

        let invalid_policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::None,
            key_derivation: key_material.derivation.clone(),
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        let result = EncryptionEngine::encrypt(
            b"must not silently pass through",
            ObjectKind::FileObject,
            &invalid_policy,
            None,
            &key_material,
            None,
        );

        assert!(matches!(result, Err(EncryptionError::PolicyViolation(_))));
    }

    #[test]
    fn encrypt_rejects_transform_order_that_omits_encryption() {
        use crate::atp::manifest::{
            HashPoint, PrivacyLevel, VerificationBoundary, VerificationLevel,
        };

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
        let transform_order = TransformOrder {
            transforms: vec![TransformType::Chunking],
            hash_point: HashPoint::Plaintext,
            verification_boundary: VerificationBoundary {
                relay_verifiable: VerificationLevel::TransferIntegrity,
                mailbox_verifiable: VerificationLevel::TransferIntegrity,
                e2e_verification_required: true,
                privacy_level: PrivacyLevel::MetadataVisible,
            },
        };

        let result = EncryptionEngine::encrypt(
            b"declared transform order must include encryption",
            ObjectKind::FileObject,
            &policy,
            None,
            &key_material,
            Some(&transform_order),
        );

        assert!(matches!(
            result,
            Err(EncryptionError::TransformOrderViolation(message))
                if message.contains("presence")
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
    fn decrypt_rejects_none_metadata_with_iv_or_auth_tag() {
        let key_material = KeyMaterial::new(
            vec![],
            "no-encryption-key".to_string(),
            1,
            KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
        );
        let valid_none_metadata = EncryptionMetadata {
            algorithm: EncryptionAlgorithm::None,
            iv: vec![],
            auth_tag: vec![],
            key_derivation: key_material.derivation.clone(),
        };

        for invalid_metadata in [
            EncryptionMetadata {
                iv: vec![1],
                ..valid_none_metadata.clone()
            },
            EncryptionMetadata {
                auth_tag: vec![1],
                ..valid_none_metadata
            },
        ] {
            let err = EncryptionEngine::decrypt(b"plaintext", &invalid_metadata, &key_material)
                .unwrap_err();

            assert!(matches!(err, EncryptionError::InvalidMetadata(_)));
        }
    }

    #[test]
    fn decrypt_rejects_malformed_metadata_key_derivation() {
        let malformed_derivation = KeyDerivation {
            kdf: KeyDerivationFunction::Direct,
            salt: b"direct-kdf-must-not-carry-salt".to_vec(),
            iterations: None,
        };
        let key_material = KeyMaterial::new(
            vec![],
            "malformed-metadata-key".to_string(),
            1,
            malformed_derivation.clone(),
        );
        let metadata = EncryptionMetadata {
            algorithm: EncryptionAlgorithm::None,
            iv: vec![],
            auth_tag: vec![],
            key_derivation: malformed_derivation,
        };

        let err = EncryptionEngine::decrypt(b"plaintext", &metadata, &key_material).unwrap_err();

        assert!(matches!(err, EncryptionError::KeyDerivationFailed(_)));
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
            ObjectKind::DirectoryObject, // Not in apply_to_kinds
            &policy,
            None,
            &key_material,
            None,
        );

        assert!(matches!(result, Err(EncryptionError::PolicyViolation(_))));
    }
}
