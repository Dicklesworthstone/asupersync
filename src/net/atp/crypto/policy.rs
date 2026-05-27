//! Encryption policy enforcement and validation for ATP-C4.
//!
//! This module implements policy-driven encryption decisions with explicit
//! privacy boundaries and relay/mailbox visibility controls.

use super::EncryptionError;
use crate::atp::manifest::{
    EncryptionAlgorithm, EncryptionDomain, EncryptionPolicy, KeyDerivation, KeyDerivationFunction,
    ObjectKind, PrivacyLevel,
};
use std::collections::BTreeMap;

/// Policy-driven encryption decision engine.
pub struct EncryptionPolicyEngine;

impl EncryptionPolicyEngine {
    /// Create a default encryption policy for standard ATP usage.
    pub fn default_policy() -> EncryptionPolicy {
        EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: KeyDerivation {
                kdf: KeyDerivationFunction::HkdfSha256,
                salt: b"atp-default-salt-32-bytes-long!!".to_vec(),
                iterations: None,
            },
            apply_to_kinds: vec![ObjectKind::FileObject, ObjectKind::ContentAddressedBlob],
            encrypt_metadata: false,
        }
    }

    /// Create a disabled encryption policy (no encryption).
    pub fn disabled_policy() -> EncryptionPolicy {
        EncryptionPolicy {
            algorithm: EncryptionAlgorithm::None,
            key_derivation: KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
            apply_to_kinds: vec![],
            encrypt_metadata: false,
        }
    }

    /// Create a high-security policy for sensitive data.
    pub fn high_security_policy() -> EncryptionPolicy {
        EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: KeyDerivation {
                kdf: KeyDerivationFunction::Argon2id,
                salt: b"atp-high-security-salt-32-bytes!".to_vec(),
                iterations: Some(100_000),
            },
            apply_to_kinds: vec![
                ObjectKind::FileObject,
                ObjectKind::ContentAddressedBlob,
                ObjectKind::StreamObject,
                ObjectKind::Directory,
            ],
            encrypt_metadata: true,
        }
    }

    /// Validate encryption policy for ATP-C4 compliance.
    pub fn validate_policy(policy: &EncryptionPolicy) -> Result<(), EncryptionError> {
        // Validate key derivation parameters
        Self::validate_key_derivation(&policy.key_derivation)?;

        // Validate algorithm support
        if !Self::is_algorithm_supported(policy.algorithm) {
            return Err(EncryptionError::UnsupportedAlgorithm(policy.algorithm));
        }

        // Validate object kinds consistency
        if matches!(policy.algorithm, EncryptionAlgorithm::None)
            && !policy.apply_to_kinds.is_empty()
        {
            return Err(EncryptionError::PolicyViolation(
                "none algorithm should have empty apply_to_kinds".to_string(),
            ));
        }

        // Validate metadata encryption consistency
        if policy.encrypt_metadata && matches!(policy.algorithm, EncryptionAlgorithm::None) {
            return Err(EncryptionError::PolicyViolation(
                "cannot encrypt metadata with none algorithm".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate key derivation parameters.
    fn validate_key_derivation(kd: &KeyDerivation) -> Result<(), EncryptionError> {
        match kd.kdf {
            KeyDerivationFunction::Direct => {
                if !kd.salt.is_empty() {
                    return Err(EncryptionError::KeyDerivationFailed(
                        "direct KDF should not have salt".to_string(),
                    ));
                }
                if kd.iterations.is_some() {
                    return Err(EncryptionError::KeyDerivationFailed(
                        "direct KDF should not have iterations".to_string(),
                    ));
                }
            }
            KeyDerivationFunction::Pbkdf2Sha256 => {
                if kd.salt.len() < 8 {
                    return Err(EncryptionError::KeyDerivationFailed(
                        "PBKDF2 salt must be at least 8 bytes".to_string(),
                    ));
                }
                let iterations = kd.iterations.unwrap_or(0);
                if iterations < 1000 {
                    return Err(EncryptionError::KeyDerivationFailed(
                        "PBKDF2 must have at least 1000 iterations".to_string(),
                    ));
                }
            }
            KeyDerivationFunction::Argon2id => {
                if kd.salt.len() < 16 {
                    return Err(EncryptionError::KeyDerivationFailed(
                        "Argon2id salt must be at least 16 bytes".to_string(),
                    ));
                }
                let iterations = kd.iterations.unwrap_or(0);
                if iterations < 1 || iterations > 1_000_000 {
                    return Err(EncryptionError::KeyDerivationFailed(
                        "Argon2id iterations must be 1-1,000,000".to_string(),
                    ));
                }
            }
            KeyDerivationFunction::HkdfSha256 => {
                if kd.salt.len() < 8 {
                    return Err(EncryptionError::KeyDerivationFailed(
                        "HKDF salt must be at least 8 bytes".to_string(),
                    ));
                }
                if kd.iterations.is_some() {
                    return Err(EncryptionError::KeyDerivationFailed(
                        "HKDF should not have iterations".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Check if encryption algorithm is supported.
    fn is_algorithm_supported(algorithm: EncryptionAlgorithm) -> bool {
        match algorithm {
            EncryptionAlgorithm::None => true,
            EncryptionAlgorithm::ChaCha20Poly1305 => true,
            EncryptionAlgorithm::Aes256Gcm => true,
        }
    }

    /// Check if encryption should be applied for a given object.
    pub fn should_encrypt(policy: &EncryptionPolicy, object_kind: ObjectKind) -> bool {
        // Never encrypt if algorithm is None
        if matches!(policy.algorithm, EncryptionAlgorithm::None) {
            return false;
        }

        // Check if object kind is allowed
        policy.apply_to_kinds.contains(&object_kind)
    }

    /// Create encryption domain for relay privacy.
    pub fn relay_privacy_domain() -> EncryptionDomain {
        EncryptionDomain {
            domain_id: "relay-privacy".to_string(),
            allowed_kdfs: vec![
                KeyDerivationFunction::HkdfSha256,
                KeyDerivationFunction::Argon2id,
            ],
            relay_privacy: true,
            mailbox_privacy: false,
        }
    }

    /// Create encryption domain for mailbox privacy.
    pub fn mailbox_privacy_domain() -> EncryptionDomain {
        EncryptionDomain {
            domain_id: "mailbox-privacy".to_string(),
            allowed_kdfs: vec![KeyDerivationFunction::Argon2id],
            relay_privacy: true,
            mailbox_privacy: true,
        }
    }

    /// Create encryption domain for end-to-end privacy.
    pub fn e2e_privacy_domain() -> EncryptionDomain {
        EncryptionDomain {
            domain_id: "e2e-privacy".to_string(),
            allowed_kdfs: vec![
                KeyDerivationFunction::Direct,
                KeyDerivationFunction::HkdfSha256,
                KeyDerivationFunction::Argon2id,
            ],
            relay_privacy: true,
            mailbox_privacy: true,
        }
    }

    /// Validate privacy level against encryption policy.
    pub fn validate_privacy_level(
        policy: &EncryptionPolicy,
        privacy_level: PrivacyLevel,
    ) -> Result<(), EncryptionError> {
        let has_encryption = !matches!(policy.algorithm, EncryptionAlgorithm::None);

        match privacy_level {
            PrivacyLevel::Public => {
                if has_encryption {
                    return Err(EncryptionError::PrivacyViolation(
                        "public privacy level inconsistent with encryption".to_string(),
                    ));
                }
            }
            PrivacyLevel::MetadataVisible => {
                if !has_encryption {
                    return Err(EncryptionError::PrivacyViolation(
                        "metadata-visible privacy level requires encryption".to_string(),
                    ));
                }
                if policy.encrypt_metadata {
                    return Err(EncryptionError::MetadataLeakage(
                        "metadata encryption conflicts with metadata-visible privacy".to_string(),
                    ));
                }
            }
            PrivacyLevel::SizeVisible => {
                if !has_encryption {
                    return Err(EncryptionError::PrivacyViolation(
                        "size-visible privacy level requires encryption".to_string(),
                    ));
                }
            }
            PrivacyLevel::FullPrivacy => {
                if !has_encryption {
                    return Err(EncryptionError::PrivacyViolation(
                        "full privacy level requires encryption".to_string(),
                    ));
                }
                if !policy.encrypt_metadata {
                    return Err(EncryptionError::MetadataLeakage(
                        "full privacy requires metadata encryption".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get recommended domains for privacy level.
    pub fn recommended_domains_for_privacy(privacy_level: PrivacyLevel) -> Vec<EncryptionDomain> {
        match privacy_level {
            PrivacyLevel::Public => vec![],
            PrivacyLevel::MetadataVisible => vec![Self::relay_privacy_domain()],
            PrivacyLevel::SizeVisible => vec![Self::mailbox_privacy_domain()],
            PrivacyLevel::FullPrivacy => vec![Self::e2e_privacy_domain()],
        }
    }
}

/// Encryption capability grant for object-level access control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionGrant {
    /// Grant identifier.
    pub grant_id: String,
    /// Object or object pattern this grant applies to.
    pub object_pattern: String,
    /// Granted capabilities.
    pub capabilities: Vec<EncryptionCapability>,
    /// Grant expiration (nanoseconds since epoch).
    pub expires_at: Option<u64>,
    /// Grant constraints.
    pub constraints: BTreeMap<String, String>,
}

/// Encryption capability types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncryptionCapability {
    /// Can encrypt objects.
    Encrypt,
    /// Can decrypt objects.
    Decrypt,
    /// Can rotate keys for objects.
    KeyRotation,
    /// Can grant capabilities to others.
    Grant,
    /// Can revoke capabilities.
    Revoke,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_validation() {
        let policy = EncryptionPolicyEngine::default_policy();
        assert!(EncryptionPolicyEngine::validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_disabled_policy() {
        let policy = EncryptionPolicyEngine::disabled_policy();
        assert!(EncryptionPolicyEngine::validate_policy(&policy).is_ok());

        // Should never encrypt with disabled policy
        assert!(!EncryptionPolicyEngine::should_encrypt(
            &policy,
            ObjectKind::FileObject,
        ));
    }

    #[test]
    fn test_high_security_policy() {
        let policy = EncryptionPolicyEngine::high_security_policy();
        assert!(EncryptionPolicyEngine::validate_policy(&policy).is_ok());

        // Should encrypt all object types
        assert!(EncryptionPolicyEngine::should_encrypt(
            &policy,
            ObjectKind::FileObject,
        ));
        assert!(EncryptionPolicyEngine::should_encrypt(
            &policy,
            ObjectKind::Directory,
        ));
    }

    #[test]
    fn test_policy_validation_errors() {
        // Invalid KDF parameters
        let bad_policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation: KeyDerivation {
                kdf: KeyDerivationFunction::Pbkdf2Sha256,
                salt: vec![1, 2, 3],   // Too short
                iterations: Some(500), // Too few
            },
            apply_to_kinds: vec![ObjectKind::FileObject],
            encrypt_metadata: false,
        };

        assert!(matches!(
            EncryptionPolicyEngine::validate_policy(&bad_policy),
            Err(EncryptionError::KeyDerivationFailed(_))
        ));

        // Inconsistent none algorithm
        let inconsistent_policy = EncryptionPolicy {
            algorithm: EncryptionAlgorithm::None,
            key_derivation: KeyDerivation {
                kdf: KeyDerivationFunction::Direct,
                salt: vec![],
                iterations: None,
            },
            apply_to_kinds: vec![ObjectKind::FileObject], // Shouldn't have kinds for None
            encrypt_metadata: false,
        };

        assert!(matches!(
            EncryptionPolicyEngine::validate_policy(&inconsistent_policy),
            Err(EncryptionError::PolicyViolation(_))
        ));
    }

    #[test]
    fn test_privacy_level_validation() {
        let encrypted_policy = EncryptionPolicyEngine::default_policy();
        let disabled_policy = EncryptionPolicyEngine::disabled_policy();

        // Public privacy with encryption should fail
        assert!(matches!(
            EncryptionPolicyEngine::validate_privacy_level(&encrypted_policy, PrivacyLevel::Public),
            Err(EncryptionError::PrivacyViolation(_))
        ));

        // Metadata visible without encryption should fail
        assert!(matches!(
            EncryptionPolicyEngine::validate_privacy_level(
                &disabled_policy,
                PrivacyLevel::MetadataVisible
            ),
            Err(EncryptionError::PrivacyViolation(_))
        ));

        // Valid combinations
        assert!(EncryptionPolicyEngine::validate_privacy_level(
            &disabled_policy,
            PrivacyLevel::Public
        )
        .is_ok());
        assert!(EncryptionPolicyEngine::validate_privacy_level(
            &encrypted_policy,
            PrivacyLevel::MetadataVisible
        )
        .is_ok());
    }

    #[test]
    fn test_encryption_domains() {
        let relay_domain = EncryptionPolicyEngine::relay_privacy_domain();
        assert_eq!(relay_domain.domain_id, "relay-privacy");
        assert!(relay_domain.relay_privacy);
        assert!(!relay_domain.mailbox_privacy);

        let e2e_domain = EncryptionPolicyEngine::e2e_privacy_domain();
        assert_eq!(e2e_domain.domain_id, "e2e-privacy");
        assert!(e2e_domain.relay_privacy);
        assert!(e2e_domain.mailbox_privacy);
    }
}
