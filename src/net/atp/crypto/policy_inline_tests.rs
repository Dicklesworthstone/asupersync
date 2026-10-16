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
            ObjectKind::DirectoryObject,
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
        let metadata_encrypted_policy = EncryptionPolicyEngine::high_security_policy();
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

        // Size-visible privacy hides metadata while still exposing size.
        assert!(matches!(
            EncryptionPolicyEngine::validate_privacy_level(
                &encrypted_policy,
                PrivacyLevel::SizeVisible
            ),
            Err(EncryptionError::MetadataLeakage(_))
        ));

        // Valid combinations
        assert!(
            EncryptionPolicyEngine::validate_privacy_level(&disabled_policy, PrivacyLevel::Public)
                .is_ok()
        );
        assert!(
            EncryptionPolicyEngine::validate_privacy_level(
                &encrypted_policy,
                PrivacyLevel::MetadataVisible
            )
            .is_ok()
        );
        assert!(
            EncryptionPolicyEngine::validate_privacy_level(
                &metadata_encrypted_policy,
                PrivacyLevel::SizeVisible
            )
            .is_ok()
        );
        assert!(
            EncryptionPolicyEngine::validate_privacy_level(
                &metadata_encrypted_policy,
                PrivacyLevel::FullPrivacy
            )
            .is_ok()
        );
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
