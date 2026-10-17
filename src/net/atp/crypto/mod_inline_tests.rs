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
