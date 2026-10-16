    use super::*;

    fn initial_test_keys(base: u8) -> KeyMaterial {
        KeyMaterial::new(
            vec![base; INITIAL_KEY_LEN],
            vec![base.wrapping_add(1); INITIAL_IV_LEN],
            vec![base.wrapping_add(2); INITIAL_HP_KEY_LEN],
        )
    }

    fn traffic_test_keys(base: u8) -> KeyMaterial {
        KeyMaterial::new(
            vec![base; DEFAULT_TRAFFIC_KEY_LEN],
            vec![base.wrapping_add(1); DEFAULT_TRAFFIC_IV_LEN],
            vec![base.wrapping_add(2); DEFAULT_TRAFFIC_HP_KEY_LEN],
        )
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn key_material_debug_redacts_packet_protection_secrets() {
        let keys = KeyMaterial::new(vec![0x11; 16], vec![0x22; 12], vec![0x33; 16]);
        let raw_key_debug = format!("{:?}", keys.key);
        let raw_iv_debug = format!("{:?}", keys.iv);
        let raw_hp_key_debug = format!("{:?}", keys.hp_key);

        let debug = format!("{keys:?}");
        assert!(debug.contains("KeyMaterial"));
        assert!(debug.contains("key"));
        assert!(debug.contains("iv"));
        assert!(debug.contains("hp_key"));
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains(&raw_key_debug),
            "packet key leaked: {debug}"
        );
        assert!(!debug.contains(&raw_iv_debug), "packet IV leaked: {debug}");
        assert!(
            !debug.contains(&raw_hp_key_debug),
            "header protection key leaked: {debug}"
        );
    }

    #[test]
    fn key_schedule_debug_redacts_nested_key_material() {
        let mut schedule = KeySchedule::new();
        let local_keys = initial_test_keys(0x31);
        let remote_keys = initial_test_keys(0x71);
        let local_key_debug = format!("{:?}", local_keys.key);
        let remote_key_debug = format!("{:?}", remote_keys.key);
        let local_hp_key_debug = format!("{:?}", local_keys.hp_key);
        let remote_hp_key_debug = format!("{:?}", remote_keys.hp_key);

        schedule
            .install_initial_keys(local_keys, remote_keys)
            .expect("install initial keys");

        let debug = format!("{schedule:?}");
        assert!(debug.contains("KeySchedule"));
        assert!(debug.contains("current_keys"));
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains(&local_key_debug),
            "local packet key leaked through KeySchedule Debug: {debug}"
        );
        assert!(
            !debug.contains(&remote_key_debug),
            "remote packet key leaked through KeySchedule Debug: {debug}"
        );
        assert!(
            !debug.contains(&local_hp_key_debug),
            "local header-protection key leaked through KeySchedule Debug: {debug}"
        );
        assert!(
            !debug.contains(&remote_hp_key_debug),
            "remote header-protection key leaked through KeySchedule Debug: {debug}"
        );
    }

    #[test]
    fn hkdf_debug_redacts_pseudorandom_key() {
        let prk = vec![0xabu8; 32];
        let raw_prk_debug = format!("{prk:?}");
        let hkdf = HkdfSha256::from_prk(&prk).expect("valid prk");

        let debug = format!("{hkdf:?}");
        assert!(debug.contains("HkdfSha256"));
        assert!(debug.contains("prk"));
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains(&raw_prk_debug),
            "HKDF pseudorandom key leaked through Debug: {debug}"
        );
    }

    #[test]
    fn test_key_schedule_creation() {
        let schedule = KeySchedule::new();

        assert!(!schedule.keys_established(PacketSpace::Initial));
        assert!(!schedule.keys_established(PacketSpace::Handshake));
        assert!(!schedule.keys_established(PacketSpace::Application));
        assert_eq!(schedule.current_key_phase(), KeyPhase::INITIAL);
    }

    #[test]
    fn test_key_installation() {
        let mut schedule = KeySchedule::new();

        // Create non-zero test keys
        let local_keys = initial_test_keys(1);
        let remote_keys = initial_test_keys(4);

        assert!(
            schedule
                .install_initial_keys(local_keys, remote_keys)
                .is_ok()
        );
        assert!(schedule.keys_established(PacketSpace::Initial));
        assert!(schedule.local_keys(PacketSpace::Initial).is_some());
        assert!(schedule.remote_keys(PacketSpace::Initial).is_some());
    }

    #[test]
    fn test_zero_key_rejection() {
        let mut schedule = KeySchedule::new();

        // Zero keys should be rejected
        let zero_keys = KeyMaterial::zero(INITIAL_KEY_LEN, INITIAL_IV_LEN);
        let non_zero_keys = initial_test_keys(1);

        assert!(
            schedule
                .install_initial_keys(zero_keys, non_zero_keys)
                .is_err()
        );
    }

    #[test]
    fn test_initial_install_rejects_wrong_key_lengths() {
        let mut schedule = KeySchedule::new();

        let traffic_sized_keys = traffic_test_keys(1);
        let initial_keys = initial_test_keys(4);

        assert!(
            schedule
                .install_initial_keys(traffic_sized_keys, initial_keys)
                .is_err()
        );
    }

    #[test]
    fn test_application_install_rejects_wrong_key_lengths() {
        let mut schedule = KeySchedule::new();

        let initial_sized_keys = initial_test_keys(1);
        let traffic_keys = traffic_test_keys(4);

        assert!(
            schedule
                .install_application_keys(initial_sized_keys, traffic_keys)
                .is_err()
        );
    }

    #[test]
    fn test_key_update_lifecycle() {
        let mut schedule = KeySchedule::new();

        // Install 1-RTT keys first
        let local_keys = KeyMaterial::new(vec![1u8; 32], vec![2u8; 12], vec![3u8; 32]);
        let remote_keys = KeyMaterial::new(vec![4u8; 32], vec![5u8; 12], vec![6u8; 32]);
        schedule
            .install_application_keys(local_keys, remote_keys)
            .unwrap();

        assert_eq!(schedule.current_key_phase(), KeyPhase::INITIAL);
        assert!(!schedule.key_update_pending());

        // Initiate key update with traffic secrets
        let local_traffic_secret = vec![0x10u8; 32];
        let remote_traffic_secret = vec![0x20u8; 32];
        assert!(
            schedule
                .initiate_key_update(&local_traffic_secret, &remote_traffic_secret)
                .is_ok()
        );
        assert!(schedule.key_update_pending());

        // Commit key update
        assert!(schedule.commit_key_update().is_ok());
        assert_eq!(schedule.current_key_phase(), KeyPhase(1));
        assert!(!schedule.key_update_pending());
        assert_eq!(schedule.key_update_count(), 1);
    }

    #[test]
    fn test_key_discard_rules() {
        let mut schedule = KeySchedule::new();

        let initial_local_keys = initial_test_keys(1);
        let initial_remote_keys = initial_test_keys(4);
        let local_keys = traffic_test_keys(7);
        let remote_keys = traffic_test_keys(10);

        // Install all keys
        schedule
            .install_initial_keys(initial_local_keys, initial_remote_keys)
            .unwrap();
        schedule
            .install_handshake_keys(local_keys.clone(), remote_keys.clone())
            .unwrap();
        schedule
            .install_application_keys(local_keys, remote_keys)
            .unwrap();

        // Initial keys can be discarded after handshake keys are established
        assert!(schedule.can_discard_initial_keys());

        // Handshake keys can be discarded after 1-RTT keys are established
        assert!(schedule.can_discard_handshake_keys());

        // Test actual discard
        assert!(schedule.discard_keys(PacketSpace::Initial).is_ok());
        assert!(!schedule.keys_established(PacketSpace::Initial));

        assert!(schedule.discard_keys(PacketSpace::Handshake).is_ok());
        assert!(!schedule.keys_established(PacketSpace::Handshake));

        // Cannot discard 1-RTT keys
        assert!(schedule.discard_keys(PacketSpace::Application).is_err());
    }

    #[test]
    fn test_initial_key_derivation() {
        let connection_id = b"test_connection_id";
        let result = KeyDerivation::derive_initial_keys(connection_id);

        assert!(result.is_ok());
        let (client_keys, server_keys) = result.unwrap();

        // Verify key lengths
        assert_eq!(client_keys.key.len(), INITIAL_KEY_LEN);
        assert_eq!(client_keys.iv.len(), INITIAL_IV_LEN);
        assert_eq!(client_keys.hp_key.len(), INITIAL_HP_KEY_LEN);
        assert_eq!(server_keys.key.len(), INITIAL_KEY_LEN);
        assert_eq!(server_keys.iv.len(), INITIAL_IV_LEN);
        assert_eq!(server_keys.hp_key.len(), INITIAL_HP_KEY_LEN);

        // Keys should be different
        assert_ne!(client_keys.key, server_keys.key);
        assert_ne!(client_keys.iv, server_keys.iv);
        assert_ne!(client_keys.hp_key, server_keys.hp_key);

        // Keys should not be zero
        assert!(KeyDerivation::verify_non_zero_keys(&client_keys).is_ok());
        assert!(KeyDerivation::verify_non_zero_keys(&server_keys).is_ok());
    }

    #[test]
    fn test_empty_connection_id_derivation_allowed() {
        let result = KeyDerivation::derive_initial_keys(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handshake_key_derivation() {
        let handshake_secret = vec![0x42u8; 32];
        let result = KeyDerivation::derive_handshake_keys(&handshake_secret);

        assert!(result.is_ok());
        let (keys1, keys2) = result.unwrap();

        // Keys should not be zero
        assert!(KeyDerivation::verify_non_zero_keys(&keys1).is_ok());
        assert!(KeyDerivation::verify_non_zero_keys(&keys2).is_ok());
    }

    #[test]
    fn test_application_key_derivation() {
        let app_secret = vec![0x55u8; 32];
        let result = KeyDerivation::derive_application_keys(&app_secret);

        assert!(result.is_ok());
        let (keys1, keys2) = result.unwrap();

        // Keys should not be zero
        assert!(KeyDerivation::verify_non_zero_keys(&keys1).is_ok());
        assert!(KeyDerivation::verify_non_zero_keys(&keys2).is_ok());
    }

    #[test]
    fn test_key_update_derivation() {
        let current_secret = vec![0xAAu8; 32];
        let result = KeyDerivation::derive_updated_keys(&current_secret);

        assert!(result.is_ok());
        let updated_keys = result.unwrap();

        // Updated keys should not be zero
        assert!(KeyDerivation::verify_non_zero_keys(&updated_keys).is_ok());
    }

    #[test]
    fn test_key_update_uses_quic_update_label() {
        let current_secret = vec![0xAAu8; TRAFFIC_SECRET_LEN];
        let actual = KeyDerivation::derive_updated_keys(&current_secret).unwrap();
        let hkdf = HkdfSha256::from_prk(&current_secret).unwrap();

        let quic_update_secret =
            KeyDerivation::hkdf_expand_label(&hkdf, TRAFFIC_SECRET_LEN, b"quic ku", &[]).unwrap();
        let quic_expected = KeyDerivation::derive_keys_from_secret(&quic_update_secret).unwrap();

        let tls_update_secret =
            KeyDerivation::hkdf_expand_label(&hkdf, TRAFFIC_SECRET_LEN, b"traffic upd", &[])
                .unwrap();
        let tls_expected = KeyDerivation::derive_keys_from_secret(&tls_update_secret).unwrap();

        assert_eq!(actual.key, quic_expected.key);
        assert_eq!(actual.iv, quic_expected.iv);
        assert_eq!(actual.hp_key, quic_expected.hp_key);
        assert_ne!(actual.key, tls_expected.key);
        assert_ne!(actual.iv, tls_expected.iv);
        assert_ne!(actual.hp_key, tls_expected.hp_key);
    }

    #[test]
    fn test_empty_secret_rejection() {
        assert!(KeyDerivation::derive_handshake_keys(&[]).is_err());
        assert!(KeyDerivation::derive_application_keys(&[]).is_err());
        assert!(KeyDerivation::derive_updated_keys(&[]).is_err());
    }

    #[test]
    fn test_rfc9001_initial_keys_match_appendix_a_vector() {
        let connection_id = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let (client_keys, server_keys) =
            KeyDerivation::derive_initial_keys(&connection_id).unwrap();

        assert_eq!(
            client_keys.key,
            decode_hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(client_keys.iv, decode_hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(
            client_keys.hp_key,
            decode_hex("9f50449e04a0e810283a1e9933adedd2")
        );
        assert_eq!(
            server_keys.key,
            decode_hex("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(server_keys.iv, decode_hex("0ac1493ca1905853b0bba03e"));
        assert_eq!(
            server_keys.hp_key,
            decode_hex("c206b8d9b9f0f37644430b490eeaa314")
        );
    }

    #[test]
    fn test_key_update_progression() {
        // Test that key updates produce different keys
        let initial_secret = vec![0x11u8; 32];
        let first_update = KeyDerivation::derive_updated_keys(&initial_secret).unwrap();

        // Use first update as input for second update
        // In practice, we'd derive new traffic secret first, but this tests the mechanism
        let second_secret = vec![0x22u8; 32];
        let second_update = KeyDerivation::derive_updated_keys(&second_secret).unwrap();

        // Updates should produce different keys
        assert_ne!(first_update.key, second_update.key);
        assert_ne!(first_update.iv, second_update.iv);
        assert_ne!(first_update.hp_key, second_update.hp_key);
    }

    #[test]
    fn test_zero_key_material_detection() {
        let zero_keys = KeyMaterial::zero(32, 12);
        assert!(KeyDerivation::verify_non_zero_keys(&zero_keys).is_err());

        let non_zero_keys = KeyMaterial::new(vec![1u8; 32], vec![2u8; 12], vec![3u8; 32]);
        assert!(KeyDerivation::verify_non_zero_keys(&non_zero_keys).is_ok());

        // Mixed case - only key is zero
        let mixed_keys = KeyMaterial::new(vec![0u8; 32], vec![2u8; 12], vec![3u8; 32]);
        assert!(KeyDerivation::verify_non_zero_keys(&mixed_keys).is_err());
    }

    #[test]
    fn test_key_phase_progression() {
        let phase0 = KeyPhase::INITIAL;
        let phase1 = phase0.next();
        let phase2 = phase1.next();

        assert_eq!(phase0.0, 0);
        assert_eq!(phase1.0, 1);
        assert_eq!(phase2.0, 2);
    }

    #[test]
    fn test_key_update_without_application_keys() {
        let mut schedule = KeySchedule::new();

        // Try to update keys without 1-RTT keys established
        let local_traffic_secret = vec![0x10u8; 32];
        let remote_traffic_secret = vec![0x20u8; 32];
        let result = schedule.initiate_key_update(&local_traffic_secret, &remote_traffic_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_double_key_update() {
        let mut schedule = KeySchedule::new();

        let local_keys = KeyMaterial::new(vec![1u8; 32], vec![2u8; 12], vec![3u8; 32]);
        let remote_keys = KeyMaterial::new(vec![4u8; 32], vec![5u8; 12], vec![6u8; 32]);
        schedule
            .install_application_keys(local_keys, remote_keys)
            .unwrap();

        let local_traffic_secret = vec![0x10u8; 32];
        let remote_traffic_secret = vec![0x20u8; 32];

        // First update should succeed
        assert!(
            schedule
                .initiate_key_update(&local_traffic_secret, &remote_traffic_secret)
                .is_ok()
        );

        // Second update while first is pending should fail
        assert!(
            schedule
                .initiate_key_update(&local_traffic_secret, &remote_traffic_secret)
                .is_err()
        );
    }
