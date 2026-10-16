    use super::*;
    use crate::security::keys::IdentityKeyStore;
    use tempfile::tempdir;

    fn create_test_identity() -> DurablePeerIdentity {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let store = IdentityKeyStore::create(path, seed, 1).expect("create key store");
        DurablePeerIdentity::from_key_store(&store).expect("durable identity")
    }

    #[test]
    fn pairing_code_generates_valid_code() {
        let identity = create_test_identity();
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let pairing_code = PairingCode::new(
            &identity,
            actions,
            ResourceScope::Any,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
            true,
        )
        .expect("create pairing code");

        assert!(!pairing_code.code.is_empty());
        assert!(pairing_code.is_valid());
        assert_eq!(pairing_code.remaining_uses(), Some(1));
    }

    #[test]
    fn pairing_manager_generates_and_uses_codes() {
        let identity = create_test_identity();
        let peer_identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions.clone(),
                ResourceScope::Any,
                Duration::from_secs(3600),
                true,
            )
            .expect("generate pairing code");

        // Use the pairing code
        let capability = manager
            .use_pairing_code(&code, &peer_identity)
            .expect("use pairing code");

        assert_eq!(capability.subject, peer_identity.peer_id());
        assert!(capability.grants_action(&CapabilityAction::Read));

        // Verify completed pairing was recorded
        let completed = manager.list_completed_pairings();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].peer, peer_identity.peer_id());
    }

    #[test]
    fn pairing_code_enforces_usage_limits() {
        let identity = create_test_identity();
        let peer_identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions,
                ResourceScope::Any,
                Duration::from_secs(3600),
                true, // one-time use
            )
            .expect("generate pairing code");

        // First use should succeed
        let _capability1 = manager
            .use_pairing_code(&code, &peer_identity)
            .expect("first use");

        // Second use should fail
        let result2 = manager.use_pairing_code(&code, &peer_identity);
        assert!(result2.is_err());
    }

    #[test]
    fn pairing_manager_cleans_up_expired_codes() {
        let identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        // Create expired code (0 second expiry)
        let temporal = TemporalScope::expires_in(Duration::from_secs(0));
        let pairing_code = PairingCode {
            code: "TEST-CODE".to_string(),
            issuer: manager.identity.peer_id(),
            issuer_public_key: manager.identity.public_key().to_string(),
            actions,
            scope: ResourceScope::Any,
            temporal,
            constraints: ScopeConstraints::default(),
            created_at: SystemTime::now(),
            description: None,
            one_time: true,
            use_count: 0,
            max_uses: Some(1),
        };

        manager
            .active_codes
            .insert("TEST-CODE".to_string(), pairing_code);

        // Wait a moment for expiry
        std::thread::sleep(Duration::from_millis(10));

        let removed_count = manager.cleanup_expired_codes();
        assert_eq!(removed_count, 1);
        assert!(manager.active_codes.is_empty());
    }

    #[test]
    fn pairing_code_summary_is_readable() {
        let identity = create_test_identity();
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);
        actions.insert(CapabilityAction::Share);

        let pairing_code = PairingCode::new(
            &identity,
            actions,
            ResourceScope::Inbox,
            TemporalScope::once(),
            ScopeConstraints::default(),
            true,
        )
        .expect("create pairing code");

        let summary = pairing_code.summary();
        assert!(summary.contains("Code:"));
        assert!(summary.contains("Read"));
        assert!(summary.contains("Share"));
        assert!(summary.contains("inbox"));
        assert!(summary.contains("1 uses remaining"));
    }

    #[test]
    fn reusable_pairing_code_remains_active_after_successful_use() {
        let identity = create_test_identity();
        let first_peer = create_test_identity();
        let second_peer = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions,
                ResourceScope::Any,
                Duration::from_secs(3600),
                false,
            )
            .expect("generate reusable pairing code");

        let first = manager
            .use_pairing_code(&code, &first_peer)
            .expect("first use should succeed");
        let second = manager
            .use_pairing_code(&code, &second_peer)
            .expect("second use should also succeed for unlimited code");

        assert_eq!(first.subject, first_peer.peer_id());
        assert_eq!(second.subject, second_peer.peer_id());
        assert!(manager.get_pairing_code(&code).is_ok());
    }

    #[test]
    fn pairing_code_collision_does_not_overwrite_active_code() {
        let identity = create_test_identity();
        let mut manager = PairingManager::new(identity.clone());

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let mut first = PairingCode::new(
            &identity,
            actions.clone(),
            ResourceScope::Any,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
            false,
        )
        .expect("create first pairing code")
        .with_description("first".to_string());
        first.code = "DUPL-ICAT-ECOD-E".to_string();

        let mut colliding = PairingCode::new(
            &identity,
            actions,
            ResourceScope::Any,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
            false,
        )
        .expect("create colliding pairing code")
        .with_description("second".to_string());
        colliding.code.clone_from(&first.code);

        assert_eq!(
            manager.insert_pairing_code_if_vacant(first.clone()),
            Some(first.code.clone())
        );
        assert_eq!(manager.insert_pairing_code_if_vacant(colliding), None);

        let stored = manager
            .get_pairing_code(&first.code)
            .expect("get original pairing code");
        assert_eq!(stored.description.as_deref(), Some("first"));
        assert_eq!(manager.list_active_codes().len(), 1);
    }

    #[test]
    fn reusable_pairing_code_issues_unique_grant_ids_for_same_peer() {
        let identity = create_test_identity();
        let peer = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions,
                ResourceScope::Any,
                Duration::from_secs(3600),
                false,
            )
            .expect("generate reusable pairing code");

        let first = manager
            .use_pairing_code(&code, &peer)
            .expect("first use should succeed");
        let second = manager
            .use_pairing_code(&code, &peer)
            .expect("second use should succeed for the same peer");

        assert_ne!(first.grant_id, second.grant_id);
        assert!(first.grant_id.starts_with("paired-"));
        assert!(second.grant_id.starts_with("paired-"));
        assert!(!first.grant_id.contains(&code));
        assert!(!second.grant_id.contains(&code));
    }

    #[test]
    fn limited_pairing_code_is_removed_after_last_use() {
        let identity = create_test_identity();
        let peer_identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions,
                ResourceScope::Any,
                Duration::from_secs(3600),
                false,
            )
            .expect("generate limited pairing code");
        manager
            .active_codes
            .get_mut(&code)
            .expect("active pairing code")
            .max_uses = Some(2);

        manager
            .use_pairing_code(&code, &peer_identity)
            .expect("first use should succeed");
        assert!(manager.get_pairing_code(&code).is_ok());

        manager
            .use_pairing_code(&code, &peer_identity)
            .expect("last allowed use should succeed");
        assert!(manager.get_pairing_code(&code).is_err());
    }

    #[test]
    fn temporary_write_share_rejects_duration_overflow() {
        let identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let result = manager.create_temp_write_share(ResourceScope::Any, u64::MAX);

        assert!(matches!(
            result,
            Outcome::Err(GrantError::PairingError { .. })
        ));
    }

    #[test]
    fn pairing_code_usage_counter_saturates_instead_of_wrapping() {
        let identity = create_test_identity();
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);
        let mut pairing_code = PairingCode::new(
            &identity,
            actions,
            ResourceScope::Any,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
            false,
        )
        .expect("create pairing code");

        pairing_code.use_count = u64::MAX;
        pairing_code.max_uses = None;

        assert!(pairing_code.record_use());
        assert_eq!(pairing_code.use_count, u64::MAX);
    }
