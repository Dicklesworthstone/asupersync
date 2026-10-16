    use super::*;
    use crate::net::atp::protocol::PeerId;

    #[test]
    fn capability_action_hierarchy() {
        assert!(CapabilityAction::Write.implies(&CapabilityAction::Read));
        assert!(CapabilityAction::Share.implies(&CapabilityAction::Read));
        assert!(CapabilityAction::Seed.implies(&CapabilityAction::Read));
        assert!(!CapabilityAction::Read.implies(&CapabilityAction::Write));
    }

    #[test]
    fn temporal_scope_validation() {
        let now = SystemTime::now();
        let past = now - Duration::from_secs(100);
        let future = now + Duration::from_secs(100);

        let current = TemporalScope::window(past, future);
        assert!(current.is_valid_at(now));

        let expired = TemporalScope::window(past, past + Duration::from_secs(50));
        assert!(!expired.is_valid_at(now));

        let not_yet = TemporalScope::window(future, future + Duration::from_secs(100));
        assert!(!not_yet.is_valid_at(now));

        let once = TemporalScope::once();
        assert!(!once.uses_exhausted(0));
        assert!(once.uses_exhausted(1));
    }

    #[test]
    fn capability_grants_action() {
        let peer_id = PeerId::test(1);
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Write);

        let capability = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        assert!(capability.grants_action(&CapabilityAction::Write));
        assert!(capability.grants_action(&CapabilityAction::Read)); // Implied
        assert!(!capability.grants_action(&CapabilityAction::Share));
    }

    #[test]
    fn capability_policy_digest_stability() {
        let peer_id = PeerId::test(1);
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let cap1 = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions.clone(),
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        let cap2 = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        assert_eq!(cap1.policy_digest(), cap2.policy_digest());
    }

    #[test]
    fn capability_policy_digest_frames_temporal_fields() {
        let peer_id = PeerId::test(1);
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let expires_at_one = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions.clone(),
            TemporalScope {
                not_before: None,
                not_after: Some(UNIX_EPOCH + Duration::from_secs(1)),
                max_uses: None,
            },
            ScopeConstraints::default(),
        );

        let one_use = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions,
            TemporalScope {
                not_before: None,
                not_after: None,
                max_uses: Some(1),
            },
            ScopeConstraints::default(),
        );

        assert_ne!(expires_at_one.policy_digest(), one_use.policy_digest());
    }
