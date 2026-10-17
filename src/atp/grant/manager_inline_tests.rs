    use super::*;
    use crate::atp::policy::{
        AccessResource, CapabilityAction, CapabilityDecision, RequestContext, ResourceScope,
        ScopeConstraints, TemporalScope,
    };
    use crate::security::keys::IdentityKeyStore;
    use std::collections::HashSet;
    use std::time::Duration;
    use tempfile::tempdir;

    fn create_test_manager() -> GrantManager {
        let temp_dir = tempdir().expect("tempdir");
        let key_store_path = temp_dir.path().join("keys.json");
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let key_store =
            IdentityKeyStore::create(key_store_path, seed, 1).expect("create key store");

        GrantManager::new(temp_dir.path(), key_store).expect("create manager")
    }

    #[test]
    fn grant_manager_issues_and_stores_grants() {
        let mut manager = create_test_manager();

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject: crate::net::atp::protocol::PeerId::test(1),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: Some("test grant".to_string()),
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");

        // Verify grant was stored
        let retrieved = manager
            .get_grant(&grant_info.capability.grant_id)
            .expect("get grant");
        assert_eq!(
            retrieved.capability.grant_id,
            grant_info.capability.grant_id
        );
    }

    #[test]
    fn grant_manager_creates_from_templates() {
        let mut manager = create_test_manager();

        let grant_info = manager
            .create_from_template("read-once", crate::net::atp::protocol::PeerId::test(1))
            .expect("create from template");

        assert!(
            grant_info
                .capability
                .grants_action(&CapabilityAction::ReadOnce)
        );
        assert_eq!(grant_info.capability.temporal.max_uses, Some(1));
    }

    #[test]
    fn grant_manager_revokes_grants() {
        let mut manager = create_test_manager();

        // Issue a grant
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject: crate::net::atp::protocol::PeerId::test(1),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: None,
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");

        // Revoke the grant
        manager
            .revoke_grant(&grant_info.capability.grant_id)
            .expect("revoke grant");

        // Verify grant is revoked
        let revoked = manager
            .get_grant(&grant_info.capability.grant_id)
            .expect("get grant");
        assert_eq!(revoked.state, GrantState::Revoked);
    }

    #[test]
    fn grant_manager_tracks_audit_records() {
        let mut manager = create_test_manager();

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject: crate::net::atp::protocol::PeerId::test(1),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: None,
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");

        // Check audit records
        let audit_records = manager
            .get_audit_records(&grant_info.capability.grant_id)
            .expect("get audit records");

        assert_eq!(audit_records.len(), 1);
        assert_eq!(audit_records[0].operation, GrantOperation::Issued);
    }

    #[test]
    fn grant_manager_records_usage_and_audit_on_granted_access() {
        let mut manager = create_test_manager();
        let subject = crate::net::atp::protocol::PeerId::test(7);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject,
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: None,
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");
        let access = AccessRequest {
            peer: subject,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext {
                session_id: Some("session-usage-audit".to_string()),
                transfer_id: None,
                source: None,
            },
        };

        let decision = manager
            .evaluate_access(&access)
            .expect("evaluate granted access");

        assert!(matches!(
            decision.decision,
            CapabilityDecision::Granted { .. }
        ));

        let updated = manager
            .get_grant(&grant_info.capability.grant_id)
            .expect("get updated grant");
        assert_eq!(updated.usage_count, 1);
        assert!(updated.last_used.is_some());

        let audit_records = manager
            .get_audit_records(&grant_info.capability.grant_id)
            .expect("get audit records");
        assert_eq!(audit_records.len(), 2);
        assert_eq!(audit_records[0].operation, GrantOperation::Issued);
        assert_eq!(audit_records[1].operation, GrantOperation::Used);
        assert_eq!(
            audit_records[1]
                .context
                .get("session_id")
                .map(String::as_str),
            Some("session-usage-audit")
        );
    }

    #[test]
    fn grant_manager_expires_one_time_grant_after_successful_access() {
        let mut manager = create_test_manager();
        let subject = crate::net::atp::protocol::PeerId::test(8);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::ReadOnce);

        let request = CreateGrantRequest {
            subject,
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::once(),
            constraints: ScopeConstraints::default(),
            description: None,
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");
        let access = AccessRequest {
            peer: subject,
            resource: AccessResource::Inbox,
            action: CapabilityAction::ReadOnce,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let first_decision = manager
            .evaluate_access(&access)
            .expect("first access evaluates");
        assert!(matches!(
            first_decision.decision,
            CapabilityDecision::Granted { .. }
        ));

        let updated = manager
            .get_grant(&grant_info.capability.grant_id)
            .expect("get updated grant");
        assert_eq!(updated.state, GrantState::Expired);
        assert_eq!(updated.usage_count, 1);

        let second_decision = manager
            .evaluate_access(&access)
            .expect("second access evaluates");
        assert!(matches!(
            second_decision.decision,
            CapabilityDecision::Denied { .. }
        ));
    }

    #[test]
    fn grant_manager_rotates_grants() {
        let mut manager = create_test_manager();

        // Issue a grant
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject: crate::net::atp::protocol::PeerId::test(1),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: None,
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");
        let original_id = grant_info.capability.grant_id.clone();

        // Rotate the grant
        let new_grant = manager.rotate_grant(&original_id).expect("rotate grant");

        // Verify old grant is marked as rotated
        let old_grant = manager.get_grant(&original_id).expect("get old grant");
        assert_eq!(old_grant.state, GrantState::Rotated);

        // Verify new grant is active
        let retrieved_new = manager
            .get_grant(&new_grant.capability.grant_id)
            .expect("get new grant");
        assert_eq!(retrieved_new.state, GrantState::Active);
    }
