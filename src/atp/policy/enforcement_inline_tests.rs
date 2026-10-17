    use super::*;
    use crate::atp::policy::{CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope};
    use std::collections::HashSet;
    use std::time::Duration;

    fn create_test_capability(peer: PeerId, action: CapabilityAction) -> Capability {
        let mut actions = HashSet::new();
        actions.insert(action);

        Capability::new(
            "test-grant".to_string(),
            peer,
            peer,
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        )
    }

    #[test]
    fn policy_enforcer_grants_valid_access() {
        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);
        let capability = create_test_capability(peer, CapabilityAction::Read);

        enforcer.add_capability(capability.clone());

        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let decision = enforcer.evaluate_access(&request);
        match decision.decision {
            CapabilityDecision::Granted { .. } => {}
            CapabilityDecision::Denied { reason, .. } => {
                panic!("Expected granted, got denied: {reason}")
            }
        }
    }

    #[test]
    fn policy_enforcer_denies_missing_capability() {
        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);

        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let decision = enforcer.evaluate_access(&request);
        match decision.decision {
            CapabilityDecision::Denied {
                reason: DenialReason::NoCapability,
                ..
            } => {}
            other => panic!("Expected NoCapability denial, got {other:?}"),
        }
    }

    #[test]
    fn policy_enforcer_path_scope_grants_in_scope_and_denies_excluded_and_out_of_scope() {
        // br-asupersync-tph5ac + br-asupersync-2ykdhb: end-to-end path-scoped
        // authorization. Before the fixes EVERY path request was denied as
        // PathTraversal (is_path_traversal_attempt flagged all absolute paths),
        // so the whole feature was dead and no enforcer test covered
        // AccessResource::Path. With both fixes: an in-scope path is granted,
        // while a path inside a literal exclusion (2ykdhb) and a fully
        // out-of-scope path are DENIED — proving access is still gated by the
        // scope, not opened up.
        use crate::atp::policy::scope::{AtpPath, PathScope};

        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);
        let mut exclusions = HashSet::new();
        exclusions.insert("/data/secret".to_string()); // literal, non-glob exclusion

        let capability = Capability::new(
            "path-grant".to_string(),
            peer,
            peer,
            ResourceScope::Path(PathScope::with_exclusions(
                "/data".to_string(),
                true,
                exclusions,
            )),
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );
        enforcer.add_capability(capability);

        let request_for = |path: &str| AccessRequest {
            peer,
            resource: AccessResource::Path(AtpPath::from_str(path).expect("valid path")),
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        // In-scope path: granted (proves path requests are no longer blanket-denied).
        match enforcer
            .evaluate_access(&request_for("/data/public/file.txt"))
            .decision
        {
            CapabilityDecision::Granted { .. } => {}
            other @ CapabilityDecision::Denied { .. } => {
                panic!("in-scope path must be granted, got {other:?}");
            }
        }

        // Descendant of a literal exclusion: denied (proves the 2ykdhb scope fix
        // in the full flow — the excluded subtree is not covered).
        match enforcer
            .evaluate_access(&request_for("/data/secret/private.txt"))
            .decision
        {
            CapabilityDecision::Denied { .. } => {}
            other @ CapabilityDecision::Granted { .. } => {
                panic!("excluded-subtree path must be denied, got {other:?}");
            }
        }

        // Fully out-of-scope path: denied.
        match enforcer
            .evaluate_access(&request_for("/other/file.txt"))
            .decision
        {
            CapabilityDecision::Denied { .. } => {}
            other @ CapabilityDecision::Granted { .. } => {
                panic!("out-of-scope path must be denied, got {other:?}");
            }
        }
    }

    #[test]
    fn policy_enforcer_denies_revoked_capability() {
        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);
        let capability = create_test_capability(peer, CapabilityAction::Read);

        enforcer.add_capability(capability.clone());
        enforcer.revoke_capability(&capability.grant_id);

        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let decision = enforcer.evaluate_access(&request);
        match decision.decision {
            CapabilityDecision::Denied {
                reason: DenialReason::NoCapability,
                ..
            } => {}
            other => panic!("Expected NoCapability denial after revocation, got {other:?}"), // ubs:ignore - test oracle
        }
    }

    #[test]
    fn policy_enforcer_tracks_usage() {
        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);
        let mut capability = create_test_capability(peer, CapabilityAction::Read);
        capability.temporal.max_uses = Some(2);

        enforcer.add_capability(capability.clone());

        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        // First use
        let decision1 = enforcer.evaluate_access(&request);
        assert!(matches!(
            decision1.decision,
            CapabilityDecision::Granted { .. }
        ));

        // Second use
        let decision2 = enforcer.evaluate_access(&request);
        assert!(matches!(
            decision2.decision,
            CapabilityDecision::Granted { .. }
        ));

        // Third use should be denied
        let decision3 = enforcer.evaluate_access(&request);
        assert!(matches!(
            decision3.decision,
            CapabilityDecision::Denied {
                reason: DenialReason::UsageExhausted,
                ..
            }
        ));
    }

    #[test]
    fn policy_enforcer_usage_count_saturates_at_u64_max() {
        let mut enforcer = PolicyEnforcer::new();
        let grant_id = "saturating-grant";

        enforcer.usage_counts.insert(grant_id.to_string(), u64::MAX);
        enforcer.increment_usage(grant_id);

        assert_eq!(enforcer.get_usage_count(grant_id), u64::MAX);
    }

    #[test]
    fn log_only_mode_allows_denied_requests() {
        let mut enforcer = PolicyEnforcer::new();
        enforcer.set_enforcement_mode(EnforcementMode::LogOnly);

        let peer = PeerId::test(1);
        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let decision = enforcer.evaluate_access(&request);
        // Should be granted even without capabilities in log-only mode
        assert!(matches!(
            decision.decision,
            CapabilityDecision::Granted { .. }
        ));
    }
