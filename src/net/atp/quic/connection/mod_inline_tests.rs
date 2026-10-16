    use super::*;
    use crate::net::atp::path::{AtpPathEndpoints, PathContinuity};
    use crate::net::atp::stun::{EndpointFamily, ObservedEndpoint};
    use crate::types::CancelKind;

    fn endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, address, port).expect("endpoint")
    }

    fn candidate(id: u64, remote_port: u16, rank: u8) -> AtpPathCandidate {
        AtpPathCandidate::new(
            AtpPathId::new(id),
            AtpPathEndpoints::new(
                endpoint("10.0.0.2", 40_000),
                endpoint("198.51.100.10", remote_port),
            ),
            rank,
            100 + id,
            format!("path-{id}"),
            format!("verifier-{id}"),
        )
        .expect("candidate")
    }

    fn state() -> AtpQuicConnectionState {
        AtpQuicConnectionState::new(
            vec![0xaa, 0xbb, 0xcc, 0xdd],
            [7; STATELESS_RESET_TOKEN_LEN],
            candidate(0, 50_000, 10),
            AtpQuicConnectionConfig {
                validation_secret: 0x1234_5678,
                ..AtpQuicConnectionConfig::default()
            },
        )
        .expect("state")
    }

    #[test]
    fn connection_id_issuance_and_retirement_enforce_active_limit() {
        let initial = QuicConnectionId::new(0, vec![1, 2, 3, 4], [1; 16], 0).expect("cid");
        let mut registry = ConnectionIdRegistry::new(initial, 2).expect("registry");

        let first = registry.issue(vec![5, 6, 7, 8], [2; 16], 1).expect("first");
        let second = registry
            .issue(vec![9, 10, 11, 12], [3; 16], 2)
            .expect("second");

        assert_eq!(first.sequence(), 1);
        assert_eq!(second.sequence(), 2);
        assert_eq!(registry.active().map(QuicConnectionId::sequence), Some(0));
        assert!(registry.retired_ids().contains(&1));
        assert!(registry.active_ids().contains_key(&0));
        assert!(registry.active_ids().contains_key(&2));

        let err = registry
            .retire(registry.active_sequence())
            .expect_err("active cid cannot retire");
        assert_eq!(
            err,
            AtpQuicConnectionError::CannotRetireActiveConnectionId { sequence: 0 }
        );
    }

    #[test]
    fn connection_id_debug_redacts_stateless_reset_token() {
        let reset_token = [0xabu8; STATELESS_RESET_TOKEN_LEN];
        let raw_token_debug = format!("{reset_token:?}");
        let cid =
            QuicConnectionId::new(7, vec![1, 2, 3, 4], reset_token, 99).expect("connection id");

        let cid_debug = format!("{cid:?}");
        assert!(cid_debug.contains("QuicConnectionId"));
        assert!(cid_debug.contains("stateless_reset_token"));
        assert!(cid_debug.contains("<redacted>"));
        assert!(
            !cid_debug.contains(&raw_token_debug),
            "QuicConnectionId Debug must not expose stateless reset token: {cid_debug}"
        );

        let registry = ConnectionIdRegistry::new(cid, 2).expect("registry");
        let registry_debug = format!("{registry:?}");
        assert!(
            !registry_debug.contains(&raw_token_debug),
            "ConnectionIdRegistry Debug must not expose nested stateless reset tokens: {registry_debug}"
        );
    }

    #[test]
    fn active_connection_id_absence_returns_none_instead_of_panicking() {
        let initial = QuicConnectionId::new(0, vec![1, 2, 3, 4], [1; 16], 0).expect("cid");
        let mut registry = ConnectionIdRegistry::new(initial, 2).expect("registry");

        registry.active_sequence = 42;

        assert_eq!(registry.active(), None);
    }

    #[test]
    fn path_challenge_response_validates_before_commit() {
        let cx = Cx::for_testing();
        let mut state = state();
        let target = candidate(1, 50_100, 1);

        let challenge = state
            .request_migration(&cx, target, PathMigrationReason::ActiveMigration, 1_000)
            .expect("challenge");
        assert_eq!(challenge.path_id(), AtpPathId::new(1));
        assert!(matches!(challenge.frame(), QuicFrame::PathChallenge { .. }));

        let err = state
            .commit_migration(&cx, AtpPathId::new(1), 1_100)
            .expect_err("commit before validation");
        assert_eq!(
            err,
            AtpQuicConnectionError::Path(PathMigrationError::NotValidated)
        );

        let outcome = state
            .on_path_response(&cx, AtpPathId::new(1), challenge.data(), 1_200)
            .expect("response");
        assert_eq!(outcome, PathValidationOutcome::Validated);

        let committed = state
            .commit_migration(&cx, AtpPathId::new(1), 1_300)
            .expect("commit");
        assert_eq!(committed.status(), PathMigrationStatus::Committed);
        assert_eq!(committed.continuity(), PathContinuity::VERIFIED);
        assert_eq!(state.path_manager().active_path_id(), AtpPathId::new(1));

        let trace = state.migration_traces().last().expect("trace");
        assert_eq!(trace.old_path_id(), AtpPathId::INITIAL);
        assert_eq!(trace.new_path_id(), AtpPathId::new(1));
        assert_eq!(trace.key_phase(), 0);
        assert!(trace.replay_pointer().contains("atp.quic.migration"));
    }

    #[test]
    fn path_response_mismatch_rejects_candidate() {
        let cx = Cx::for_testing();
        let mut state = state();
        let challenge = state
            .request_migration(
                &cx,
                candidate(2, 50_200, 1),
                PathMigrationReason::RelayFallback,
                10,
            )
            .expect("challenge");
        let mut wrong = challenge.data();
        wrong[0] ^= 0xff;

        let outcome = state
            .on_path_response(&cx, AtpPathId::new(2), wrong, 20)
            .expect("response");
        assert_eq!(outcome, PathValidationOutcome::Rejected);
        assert!(state.pending_challenges().is_empty());
        assert_eq!(
            state.path_manager().history()[0].status(),
            PathMigrationStatus::Rejected
        );
    }

    #[test]
    fn validation_timeout_rejects_pending_migration() {
        let cx = Cx::for_testing();
        let mut state = state();
        let challenge = state
            .request_migration(
                &cx,
                candidate(3, 50_300, 1),
                PathMigrationReason::MobileChurn,
                10,
            )
            .expect("challenge");

        let expired = state
            .expire_validations(&cx, challenge.expires_at_micros())
            .expect("expire");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].status(), PathMigrationStatus::TimedOut);
        assert!(state.pending_challenges().is_empty());
    }

    #[test]
    fn nat_rebinding_preserves_verified_transfer_continuity() {
        let cx = Cx::for_testing();
        let mut state = state();
        let challenge = state
            .observe_nat_rebinding(&cx, candidate(4, 55_000, 1), 2_000)
            .expect("nat rebinding challenge");
        assert_eq!(
            state.path_manager().pending()[&AtpPathId::new(4)].reason(),
            PathMigrationReason::NatRebinding
        );

        assert_eq!(
            state
                .on_path_response(&cx, AtpPathId::new(4), challenge.data(), 2_100)
                .expect("response"),
            PathValidationOutcome::Validated
        );
        let committed = state
            .commit_migration(&cx, AtpPathId::new(4), 2_200)
            .expect("commit");
        assert!(committed.continuity().is_verified());
        assert_eq!(committed.candidate().verifier_context(), "verifier-4");
    }

    #[test]
    fn preferred_address_key_update_and_candidate_race_are_observable() {
        let cx = Cx::for_testing();
        let mut state = state();
        let best = state
            .path_manager()
            .race_candidates(vec![candidate(5, 50_500, 20), candidate(6, 50_600, 5)])
            .expect("winner");
        assert_eq!(best.id(), AtpPathId::new(6));

        let challenge = state
            .request_migration(&cx, best, PathMigrationReason::PreferredAddress, 3_000)
            .expect("challenge");
        state
            .on_path_response(&cx, AtpPathId::new(6), challenge.data(), 3_100)
            .expect("response");
        state
            .commit_migration(&cx, AtpPathId::new(6), 3_200)
            .expect("commit");

        assert_eq!(state.request_key_update(&cx).expect("request"), 1);
        assert_eq!(state.commit_key_update(&cx).expect("commit"), 1);
        let key_trace = state.migration_traces().last().expect("key trace");
        assert_eq!(key_trace.event(), MigrationTraceEvent::KeyUpdate);
        assert_eq!(key_trace.key_phase(), 1);
        assert_eq!(key_trace.new_path_id(), AtpPathId::new(6));
    }

    #[test]
    fn cancellation_checkpoint_blocks_migration_request() {
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, Some("test cancel"));
        let mut state = state();
        let err = state
            .request_migration(
                &cx,
                candidate(7, 50_700, 1),
                PathMigrationReason::ActiveMigration,
                1,
            )
            .expect_err("cancelled");
        assert_eq!(err, AtpQuicConnectionError::Cancelled);
    }

    #[test]
    fn active_migration_disabled_still_allows_nat_rebinding_validation() {
        let cx = Cx::for_testing();
        let mut state = AtpQuicConnectionState::new(
            vec![0xaa, 0xbb, 0xcc, 0xdd],
            [7; STATELESS_RESET_TOKEN_LEN],
            candidate(0, 50_000, 10),
            AtpQuicConnectionConfig {
                active_migration_disabled: true,
                ..AtpQuicConnectionConfig::default()
            },
        )
        .expect("state");

        let err = state
            .request_migration(
                &cx,
                candidate(8, 50_800, 1),
                PathMigrationReason::ActiveMigration,
                1,
            )
            .expect_err("active migration disabled");
        assert_eq!(err, AtpQuicConnectionError::ActiveMigrationDisabled);

        state
            .observe_nat_rebinding(&cx, candidate(9, 50_900, 1), 2)
            .expect("nat rebinding allowed");
    }
