    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::ObligationKind;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn panic_message(result: Result<(), Box<dyn std::any::Any + Send>>) -> String {
        let payload = result.expect_err("operation should panic");
        if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else if let Some(message) = payload.downcast_ref::<&'static str>() {
            (*message).to_string()
        } else {
            "<non-string panic>".to_string()
        }
    }

    // ---- GradedObligation: correct usage -----------------------------------

    #[test]
    fn obligation_commit_clean() {
        init_test("obligation_commit_clean");
        let ob = GradedObligation::reserve(ObligationKind::SendPermit, "test");
        let kind = ob.kind();
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "kind",
            ObligationKind::SendPermit,
            kind
        );
        let is_resolved = ob.is_resolved();
        crate::assert_with_log!(!is_resolved, "not yet resolved", false, is_resolved);

        let proof = ob.resolve(Resolution::Commit);
        let r = proof.resolution();
        crate::assert_with_log!(r == Resolution::Commit, "resolution", Resolution::Commit, r);
        let state = proof.obligation_state();
        crate::assert_with_log!(
            state == ObligationState::Committed,
            "record state",
            ObligationState::Committed,
            state
        );
        crate::test_complete!("obligation_commit_clean");
    }

    #[test]
    fn obligation_abort_clean() {
        init_test("obligation_abort_clean");
        let ob = GradedObligation::reserve(ObligationKind::Ack, "ack-test");
        let proof = ob.resolve(Resolution::Abort);
        let r = proof.resolution();
        crate::assert_with_log!(r == Resolution::Abort, "resolution", Resolution::Abort, r);
        let state = proof.obligation_state();
        crate::assert_with_log!(
            state == ObligationState::Aborted,
            "record state",
            ObligationState::Aborted,
            state
        );
        crate::test_complete!("obligation_abort_clean");
    }

    #[test]
    fn obligation_into_raw_disarms() {
        init_test("obligation_into_raw_disarms");
        let ob = GradedObligation::reserve(ObligationKind::Lease, "lease-test");
        let raw = ob.into_raw();
        let kind = raw.kind;
        crate::assert_with_log!(
            kind == ObligationKind::Lease,
            "raw kind",
            ObligationKind::Lease,
            kind
        );
        // raw can be dropped without panic.
        drop(raw);
        crate::test_complete!("obligation_into_raw_disarms");
    }

    // ---- GradedObligation: leak detection ----------------------------------

    #[test]
    #[should_panic(expected = "[ASUP-E101] OBLIGATION LEAKED")]
    fn obligation_drop_without_resolve_panics() {
        init_test("obligation_drop_without_resolve_panics");
        let _ob = GradedObligation::reserve(ObligationKind::IoOp, "leaked-io");
        // Dropped without resolving — should panic.
    }

    #[test]
    fn obligation_drop_without_resolve_panic_carries_asup_e101() {
        init_test("obligation_drop_without_resolve_panic_carries_asup_e101");
        let message = panic_message(std::panic::catch_unwind(|| {
            let _ob = GradedObligation::reserve(ObligationKind::IoOp, "leaked-io");
        }));
        crate::assert_with_log!(
            message.contains("[ASUP-E101]"),
            "error code",
            true,
            message.contains("[ASUP-E101]")
        );
        crate::assert_with_log!(
            message.contains("OBLIGATION LEAKED"),
            "diagnostic class",
            true,
            message.contains("OBLIGATION LEAKED")
        );
        crate::test_complete!("obligation_drop_without_resolve_panic_carries_asup_e101");
    }

    #[test]
    fn panic_leaks_snapshot_records_unwind_drop() {
        init_test("panic_leaks_snapshot_records_unwind_drop");
        let before = panic_leaks();
        let result = std::panic::catch_unwind(|| {
            let _ob = GradedObligation::reserve(ObligationKind::Lease, "panic-unwind");
            panic!("force unwind with unresolved obligation");
        });
        crate::assert_with_log!(result.is_err(), "panic captured", true, result.is_err());

        let after = panic_leaks();
        crate::assert_with_log!(
            after.total_leaked >= before.total_leaked.saturating_add(1),
            "panic leak recorded",
            before.total_leaked.saturating_add(1),
            after.total_leaked
        );
        let current_count = panic_leak_count();
        crate::assert_with_log!(
            current_count >= after.total_leaked,
            "count compatibility",
            after.total_leaked,
            current_count
        );
        crate::test_complete!("panic_leaks_snapshot_records_unwind_drop");
    }

    // ---- GradedScope: correct usage ----------------------------------------

    #[test]
    fn scope_clean_close() {
        init_test("scope_clean_close");
        let mut scope = GradedScope::open("test-scope");
        scope.on_reserve();
        scope.on_resolve();
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 0, "outstanding", 0, outstanding);

        let proof = scope.close().expect("scope should close cleanly");
        let label = proof.label();
        crate::assert_with_log!(label == "test-scope", "label", "test-scope", label);
        let total = proof.total_reserved();
        crate::assert_with_log!(total == 1, "reserved", 1, total);
        crate::test_complete!("scope_clean_close");
    }

    #[test]
    fn scope_multiple_obligations() {
        init_test("scope_multiple_obligations");
        let mut scope = GradedScope::open("multi");
        scope.on_reserve();
        scope.on_reserve();
        scope.on_reserve();
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 3, "outstanding", 3, outstanding);

        scope.on_resolve();
        scope.on_resolve();
        scope.on_resolve();
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 0, "outstanding", 0, outstanding);

        let proof = scope.close().expect("clean");
        let total = proof.total_reserved();
        crate::assert_with_log!(total == 3, "reserved", 3, total);
        crate::test_complete!("scope_multiple_obligations");
    }

    #[test]
    fn scope_close_with_leak_returns_error() {
        init_test("scope_close_with_leak_returns_error");
        let mut scope = GradedScope::open("leaky-scope");
        scope.on_reserve();
        scope.on_reserve();
        scope.on_resolve(); // Only 1 of 2 resolved.

        let err = scope.close().expect_err("should fail");
        let outstanding = err.outstanding;
        crate::assert_with_log!(outstanding == 1, "outstanding", 1, outstanding);
        let label = &err.label;
        crate::assert_with_log!(label == "leaky-scope", "label", "leaky-scope", label);

        // Verify Display impl.
        let msg = format!("{err}");
        let has_leaked = msg.contains("leaked");
        crate::assert_with_log!(has_leaked, "display has leaked", true, has_leaked);
        crate::test_complete!("scope_close_with_leak_returns_error");
    }

    #[test]
    #[should_panic(expected = "SCOPE LEAKED")]
    fn scope_drop_with_outstanding_panics() {
        init_test("scope_drop_with_outstanding_panics");
        let mut scope = GradedScope::open("drop-leak");
        scope.on_reserve();
        // Dropped without closing — should panic because outstanding > 0.
    }

    #[test]
    fn scope_drop_without_close_ok_when_empty() {
        init_test("scope_drop_without_close_ok_when_empty");
        let _scope = GradedScope::open("empty-scope");
        // No obligations reserved, drop is fine.
    }

    // ---- Combined: obligation + scope --------------------------------------

    #[test]
    fn combined_obligation_and_scope() {
        init_test("combined_obligation_and_scope");
        let mut scope = GradedScope::open("combined");

        // Reserve two obligations.
        let ob1 = GradedObligation::reserve(ObligationKind::SendPermit, "send");
        scope.on_reserve();
        let ob2 = GradedObligation::reserve(ObligationKind::Ack, "ack");
        scope.on_reserve();

        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 2, "outstanding", 2, outstanding);

        // Resolve both.
        let _proof1 = ob1.resolve(Resolution::Commit);
        scope.on_resolve();
        let _proof2 = ob2.resolve(Resolution::Abort);
        scope.on_resolve();

        // Close scope.
        let proof = scope.close().expect("clean close");
        let total = proof.total_reserved();
        crate::assert_with_log!(total == 2, "total reserved", 2, total);
        crate::test_complete!("combined_obligation_and_scope");
    }

    // ---- Toy API -----------------------------------------------------------

    #[test]
    fn toy_channel_correct_usage() {
        init_test("toy_channel_correct_usage");
        let mut ch = toy_api::ToyChannel::new(10);

        // Reserve and commit.
        let permit = ch.reserve_send().expect("should get permit");
        let proof = ch.commit_send(permit, "hello".to_string());
        let resolution = proof.resolution();
        crate::assert_with_log!(
            resolution == Resolution::Commit,
            "commit",
            Resolution::Commit,
            resolution
        );
        let len = ch.len();
        crate::assert_with_log!(len == 1, "len", 1, len);
        crate::test_complete!("toy_channel_correct_usage");
    }

    #[test]
    fn toy_channel_abort_usage() {
        init_test("toy_channel_abort_usage");
        let mut ch = toy_api::ToyChannel::new(10);

        let permit = ch.reserve_send().expect("should get permit");
        let proof = ch.abort_send(permit);
        let resolution = proof.resolution();
        crate::assert_with_log!(
            resolution == Resolution::Abort,
            "abort",
            Resolution::Abort,
            resolution
        );
        let len = ch.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("toy_channel_abort_usage");
    }

    #[test]
    #[should_panic(expected = "OBLIGATION LEAKED")]
    fn toy_channel_leaked_permit_panics() {
        init_test("toy_channel_leaked_permit_panics");
        let mut ch = toy_api::ToyChannel::new(10);
        let _permit = ch.reserve_send().expect("should get permit");
        // Dropped without commit or abort — panics.
    }

    #[test]
    fn toy_channel_full_returns_none() {
        init_test("toy_channel_full_returns_none");
        let mut ch = toy_api::ToyChannel::new(0);
        let permit = ch.reserve_send();
        let is_none = permit.is_none();
        crate::assert_with_log!(is_none, "full", true, is_none);
        crate::test_complete!("toy_channel_full_returns_none");
    }

    #[test]
    fn toy_channel_reservation_tracks_outstanding_capacity() {
        init_test("toy_channel_reservation_tracks_outstanding_capacity");
        let mut ch = toy_api::ToyChannel::new(1);

        let first = ch.reserve_send().expect("first permit should succeed");
        let second = ch.reserve_send();
        crate::assert_with_log!(
            second.is_none(),
            "second permit blocked by outstanding reservation",
            true,
            second.is_none()
        );

        let _proof = ch.abort_send(first);
        let retry = ch.reserve_send();
        let retry_present = retry.is_some();
        crate::assert_with_log!(
            retry_present,
            "capacity should reopen after abort",
            true,
            retry_present
        );
        let retry = retry.expect("retry permit should be present after abort");
        let _retry_proof = ch.abort_send(retry);
        crate::test_complete!("toy_channel_reservation_tracks_outstanding_capacity");
    }

    #[test]
    fn toy_channel_commit_rejects_wrong_obligation_kind() {
        init_test("toy_channel_commit_rejects_wrong_obligation_kind");
        let mut ch = toy_api::ToyChannel::from_state(1, Vec::new(), 1);
        let forged = GradedObligation::reserve(ObligationKind::Ack, "forged ack");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ch.commit_send(forged, "hello".to_string())
        }));

        crate::assert_with_log!(
            result.is_err(),
            "wrong kind rejected",
            true,
            result.is_err()
        );
        crate::assert_with_log!(ch.is_empty(), "no message enqueued", true, ch.is_empty());
        let retry = ch.reserve_send();
        crate::assert_with_log!(
            retry.is_none(),
            "reservation count preserved after rejected commit",
            true,
            retry.is_none()
        );
        crate::test_complete!("toy_channel_commit_rejects_wrong_obligation_kind");
    }

    #[test]
    fn toy_channel_abort_rejects_wrong_obligation_kind() {
        init_test("toy_channel_abort_rejects_wrong_obligation_kind");
        let mut ch = toy_api::ToyChannel::from_state(1, Vec::new(), 1);
        let forged = GradedObligation::reserve(ObligationKind::Lease, "forged lease");

        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ch.abort_send(forged)));

        crate::assert_with_log!(
            result.is_err(),
            "wrong kind rejected",
            true,
            result.is_err()
        );
        crate::assert_with_log!(ch.is_empty(), "abort does not enqueue", true, ch.is_empty());
        let retry = ch.reserve_send();
        crate::assert_with_log!(
            retry.is_none(),
            "reservation count preserved after rejected abort",
            true,
            retry.is_none()
        );
        crate::test_complete!("toy_channel_abort_rejects_wrong_obligation_kind");
    }

    // ---- Display impls -----------------------------------------------------

    #[test]
    fn display_impls() {
        init_test("graded_display_impls");
        let proof = ResolvedProof {
            kind: ObligationKind::SendPermit,
            resolution: Resolution::Commit,
        };
        let s = format!("{proof}");
        let has_resolved = s.contains("resolved");
        crate::assert_with_log!(has_resolved, "proof display", true, has_resolved);

        let scope_proof = ScopeProof {
            label: "test".to_string(),
            total_reserved: 3,
            total_resolved: 3,
        };
        let s = format!("{scope_proof}");
        let has_clean = s.contains("clean");
        crate::assert_with_log!(has_clean, "scope proof display", true, has_clean);

        let err = ScopeLeakError {
            label: "bad".to_string(),
            outstanding: 2,
            reserved: 5,
            resolved: 3,
        };
        let s = format!("{err}");
        let has_leaked = s.contains("leaked");
        crate::assert_with_log!(has_leaked, "scope error display", true, has_leaked);

        let resolution = format!("{}", Resolution::Commit);
        crate::assert_with_log!(
            resolution == "commit",
            "resolution display",
            "commit",
            resolution
        );

        crate::test_complete!("graded_display_impls");
    }

    // ---- Typing judgment demonstration -------------------------------------

    #[test]
    fn typing_judgment_demonstration() {
        init_test("typing_judgment_demonstration");
        // This test demonstrates the typing discipline:
        //
        // 1. reserve() creates an obligation (1 resource unit)
        // 2. resolve() consumes it (0 resource units)
        // 3. Scope verifies zero-leak at exit
        //
        // The key insight: in a linear type system, step 2 is mandatory.
        // In Rust (affine), we enforce it with Drop + #[must_use].

        let mut scope = GradedScope::open("typing_demo");

        // Typing rule: Γ ⊢ reserve(SendPermit) : Obligation<SendPermit>  [+1]
        let ob = GradedObligation::reserve(ObligationKind::SendPermit, "demo");
        scope.on_reserve();

        // Typing rule: Γ, ob: Obligation<SendPermit> ⊢ resolve(ob, Commit) : Proof  [-1]
        let proof = ob.resolve(Resolution::Commit);
        scope.on_resolve();

        // Typing rule: Γ ⊢ scope_close : ScopeProof   [requires 0 outstanding]
        let scope_proof = scope.close().expect("scope should be clean");

        // Verify the proof tokens exist (zero-cost witnesses).
        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "proof kind",
            ObligationKind::SendPermit,
            kind
        );
        let label = scope_proof.label();
        crate::assert_with_log!(label == "typing_demo", "scope label", "typing_demo", label);

        crate::test_complete!("typing_judgment_demonstration");
    }

    // ---- Resource semiring properties --------------------------------------

    #[test]
    fn resource_semiring_identity() {
        init_test("resource_semiring_identity");
        // 0 is the identity for +: scope with 0 obligations is clean.
        let scope = GradedScope::open("zero");
        let proof = scope.close().expect("zero obligations = clean");
        let total = proof.total_reserved();
        crate::assert_with_log!(total == 0, "zero reserved", 0, total);
        crate::test_complete!("resource_semiring_identity");
    }

    #[test]
    fn resource_semiring_additive() {
        init_test("resource_semiring_additive");
        // + is additive: obligations accumulate and must all be resolved.
        let mut scope = GradedScope::open("additive");

        // Reserve 3 obligations (1 + 1 + 1 = 3).
        for _ in 0..3 {
            let ob = GradedObligation::reserve(ObligationKind::Lease, "lease");
            scope.on_reserve();
            let _proof = ob.resolve(Resolution::Commit);
            scope.on_resolve();
        }

        let proof = scope.close().expect("all resolved");
        let total = proof.total_reserved();
        crate::assert_with_log!(total == 3, "3 reserved", 3, total);
        let resolved = proof.total_resolved();
        crate::assert_with_log!(resolved == 3, "3 resolved", 3, resolved);
        crate::test_complete!("resource_semiring_additive");
    }

    // ---- ObligationToken typestate tests ------------------------------------

    #[test]
    fn token_commit_returns_proof() {
        init_test("token_commit_returns_proof");
        let token: SendPermitToken = ObligationToken::reserve_test("commit-test");
        let proof = token.commit();
        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "proof kind",
            ObligationKind::SendPermit,
            kind
        );
        crate::test_complete!("token_commit_returns_proof");
    }

    #[test]
    fn token_abort_returns_proof() {
        init_test("token_abort_returns_proof");
        let token: AckToken = ObligationToken::reserve_test("abort-test");
        let proof = token.abort();
        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::Ack,
            "proof kind",
            ObligationKind::Ack,
            kind
        );
        crate::test_complete!("token_abort_returns_proof");
    }

    #[test]
    fn token_dynamic_kind_bridge_accepts_matching_hot_path_kind() {
        init_test("token_dynamic_kind_bridge_accepts_matching_hot_path_kind");
        let token: SendPermitToken = ObligationToken::try_reserve_kind(
            ObligationKind::SendPermit,
            "hot-path send",
            RegionId::new_ephemeral(),
        )
        .expect("send permit dynamic kind should map to SendPermitToken");

        let proof = token.commit();
        crate::assert_with_log!(
            proof.kind() == ObligationKind::SendPermit,
            "typed proof kind",
            ObligationKind::SendPermit,
            proof.kind()
        );
        let resolved = proof.into_resolved_proof();
        crate::assert_with_log!(
            resolved.resolution() == Resolution::Commit,
            "resolved proof",
            Resolution::Commit,
            resolved.resolution()
        );
        crate::test_complete!("token_dynamic_kind_bridge_accepts_matching_hot_path_kind");
    }

    #[test]
    fn token_dynamic_kind_bridge_rejects_mismatched_protocol_family() {
        init_test("token_dynamic_kind_bridge_rejects_mismatched_protocol_family");
        let err = SendPermitToken::try_reserve_kind(
            ObligationKind::Ack,
            "wrong dynamic family",
            RegionId::new_ephemeral(),
        )
        .expect_err("Ack must not manufacture a SendPermitToken");

        crate::assert_with_log!(
            err.expected == ObligationKind::SendPermit,
            "expected typed kind",
            ObligationKind::SendPermit,
            err.expected
        );
        crate::assert_with_log!(
            err.actual == ObligationKind::Ack,
            "actual dynamic kind",
            ObligationKind::Ack,
            err.actual
        );
        crate::assert_with_log!(
            format!("{err}").contains("expected send_permit, got ack"),
            "diagnostic",
            true,
            format!("{err}").contains("expected send_permit, got ack")
        );
        crate::test_complete!("token_dynamic_kind_bridge_rejects_mismatched_protocol_family");
    }

    #[test]
    fn scoped_dynamic_kind_bridge_tracks_abort_cleanup_parity() {
        init_test("scoped_dynamic_kind_bridge_tracks_abort_cleanup_parity");
        let mut scope = GradedScope::open("lease-hot-path");
        let token: LeaseToken = scope
            .try_reserve_token_kind(ObligationKind::Lease, "lease cancellation cleanup")
            .expect("Lease dynamic kind should map to LeaseToken");
        crate::assert_with_log!(scope.outstanding() == 1, "reserved", 1, scope.outstanding());

        let proof = scope.resolve_abort(token);
        crate::assert_with_log!(
            proof.kind() == ObligationKind::Lease,
            "abort proof kind",
            ObligationKind::Lease,
            proof.kind()
        );
        let resolved = proof.into_resolved_proof();
        crate::assert_with_log!(
            resolved.resolution() == Resolution::Abort,
            "abort bridges to resolved proof",
            Resolution::Abort,
            resolved.resolution()
        );

        let scope_proof = scope.close().expect("abort must leave scope balanced");
        crate::assert_with_log!(
            scope_proof.total_reserved() == 1,
            "scope reserved count",
            1,
            scope_proof.total_reserved()
        );
        crate::assert_with_log!(
            scope_proof.total_resolved() == 1,
            "scope resolved count",
            1,
            scope_proof.total_resolved()
        );
        crate::test_complete!("scoped_dynamic_kind_bridge_tracks_abort_cleanup_parity");
    }

    #[test]
    fn scoped_dynamic_kind_bridge_mismatch_does_not_increment_scope() {
        init_test("scoped_dynamic_kind_bridge_mismatch_does_not_increment_scope");
        let mut scope = GradedScope::open("mismatch");
        let err = scope
            .try_reserve_token_kind::<AckKind>(ObligationKind::SendPermit, "wrong ack family")
            .expect_err("SendPermit must not reserve AckToken scope state");

        crate::assert_with_log!(
            err.expected == ObligationKind::Ack,
            "expected typed kind",
            ObligationKind::Ack,
            err.expected
        );
        crate::assert_with_log!(
            err.actual == ObligationKind::SendPermit,
            "actual dynamic kind",
            ObligationKind::SendPermit,
            err.actual
        );
        crate::assert_with_log!(
            scope.outstanding() == 0,
            "mismatch leaves scope empty",
            0,
            scope.outstanding()
        );
        let proof = scope.close().expect("mismatch must not leak scope state");
        crate::assert_with_log!(
            proof.total_reserved() == 0,
            "no reservation recorded",
            0,
            proof.total_reserved()
        );
        crate::test_complete!("scoped_dynamic_kind_bridge_mismatch_does_not_increment_scope");
    }

    #[test]
    fn typed_obligation_bridge_contract_logs_required_evidence_fields() {
        init_test("typed_obligation_bridge_contract_logs_required_evidence_fields");
        let contract = typed_obligation_bridge_contract();

        crate::assert_with_log!(
            contract.bead_id == "asupersync-d87ytw.13",
            "bead id",
            "asupersync-d87ytw.13",
            contract.bead_id
        );
        crate::assert_with_log!(
            contract.protocol_family.contains("send-permit")
                && contract.protocol_family.contains("lease"),
            "protocol family",
            "send-permit/ack/lease graded obligations",
            contract.protocol_family
        );
        crate::assert_with_log!(
            contract
                .typed_entrypoint
                .ends_with("ObligationToken::try_reserve_kind"),
            "typed entrypoint",
            "ObligationToken::try_reserve_kind",
            contract.typed_entrypoint
        );
        crate::assert_with_log!(
            contract.dynamic_fallback == "asupersync::record::ObligationKind",
            "dynamic fallback",
            "asupersync::record::ObligationKind",
            contract.dynamic_fallback
        );
        crate::assert_with_log!(
            contract.compile_fail_surface.contains("commit-then-abort"),
            "compile-fail surface",
            "commit-then-abort",
            contract.compile_fail_surface
        );
        crate::assert_with_log!(
            contract.replay_command.contains("rch exec --")
                && contract
                    .replay_command
                    .contains("--lib dynamic_kind_bridge"),
            "replay command",
            "rch exec -- cargo test --lib dynamic_kind_bridge",
            contract.replay_command
        );
        crate::assert_with_log!(
            contract
                .invariants
                .contains(&"mismatched dynamic kind does not arm a token"),
            "migration fallback invariant",
            true,
            contract
                .invariants
                .contains(&"mismatched dynamic kind does not arm a token")
        );
        crate::test_complete!("typed_obligation_bridge_contract_logs_required_evidence_fields");
    }

    #[test]
    #[should_panic(expected = "[ASUP-E101] OBLIGATION TOKEN LEAKED")]
    fn token_drop_without_consume_panics() {
        init_test("token_drop_without_consume_panics");
        let _token: SendPermitToken = ObligationToken::reserve_test("leaked-token");
        // Dropped without commit or abort — should panic.
    }

    #[test]
    fn token_drop_without_consume_panic_carries_asup_e101() {
        init_test("token_drop_without_consume_panic_carries_asup_e101");
        let message = panic_message(std::panic::catch_unwind(|| {
            let _token: SendPermitToken = ObligationToken::reserve_test("leaked-token");
        }));
        crate::assert_with_log!(
            message.contains("[ASUP-E101]"),
            "error code",
            true,
            message.contains("[ASUP-E101]")
        );
        crate::assert_with_log!(
            message.contains("OBLIGATION TOKEN LEAKED"),
            "diagnostic class",
            true,
            message.contains("OBLIGATION TOKEN LEAKED")
        );
        crate::test_complete!("token_drop_without_consume_panic_carries_asup_e101");
    }

    #[test]
    fn tokens_dropped_while_unwinding_count_as_panic_leaks() {
        // br-asupersync-27bbrg: a token dropped during a panic returned without
        // being counted, so panic_leak_count missed permits, leases and
        // transaction tokens. The counter is global; 50 leaks in one unwind
        // cannot come from a concurrent test.
        init_test("tokens_dropped_while_unwinding_count_as_panic_leaks");
        let before = panic_leak_count();
        let result = std::panic::catch_unwind(|| {
            let _tokens: Vec<SendPermitToken> = (0..50)
                .map(|_| ObligationToken::reserve_test("unwound-token"))
                .collect();
            panic!("force unwind with armed tokens");
        });
        assert!(result.is_err());
        let after = panic_leak_count();
        assert!(
            after >= before + 50,
            "50 armed tokens dropped while unwinding: {before} -> {after}"
        );
        crate::test_complete!("tokens_dropped_while_unwinding_count_as_panic_leaks");
    }

    #[test]
    fn root_region_obligation_reserve_panic_carries_asup_e103() {
        init_test("root_region_obligation_reserve_panic_carries_asup_e103");
        let root_region = RegionId::from_arena(crate::util::ArenaIndex::new(0, 0));
        let message = panic_message(std::panic::catch_unwind(|| {
            let _token: SendPermitToken = ObligationToken::reserve("root-token", root_region);
        }));
        crate::assert_with_log!(
            message.contains("[ASUP-E103]"),
            "error code",
            true,
            message.contains("[ASUP-E103]")
        );
        crate::assert_with_log!(
            message.contains("root region"),
            "diagnostic class",
            true,
            message.contains("root region")
        );
        crate::test_complete!("root_region_obligation_reserve_panic_carries_asup_e103");
    }

    #[test]
    fn token_into_raw_disarms() {
        init_test("token_into_raw_disarms");
        let token: LeaseToken = ObligationToken::reserve_test("raw-escape");
        let raw = token.into_raw();
        let kind = raw.kind;
        crate::assert_with_log!(
            kind == ObligationKind::Lease,
            "raw kind",
            ObligationKind::Lease,
            kind
        );
        drop(raw);
        crate::test_complete!("token_into_raw_disarms");
    }

    #[test]
    fn committed_proof_bridge() {
        init_test("committed_proof_bridge");
        let token: SendPermitToken = ObligationToken::reserve_test("bridge-commit");
        let committed = token.commit();
        let resolved = committed.into_resolved_proof();
        let r = resolved.resolution();
        crate::assert_with_log!(r == Resolution::Commit, "resolution", Resolution::Commit, r);
        let kind = resolved.kind();
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "kind",
            ObligationKind::SendPermit,
            kind
        );
        crate::test_complete!("committed_proof_bridge");
    }

    #[test]
    fn aborted_proof_bridge() {
        init_test("aborted_proof_bridge");
        let token: AckToken = ObligationToken::reserve_test("bridge-abort");
        let aborted = token.abort();
        let resolved = aborted.into_resolved_proof();
        let r = resolved.resolution();
        crate::assert_with_log!(r == Resolution::Abort, "resolution", Resolution::Abort, r);
        let kind = resolved.kind();
        crate::assert_with_log!(
            kind == ObligationKind::Ack,
            "kind",
            ObligationKind::Ack,
            kind
        );
        crate::test_complete!("aborted_proof_bridge");
    }

    #[test]
    fn token_kind_mapping() {
        init_test("token_kind_mapping");
        let sp = SendPermit::obligation_kind();
        crate::assert_with_log!(
            sp == ObligationKind::SendPermit,
            "SendPermit",
            ObligationKind::SendPermit,
            sp
        );
        let ack = AckKind::obligation_kind();
        crate::assert_with_log!(
            ack == ObligationKind::Ack,
            "AckKind",
            ObligationKind::Ack,
            ack
        );
        let lease = LeaseKind::obligation_kind();
        crate::assert_with_log!(
            lease == ObligationKind::Lease,
            "LeaseKind",
            ObligationKind::Lease,
            lease
        );
        let io = IoOpKind::obligation_kind();
        crate::assert_with_log!(
            io == ObligationKind::IoOp,
            "IoOpKind",
            ObligationKind::IoOp,
            io
        );
        crate::test_complete!("token_kind_mapping");
    }

    #[test]
    fn scope_reserve_and_commit_token() {
        init_test("scope_reserve_and_commit_token");
        let mut scope = GradedScope::open("token-scope-commit");
        let token: SendPermitToken = scope.reserve_token("scoped-send");
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 1, "outstanding", 1, outstanding);

        let proof = scope.resolve_commit(token);
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 0, "outstanding", 0, outstanding);

        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "kind",
            ObligationKind::SendPermit,
            kind
        );

        let scope_proof = scope.close().expect("scope should close cleanly");
        let total = scope_proof.total_reserved();
        crate::assert_with_log!(total == 1, "reserved", 1, total);
        crate::test_complete!("scope_reserve_and_commit_token");
    }

    #[test]
    fn scope_reserve_and_abort_token() {
        init_test("scope_reserve_and_abort_token");
        let mut scope = GradedScope::open("token-scope-abort");
        let token: AckToken = scope.reserve_token("scoped-ack");
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 1, "outstanding", 1, outstanding);

        let proof = scope.resolve_abort(token);
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 0, "outstanding", 0, outstanding);

        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::Ack,
            "kind",
            ObligationKind::Ack,
            kind
        );

        let scope_proof = scope.close().expect("scope should close cleanly");
        let total = scope_proof.total_reserved();
        crate::assert_with_log!(total == 1, "reserved", 1, total);
        crate::test_complete!("scope_reserve_and_abort_token");
    }

    #[test]
    fn all_four_token_kinds() {
        init_test("all_four_token_kinds");

        // SendPermit
        let t1: SendPermitToken = ObligationToken::reserve_test("sp");
        let p1 = t1.commit();
        let k1 = p1.kind();
        crate::assert_with_log!(
            k1 == ObligationKind::SendPermit,
            "SendPermit",
            ObligationKind::SendPermit,
            k1
        );

        // Ack
        let t2: AckToken = ObligationToken::reserve_test("ack");
        let p2 = t2.abort();
        let k2 = p2.kind();
        crate::assert_with_log!(k2 == ObligationKind::Ack, "Ack", ObligationKind::Ack, k2);

        // Lease
        let t3: LeaseToken = ObligationToken::reserve_test("lease");
        let p3 = t3.commit();
        let k3 = p3.kind();
        crate::assert_with_log!(
            k3 == ObligationKind::Lease,
            "Lease",
            ObligationKind::Lease,
            k3
        );

        // IoOp
        let t4: IoOpToken = ObligationToken::reserve_test("io");
        let p4 = t4.abort();
        let k4 = p4.kind();
        crate::assert_with_log!(k4 == ObligationKind::IoOp, "IoOp", ObligationKind::IoOp, k4);

        crate::test_complete!("all_four_token_kinds");
    }

    // =========================================================================
    // Wave 59 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn resolution_debug_clone_copy_eq() {
        let r = Resolution::Commit;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Commit"), "{dbg}");
        let copied = r;
        let cloned = r;
        assert_eq!(copied, cloned);
        assert_ne!(r, Resolution::Abort);
    }

    #[test]
    fn resolved_proof_debug_eq() {
        let rp = ResolvedProof {
            kind: ObligationKind::SendPermit,
            resolution: Resolution::Commit,
        };
        let dbg = format!("{rp:?}");
        assert!(dbg.contains("ResolvedProof"), "{dbg}");
        let rp_same = ResolvedProof {
            kind: ObligationKind::SendPermit,
            resolution: Resolution::Commit,
        };
        assert_eq!(rp, rp_same);
    }

    #[test]
    fn scope_proof_debug_accessors() {
        let sp = ScopeProof {
            label: "test".to_string(),
            total_reserved: 5,
            total_resolved: 5,
        };
        let dbg = format!("{sp:?}");
        assert!(dbg.contains("ScopeProof"), "{dbg}");
        assert_eq!(sp.label(), "test");
        assert_eq!(sp.total_reserved(), 5);
        assert_eq!(sp.total_resolved(), 5);
    }

    #[test]
    #[should_panic(expected = "on_reserve overflowed outstanding obligation count")]
    fn scope_on_reserve_overflow_panics_instead_of_wrapping() {
        let mut scope = GradedScope {
            label: "overflow".to_string(),
            reserved: u32::MAX,
            resolved: 0,
            closed: false,
        };
        scope.on_reserve();
    }

    #[test]
    #[should_panic(expected = "toy channel occupancy overflowed")]
    fn toy_channel_capacity_overflow_panics_instead_of_wrapping() {
        let mut ch =
            toy_api::ToyChannel::from_state(usize::MAX, vec!["occupied".to_string()], usize::MAX);
        let _ = ch.reserve_send();
    }

    #[test]
    fn close_err_does_not_panic_when_caller_handles_error() {
        let mut scope = GradedScope::open("leak-test");
        scope.on_reserve();
        // close() returns Err because 1 obligation is outstanding.
        // The caller explicitly called close() and received the error,
        // so Drop should NOT panic — the leak is acknowledged.
        let err = scope.close().expect_err("should return leak error");
        assert_eq!(err.outstanding, 1);
    }

    // ========================================================================
    // GRADED-REFINEMENT conformance harness (Pattern 4: spec-derived)
    //
    // The typing judgment at the top of this module is the spec:
    //
    //   Γ ⊢ reserve(K)     : Obligation<K>     [+1 unit of K]
    //   Γ, x: Obligation<K> ⊢ commit(x) : ()   [-1 unit of K]
    //   Γ, x: Obligation<K> ⊢ abort(x)  : ()   [-1 unit of K]
    //   Γ ⊢ scope(body) : τ   iff   Γ_exit has 0 outstanding Obligation<K>
    //
    // Each GRADED-REFINEMENT-N clause below mechanically verifies one
    // refinement-boundary law implied by the judgment.
    //
    // Every case emits one stderr JSON-line verdict of shape:
    //   {"id":"GRADED-REFINEMENT-N","verdict":"PASS|FAIL","level":"MUST"}
    // so a CI harness can grep+count pass/fail without parsing panics.
    // ========================================================================

    fn emit_verdict(id: &str, pass: bool) {
        eprintln!(
            "{{\"id\":\"{id}\",\"verdict\":\"{}\",\"level\":\"MUST\"}}",
            if pass { "PASS" } else { "FAIL" }
        );
    }

    // GRADED-REFINEMENT-1: reserve(K) increases reserved count by exactly 1.
    #[test]
    fn conformance_graded_refinement_1_reserve_is_plus_one() {
        init_test("GRADED-REFINEMENT-1");
        let mut scope = GradedScope::open("L1");
        let r0 = scope.outstanding();
        scope.on_reserve();
        let r1 = scope.outstanding();
        let pass = r0 == 0 && r1 == 1;
        emit_verdict("GRADED-REFINEMENT-1", pass);
        // Clean up so Drop doesn't panic.
        scope.on_resolve();
        let _ = scope.close();
        assert!(pass, "reserve did not increment outstanding by exactly 1");
    }

    // GRADED-REFINEMENT-2: commit(x) decreases outstanding by exactly 1.
    #[test]
    fn conformance_graded_refinement_2_commit_is_minus_one() {
        init_test("GRADED-REFINEMENT-2");
        let mut scope = GradedScope::open("L2");
        scope.on_reserve();
        let before = scope.outstanding();
        let tok: ObligationToken<SendPermit> = ObligationToken::reserve_test("L2");
        let _proof = tok.commit(); // consume token
        scope.on_resolve();
        let after = scope.outstanding();
        let pass = before == 1 && after == 0;
        emit_verdict("GRADED-REFINEMENT-2", pass);
        let _ = scope.close();
        assert!(pass, "commit did not decrement outstanding by exactly 1");
    }

    // GRADED-REFINEMENT-3: abort(x) decreases outstanding by exactly 1
    // (symmetric with commit: the refinement sees only "resolved").
    #[test]
    fn conformance_graded_refinement_3_abort_is_minus_one() {
        init_test("GRADED-REFINEMENT-3");
        let mut scope = GradedScope::open("L3");
        scope.on_reserve();
        let before = scope.outstanding();
        let tok: ObligationToken<AckKind> = ObligationToken::reserve_test("L3");
        let _proof = tok.abort();
        scope.on_resolve();
        let after = scope.outstanding();
        let pass = before == 1 && after == 0;
        emit_verdict("GRADED-REFINEMENT-3", pass);
        let _ = scope.close();
        assert!(pass, "abort did not decrement outstanding by exactly 1");
    }

    // GRADED-REFINEMENT-4: scope close() at 0 outstanding yields a ScopeProof
    // whose total_reserved == total_resolved.
    #[test]
    fn conformance_graded_refinement_4_close_clean_boundary() {
        init_test("GRADED-REFINEMENT-4");
        let mut scope = GradedScope::open("L4");
        for _ in 0..7 {
            scope.on_reserve();
            scope.on_resolve();
        }
        let result = scope.close();
        let pass = match &result {
            Ok(p) => p.total_reserved() == 7 && p.total_resolved() == 7,
            Err(_) => false,
        };
        emit_verdict("GRADED-REFINEMENT-4", pass);
        assert!(
            pass,
            "close() at 0 outstanding did not produce matching counts"
        );
    }

    // GRADED-REFINEMENT-5: scope close() with outstanding > 0 yields a
    // ScopeLeakError whose fields satisfy reserved - resolved == outstanding.
    #[test]
    fn conformance_graded_refinement_5_close_leak_exact_accounting() {
        init_test("GRADED-REFINEMENT-5");
        let mut scope = GradedScope::open("L5");
        for _ in 0..5 {
            scope.on_reserve();
        }
        for _ in 0..2 {
            scope.on_resolve();
        }
        let err = scope.close().expect_err("expected leak");
        let pass = err.reserved == 5
            && err.resolved == 2
            && err.outstanding == err.reserved - err.resolved
            && err.outstanding == 3;
        emit_verdict("GRADED-REFINEMENT-5", pass);
        assert!(pass, "leak accounting diverges from reserved - resolved");
    }

    // GRADED-REFINEMENT-6: outstanding() is a pure function of the running
    // net of reserves vs. resolves. After any prefix of a balanced interleaving,
    // outstanding() == (#reserves_seen - #resolves_seen) and is non-negative.
    //
    // Note: on_resolve() panics if called more times than on_reserve(), so the
    // op sequence below is a valid prefix (net never goes negative).
    #[test]
    fn conformance_graded_refinement_6_outstanding_tracks_running_net() {
        init_test("GRADED-REFINEMENT-6");
        let mut scope = GradedScope::open("L6");
        let ops = [
            true, true, false, true, false, false, true, true, false, false,
        ];
        let mut net: i64 = 0;
        let mut ok = true;
        for reserve in ops {
            if reserve {
                scope.on_reserve();
                net += 1;
            } else {
                scope.on_resolve();
                net -= 1;
            }
            let got = i64::from(scope.outstanding());
            if got != net || net < 0 {
                ok = false;
            }
        }
        // Balanced: outstanding must be exactly 0 at the end.
        ok = ok && scope.outstanding() == 0 && net == 0;
        emit_verdict("GRADED-REFINEMENT-6", ok);
        let _ = scope.close();
        assert!(ok, "outstanding diverged from the running net of ops");
    }

    // GRADED-REFINEMENT-7: Resolution preserves obligation kind.
    // GradedObligation::reserve(K, _).resolve(r).kind() == K.
    #[test]
    fn conformance_graded_refinement_7_resolution_preserves_kind() {
        init_test("GRADED-REFINEMENT-7");
        let cases = [
            (ObligationKind::SendPermit, Resolution::Commit),
            (ObligationKind::SendPermit, Resolution::Abort),
            (ObligationKind::Ack, Resolution::Commit),
            (ObligationKind::Ack, Resolution::Abort),
            (ObligationKind::Lease, Resolution::Commit),
            (ObligationKind::Lease, Resolution::Abort),
            (ObligationKind::IoOp, Resolution::Commit),
            (ObligationKind::IoOp, Resolution::Abort),
            (ObligationKind::SemaphorePermit, Resolution::Commit),
            (ObligationKind::SemaphorePermit, Resolution::Abort),
            (ObligationKind::Transaction, Resolution::Commit),
            (ObligationKind::Transaction, Resolution::Abort),
        ];
        let mut pass = true;
        for (k, r) in cases {
            let ob = GradedObligation::reserve(k, "kind-test");
            let proof = ob.resolve(r);
            if proof.kind() != k || proof.resolution() != r {
                pass = false;
            }
        }
        emit_verdict("GRADED-REFINEMENT-7", pass);
        assert!(pass, "resolution dropped kind or resolution on the floor");
    }

    // GRADED-REFINEMENT-8: Typestate ObligationToken<K> preserves K through
    // CommittedProof<K> / AbortedProof<K>.
    #[test]
    fn conformance_graded_refinement_8_typestate_preserves_kind() {
        init_test("GRADED-REFINEMENT-8");
        let send_commit = <SendPermit as TokenKind>::obligation_kind();
        let ack_abort = <AckKind as TokenKind>::obligation_kind();

        let t1: SendPermitToken = ObligationToken::reserve_test("send");
        let p1 = t1.commit();
        let pass1 = p1.kind() == send_commit && p1.into_resolved_proof().kind() == send_commit;

        let t2: AckToken = ObligationToken::reserve_test("ack");
        let p2 = t2.abort();
        let pass2 = p2.kind() == ack_abort && p2.into_resolved_proof().kind() == ack_abort;

        let pass = pass1 && pass2;
        emit_verdict("GRADED-REFINEMENT-8", pass);
        assert!(pass, "typestate token lost kind across commit/abort");
    }

    // GRADED-REFINEMENT-9: into_raw() disarms the drop bomb AND preserves kind.
    #[test]
    fn conformance_graded_refinement_9_into_raw_disarms_and_preserves_kind() {
        init_test("GRADED-REFINEMENT-9");
        let ob = GradedObligation::reserve(ObligationKind::Lease, "raw");
        let raw = ob.into_raw();
        let pass_a = raw.kind == ObligationKind::Lease && raw.description == "raw";

        let tok: LeaseToken = ObligationToken::reserve_test("raw-ts");
        let raw2 = tok.into_raw();
        let pass_b = raw2.kind == ObligationKind::Lease && raw2.description == "raw-ts";

        // If into_raw did NOT disarm the drop bomb, the two calls above would
        // have panicked. Reaching this point is the disarm proof.
        let pass = pass_a && pass_b;
        emit_verdict("GRADED-REFINEMENT-9", pass);
        assert!(
            pass,
            "into_raw lost kind or description across the boundary"
        );
    }

    // GRADED-REFINEMENT-10: Boundary monotonicity — scope close() returning
    // Ok implies all ScopeProof counts are ≥ 0 and total_reserved == total_resolved;
    // scope close() returning Err implies outstanding > 0 and
    // reserved > resolved. Cases are disjoint and cover the boundary.
    #[test]
    fn conformance_graded_refinement_10_close_boundary_disjoint() {
        init_test("GRADED-REFINEMENT-10");
        // Clean side.
        let mut clean = GradedScope::open("L10-clean");
        for _ in 0..3 {
            clean.on_reserve();
            clean.on_resolve();
        }
        let clean_ok = clean.close();
        let clean_pass =
            matches!(&clean_ok, Ok(p) if p.total_reserved() == 3 && p.total_resolved() == 3);

        // Leaky side.
        let mut leaky = GradedScope::open("L10-leaky");
        for _ in 0..4 {
            leaky.on_reserve();
        }
        for _ in 0..1 {
            leaky.on_resolve();
        }
        let leaky_err = leaky.close();
        let leaky_pass = matches!(
            &leaky_err,
            Err(e) if e.outstanding == 3 && e.reserved > e.resolved && e.reserved == 4 && e.resolved == 1
        );

        let pass = clean_pass && leaky_pass;
        emit_verdict("GRADED-REFINEMENT-10", pass);
        assert!(
            pass,
            "close() boundary cases are not disjoint or mis-accounted"
        );
    }
