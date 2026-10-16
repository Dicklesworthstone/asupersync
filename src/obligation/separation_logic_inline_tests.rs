    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn r(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn o(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    fn reserve_event(
        time_ns: u64,
        obligation: ObligationId,
        kind: ObligationKind,
        task: TaskId,
        region: RegionId,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            },
        )
    }

    fn commit_event(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Commit {
                obligation,
                region,
                kind,
            },
        )
    }

    fn abort_event(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Abort {
                obligation,
                region,
                kind,
            },
        )
    }

    fn leak_event(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Leak {
                obligation,
                region,
                kind,
            },
        )
    }

    fn close_event(time_ns: u64, region: RegionId) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::RegionClose { region },
        )
    }

    // ---- Resource Algebra tests ------------------------------------------------

    #[test]
    fn excl_compose_disjoint() {
        init_test("excl_compose_disjoint");
        let a: Excl<ObligationState> = Excl::Some(ObligationState::Reserved);
        let b: Excl<ObligationState> = Excl::Consumed;
        let result = a.compose(&b);
        crate::assert_with_log!(
            result.is_none(),
            "consumed tombstone still conflicts with live ownership",
            true,
            result.is_none()
        );
        crate::test_complete!("excl_compose_disjoint");
    }

    #[test]
    fn excl_compose_aliasing_fails() {
        init_test("excl_compose_aliasing_fails");
        let a: Excl<ObligationState> = Excl::Some(ObligationState::Reserved);
        let b: Excl<ObligationState> = Excl::Some(ObligationState::Committed);
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_none(), "aliasing compose fails", true, true);
        crate::test_complete!("excl_compose_aliasing_fails");
    }

    #[test]
    fn agree_compose_matching() {
        init_test("agree_compose_matching");
        let a = Agree(ObligationKind::SendPermit);
        let b = Agree(ObligationKind::SendPermit);
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_some(), "matching agree succeeds", true, true);
        crate::test_complete!("agree_compose_matching");
    }

    #[test]
    fn agree_compose_mismatch_fails() {
        init_test("agree_compose_mismatch_fails");
        let a = Agree(ObligationKind::SendPermit);
        let b = Agree(ObligationKind::Lease);
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_none(), "mismatch agree fails", true, true);
        crate::test_complete!("agree_compose_mismatch_fails");
    }

    #[test]
    fn auth_nat_valid_fragment() {
        init_test("auth_nat_valid_fragment");
        let auth = AuthNat::Auth(5);
        let frag = AuthNat::Frag(3);
        let result = auth.compose(&frag);
        crate::assert_with_log!(result.is_some(), "valid fragment compose", true, true);
        crate::test_complete!("auth_nat_valid_fragment");
    }

    #[test]
    fn auth_nat_exceeding_fragment_fails() {
        init_test("auth_nat_exceeding_fragment_fails");
        let auth = AuthNat::Auth(2);
        let frag = AuthNat::Frag(5);
        let result = auth.compose(&frag);
        crate::assert_with_log!(result.is_none(), "exceeding fragment fails", true, true);
        crate::test_complete!("auth_nat_exceeding_fragment_fails");
    }

    #[test]
    fn auth_nat_two_auth_fails() {
        init_test("auth_nat_two_auth_fails");
        let a = AuthNat::Auth(1);
        let b = AuthNat::Auth(2);
        let result = a.compose(&b);
        crate::assert_with_log!(result.is_none(), "two auth fails", true, true);
        crate::test_complete!("auth_nat_two_auth_fails");
    }

    #[test]
    fn auth_nat_fragments_additive() {
        init_test("auth_nat_fragments_additive");
        let a = AuthNat::Frag(3);
        let b = AuthNat::Frag(4);
        let result = a.compose(&b);
        let expected = AuthNat::Frag(7);
        crate::assert_with_log!(
            result == Some(expected.clone()),
            "fragments add",
            expected,
            result
        );
        crate::test_complete!("auth_nat_fragments_additive");
    }

    #[test]
    fn auth_nat_fragment_overflow_returns_none() {
        init_test("auth_nat_fragment_overflow_returns_none");
        let a = AuthNat::Frag(u64::MAX);
        let b = AuthNat::Frag(1);
        let result = a.compose(&b);
        crate::assert_with_log!(
            result.is_none(),
            "fragment overflow yields invalid composition",
            true,
            true
        );
        crate::test_complete!("auth_nat_fragment_overflow_returns_none");
    }

    // ---- Resource Predicate tests ----------------------------------------------

    #[test]
    fn resource_predicate_separation() {
        init_test("resource_predicate_separation");
        let p1 = ResourcePredicate::reserved(o(0), ObligationKind::SendPermit, t(0), r(0));
        let p2 = ResourcePredicate::reserved(o(1), ObligationKind::Ack, t(0), r(0));
        let separable = p1.is_separable_from(&p2);
        crate::assert_with_log!(separable, "different IDs are separable", true, separable);
        crate::test_complete!("resource_predicate_separation");
    }

    #[test]
    fn resource_predicate_same_id_not_separable() {
        init_test("resource_predicate_same_id_not_separable");
        let p1 = ResourcePredicate::reserved(o(0), ObligationKind::SendPermit, t(0), r(0));
        let p2 = ResourcePredicate::reserved(o(0), ObligationKind::SendPermit, t(0), r(0));
        let separable = p1.is_separable_from(&p2);
        crate::assert_with_log!(!separable, "same ID not separable", false, separable);
        crate::test_complete!("resource_predicate_same_id_not_separable");
    }

    #[test]
    fn resource_predicate_display() {
        init_test("resource_predicate_display");
        let p = ResourcePredicate::reserved(o(0), ObligationKind::Lease, t(1), r(2));
        let s = format!("{p}");
        let has_lease = s.contains("lease");
        crate::assert_with_log!(has_lease, "display has kind", true, has_lease);
        crate::test_complete!("resource_predicate_display");
    }

    // ---- Frame Condition tests -------------------------------------------------

    #[test]
    fn frame_condition_other_obligations_framed() {
        init_test("frame_condition_other_obligations_framed");
        let frame = FrameCondition::single_obligation(o(0), t(0), r(0));
        let framed = frame.is_framed(o(1));
        crate::assert_with_log!(framed, "other obligation is framed", true, framed);
        let not_framed = !frame.is_framed(o(0));
        crate::assert_with_log!(not_framed, "target is NOT framed", true, not_framed);
        crate::test_complete!("frame_condition_other_obligations_framed");
    }

    #[test]
    fn frame_condition_other_tasks_framed() {
        init_test("frame_condition_other_tasks_framed");
        let frame = FrameCondition::single_obligation(o(0), t(0), r(0));
        let framed = frame.task_is_framed(t(1));
        crate::assert_with_log!(framed, "other task is framed", true, framed);
        let not_framed = !frame.task_is_framed(t(0));
        crate::assert_with_log!(not_framed, "target task NOT framed", true, not_framed);
        crate::test_complete!("frame_condition_other_tasks_framed");
    }

    #[test]
    fn frame_condition_other_regions_framed() {
        init_test("frame_condition_other_regions_framed");
        let frame = FrameCondition::single_obligation(o(0), t(0), r(0));
        let framed = frame.region_is_framed(r(1));
        crate::assert_with_log!(framed, "other region is framed", true, framed);
        crate::test_complete!("frame_condition_other_regions_framed");
    }

    // ---- Separation Property tests ---------------------------------------------

    #[test]
    fn separation_property_formal_statements() {
        init_test("separation_property_formal_statements");
        let props = [
            SeparationProperty::DistinctIdentity {
                left: o(0),
                right: o(1),
            },
            SeparationProperty::NoAliasing { obligation: o(0) },
            SeparationProperty::NoUseAfterRelease { obligation: o(0) },
            SeparationProperty::RegionClosureQuiescence { region: r(0) },
            SeparationProperty::HolderCleanup { task: t(0) },
            SeparationProperty::TemporalOrdering {
                obligation: Some(o(0)),
            },
            SeparationProperty::AuthoritativePendingAgreement,
        ];
        for prop in &props {
            let stmt = prop.formal_statement();
            let non_empty = !stmt.is_empty();
            crate::assert_with_log!(non_empty, format!("{prop} has statement"), true, non_empty);
        }
        crate::test_complete!("separation_property_formal_statements");
    }

    // ---- Judgment tests --------------------------------------------------------

    #[test]
    fn judgment_reserve_has_frame() {
        init_test("judgment_reserve_has_frame");
        let j = Judgment::reserve(o(0), ObligationKind::SendPermit, t(0), r(0), 0, 0);
        let has_frame = j.frame.is_some();
        crate::assert_with_log!(has_frame, "reserve judgment has frame", true, has_frame);

        // Postcondition should have the obligation predicate.
        let post_pred_count = j.postcondition.predicates.len();
        crate::assert_with_log!(
            post_pred_count == 1,
            "one postcondition predicate",
            1,
            post_pred_count
        );

        // Postcondition pending counts should be incremented.
        let holder_count = j.postcondition.holder_pending.get(&t(0)).copied();
        crate::assert_with_log!(
            holder_count == Some(1),
            "holder pending = 1",
            Some(1),
            holder_count
        );

        let region_count = j.postcondition.region_pending.get(&r(0)).copied();
        crate::assert_with_log!(
            region_count == Some(1),
            "region pending = 1",
            Some(1),
            region_count
        );
        crate::test_complete!("judgment_reserve_has_frame");
    }

    #[test]
    fn judgment_commit_decrements_counts() {
        init_test("judgment_commit_decrements_counts");
        let j = Judgment::commit(o(0), ObligationKind::SendPermit, t(0), r(0), 2, 3);
        let holder_post = j.postcondition.holder_pending.get(&t(0)).copied();
        crate::assert_with_log!(
            holder_post == Some(1),
            "holder decremented",
            Some(1),
            holder_post
        );
        let region_post = j.postcondition.region_pending.get(&r(0)).copied();
        crate::assert_with_log!(
            region_post == Some(2),
            "region decremented",
            Some(2),
            region_post
        );
        crate::test_complete!("judgment_commit_decrements_counts");
    }

    #[test]
    #[should_panic(expected = "commit judgment requires positive holder pending count")]
    fn judgment_commit_rejects_zero_pending() {
        let _ = Judgment::commit(o(0), ObligationKind::SendPermit, t(0), r(0), 0, 1);
    }

    #[test]
    fn judgment_region_close_requires_zero_pending() {
        init_test("judgment_region_close_requires_zero_pending");
        let j = Judgment::region_close(r(0));
        let pre_pending = j.precondition.region_pending.get(&r(0)).copied();
        crate::assert_with_log!(
            pre_pending == Some(0),
            "pre requires 0 pending",
            Some(0),
            pre_pending
        );
        let pre_open = j.precondition.regions_open.contains(&r(0));
        crate::assert_with_log!(pre_open, "pre requires open", true, pre_open);
        let post_closed = j.postcondition.regions_closed.contains(&r(0));
        crate::assert_with_log!(post_closed, "post has closed", true, post_closed);
        crate::test_complete!("judgment_region_close_requires_zero_pending");
    }

    // ---- Verifier: sound traces ------------------------------------------------

    #[test]
    fn verifier_clean_reserve_commit_close() {
        init_test("verifier_clean_reserve_commit_close");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            close_event(20, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "clean trace is sound", true, sound);
        let jv = result.judgments_verified;
        crate::assert_with_log!(jv == 3, "3 judgments verified", 3, jv);
        crate::test_complete!("verifier_clean_reserve_commit_close");
    }

    #[test]
    fn verifier_clean_abort_path() {
        init_test("verifier_clean_abort_path");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::Lease, t(0), r(0)),
            abort_event(5, o(0), r(0), ObligationKind::Lease),
            close_event(10, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "abort path is sound", true, sound);
        crate::test_complete!("verifier_clean_abort_path");
    }

    #[test]
    fn verifier_clean_multiple_obligations() {
        init_test("verifier_clean_multiple_obligations");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_event(1, o(1), ObligationKind::Ack, t(0), r(0)),
            reserve_event(2, o(2), ObligationKind::Lease, t(1), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            commit_event(11, o(1), r(0), ObligationKind::Ack),
            abort_event(12, o(2), r(0), ObligationKind::Lease),
            close_event(20, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "multiple obligations sound", true, sound);
        crate::test_complete!("verifier_clean_multiple_obligations");
    }

    #[test]
    fn verifier_clean_nested_regions() {
        init_test("verifier_clean_nested_regions");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve_event(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit_event(10, o(1), r(1), ObligationKind::SendPermit),
            close_event(15, r(1)),
            commit_event(20, o(0), r(0), ObligationKind::Lease),
            close_event(25, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "nested regions sound", true, sound);
        crate::test_complete!("verifier_clean_nested_regions");
    }

    #[test]
    fn metamorphic_framed_subtrace_reordering_preserves_verifier_outcome() {
        init_test("metamorphic_framed_subtrace_reordering_preserves_verifier_outcome");

        let interleaved = vec![
            reserve_event(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve_event(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit_event(10, o(0), r(0), ObligationKind::Lease),
            abort_event(11, o(1), r(1), ObligationKind::SendPermit),
            close_event(20, r(0)),
            close_event(21, r(1)),
        ];
        let reordered = vec![
            reserve_event(0, o(1), ObligationKind::SendPermit, t(1), r(1)),
            abort_event(1, o(1), r(1), ObligationKind::SendPermit),
            close_event(2, r(1)),
            reserve_event(10, o(0), ObligationKind::Lease, t(0), r(0)),
            commit_event(11, o(0), r(0), ObligationKind::Lease),
            close_event(12, r(0)),
        ];

        let mut interleaved_verifier = SeparationLogicVerifier::new();
        let interleaved_result = interleaved_verifier.verify(&interleaved);

        let mut reordered_verifier = SeparationLogicVerifier::new();
        let reordered_result = reordered_verifier.verify(&reordered);

        crate::assert_with_log!(
            interleaved_result.is_sound(),
            "interleaved framed trace is sound",
            true,
            interleaved_result.is_sound()
        );
        crate::assert_with_log!(
            reordered_result.is_sound(),
            "reordered framed trace is sound",
            true,
            reordered_result.is_sound()
        );
        crate::assert_with_log!(
            interleaved_result.violations.len() == reordered_result.violations.len(),
            "framed reorder preserves violation count",
            interleaved_result.violations.len(),
            reordered_result.violations.len()
        );
        crate::assert_with_log!(
            interleaved_result.judgments_verified == reordered_result.judgments_verified,
            "framed reorder preserves judgment count",
            interleaved_result.judgments_verified,
            reordered_result.judgments_verified
        );
        crate::assert_with_log!(
            interleaved_result.frame_checks == reordered_result.frame_checks,
            "framed reorder preserves frame checks",
            interleaved_result.frame_checks,
            reordered_result.frame_checks
        );
        crate::assert_with_log!(
            interleaved_result.separation_checks == reordered_result.separation_checks,
            "framed reorder preserves separation checks",
            interleaved_result.separation_checks,
            reordered_result.separation_checks
        );
        crate::test_complete!("metamorphic_framed_subtrace_reordering_preserves_verifier_outcome");
    }

    #[test]
    fn verifier_leak_is_terminal() {
        init_test("verifier_leak_is_terminal");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::IoOp, t(0), r(0)),
            leak_event(5, o(0), r(0), ObligationKind::IoOp),
            close_event(10, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "leak is terminal (sound)", true, sound);
        crate::test_complete!("verifier_leak_is_terminal");
    }

    // ---- Verifier: violations --------------------------------------------------

    #[test]
    fn verifier_detects_aliasing() {
        init_test("verifier_detects_aliasing");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_event(5, o(0), ObligationKind::SendPermit, t(0), r(0)), // Alias!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "aliasing detected", false, sound);
        let aliasing_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::NoAliasing { .. }))
            .count();
        crate::assert_with_log!(
            aliasing_count == 1,
            "one aliasing violation",
            1,
            aliasing_count
        );
        crate::test_complete!("verifier_detects_aliasing");
    }

    #[test]
    fn verifier_detects_use_after_release() {
        init_test("verifier_detects_use_after_release");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            commit_event(20, o(0), r(0), ObligationKind::SendPermit), // Use after release!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "use-after-release detected", false, sound);
        let uar_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::NoUseAfterRelease { .. }))
            .count();
        crate::assert_with_log!(
            uar_count == 1,
            "one use-after-release violation",
            1,
            uar_count
        );
        crate::test_complete!("verifier_detects_use_after_release");
    }

    #[test]
    fn verifier_detects_reuse_after_release() {
        init_test("verifier_detects_reuse_after_release");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            reserve_event(20, o(0), ObligationKind::SendPermit, t(1), r(1)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let reuse_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::NoUseAfterRelease { .. }))
            .count();
        crate::assert_with_log!(
            reuse_count >= 1,
            "reusing a resolved obligation id is use-after-release",
            true,
            reuse_count >= 1
        );
        crate::test_complete!("verifier_detects_reuse_after_release");
    }

    #[test]
    fn verifier_detects_region_close_with_pending() {
        init_test("verifier_detects_region_close_with_pending");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_event(10, r(0)), // Region closed with pending obligation!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "pending at close detected", false, sound);
        let quiescence_count = result
            .violations_for_property(|p| {
                matches!(p, SeparationProperty::RegionClosureQuiescence { .. })
            })
            .count();
        crate::assert_with_log!(
            quiescence_count >= 1,
            "quiescence violation",
            true,
            quiescence_count >= 1
        );
        crate::test_complete!("verifier_detects_region_close_with_pending");
    }

    #[test]
    fn verifier_detects_kind_mismatch() {
        init_test("verifier_detects_kind_mismatch");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::Lease), // Kind mismatch!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "kind mismatch detected", false, sound);
        crate::test_complete!("verifier_detects_kind_mismatch");
    }

    #[test]
    fn verifier_detects_region_mismatch() {
        init_test("verifier_detects_region_mismatch");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(1), ObligationKind::SendPermit), // Region mismatch!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "region mismatch detected", false, sound);
        crate::test_complete!("verifier_detects_region_mismatch");
    }

    #[test]
    fn verifier_detects_per_obligation_time_reversal() {
        init_test("verifier_detects_per_obligation_time_reversal");
        let events = vec![
            reserve_event(10, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(5, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let temporal_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::TemporalOrdering { .. }))
            .count();
        crate::assert_with_log!(
            temporal_count >= 1,
            "resolution before reserve timestamp detected",
            true,
            temporal_count >= 1
        );
        crate::test_complete!("verifier_detects_per_obligation_time_reversal");
    }

    #[test]
    fn verifier_detects_non_monotone_trace_times() {
        init_test("verifier_detects_non_monotone_trace_times");
        let events = vec![
            reserve_event(10, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_event(9, o(1), ObligationKind::Ack, t(1), r(1)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let temporal_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::TemporalOrdering { .. }))
            .count();
        crate::assert_with_log!(
            temporal_count >= 1,
            "non-monotone trace time detected",
            true,
            temporal_count >= 1
        );
        crate::test_complete!("verifier_detects_non_monotone_trace_times");
    }

    #[test]
    fn verifier_detects_resolve_without_reserve() {
        init_test("verifier_detects_resolve_without_reserve");
        let events = vec![
            commit_event(10, o(99), r(0), ObligationKind::SendPermit), // Never reserved!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "resolve without reserve detected", false, sound);
        crate::test_complete!("verifier_detects_resolve_without_reserve");
    }

    #[test]
    fn verifier_detects_unresolved_at_trace_end() {
        init_test("verifier_detects_unresolved_at_trace_end");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::Ack, t(0), r(0)),
            // No resolution — obligation still pending at trace end.
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "unresolved detected", false, sound);
        let holder_count = result
            .violations_for_property(|p| matches!(p, SeparationProperty::HolderCleanup { .. }))
            .count();
        crate::assert_with_log!(
            holder_count == 1,
            "holder cleanup violation",
            1,
            holder_count
        );
        crate::test_complete!("verifier_detects_unresolved_at_trace_end");
    }

    #[test]
    fn verifier_detects_reserve_in_closed_region() {
        init_test("verifier_detects_reserve_in_closed_region");
        let events = vec![
            close_event(0, r(0)),
            reserve_event(10, o(0), ObligationKind::SendPermit, t(0), r(0)), // After close!
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "reserve in closed region detected", false, sound);
        crate::test_complete!("verifier_detects_reserve_in_closed_region");
    }

    #[test]
    fn verifier_detects_double_close() {
        init_test("verifier_detects_double_close");
        let events = vec![close_event(0, r(0)), close_event(10, r(0))];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(!sound, "double close detected", false, sound);
        crate::test_complete!("verifier_detects_double_close");
    }

    #[test]
    fn verifier_failed_close_with_pending_does_not_poison_later_close() {
        init_test("verifier_failed_close_with_pending_does_not_poison_later_close");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_event(10, r(0)), // invalid: pending > 0
            commit_event(20, o(0), r(0), ObligationKind::SendPermit),
            close_event(30, r(0)), // should be valid after commit
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);

        let quiescence_count = result
            .violations_for_property(|p| {
                matches!(p, SeparationProperty::RegionClosureQuiescence { .. })
            })
            .count();
        crate::assert_with_log!(
            quiescence_count == 1,
            "only the first close should violate quiescence",
            1,
            quiescence_count
        );

        let poisoned_close = result
            .violations
            .iter()
            .any(|v| v.description.contains("already closed"));
        crate::assert_with_log!(
            !poisoned_close,
            "failed close should not mark region closed",
            false,
            poisoned_close
        );
        crate::test_complete!("verifier_failed_close_with_pending_does_not_poison_later_close");
    }

    // ---- Verifier: realistic scenarios -----------------------------------------

    #[test]
    fn verifier_realistic_channel_send_with_cancel() {
        init_test("verifier_realistic_channel_send_with_cancel");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_event(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            abort_event(11, o(1), r(0), ObligationKind::SendPermit),
            close_event(20, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let sound = result.is_sound();
        crate::assert_with_log!(sound, "cancel scenario sound", true, sound);
        crate::test_complete!("verifier_realistic_channel_send_with_cancel");
    }

    #[test]
    fn verifier_all_five_kinds_uniform() {
        init_test("verifier_all_five_kinds_uniform");
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
            ObligationKind::SemaphorePermit,
        ];

        for (i, kind) in kinds.iter().enumerate() {
            let idx = i as u32;
            let events = vec![
                reserve_event(0, o(idx), *kind, t(0), r(0)),
                commit_event(10, o(idx), r(0), *kind),
                close_event(20, r(0)),
            ];

            let mut verifier = SeparationLogicVerifier::new();
            let result = verifier.verify(&events);
            let sound = result.is_sound();
            crate::assert_with_log!(sound, format!("{kind} is sound"), true, sound);
        }
        crate::test_complete!("verifier_all_five_kinds_uniform");
    }

    #[test]
    fn verifier_reuse_across_traces() {
        init_test("verifier_reuse_across_traces");
        let mut verifier = SeparationLogicVerifier::new();

        // First trace: violation.
        let events1 = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_event(10, r(0)),
        ];
        let r1 = verifier.verify(&events1);
        let r1_sound = r1.is_sound();
        crate::assert_with_log!(!r1_sound, "first not sound", false, r1_sound);

        // Second trace: clean.
        let events2 = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(5, o(0), r(0), ObligationKind::SendPermit),
            close_event(10, r(0)),
        ];
        let r2 = verifier.verify(&events2);
        let r2_sound = r2.is_sound();
        crate::assert_with_log!(r2_sound, "second is sound", true, r2_sound);
        crate::test_complete!("verifier_reuse_across_traces");
    }

    // ---- Spec table tests ------------------------------------------------------

    #[test]
    fn obligation_spec_all_kinds() {
        init_test("obligation_spec_all_kinds");
        let specs = ObligationSpec::all_specs();
        let count = specs.len();
        crate::assert_with_log!(count == 5, "5 specs", 5, count);

        for spec in &specs {
            let has_predicate = !spec.resource_predicate.is_empty();
            crate::assert_with_log!(
                has_predicate,
                format!("{} has predicate", spec.kind),
                true,
                has_predicate
            );
            let has_frame = !spec.frame_condition.is_empty();
            crate::assert_with_log!(
                has_frame,
                format!("{} has frame", spec.kind),
                true,
                has_frame
            );
            let has_reserve = !spec.reserve_triple.is_empty();
            crate::assert_with_log!(
                has_reserve,
                format!("{} has reserve triple", spec.kind),
                true,
                has_reserve
            );
            let sep_count = spec.separation_properties.len();
            crate::assert_with_log!(
                sep_count == 5,
                format!("{} has 5 sep props", spec.kind),
                5,
                sep_count
            );
        }
        crate::test_complete!("obligation_spec_all_kinds");
    }

    #[test]
    fn obligation_spec_display() {
        init_test("obligation_spec_display");
        let spec = ObligationSpec::for_kind(ObligationKind::SendPermit);
        let s = format!("{spec}");
        let has_send = s.contains("send_permit");
        crate::assert_with_log!(has_send, "display has kind name", true, has_send);
        let has_frame = s.contains("Frame");
        crate::assert_with_log!(has_frame, "display has frame", true, has_frame);
        crate::test_complete!("obligation_spec_display");
    }

    // ---- Protocol spec tests ---------------------------------------------------

    #[test]
    fn protocol_spec_all_protocols() {
        init_test("protocol_spec_all_protocols");
        let protocols = ProtocolSpec::all_protocols();
        let count = protocols.len();
        crate::assert_with_log!(count == 3, "3 protocols", 3, count);

        for proto in &protocols {
            let has_global = !proto.global_type.is_empty();
            crate::assert_with_log!(
                has_global,
                format!("{} has global type", proto.name),
                true,
                has_global
            );
            let has_init = !proto.init_triple.is_empty();
            crate::assert_with_log!(
                has_init,
                format!("{} has init triple", proto.name),
                true,
                has_init
            );
            let has_delegation = !proto.delegation_triple.is_empty();
            crate::assert_with_log!(
                has_delegation,
                format!("{} has delegation triple", proto.name),
                true,
                has_delegation
            );
        }
        crate::test_complete!("protocol_spec_all_protocols");
    }

    #[test]
    fn protocol_spec_display() {
        init_test("protocol_spec_display");
        let proto = ProtocolSpec::send_permit();
        let s = format!("{proto}");
        let has_name = s.contains("SendPermit");
        crate::assert_with_log!(has_name, "display has protocol name", true, has_name);
        let has_global = s.contains("Sender -> Receiver");
        crate::assert_with_log!(has_global, "display has global type", true, has_global);
        crate::test_complete!("protocol_spec_display");
    }

    // ---- Verification Result display -------------------------------------------

    #[test]
    fn verification_result_display() {
        init_test("verification_result_display");
        let events = vec![
            reserve_event(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_event(10, o(0), r(0), ObligationKind::SendPermit),
            close_event(20, r(0)),
        ];

        let mut verifier = SeparationLogicVerifier::new();
        let result = verifier.verify(&events);
        let s = format!("{result}");
        let has_sound = s.contains("Sound:");
        crate::assert_with_log!(has_sound, "display has Sound", true, has_sound);
        let has_events = s.contains("Events checked:");
        crate::assert_with_log!(has_events, "display has events", true, has_events);
        crate::test_complete!("verification_result_display");
    }

    // =========================================================================
    // Wave 55 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn operation_footprint_debug_clone_eq() {
        let fp = OperationFootprint {
            obligations_touched: vec![o(1)],
            tasks_touched: vec![t(0)],
            regions_touched: vec![r(0)],
        };
        let dbg = format!("{fp:?}");
        assert!(dbg.contains("OperationFootprint"), "{dbg}");
        let cloned = fp.clone();
        assert_eq!(fp, cloned);
    }

    #[test]
    fn judgment_op_debug_clone_eq() {
        let op = JudgmentOp::Reserve {
            kind: ObligationKind::SendPermit,
            holder: t(1),
            region: r(0),
        };
        let dbg = format!("{op:?}");
        assert!(dbg.contains("Reserve"), "{dbg}");
        let cloned = op.clone();
        assert_eq!(op, cloned);

        let op2 = JudgmentOp::Commit { obligation: o(1) };
        assert_ne!(op, op2);
    }

    #[test]
    fn sl_violation_debug_clone() {
        let v = SLViolation {
            property: SeparationProperty::NoAliasing { obligation: o(0) },
            time: Time::ZERO,
            description: "test violation".to_string(),
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("SLViolation"), "{dbg}");
        let cloned = v;
        assert_eq!(cloned.description, "test violation");
    }

    #[test]
    fn verification_result_debug_clone() {
        let result = VerificationResult {
            violations: vec![],
            events_checked: 10,
            judgments_verified: 5,
            frame_checks: 3,
            separation_checks: 2,
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("VerificationResult"), "{dbg}");
        let cloned = result;
        assert!(cloned.is_sound());
        assert_eq!(cloned.events_checked, 10);
    }
