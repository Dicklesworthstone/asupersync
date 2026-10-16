    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn test_object_id() -> ObjectId {
        ObjectId::new_for_test(1)
    }

    fn test_task_id() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(1, 0))
    }

    fn test_task_id_with_generation(index: u32, generation: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(index, generation))
    }

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(1, 0))
    }

    fn test_region_id_with_generation(index: u32, generation: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(index, generation))
    }

    fn test_params() -> ObjectParams {
        ObjectParams::new(test_object_id(), 5120, 1280, 1, 4)
    }

    #[test]
    fn obligation_lifecycle_commit() {
        let obj = SymbolicObligation::new_for_test(1, test_object_id(), 4);

        assert_eq!(obj.state(), SymbolicObligationState::Reserved);
        assert!(obj.is_pending());
        assert_eq!(obj.progress().total, 4);
        assert_eq!(obj.progress().fulfilled, 0);
        assert!(!obj.progress().complete);

        obj.commit();
    }

    #[test]
    fn obligation_lifecycle_abort() {
        let obj = SymbolicObligation::new_for_test(2, test_object_id(), 4);
        assert!(obj.is_pending());
        obj.abort();
    }

    #[test]
    fn partial_fulfillment_tracking() {
        let obj = SymbolicObligation::new_for_test(3, test_object_id(), 3);

        let sym1 = SymbolId::new(test_object_id(), 0, 0);
        let sym2 = SymbolId::new(test_object_id(), 0, 1);

        obj.fulfill_one(sym1);
        assert_eq!(obj.state(), SymbolicObligationState::InProgress);
        assert_eq!(obj.progress().fulfilled, 1);

        obj.fulfill_one(sym2);
        assert_eq!(obj.progress().fulfilled, 2);
        assert!(!obj.progress().complete);

        obj.fulfill_many(1);
        assert!(obj.progress().complete);

        obj.commit();
    }

    #[test]
    fn commit_or_abort_complete() {
        let obj = SymbolicObligation::new_for_test(4, test_object_id(), 2);
        obj.fulfill_many(2);
        obj.commit_or_abort();
        // If complete, should commit (no panic)
    }

    #[test]
    fn commit_or_abort_incomplete() {
        let obj = SymbolicObligation::new_for_test(5, test_object_id(), 10);
        obj.fulfill_many(3);
        obj.commit_or_abort();
        // If incomplete, should abort (no panic)
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "SymbolicObligation leaked")]
    fn leak_detection_panics_in_debug() {
        let _obj = SymbolicObligation::new_for_test(6, test_object_id(), 1);
        // Dropping without resolution triggers panic in debug
    }

    #[test]
    fn fulfillment_progress_zero_total() {
        let progress = FulfillmentProgress::new(0);
        assert!(progress.is_complete());
        assert!((progress.percent() - 1.0).abs() < f64::EPSILON);
        assert_eq!(progress.remaining(), 0);
    }

    #[test]
    fn fulfillment_progress_snapshot() {
        let progress = FulfillmentProgress::new(10);
        progress.add(7);
        let snap = progress.snapshot();
        assert_eq!(snap.total, 10);
        assert_eq!(snap.fulfilled, 7);
        assert!(!snap.complete);
        assert!((snap.percent - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn fulfillment_progress_saturates_on_overflow() {
        let progress = FulfillmentProgress::new(u32::MAX);
        progress.add(u32::MAX);
        assert_eq!(progress.fulfilled(), u32::MAX);

        // Increment past the bound should saturate instead of wrapping.
        progress.increment();
        assert_eq!(progress.fulfilled(), u32::MAX);
        assert!(progress.is_complete());
    }

    #[test]
    fn fulfillment_progress_percent_clamps_at_one() {
        let progress = FulfillmentProgress::new(3);
        progress.add(5);

        assert_eq!(progress.fulfilled(), 5);
        assert!((progress.percent() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fulfillment_progress_snapshot_clamps_percent_from_captured_fulfillment() {
        let progress = FulfillmentProgress::new(2);
        progress.add(5);

        let snapshot = progress.snapshot();

        assert_eq!(snapshot.total, 2);
        assert_eq!(snapshot.fulfilled, 5);
        assert!(snapshot.complete);
        assert!((snapshot.percent - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn obligation_kind_display() {
        assert_eq!(SymbolicObligationKind::SendObject.as_str(), "send_object");
        assert_eq!(
            SymbolicObligationKind::AcknowledgeReceipt.as_str(),
            "ack_receipt"
        );
    }

    #[test]
    fn obligation_state_properties() {
        assert!(!SymbolicObligationState::Reserved.is_terminal());
        assert!(!SymbolicObligationState::InProgress.is_terminal());
        assert!(SymbolicObligationState::Committed.is_terminal());
        assert!(SymbolicObligationState::Aborted.is_terminal());
        assert!(SymbolicObligationState::Leaked.is_terminal());

        assert!(SymbolicObligationState::Committed.is_success());
        assert!(SymbolicObligationState::Aborted.is_success());
        assert!(!SymbolicObligationState::Leaked.is_success());

        assert!(SymbolicObligationState::Leaked.is_leaked());
        assert!(!SymbolicObligationState::Committed.is_leaked());
    }

    #[test]
    fn registry_create_and_lookup() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let region = test_region_id();
        let object = test_object_id();
        let params = test_params();

        let obligation = registry.create_send_object(
            object,
            &params,
            holder,
            region,
            Time::from_nanos(1_000_000_000),
        );

        // Registry should have indexed it.
        assert_eq!(registry.obligations_for_region(region).len(), 1);
        assert_eq!(registry.obligations_for_task(holder).len(), 1);
        assert_eq!(registry.obligations_for_object(object).len(), 1);
        assert!(registry.has_pending_in_region(region));

        let pending = registry.pending_in_region(region);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, SymbolicObligationKind::SendObject);

        // Commit resolves - update registry state.
        obligation.commit();

        assert!(registry.obligations_for_region(region).is_empty());
        assert!(registry.obligations_for_task(holder).is_empty());
        assert!(registry.obligations_for_object(object).is_empty());
        assert!(!registry.has_pending_in_region(region));
        assert!(registry.pending_in_region(region).is_empty());
    }

    #[test]
    fn registry_multiple_obligations() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let region = test_region_id();
        let object = test_object_id();

        let sym1 = SymbolId::new(object, 0, 0);
        let sym2 = SymbolId::new(object, 0, 1);

        let o1 = registry.create_send_symbol(sym1, holder, region, Time::from_nanos(1_000_000_000));
        let o2 = registry.create_send_symbol(sym2, holder, region, Time::from_nanos(1_000_000_000));

        assert_eq!(registry.obligations_for_object(object).len(), 2);
        assert!(registry.has_pending_in_region(region));

        o1.commit();

        assert_eq!(registry.obligations_for_object(object), vec![o2.id()]);
        // Still has pending because o2 is unresolved.
        assert!(registry.has_pending_in_region(region));

        o2.abort();

        assert!(registry.obligations_for_object(object).is_empty());
        assert!(!registry.has_pending_in_region(region));
        assert!(registry.pending_in_region(region).is_empty());
    }

    #[test]
    fn registry_decode_obligation() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let region = test_region_id();
        let object = test_object_id();

        let obligation =
            registry.create_decode(object, 4, holder, region, Time::from_nanos(1_000_000_000));
        assert_eq!(obligation.kind(), SymbolicObligationKind::DecodeObject);
        assert_eq!(obligation.progress().total, 4);

        let pending = registry.pending_in_region(region);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, SymbolicObligationState::Reserved);

        obligation.fulfill_many(4);
        let pending = registry.pending_in_region(region);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, SymbolicObligationState::InProgress);

        assert!(obligation.progress().complete);
        obligation.commit();
        assert!(!registry.has_pending_in_region(region));
    }

    #[test]
    fn registry_obligations_for_task_preserve_same_slot_generations() {
        let registry = SymbolicObligationRegistry::new();
        let older = test_task_id_with_generation(5, 0);
        let newer = test_task_id_with_generation(5, 1);
        let region = test_region_id();
        let object = test_object_id();
        let params = test_params();

        let older_obligation = registry.create_send_object(
            object,
            &params,
            older,
            region,
            Time::from_nanos(1_000_000_000),
        );
        let newer_obligation =
            registry.create_acknowledge(object, 1, newer, region, Time::from_nanos(1_000_000_000));

        assert_eq!(
            registry.obligations_for_task(older),
            vec![older_obligation.id()]
        );
        assert_eq!(
            registry.obligations_for_task(newer),
            vec![newer_obligation.id()]
        );

        older_obligation.abort();
        newer_obligation.abort();
    }

    #[test]
    fn registry_obligations_for_region_preserve_same_slot_generations() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let older = test_region_id_with_generation(7, 0);
        let newer = test_region_id_with_generation(7, 1);
        let object = test_object_id();
        let params = test_params();

        let older_obligation = registry.create_send_object(
            object,
            &params,
            holder,
            older,
            Time::from_nanos(1_000_000_000),
        );
        let newer_obligation =
            registry.create_acknowledge(object, 1, holder, newer, Time::from_nanos(1_000_000_000));

        assert_eq!(
            registry.obligations_for_region(older),
            vec![older_obligation.id()]
        );
        assert_eq!(
            registry.obligations_for_region(newer),
            vec![newer_obligation.id()]
        );

        older_obligation.abort();
        newer_obligation.abort();
    }

    #[test]
    fn registry_acknowledge_obligation() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let region = test_region_id();
        let object = test_object_id();

        let obligation =
            registry.create_acknowledge(object, 8, holder, region, Time::from_nanos(1_000_000_000));
        assert_eq!(
            obligation.kind(),
            SymbolicObligationKind::AcknowledgeReceipt
        );
        assert_eq!(obligation.progress().total, 8);

        obligation.abort();
        assert!(!registry.has_pending_in_region(region));
    }

    #[test]
    #[should_panic(expected = "fulfilled symbol mismatch")]
    fn send_symbol_obligation_rejects_wrong_symbol_progress() {
        let object = test_object_id();
        let expected = SymbolId::new(object, 0, 0);
        let wrong = SymbolId::new(object, 0, 1);
        let obligation = SymbolicObligation::new_send_symbol(
            ObligationId::from_arena(ArenaIndex::new(99, 0)),
            expected,
            test_task_id(),
            test_region_id(),
            Time::from_nanos(1_000_000_000),
            None,
        );

        obligation.fulfill_one(wrong);
    }

    #[test]
    #[should_panic(expected = "fulfilled symbol object mismatch")]
    fn send_object_obligation_rejects_wrong_object_progress() {
        let obligation = SymbolicObligation::new_send_object(
            ObligationId::from_arena(ArenaIndex::new(100, 0)),
            test_object_id(),
            &test_params(),
            test_task_id(),
            test_region_id(),
            Time::from_nanos(1_000_000_000),
            None,
        );
        let wrong_object_symbol = SymbolId::new(ObjectId::new_for_test(99), 0, 0);

        obligation.fulfill_one(wrong_object_symbol);
    }

    #[test]
    #[should_panic(expected = "fulfill_many is invalid for single-symbol obligations")]
    fn send_symbol_obligation_rejects_bulk_progress_without_symbol_identity() {
        let obligation = SymbolicObligation::new_send_symbol(
            ObligationId::from_arena(ArenaIndex::new(101, 0)),
            SymbolId::new(test_object_id(), 0, 0),
            test_task_id(),
            test_region_id(),
            Time::from_nanos(1_000_000_000),
            None,
        );

        obligation.fulfill_many(1);
    }

    #[test]
    #[should_panic(expected = "symbolic obligation id overflow")]
    fn registry_panics_on_obligation_id_overflow() {
        let registry = SymbolicObligationRegistry::new();
        registry
            .next_id
            .store(u64::from(u32::MAX) + 1, Ordering::Relaxed);

        let _ = registry.create_decode(
            test_object_id(),
            1,
            test_task_id(),
            test_region_id(),
            Time::from_nanos(1_000_000_000),
        );
    }

    #[test]
    fn symbolic_obligation_kind_debug_clone_copy_eq() {
        let a = SymbolicObligationKind::SendObject;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, SymbolicObligationKind::DecodeObject);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("SendObject"));
    }

    #[test]
    fn symbolic_obligation_state_debug_clone_copy_eq() {
        let a = SymbolicObligationState::Committed;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, SymbolicObligationState::Aborted);
        assert_ne!(a, SymbolicObligationState::Leaked);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Committed"));
    }
