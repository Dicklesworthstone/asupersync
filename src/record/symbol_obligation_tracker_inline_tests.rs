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

    fn test_region(index: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(index, 1))
    }

    fn test_ids() -> (ObligationId, TaskId, RegionId) {
        (
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            test_region(0),
        )
    }

    // Test 1: Basic obligation creation and commit
    #[test]
    fn test_transmit_obligation_lifecycle_commit() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let mut ob = SymbolObligation::transmit(
            oid,
            tid,
            rid,
            symbol_id,
            dest,
            None,
            None,
            Time::from_nanos(1_000_000_000),
        );

        assert!(ob.is_pending());
        ob.commit(Time::from_millis(100));
        assert!(!ob.is_pending());
        assert_eq!(ob.state(), ObligationState::Committed);
    }

    // Test 2: Basic obligation abort
    #[test]
    fn test_transmit_obligation_lifecycle_abort() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let mut ob = SymbolObligation::transmit(
            oid,
            tid,
            rid,
            symbol_id,
            dest,
            None,
            None,
            Time::from_nanos(1_000_000_000),
        );

        ob.abort(Time::from_millis(100));
        assert_eq!(ob.state(), ObligationState::Aborted);
    }

    // Test 3: Epoch validity checking
    #[test]
    fn test_epoch_window_validity() {
        let (oid, tid, rid) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let window = EpochWindow {
            start: EpochId(10),
            end: EpochId(20),
        };

        let ob = SymbolObligation::decoding(
            oid,
            tid,
            rid,
            object_id,
            10,
            window,
            Time::from_nanos(1_000_000_000),
        );

        assert!(!ob.is_epoch_valid(EpochId(5))); // Before window
        assert!(ob.is_epoch_valid(EpochId(10))); // Start of window
        assert!(ob.is_epoch_valid(EpochId(15))); // Middle of window
        assert!(ob.is_epoch_valid(EpochId(20))); // End of window
        assert!(!ob.is_epoch_valid(EpochId(25))); // After window
    }

    // Test 4: Deadline expiry detection
    #[test]
    fn test_deadline_expiry() {
        let (oid, tid, rid) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let deadline = Time::from_millis(1000);

        let ob = SymbolObligation::lease(
            oid,
            tid,
            rid,
            object_id,
            deadline,
            Time::from_nanos(1_000_000_000),
        );

        assert!(!ob.is_expired(Time::from_millis(500)));
        assert!(ob.is_expired(Time::from_millis(1000)));
        assert!(ob.is_expired(Time::from_millis(1001)));
    }

    // Test 5: Tracker registration and lookup
    #[test]
    fn test_tracker_registration() {
        let rid = test_region(0);
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let ob = SymbolObligation::transmit(
            oid,
            tid,
            rid,
            symbol_id,
            dest,
            None,
            None,
            Time::from_nanos(1_000_000_000),
        );

        let id = tracker.register(ob);
        assert_eq!(tracker.pending_count(), 1);

        let found = tracker.by_symbol(symbol_id);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), id);
    }

    // Regression: duplicate registration must fail closed and preserve the
    // original pending obligation instead of silently discarding it.
    #[test]
    fn test_register_same_id_panics_and_preserves_original_obligation() {
        let rid = test_region(0);
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));
        let first_symbol = SymbolId::new_for_test(11, 0, 0);
        let second_symbol = SymbolId::new_for_test(12, 0, 0);

        let first = SymbolObligation::transmit(
            oid,
            tid,
            rid,
            first_symbol,
            dest,
            None,
            None,
            Time::from_nanos(1_000_000_000),
        );
        tracker.register(first);
        assert_eq!(tracker.by_symbol(first_symbol).len(), 1);

        let second = SymbolObligation::transmit(
            oid,
            tid,
            rid,
            second_symbol,
            dest,
            None,
            None,
            Time::from_nanos(1),
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracker.register(second);
        }));
        assert!(panic.is_err());

        let original = tracker.by_symbol(first_symbol);
        assert_eq!(original.len(), 1);
        assert_eq!(original[0].id(), oid);
        assert!(tracker.by_symbol(second_symbol).is_empty());
        assert_eq!(tracker.pending_count(), 1);
    }

    // Regression: the tracker must reject obligations that belong to another
    // region instead of silently tracking them under the wrong owner.
    #[test]
    fn test_register_cross_region_obligation_panics() {
        let tracker_region = test_region(0);
        let other_region = test_region(9);
        let mut tracker = SymbolObligationTracker::new(tracker_region);

        let (oid, tid, _) = test_ids();
        let symbol_id = SymbolId::new_for_test(77, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));
        let obligation = SymbolObligation::transmit(
            oid,
            tid,
            other_region,
            symbol_id,
            dest,
            None,
            None,
            Time::from_nanos(1_000_000_000),
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracker.register(obligation);
        }));
        assert!(panic.is_err());
        assert_eq!(tracker.pending_count(), 0);
        assert!(tracker.by_symbol(symbol_id).is_empty());
    }

    // Test 6: Tracker resolution (commit)
    #[test]
    fn test_tracker_resolve_commit() {
        let rid = test_region(0);
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let ob = SymbolObligation::transmit(
            oid,
            tid,
            rid,
            symbol_id,
            dest,
            None,
            None,
            Time::from_nanos(1_000_000_000),
        );

        let id = tracker.register(ob);
        let resolved = tracker.resolve(id, true, Time::from_millis(100));

        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().state(), ObligationState::Committed);
        assert_eq!(tracker.pending_count(), 0);
    }

    // Test 7: Leak detection during region close
    #[test]
    fn test_leak_detection() {
        let rid = test_region(0);
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid1, tid, _) = test_ids();
        let oid2 = ObligationId::from_arena(ArenaIndex::new(1, 0));
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let ob1 = SymbolObligation::transmit(
            oid1,
            tid,
            rid,
            symbol_id,
            dest,
            None,
            None,
            Time::from_nanos(1_000_000_000),
        );
        let ob2 = SymbolObligation::ack(
            oid2,
            tid,
            rid,
            symbol_id,
            dest,
            Time::from_nanos(1_000_000_000),
        );

        tracker.register(ob1);
        let id2 = tracker.register(ob2);

        // Resolve one, leave the other
        tracker.resolve(id2, true, Time::from_millis(100));

        let leaked = tracker.check_leaks(Time::from_millis(200));
        assert_eq!(leaked.len(), 1);
        assert_eq!(tracker.pending_count(), 0);
        assert!(tracker.by_symbol(symbol_id).is_empty());
    }

    // Test 8: Epoch-based abort
    #[test]
    fn test_abort_expired_epoch() {
        let rid = test_region(0);
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let window = EpochWindow {
            start: EpochId(10),
            end: EpochId(20),
        };

        let ob = SymbolObligation::decoding(
            oid,
            tid,
            rid,
            object_id,
            10,
            window,
            Time::from_nanos(1_000_000_000),
        );
        tracker.register(ob);

        // Epoch 15 is valid, nothing aborted
        let aborted = tracker.abort_expired_epoch(EpochId(15), Time::from_millis(100));
        assert_eq!(aborted.len(), 0);

        // Epoch 25 is past window, obligation aborted
        let aborted = tracker.abort_expired_epoch(EpochId(25), Time::from_millis(200));
        assert_eq!(aborted.len(), 1);
        assert_eq!(tracker.pending_count(), 0);
        assert!(tracker.obligations.is_empty());
        assert!(tracker.by_object.is_empty());
    }

    // Test 9: Deadline-based abort
    #[test]
    fn test_abort_expired_deadlines() {
        let rid = test_region(0);
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let deadline = Time::from_millis(1000);

        let ob = SymbolObligation::lease(
            oid,
            tid,
            rid,
            object_id,
            deadline,
            Time::from_nanos(1_000_000_000),
        );
        tracker.register(ob);

        // Before deadline
        let aborted = tracker.abort_expired_deadlines(Time::from_millis(500));
        assert_eq!(aborted.len(), 0);

        // At the deadline, the lease is no longer valid.
        let aborted = tracker.abort_expired_deadlines(deadline);
        assert_eq!(aborted.len(), 1);
        assert_eq!(tracker.pending_count(), 0);
        assert!(tracker.obligations.is_empty());
        assert!(tracker.by_object.is_empty());
    }

    // Test 10: Decoding progress updates
    #[test]
    fn test_decoding_progress_update() {
        let (oid, tid, rid) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let window = EpochWindow {
            start: EpochId(1),
            end: EpochId(100),
        };

        let mut ob = SymbolObligation::decoding(
            oid,
            tid,
            rid,
            object_id,
            10,
            window,
            Time::from_nanos(1_000_000_000),
        );

        // Initial state
        if let SymbolObligationKind::DecodingInProgress {
            symbols_received, ..
        } = ob.symbol_kind()
        {
            assert_eq!(*symbols_received, 0);
        }

        // Update progress
        assert!(ob.update_decoding_progress(5).is_ok());

        if let SymbolObligationKind::DecodingInProgress {
            symbols_received, ..
        } = ob.symbol_kind()
        {
            assert_eq!(*symbols_received, 5);
        }
    }

    // Test 11b: Updating progress on a non-decoding obligation returns error.
    #[test]
    fn test_decoding_progress_update_rejects_non_decoding_obligation() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(42, 0, 0);

        let mut ob = SymbolObligation::ack(
            oid,
            tid,
            rid,
            symbol_id,
            rid,
            Time::from_nanos(1_000_000_000),
        );

        let result = ob.update_decoding_progress(1);
        assert_eq!(
            result,
            Err(DecodingProgressUpdateError::NotDecodingObligation)
        );
    }

    // Test 11c: Updating progress beyond the decode target returns error.
    #[test]
    fn test_decoding_progress_update_rejects_received_above_needed() {
        let (oid, tid, rid) = test_ids();
        let object_id = ObjectId::new_for_test(7);
        let window = EpochWindow {
            start: EpochId(1),
            end: EpochId(2),
        };

        let mut ob = SymbolObligation::decoding(
            oid,
            tid,
            rid,
            object_id,
            3,
            window,
            Time::from_nanos(1_000_000_000),
        );
        let result = ob.update_decoding_progress(4);
        assert_eq!(
            result,
            Err(DecodingProgressUpdateError::SymbolsReceivedExceedsNeeded {
                received: 4,
                needed: 3,
            })
        );

        if let SymbolObligationKind::DecodingInProgress {
            symbols_received, ..
        } = ob.symbol_kind()
        {
            assert_eq!(*symbols_received, 0);
        }
    }

    // Test 11d: Decoding progress must not move backwards.
    #[test]
    fn test_decoding_progress_update_rejects_regression() {
        let (oid, tid, rid) = test_ids();
        let object_id = ObjectId::new_for_test(8);
        let window = EpochWindow {
            start: EpochId(1),
            end: EpochId(2),
        };

        let mut ob = SymbolObligation::decoding(
            oid,
            tid,
            rid,
            object_id,
            6,
            window,
            Time::from_nanos(1_000_000_000),
        );
        assert!(ob.update_decoding_progress(4).is_ok());

        let result = ob.update_decoding_progress(2);
        assert_eq!(
            result,
            Err(DecodingProgressUpdateError::SymbolsReceivedRegressed {
                previous: 4,
                attempted: 2,
            })
        );

        if let SymbolObligationKind::DecodingInProgress {
            symbols_received, ..
        } = ob.symbol_kind()
        {
            assert_eq!(*symbols_received, 4);
        }
    }

    // Test 11: Double resolution panics
    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn test_double_commit_panics() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let mut ob = SymbolObligation::transmit(
            oid,
            tid,
            rid,
            symbol_id,
            dest,
            None,
            None,
            Time::from_nanos(1_000_000_000),
        );

        ob.commit(Time::from_millis(100));
        ob.commit(Time::from_millis(200)); // Should panic
    }

    // Test 12: No epoch constraint means always valid
    #[test]
    fn test_no_epoch_constraint_always_valid() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);

        let ob = SymbolObligation::ack(
            oid,
            tid,
            rid,
            symbol_id,
            rid,
            Time::from_nanos(1_000_000_000),
        );

        assert!(ob.is_epoch_valid(EpochId(0)));
        assert!(ob.is_epoch_valid(EpochId(u64::MAX)));
    }

    #[test]
    fn epoch_id_debug_clone_copy_eq_ord_hash() {
        use std::collections::HashSet;
        let a = EpochId(42);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, EpochId(99));
        assert!(a < EpochId(100));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("EpochId"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn epoch_window_debug_clone_copy_eq() {
        let a = EpochWindow {
            start: EpochId(10),
            end: EpochId(20),
        };
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(
            a,
            EpochWindow {
                start: EpochId(0),
                end: EpochId(5)
            }
        );
        let dbg = format!("{a:?}");
        assert!(dbg.contains("EpochWindow"));
    }
