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

    fn test_ids() -> (ObligationId, TaskId, RegionId) {
        (
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            RegionId::from_arena(ArenaIndex::new(0, 1)),
        )
    }

    #[test]
    fn obligation_state_predicates() {
        init_test("obligation_state_predicates");
        let reserved_terminal = ObligationState::Reserved.is_terminal();
        crate::assert_with_log!(
            !reserved_terminal,
            "reserved terminal",
            false,
            reserved_terminal
        );
        let committed_terminal = ObligationState::Committed.is_terminal();
        crate::assert_with_log!(
            committed_terminal,
            "committed terminal",
            true,
            committed_terminal
        );
        let aborted_terminal = ObligationState::Aborted.is_terminal();
        crate::assert_with_log!(aborted_terminal, "aborted terminal", true, aborted_terminal);
        let leaked_terminal = ObligationState::Leaked.is_terminal();
        crate::assert_with_log!(leaked_terminal, "leaked terminal", true, leaked_terminal);

        let reserved_resolved = ObligationState::Reserved.is_resolved();
        crate::assert_with_log!(
            !reserved_resolved,
            "reserved resolved",
            false,
            reserved_resolved
        );
        let committed_resolved = ObligationState::Committed.is_resolved();
        crate::assert_with_log!(
            committed_resolved,
            "committed resolved",
            true,
            committed_resolved
        );
        let aborted_resolved = ObligationState::Aborted.is_resolved();
        crate::assert_with_log!(aborted_resolved, "aborted resolved", true, aborted_resolved);
        let leaked_resolved = ObligationState::Leaked.is_resolved();
        crate::assert_with_log!(leaked_resolved, "leaked resolved", true, leaked_resolved);

        let reserved_success = ObligationState::Reserved.is_success();
        crate::assert_with_log!(
            !reserved_success,
            "reserved success",
            false,
            reserved_success
        );
        let committed_success = ObligationState::Committed.is_success();
        crate::assert_with_log!(
            committed_success,
            "committed success",
            true,
            committed_success
        );
        let aborted_success = ObligationState::Aborted.is_success();
        crate::assert_with_log!(aborted_success, "aborted success", true, aborted_success);
        let leaked_success = ObligationState::Leaked.is_success();
        crate::assert_with_log!(!leaked_success, "leaked success", false, leaked_success);

        let reserved_leaked = ObligationState::Reserved.is_leaked();
        crate::assert_with_log!(!reserved_leaked, "reserved leaked", false, reserved_leaked);
        let committed_leaked = ObligationState::Committed.is_leaked();
        crate::assert_with_log!(
            !committed_leaked,
            "committed leaked",
            false,
            committed_leaked
        );
        let aborted_leaked = ObligationState::Aborted.is_leaked();
        crate::assert_with_log!(!aborted_leaked, "aborted leaked", false, aborted_leaked);
        let leaked_leaked = ObligationState::Leaked.is_leaked();
        crate::assert_with_log!(leaked_leaked, "leaked leaked", true, leaked_leaked);
        crate::test_complete!("obligation_state_predicates");
    }

    #[test]
    fn obligation_lifecycle_commit() {
        init_test("obligation_lifecycle_commit");
        let (oid, tid, rid) = test_ids();
        let reserved_at = Time::from_nanos(10);
        let mut ob = ObligationRecord::new(oid, ObligationKind::SendPermit, tid, rid, reserved_at);

        let pending = ob.is_pending();
        crate::assert_with_log!(pending, "pending", true, pending);
        let leaked = ob.is_leaked();
        crate::assert_with_log!(!leaked, "leaked", false, leaked);
        crate::assert_with_log!(
            ob.state == ObligationState::Reserved,
            "state",
            ObligationState::Reserved,
            ob.state
        );

        let duration = ob.commit(Time::from_nanos(25));
        let pending = ob.is_pending();
        crate::assert_with_log!(!pending, "pending", false, pending);
        let leaked = ob.is_leaked();
        crate::assert_with_log!(!leaked, "leaked", false, leaked);
        crate::assert_with_log!(
            ob.state == ObligationState::Committed,
            "state",
            ObligationState::Committed,
            ob.state
        );
        crate::assert_with_log!(duration == 15, "duration", 15, duration);
        let resolved = ob.resolved_at;
        crate::assert_with_log!(
            resolved == Some(Time::from_nanos(25)),
            "resolved_at",
            Some(Time::from_nanos(25)),
            resolved
        );
        crate::test_complete!("obligation_lifecycle_commit");
    }

    #[test]
    fn obligation_lifecycle_abort() {
        init_test("obligation_lifecycle_abort");
        let (oid, tid, rid) = test_ids();
        let reserved_at = Time::from_nanos(100);
        let mut ob = ObligationRecord::new(oid, ObligationKind::Ack, tid, rid, reserved_at);

        let duration = ob.abort(Time::from_nanos(140), ObligationAbortReason::Explicit);
        let pending = ob.is_pending();
        crate::assert_with_log!(!pending, "pending", false, pending);
        let leaked = ob.is_leaked();
        crate::assert_with_log!(!leaked, "leaked", false, leaked);
        crate::assert_with_log!(
            ob.state == ObligationState::Aborted,
            "state",
            ObligationState::Aborted,
            ob.state
        );
        crate::assert_with_log!(duration == 40, "duration", 40, duration);
        let reason = ob.abort_reason;
        crate::assert_with_log!(
            reason == Some(ObligationAbortReason::Explicit),
            "abort_reason",
            Some(ObligationAbortReason::Explicit),
            reason
        );
        crate::test_complete!("obligation_lifecycle_abort");
    }

    #[test]
    fn obligation_lifecycle_leaked() {
        init_test("obligation_lifecycle_leaked");
        let (oid, tid, rid) = test_ids();
        let reserved_at = Time::from_nanos(5);
        let mut ob = ObligationRecord::new(oid, ObligationKind::Lease, tid, rid, reserved_at);

        let duration = ob.mark_leaked(Time::from_nanos(8));
        let pending = ob.is_pending();
        crate::assert_with_log!(!pending, "pending", false, pending);
        let leaked = ob.is_leaked();
        crate::assert_with_log!(leaked, "leaked", true, leaked);
        crate::assert_with_log!(
            ob.state == ObligationState::Leaked,
            "state",
            ObligationState::Leaked,
            ob.state
        );
        crate::assert_with_log!(duration == 3, "duration", 3, duration);
        crate::test_complete!("obligation_lifecycle_leaked");
    }

    #[test]
    fn obligation_resolution_couples_state_and_abort_reason() {
        init_test("obligation_resolution_couples_state_and_abort_reason");
        crate::assert_with_log!(
            ObligationResolution::Commit.state() == ObligationState::Committed,
            "commit state",
            ObligationState::Committed,
            ObligationResolution::Commit.state()
        );
        crate::assert_with_log!(
            ObligationResolution::Commit.abort_reason().is_none(),
            "commit reason",
            None::<ObligationAbortReason>,
            ObligationResolution::Commit.abort_reason()
        );

        let abort = ObligationResolution::Abort(ObligationAbortReason::Cancel);
        crate::assert_with_log!(
            abort.state() == ObligationState::Aborted,
            "abort state",
            ObligationState::Aborted,
            abort.state()
        );
        crate::assert_with_log!(
            abort.abort_reason() == Some(ObligationAbortReason::Cancel),
            "abort reason",
            Some(ObligationAbortReason::Cancel),
            abort.abort_reason()
        );

        crate::assert_with_log!(
            ObligationResolution::Leak.state() == ObligationState::Leaked,
            "leak state",
            ObligationState::Leaked,
            ObligationResolution::Leak.state()
        );
        crate::assert_with_log!(
            ObligationResolution::Leak.abort_reason().is_none(),
            "leak reason",
            None::<ObligationAbortReason>,
            ObligationResolution::Leak.abort_reason()
        );
        crate::test_complete!("obligation_resolution_couples_state_and_abort_reason");
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn double_commit_panics() {
        init_test("double_commit_panics");
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(
            oid,
            ObligationKind::IoOp,
            tid,
            rid,
            Time::from_nanos(1_000_000_000),
        );
        ob.commit(Time::from_nanos(1_000_000_000));
        ob.commit(Time::from_nanos(1_000_000_000)); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn double_abort_panics() {
        init_test("double_abort_panics");
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(
            oid,
            ObligationKind::IoOp,
            tid,
            rid,
            Time::from_nanos(1_000_000_000),
        );
        ob.abort(
            Time::from_nanos(1_000_000_000),
            ObligationAbortReason::Explicit,
        );
        ob.abort(
            Time::from_nanos(1_000_000_000),
            ObligationAbortReason::Explicit,
        ); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn commit_after_abort_panics() {
        init_test("commit_after_abort_panics");
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(
            oid,
            ObligationKind::SendPermit,
            tid,
            rid,
            Time::from_nanos(1_000_000_000),
        );
        ob.abort(
            Time::from_nanos(1_000_000_000),
            ObligationAbortReason::Cancel,
        );
        ob.commit(Time::from_nanos(1_000_000_000)); // Should panic
    }

    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn mark_leaked_after_commit_panics() {
        init_test("mark_leaked_after_commit_panics");
        let (oid, tid, rid) = test_ids();
        let mut ob = ObligationRecord::new(
            oid,
            ObligationKind::SendPermit,
            tid,
            rid,
            Time::from_nanos(1_000_000_000),
        );
        ob.commit(Time::from_nanos(1_000_000_000));
        ob.mark_leaked(Time::from_nanos(1_000_000_000)); // Should panic
    }

    #[test]
    fn obligation_kinds_are_distinguishable() {
        init_test("obligation_kinds_are_distinguishable");
        crate::assert_with_log!(
            ObligationKind::SendPermit != ObligationKind::Ack,
            "send != ack",
            "not equal",
            (ObligationKind::SendPermit, ObligationKind::Ack)
        );
        crate::assert_with_log!(
            ObligationKind::Ack != ObligationKind::Lease,
            "ack != lease",
            "not equal",
            (ObligationKind::Ack, ObligationKind::Lease)
        );
        crate::assert_with_log!(
            ObligationKind::Lease != ObligationKind::IoOp,
            "lease != ioop",
            "not equal",
            (ObligationKind::Lease, ObligationKind::IoOp)
        );
        crate::test_complete!("obligation_kinds_are_distinguishable");
    }

    #[test]
    fn with_description_sets_description() {
        init_test("with_description_sets_description");
        let (oid, tid, rid) = test_ids();
        let ob = ObligationRecord::with_description(
            oid,
            ObligationKind::SendPermit,
            tid,
            rid,
            Time::from_nanos(1_000_000_000),
            "test description",
        );
        crate::assert_with_log!(
            ob.description == Some("test description".to_string()),
            "description",
            Some("test description".to_string()),
            ob.description
        );
        crate::test_complete!("with_description_sets_description");
    }

    // Pure data-type tests (wave 12 – CyanBarn)

    #[test]
    fn source_location_display() {
        let loc = SourceLocation {
            file: "src/main.rs",
            line: 42,
            column: 5,
        };
        assert_eq!(loc.to_string(), "src/main.rs:42:5");
    }

    #[test]
    fn source_location_unknown() {
        let loc = SourceLocation::unknown();
        assert_eq!(loc.file, "<unknown>");
        assert_eq!(loc.line, 0);
        assert_eq!(loc.column, 0);
        assert_eq!(loc.to_string(), "<unknown>:0:0");
    }

    #[test]
    fn source_location_debug_copy_eq() {
        let loc = SourceLocation {
            file: "f.rs",
            line: 1,
            column: 1,
        };
        let dbg = format!("{loc:?}");
        assert!(dbg.contains("f.rs"));

        // Copy
        let loc2 = loc;
        assert_eq!(loc, loc2);

        // Inequality
        let loc3 = SourceLocation {
            file: "g.rs",
            line: 1,
            column: 1,
        };
        assert_ne!(loc, loc3);
    }

    #[test]
    fn obligation_kind_display_all() {
        assert_eq!(ObligationKind::SendPermit.to_string(), "send_permit");
        assert_eq!(ObligationKind::Ack.to_string(), "ack");
        assert_eq!(ObligationKind::Lease.to_string(), "lease");
        assert_eq!(ObligationKind::IoOp.to_string(), "io_op");
    }

    #[test]
    fn obligation_kind_as_str_all() {
        assert_eq!(ObligationKind::SendPermit.as_str(), "send_permit");
        assert_eq!(ObligationKind::Ack.as_str(), "ack");
        assert_eq!(ObligationKind::Lease.as_str(), "lease");
        assert_eq!(ObligationKind::IoOp.as_str(), "io_op");
    }

    #[test]
    fn obligation_kind_debug_copy_hash_ord() {
        use std::collections::HashSet;

        let k = ObligationKind::Lease;
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Lease"));

        // Copy
        let k2 = k;
        assert_eq!(k, k2);

        // Hash
        let mut set = HashSet::new();
        set.insert(ObligationKind::SendPermit);
        set.insert(ObligationKind::Ack);
        set.insert(ObligationKind::Lease);
        set.insert(ObligationKind::IoOp);
        assert_eq!(set.len(), 4);

        // Ord
        let mut kinds = [
            ObligationKind::IoOp,
            ObligationKind::SendPermit,
            ObligationKind::Lease,
            ObligationKind::Ack,
        ];
        kinds.sort();
        assert_eq!(kinds[0], ObligationKind::SendPermit);
    }

    #[test]
    fn obligation_abort_reason_display_all() {
        assert_eq!(ObligationAbortReason::Cancel.to_string(), "cancel");
        assert_eq!(ObligationAbortReason::Error.to_string(), "error");
        assert_eq!(ObligationAbortReason::Explicit.to_string(), "explicit");
    }

    #[test]
    fn obligation_abort_reason_debug_copy_eq() {
        let r = ObligationAbortReason::Cancel;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Cancel"));

        let r2 = r;
        assert_eq!(r, r2);

        assert_ne!(ObligationAbortReason::Cancel, ObligationAbortReason::Error);
    }

    #[test]
    fn obligation_state_debug_copy_eq() {
        let states = [
            ObligationState::Reserved,
            ObligationState::Committed,
            ObligationState::Aborted,
            ObligationState::Leaked,
        ];
        for s in &states {
            let dbg = format!("{s:?}");
            assert!(!dbg.is_empty());

            // Copy
            let s2 = *s;
            assert_eq!(*s, s2);
        }

        assert_ne!(ObligationState::Reserved, ObligationState::Committed);
        assert_ne!(ObligationState::Aborted, ObligationState::Leaked);
    }

    #[test]
    fn obligation_record_new_defaults() {
        let (oid, tid, rid) = test_ids();
        let ob = ObligationRecord::new(
            oid,
            ObligationKind::IoOp,
            tid,
            rid,
            Time::from_nanos(1_000_000_000),
        );
        assert_eq!(ob.state, ObligationState::Reserved);
        assert!(ob.description.is_none());
        assert!(ob.resolved_at.is_none());
        assert!(ob.abort_reason.is_none());
        assert!(ob.acquire_backtrace.is_none());
        assert_eq!(ob.acquired_at, SourceLocation::unknown());
    }

    #[test]
    fn obligation_record_debug() {
        let (oid, tid, rid) = test_ids();
        let ob = ObligationRecord::new(
            oid,
            ObligationKind::SendPermit,
            tid,
            rid,
            Time::from_nanos(1_000_000_000),
        );
        let dbg = format!("{ob:?}");
        assert!(dbg.contains("ObligationRecord"));
        assert!(dbg.contains("SendPermit"));
    }

    #[test]
    fn source_location_debug_clone_copy_eq() {
        let loc = SourceLocation::unknown();
        let dbg = format!("{loc:?}");
        assert!(dbg.contains("SourceLocation"), "{dbg}");
        let copied: SourceLocation = loc;
        let cloned = loc;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn obligation_kind_debug_clone_copy_hash_eq() {
        use std::collections::HashSet;
        let k = ObligationKind::Lease;
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Lease"), "{dbg}");
        let copied: ObligationKind = k;
        let cloned = k;
        assert_eq!(copied, cloned);
        assert!(k < ObligationKind::IoOp);

        let mut set = HashSet::new();
        set.insert(ObligationKind::SendPermit);
        set.insert(ObligationKind::Ack);
        set.insert(ObligationKind::Lease);
        set.insert(ObligationKind::IoOp);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn obligation_abort_reason_debug_clone_copy_eq() {
        let r = ObligationAbortReason::Cancel;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Cancel"), "{dbg}");
        let copied: ObligationAbortReason = r;
        let cloned = r;
        assert_eq!(copied, cloned);
        assert_ne!(r, ObligationAbortReason::Explicit);
    }
