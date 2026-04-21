use asupersync::record::region::RegionState;
use asupersync::runtime::{RegionCreateError, RegionTable};
use asupersync::types::{Budget, TaskId, Time};

#[derive(Clone, Copy)]
enum CleanupStep {
    Child,
    Task,
    Obligation,
}

fn drive_close(order: &[CleanupStep]) -> (Vec<bool>, RegionState) {
    let mut table = RegionTable::new();
    let root = table.create_root(Budget::default(), Time::ZERO);
    let child = table
        .create_child(root, Budget::default(), Time::ZERO)
        .expect("child region");

    let root_record = table.get(root.arena_index()).expect("root record");
    let task = TaskId::new_for_test(7, 0);
    root_record.add_task(task).expect("task admission");
    root_record
        .try_reserve_obligation()
        .expect("obligation admission");

    assert!(root_record.begin_close(None));
    assert!(root_record.begin_drain());
    assert!(root_record.begin_finalize());

    let mut gate_results = vec![root_record.complete_close()];
    for step in order {
        match step {
            CleanupStep::Child => root_record.remove_child(child),
            CleanupStep::Task => root_record.remove_task(task),
            CleanupStep::Obligation => root_record.resolve_obligation(),
        }
        gate_results.push(root_record.complete_close());
    }

    (gate_results, root_record.state())
}

#[test]
fn metamorphic_close_quiescence_gate_is_cleanup_order_independent() {
    let remove_child_first = [
        CleanupStep::Child,
        CleanupStep::Task,
        CleanupStep::Obligation,
    ];
    let resolve_obligation_first = [
        CleanupStep::Obligation,
        CleanupStep::Task,
        CleanupStep::Child,
    ];

    let (child_first_gates, child_first_state) = drive_close(&remove_child_first);
    let (obligation_first_gates, obligation_first_state) = drive_close(&resolve_obligation_first);

    assert_eq!(child_first_gates, vec![false, false, false, true]);
    assert_eq!(obligation_first_gates, vec![false, false, false, true]);
    assert_eq!(child_first_state, RegionState::Closed);
    assert_eq!(obligation_first_state, RegionState::Closed);
}

#[test]
fn metamorphic_repeated_close_stays_fail_closed_for_child_admission() {
    let mut table = RegionTable::new();
    let root = table.create_root(Budget::default(), Time::ZERO);

    {
        let root_record = table.get(root.arena_index()).expect("root record");
        assert!(root_record.begin_close(None));
        assert!(!root_record.begin_close(None));
    }

    for _ in 0..2 {
        let err = table
            .create_child(root, Budget::default(), Time::ZERO)
            .expect_err("closed parent must reject child admission");
        assert_eq!(err, RegionCreateError::ParentClosed(root));
        assert_eq!(
            table.len(),
            1,
            "failed child admission must not leak a record"
        );
    }

    {
        let root_record = table.get(root.arena_index()).expect("root record");
        assert!(root_record.begin_drain());
        assert!(root_record.begin_finalize());
        assert!(root_record.complete_close());
        assert_eq!(root_record.state(), RegionState::Closed);
    }

    for _ in 0..2 {
        let err = table
            .create_child(root, Budget::default(), Time::ZERO)
            .expect_err("closed parent must continue rejecting child admission");
        assert_eq!(err, RegionCreateError::ParentClosed(root));
        assert_eq!(table.len(), 1, "repeated failures must not leak a record");
    }
}
