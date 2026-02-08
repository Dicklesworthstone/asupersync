use asupersync::gen_server::{SystemMsg, SystemMsgBatch};
use asupersync::monitor::{DownNotification, DownReason, MonitorRef};
use asupersync::runtime::{RuntimeState, SpawnError};
use asupersync::supervision::{ChildSpec, StartTieBreak, SupervisorBuilder};
use asupersync::types::{TaskId, Time};

/// Helper to create a dummy SystemMsg for testing ordering.
fn make_down(vt: u64, tid: u32) -> SystemMsg {
    SystemMsg::Down {
        completion_vt: Time::from_nanos(vt),
        notification: DownNotification {
            monitored: TaskId::new_for_test(tid, 0),
            reason: DownReason::Normal,
            monitor_ref: MonitorRef::new_for_test(0),
        },
    }
}

fn make_exit(vt: u64, tid: u32) -> SystemMsg {
    SystemMsg::Exit {
        exit_vt: Time::from_nanos(vt),
        from: TaskId::new_for_test(tid, 0),
        reason: DownReason::Normal,
    }
}

fn make_timeout(vt: u64, id: u64) -> SystemMsg {
    SystemMsg::Timeout {
        tick_vt: Time::from_nanos(vt),
        id,
    }
}

#[test]
fn test_sys_msg_batch_ordering() {
    let mut batch = SystemMsgBatch::new();

    // Insert messages in shuffled order to verify sort.
    // Spec order: (vt, kind_rank, subject_key)
    // Kind rank: Down(0) < Exit(1) < Timeout(2)

    // Late time (should be last)
    batch.push(make_down(200, 1));

    // Same time (100), different kinds
    batch.push(make_timeout(100, 5)); // Rank 2
    batch.push(make_exit(100, 3)); // Rank 1
    batch.push(make_down(100, 2)); // Rank 0

    // Same time (100), same kind (Down), different TIDs
    batch.push(make_down(100, 99)); // TID 99 > TID 2

    // Early time (should be first)
    batch.push(make_timeout(50, 1));

    let sorted = batch.into_sorted();

    // Expected order:
    // 1. Time 50, Timeout
    // 2. Time 100, Down, TID 2
    // 3. Time 100, Down, TID 99
    // 4. Time 100, Exit, TID 3
    // 5. Time 100, Timeout, ID 5
    // 6. Time 200, Down, TID 1

    let keys: Vec<(u64, u8)> = sorted
        .iter()
        .map(|m| {
            let (t, rank, _) = m.sort_key();
            (t.as_nanos(), rank)
        })
        .collect();

    assert_eq!(
        keys,
        vec![
            (50, 2),  // Timeout
            (100, 0), // Down
            (100, 0), // Down
            (100, 1), // Exit
            (100, 2), // Timeout
            (200, 0), // Down
        ]
    );

    // Verify tie-break on TIDs for the two Downs at time 100
    if let (
        SystemMsg::Down {
            notification: n1, ..
        },
        SystemMsg::Down {
            notification: n2, ..
        },
    ) = (&sorted[1], &sorted[2])
    {
        assert_eq!(n1.monitored.arena_index().index(), 2);
        assert_eq!(n2.monitored.arena_index().index(), 99);
    } else {
        panic!("Unexpected message types at index 1 and 2");
    }
}

#[test]
fn test_supervisor_shutdown_order() {
    // Contract SUP-STOP: Children are stopped in reverse start order.
    // Start order is determined by dependencies (topological sort).

    fn noop_start(
        _scope: &asupersync::cx::Scope<'static, asupersync::types::policy::FailFast>,
        _state: &mut RuntimeState,
        _cx: &asupersync::cx::Cx,
    ) -> Result<TaskId, SpawnError> {
        Ok(TaskId::new_for_test(0, 1))
    }

    let child_a = ChildSpec::new("A", noop_start);
    let child_b = ChildSpec::new("B", noop_start).depends_on("A");
    let child_c = ChildSpec::new("C", noop_start).depends_on("B");

    // Builder insertion order: C, B, A (reverse of dependency)
    let builder = SupervisorBuilder::new("sup")
        .child(child_c)
        .child(child_b)
        .child(child_a)
        .with_tie_break(StartTieBreak::InsertionOrder); // Should not matter for dependent nodes

    let compiled = builder.compile().expect("compilation success");

    // Expected start order: A -> B -> C
    let start_names = compiled.child_start_order_names();
    assert_eq!(start_names, vec!["A", "B", "C"]);

    // Expected stop order: C -> B -> A
    let stop_names = compiled.child_stop_order_names();
    assert_eq!(stop_names, vec!["C", "B", "A"]);
}
