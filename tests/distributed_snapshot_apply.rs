use asupersync::distributed::bridge::{RegionBridge, RegionMode};
use asupersync::distributed::snapshot::{BudgetSnapshot, RegionSnapshot, TaskSnapshot, TaskState};
use asupersync::record::region::RegionState;
use asupersync::types::{Budget, RegionId, TaskId, Time};

#[test]
fn test_apply_snapshot_updates_local_state() {
    // 1. Create a local bridge
    let region_id = RegionId::new_for_test(1, 0);
    let mut bridge = RegionBridge::new_local(region_id, None, Budget::default());

    // 2. Create a snapshot with DIFFERENT state than the bridge
    // - State: Open -> Closing
    // - Tasks: [1] -> [1, 2]
    // - Children: [] -> [3]
    // - Budget: defaults -> modified deadline
    let snapshot = RegionSnapshot {
        region_id,
        state: RegionState::Closing,
        timestamp: Time::from_secs(100),
        sequence: 1,
        tasks: vec![
            TaskSnapshot {
                task_id: TaskId::new_for_test(1, 0),
                state: TaskState::Running,
                priority: 0,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(2, 0),
                state: TaskState::Running,
                priority: 0,
            },
        ],
        children: vec![RegionId::new_for_test(3, 0)],
        finalizer_count: 0,
        budget: BudgetSnapshot {
            deadline_nanos: Some(999999),
            polls_remaining: Some(50),
            cost_remaining: None,
        },
        cancel_reason: Some("remote cancel".to_string()),
        parent: None,
        metadata: vec![],
    };

    // 3. Apply snapshot
    bridge.apply_snapshot(&snapshot).expect("apply_snapshot failed");

    // 4. Verify local state matches snapshot
    // This will fail until apply_snapshot is implemented
    assert_eq!(bridge.local_state(), RegionState::Closing, "State mismatch");
    
    let tasks = bridge.local().task_ids();
    assert!(tasks.contains(&TaskId::new_for_test(2, 0)), "Task 2 missing");
    
    let children = bridge.local().child_ids();
    assert!(children.contains(&RegionId::new_for_test(3, 0)), "Child 3 missing");
    
    let budget = bridge.local().budget();
    assert_eq!(budget.poll_quota, 50, "Budget poll quota mismatch");
    
    let reason = bridge.local().cancel_reason();
    assert!(reason.is_some(), "Cancel reason missing");
}
