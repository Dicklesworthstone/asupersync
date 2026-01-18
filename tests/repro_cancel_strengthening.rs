use asupersync::record::TaskRecord;
use asupersync::types::{Budget, CancelReason, CxInner, RegionId, TaskId};
use std::sync::{Arc, RwLock};

#[test]
fn repro_cancel_strengthening_bug() {
    let task_id = TaskId::new_for_test(0, 0);
    let region_id = RegionId::new_for_test(0, 0);
    let initial_budget = Budget::INFINITE;

    let mut task = TaskRecord::new(task_id, region_id, initial_budget);

    let inner = Arc::new(RwLock::new(CxInner::new(
        region_id,
        task_id,
        initial_budget,
    )));
    task.set_cx_inner(inner.clone());

    // 1. Move to Running
    task.start_running();

    // 2. Request cancel (Timeout) with loose budget
    let loose_budget = Budget::new().with_poll_quota(1000);
    task.request_cancel_with_budget(CancelReason::timeout(), loose_budget);

    // 3. Acknowledge cancel -> Cancelling state
    task.acknowledge_cancel();

    // Verify inner has loose budget
    {
        let guard = inner.read().unwrap();
        assert_eq!(guard.budget.poll_quota, 1000);
    }

    // 4. Request stronger cancel (Shutdown) with tight budget
    let tight_budget = Budget::new().with_poll_quota(10);
    task.request_cancel_with_budget(CancelReason::shutdown(), tight_budget);

    // 5. Verify task state has tight budget
    let current_budget = task.cleanup_budget().expect("should be cancelling");
    assert_eq!(
        current_budget.poll_quota, 10,
        "Task record should have tight budget"
    );

    // 6. Verify inner has tight budget (The Bug)
    {
        let guard = inner.read().unwrap();
        // This assertion fails if the bug exists
        assert_eq!(
            guard.budget.poll_quota, 10,
            "CxInner should have tight budget but likely has 1000"
        );
    }
}
