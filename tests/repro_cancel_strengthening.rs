#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::record::TaskRecord;
use asupersync::types::{Budget, CancelReason, CxInner, RegionId, TaskId};
use common::*;
use parking_lot::RwLock;
use std::sync::Arc;

#[test]
fn repro_cancel_strengthening_bug() {
    init_test_logging();
    test_phase!("repro_cancel_strengthening_bug");
    test_section!("setup");
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

    test_section!("transition_to_running");
    // 1. Move to Running
    task.start_running();

    // 2. Request cancel (Timeout) with loose budget
    test_section!("request_loose_cancel");
    let loose_budget = Budget::new().with_poll_quota(1000);
    task.request_cancel_with_budget(CancelReason::timeout(), loose_budget);

    // 3. Acknowledge cancel -> Cancelling state
    task.acknowledge_cancel();

    // Verify inner has loose budget
    test_section!("verify_loose_budget");
    let loose_quota = {
        let guard = inner.read();
        let quota = guard.budget.poll_quota;
        drop(guard);
        quota
    };
    assert_with_log!(
        loose_quota == 1000,
        "cx inner should start with loose budget",
        1000,
        loose_quota
    );

    // 4. Request stronger cancel (Shutdown) with tight budget
    test_section!("request_tight_cancel");
    let tight_budget = Budget::new().with_poll_quota(10);
    task.request_cancel_with_budget(CancelReason::shutdown(), tight_budget);

    // 5. Verify task state has tight budget
    test_section!("verify_task_budget");
    let current_budget = task.cleanup_budget().expect("should be cancelling");
    assert_with_log!(
        current_budget.poll_quota == 10,
        "task record should have tight budget",
        10,
        current_budget.poll_quota
    );

    // 6. Verify inner has tight budget (The Bug)
    test_section!("verify_inner_budget");
    let tight_quota = {
        let guard = inner.read();
        let quota = guard.budget.poll_quota;
        drop(guard);
        quota
    };
    // This assertion fails if the bug exists
    assert_with_log!(
        tight_quota == 10,
        "cx inner should have tight budget but likely has 1000",
        10,
        tight_quota
    );
    test_complete!("repro_cancel_strengthening_bug");
}
