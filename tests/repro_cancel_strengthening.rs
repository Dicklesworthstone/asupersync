#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::runtime::RuntimeState;
use asupersync::types::{Budget, CancelReason};
use common::*;

#[test]
fn repro_cancel_strengthening_bug() {
    init_test_logging();
    test_phase!("repro_cancel_strengthening_bug");
    test_section!("setup");
    let initial_budget = Budget::INFINITE;
    let mut state = RuntimeState::new();
    let region_id = state.create_root_region(initial_budget);
    let (task_id, _handle) = state
        .create_task(region_id, initial_budget, async {})
        .expect("create linked task");

    test_section!("transition_to_running");
    // 1. Move to Running
    state
        .task_mut(task_id)
        .expect("task record")
        .start_running();

    // 2. Request cancel (Timeout) with loose budget
    test_section!("request_loose_cancel");
    let loose_budget = Budget::new().with_poll_quota(1000);
    let loose_cancel_effects = state
        .task_mut(task_id)
        .expect("task record")
        .request_cancel_with_budget(CancelReason::timeout(), loose_budget);
    let (_newly_cancelled, loose_cancel_wakes) = loose_cancel_effects.into_parts();
    loose_cancel_wakes.dispatch();

    // 3. Acknowledge cancel -> Cancelling state
    state
        .task_mut(task_id)
        .expect("task record")
        .acknowledge_cancel();

    // Verify inner has loose budget
    test_section!("verify_loose_budget");
    let loose_quota = state
        .task(task_id)
        .expect("task record")
        .context_budget()
        .expect("linked task context")
        .poll_quota;
    assert_with_log!(
        loose_quota == 1000,
        "cx inner should start with loose budget",
        1000,
        loose_quota
    );

    // 4. Request stronger cancel (Shutdown) with tight budget
    test_section!("request_tight_cancel");
    let tight_budget = Budget::new().with_poll_quota(10);
    let tight_cancel_effects = state
        .task_mut(task_id)
        .expect("task record")
        .request_cancel_with_budget(CancelReason::shutdown(), tight_budget);
    let (_newly_cancelled, tight_cancel_wakes) = tight_cancel_effects.into_parts();
    tight_cancel_wakes.dispatch();

    // 5. Verify task state has tight budget
    test_section!("verify_task_budget");
    let current_budget = state
        .task(task_id)
        .expect("task record")
        .cleanup_budget()
        .expect("should be cancelling");
    assert_with_log!(
        current_budget.poll_quota == 10,
        "task record should have tight budget",
        10,
        current_budget.poll_quota
    );

    // 6. Verify inner has tight budget (The Bug)
    test_section!("verify_inner_budget");
    let tight_quota = state
        .task(task_id)
        .expect("task record")
        .context_budget()
        .expect("linked task context")
        .poll_quota;
    // This assertion fails if the bug exists
    assert_with_log!(
        tight_quota == 10,
        "cx inner should have tight budget but likely has 1000",
        10,
        tight_quota
    );
    test_complete!("repro_cancel_strengthening_bug");
}
