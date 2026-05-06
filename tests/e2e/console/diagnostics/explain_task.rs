//! Task explanation E2E tests.

use crate::console_e2e::common::create_test_runtime_state;
use crate::console_e2e::util::init_console_test;
use asupersync::observability::{BlockReason, Diagnostics};
use asupersync::types::TaskId;

#[test]
fn e2e_diagnostics_explain_task_not_found() {
    init_console_test("e2e_diagnostics_explain_task_not_found");

    let state = create_test_runtime_state();
    let diagnostics = Diagnostics::new(state);

    // Query a non-existent task
    let fake_id = TaskId::new_for_test(88888, 0);
    let explanation = diagnostics.explain_task_blocked(fake_id);

    let is_not_found = matches!(explanation.block_reason, BlockReason::TaskNotFound);
    crate::assert_with_log!(is_not_found, "task not found", true, is_not_found);

    crate::test_complete!("e2e_diagnostics_explain_task_not_found");
}

#[test]
fn e2e_diagnostics_explain_task_display() {
    init_console_test("e2e_diagnostics_explain_task_display");

    let state = create_test_runtime_state();
    let diagnostics = Diagnostics::new(state);

    // Get an explanation and verify it can be displayed
    let fake_id = TaskId::new_for_test(77777, 0);
    let explanation = diagnostics.explain_task_blocked(fake_id);

    let rendered = format!("{explanation}");
    crate::assert_with_log!(
        rendered.contains("Task"),
        "display has task",
        true,
        rendered.contains("Task")
    );
    crate::assert_with_log!(
        rendered.contains("blocked"),
        "display has blocked",
        true,
        rendered.contains("blocked")
    );

    crate::test_complete!("e2e_diagnostics_explain_task_display");
}

#[test]
fn e2e_diagnostics_block_reason_display() {
    init_console_test("e2e_diagnostics_block_reason_display");

    // Test that each BlockReason variant has meaningful Display
    let variants = [
        (BlockReason::TaskNotFound, "not found"),
        (BlockReason::NotStarted, "not started"),
        (BlockReason::AwaitingSchedule, "schedule"),
        (BlockReason::Completed, "completed"),
        (
            BlockReason::AwaitingFuture {
                description: "test".to_string(),
            },
            "future",
        ),
    ];

    for (reason, expected_substring) in variants {
        let rendered = format!("{reason}");
        crate::assert_with_log!(
            rendered.to_lowercase().contains(expected_substring),
            "block reason display",
            true,
            rendered.to_lowercase().contains(expected_substring)
        );
    }

    crate::test_complete!("e2e_diagnostics_block_reason_display");
}
