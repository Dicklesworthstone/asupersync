#![allow(clippy::all)]
#![allow(missing_docs)]
//! Regression test for local queue dead task stealing bug.

use asupersync::runtime::scheduler::local_queue::LocalQueue;
use asupersync::types::TaskId;
use std::sync::Arc;

#[test]
fn test_dead_tasks_block_stealing() {
    let state = LocalQueue::test_state(10);
    let queue = LocalQueue::new(Arc::clone(&state));

    for i in 0..10 {
        queue.push(TaskId::new_for_test(i, 0));
    }

    // Now, remove the first 8 tasks from the state to simulate them completing
    {
        let mut guard = state.lock().unwrap();
        for i in 0..8 {
            guard.remove_task(TaskId::new_for_test(i, 0));
        }
    }

    // Now try to steal. Task 8 is still alive and at index 8.
    let stealer = queue.stealer();
    let stolen = stealer.steal();

    assert_eq!(
        stolen,
        Some(TaskId::new_for_test(8, 0)),
        "Stealer should have skipped dead tasks and stolen task 8"
    );
}
