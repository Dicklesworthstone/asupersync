#![allow(missing_docs)]
//! Regression test for missing-record local queue stealing.

use asupersync::runtime::scheduler::local_queue::LocalQueue;
use asupersync::types::TaskId;
use std::sync::Arc;

#[test]
fn missing_records_do_not_block_stealing() {
    let state = LocalQueue::test_state(10);
    let queue = LocalQueue::new(Arc::clone(&state));

    for i in 0..10 {
        queue.push(TaskId::new_for_test(i, 0));
    }

    // Remove the first 8 task records. These represent pre-arena test ids or
    // stale records; current queue semantics treat them as stealable rather
    // than letting them strand later work in the victim queue.
    {
        let mut guard = state.lock().unwrap();
        for i in 0..8 {
            guard.remove_task(TaskId::new_for_test(i, 0));
        }
    }

    let stealer = queue.stealer();
    for i in 0..10 {
        assert_eq!(
            stealer.steal(),
            Some(TaskId::new_for_test(i, 0)),
            "stealer should drain missing-record prefixes without blocking later work"
        );
    }
    assert_eq!(stealer.steal(), None);
}
