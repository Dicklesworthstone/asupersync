#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::epoch::{EpochBarrier, EpochId};
use asupersync::types::Time;
use common::*;
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn test_epoch_barrier_overflow_race() {
    init_test_logging();
    test_phase!("test_epoch_barrier_overflow_race");
    test_section!("setup");
    // 10 expected, but 20 arrive
    let expected = 10_u32;
    let actual = 20_usize;
    let barrier = Arc::new(EpochBarrier::new(EpochId(1), expected, Time::ZERO));

    let start_gate = Arc::new(Barrier::new(actual));

    let mut handles = Vec::new();

    for i in 0..actual {
        let b = barrier.clone();
        let g = start_gate.clone();
        let id = format!("p-{i}");

        handles.push(thread::spawn(move || {
            g.wait();
            // We ignore error "Participant already arrived" (IDs are unique so won't happen)
            // We ignore "Barrier already triggered" - wait, checking this might stop latecomers?
            // arrive() checks is_triggered() at the start!

            // If checking is_triggered() is racey (read lock), multiple might pass it.
            b.arrive(&id, Time::ZERO).is_ok_and(|res| res.is_some())
        }));
    }

    let mut trigger_count = 0;
    for h in handles {
        if h.join().unwrap() {
            trigger_count += 1;
        }
    }

    // Even with overflow, exactly ONE should trigger
    test_section!("verify");
    assert_with_log!(
        trigger_count == 1,
        "expected exactly 1 trigger",
        1,
        trigger_count
    );
    test_complete!("test_epoch_barrier_overflow_race");
}
