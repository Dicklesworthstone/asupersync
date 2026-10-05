//! An idle scheduler dispatch must not take the global `RuntimeState` lock.
//!
//! Every worker calls `ThreeLaneWorker::next_task` on every dispatch. A
//! global-state lock on that path serializes the whole worker fleet on one
//! mutex even when there is no work
//! (br-asupersync-issue65-criticisms-kpmoy5.1.2, kpmoy5.1.3). The runtime
//! builder gives every worker a timer driver and the obligation mailbox, and
//! with both attached an idle dispatch must answer from atomics alone.
//!
//! Run with `cargo test --test scheduler_idle_dispatch_lock_free --features lock-metrics`.

#![cfg(feature = "lock-metrics")]

use asupersync::runtime::RuntimeState;
use asupersync::runtime::obligation_mailbox::ObligationMailbox;
use asupersync::runtime::scheduler::three_lane::{ThreeLaneScheduler, ThreeLaneWorker};
use asupersync::sync::ContendedMutex;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::Time;
use std::sync::Arc;

const IDLE_DISPATCHES: u64 = 1_000;

fn idle_worker(
    attach_obligation_mailbox: bool,
) -> (Arc<ContendedMutex<RuntimeState>>, ThreeLaneWorker) {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000)));
    let mut runtime_state = RuntimeState::new();
    runtime_state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
    let state = Arc::new(ContendedMutex::new("runtime_state", runtime_state));
    let mut scheduler = ThreeLaneScheduler::new(1, &state);
    if attach_obligation_mailbox {
        scheduler.attach_obligation_mailbox(&Arc::new(ObligationMailbox::new()));
    }
    let worker = scheduler
        .take_workers()
        .pop()
        .expect("a one-worker scheduler has a worker");
    (state, worker)
}

/// Dispatches `IDLE_DISPATCHES` times on an empty scheduler and returns how
/// many times the runtime-state lock was taken.
fn idle_dispatch_lock_acquisitions(attach_obligation_mailbox: bool) -> u64 {
    let (state, mut worker) = idle_worker(attach_obligation_mailbox);
    // Settle any one-time initialization before counting.
    for _ in 0..8 {
        assert!(worker.next_task().is_none(), "the scheduler is empty");
    }
    state.reset_metrics();
    for _ in 0..IDLE_DISPATCHES {
        assert!(worker.next_task().is_none(), "the scheduler is empty");
    }
    state.snapshot().acquisitions
}

#[test]
fn idle_dispatch_takes_no_runtime_state_lock() {
    let acquisitions = idle_dispatch_lock_acquisitions(true);
    assert_eq!(
        acquisitions, 0,
        "{IDLE_DISPATCHES} idle dispatches took the RuntimeState lock {acquisitions} times"
    );
}

/// Planted negative: without the obligation mailbox the worker cannot tell
/// that no obligation posts are pending, so it locks on every dispatch. This
/// proves the counter observes the dispatch path that the test above guards.
#[test]
fn without_the_obligation_mailbox_every_idle_dispatch_locks() {
    let acquisitions = idle_dispatch_lock_acquisitions(false);
    assert!(
        acquisitions >= IDLE_DISPATCHES,
        "expected at least one lock per dispatch without the mailbox, got {acquisitions}"
    );
}
