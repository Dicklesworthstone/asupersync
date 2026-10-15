//! Scheduler shutdown behavior audit tests.
//!
//! The scheduler owns the low-level worker-stop signal only:
//! `ThreeLaneScheduler::shutdown()` sets the shared shutdown flag and wakes
//! workers. It does not own application cancellation, finalizer drain,
//! obligation cleanup, timeout policy, or region-close quiescence. Those
//! higher-level shutdown semantics live in the app/region runtime state.
//!
//! These tests keep that boundary executable so the audit module does not
//! claim missing Tokio-style APIs as scheduler defects.

#![cfg(test)]

use crate::runtime::scheduler::three_lane::ThreeLaneScheduler;
use crate::runtime::state::RuntimeState;
use crate::sync::ContendedMutex;
use crate::types::{TaskId, Time};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn test_state() -> Arc<ContendedMutex<RuntimeState>> {
    Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()))
}

fn three_lane_source() -> &'static str {
    include_str!("three_lane.rs")
}

fn shutdown_body(source: &str) -> &str {
    let marker = "pub fn shutdown(&self) {";
    let start = source.find(marker).expect("ThreeLaneScheduler::shutdown");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("shutdown body close");
    &source[start..start + body_end]
}

#[test]
fn scheduler_shutdown_is_idempotent_shared_signal() {
    let state = test_state();
    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    assert!(!scheduler.is_shutdown());

    scheduler.shutdown();
    scheduler.shutdown();

    assert!(scheduler.is_shutdown());

    let workers = scheduler.take_workers();
    assert_eq!(workers.len(), 2);
    for worker in workers {
        assert!(
            worker.shutdown.load(Ordering::Acquire),
            "scheduler shutdown flag must be shared with every worker"
        );
    }
}

#[test]
fn scheduler_shutdown_is_worker_stop_not_task_drain() {
    let state = test_state();
    let mut scheduler = ThreeLaneScheduler::new(1, &state);

    scheduler.inject_cancel(TaskId::new_for_test(9001, 1), 250);
    scheduler.inject_timed(TaskId::new_for_test(9002, 1), Time::from_nanos(10));
    scheduler.inject_ready(TaskId::new_for_test(9003, 1), 10);

    scheduler.shutdown();

    let workers = scheduler.take_workers();
    let worker = workers.first().expect("one worker");
    assert_eq!(
        worker.global.len(),
        3,
        "scheduler shutdown must not silently drain or drop queued work; app/region cancellation owns drain/finalize"
    );

    let state = state
        .lock()
        .expect("runtime state lock should not be poisoned");
    assert!(state.tasks_is_empty());
    assert!(state.obligations_is_empty());
}

#[test]
fn worker_run_loop_exits_when_shutdown_is_already_signaled() {
    let state = test_state();
    let mut scheduler = ThreeLaneScheduler::new(1, &state);
    let mut worker = scheduler
        .take_workers()
        .pop()
        .expect("scheduler should create one worker");
    scheduler.shutdown();

    let (done_tx, done_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        worker.run_loop();
        done_tx.send(()).expect("send completion");
    });

    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("shutdown-signaled worker should exit without parking forever");
    handle.join().expect("worker thread should not panic");
}

#[test]
fn scheduler_shutdown_source_pins_signal_only_boundary() {
    let source = three_lane_source();
    let body = shutdown_body(source);

    assert!(
        body.contains("self.shutdown.store(true, Ordering::Release);"),
        "shutdown must publish the worker-stop signal with Release ordering"
    );
    assert!(
        body.contains("self.wake_all();"),
        "shutdown must wake workers after publishing the stop signal"
    );

    for unsupported in [
        "pub fn shutdown_now(",
        "pub fn shutdown_timeout(",
        "pub async fn shutdown_timeout(",
    ] {
        assert!(
            !source.contains(unsupported),
            "scheduler must not grow a Tokio-style `{unsupported}` API; region/app shutdown owns timeout policy"
        );
    }

    for forbidden in [
        "cancel_request(",
        "drain_ready_async_finalizers(",
        "create_obligation(",
        "commit_obligation(",
        "abort_obligation(",
    ] {
        assert!(
            !body.contains(forbidden),
            "scheduler shutdown must remain a wake signal and must not perform `{forbidden}` directly"
        );
    }
}
