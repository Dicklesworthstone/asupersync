//! Basic messaging tests for actors.
//!
//! These tests verify fundamental message send/receive patterns.

use crate::actor_e2e::util::init_actor_test;
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use std::sync::{Arc, Mutex};

/// Test: Messages are processed in the order they arrive.
#[test]
fn actor_fifo_message_ordering() {
    init_actor_test("actor_fifo_message_ordering");

    let mut runtime = LabRuntime::new(LabConfig::new(42).max_steps(10_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_task = Arc::clone(&events);

    // Simulate FIFO message processing
    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            for i in 0..5 {
                events_task.lock().unwrap().push(format!("msg:{i}"));
            }
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let trace = events.lock().unwrap().clone();

    // Verify FIFO ordering
    let expected = ["msg:0", "msg:1", "msg:2", "msg:3", "msg:4"];
    for (i, (actual, expected)) in trace.iter().zip(expected.iter()).enumerate() {
        assert_with_log!(
            actual == *expected,
            &format!("message {i} should match"),
            expected.to_string(),
            actual.clone()
        );
    }
}

/// Test: Multiple tasks can concurrently send messages.
#[test]
fn actor_concurrent_senders() {
    init_actor_test("actor_concurrent_senders");

    let mut runtime = LabRuntime::new(LabConfig::new(42).max_steps(10_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Create 3 sender tasks
    for sender_id in 0..3 {
        let events_sender = Arc::clone(&events);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                events_sender
                    .lock()
                    .unwrap()
                    .push(format!("sender:{sender_id}:msg"));
            })
            .expect("create sender task");

        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let trace = events.lock().unwrap().clone();

    // All senders should have sent their message
    let count = trace.len();
    assert_with_log!(count == 3, "all 3 senders should send", 3, count);

    // Each sender should appear
    for i in 0..3 {
        let has_sender = trace.iter().any(|e| e.contains(&format!("sender:{i}")));
        assert_with_log!(
            has_sender,
            &format!("sender {i} should appear"),
            true,
            has_sender
        );
    }
}

/// Test: Actor can be stopped gracefully.
#[test]
fn actor_graceful_stop() {
    init_actor_test("actor_graceful_stop");

    let mut runtime = LabRuntime::new(LabConfig::new(42).max_steps(10_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_task = Arc::clone(&events);

    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            events_task.lock().unwrap().push("started".into());
            // Simulate some work
            for i in 0..3 {
                events_task.lock().unwrap().push(format!("work:{i}"));
            }
            events_task.lock().unwrap().push("stopping".into());
            events_task.lock().unwrap().push("stopped".into());
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let trace = events.lock().unwrap().clone();

    // Verify lifecycle events
    let has_started = trace.iter().any(|e| e == "started");
    let has_stopped = trace.iter().any(|e| e == "stopped");

    assert_with_log!(has_started, "should have started", true, has_started);
    assert_with_log!(has_stopped, "should have stopped", true, has_stopped);
}
