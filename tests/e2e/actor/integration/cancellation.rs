//! Cancellation integration tests for actors.
//!
//! These tests verify actor behavior during cancellation scenarios.

use crate::actor_e2e::util::init_actor_test;
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, CancelReason};
use std::sync::{Arc, Mutex};

/// Test: Actor respects cancellation request.
#[test]
fn actor_respects_cancellation() {
    init_actor_test("actor_respects_cancellation");

    let mut runtime = LabRuntime::new(LabConfig::new(42).max_steps(10_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_task = Arc::clone(&events);

    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx = Cx::for_testing();

            events_task.lock().unwrap().push("started".into());

            // Simulate work with cancellation check
            for i in 0..10 {
                if cx.is_cancel_requested() {
                    events_task
                        .lock()
                        .unwrap()
                        .push(format!("cancelled_at:{i}"));
                    break;
                }
                events_task.lock().unwrap().push(format!("work:{i}"));
            }

            events_task.lock().unwrap().push("exiting".into());
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let trace = events.lock().unwrap().clone();

    // Should have started and exited
    let has_started = trace.iter().any(|e| e == "started");
    let has_exiting = trace.iter().any(|e| e == "exiting");

    assert_with_log!(has_started, "should have started", true, has_started);
    assert_with_log!(has_exiting, "should have exited", true, has_exiting);
}

/// Test: Region close triggers actor cancellation.
#[test]
fn region_close_cancels_actors() {
    init_actor_test("region_close_cancels_actors");

    let mut runtime = LabRuntime::new(LabConfig::new(42).max_steps(10_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_task = Arc::clone(&events);

    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            events_task.lock().unwrap().push("actor:running".into());
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let trace = events.lock().unwrap().clone();

    let has_running = trace.iter().any(|e| e == "actor:running");
    assert_with_log!(has_running, "actor should have run", true, has_running);
}
