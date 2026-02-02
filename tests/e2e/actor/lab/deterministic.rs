//! Determinism tests for actors in the lab runtime.
//!
//! These tests verify that running the same actor scenario with the same seed
//! produces identical event traces, ensuring reproducible behavior.

use crate::actor_e2e::util::init_actor_test;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use std::sync::{Arc, Mutex};

/// Run a simple counter actor scenario and return the event trace.
fn run_counter_scenario(seed: u64) -> Vec<String> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(10_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_sender = Arc::clone(&events);

    // Create a simple message processing loop
    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // Simulate actor message handling
            let mut count = 0u64;
            for i in 0..5 {
                count += i;
                events_sender
                    .lock()
                    .unwrap()
                    .push(format!("msg:{i}:total:{count}"));
            }
            events_sender
                .lock()
                .unwrap()
                .push(format!("done:count={count}"));
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let result = events.lock().unwrap().clone();
    result
}

/// Run a multi-actor scenario with message exchanges.
fn run_multi_actor_scenario(seed: u64) -> Vec<String> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(20_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_a = Arc::clone(&events);
    let events_b = Arc::clone(&events);

    // Actor A: sends messages to B
    let (task_sender_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            events_a.lock().unwrap().push("A:start".into());
            for i in 0..3 {
                events_a.lock().unwrap().push(format!("A:send:{i}"));
            }
            events_a.lock().unwrap().push("A:done".into());
        })
        .expect("create task A");

    // Actor B: receives messages from A
    let (task_receiver_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            events_b.lock().unwrap().push("B:start".into());
            for i in 0..3 {
                events_b.lock().unwrap().push(format!("B:recv:{i}"));
            }
            events_b.lock().unwrap().push("B:done".into());
        })
        .expect("create task B");

    // Schedule both tasks
    {
        let mut sched = runtime.scheduler.lock().unwrap();
        sched.schedule(task_sender_id, 0);
        sched.schedule(task_receiver_id, 1);
    }

    runtime.run_until_quiescent();
    let result = events.lock().unwrap().clone();
    result
}

#[test]
fn actor_lab_same_seed_same_trace() {
    init_actor_test("actor_lab_same_seed_same_trace");

    let trace1 = run_counter_scenario(42);
    let trace2 = run_counter_scenario(42);

    assert_with_log!(
        trace1 == trace2,
        "same seed should produce same trace",
        format!("{trace1:?}"),
        format!("{trace2:?}")
    );
}

#[test]
fn actor_lab_different_seed_may_differ() {
    init_actor_test("actor_lab_different_seed_may_differ");

    let trace1 = run_multi_actor_scenario(42);
    let trace2 = run_multi_actor_scenario(43);

    // Both should complete, but ordering might differ
    let trace1_has_a = trace1.iter().any(|e| e.starts_with("A:"));
    let trace1_has_b = trace1.iter().any(|e| e.starts_with("B:"));
    let trace2_has_a = trace2.iter().any(|e| e.starts_with("A:"));
    let trace2_has_b = trace2.iter().any(|e| e.starts_with("B:"));

    assert_with_log!(trace1_has_a, "trace1 has A events", true, trace1_has_a);
    assert_with_log!(trace1_has_b, "trace1 has B events", true, trace1_has_b);
    assert_with_log!(trace2_has_a, "trace2 has A events", true, trace2_has_a);
    assert_with_log!(trace2_has_b, "trace2 has B events", true, trace2_has_b);
}

#[test]
fn actor_lab_multi_run_consistency() {
    init_actor_test("actor_lab_multi_run_consistency");

    // Run the same scenario 5 times with the same seed
    let seed = 123;
    let baseline = run_multi_actor_scenario(seed);

    for run in 1..=5 {
        let trace = run_multi_actor_scenario(seed);
        assert_with_log!(
            trace == baseline,
            &format!("run {run} should match baseline"),
            format!("{baseline:?}"),
            format!("{trace:?}")
        );
    }
}

#[test]
fn actor_lab_event_ordering_deterministic() {
    init_actor_test("actor_lab_event_ordering_deterministic");

    // Use a specific seed that we know produces a particular ordering
    let seed = 999;
    let trace1 = run_multi_actor_scenario(seed);
    let trace2 = run_multi_actor_scenario(seed);

    // The exact ordering should be identical
    for (i, (e1, e2)) in trace1.iter().zip(trace2.iter()).enumerate() {
        assert_with_log!(
            e1 == e2,
            &format!("event {i} should match"),
            e1.clone(),
            e2.clone()
        );
    }

    assert_with_log!(
        trace1.len() == trace2.len(),
        "trace lengths should match",
        trace1.len(),
        trace2.len()
    );
}
