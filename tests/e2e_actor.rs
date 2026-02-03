//! Actor E2E test suite entry point.
//!
//! This file provides the entry point for the actor E2E test suite,
//! including unit tests, integration tests, lab runtime tests, and E2E scenarios.
//!
//! Run with: `cargo test --test e2e_actor`

#![allow(unused_imports)]

mod common {
    pub fn init_test_logging() {
        // Initialize tracing for tests if not already done
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
    }
}

/// Phase tracking macro for structured test logging.
#[macro_export]
macro_rules! test_phase {
    ($name:expr) => {
        tracing::info!(test = $name, "=== TEST START ===");
    };
}

/// Assertion with logging for better test output.
#[macro_export]
macro_rules! assert_with_log {
    ($cond:expr, $msg:expr, $expected:expr, $actual:expr) => {
        if !$cond {
            tracing::error!(
                message = $msg,
                expected = ?$expected,
                actual = ?$actual,
                "Assertion failed"
            );
        }
        assert!($cond, "{}: expected {:?}, got {:?}", $msg, $expected, $actual);
    };
}

// Re-export the actor test module as actor_e2e for internal use
#[path = "e2e/actor/mod.rs"]
pub mod actor_e2e;

use actor_e2e::util::{CounterActor, CounterMessage, EchoActor};
use asupersync::channel::mpsc::SendError;
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::policy::FailFast;
use asupersync::types::Budget;
use std::sync::{Arc, Mutex};

fn init_test(name: &str) {
    common::init_test_logging();
    test_phase!(name);
}

fn spawn_actor_in_lab<A: asupersync::actor::Actor>(
    runtime: &mut LabRuntime,
    cx: &Cx,
    actor: A,
    mailbox_capacity: usize,
) -> (asupersync::actor::ActorHandle<A>, asupersync::types::TaskId) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let scope = Scope::<FailFast>::new(region, Budget::INFINITE);
    let (handle, stored) = scope
        .spawn_actor(&mut runtime.state, cx, actor, mailbox_capacity)
        .expect("spawn actor");
    let task_id = handle.task_id();
    runtime.state.store_spawned_task(task_id, stored);
    (handle, task_id)
}

fn run_lab(runtime: &mut LabRuntime, task_id: asupersync::types::TaskId) {
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();
}

#[test]
fn test_actor_counter_logs_start_and_stop() {
    init_test("test_actor_counter_logs_start_and_stop");
    let mut runtime = LabRuntime::new(LabConfig::new(1).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = CounterActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    drop(handle);
    run_lab(&mut runtime, task_id);

    let trace = events.lock().unwrap().clone();
    let has_start = trace.iter().any(|e| e == "started");
    let has_stop = trace.iter().any(|e| e.starts_with("stopped:count="));

    assert_with_log!(has_start, "on_start logged", true, has_start);
    assert_with_log!(has_stop, "on_stop logged", true, has_stop);
}

#[test]
fn test_actor_counter_increments_accumulate() {
    init_test("test_actor_counter_increments_accumulate");
    let mut runtime = LabRuntime::new(LabConfig::new(2).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = CounterActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    handle.try_send(CounterMessage::Increment(2)).unwrap();
    handle.try_send(CounterMessage::Increment(3)).unwrap();

    drop(handle);
    run_lab(&mut runtime, task_id);

    let trace = events.lock().unwrap().clone();
    let inc2 = trace.iter().any(|e| e == "increment:2->2");
    let inc3 = trace.iter().any(|e| e == "increment:3->5");

    assert_with_log!(inc2, "increment 2", true, inc2);
    assert_with_log!(inc3, "increment 3", true, inc3);
}

#[test]
fn test_actor_counter_reset_clears_count() {
    init_test("test_actor_counter_reset_clears_count");
    let mut runtime = LabRuntime::new(LabConfig::new(3).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = CounterActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    handle.try_send(CounterMessage::Increment(5)).unwrap();
    handle.try_send(CounterMessage::Reset).unwrap();
    handle.try_send(CounterMessage::GetCount).unwrap();

    drop(handle);
    run_lab(&mut runtime, task_id);

    let trace = events.lock().unwrap().clone();
    let reset = trace.iter().any(|e| e == "reset");
    let get_zero = trace.iter().any(|e| e == "get:0");

    assert_with_log!(reset, "reset logged", true, reset);
    assert_with_log!(get_zero, "count cleared", true, get_zero);
}

#[test]
fn test_actor_counter_get_count_after_increment() {
    init_test("test_actor_counter_get_count_after_increment");
    let mut runtime = LabRuntime::new(LabConfig::new(4).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = CounterActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    handle.try_send(CounterMessage::Increment(1)).unwrap();
    handle.try_send(CounterMessage::GetCount).unwrap();

    drop(handle);
    run_lab(&mut runtime, task_id);

    let trace = events.lock().unwrap().clone();
    let get_one = trace.iter().any(|e| e == "get:1");
    assert_with_log!(get_one, "count after increment", true, get_one);
}

#[test]
fn test_actor_echo_records_messages() {
    init_test("test_actor_echo_records_messages");
    let mut runtime = LabRuntime::new(LabConfig::new(5).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = EchoActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    handle.try_send("alpha".to_string()).unwrap();
    handle.try_send("beta".to_string()).unwrap();

    drop(handle);
    run_lab(&mut runtime, task_id);

    let trace = events.lock().unwrap().clone();
    let alpha = trace.iter().any(|e| e == "echo:recv:alpha");
    let beta = trace.iter().any(|e| e == "echo:recv:beta");

    assert_with_log!(alpha, "alpha received", true, alpha);
    assert_with_log!(beta, "beta received", true, beta);
}

#[test]
fn test_actor_echo_stop_reports_count() {
    init_test("test_actor_echo_stop_reports_count");
    let mut runtime = LabRuntime::new(LabConfig::new(6).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = EchoActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    handle.try_send("m1".to_string()).unwrap();
    handle.try_send("m2".to_string()).unwrap();
    handle.try_send("m3".to_string()).unwrap();

    drop(handle);
    run_lab(&mut runtime, task_id);

    let trace = events.lock().unwrap().clone();
    let stopped = trace.iter().any(|e| e == "echo:stopped:count=3");
    assert_with_log!(stopped, "stop count", true, stopped);
}

#[test]
fn test_actor_try_send_full_returns_error() {
    init_test("test_actor_try_send_full_returns_error");
    let mut runtime = LabRuntime::new(LabConfig::new(7).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = CounterActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 1);

    handle.try_send(CounterMessage::Increment(1)).unwrap();
    let err = handle.try_send(CounterMessage::Increment(1)).unwrap_err();
    let full = matches!(err, SendError::Full(_));
    assert_with_log!(full, "mailbox full", true, full);

    drop(handle);
    run_lab(&mut runtime, task_id);
}

#[test]
fn test_actor_ref_clone_sends_messages() {
    init_test("test_actor_ref_clone_sends_messages");
    let mut runtime = LabRuntime::new(LabConfig::new(8).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = CounterActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    let sender = handle.sender();
    let sender2 = sender.clone();
    sender.try_send(CounterMessage::Increment(1)).unwrap();
    sender2.try_send(CounterMessage::Increment(2)).unwrap();

    drop(handle);
    run_lab(&mut runtime, task_id);

    let trace = events.lock().unwrap().clone();
    let inc1 = trace.iter().any(|e| e == "increment:1->1");
    let inc2 = trace.iter().any(|e| e == "increment:2->3");
    assert_with_log!(inc1, "increment 1", true, inc1);
    assert_with_log!(inc2, "increment 2", true, inc2);
}

#[test]
fn test_actor_id_matches_ref() {
    init_test("test_actor_id_matches_ref");
    let mut runtime = LabRuntime::new(LabConfig::new(9).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = CounterActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    let actor_id = handle.actor_id();
    let ref_id = handle.sender().actor_id();
    let same = actor_id == ref_id;
    assert_with_log!(same, "actor id stable", true, same);

    drop(handle);
    run_lab(&mut runtime, task_id);
}

#[test]
fn test_actor_stop_marks_finished() {
    init_test("test_actor_stop_marks_finished");
    let mut runtime = LabRuntime::new(LabConfig::new(10).max_steps(10_000));
    let cx: Cx = Cx::for_testing();

    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = CounterActor::new(Arc::clone(&events));
    let (handle, task_id) = spawn_actor_in_lab(&mut runtime, &cx, actor, 16);

    handle.stop();
    run_lab(&mut runtime, task_id);

    let finished = handle.is_finished();
    assert_with_log!(finished, "actor finished", true, finished);
}
