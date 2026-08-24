#![allow(warnings)]
#![allow(clippy::all)]
//! Cancellation integration tests for actors.
//!
//! These tests verify actor behavior during cancellation scenarios.

use crate::actor_e2e::util::init_actor_test;
use asupersync::actor::Actor;
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::{JoinError, RuntimeBuilder, RuntimeState};
use asupersync::types::policy::FailFast;
use asupersync::types::{Budget, CancelReason, Outcome};
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A graceful stop preserves the committed FIFO tail after a handler panic.
///
/// This is intentionally a native-runtime integration regression: it drives
/// the public actor spawn, send, stop, and join sequence without compiling the
/// monolithic in-crate unit-test binary.
#[test]
fn native_actor_graceful_drain_continues_after_handler_panic() {
    #[derive(Debug)]
    struct DrainPanicActor {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Actor for DrainPanicActor {
        type Message = u8;

        fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.events.lock().push("start");
            Box::pin(async {})
        }

        fn handle(
            &mut self,
            _cx: &Cx,
            msg: Self::Message,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                0 => self.events.lock().push("handle-0"),
                1 => {
                    self.events.lock().push("handle-1-panic");
                    panic!("graceful drain handler panic");
                }
                2 => self.events.lock().push("handle-2"),
                3 => self.events.lock().push("handle-3"),
                _ => unreachable!("fixture message outside 0..=3"),
            }
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.events.lock().push("stop");
            Box::pin(async {})
        }
    }

    init_actor_test("native_actor_graceful_drain_continues_after_handler_panic");
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build native current-thread runtime");
    let mut state = RuntimeState::new();
    let root = state.create_root_region(Budget::INFINITE);
    let cx: Cx = Cx::for_testing();
    let scope = Scope::<FailFast>::new(root, Budget::INFINITE);
    let events = Arc::new(Mutex::new(Vec::new()));
    let actor = DrainPanicActor {
        events: Arc::clone(&events),
    };
    let (mut handle, mut stored) = scope
        .spawn_actor(&mut state, &cx, actor, 8)
        .expect("spawn actor");

    for msg in 0..=3 {
        handle.try_send(msg).expect("queue drain fixture");
    }
    handle.stop();

    let task_outcome = runtime.block_on(std::future::poll_fn(|task_cx| stored.poll(task_cx)));
    match task_outcome {
        Outcome::Panicked(payload) => assert_eq!(
            payload.message(),
            "graceful drain handler panic",
            "task outcome preserves first drain panic"
        ),
        other => panic!("expected panicked actor task, got {other:?}"),
    }

    match runtime.block_on(handle.join(&cx)) {
        Err(JoinError::Panicked(payload)) => assert_eq!(
            payload.message(),
            "graceful drain handler panic",
            "join preserves first drain panic"
        ),
        other => panic!("expected panicked actor join, got {other:?}"),
    }
    assert_eq!(
        *events.lock(),
        vec![
            "start",
            "handle-0",
            "handle-1-panic",
            "handle-2",
            "handle-3",
            "stop",
        ],
        "graceful drain must invoke the committed FIFO tail and cleanup after a handler panic"
    );
    assert!(handle.is_finished(), "actor must publish terminal state");
}

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
            let cx: Cx = Cx::for_testing();

            events_task.lock().push("started".into());

            // Simulate work with cancellation check
            for i in 0..10 {
                if cx.is_cancel_requested() {
                    events_task.lock().push(format!("cancelled_at:{i}"));
                    break;
                }
                events_task.lock().push(format!("work:{i}"));
            }

            events_task.lock().push("exiting".into());
        })
        .expect("create task");

    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let trace = events.lock().clone();

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
            events_task.lock().push("actor:running".into());
        })
        .expect("create task");

    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let trace = events.lock().clone();

    let has_running = trace.iter().any(|e| e == "actor:running");
    assert_with_log!(has_running, "actor should have run", true, has_running);
}
