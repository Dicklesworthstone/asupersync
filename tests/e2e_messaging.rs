//! E2E: Messaging pub/sub and queues — broadcast fanout, mpsc queue,
//! watch state propagation, oneshot rendezvous.

mod common;

use asupersync::channel::mpsc;
use asupersync::channel::session::tracked_channel;
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, CancelReason};
use parking_lot::Mutex;
use std::sync::Arc;

// =========================================================================
// MPSC Queue: exactly-once delivery
// =========================================================================

#[test]
fn e2e_mpsc_queue_delivery() {
    common::init_test_logging();
    common::run_test_with_cx(|cx| async move {
        test_phase!("MPSC Queue");

        let (tx, rx) = asupersync::channel::mpsc::channel::<i32>(10);

        test_section!("Send messages");
        for i in 0..5 {
            let permit = tx.reserve(&cx).await.unwrap();
            permit.send(i);
        }

        test_section!("Receive messages in order");
        for expected in 0..5 {
            let val = rx.recv(&cx).await.unwrap();
            assert_eq!(val, expected);
        }

        test_section!("Drop sender -> receiver gets disconnect");
        drop(tx);
        let result = rx.recv(&cx).await;
        assert!(result.is_err());

        test_complete!("e2e_mpsc_queue", messages = 5);
    });
}

// =========================================================================
// Broadcast: fan-out to multiple subscribers
// =========================================================================

#[test]
fn e2e_broadcast_fanout() {
    common::init_test_logging();
    common::run_test_with_cx(|cx| async move {
        test_phase!("Broadcast Fan-Out");

        let (tx, mut rx1) = asupersync::channel::broadcast::channel::<String>(16);
        let mut rx2 = tx.subscribe();
        let mut rx3 = tx.subscribe();

        test_section!("Publish messages");
        for i in 0..3 {
            tx.send(&cx, format!("msg-{i}")).unwrap();
        }

        test_section!("All subscribers receive all messages");
        for rx in [&mut rx1, &mut rx2, &mut rx3] {
            for i in 0..3 {
                let msg = rx.recv(&cx).await.unwrap();
                assert_eq!(msg, format!("msg-{i}"));
            }
        }

        test_complete!("e2e_broadcast_fanout", subscribers = 3, messages = 3);
    });
}

// =========================================================================
// Watch: state propagation (latest value only)
// =========================================================================

#[test]
fn e2e_watch_state_propagation() {
    common::init_test_logging();
    test_phase!("Watch State Propagation");

    let (tx, rx) = asupersync::channel::watch::channel::<String>("initial".to_string());

    test_section!("Read initial value");
    let val = rx.borrow_and_clone();
    assert_eq!(val, "initial");

    test_section!("Update value");
    tx.send("updated".to_string()).unwrap();
    let val = rx.borrow_and_clone();
    assert_eq!(val, "updated");

    test_section!("Multiple rapid updates - only latest visible");
    tx.send("v1".to_string()).unwrap();
    tx.send("v2".to_string()).unwrap();
    tx.send("v3".to_string()).unwrap();
    let val = rx.borrow_and_clone();
    assert_eq!(val, "v3");

    test_complete!("e2e_watch_state");
}

// =========================================================================
// Oneshot: single-use rendezvous
// =========================================================================

#[test]
fn e2e_oneshot_rendezvous() {
    common::init_test_logging();
    common::run_test_with_cx(|cx| async move {
        test_phase!("Oneshot Rendezvous");

        let (tx, rx) = asupersync::channel::oneshot::channel::<i32>();

        test_section!("Send single value");
        tx.send(&cx, 42).unwrap();

        test_section!("Receive single value");
        let val = rx.recv(&cx).await.unwrap();
        assert_eq!(val, 42);

        test_complete!("e2e_oneshot", value = 42);
    });
}

// =========================================================================
// MPSC backpressure: channel full blocks sender
// =========================================================================

#[test]
fn e2e_mpsc_backpressure() {
    common::init_test_logging();
    common::run_test_with_cx(|cx| async move {
        test_phase!("MPSC Backpressure");

        let (tx, rx) = asupersync::channel::mpsc::channel::<i32>(2);

        test_section!("Fill channel to capacity");
        let p1 = tx.reserve(&cx).await.unwrap();
        p1.send(1);
        let p2 = tx.reserve(&cx).await.unwrap();
        p2.send(2);

        test_section!("Drain one to make space");
        let val = rx.recv(&cx).await.unwrap();
        assert_eq!(val, 1);

        // Now there's space
        let p3 = tx.reserve(&cx).await.unwrap();
        p3.send(3);

        let val = rx.recv(&cx).await.unwrap();
        assert_eq!(val, 2);
        let val = rx.recv(&cx).await.unwrap();
        assert_eq!(val, 3);

        test_complete!("e2e_mpsc_backpressure");
    });
}

// =========================================================================
// Broadcast: unsubscribe mid-stream
// =========================================================================

#[test]
fn e2e_broadcast_unsubscribe() {
    common::init_test_logging();
    common::run_test_with_cx(|cx| async move {
        test_phase!("Broadcast Unsubscribe");

        let (tx, mut rx1) = asupersync::channel::broadcast::channel::<i32>(16);
        let rx2 = tx.subscribe();

        test_section!("Send before unsubscribe");
        tx.send(&cx, 1).unwrap();

        test_section!("Drop rx2 (unsubscribe)");
        drop(rx2);

        test_section!("Send after unsubscribe");
        tx.send(&cx, 2).unwrap();

        // rx1 still receives both
        let v1 = rx1.recv(&cx).await.unwrap();
        let v2 = rx1.recv(&cx).await.unwrap();
        assert_eq!(v1, 1);
        assert_eq!(v2, 2);

        test_complete!("e2e_broadcast_unsubscribe");
    });
}

// =========================================================================
// Tracked MPSC (obligation tokens) — Lab E2E
// =========================================================================

#[test]
fn e2e_tracked_mpsc_commit_with_lab_replay() {
    common::init_test_logging();
    test_phase!("Tracked MPSC Commit (Lab)");

    let seed = 0x00C0_FFEE_u64;
    let mut runtime = LabRuntime::new(
        LabConfig::new(seed)
            .with_default_replay_recording()
            .trace_capacity(16 * 1024),
    );
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (tx, rx) = tracked_channel::<u64>(2);
    let received = Arc::new(Mutex::new(Vec::new()));
    let recv_store = Arc::clone(&received);

    test_section!("spawn_receiver");
    let (recv_task, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            let value = rx.recv(&cx).await.expect("recv");
            recv_store.lock().push(value);
        })
        .expect("create recv task");
    runtime.scheduler.lock().schedule(recv_task, 0);

    test_section!("spawn_sender");
    let (send_task, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            let permit = tx.reserve(&cx).await.expect("reserve");
            let proof = permit.send(42);
            tracing::info!(proof_kind = ?proof.kind(), "tracked permit committed");
        })
        .expect("create send task");
    runtime.scheduler.lock().schedule(send_task, 0);

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let guard = received.lock();
    assert_eq!(&*guard, &[42]);
    drop(guard);
    assert!(runtime.is_quiescent(), "runtime should be quiescent");
    let trace = runtime.finish_replay_trace();
    assert!(trace.is_some(), "replay trace should be captured");

    test_complete!("e2e_tracked_mpsc_commit_with_lab_replay", messages = 1);
}

#[test]
fn e2e_tracked_mpsc_abort_with_lab_replay() {
    common::init_test_logging();
    test_phase!("Tracked MPSC Abort (Lab)");

    let seed = 0x000A_11CE_u64;
    let mut runtime = LabRuntime::new(
        LabConfig::new(seed)
            .with_default_replay_recording()
            .trace_capacity(16 * 1024),
    );
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (tx, rx) = tracked_channel::<u64>(1);
    let result = Arc::new(Mutex::new(None));
    let recv_result = Arc::clone(&result);

    test_section!("spawn_receiver");
    let (recv_task, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            let recv = rx.recv(&cx).await;
            *recv_result.lock() = Some(recv);
        })
        .expect("create recv task");
    runtime.scheduler.lock().schedule(recv_task, 0);

    test_section!("spawn_sender_abort");
    let (send_task, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            let permit = tx.reserve(&cx).await.expect("reserve");
            let proof = permit.abort();
            tracing::info!(proof_kind = ?proof.kind(), "tracked permit aborted");
        })
        .expect("create send task");
    runtime.scheduler.lock().schedule(send_task, 0);

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let recv = result.lock().take();
    assert!(matches!(recv, Some(Err(mpsc::RecvError::Disconnected))));
    assert!(runtime.is_quiescent(), "runtime should be quiescent");
    let trace = runtime.finish_replay_trace();
    assert!(trace.is_some(), "replay trace should be captured");

    test_complete!("e2e_tracked_mpsc_abort_with_lab_replay");
}

#[test]
fn e2e_tracked_mpsc_cancel_mid_reserve() {
    common::init_test_logging();
    test_phase!("Tracked MPSC Cancel Mid-Reserve (Lab)");

    let seed = 0xCA11_0FFEu64;
    let mut runtime = LabRuntime::new(
        LabConfig::new(seed)
            .with_default_replay_recording()
            .trace_capacity(16 * 1024),
    );
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (tx, _rx) = mpsc::channel::<u64>(1);
    let outcome = Arc::new(Mutex::new(None));
    let outcome_store = Arc::clone(&outcome);

    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let Some(cx) = Cx::current() else {
                return;
            };

            let hold = tx.reserve(&cx).await.expect("reserve initial");
            let result = tx.reserve(&cx).await.map(|permit| {
                permit.abort();
            });

            tracing::info!(result = ?result, "second reserve result after cancel");
            hold.abort();
            *outcome_store.lock() = Some(result);
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    test_section!("block_then_cancel");
    for _ in 0..3 {
        runtime.step_for_test();
    }
    let reason = CancelReason::user("mid-reserve");
    let tasks = runtime.state.cancel_request(root, &reason, None);
    {
        let mut scheduler = runtime.scheduler.lock();
        for (task, priority) in tasks {
            scheduler.schedule_cancel(task, priority);
        }
    }

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let result = outcome.lock().take();
    assert!(matches!(result, Some(Err(mpsc::SendError::Cancelled(())))));
    assert!(runtime.is_quiescent(), "runtime should be quiescent");
    let trace = runtime.finish_replay_trace();
    assert!(trace.is_some(), "replay trace should be captured");

    test_complete!("e2e_tracked_mpsc_cancel_mid_reserve");
}

#[test]
#[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
fn e2e_tracked_mpsc_leak_detection_panics() {
    common::init_test_logging();
    test_phase!("Tracked MPSC Leak Detection");

    common::run_test_with_cx(|cx| async move {
        let (tx, _rx) = tracked_channel::<u64>(1);
        let permit = tx.reserve(&cx).await.expect("reserve");
        drop(permit);
    });
}
