//! E2E: Messaging pub/sub and queues — broadcast fanout, mpsc queue,
//! watch state propagation, oneshot rendezvous.

mod common;

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
