//! `watch::Receiver::wait_for`: waits until the value satisfies a predicate,
//! returning the accepted value borrowed and marked seen. An already-matching
//! value returns at once; values published from another task are checked as
//! they arrive; a sender dropped before any match reports `Closed`; and a
//! cancelled wait leaves the receiver as it was.

use asupersync::channel::watch;
use asupersync::cx::Cx;
use asupersync::runtime::{RuntimeBuilder, yield_now};

#[test]
fn wait_for_returns_the_first_matching_value() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let cx = Cx::current().expect("runtime Cx");
        let (tx, mut rx) = watch::channel(0_u32);

        // Already satisfied: no change is needed.
        assert_eq!(
            *rx.wait_for(&cx, |value| *value == 0).await.expect("now"),
            0
        );
        assert!(!rx.has_changed());

        // Satisfied later, by values sent from another task.
        let sender = handle.spawn(async move {
            for value in 1..=5 {
                for _ in 0..5 {
                    yield_now().await;
                }
                tx.send(value).expect("send");
            }
            tx
        });
        let seen = *rx.wait_for(&cx, |value| *value >= 3).await.expect("three");
        assert!(seen >= 3, "{seen}");
        assert!(!rx.has_changed() || *rx.borrow() > seen);
        let tx = sender.await;

        // The sender goes away without ever matching.
        drop(tx);
        assert_eq!(
            rx.wait_for(&cx, |value| *value == 99).await.err(),
            Some(watch::RecvError::Closed)
        );
        // A value that matches is still returned after the sender is gone.
        assert_eq!(
            *rx.wait_for(&cx, |value| *value == 5).await.expect("five"),
            5
        );
    });
}

#[test]
fn a_cancelled_wait_leaves_the_receiver_unchanged() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("runtime Cx");
        let (tx, mut rx) = watch::channel("idle");
        tx.send("busy").expect("send");
        let version = rx.seen_version();
        {
            let wait = rx.wait_for(&cx, |state| *state == "ready");
            let mut wait = std::pin::pin!(wait);
            let waker = std::task::Waker::noop();
            let mut context = std::task::Context::from_waker(waker);
            assert!(std::future::Future::poll(wait.as_mut(), &mut context).is_pending());
        }
        assert_eq!(
            rx.seen_version(),
            version,
            "dropping the wait marks nothing"
        );
        assert!(rx.has_changed());

        tx.send("ready").expect("send");
        assert_eq!(
            *rx.wait_for(&cx, |state| *state == "ready")
                .await
                .expect("ready"),
            "ready"
        );
        assert!(!rx.has_changed());
    });
}
