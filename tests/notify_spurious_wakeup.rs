#![allow(missing_docs)]

use asupersync::sync::Notify;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

fn noop_waker() -> Waker {
    std::task::Waker::noop().clone()
}
fn poll_once<F: Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(fut).poll(&mut cx)
}

#[test]
fn notify_waiters_spurious_wakeup_bug() {
    let notify = Notify::new();
    let mut fut1 = notify.notified();
    assert!(poll_once(&mut fut1).is_pending());

    notify.notify_waiters();

    let mut fut2 = notify.notified();
    assert!(poll_once(&mut fut2).is_pending());

    drop(fut1);

    assert!(
        poll_once(&mut fut2).is_pending(),
        "dropping a broadcast waiter spuriously woke a later waiter"
    );
}

#[test]
fn notify_waiters_does_not_wake_unpolled_future_created_before_broadcast() {
    let notify = Notify::new();

    let mut fut = notify.notified();

    // A future created before the broadcast is not yet waiting until its
    // first poll registers it.
    notify.notify_waiters();

    assert!(
        poll_once(&mut fut).is_pending(),
        "broadcast spuriously woke an unpolled future"
    );
}
