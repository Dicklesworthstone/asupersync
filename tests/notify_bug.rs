//! Regression test for notify spurious wakeup detection.

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
fn dropping_broadcast_woken_waiter_does_not_wake_late_waiter() {
    let notify = Notify::new();
    let mut fut1 = notify.notified();
    assert!(poll_once(&mut fut1).is_pending());
    assert_eq!(notify.waiter_count(), 1);

    notify.notify_waiters();
    assert_eq!(
        notify.waiter_count(),
        0,
        "broadcast should mark the original waiter inactive"
    );

    let mut fut2 = notify.notified();
    assert!(poll_once(&mut fut2).is_pending());
    assert_eq!(notify.waiter_count(), 1);

    drop(fut1);
    assert_eq!(
        notify.waiter_count(),
        1,
        "dropping a broadcast-woken waiter must not remove a late waiter"
    );

    assert!(
        poll_once(&mut fut2).is_pending(),
        "dropping a broadcast-woken waiter must not spuriously wake a late waiter"
    );
}
