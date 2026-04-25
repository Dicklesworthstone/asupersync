//! Regression test for Notify baton handoff after mixed single/broadcast wakeups.

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
fn cancelled_notify_one_waiter_passes_exactly_one_baton_after_broadcast() {
    let notify = Notify::new();

    let mut waiter_a = notify.notified();
    let mut waiter_b = notify.notified();

    assert_eq!(poll_once(&mut waiter_a), Poll::Pending);
    assert_eq!(poll_once(&mut waiter_b), Poll::Pending);

    // notify_one wakes A
    notify.notify_one();

    // broadcast wakes B
    notify.notify_waiters();
    assert_eq!(
        poll_once(&mut waiter_b),
        Poll::Ready(()),
        "broadcast waiter should be ready"
    );

    // C starts waiting
    let mut waiter_c = notify.notified();
    assert_eq!(poll_once(&mut waiter_c), Poll::Pending);

    // A is dropped (cancelled)! It must pass the baton to C!
    drop(waiter_a);

    // Now C should be ready because A passed the baton to it.
    assert_eq!(poll_once(&mut waiter_c), Poll::Ready(()), "baton was lost");

    let mut waiter_d = notify.notified();
    assert_eq!(
        poll_once(&mut waiter_d),
        Poll::Pending,
        "baton handoff should not create an extra stored token"
    );
}
