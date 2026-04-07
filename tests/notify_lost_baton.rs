//! Regression test for Notify baton handoff after mixed single/broadcast wakeups.

use asupersync::sync::Notify;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

struct NoopWaker;
impl std::task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}
fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}
fn poll_once<F: Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(fut).poll(&mut cx)
}

#[test]
fn notify_one_lost_if_polled_after_broadcast() {
    let notify = Notify::new();

    let mut waiter_a = notify.notified();
    let mut waiter_b = notify.notified();

    assert_eq!(poll_once(&mut waiter_a), Poll::Pending);
    assert_eq!(poll_once(&mut waiter_b), Poll::Pending);

    // notify_one wakes A
    notify.notify_one();

    // broadcast wakes B
    notify.notify_waiters();

    // C starts waiting
    let mut waiter_c = notify.notified();
    assert_eq!(poll_once(&mut waiter_c), Poll::Pending);

    // A is dropped (cancelled)! It must pass the baton to C!
    drop(waiter_a);

    // Now C should be ready because A passed the baton to it.
    assert_eq!(poll_once(&mut waiter_c), Poll::Ready(()), "Baton was lost!");
}
