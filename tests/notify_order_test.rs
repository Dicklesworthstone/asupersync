//! Regression tests for Notify operation ordering.

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
fn broadcast_then_notify_one_wakes_waiter_and_stores_one_late_token() {
    let notify = Notify::new();
    let mut f1 = notify.notified();
    assert_eq!(poll_once(&mut f1), Poll::Pending);
    assert_eq!(notify.waiter_count(), 1);

    notify.notify_waiters();
    assert_eq!(notify.waiter_count(), 0);

    notify.notify_one();
    assert_eq!(notify.waiter_count(), 0);

    assert_eq!(poll_once(&mut f1), Poll::Ready(()));

    let mut f2 = notify.notified();
    assert_eq!(
        poll_once(&mut f2),
        Poll::Ready(()),
        "notify_one after broadcast should store one token for a late waiter"
    );

    let mut f3 = notify.notified();
    assert_eq!(
        poll_once(&mut f3),
        Poll::Pending,
        "only one late token should be stored"
    );
}

#[test]
fn notify_one_then_broadcast_does_not_store_late_token() {
    let notify = Notify::new();
    let mut f1 = notify.notified();
    assert_eq!(poll_once(&mut f1), Poll::Pending);
    assert_eq!(notify.waiter_count(), 1);

    notify.notify_one();
    assert_eq!(notify.waiter_count(), 0);

    notify.notify_waiters();
    assert_eq!(notify.waiter_count(), 0);

    assert_eq!(poll_once(&mut f1), Poll::Ready(()));

    let mut f2 = notify.notified();
    assert_eq!(
        poll_once(&mut f2),
        Poll::Pending,
        "broadcast after notify_one should not create a token for a late waiter"
    );
    assert_eq!(notify.waiter_count(), 1);
}
