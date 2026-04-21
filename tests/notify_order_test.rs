#![allow(warnings)]
#![allow(clippy::all)]
//! Test for notify ordering.

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
fn test_order_1_waiters_then_one() {
    let notify = Notify::new();
    let mut f1 = notify.notified();
    assert!(poll_once(&mut f1).is_pending());

    notify.notify_waiters();
    notify.notify_one();

    assert!(poll_once(&mut f1).is_ready());

    let mut f2 = notify.notified();
    assert!(poll_once(&mut f2).is_ready(), "Order 1 lost token");
}

#[test]
fn test_order_2_one_then_waiters() {
    let notify = Notify::new();
    let mut f1 = notify.notified();
    assert!(poll_once(&mut f1).is_pending());

    notify.notify_one();
    notify.notify_waiters();

    assert!(poll_once(&mut f1).is_ready());

    let mut f2 = notify.notified();
    assert!(
        poll_once(&mut f2).is_pending(),
        "Order 2 should NOT have a token (not commutative)"
    );
}
