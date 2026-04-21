#![allow(clippy::all)]
//! Test for commutativity bug.
use asupersync::sync::Notify;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
fn poll_once<F: Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    Pin::new(fut).poll(&mut cx)
}

#[test]
fn test_notify_commutativity() {
    // Order 1
    let notify1 = Notify::new();
    let mut f1_1 = notify1.notified();
    assert!(poll_once(&mut f1_1).is_pending());

    notify1.notify_waiters();
    notify1.notify_one();

    assert!(poll_once(&mut f1_1).is_ready());
    let mut f1_2 = notify1.notified();
    let order1_yields_token = poll_once(&mut f1_2).is_ready();

    // Order 2
    let notify2 = Notify::new();
    let mut f2_1 = notify2.notified();
    assert!(poll_once(&mut f2_1).is_pending());

    notify2.notify_one();
    notify2.notify_waiters();

    assert!(poll_once(&mut f2_1).is_ready());
    let mut f2_2 = notify2.notified();
    let order2_yields_token = poll_once(&mut f2_2).is_ready();

    assert_ne!(
        order1_yields_token, order2_yields_token,
        "notify_one and notify_waiters inherently do not commute"
    );
}
