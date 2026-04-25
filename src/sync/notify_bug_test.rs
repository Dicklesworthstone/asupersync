use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use crate::sync::Notify;

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

    notify.notify_waiters();

    let mut fut2 = notify.notified();
    assert!(poll_once(&mut fut2).is_pending());

    drop(fut1);

    // If fut2 is now ready, it means the drop of a broadcast-woken waiter
    // spuriously woke fut2!
    let is_ready = poll_once(&mut fut2).is_ready();
    assert!(!is_ready, "Spurious wakeup detected!");
}
