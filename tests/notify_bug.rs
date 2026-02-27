//! Regression test for notify cancellation safety token behavior.

use asupersync::sync::Notify;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

struct NoopWaker;
impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Arc::new(NoopWaker).into()
}

fn poll_once<F>(fut: &mut F) -> Poll<F::Output>
where
    F: Future + Unpin,
{
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(fut).poll(&mut cx)
}

#[test]
fn test_notify_cancel_safety_bug() {
    // Scenario 1: we poll fut1
    let notify = Notify::new();
    let mut fut1 = notify.notified();
    assert!(poll_once(&mut fut1).is_pending()); // registers fut1

    notify.notify_one(); // sets notified=true for fut1
    notify.notify_waiters(); // generation=1

    assert!(poll_once(&mut fut1).is_ready());
    let mut fut2 = notify.notified();
    let left_token_polled = poll_once(&mut fut2).is_ready();

    // Scenario 2: we drop fut1 instead of polling it
    let notify2 = Notify::new();
    let mut fut1_2 = notify2.notified();
    assert!(poll_once(&mut fut1_2).is_pending());
    notify2.notify_one();
    notify2.notify_waiters();
    drop(fut1_2); // Drops instead of polling

    let mut fut2_2 = notify2.notified();
    let left_token_dropped = poll_once(&mut fut2_2).is_ready();

    // Polling consumes the token, dropping passes the baton
    assert_eq!(left_token_polled, false, "Polling to completion should consume the token");
    assert_eq!(left_token_dropped, true, "Dropping a notified future must pass the baton to prevent lost wakeups");
}
