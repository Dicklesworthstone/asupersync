use crate::sync::Notify;
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

#[test]
fn notify_one_and_waiters_duplicate_wakeup_bug() {
    let notify = Notify::new();
    let mut fut1 = notify.notified();
    let mut fut2 = notify.notified();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let _ = Pin::new(&mut fut1).poll(&mut cx);
    let _ = Pin::new(&mut fut2).poll(&mut cx);

    // notify_one targets the first waiter.
    notify.notify_one();

    // notify_waiters increments generation.
    notify.notify_waiters();

    // Now poll fut1. It will see generation changed, call remove_and_baton_pass,
    // which will baton-pass the notify_one to fut2! But fut1 ALSO completes.
    let ready1 = matches!(Pin::new(&mut fut1).poll(&mut cx), Poll::Ready(()));
    assert!(ready1, "fut1 should be ready");

    // Check if fut2 is ALSO ready due to baton pass?
    // Wait, notify_waiters woke fut2 anyway!
    // Let's check stored_notifications instead.

    // Let's add a third future AFTER notify_waiters.
    let mut fut3 = notify.notified();
    let ready3 = matches!(Pin::new(&mut fut3).poll(&mut cx), Poll::Ready(()));

    assert!(
        !ready3,
        "fut3 should NOT be ready, but it got a duplicated wakeup!"
    );
}
