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
fn notify_one_lost_if_dropped_after_waiters() {
    let notify = Notify::new();
    let mut fut1 = notify.notified();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // fut1 registers
    let _ = Pin::new(&mut fut1).poll(&mut cx);

    // notify_one selects fut1
    notify.notify_one();

    // notify_waiters increments generation
    notify.notify_waiters();

    // fut1 is dropped (cancelled) before consuming!
    drop(fut1);

    // Because fut1 was cancelled, the notify_one token should be baton-passed
    // or re-stored.
    let mut fut2 = notify.notified();
    let ready2 = matches!(Pin::new(&mut fut2).poll(&mut cx), Poll::Ready(()));

    assert!(
        ready2,
        "fut2 should be ready because fut1 was cancelled and should have baton-passed the notify_one token"
    );
}
