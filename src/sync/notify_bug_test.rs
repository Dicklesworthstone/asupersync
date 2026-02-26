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

    notify.notify_one();
    notify.notify_waiters();

    let ready1 = matches!(Pin::new(&mut fut1).poll(&mut cx), Poll::Ready(()));
    let ready2 = matches!(Pin::new(&mut fut2).poll(&mut cx), Poll::Ready(()));
    assert!(ready1, "fut1 should be ready");
    assert!(ready2, "fut2 should be ready");

    let mut fut3 = notify.notified();
    let ready3 = matches!(Pin::new(&mut fut3).poll(&mut cx), Poll::Ready(()));

    assert!(
        !ready3,
        "fut3 should NOT be ready, but it got a duplicated wakeup!"
    );
}
