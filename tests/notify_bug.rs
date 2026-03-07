//!
//! Notify bug test.
//!
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

fn main() {
    let notify = Notify::new();

    // fut1 created BEFORE broadcast
    let mut fut1 = notify.notified();

    // notify_one adds a stored notification
    notify.notify_one();

    // notify_waiters bumps generation
    notify.notify_waiters();

    // fut2 created AFTER broadcast
    let mut fut2 = notify.notified();

    // fut1 polls. It should complete using the broadcast generation,
    // LEAVING the stored notification intact!
    assert_eq!(poll_once(&mut fut1), Poll::Ready(()));

    // fut2 polls. Since the stored notification was left intact, it should complete!
    assert_eq!(
        poll_once(&mut fut2),
        Poll::Ready(()),
        "lost wakeup! fut1 consumed the token incorrectly"
    );

    println!("SUCCESS!");
}
