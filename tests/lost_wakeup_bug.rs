//! Regression test for lost wakeups in the mutex waiter baton-passing path.

use asupersync::cx::Cx;
use asupersync::sync::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

fn poll_once<T, F>(future: &mut F) -> Option<T>
where
    F: Future<Output = T> + Unpin,
{
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    match Pin::new(future).poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

#[test]
fn mutex_waiter_baton_chain_reaches_tail_waiter() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(0u32);

    let mut fut_hold = mutex.lock(&cx);
    let guard = poll_once(&mut fut_hold).unwrap().unwrap();

    let mut fut1 = mutex.lock(&cx);
    assert!(poll_once(&mut fut1).is_none());

    let mut fut2 = mutex.lock(&cx);
    assert!(poll_once(&mut fut2).is_none());

    let mut fut3 = mutex.lock(&cx);
    assert!(poll_once(&mut fut3).is_none());

    assert_eq!(mutex.waiters(), 3);

    drop(guard);

    assert_eq!(mutex.waiters(), 2);

    drop(fut1);

    assert_eq!(
        mutex.waiters(),
        1,
        "dropping W1 should pass the baton through W2 and leave only W3 queued"
    );

    drop(fut2);

    assert_eq!(
        mutex.waiters(),
        0,
        "dropping W2 should pass the baton to W3 and remove it from the queue"
    );

    let tail_guard = poll_once(&mut fut3)
        .expect("tail waiter should be woken")
        .expect("tail waiter lock acquisition should succeed");
    assert_eq!(
        *tail_guard, 0,
        "lost wakeup: W3 stayed pending with free lock"
    );
}
