#![allow(clippy::all)]
//! Regression test for lost wakeups in the mutex waiter baton-passing path.

use asupersync::cx::Cx;
use asupersync::sync::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

fn noop_waker() -> Waker {
    std::task::Waker::noop().clone()
}

fn poll_once<T, F>(future: &mut F) -> Option<T>
where
    F: Future<Output = T> + Unpin,
{
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    match Pin::new(future).poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

#[test]
fn mutex_waiter_chain_does_not_lose_wakeup() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(0u32);

    // Hold lock
    let mut fut_hold = mutex.lock(&cx);
    let guard = poll_once(&mut fut_hold).unwrap().unwrap();

    // Queue W1, W2, W3
    let mut fut1 = mutex.lock(&cx);
    let _ = poll_once(&mut fut1);

    let mut fut2 = mutex.lock(&cx);
    let _ = poll_once(&mut fut2);

    let mut fut3 = mutex.lock(&cx);
    let _ = poll_once(&mut fut3);

    assert_eq!(mutex.waiters(), 3);

    // Unlock wakes W1 and pops it from the queue
    drop(guard);

    assert_eq!(mutex.waiters(), 2);

    // W1 drops, it is no longer in the queue but it passes baton to W2
    drop(fut1);

    assert_eq!(mutex.waiters(), 2);

    // W2 drops. Removes itself. Regression target: baton must continue to W3.
    drop(fut2);

    assert_eq!(mutex.waiters(), 1);

    // Now W3 polls. It should acquire the lock since lock is free!
    let res = poll_once(&mut fut3);
    assert!(
        res.is_some(),
        "lost wakeup: W3 stayed pending with free lock"
    );
}
