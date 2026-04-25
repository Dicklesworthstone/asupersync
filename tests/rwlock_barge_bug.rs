//! Regression test for writer fairness (no barging) in `RwLock`.

use asupersync::sync::RwLock;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

fn poll_once<F>(fut: &mut F) -> Poll<F::Output>
where
    F: Future + Unpin,
{
    let mut cx = Context::from_waker(std::task::Waker::noop());
    Pin::new(fut).poll(&mut cx)
}

#[test]
fn queued_writer_keeps_turn_when_later_writer_arrives() {
    let cx = asupersync::Cx::for_testing();

    let lock = RwLock::new(0);

    let w1 = lock.try_write().unwrap();

    let mut w2_fut = Box::pin(lock.write(&cx));
    assert!(poll_once(&mut w2_fut).is_pending());

    drop(w1);

    let mut w3_fut = Box::pin(lock.write(&cx));
    assert!(
        poll_once(&mut w3_fut).is_pending(),
        "later writer must not barge ahead of the pre-granted writer"
    );

    let Poll::Ready(Ok(w2_guard)) = poll_once(&mut w2_fut) else {
        panic!("queued writer should acquire before later writer");
    };

    assert!(
        poll_once(&mut w3_fut).is_pending(),
        "later writer must remain queued while earlier writer holds the lock"
    );

    drop(w2_guard);

    let Poll::Ready(Ok(w3_guard)) = poll_once(&mut w3_fut) else {
        panic!("later writer should acquire after earlier writer releases");
    };
    drop(w3_guard);

    assert!(
        lock.try_write().is_ok(),
        "lock should return to writable state after queued writers finish"
    );
}
