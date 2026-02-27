//! Regression test for writer fairness (no barging) in `RwLock`.

use asupersync::sync::RwLock;
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
fn test_rwlock_barge_bug() {
    let cx = asupersync::cx::Cx::new(
        asupersync::types::RegionId::from_arena(asupersync::util::ArenaIndex::new(0, 0)),
        asupersync::types::TaskId::from_arena(asupersync::util::ArenaIndex::new(0, 0)),
        asupersync::types::Budget::INFINITE,
    );

    let lock = RwLock::new(0);

    // W1 acquires
    let w1 = lock.try_write().unwrap();

    // W2 waits
    let mut w2_fut = Box::pin(lock.write(&cx));
    assert!(poll_once(&mut w2_fut).is_pending());

    // W1 drops, waking W2 and popping it from the queue
    drop(w1);

    // W3 comes in before W2 is polled!
    let mut w3_fut = Box::pin(lock.write(&cx));
    let w3_res = poll_once(&mut w3_fut);

    // W3 SHOULD be pending because W2 is the next in line!
    // If w3_res is Ready, W3 barged!
    assert!(w3_res.is_pending(), "W3 barged and stole the lock from W2!");
}
