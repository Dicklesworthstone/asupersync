#![allow(clippy::all)]
#![allow(missing_docs)]
//! Tests for mpsc waker bug — ensures unpolled Recv drop does not clear registered wakers.

use asupersync::channel::mpsc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Waker};

struct TrackWaker(Arc<AtomicBool>);
impl std::task::Wake for TrackWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn test_mpsc_recv_drop_clears_waker_erroneously() {
    let (tx, mut rx) = mpsc::channel::<i32>(10);
    let cx = asupersync::Cx::for_testing();

    let woken = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(TrackWaker(woken.clone())));
    let mut ctx = Context::from_waker(&waker);

    // 1. Manually poll rx to register the waker
    let poll = rx.poll_recv(&cx, &mut ctx);
    assert!(poll.is_pending());

    // 2. Create a Recv future, but DON'T poll it!
    let f = rx.recv(&cx);

    // 3. Drop the Recv future.
    drop(f);

    // 4. Send a message.
    tx.try_send(42).unwrap();

    // 5. If the waker was erroneously cleared by dropping `f` (which was never polled),
    // `wake()` won't be called.
    assert!(
        woken.load(Ordering::SeqCst),
        "Waker was lost due to unpolled Recv drop"
    );
}
