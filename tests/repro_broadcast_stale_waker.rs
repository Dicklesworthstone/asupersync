#![allow(missing_docs)]

use asupersync::channel::broadcast;
use asupersync::cx::Cx;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake};

struct FlagWaker(AtomicBool);

impl Wake for FlagWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl FlagWaker {
    fn new() -> Arc<Self> {
        Arc::new(Self(AtomicBool::new(false)))
    }
    fn woken(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn repro_broadcast_stale_waker() {
    let cx = Cx::for_testing();
    let (tx, mut rx) = broadcast::channel::<i32>(10);

    let waker_a = FlagWaker::new();
    let waker_b = FlagWaker::new();

    let mut fut = Box::pin(rx.recv(&cx));

    // 1. Poll with Waker A
    {
        let waker = waker_a.into();
        let mut ctx = Context::from_waker(&waker);
        assert!(matches!(fut.as_mut().poll(&mut ctx), Poll::Pending));
    }

    // 2. Poll with Waker B (simulate task migration or waker rotation)
    {
        let waker = waker_b.clone().into();
        let mut ctx = Context::from_waker(&waker);
        assert!(matches!(fut.as_mut().poll(&mut ctx), Poll::Pending));
    }

    // 3. Send message
    tx.send(&cx, 42).unwrap();

    // 4. Assert Waker B is woken
    assert!(waker_b.woken(), "Waker B should be woken (current waker)");
}
