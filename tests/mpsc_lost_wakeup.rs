//! Regression coverage for MPSC reserve waiter baton passing.

use asupersync::channel::mpsc::channel;
use asupersync::cx::Cx;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Wake};

struct FlagWaker(Arc<AtomicBool>);
impl Wake for FlagWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[test]
fn pending_reserve_drop_passes_capacity_wakeup_to_next_waiter() {
    let (tx, mut rx) = channel::<i32>(1);
    let cx = Cx::for_testing();

    tx.try_send(1).unwrap();

    let mut r1 = Box::pin(tx.reserve(&cx));
    let mut r2 = Box::pin(tx.reserve(&cx));

    let flag1 = Arc::new(AtomicBool::new(false));
    let waker1 = Arc::new(FlagWaker(flag1.clone())).into();
    let mut ctx1 = Context::from_waker(&waker1);

    let flag2 = Arc::new(AtomicBool::new(false));
    let waker2 = Arc::new(FlagWaker(flag2.clone())).into();
    let mut ctx2 = Context::from_waker(&waker2);

    assert!(r1.as_mut().poll(&mut ctx1).is_pending());
    assert!(r2.as_mut().poll(&mut ctx2).is_pending());

    // Receiver receives the message, freeing 1 capacity.
    // This pops r1 from the queue and wakes it.
    let _ = rx.try_recv().unwrap();
    assert!(flag1.load(Ordering::Relaxed)); // r1 should be woken

    // r1 is dropped (cancelled) BEFORE it polls.
    drop(r1);

    // If r1 passed the baton correctly, r2 should be woken.
    assert!(
        flag2.load(Ordering::Relaxed),
        "r2 should be woken by r1's drop"
    );
}
