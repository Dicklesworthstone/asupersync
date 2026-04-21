#![allow(missing_docs)]
#![cfg(feature = "test-internals")]
//! Targeted rwlock fairness reproduction test.

use asupersync::cx::Cx;
use asupersync::sync::RwLock;
use asupersync::sync::RwLockError;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn noop_waker() -> Waker {
    Waker::noop().clone()
}

struct CountWaker(Arc<AtomicUsize>);
use std::task::Wake;
impl Wake for CountWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_rwlock_writer_turn_stolen_by_readers_when_queued_writer_drops() {
    let cx = Cx::for_testing();
    let lock = Arc::new(RwLock::new(0_u32));

    let mut fut_a = lock.write(&cx);
    let waker = noop_waker();
    let mut poll_cx = Context::from_waker(&waker);
    let Poll::Ready(Ok(write_guard_a)) = std::pin::Pin::new(&mut fut_a).poll(&mut poll_cx) else {
        panic!("writer A failed")
    };

    let mut fut_b = lock.write(&cx);
    assert!(
        std::pin::Pin::new(&mut fut_b)
            .poll(&mut poll_cx)
            .is_pending()
    );

    let mut fut_c = lock.write(&cx);
    assert!(
        std::pin::Pin::new(&mut fut_c)
            .poll(&mut poll_cx)
            .is_pending()
    );

    let mut fut_d = lock.read(&cx);
    assert!(
        std::pin::Pin::new(&mut fut_d)
            .poll(&mut poll_cx)
            .is_pending()
    );

    drop(write_guard_a);
    drop(fut_c);

    assert!(
        std::pin::Pin::new(&mut fut_d)
            .poll(&mut poll_cx)
            .is_pending(),
        "reader D stole the queued writer turn after writer C dropped"
    );

    assert!(
        matches!(
            std::pin::Pin::new(&mut fut_b).poll(&mut poll_cx),
            Poll::Ready(Ok(_))
        ),
        "writer B should acquire next after writer A releases"
    );
}

#[test]
fn test_rwlock_writer_panic_wakes_all_waiters_without_pregranting_slots() {
    let cx = Cx::for_testing();
    let lock = Arc::new(RwLock::new(0_u32));

    let mut active_writer = lock.write(&cx);
    let noop = noop_waker();
    let mut noop_cx = Context::from_waker(&noop);
    let Poll::Ready(Ok(active_guard)) = std::pin::Pin::new(&mut active_writer).poll(&mut noop_cx)
    else {
        panic!("active writer failed")
    };

    let writer_wake_count = Arc::new(AtomicUsize::new(0));
    let writer_waker = Waker::from(Arc::new(CountWaker(writer_wake_count.clone())));
    let mut writer_poll_cx = Context::from_waker(&writer_waker);
    let mut queued_writer = lock.write(&cx);
    assert!(
        std::pin::Pin::new(&mut queued_writer)
            .poll(&mut writer_poll_cx)
            .is_pending()
    );

    let reader_wake_count = Arc::new(AtomicUsize::new(0));
    let reader_waker = Waker::from(Arc::new(CountWaker(reader_wake_count.clone())));
    let mut reader_poll_cx = Context::from_waker(&reader_waker);
    let mut queued_reader = lock.read(&cx);
    assert!(
        std::pin::Pin::new(&mut queued_reader)
            .poll(&mut reader_poll_cx)
            .is_pending()
    );

    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = active_guard;
        panic!("poison rwlock");
    }));
    assert!(panic_result.is_err(), "writer panic should poison the lock");

    let writer_woken = writer_wake_count.load(Ordering::SeqCst) > 0;
    let reader_woken = reader_wake_count.load(Ordering::SeqCst) > 0;
    assert!(writer_woken, "queued writer was not woken on poison");
    assert!(reader_woken, "queued reader was not woken on poison");

    let writer_result = std::pin::Pin::new(&mut queued_writer).poll(&mut writer_poll_cx);
    assert!(
        matches!(writer_result, Poll::Ready(Err(RwLockError::Poisoned))),
        "queued writer should fail closed with poison"
    );

    let reader_result = std::pin::Pin::new(&mut queued_reader).poll(&mut reader_poll_cx);
    assert!(
        matches!(reader_result, Poll::Ready(Err(RwLockError::Poisoned))),
        "queued reader should fail closed with poison"
    );
}
