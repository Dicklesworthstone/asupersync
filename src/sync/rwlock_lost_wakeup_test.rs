use super::RwLock;
use crate::cx::Cx;
use crate::types::{Budget, RegionId, TaskId};
use crate::util::ArenaIndex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

struct CountWaker(Arc<AtomicUsize>);

impl Wake for CountWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn dropping_blocked_writer_wakes_queued_reader() {
    crate::test_utils::init_test_logging();
    crate::test_phase!("dropping_blocked_writer_wakes_queued_reader");

    let cx = test_cx();
    let lock = RwLock::new(0_u32);

    let wake_count = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
    let mut task_cx = Context::from_waker(&waker);

    let mut first_reader = lock.read(&cx);
    let guard = match Pin::new(&mut first_reader).poll(&mut task_cx) {
        Poll::Ready(Ok(guard)) => guard,
        Poll::Ready(Err(err)) => panic!("expected first reader to acquire immediately: {err:?}"),
        Poll::Pending => panic!("expected first reader to acquire immediately"),
    };

    let mut waiting_writer = lock.write(&cx);
    assert!(
        Pin::new(&mut waiting_writer)
            .poll(&mut task_cx)
            .is_pending()
    );

    let mut queued_reader = lock.read(&cx);
    assert!(Pin::new(&mut queued_reader).poll(&mut task_cx).is_pending());

    wake_count.store(0, Ordering::SeqCst);

    drop(waiting_writer);

    assert!(
        wake_count.load(Ordering::SeqCst) > 0,
        "queued reader should be woken when the blocked writer is dropped"
    );

    // Releasing the active reader should let the queued reader complete.
    drop(guard);

    match Pin::new(&mut queued_reader).poll(&mut task_cx) {
        Poll::Ready(Ok(_second_guard)) => {}
        Poll::Ready(Err(err)) => panic!("queued reader should acquire after wake: {err:?}"),
        Poll::Pending => panic!("queued reader remained pending after wake + reader release"),
    }
}
