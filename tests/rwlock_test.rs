//! Targeted rwlock fairness reproduction test.

use asupersync::cx::Cx;
use asupersync::sync::RwLock;
use std::future::Future;
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

#[test]
fn test_rwlock_writer_turn_stolen_by_readers_when_queued_writer_drops() {
    let cx = Cx::new(
        asupersync::types::RegionId::from_arena(asupersync::util::ArenaIndex::new(0, 0)),
        asupersync::types::TaskId::from_arena(asupersync::util::ArenaIndex::new(0, 0)),
        asupersync::types::Budget::INFINITE,
    );
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

    let d_ready = std::pin::Pin::new(&mut fut_d).poll(&mut poll_cx).is_ready();
    println!("D ready? {d_ready}");
}
