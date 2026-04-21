#![allow(clippy::all)]
#![allow(missing_docs)]
//! Watch channel leak tests.

use asupersync::channel::watch::channel;
use asupersync::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

struct DummyWaker {
    count: Arc<AtomicUsize>,
}

impl std::task::Wake for DummyWaker {
    fn wake(self: Arc<Self>) {
        // no-op
    }
}

impl Drop for DummyWaker {
    fn drop(&mut self) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_watch_waker_leak() {
    let cx = Cx::for_testing();
    let (_tx, mut rx) = channel(0);

    let drop_count = Arc::new(AtomicUsize::new(0));

    {
        let waker_arc = Arc::new(DummyWaker {
            count: drop_count.clone(),
        });
        let waker = Waker::from(waker_arc);
        let mut task_cx = Context::from_waker(&waker);

        let mut fut = rx.changed(&cx);
        assert!(Pin::new(&mut fut).poll(&mut task_cx).is_pending());
    } // fut is dropped here

    // Waker should be dropped when fut is dropped!
    assert_eq!(drop_count.load(Ordering::SeqCst), 1, "Waker leaked!");
}
