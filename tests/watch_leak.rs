//! Watch channel leak tests.

use asupersync::channel::watch::channel;
use asupersync::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

struct DropCountingWaker {
    drops: Arc<AtomicUsize>,
}

impl std::task::Wake for DropCountingWaker {
    fn wake(self: Arc<Self>) {
        drop(self);
    }
}

impl Drop for DropCountingWaker {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn dropped_pending_changed_future_releases_registered_waker() {
    let cx = Cx::for_testing();
    let (tx, mut rx) = channel(0);

    let drops = Arc::new(AtomicUsize::new(0));

    {
        let waker_arc = Arc::new(DropCountingWaker {
            drops: Arc::clone(&drops),
        });
        let waker = Waker::from(waker_arc);
        let mut task_cx = Context::from_waker(&waker);

        let mut fut = rx.changed(&cx);
        assert!(Pin::new(&mut fut).poll(&mut task_cx).is_pending());
    }

    assert_eq!(
        drops.load(Ordering::Acquire),
        1,
        "dropped pending changed future must remove its registered waker"
    );

    assert!(
        tx.send(1).is_ok(),
        "send should succeed after waiter cleanup"
    );
    let mut task_cx = Context::from_waker(Waker::noop());
    let mut fut = rx.changed(&cx);
    assert!(
        Pin::new(&mut fut).poll(&mut task_cx).is_ready(),
        "receiver should remain usable after pending future cleanup"
    );
}
