#![allow(missing_docs)]

use asupersync::channel::watch::channel;
use asupersync::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::task::{Context, Waker};

struct CountingWaker {
    wakes: AtomicUsize,
}

impl CountingWaker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wakes: AtomicUsize::new(0),
        })
    }
}

impl std::task::Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, AtomicOrdering::AcqRel);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, AtomicOrdering::AcqRel);
    }
}

#[test]
fn test_watch_lost_wakeup() {
    let cx = Cx::for_testing();

    let (tx, mut rx) = channel(0);

    let waker1_arc = CountingWaker::new();
    let waker1 = Waker::from(waker1_arc.clone());
    let mut task_cx1 = Context::from_waker(&waker1);

    {
        let mut fut1 = rx.changed(&cx);
        assert!(Pin::new(&mut fut1).poll(&mut task_cx1).is_pending());
    }

    let waker2_arc = CountingWaker::new();
    let waker2 = Waker::from(waker2_arc.clone());
    let mut task_cx2 = Context::from_waker(&waker2);

    let mut fut2 = rx.changed(&cx);
    assert!(Pin::new(&mut fut2).poll(&mut task_cx2).is_pending());

    tx.send(1).unwrap();

    println!(
        "Waker 1 wakes: {}",
        waker1_arc.wakes.load(AtomicOrdering::Acquire)
    );
    println!(
        "Waker 2 wakes: {}",
        waker2_arc.wakes.load(AtomicOrdering::Acquire)
    );

    assert_eq!(
        waker2_arc.wakes.load(AtomicOrdering::Acquire),
        1,
        "waker 2 was not woken! Lost wakeup!"
    );
}
