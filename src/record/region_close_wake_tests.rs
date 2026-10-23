//! Functional close notifications retain quiescence and isolate foreign callbacks.
use super::*;
use std::sync::atomic::AtomicUsize;
use std::task::{Wake, Waker};

#[derive(Default)]
struct Counts {
    wakes: AtomicUsize,
    drops: AtomicUsize,
    panic_payload_drops: AtomicUsize,
}

struct PayloadBomb(Arc<Counts>);

impl Drop for PayloadBomb {
    fn drop(&mut self) {
        self.0.panic_payload_drops.fetch_add(1, Ordering::SeqCst);
        panic!("a caught panic payload must not be destroyed");
    }
}

struct Waiter {
    counts: Arc<Counts>,
    panic_wake: bool,
    panic_drop: bool,
}

impl Wake for Waiter {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.counts.wakes.fetch_add(1, Ordering::SeqCst);
        if self.panic_wake {
            std::panic::panic_any(PayloadBomb(Arc::clone(&self.counts)));
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.counts.drops.fetch_add(1, Ordering::SeqCst);
        if self.panic_drop {
            std::panic::panic_any(PayloadBomb(Arc::clone(&self.counts)));
        }
    }
}

struct HeapDrop(Arc<AtomicUsize>);

impl Drop for HeapDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn closing_region(
    panic_wake: bool,
    panic_drop: bool,
) -> (RegionRecord, Arc<Counts>, Arc<AtomicUsize>) {
    let region = RegionRecord::new(RegionId::new_for_test(0, 1), None, Budget::INFINITE);
    let heap_drops = Arc::new(AtomicUsize::new(0));
    region
        .heap_alloc(HeapDrop(Arc::clone(&heap_drops)))
        .unwrap();
    let counts = Arc::new(Counts::default());
    let first = Waker::from(Arc::new(Waiter {
        counts: Arc::clone(&counts),
        panic_wake,
        panic_drop,
    }));
    let healthy = Waker::from(Arc::new(Waiter {
        counts: Arc::clone(&counts),
        panic_wake: false,
        panic_drop: false,
    }));
    region.close_notify.lock().waiters.extend([first, healthy]);
    assert!(region.begin_close(None));
    assert!(region.begin_finalize());
    (region, counts, heap_drops)
}

#[test]
fn deferred_close_notifications_follow_heap_cleanup_and_published_receipt() {
    for (panic_wake, panic_drop) in [(false, false), (true, false), (false, true)] {
        let (region, counts, heap_drops) = closing_region(panic_wake, panic_drop);
        let wakes = region.complete_close_deferred_wakes().unwrap();
        assert_eq!(region.state(), RegionState::Closed);
        assert_eq!(heap_drops.load(Ordering::SeqCst), 1);
        assert!(region.close_receipt_handle().lock().is_some());
        assert!(region.close_notify.lock().closed);
        assert_eq!(counts.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 0);
        assert!(region.complete_close_deferred_wakes().is_none());
        wakes.dispatch();
        assert_eq!(counts.wakes.load(Ordering::SeqCst), 2);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 2);
        assert_eq!(counts.panic_payload_drops.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn direct_complete_close_still_finishes_notifications_synchronously() {
    let (region, counts, heap_drops) = closing_region(true, false);
    assert!(region.complete_close());
    assert_eq!(heap_drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.wakes.load(Ordering::SeqCst), 2);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 2);
    assert!(!region.complete_close());
    assert_eq!(counts.wakes.load(Ordering::SeqCst), 2);
    assert_eq!(counts.panic_payload_drops.load(Ordering::SeqCst), 0);
}

#[test]
fn abandoned_close_notifications_do_not_run_waker_destructors() {
    let (region, counts, heap_drops) = closing_region(false, true);
    let wakes = region.complete_close_deferred_wakes().unwrap();
    // An outer lock may still be held when its caller abandons the token.
    // The explicit fail-closed policy intentionally leaks opaque handles.
    let lock = std::sync::Mutex::new(());
    let _guard = lock.lock().unwrap();
    drop(wakes);
    assert_eq!(heap_drops.load(Ordering::SeqCst), 1);
    assert!(region.close_receipt_handle().lock().is_some());
    assert_eq!(counts.wakes.load(Ordering::SeqCst), 0);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 0);
    assert_eq!(counts.panic_payload_drops.load(Ordering::SeqCst), 0);
}
