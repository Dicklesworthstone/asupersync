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

#[test]
fn distributed_snapshot_close_isolates_waiter_wake_and_drop_panics() {
    for (panic_wake, panic_drop) in [(true, false), (false, true)] {
        let (region, counts, heap_drops) = closing_region(panic_wake, panic_drop);
        let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            region.apply_distributed_snapshot(
                RegionState::Closed,
                Budget::INFINITE,
                Vec::new(),
                Vec::new(),
                None,
            );
        }));
        let completed = applied.is_ok();
        // Keep a regression failure from running the hostile panic payload's
        // destructor in the test harness while reporting the escaped panic.
        if let Err(payload) = applied {
            std::mem::forget(payload);
        }
        assert!(completed, "snapshot close must contain each waiter panic");
        assert_eq!(region.state(), RegionState::Closed);
        assert_eq!(heap_drops.load(Ordering::SeqCst), 1);
        assert!(region.close_notify.lock().closed);
        assert_eq!(counts.wakes.load(Ordering::SeqCst), 2);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 2);
        assert_eq!(counts.panic_payload_drops.load(Ordering::SeqCst), 0);
    }
}

struct SnapshotCloseProbe {
    region: Weak<RegionRecord>,
    heap_drops: Arc<AtomicUsize>,
    observations: Arc<Counts>,
}

impl SnapshotCloseProbe {
    fn observes_closed_without_locks(&self) -> bool {
        let Some(region) = self.region.upgrade() else {
            return false;
        };
        // Record success instead of asserting inside a callback whose panic is
        // deliberately contained. Both callbacks must observe released locks.
        let inner_unlocked = region.inner.try_write().is_some();
        let notify_ready = region
            .close_notify
            .try_lock()
            .is_some_and(|notify| notify.closed && notify.waiters.is_empty());
        inner_unlocked
            && notify_ready
            && region.state() == RegionState::Closed
            && self.heap_drops.load(Ordering::SeqCst) == 1
    }
}

impl Wake for SnapshotCloseProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.observes_closed_without_locks() {
            self.observations.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl Drop for SnapshotCloseProbe {
    fn drop(&mut self) {
        if self.observes_closed_without_locks() {
            self.observations.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[test]
fn distributed_snapshot_close_notifies_after_cleanup_and_only_once() {
    let region = Arc::new(RegionRecord::new(
        RegionId::new_for_test(0, 1),
        None,
        Budget::INFINITE,
    ));
    let heap_drops = Arc::new(AtomicUsize::new(0));
    region
        .heap_alloc(HeapDrop(Arc::clone(&heap_drops)))
        .unwrap();
    let observations = Arc::new(Counts::default());
    region
        .close_notify
        .lock()
        .waiters
        .push(Waker::from(Arc::new(SnapshotCloseProbe {
            region: Arc::downgrade(&region),
            heap_drops: Arc::clone(&heap_drops),
            observations: Arc::clone(&observations),
        })));

    region.apply_distributed_snapshot(
        RegionState::Closing,
        Budget::INFINITE,
        Vec::new(),
        Vec::new(),
        None,
    );
    assert_eq!(heap_drops.load(Ordering::SeqCst), 0);
    assert_eq!(observations.wakes.load(Ordering::SeqCst), 0);
    assert_eq!(observations.drops.load(Ordering::SeqCst), 0);
    assert!(!region.close_notify.lock().closed);

    for _ in 0..2 {
        region.apply_distributed_snapshot(
            RegionState::Closed,
            Budget::INFINITE,
            Vec::new(),
            Vec::new(),
            None,
        );
        assert_eq!(heap_drops.load(Ordering::SeqCst), 1);
        assert_eq!(observations.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(observations.drops.load(Ordering::SeqCst), 1);
        let notify = region.close_notify.lock();
        assert!(notify.closed);
        assert!(notify.waiters.is_empty());
    }
}
