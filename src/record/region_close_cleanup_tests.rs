//! Closing a region must finish reclamation before publishing its receipt.
use super::*;
use std::sync::atomic::AtomicUsize;
use std::task::{Wake, Waker};

#[derive(Default)]
struct CleanupCounts {
    heap_drops: AtomicUsize,
    panic_payload_drops: AtomicUsize,
    wakes: AtomicUsize,
    wake_saw_cleanup: AtomicBool,
    #[cfg(feature = "tracing-integration")]
    diagnostic_panics: AtomicUsize,
}

struct PanicPayload(Arc<CleanupCounts>);

impl Drop for PanicPayload {
    fn drop(&mut self) {
        self.0.panic_payload_drops.fetch_add(1, Ordering::SeqCst);
        panic!("a caught cleanup panic payload must not be destroyed");
    }
}

struct HeapPayload {
    counts: Arc<CleanupCounts>,
    panic_on_drop: bool,
}

impl Drop for HeapPayload {
    fn drop(&mut self) {
        self.counts.heap_drops.fetch_add(1, Ordering::SeqCst);
        if self.panic_on_drop {
            std::panic::panic_any(PanicPayload(Arc::clone(&self.counts)));
        }
    }
}

struct CloseWaiter {
    counts: Arc<CleanupCounts>,
    receipt: Arc<parking_lot::Mutex<Option<RegionCloseOutcome>>>,
}

impl Wake for CloseWaiter {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.counts.wakes.fetch_add(1, Ordering::SeqCst);
        self.counts.wake_saw_cleanup.store(
            self.counts.heap_drops.load(Ordering::SeqCst) == 3 && self.receipt.lock().is_some(),
            Ordering::SeqCst,
        );
    }
}

fn closing_region(counts: &Arc<CleanupCounts>) -> RegionRecord {
    let region = RegionRecord::new(RegionId::new_for_test(0, 1), None, Budget::INFINITE);
    // The healthy payload comes after both failures: cleanup may not merely
    // contain the first panic and abandon the rest of the heap.
    for panic_on_drop in [true, true, false] {
        region
            .heap_alloc(HeapPayload {
                counts: Arc::clone(counts),
                panic_on_drop,
            })
            .expect("heap admission");
    }
    region
        .close_notify
        .lock()
        .waiters
        .push(Waker::from(Arc::new(CloseWaiter {
            counts: Arc::clone(counts),
            receipt: region.close_receipt_handle(),
        })));
    assert!(region.begin_close(None));
    assert!(region.begin_finalize());
    region
}

fn assert_cleanup_complete(region: &RegionRecord, counts: &CleanupCounts) {
    assert_eq!(region.state(), RegionState::Closed);
    assert_eq!(region.heap_len(), 0);
    assert_eq!(counts.heap_drops.load(Ordering::SeqCst), 3);
    assert_eq!(counts.panic_payload_drops.load(Ordering::SeqCst), 0);
    assert!(region.close_receipt_handle().lock().is_some());
    assert!(region.close_notify.lock().closed);
    assert_eq!(counts.wakes.load(Ordering::SeqCst), 1);
    assert!(counts.wake_saw_cleanup.load(Ordering::SeqCst));
    assert!(
        !region.complete_close(),
        "a closed region is not reclaimed twice"
    );
}

#[test]
fn heap_panic_payloads_cannot_interrupt_direct_or_deferred_close() {
    for deferred in [false, true] {
        let counts = Arc::new(CleanupCounts::default());
        let region = closing_region(&counts);
        if deferred {
            let wakes = region.complete_close_deferred_wakes().expect("close");
            assert_eq!(counts.heap_drops.load(Ordering::SeqCst), 3);
            assert!(region.close_receipt_handle().lock().is_some());
            assert_eq!(counts.wakes.load(Ordering::SeqCst), 0);
            wakes.dispatch();
        } else {
            assert!(region.complete_close());
        }
        assert_cleanup_complete(&region, &counts);
    }
}

struct CloseOnDrop<'a>(&'a RegionRecord);

impl Drop for CloseOnDrop<'_> {
    fn drop(&mut self) {
        assert!(self.0.complete_close());
    }
}

#[test]
fn heap_cleanup_stays_contained_while_its_owner_is_unwinding() {
    let counts = Arc::new(CleanupCounts::default());
    let region = closing_region(&counts);
    let owner_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _close = CloseOnDrop(&region);
        panic!("original owner panic");
    }));
    let payload = owner_panic.expect_err("the original owner panic is preserved");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"original owner panic")
    );
    assert_cleanup_complete(&region, &counts);
}

#[cfg(feature = "tracing-integration")]
mod diagnostics {
    use super::*;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    #[derive(Clone, Copy)]
    enum Fault {
        HeapWarning,
        ClosedEvent,
        ClosedSpanRecord,
    }

    struct PanickingSubscriber {
        fault: Fault,
        armed: Arc<AtomicBool>,
        counts: Arc<CleanupCounts>,
    }

    impl PanickingSubscriber {
        fn fail(&self) {
            self.counts.diagnostic_panics.fetch_add(1, Ordering::SeqCst);
            std::panic::panic_any(PanicPayload(Arc::clone(&self.counts)));
        }
    }

    impl Subscriber for PanickingSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {
            if self.armed.load(Ordering::SeqCst) && matches!(self.fault, Fault::ClosedSpanRecord) {
                self.fail();
            }
        }

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            if !self.armed.load(Ordering::SeqCst) {
                return;
            }
            let level = event.metadata().level();
            if (matches!(self.fault, Fault::HeapWarning) && *level == tracing::Level::WARN)
                || (matches!(self.fault, Fault::ClosedEvent) && *level == tracing::Level::DEBUG)
            {
                self.fail();
            }
        }

        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    fn run_fault(fault: Fault, unwind_owner: bool) {
        let counts = Arc::new(CleanupCounts::default());
        let armed = Arc::new(AtomicBool::new(false));
        tracing::subscriber::with_default(
            PanickingSubscriber {
                fault,
                armed: Arc::clone(&armed),
                counts: Arc::clone(&counts),
            },
            || {
                let region = closing_region(&counts);
                armed.store(true, Ordering::SeqCst);
                if unwind_owner {
                    let original = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _close = CloseOnDrop(&region);
                        panic!("owner panic with diagnostics");
                    }));
                    let payload = original.expect_err("original owner panic");
                    assert_eq!(
                        payload.downcast_ref::<&str>(),
                        Some(&"owner panic with diagnostics")
                    );
                } else {
                    let wakes = region.complete_close_deferred_wakes().expect("close");
                    assert_eq!(counts.wakes.load(Ordering::SeqCst), 0);
                    wakes.dispatch();
                }
                assert_cleanup_complete(&region, &counts);
                assert!(
                    counts.diagnostic_panics.load(Ordering::SeqCst) > 0,
                    "the faulting subscriber must actually be invoked"
                );
            },
        );
    }

    #[test]
    fn warning_subscriber_cannot_interrupt_remaining_heap_drops() {
        run_fault(Fault::HeapWarning, false);
    }

    #[test]
    fn terminal_transition_subscriber_cannot_strand_a_closed_region() {
        run_fault(Fault::ClosedEvent, false);
        run_fault(Fault::ClosedSpanRecord, false);
    }

    #[test]
    fn cleanup_diagnostics_stay_contained_during_owner_unwind() {
        run_fault(Fault::HeapWarning, true);
        run_fault(Fault::ClosedEvent, true);
        run_fault(Fault::ClosedSpanRecord, true);
    }
}
