use super::*;

#[test]
fn retirement_accounts_once_when_the_task_exits_on_either_side_of_submission() {
    for exit_first in [false, true] {
        let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
        let mut metrics = crate::observability::otel::MetricsSnapshot::new();
        metrics.add_counter("requests", Vec::new(), 1);
        exporter.enqueue_metrics(&metrics).unwrap();
        exporter.enqueue_metrics(&metrics).unwrap();
        {
            let mut state = exporter.export_queue.state.lock();
            state.managed = true;
            state.stats.consumer_active = true;
        }
        let shared = Arc::new(Shared {
            queue: Arc::clone(&exporter.export_queue),
            lifecycle: AtomicU8::new(STARTING),
            outcome: Mutex::new(None),
        });
        let exit = ExitGuard(Arc::clone(&shared));
        if exit_first {
            drop(exit);
            assert_eq!(exporter.queue_stats().retained_batches, 2);
            shared.activate();
        } else {
            shared.activate();
            drop(exit);
        }
        let stats = exporter.queue_stats();
        assert_eq!(stats.failed_batches, 2);
        assert_eq!(stats.retained_batches, 0);
        assert_eq!(stats.retained_bytes, 0);
        assert!(!stats.consumer_active);
        assert!(exporter.enqueue_metrics(&metrics).is_err());
    }
}

#[test]
fn panicking_rejected_factory_does_not_strand_the_consumer_claim() {
    struct PanicOnDrop;
    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("captured clock destructor");
        }
    }

    let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
    let mut metrics = crate::observability::otel::MetricsSnapshot::new();
    metrics.add_counter("requests", Vec::new(), 1);
    exporter.enqueue_metrics(&metrics).unwrap();
    let before = exporter.queue_stats();
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _claim = AdmissionClaim::new(&exporter.export_queue).unwrap();
        let shared = Arc::new(Shared {
            queue: Arc::clone(&exporter.export_queue),
            lifecycle: AtomicU8::new(STARTING),
            outcome: Mutex::new(None),
        });
        let exit = ExitGuard(shared);
        let clock = PanicOnDrop;
        // This is the actual Cx::spawn synchronous refusal path: no gateway,
        // so the captured factory drops before the runtime's panic boundary.
        let _submitted = Cx::for_testing().spawn(move |_| async move {
            let _exit = exit;
            drop(clock);
        });
    }));
    assert!(refused.is_err());
    assert_eq!(exporter.queue_stats(), before);
    let consumer = exporter.export_queue.consumer().unwrap();
    drop(consumer);
    exporter.enqueue_metrics(&metrics).unwrap();
    assert_eq!(exporter.queue_stats().retained_batches, 2);
    assert_eq!(exporter.queue_stats().failed_batches, 0);
}

#[test]
fn explicit_owner_cancellation_wakes_an_actually_parked_empty_consumer() {
    struct WakeCount(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let owner = Cx::for_testing();
    let worker = Cx::for_testing();
    let shared = Shared {
        queue: Arc::new(ExportQueue::default()),
        lifecycle: AtomicU8::new(ACTIVE),
        outcome: Mutex::new(None),
    };
    let wakes = Arc::new(WakeCount(std::sync::atomic::AtomicUsize::new(0)));
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    let mut context = Context::from_waker(&waker);
    let mut running = std::pin::pin!(run(&shared, &worker, &owner, || 1));
    assert!(running.as_mut().poll(&mut context).is_pending());
    assert_eq!(shared.queue.ready.waiter_count(), 1);
    owner.cancel_with(CancelKind::User, Some("cancel parked exporter owner"));
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        running.as_mut().poll(&mut context),
        Poll::Ready(ManagedOtlpOutcome::Cancelled(_)),
    ));
    assert!(!worker.is_cancel_requested());
}
