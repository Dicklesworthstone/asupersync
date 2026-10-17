    use super::*;
    use crate::cx::CancelWakerToken;
    use crate::observability::otel::MetricsSnapshot;
    use crate::types::CancelKind;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("fixture should complete in one poll"),
        }
    }

    struct Probe {
        calls: Arc<AtomicUsize>,
        fail: bool,
        cancel: bool,
    }

    impl AsyncMetricsExporter for Probe {
        fn export<'a>(
            &'a self,
            cx: &'a Cx,
            batch: MetricsExportBatch<'a>,
        ) -> MetricsExportFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(batch.start_time_unix_nano(), 100);
                assert_eq!(batch.time_unix_nano(), 200);
                if self.cancel {
                    cx.cancel_with(CancelKind::User, Some("fan-out fixture cancellation"));
                }
                if self.fail {
                    Err(ExportError::new("private-backend-error"))
                } else {
                    Ok(())
                }
            })
        }
    }

    fn probe(fail: bool, cancel: bool) -> (Box<dyn AsyncMetricsExporter>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let exporter = Probe {
            calls: Arc::clone(&calls),
            fail,
            cancel,
        };
        (Box::new(exporter), calls)
    }

    fn batch(snapshot: &MetricsSnapshot) -> MetricsExportBatch<'_> {
        MetricsExportBatch::new(snapshot, 100, 200).unwrap()
    }

    #[test]
    fn failure_preserves_indices_and_does_not_suppress_or_retry_other_destinations() {
        let (first, a) = probe(true, false);
        let (second, b) = probe(false, false);
        let (third, c) = probe(true, false);
        let multi = AsyncMultiExporter::try_new(vec![first, second, third]).unwrap();
        let snapshot = MetricsSnapshot::new();
        let report = ready(multi.export_all(&Cx::for_testing(), batch(&snapshot)));
        assert_eq!(report.succeeded(), 1);
        assert_eq!(report.failed(), 2);
        assert_eq!(report.not_attempted(), 0);
        assert!(!report.was_interrupted());
        assert!(matches!(report.outcomes()[0], AsyncExportOutcome::Failed(_)));
        assert!(matches!(report.outcomes()[1], AsyncExportOutcome::Succeeded));
        assert!(matches!(report.outcomes()[2], AsyncExportOutcome::Failed(_)));
        for count in [a, b, c] {
            assert_eq!(count.load(Ordering::SeqCst), 1);
        }
        let error = report.into_result().unwrap_err().to_string();
        assert!(!error.contains("private-backend-error"));
    }

    #[test]
    fn shared_in_memory_and_null_exporters_complete_without_a_background_consumer() {
        let memory = Arc::new(InMemoryExporter::new());
        let multi = AsyncMultiExporter::try_new(vec![
            Box::new(Arc::clone(&memory)),
            Box::new(NullExporter::new()),
        ])
        .unwrap();
        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter("requests", Vec::new(), 7);
        let report = ready(multi.export_all(&Cx::for_testing(), batch(&snapshot)));
        assert!(report.is_success());
        assert_eq!(report.succeeded(), 2);
        assert_eq!(memory.snapshots()[0].counters, snapshot.counters);
    }

    #[test]
    fn cancellation_before_start_never_calls_a_destination() {
        let (exporter, calls) = probe(false, false);
        let multi = AsyncMultiExporter::try_new(vec![exporter]).unwrap();
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, None);
        let snapshot = MetricsSnapshot::new();
        let report = ready(multi.export_all(&cx, batch(&snapshot)));
        assert!(report.was_interrupted());
        assert_eq!(report.not_attempted(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(report.into_result().is_err());
    }

    #[test]
    fn cancellation_after_success_preserves_success_and_skips_later_destinations() {
        let (first, a) = probe(false, true);
        let (second, b) = probe(false, false);
        let multi = AsyncMultiExporter::try_new(vec![first, second]).unwrap();
        let snapshot = MetricsSnapshot::new();
        let report = ready(multi.export_all(&Cx::for_testing(), batch(&snapshot)));
        assert_eq!(report.succeeded(), 1);
        assert_eq!(report.failed(), 0);
        assert_eq!(report.not_attempted(), 1);
        assert!(report.was_interrupted());
        assert_eq!(a.load(Ordering::SeqCst), 1);
        assert_eq!(b.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn trait_export_never_reports_partial_delivery_as_success() {
        let (first, _) = probe(false, false);
        let (second, _) = probe(true, false);
        let multi = AsyncMultiExporter::try_new(vec![first, second]).unwrap();
        let snapshot = MetricsSnapshot::new();
        assert!(ready(AsyncMetricsExporter::export(
            &multi,
            &Cx::for_testing(),
            batch(&snapshot),
        ))
        .is_err());
    }

    #[test]
    fn empty_fanout_and_destination_limit_are_explicit() {
        let empty = AsyncMultiExporter::try_new(Vec::new()).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        let snapshot = MetricsSnapshot::new();
        assert!(ready(empty.export_all(&Cx::for_testing(), batch(&snapshot))).is_success());
        let too_many = (0..=MAX_ASYNC_METRICS_EXPORTERS)
            .map(|_| Box::new(NullExporter::new()) as Box<dyn AsyncMetricsExporter>)
            .collect();
        assert!(AsyncMultiExporter::try_new(too_many).is_err());
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, None);
        assert!(!ready(empty.export_all(&cx, batch(&snapshot))).is_success());
    }

    struct Parked {
        drops: Arc<AtomicUsize>,
    }

    struct ParkedFuture<'a> {
        cx: &'a Cx,
        token: Option<CancelWakerToken>,
        drops: Arc<AtomicUsize>,
    }

    impl Future for ParkedFuture<'_> {
        type Output = Result<(), ExportError>;

        fn poll(self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.token = Some(this.cx.refresh_cancel_waker(this.token, task_cx.waker()));
            if checkpoint(this.cx).is_err() {
                Poll::Ready(Err(ExportError::new("fixture.cancelled")))
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for ParkedFuture<'_> {
        fn drop(&mut self) {
            if let Some(token) = self.token.take() {
                self.cx.clear_cancel_waker(token);
            }
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl AsyncMetricsExporter for Parked {
        fn export<'a>(
            &'a self,
            cx: &'a Cx,
            _batch: MetricsExportBatch<'a>,
        ) -> MetricsExportFuture<'a> {
            Box::pin(ParkedFuture {
                cx,
                token: None,
                drops: Arc::clone(&self.drops),
            })
        }
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn parked_export_wakes_on_cancellation_and_later_destination_stays_unattempted() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (later, calls) = probe(false, false);
        let multi = AsyncMultiExporter::try_new(vec![
            Box::new(Parked { drops: Arc::clone(&drops) }),
            later,
        ])
        .unwrap();
        let snapshot = MetricsSnapshot::new();
        let cx = Cx::for_testing();
        let wake_count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&waker);
        let mut future = Box::pin(multi.export_all(&cx, batch(&snapshot)));
        assert!(future.as_mut().poll(&mut task_cx).is_pending());
        cx.cancel_with(CancelKind::User, None);
        assert!(wake_count.0.load(Ordering::SeqCst) > 0);
        let Poll::Ready(report) = future.as_mut().poll(&mut task_cx) else {
            panic!("cancellation must finish the cooperative active destination");
        };
        assert_eq!(report.failed(), 1);
        assert_eq!(report.not_attempted(), 1);
        assert!(report.was_interrupted());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dropping_fanout_drops_its_active_future_without_starting_later_work() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (later, calls) = probe(false, false);
        let multi = AsyncMultiExporter::try_new(vec![
            Box::new(Parked { drops: Arc::clone(&drops) }),
            later,
        ])
        .unwrap();
        let snapshot = MetricsSnapshot::new();
        let cx = Cx::for_testing();
        let mut future = Box::pin(multi.export_all(&cx, batch(&snapshot)));
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(future);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
