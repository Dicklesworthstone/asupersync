//! Ordered, caller-owned fan-out with explicit partial-delivery receipts.

use super::{AsyncMetricsExporter, MetricsExportBatch, MetricsExportFuture, checkpoint};
use crate::cx::Cx;
use crate::observability::otel::{ExportError, InMemoryExporter, MetricsExporter, NullExporter};
use std::sync::Arc;

/// Maximum destinations in one direct metrics fan-out.
pub const MAX_ASYNC_METRICS_EXPORTERS: usize = 64;

/// Outcome at one destination's stable constructor index.
#[derive(Debug)]
#[non_exhaustive]
pub enum AsyncExportOutcome {
    /// The destination completed its export successfully.
    Succeeded,
    /// Full delivery was not acknowledged. The destination may have accepted
    /// some or all data already; this is not permission to retry blindly.
    Failed(ExportError),
    /// Cancellation or budget exhaustion prevented starting this destination.
    NotAttempted,
}

/// One outcome for every configured destination, in constructor order.
///
/// This receipt does not imply atomic delivery across destinations. Successful
/// destinations are never automatically retried. Failed destinations may have
/// ambiguous acceptance; only `NotAttempted` guarantees no attempt was made by
/// this fan-out. Dropping the future before completion produces no receipt.
#[must_use]
#[derive(Debug)]
pub struct AsyncExportReport {
    outcomes: Vec<AsyncExportOutcome>,
    interrupted: bool,
}

impl AsyncExportReport {
    /// Outcomes indexed by the destination's position in the constructor.
    #[must_use]
    pub fn outcomes(&self) -> &[AsyncExportOutcome] {
        &self.outcomes
    }

    /// Number of destinations that acknowledged successful completion.
    #[must_use]
    pub fn succeeded(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AsyncExportOutcome::Succeeded))
            .count()
    }

    /// Number of attempted destinations that returned an error.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AsyncExportOutcome::Failed(_)))
            .count()
    }

    /// Number of destinations whose export method was never called.
    #[must_use]
    pub fn not_attempted(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AsyncExportOutcome::NotAttempted))
            .count()
    }

    /// Whether a context checkpoint stopped this fan-out from proceeding.
    /// Cancellation returned by an active exporter also appears in its failed
    /// outcome. This flag does not reinterpret that exporter's error.
    #[must_use]
    pub const fn was_interrupted(&self) -> bool {
        self.interrupted
    }

    /// Whether every destination completed successfully without interruption.
    #[must_use]
    pub fn is_success(&self) -> bool {
        !self.interrupted
            && self
                .outcomes
                .iter()
                .all(|outcome| matches!(outcome, AsyncExportOutcome::Succeeded))
    }

    /// Reduce to the trait's coarse result. Use `outcomes` before this call to
    /// retain per-destination diagnostics. The aggregate error intentionally
    /// omits backend messages, which may contain sensitive application data.
    pub fn into_result(self) -> Result<(), ExportError> {
        if self.is_success() {
            Ok(())
        } else {
            Err(ExportError::new(format!(
                "otlp.multi.incomplete: {} succeeded, {} failed, {} not attempted; interrupted={}",
                self.succeeded(),
                self.failed(),
                self.not_attempted(),
                self.interrupted,
            )))
        }
    }
}

/// A finite set of direct asynchronous metrics destinations.
///
/// Destinations are awaited sequentially inside the caller's future. Ordinary
/// export errors do not suppress later destinations, but cancellation or budget
/// exhaustion stops before starting another one. There is no detached task,
/// implicit background queue, concurrent fan-out, or whole-batch retry here.
/// The active destination must honor the `AsyncMetricsExporter` contract.
///
/// This is the direct-delivery alternative to `MultiExporter` plus an explicitly
/// driven bounded OTLP queue. Do not wrap an arbitrary synchronous exporter as
/// an async destination: its `Ok` may mean admission rather than delivery, and
/// its implementation may block a runtime worker. The in-memory and null
/// exporters have dedicated immediate adapters below.
pub struct AsyncMultiExporter {
    exporters: Vec<Box<dyn AsyncMetricsExporter>>,
}

impl std::fmt::Debug for AsyncMultiExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncMultiExporter")
            .field("exporter_count", &self.exporters.len())
            .finish_non_exhaustive()
    }
}

impl AsyncMultiExporter {
    /// Create a fixed, ordered fan-out of at most 64 destinations.
    /// An empty fan-out is valid and succeeds unless its context is cancelled.
    pub fn try_new(exporters: Vec<Box<dyn AsyncMetricsExporter>>) -> Result<Self, ExportError> {
        if exporters.len() > MAX_ASYNC_METRICS_EXPORTERS {
            return Err(ExportError::new("otlp.multi.destination_limit"));
        }
        Ok(Self { exporters })
    }

    /// Number of configured destinations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exporters.len()
    }

    /// Whether no destinations are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exporters.is_empty()
    }

    /// Attempt delivery and retain every destination's outcome.
    ///
    /// Successful work is preserved at a cancellation boundary. For example,
    /// a destination that completes and then cancels the context is reported
    /// as successful, while subsequent destinations remain `NotAttempted`.
    pub async fn export_all(&self, cx: &Cx, batch: MetricsExportBatch<'_>) -> AsyncExportReport {
        let mut report = AsyncExportReport {
            outcomes: Vec::with_capacity(self.exporters.len()),
            interrupted: checkpoint(cx).is_err(),
        };
        if !report.interrupted {
            for exporter in &self.exporters {
                if checkpoint(cx).is_err() {
                    report.interrupted = true;
                    break;
                }
                let outcome = match exporter.export(cx, batch).await {
                    Ok(()) => AsyncExportOutcome::Succeeded,
                    Err(error) => AsyncExportOutcome::Failed(error),
                };
                report.outcomes.push(outcome);
            }
        }
        report
            .outcomes
            .resize_with(self.exporters.len(), || AsyncExportOutcome::NotAttempted);
        report
    }
}

impl AsyncMetricsExporter for AsyncMultiExporter {
    fn export<'a>(&'a self, cx: &'a Cx, batch: MetricsExportBatch<'a>) -> MetricsExportFuture<'a> {
        Box::pin(async move { self.export_all(cx, batch).await.into_result() })
    }
}

impl<T: AsyncMetricsExporter + ?Sized> AsyncMetricsExporter for Arc<T> {
    fn export<'a>(&'a self, cx: &'a Cx, batch: MetricsExportBatch<'a>) -> MetricsExportFuture<'a> {
        AsyncMetricsExporter::export(self.as_ref(), cx, batch)
    }
}

impl AsyncMetricsExporter for InMemoryExporter {
    fn export<'a>(&'a self, cx: &'a Cx, batch: MetricsExportBatch<'a>) -> MetricsExportFuture<'a> {
        Box::pin(async move {
            checkpoint(cx)?;
            MetricsExporter::export(self, batch.snapshot())
        })
    }
}

impl AsyncMetricsExporter for NullExporter {
    fn export<'a>(&'a self, cx: &'a Cx, batch: MetricsExportBatch<'a>) -> MetricsExportFuture<'a> {
        Box::pin(async move {
            checkpoint(cx)?;
            MetricsExporter::export(self, batch.snapshot())
        })
    }
}

#[cfg(test)]
mod tests {
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
}
