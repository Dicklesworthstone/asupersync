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
#[path = "multi_inline_tests.rs"]
mod tests;
