//! Bounded all-signal admission for the native OTLP/gRPC transport.

use super::{
    Destination, ExportError, ExportQueue, ManagedOtlpError, ManagedOtlpExporter,
    OtlpExportQueueStats, OtlpGrpcExporter, OtlpGrpcRetryPolicy, OtlpGrpcSignal,
    OtlpLogKeyValueInput, OtlpLogRecordInput, OtlpTraceSpanInput, OwnedOtlpLogs, OwnedOtlpMetrics,
    OwnedOtlpTraces, managed,
};
use crate::Cx;
use std::sync::Arc;

/// Bounded cumulative accounting for a native gRPC producer queue.
///
/// `queue.delivered_batches` counts terminal collector acknowledgements,
/// including partial success. It does not mean every item was accepted.
/// Explicit rejection totals below are authoritative collector counts; failed
/// or interrupted batches can have unknown acceptance and are never guessed
/// into these totals. All cumulative counters saturate at `u64::MAX`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OtlpGrpcQueueStats {
    /// Shared admission, in-flight, delivery, and failure accounting.
    pub queue: OtlpExportQueueStats,
    /// Terminal responses containing partial success, including warnings or
    /// an empty partial-success field. Each batch contributes at most once.
    pub partial_success_batches: u64,
    /// Metric data points explicitly rejected by completed collector responses.
    pub rejected_data_points: u64,
    /// Trace spans explicitly rejected by completed collector responses.
    pub rejected_spans: u64,
    /// Log records explicitly rejected by completed collector responses.
    pub rejected_log_records: u64,
}

/// Synchronous bounded admission and structured asynchronous delivery for
/// owned OTLP metrics, traces, and logs over one native gRPC transport.
///
/// Clones share the existing 64-batch, 8-MiB queue, including in-flight and
/// retrying batches. Encoded allocation capacity and captured configuration
/// bytes are charged before publication. Container overhead, the caller-owned
/// channel's resources, and temporary mapper/transport allocations are extra;
/// existing finite mapper limits and a 4-MiB request ceiling bound those
/// encodings separately. Each immutable transport is conservatively charged
/// for every batch even though its allocation is shared.
///
/// Admission starts no task and performs no I/O. A full queue refuses the new
/// collection atomically and preserves accepted work. Delivery requires an
/// explicit caller-owned consumer or [`Self::spawn_queued`], which owns a real
/// task and child region. There is no detached worker or hidden runtime.
///
/// By default each batch uses one logical native unary invocation. Retry is
/// opt-in through [`Self::with_retry_policy`]; the policy is captured at admission
/// and stays within the delivery/owner bounds. A valid partial receipt is
/// terminal and never retried. Its rejected items are counted separately while
/// later batches may continue. Raw collector diagnostics are not retained.
#[derive(Clone)]
pub struct QueuedOtlpGrpcExporter {
    transport: Arc<OtlpGrpcExporter>,
    queue: Arc<ExportQueue>,
    retry_policy: Option<OtlpGrpcRetryPolicy>,
}

impl std::fmt::Debug for QueuedOtlpGrpcExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedOtlpGrpcExporter")
            .field("retry_enabled", &self.retry_policy.is_some())
            .field("stats", &self.queue_stats())
            .finish_non_exhaustive()
    }
}

impl QueuedOtlpGrpcExporter {
    /// Give an already-validated native sender a fresh bounded producer queue.
    /// No network operation, runtime, worker, or region is created here.
    #[must_use]
    pub fn new(transport: OtlpGrpcExporter) -> Self {
        Self {
            transport: Arc::new(transport),
            queue: Arc::new(ExportQueue::default()),
            retry_policy: None,
        }
    }

    /// Use an explicitly validated finite retry policy for future admissions
    /// through this clone. Already queued batches retain their original policy,
    /// and other producer clones are unchanged. Partial success never retries.
    #[must_use]
    pub fn with_retry_policy(mut self, policy: OtlpGrpcRetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Admit one already-encoded OTLP protobuf body without network I/O.
    /// Supply the signal explicitly and do not prepend a gRPC frame. The
    /// sender's smaller request limit and queue capacity are checked first.
    /// `Ok(())` means admission, not collector acknowledgement.
    pub fn enqueue_encoded(
        &self,
        signal: OtlpGrpcSignal,
        body: Vec<u8>,
    ) -> Result<(), ExportError> {
        self.admit(signal, vec![body]).map(|_| ())
    }

    /// Collect owned metrics with an explicit Unix point timestamp and admit
    /// every encoded request together. A mapping, byte-limit, or capacity
    /// refusal publishes no prefix. The returned count is admitted requests.
    pub fn enqueue_owned_metrics(
        &self,
        metrics: &OwnedOtlpMetrics,
        point_time_unix_nano: u64,
    ) -> Result<usize, ExportError> {
        let attributes: Vec<_> = self.transport.resource_attributes().collect();
        let requests = metrics
            .collect(point_time_unix_nano, &attributes)
            .map_err(|error| ExportError::new(error.to_string()))?;
        self.admit(OtlpGrpcSignal::Metrics, requests)
    }

    /// Validate, sample, encode, and atomically admit borrowed trace spans.
    /// Producer timestamps and lineage are preserved by the existing owned
    /// mapper. An all-unsampled collection admits nothing and performs no I/O.
    pub fn enqueue_owned_traces(
        &self,
        traces: &OwnedOtlpTraces,
        spans: &[OtlpTraceSpanInput<'_>],
    ) -> Result<usize, ExportError> {
        let attributes: Vec<_> = self.transport.resource_attributes().collect();
        let requests = traces
            .collect(spans, &attributes)
            .map_err(|error| ExportError::new(error.to_string()))?
            .into_requests();
        self.admit(OtlpGrpcSignal::Traces, requests)
    }

    /// Encode and atomically admit structured logs with their typed bodies and
    /// producer timestamps. Empty input admits nothing. Filtering remains the
    /// responsibility of the existing privacy-aware producers and builders.
    pub fn enqueue_owned_logs(
        &self,
        logs: &OwnedOtlpLogs,
        records: &[OtlpLogRecordInput<'_>],
    ) -> Result<usize, ExportError> {
        let attributes: Vec<_> = self
            .transport
            .resource_attributes()
            .map(|(key, value)| OtlpLogKeyValueInput::string(key, value))
            .collect();
        let requests = logs
            .collect(records, &attributes)
            .map_err(|error| ExportError::new(error.to_string()))?
            .into_requests();
        self.admit(OtlpGrpcSignal::Logs, requests)
    }

    /// Snapshot shared admission and cumulative partial-rejection accounting.
    ///
    /// After a managed `join`, this producer or any retained clone can inspect
    /// these terminal counters. The existing managed receipt's `queue` field
    /// contains the same base counters; use this method for signal-specific
    /// rejections before interpreting a drained service as full acceptance.
    #[must_use]
    pub fn queue_stats(&self) -> OtlpGrpcQueueStats {
        let state = self.queue.state.lock();
        OtlpGrpcQueueStats {
            queue: state.stats,
            partial_success_batches: state.grpc.batches,
            rejected_data_points: state.grpc.rejected_data_points,
            rejected_spans: state.grpc.rejected_spans,
            rejected_log_records: state.grpc.rejected_log_records,
        }
    }

    /// Deliver only the finite queue prefix present at entry and return its
    /// terminal receipt count. Partial success is included; inspect queue stats
    /// for rejections. A second consumer is refused. Cancellation/drop after
    /// dequeue retires that attempt as failed without replay, while later
    /// manual backlog remains available to another consumer.
    pub async fn flush_queued(&self, cx: &Cx) -> Result<usize, ExportError> {
        // Owned bodies already contain timestamps; this unused legacy value
        // never overwrites encoded metrics, spans, or log records.
        self.queue.flush_prefix(cx, 1).await
    }

    /// Drive the shared queue inside the caller's task until cancellation or
    /// delivery failure. Admission wakes an idle consumer; owner cancellation
    /// and deadline also wake it. Partial receipts do not stop later batches.
    /// Stop producers and this consumer before a finite manual flush.
    pub async fn run_queued(&self, cx: &Cx) -> Result<(), ExportError> {
        self.queue.run(cx, || 1).await
    }

    /// Own one delivery task in a real child region of `cx`, reusing the
    /// existing managed admission/drain/abort/join state machine.
    ///
    /// `begin_drain` seals all producer clones. `join` proves actual task and
    /// region retirement; dropping only a join observation does not stop the
    /// service. Every terminal service path seals admission and retires backlog.
    /// A drained service may contain partial receipts: inspect [`Self::queue_stats`]
    /// after joining to see explicit rejected items. No metrics clock is needed
    /// because owned messages retain their original timestamps.
    pub async fn spawn_queued(&self, cx: &Cx) -> Result<ManagedOtlpExporter, ManagedOtlpError> {
        managed::spawn_queue(&self.queue, cx, || 1).await
    }

    fn admit(&self, signal: OtlpGrpcSignal, requests: Vec<Vec<u8>>) -> Result<usize, ExportError> {
        self.queue.admit_encoded(
            Destination::Grpc {
                exporter: Arc::clone(&self.transport),
                retry_policy: self.retry_policy,
            },
            signal,
            requests,
        )
    }
}

#[cfg(test)]
#[path = "queued_grpc_tests.rs"]
mod tests;
