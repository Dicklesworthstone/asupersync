//! Acknowledged, bounded all-signal OTLP/HTTP delivery.

use super::{
    Destination, ExportError, ExportQueue, ManagedOtlpError, ManagedOtlpExporter,
    OtlpCancelWakerGuard, OtlpExportQueueStats, OtlpGrpcQueueReceipt as OtlpQueueReceipt,
    OtlpGrpcResponse as OtlpSignalResponse, OtlpGrpcSignal as OtlpSignal, OtlpHttpConfig,
    OtlpHttpExporter, add_bytes, decode_otlp_http_response, managed,
};
use crate::Cx;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

/// Cumulative accounting for an acknowledged native HTTP queue.
///
/// Delivered batches have terminal collector acknowledgements, including
/// partial success. They are not a count of accepted telemetry items. Failed
/// requests can have unknown acceptance and are never added to rejection totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OtlpHttpQueueStats {
    /// Shared admission, in-flight, delivery, and failure accounting.
    pub queue: OtlpExportQueueStats,
    /// Responses containing partial success, including zero-rejected warnings
    /// and empty partial-success fields. Each request contributes once.
    pub partial_success_batches: u64,
    /// Metric data points explicitly rejected by the collector.
    pub rejected_data_points: u64,
    /// Trace spans explicitly rejected by the collector.
    pub rejected_spans: u64,
    /// Log records explicitly rejected by the collector.
    pub rejected_log_records: u64,
}

/// A caller-owned bounded queue with explicit HTTP endpoints for all signals.
///
/// Each endpoint is used exactly as configured. No path is inferred or
/// rewritten; normally the caller selects /v1/metrics, /v1/traces and /v1/logs.
/// Immutable configuration includes TLS/authentication, compression and retry
/// policy. Configuration is captured at admission and cannot redirect already
/// accepted telemetry. No global provider, runtime, worker or I/O is created
/// by construction or admission.
///
/// Clones share the existing 64-batch, 8-MiB queue. Encoded Vec capacity,
/// captured configuration and collection-receipt storage are charged before
/// atomic publication, including in-flight/retrying work. Shared configuration
/// is conservatively charged for every batch. The producer's three bounded
/// configurations, container overhead and temporary HTTP/compression buffers
/// are additional; encoded requests and responses are limited to 4 MiB.
///
/// Delivery requires an explicit Cx with a timer. Each request's configuration
/// timeout bounds its whole delivery, including retries, Retry-After waits and
/// request compression; an earlier owner deadline tightens it. A request is
/// acknowledged only by HTTP 200 with the protobuf content type and a complete,
/// valid bounded OTLP response. Partial success is terminal, counted once and
/// never replayed. Later admitted requests may continue.
///
/// The existing OtlpHttpExporter admission API keeps its legacy delivery
/// contract. This separate queue provides collector receipts and shared SDK
/// lifecycle support without changing that API.
#[derive(Clone)]
pub struct QueuedOtlpHttpExporter {
    metrics: Arc<OtlpHttpConfig>,
    traces: Arc<OtlpHttpConfig>,
    logs: Arc<OtlpHttpConfig>,
    queue: Arc<ExportQueue>,
}

impl std::fmt::Debug for QueuedOtlpHttpExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedOtlpHttpExporter")
            .field("stats", &self.queue_stats())
            .finish_non_exhaustive()
    }
}

impl QueuedOtlpHttpExporter {
    /// Supply three already-validated immutable signal configurations.
    ///
    /// The configurations may use different collectors or credentials. SDK
    /// requests already contain their authoritative resource metadata; raw
    /// admission does not rewrite encoded resources from these defaults.
    #[must_use]
    pub fn new(metrics: OtlpHttpConfig, traces: OtlpHttpConfig, logs: OtlpHttpConfig) -> Self {
        Self {
            metrics: compact(metrics),
            traces: compact(traces),
            logs: compact(logs),
            queue: Arc::new(ExportQueue::default()),
        }
    }

    /// Immutable configuration used for the selected signal.
    #[must_use]
    pub fn config(&self, signal: OtlpSignal) -> &OtlpHttpConfig {
        self.configuration(signal)
    }

    fn configuration(&self, signal: OtlpSignal) -> &Arc<OtlpHttpConfig> {
        match signal {
            OtlpSignal::Metrics => &self.metrics,
            OtlpSignal::Traces => &self.traces,
            OtlpSignal::Logs => &self.logs,
        }
    }

    fn destination(&self, signal: OtlpSignal) -> Destination {
        Destination::AcknowledgedHttp {
            config: Arc::clone(self.configuration(signal)),
        }
    }

    /// Admit one protobuf body without framing, I/O or a delivery task.
    /// Success means queue admission, not collector acknowledgement.
    pub fn enqueue_encoded(&self, signal: OtlpSignal, body: Vec<u8>) -> Result<(), ExportError> {
        self.queue
            .admit_encoded(self.destination(signal), signal, vec![body])
            .map(|_| ())
    }

    /// Atomically admit a whole encoded collection and observe its delivery.
    ///
    /// Every request is checked before any prefix is published. Dropping the
    /// returned observation leaves accepted work owned by the queue. The
    /// receipt resolves only after all payloads and credit have retired and
    /// retains ordered full/partial acknowledgements. Never replay completed
    /// responses from a failed collection. Empty input produces no I/O.
    pub fn enqueue_encoded_with_receipt(
        &self,
        signal: OtlpSignal,
        requests: Vec<Vec<u8>>,
    ) -> Result<OtlpQueueReceipt, ExportError> {
        self.queue
            .admit_encoded_with_receipt(self.destination(signal), signal, requests)
    }

    /// Shared queue and terminal partial-success counters.
    #[must_use]
    pub fn queue_stats(&self) -> OtlpHttpQueueStats {
        let state = self.queue.state.lock();
        OtlpHttpQueueStats {
            queue: state.stats,
            partial_success_batches: state.http.batches,
            rejected_data_points: state.http.rejected_data_points,
            rejected_spans: state.http.rejected_spans,
            rejected_log_records: state.http.rejected_log_records,
        }
    }

    /// Deliver the admitted prefix under the caller's explicit ownership.
    /// A failed batch retires once; unattempted backlog remains queued.
    pub async fn flush_queued(&self, cx: &Cx) -> Result<usize, ExportError> {
        self.queue.flush_prefix(cx, 1).await
    }

    /// Consume until cancellation or failure, without starting another task.
    /// Partial acknowledgements do not stop later requests.
    pub async fn run_queued(&self, cx: &Cx) -> Result<(), ExportError> {
        self.queue.run(cx, || 1).await
    }

    /// Own delivery in a real child region using the shared drain/abort/join
    /// state machine. Sealing affects every producer clone. After join, inspect
    /// queue_stats for partial-success rejection totals as well as delivery.
    pub async fn spawn_queued(&self, cx: &Cx) -> Result<ManagedOtlpExporter, ManagedOtlpError> {
        managed::spawn_queue(&self.queue, cx, || 1).await
    }
}

fn compact(config: OtlpHttpConfig) -> Arc<OtlpHttpConfig> {
    // Public builders accept owned strings; discard spare source capacities
    // before retaining a producer configuration. The validated contents are
    // bounded independently of those caller allocations.
    let compact = config.clone();
    drop(config);
    Arc::new(compact)
}

pub(super) fn configuration_bytes(config: &OtlpHttpConfig) -> Result<usize, ExportError> {
    let mut bytes = std::mem::size_of::<OtlpHttpConfig>();
    add_bytes(&mut bytes, config.endpoint.capacity())?;
    add_bytes(
        &mut bytes,
        config.auth_headers.capacity() * std::mem::size_of::<super::OtlpAuthHeader>(),
    )?;
    for header in &config.auth_headers {
        add_bytes(&mut bytes, header.name.capacity())?;
        add_bytes(&mut bytes, header.value.0.capacity())?;
    }
    add_bytes(
        &mut bytes,
        config.resource_attributes.capacity() * std::mem::size_of::<(String, String)>(),
    )?;
    for (key, value) in &config.resource_attributes {
        add_bytes(&mut bytes, key.capacity())?;
        add_bytes(&mut bytes, value.capacity())?;
    }
    Ok(bytes)
}

pub(super) async fn send(
    config: &OtlpHttpConfig,
    cx: &Cx,
    signal: OtlpSignal,
    body: Vec<u8>,
) -> Result<OtlpSignalResponse, &'static str> {
    cx.checkpoint().map_err(|_| "otlp.http.cancelled")?;
    let timer = cx.timer_driver().ok_or("otlp.http.timer_required")?;
    let deadline = timer
        .now()
        .saturating_add_nanos(u64::try_from(config.timeout.as_nanos()).unwrap_or(u64::MAX));
    let deadline = cx
        .budget()
        .deadline
        .map_or(deadline, |owner| owner.min(deadline));
    let mut sleeper = crate::time::Sleep::with_timer_driver(deadline, timer.clone());
    let sender = OtlpHttpExporter::from_config(config.clone());
    let mut operation: Pin<Box<dyn Future<Output = Result<Vec<u8>, ExportError>> + Send + '_>> =
        Box::pin(sender.send_otlp_protobuf_response_body_checked(cx, body, true));
    let mut cancel = OtlpCancelWakerGuard::new(cx);
    let bytes = poll_fn(|task| {
        cancel.refresh(task.waker());
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err("otlp.http.cancelled"));
        }
        // Check the total deadline before resuming a retry/backoff continuation;
        // expiry cannot start a fresh attempt merely because the wait is ready.
        if timer.now() >= deadline {
            return Poll::Ready(Err("otlp.http.deadline_exceeded"));
        }
        match operation.as_mut().poll(task) {
            Poll::Ready(Ok(bytes)) => Poll::Ready(Ok(bytes)),
            // Peer diagnostics, response headers and endpoint text stay out of
            // both the collection error and managed owner's automatic output.
            Poll::Ready(Err(_)) => Poll::Ready(Err("otlp.http.export_failed")),
            Poll::Pending => {
                if Pin::new(&mut sleeper).poll_deadline(task).is_ready() {
                    Poll::Ready(Err("otlp.http.deadline_exceeded"))
                } else {
                    Poll::Pending
                }
            }
        }
    })
    .await?;
    let acknowledgement =
        decode_otlp_http_response(&bytes).map_err(|_| "otlp.http.invalid_response")?;
    Ok(OtlpSignalResponse::from_acknowledgement(
        signal,
        acknowledgement,
    ))
}

#[cfg(test)]
#[path = "queued_http_tests.rs"]
pub(in crate::observability::otel) mod tests;
