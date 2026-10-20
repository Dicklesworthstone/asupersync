//! Bounded synchronous admission and caller-owned asynchronous OTLP delivery.

// This split implementation intentionally uses its parent module's private
// exporter machinery as one cohesive unit (as transport_rq/bonded.rs does).
#[allow(clippy::wildcard_imports)]
use super::*;
use std::collections::VecDeque;

/// Maximum admitted batches, including the batch currently being delivered.
pub const OTLP_EXPORT_QUEUE_MAX_BATCHES: usize = 64;
/// Maximum admitted snapshot string or encoded trace bytes, including the in-flight batch.
///
/// Container overhead and temporary protobuf/HTTP encodings are additional;
/// finite point/attribute limits bound those independently.
pub const OTLP_EXPORT_QUEUE_MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_POINTS: usize = 4096;

/// Shared queue counters. Cloned exporters share admission and delivery state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OtlpExportQueueStats {
    /// Batches awaiting an async consumer.
    pub queued_batches: usize,
    /// Batches admitted but not yet retired, including the current request.
    pub retained_batches: usize,
    /// Admitted snapshot and configuration string bytes.
    pub retained_bytes: usize,
    /// Batches fully acknowledged by the collector.
    pub delivered_batches: u64,
    /// Failed or abandoned delivery attempts. These are never requeued.
    pub failed_batches: u64,
    /// Whether a caller currently owns the async consumer.
    pub consumer_active: bool,
}

#[derive(Debug, Default)]
pub(super) struct ExportQueue {
    state: Mutex<QueueState>,
    ready: crate::sync::Notify,
}

#[derive(Debug, Default)]
struct QueueState {
    pending: VecDeque<Batch>,
    stats: OtlpExportQueueStats,
}

#[derive(Debug)]
enum Payload {
    Metrics(MetricsSnapshot),
    Logs(LogsSnapshot),
    Traces(Vec<u8>),
}

#[derive(Debug)]
struct Batch {
    payload: Payload,
    config: OtlpHttpConfig,
    legacy_retry_compatibility: bool,
    bytes: usize,
}

impl ExportQueue {
    pub(super) fn check_flushed(&self) -> Result<(), ExportError> {
        let state = self.state.lock();
        if state.stats.retained_batches != 0 {
            return Err(ExportError::new(
                "otlp.queue.pending: drive flush_queued or run_queued with an explicit Cx",
            ));
        }
        if state.stats.failed_batches != 0 {
            return Err(ExportError::new(
                "otlp.queue.delivery_failed: an admitted batch failed or was abandoned; inspect queue_stats",
            ));
        }
        Ok(())
    }

    fn admit(
        &self,
        exporter: &OtlpHttpExporter,
        bytes: usize,
        payload: impl FnOnce() -> Payload,
    ) -> Result<(), ExportError> {
        exporter.validate_for_export().map_err(ExportError::from)?;
        let config = exporter.snapshot_config();
        let bytes = bytes
            .checked_add(config_bytes(&config)?)
            .ok_or_else(queue_full)?;
        let mut state = self.state.lock();
        let retained = state
            .stats
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(queue_full)?;
        if state.stats.retained_batches >= OTLP_EXPORT_QUEUE_MAX_BATCHES
            || retained > OTLP_EXPORT_QUEUE_MAX_BYTES
        {
            return Err(queue_full());
        }
        // Validate and reserve before cloning caller-owned snapshots. No user
        // callbacks or wakers run under this lock.
        state.pending.push_back(Batch {
            payload: payload(),
            config,
            legacy_retry_compatibility: exporter.legacy_retry_compatibility,
            bytes,
        });
        state.stats.retained_batches += 1;
        state.stats.retained_bytes = retained;
        state.stats.queued_batches = state.pending.len();
        drop(state);
        self.ready.notify_one();
        Ok(())
    }

    fn consumer(&self) -> Result<Consumer<'_>, ExportError> {
        let mut state = self.state.lock();
        if state.stats.consumer_active {
            return Err(ExportError::new("otlp.queue.consumer_busy"));
        }
        state.stats.consumer_active = true;
        Ok(Consumer { queue: self })
    }

    fn admit_traces(
        &self,
        exporter: &OtlpHttpExporter,
        requests: Vec<Vec<u8>>,
    ) -> Result<usize, ExportError> {
        let count = requests.len();
        if count == 0 {
            return Ok(0);
        }
        let config = exporter.snapshot_config();
        let configuration_bytes = config_bytes(&config)?;
        let mut bytes = configuration_bytes.checked_mul(count).ok_or_else(queue_full)?;
        for request in &requests {
            if request.len() > OWNED_OTLP_DEFAULT_REQUEST_BYTES {
                return Err(ExportError::new("otlp.queue.encoded_batch_too_large"));
            }
            add_bytes(&mut bytes, request.len())?;
        }
        let mut state = self.state.lock();
        let retained_batches = state.stats.retained_batches.checked_add(count).ok_or_else(queue_full)?;
        let retained_bytes = state.stats.retained_bytes.checked_add(bytes).ok_or_else(queue_full)?;
        if retained_batches > OTLP_EXPORT_QUEUE_MAX_BATCHES
            || retained_bytes > OTLP_EXPORT_QUEUE_MAX_BYTES
        {
            return Err(queue_full());
        }
        // One collection is one admission decision. Publishing a prefix here
        // would make a capacity retry duplicate the earlier accepted spans.
        for request in requests {
            let bytes = request.len() + configuration_bytes;
            state.pending.push_back(Batch {
                payload: Payload::Traces(request),
                config: config.clone(),
                legacy_retry_compatibility: exporter.legacy_retry_compatibility,
                bytes,
            });
        }
        state.stats.retained_batches = retained_batches;
        state.stats.retained_bytes = retained_bytes;
        state.stats.queued_batches = state.pending.len();
        drop(state);
        self.ready.notify_one();
        Ok(count)
    }

    fn take(&self) -> Option<Delivery<'_>> {
        let mut state = self.state.lock();
        let batch = state.pending.pop_front()?;
        state.stats.queued_batches = state.pending.len();
        Some(Delivery {
            queue: self,
            batch: Some(batch),
            delivered: false,
        })
    }
}

struct Consumer<'a> {
    queue: &'a ExportQueue,
}

impl Drop for Consumer<'_> {
    fn drop(&mut self) {
        self.queue.state.lock().stats.consumer_active = false;
    }
}

struct Delivery<'a> {
    queue: &'a ExportQueue,
    batch: Option<Batch>,
    delivered: bool,
}

impl Delivery<'_> {
    async fn send(&mut self, cx: &crate::Cx, point_time: u64) -> Result<(), ExportError> {
        let batch = self.batch.as_ref().expect("delivery owns its batch");
        let body = match &batch.payload {
            Payload::Metrics(snapshot) => encode_metrics(snapshot, point_time, &batch.config)?,
            Payload::Logs(snapshot) => snapshot.to_otlp_protobuf(),
            Payload::Traces(body) => body.clone(),
        };
        if body.len() > OWNED_OTLP_DEFAULT_REQUEST_BYTES {
            return Err(ExportError::new("otlp.queue.encoded_batch_too_large"));
        }
        // Capture each batch's destination and credentials at admission. A
        // fluent configuration change on another clone cannot redirect it.
        let mut sender = OtlpHttpExporter::from_config(batch.config.clone());
        sender.legacy_retry_compatibility = batch.legacy_retry_compatibility;
        sender.send_otlp_protobuf(cx, body).await?;
        self.delivered = true;
        Ok(())
    }
}

impl Drop for Delivery<'_> {
    fn drop(&mut self) {
        let batch = self.batch.take().expect("delivery retires once");
        let bytes = batch.bytes;
        // Release retained snapshots before returning admission credit.
        drop(batch);
        let mut state = self.queue.state.lock();
        state.stats.retained_batches -= 1;
        state.stats.retained_bytes -= bytes;
        if self.delivered {
            state.stats.delivered_batches = state.stats.delivered_batches.saturating_add(1);
        } else {
            state.stats.failed_batches = state.stats.failed_batches.saturating_add(1);
        }
    }
}

impl OtlpHttpExporter {
    /// Validate and enqueue an entire finite trace collection without network I/O.
    ///
    /// All encoded requests are admitted together, or none are admitted. Queue
    /// limits include the complete encoded requests and each request's captured
    /// destination/resource/authentication configuration, including in-flight
    /// delivery. The mapper's separate finite allocation limits apply before
    /// admission; one temporary request copy is retained during delivery.
    ///
    /// Returns the number of admitted requests, not acknowledged spans. Drive
    /// `flush_queued` or `run_queued` inside an explicit Cx to deliver them. Trace
    /// timestamps are retained; the metrics timestamp argument does not replace
    /// them. Unsampled collections enqueue nothing. A later delivery error must
    /// not be treated as permission to re-enqueue the entire collection, since
    /// preceding requests or the collector may already have accepted spans.
    pub fn enqueue_owned_traces(
        &self,
        traces: &OwnedOtlpTraces,
        spans: &[OtlpTraceSpanInput<'_>],
    ) -> Result<usize, ExportError> {
        self.validate_for_export().map_err(ExportError::from)?;
        let attributes = self.resource_attributes.iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let collection = traces.collect(spans, &attributes)
            .map_err(|error| ExportError::new(error.to_string()))?;
        self.export_queue.admit_traces(self, collection.into_requests())
    }

    pub(super) fn enqueue_metrics(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        let bytes = metrics_bytes(metrics)?;
        // Refuse here what delivery could never encode: more than 1000 points
        // for one metric, more fields than the wire limits allow, or a body
        // over the request limit. Admitted, such a batch failed at delivery
        // without any I/O, taking the whole snapshot with it and stopping
        // run_queued. The timestamp is a fixed-width field, so encoding with a
        // placeholder predicts the delivered size exactly.
        let encoded = encode_metrics(metrics, 1, &self.snapshot_config())?;
        if encoded.len() > OWNED_OTLP_DEFAULT_REQUEST_BYTES {
            return Err(ExportError::new("otlp.queue.encoded_batch_too_large"));
        }
        self.export_queue
            .admit(self, bytes, || Payload::Metrics(metrics.clone()))
    }

    pub(super) fn enqueue_logs(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
        let bytes = logs_bytes(logs)?;
        // The queue admits up to OTLP_EXPORT_QUEUE_MAX_BYTES, but one request
        // body may not exceed the request limit; refuse that here, not at
        // delivery.
        if logs.to_otlp_protobuf().len() > OWNED_OTLP_DEFAULT_REQUEST_BYTES {
            return Err(ExportError::new("otlp.queue.encoded_batch_too_large"));
        }
        self.export_queue
            .admit(self, bytes, || Payload::Logs(logs.clone()))
    }

    /// Inspect shared queue admission and terminal delivery counters.
    #[must_use]
    pub fn queue_stats(&self) -> OtlpExportQueueStats {
        self.export_queue.state.lock().stats
    }

    /// Deliver the finite queue prefix present when this call starts.
    ///
    /// `point_time_unix_nano` is an explicit collection timestamp for legacy
    /// metrics snapshots, which contain no timestamp. Logs retain their own
    /// timestamps. No task or runtime is spawned. Cancellation/drop retires
    /// the current attempt as failed, since collector acceptance may already
    /// have occurred; later queued batches remain available for another call.
    /// Sync `flush()` checks completion and never pretends pending work was sent.
    pub async fn flush_queued(
        &self,
        cx: &crate::Cx,
        point_time_unix_nano: u64,
    ) -> Result<usize, ExportError> {
        if point_time_unix_nano == 0 {
            return Err(ExportError::new("otlp.queue.invalid_timestamp"));
        }
        let _consumer = self.export_queue.consumer()?;
        let count = self.queue_stats().queued_batches;
        for _ in 0..count {
            cx.checkpoint()
                .map_err(|_| ExportError::new("otlp.queue.cancelled"))?;
            let mut delivery = self
                .export_queue
                .take()
                .expect("exclusive consumer owns prefix");
            delivery.send(cx, point_time_unix_nano).await?;
        }
        Ok(count)
    }

    /// Drive queued exports inside a caller-owned task until cancellation or
    /// delivery failure. The explicit clock supplies Unix nanoseconds for
    /// metrics; it is called outside all queue locks. Use `flush_queued` after
    /// stopping producers when a finite graceful drain is required.
    pub async fn run_queued(
        &self,
        cx: &crate::Cx,
        mut unix_time_nanos: impl FnMut() -> u64,
    ) -> Result<(), ExportError> {
        use std::future::{Future, poll_fn};
        use std::pin::pin;
        use std::task::Poll;

        let _consumer = self.export_queue.consumer()?;
        let mut cancel = OtlpCancelWakerGuard::new(cx);
        let mut deadline = cx.budget().deadline.map(|deadline| {
            cx.timer_driver().map_or_else(
                || crate::time::sleep_until(deadline),
                |driver| crate::time::Sleep::with_timer_driver(deadline, driver),
            )
        });
        loop {
            let mut ready = pin!(
                self.export_queue
                    .ready
                    .wait_until(|| { self.queue_stats().queued_batches != 0 })
            );
            poll_fn(|task_cx| {
                cancel.refresh(task_cx.waker());
                if cx.checkpoint().is_err() {
                    return Poll::Ready(Err(ExportError::new("otlp.queue.cancelled")));
                }
                if let Some(deadline) = deadline.as_mut()
                    && std::pin::Pin::new(deadline)
                        .poll_deadline(task_cx)
                        .is_ready()
                {
                    return Poll::Ready(Err(ExportError::new("otlp.queue.deadline_exceeded")));
                }
                ready.as_mut().poll(task_cx).map(Ok)
            })
            .await?;
            // Read and validate the caller's clock before dequeueing, so a
            // broken clock does not consume accepted telemetry.
            let timestamp = unix_time_nanos();
            if timestamp == 0 {
                return Err(ExportError::new("otlp.queue.invalid_timestamp"));
            }
            if let Some(mut delivery) = self.export_queue.take() {
                delivery.send(cx, timestamp).await?;
            }
        }
    }
}

impl OtlpLogsHttpExporter {
    /// Shared queue admission and delivery counters.
    #[must_use]
    pub fn queue_stats(&self) -> OtlpExportQueueStats {
        self.http.queue_stats()
    }

    /// Deliver the current queue prefix; log timestamps are retained exactly.
    pub async fn flush_queued(&self, cx: &crate::Cx) -> Result<usize, ExportError> {
        self.http.flush_queued(cx, 1).await
    }

    /// Drive log exports inside the caller's task until cancellation or error.
    pub async fn run_queued(&self, cx: &crate::Cx) -> Result<(), ExportError> {
        self.http.run_queued(cx, || 1).await
    }
}

fn queue_full() -> ExportError {
    ExportError::new("otlp.queue.capacity_exceeded: batch was not admitted")
}

fn add_bytes(total: &mut usize, bytes: usize) -> Result<(), ExportError> {
    *total = total.checked_add(bytes).ok_or_else(queue_full)?;
    if *total > OTLP_EXPORT_QUEUE_MAX_BYTES {
        return Err(queue_full());
    }
    Ok(())
}

fn config_bytes(config: &OtlpHttpConfig) -> Result<usize, ExportError> {
    let mut bytes = config.endpoint.len();
    for header in &config.auth_headers {
        add_bytes(&mut bytes, header.name.len())?;
        add_bytes(&mut bytes, header.value.0.len())?;
    }
    add_bytes(&mut bytes, attribute_bytes(&config.resource_attributes)?)?;
    Ok(bytes)
}

fn attribute_bytes(attributes: &[(String, String)]) -> Result<usize, ExportError> {
    validate_owned_otlp_attributes(
        attributes.len(),
        attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    )
    .map_err(|error| ExportError::new(error.to_string()))?;
    let mut keys = BTreeSet::new();
    let mut bytes = 0;
    for (key, value) in attributes {
        if !keys.insert(key.as_str()) {
            return Err(ExportError::new("otlp.queue.duplicate_attribute"));
        }
        add_bytes(&mut bytes, key.len())?;
        add_bytes(&mut bytes, value.len())?;
    }
    Ok(bytes)
}

fn metrics_bytes(snapshot: &MetricsSnapshot) -> Result<usize, ExportError> {
    let count = snapshot
        .counters
        .len()
        .saturating_add(snapshot.gauges.len())
        .saturating_add(snapshot.histograms.len());
    if count > MAX_POINTS {
        return Err(queue_full());
    }
    let mut bytes = 0;
    let mut names = BTreeMap::new();
    let mut streams = BTreeSet::new();
    for (kind, name, labels) in snapshot
        .counters
        .iter()
        .map(|(n, l, _)| (0, n, l))
        .chain(snapshot.gauges.iter().map(|(n, l, _)| (1, n, l)))
        .chain(snapshot.histograms.iter().map(|(n, l, _, _)| (2, n, l)))
    {
        if name.is_empty()
            || name.len() > 1024
            || names.insert(name, kind).is_some_and(|old| old != kind)
        {
            return Err(ExportError::new("otlp.queue.invalid_metric_name_or_kind"));
        }
        add_bytes(&mut bytes, name.len())?;
        add_bytes(&mut bytes, attribute_bytes(labels)?)?;
        let mut labels = labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>();
        labels.sort_unstable();
        if !streams.insert((name.as_str(), labels)) {
            return Err(ExportError::new("otlp.queue.duplicate_metric_stream"));
        }
    }
    if snapshot
        .counters
        .iter()
        .any(|(_, _, v)| i64::try_from(*v).is_err())
        || snapshot
            .histograms
            .iter()
            .any(|(_, _, count, sum)| !sum.is_finite() || (*count == 0 && *sum != 0.0))
    {
        return Err(ExportError::new("otlp.queue.invalid_numeric_value"));
    }
    Ok(bytes)
}

fn logs_bytes(snapshot: &LogsSnapshot) -> Result<usize, ExportError> {
    if snapshot.records.len() > MAX_POINTS {
        return Err(queue_full());
    }
    let mut bytes = attribute_bytes(&snapshot.resource_attributes)?;
    for value in [
        &snapshot.scope_name,
        &snapshot.scope_version,
        &snapshot.schema_url,
    ] {
        if value.len() > 4096 {
            return Err(queue_full());
        }
        add_bytes(&mut bytes, value.len())?;
    }
    for record in &snapshot.records {
        add_bytes(&mut bytes, attribute_bytes(&record.attributes)?)?;
        add_bytes(&mut bytes, record.body.len())?;
        add_bytes(&mut bytes, record.severity_text.len())?;
        add_bytes(&mut bytes, record.event_name.len())?;
        add_bytes(&mut bytes, record.trace_id.len())?;
        add_bytes(&mut bytes, record.span_id.len())?;
    }
    Ok(bytes)
}

fn encode_metrics(
    snapshot: &MetricsSnapshot,
    timestamp: u64,
    config: &OtlpHttpConfig,
) -> Result<Vec<u8>, ExportError> {
    use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
    use crate::observability::otlp_proto::common_and_resource::{InstrumentationScope, Resource};
    use crate::observability::otlp_proto::metrics::{
        Gauge, Histogram, HistogramDataPoint, Metric, MetricData, NumberDataPoint,
        NumberDataPointValue, ResourceMetrics, ScopeMetrics, Sum,
    };

    let mut metrics = BTreeMap::<&str, Metric>::new();
    for (name, labels, value) in &snapshot.counters {
        let point = NumberDataPoint {
            time_unix_nano: timestamp,
            value: Some(NumberDataPointValue::Int(i64::try_from(*value).map_err(
                |_| ExportError::new("otlp.queue.invalid_numeric_value"),
            )?)),
            attributes: owned_otlp_stream_attributes(labels)
                .map_err(|e| ExportError::new(e.to_string()))?,
            ..NumberDataPoint::default()
        };
        let metric = metrics.entry(name).or_insert_with(|| Metric {
            name: name.clone(),
            data: Some(MetricData::Sum(Sum {
                aggregation_temporality: 2,
                is_monotonic: true,
                ..Sum::default()
            })),
            ..Metric::default()
        });
        if let Some(MetricData::Sum(sum)) = &mut metric.data {
            sum.data_points.push(point);
        }
    }
    for (name, labels, value) in &snapshot.gauges {
        let point = NumberDataPoint {
            time_unix_nano: timestamp,
            value: Some(NumberDataPointValue::Int(*value)),
            attributes: owned_otlp_stream_attributes(labels)
                .map_err(|e| ExportError::new(e.to_string()))?,
            ..NumberDataPoint::default()
        };
        let metric = metrics.entry(name).or_insert_with(|| Metric {
            name: name.clone(),
            data: Some(MetricData::Gauge(Gauge::default())),
            ..Metric::default()
        });
        if let Some(MetricData::Gauge(gauge)) = &mut metric.data {
            gauge.data_points.push(point);
        }
    }
    for (name, labels, count, sum) in &snapshot.histograms {
        // The legacy snapshot carries totals, not explicit bucket boundaries.
        // A single +Inf bucket preserves that information without inventing a distribution.
        let point = HistogramDataPoint {
            time_unix_nano: timestamp,
            count: *count,
            sum: Some(*sum),
            bucket_counts: vec![*count],
            attributes: owned_otlp_stream_attributes(labels)
                .map_err(|e| ExportError::new(e.to_string()))?,
            ..HistogramDataPoint::default()
        };
        let metric = metrics.entry(name).or_insert_with(|| Metric {
            name: name.clone(),
            data: Some(MetricData::Histogram(Histogram {
                aggregation_temporality: 2,
                ..Histogram::default()
            })),
            ..Metric::default()
        });
        if let Some(MetricData::Histogram(histogram)) = &mut metric.data {
            histogram.data_points.push(point);
        }
    }
    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: owned_otlp_stream_attributes(&config.resource_attributes)
                    .map_err(|e| ExportError::new(e.to_string()))?,
                ..Resource::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "asupersync".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    ..InstrumentationScope::default()
                }),
                metrics: metrics.into_values().collect(),
                ..ScopeMetrics::default()
            }],
            ..ResourceMetrics::default()
        }],
        ..ExportMetricsServiceRequest::default()
    };
    request
        .encode_to_bytes(otlp_request_limits(OWNED_OTLP_DEFAULT_REQUEST_BYTES))
        .map(|bytes| bytes.to_vec())
        .map_err(|_| ExportError::new("otlp.queue.encoded_batch_too_large"))
}

#[cfg(test)]
#[path = "queued_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "queued_trace_tests.rs"]
mod trace_tests;
