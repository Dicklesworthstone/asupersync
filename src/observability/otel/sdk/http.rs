//! External SDK providers delivered through acknowledged native OTLP/HTTP.

use super::common::SdkResource;
use super::logs::{OtlpSdkLogConfig, OtlpSdkLogError, map_logs};
use super::metrics::{OtlpSdkMetricsConfig, OtlpSdkMetricsError, map_metrics};
use super::queue as delivery;
use super::traces::{OtlpSdkTraceConfig, OtlpSdkTraceError, map_traces, prepare_resource};
use crate::observability::otel::{OtlpSignal, OwnedOtlpExportPolicy, QueuedOtlpHttpExporter};
use opentelemetry::logs::Severity;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogBatch, LogExporter};
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// SDK cumulative metrics exported through a caller-managed native HTTP queue.
///
/// Install this exporter in the caller's SDK reader/provider, and start
/// [`QueuedOtlpHttpExporter::spawn_queued`] before SDK export. The adapter creates
/// no reader, cadence, thread, runtime, global provider or implicit endpoint.
/// The queue's metrics configuration supplies its exact URL, TLS/authentication,
/// compression and bounded request retry policy.
///
/// This uses the same typed, bounded mapper as [`super::OtlpSdkMetricExporter`]:
/// all four aggregation families, typed resource/scope schemas and attributes,
/// checked unsigned integer conversion, exemplars, and deterministic point
/// partitioning. The full collection is validated and encoded before atomic
/// admission. SDK metadata is authoritative; HTTP resource defaults are not
/// reapplied. An explicit policy filters owned typed values before encoding.
///
/// Success waits for every request's complete HTTP 200 protobuf acknowledgement,
/// including terminal partial success. Rejected points are available through
/// `queue().queue_stats()` and are never replayed as a whole collection.
///
/// Force-flush waits at most five seconds; shutdown uses the supplied timeout.
/// Call blocking SDK lifecycle methods outside the native runtime, or use the
/// managed handle's async drain/join path. SDK callbacks and reader/provider
/// blocking behavior are outside these bounds. Shutdown seals admission for
/// every clone sharing the queue, so independently managed providers should
/// use dedicated queues.
#[derive(Clone)]
pub struct OtlpSdkHttpMetricExporter {
    queue: QueuedOtlpHttpExporter,
    config: OtlpSdkMetricsConfig,
    policy: OwnedOtlpExportPolicy,
}

impl fmt::Debug for OtlpSdkHttpMetricExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpSdkHttpMetricExporter")
            .field("config", &self.config)
            .field("policy", &self.policy)
            .field("queue", &self.queue)
            .finish()
    }
}

impl OtlpSdkHttpMetricExporter {
    /// Wrap a caller-owned queue using finite default mapping limits.
    #[must_use]
    pub fn new(queue: QueuedOtlpHttpExporter) -> Self {
        Self {
            queue,
            config: OtlpSdkMetricsConfig::new(),
            policy: OwnedOtlpExportPolicy::new(),
        }
    }

    /// Validate every finite mapper bound before constructing an exporter.
    pub fn try_with_config(
        queue: QueuedOtlpHttpExporter,
        config: OtlpSdkMetricsConfig,
    ) -> Result<Self, OtlpSdkMetricsError> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new(queue)
        })
    }

    /// Filter typed values and override explicitly selected metadata.
    #[must_use]
    pub fn with_policy(mut self, policy: OwnedOtlpExportPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Shared queue for managed startup, partial counters and async drain/join.
    #[must_use]
    pub const fn queue(&self) -> &QueuedOtlpHttpExporter {
        &self.queue
    }

    /// Immutable validated mapper limits.
    #[must_use]
    pub const fn config(&self) -> &OtlpSdkMetricsConfig {
        &self.config
    }
}

impl PushMetricExporter for OtlpSdkHttpMetricExporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        delivery::export(&self.queue, OtlpSignal::Metrics, || {
            map_metrics(metrics, &self.policy, &self.config)
                .map(|mapped| mapped.into_parts().0)
                .map_err(|error| error.code())
        })
        .await
    }

    fn force_flush(&self) -> OTelSdkResult {
        delivery::force_flush(&self.queue, OtlpSignal::Metrics, FLUSH_TIMEOUT)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        delivery::shutdown(&self.queue, OtlpSignal::Metrics, timeout)
    }

    fn temporality(&self) -> Temporality {
        Temporality::Cumulative
    }
}

/// SDK spans exported through a caller-managed acknowledged HTTP queue.
///
/// Start [`QueuedOtlpHttpExporter::spawn_queued`] before the SDK processor exports.
/// Use the SDK batch processor, or emit with its simple processor only on a
/// thread outside the native runtime. Simple processors block on their own
/// exporter mutex before calling this adapter. The adapter's native-`Cx` guard
/// runs before mapping/admission but cannot prevent that upstream mutex wait.
///
/// The same mapper as [`super::OtlpSdkSpanExporter`] preserves typed resource and
/// scope schemas, events/links, producer dropped counts, timestamps and remote
/// context flags. It does not resample or require parents in one batch. Every
/// raw attribute update is validated before last-value-wins normalization.
/// Explicit policy applies before encoding. The complete collection is checked
/// before atomic admission, and the owned SDK span batch is dropped before the
/// first transport wait.
///
/// Export waits for every terminal collector acknowledgement. Partial success
/// is terminal and never replayed; rejected spans remain in queue statistics.
/// Endpoint, compression and request-scoped retry behavior come from the queue's
/// traces configuration. No SDK resource metadata is rewritten from HTTP defaults.
///
/// Invalid SDK resource updates latch a static failure without retaining source
/// values; a valid later update recovers. Force-flush has a five-second bound,
/// shutdown uses its supplied timeout, and SDK callbacks/processor/provider
/// blocking behavior remains outside those bounds. Blocking lifecycle calls
/// belong off the native runtime; managed drain/join is the async alternative.
/// Shutdown seals every clone of this queue. Dedicate a queue to each
/// independently managed SDK provider.
#[derive(Clone)]
pub struct OtlpSdkHttpSpanExporter {
    queue: QueuedOtlpHttpExporter,
    config: OtlpSdkTraceConfig,
    policy: OwnedOtlpExportPolicy,
    resource: Result<Arc<SdkResource>, OtlpSdkTraceError>,
}

impl fmt::Debug for OtlpSdkHttpSpanExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpSdkHttpSpanExporter")
            .field("config", &self.config)
            .field("policy", &self.policy)
            .field("queue", &self.queue)
            .field("resource_valid", &self.resource.is_ok())
            .field(
                "resource_attributes",
                &self
                    .resource
                    .as_ref()
                    .map_or(0, |resource| resource.resource.attributes.len()),
            )
            .finish()
    }
}

impl OtlpSdkHttpSpanExporter {
    /// Wrap a queue with finite defaults and an empty SDK resource.
    #[must_use]
    pub fn new(queue: QueuedOtlpHttpExporter) -> Self {
        Self {
            queue,
            config: OtlpSdkTraceConfig::new(),
            policy: OwnedOtlpExportPolicy::new(),
            resource: Ok(Arc::new(SdkResource::empty())),
        }
    }

    /// Validate every finite mapper bound before constructing an exporter.
    pub fn try_with_config(
        queue: QueuedOtlpHttpExporter,
        config: OtlpSdkTraceConfig,
    ) -> Result<Self, OtlpSdkTraceError> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new(queue)
        })
    }

    /// Apply an immutable resource/scope/privacy policy.
    #[must_use]
    pub fn with_policy(mut self, policy: OwnedOtlpExportPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Shared queue for managed startup, partial counters and async drain/join.
    #[must_use]
    pub const fn queue(&self) -> &QueuedOtlpHttpExporter {
        &self.queue
    }

    /// Immutable validated mapper limits.
    #[must_use]
    pub const fn config(&self) -> &OtlpSdkTraceConfig {
        &self.config
    }
}

impl SpanExporter for OtlpSdkHttpSpanExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        delivery::export(&self.queue, OtlpSignal::Traces, move || {
            let resource = self.resource.as_ref().map_err(|error| error.code())?;
            let mapped = map_traces(&batch, resource, &self.policy, &self.config);
            // Source Vec/String spare capacities cannot survive a delivery wait.
            drop(batch);
            mapped
                .map(|mapped| mapped.into_parts().0)
                .map_err(|error| error.code())
        })
        .await
    }

    fn force_flush(&self) -> OTelSdkResult {
        delivery::force_flush(&self.queue, OtlpSignal::Traces, FLUSH_TIMEOUT)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        delivery::shutdown(&self.queue, OtlpSignal::Traces, timeout)
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.resource = prepare_resource(resource, &self.config).map(Arc::new);
    }
}

/// Typed SDK logs exported through a caller-managed acknowledged HTTP queue.
///
/// The caller installs/owns its SDK provider and processor and starts
/// [`QueuedOtlpHttpExporter::spawn_queued`]. Use a batch processor, or emit with
/// the simple processor only off the native runtime. Its exporter mutex may
/// block before this adapter's active-`Cx` refusal is invoked.
///
/// Mapping is shared with [`super::OtlpSdkLogExporter`]. Nested typed bodies and
/// attributes, severity, event name, trace correlation, independent resource and
/// scope schemas, and target-to-scope precedence are preserved. Bytes remain
/// opaque under privacy rules; omit the body or drop its key when binary data
/// must not be exported. Raw updates are validated before last-value-wins
/// normalization. SDK 0.32 exposes no source attribute-drop counter for logs.
/// Explicit policy runs before encoding, and the whole borrowed collection is
/// checked before any request is admitted. Transport resource defaults are not
/// reapplied.
///
/// Success awaits terminal acknowledgements for all requests. Partial success
/// never causes whole-batch replay; rejected records remain in queue statistics.
/// The logs configuration controls the exact endpoint, TLS/authentication,
/// compression and bounded request retries. No provider/thread/runtime is created.
///
/// Invalid resource updates latch static errors and can be replaced by later
/// valid updates. The SDK log exporter trait has no flush hook:
/// [`Self::force_flush_queue`] observes already admitted native work only.
/// Shutdown seals every clone sharing the queue; dedicate a queue to each
/// independently managed provider. Blocking lifecycle calls belong off the
/// native runtime, or use managed async drain/join. SDK callbacks and
/// processor/provider blocking behavior are outside adapter timeout guarantees.
#[derive(Clone)]
pub struct OtlpSdkHttpLogExporter {
    queue: QueuedOtlpHttpExporter,
    config: OtlpSdkLogConfig,
    policy: OwnedOtlpExportPolicy,
    resource: Result<Arc<SdkResource>, OtlpSdkLogError>,
}

impl fmt::Debug for OtlpSdkHttpLogExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpSdkHttpLogExporter")
            .field("config", &self.config)
            .field("policy", &self.policy)
            .field("queue", &self.queue)
            .field("resource_valid", &self.resource.is_ok())
            .field(
                "resource_attributes",
                &self
                    .resource
                    .as_ref()
                    .map_or(0, |resource| resource.resource.attributes.len()),
            )
            .finish()
    }
}

impl OtlpSdkHttpLogExporter {
    /// Wrap a queue with finite defaults and an empty SDK resource.
    #[must_use]
    pub fn new(queue: QueuedOtlpHttpExporter) -> Self {
        Self {
            queue,
            config: OtlpSdkLogConfig::new(),
            policy: OwnedOtlpExportPolicy::new(),
            resource: Ok(Arc::new(SdkResource::empty())),
        }
    }

    /// Validate every finite mapper bound before constructing an exporter.
    pub fn try_with_config(
        queue: QueuedOtlpHttpExporter,
        config: OtlpSdkLogConfig,
    ) -> Result<Self, OtlpSdkLogError> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new(queue)
        })
    }

    /// Apply an immutable resource/scope/privacy policy.
    #[must_use]
    pub fn with_policy(mut self, policy: OwnedOtlpExportPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Shared queue for managed startup, partial counters and async drain/join.
    #[must_use]
    pub const fn queue(&self) -> &QueuedOtlpHttpExporter {
        &self.queue
    }

    /// Immutable validated mapper limits.
    #[must_use]
    pub const fn config(&self) -> &OtlpSdkLogConfig {
        &self.config
    }

    /// Observe admitted native work within `timeout`; this does not flush the
    /// SDK processor's own buffer. Pending native-context blocking waits refuse.
    pub fn force_flush_queue(&self, timeout: Duration) -> OTelSdkResult {
        delivery::force_flush(&self.queue, OtlpSignal::Logs, timeout)
    }
}

impl LogExporter for OtlpSdkHttpLogExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        delivery::export(&self.queue, OtlpSignal::Logs, move || {
            let resource = self.resource.as_ref().map_err(|error| error.code())?;
            // Only bounded encoded bytes are owned by the native queue.
            map_logs(&batch, resource, &self.policy, &self.config)
                .map(|mapped| mapped.into_parts().0)
                .map_err(|error| error.code())
        })
        .await
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        delivery::shutdown(&self.queue, OtlpSignal::Logs, timeout)
    }

    fn event_enabled(&self, _: Severity, _: &str, _: Option<&str>) -> bool {
        // Emission may happen on a native task before an SDK batch worker exports.
        true
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.resource = SdkResource::prepare(resource, self.config.max_collection_bytes())
            .map(Arc::new)
            .map_err(Into::into);
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
