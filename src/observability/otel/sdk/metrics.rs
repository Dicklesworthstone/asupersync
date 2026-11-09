//! Bounded OpenTelemetry SDK 0.32 metrics mapping and acknowledged delivery.

use super::common::{self, SdkValueError, ValueBudget, attribute_nodes};
use crate::grpc::protobuf::ProtoMessage;
use crate::observability::otel::export_policy::compare_policy_attributes;
use crate::observability::otel::{
    OtlpGrpcSignal, OwnedOtlpExportPolicy, OwnedOtlpPolicyError, OwnedOtlpPolicyOutput,
    OwnedOtlpPolicyReport, QueuedOtlpGrpcExporter,
};
use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{
    InstrumentationScope, KeyValue, Resource,
};
use crate::observability::otlp_proto::metrics::{
    AggregationTemporality, Exemplar, ExemplarValue, ExponentialHistogram,
    ExponentialHistogramBuckets, ExponentialHistogramDataPoint, Gauge, Histogram,
    HistogramDataPoint, Metric, MetricData, NumberDataPoint, NumberDataPointValue, ResourceMetrics,
    ScopeMetrics, Sum,
};
use opentelemetry::Value;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::data::{
    self as sdk, AggregatedMetrics, MetricData as SdkMetricData,
};
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use std::cmp::Ordering;
use std::fmt;
use std::time::{Duration, SystemTime};

#[path = "metrics_batch.rs"]
mod batch;
use batch::MetricsRequests;

const MAX_SCOPES: usize = 128;
const MAX_METRICS: usize = 4096;
const MAX_POINTS: usize = 16_384;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUESTS: usize = 64;
const MAX_EXEMPLARS: usize = 128;
const MAX_BUCKETS: usize = 4096;
const POINTS_PER_METRIC_REQUEST: usize = 1000;
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Value-free admission/mapping errors for the native SDK metrics adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtlpSdkMetricsError {
    /// A configured finite limit is zero or exceeds the supported maximum.
    InvalidConfiguration,
    /// A collection, attribute, array, exemplar, bucket, or request bound failed.
    LimitExceeded,
    /// An attribute is empty, duplicated, oversized, or unsupported.
    InvalidAttributes,
    /// A number is non-finite or cannot be represented in its OTLP field.
    InvalidNumericValue,
    /// A timestamp predates the epoch, is zero where required, or overflows u64.
    InvalidTimestamp,
    /// The adapter admits cumulative aggregation, as selected by its exporter.
    UnsupportedTemporality,
    /// Histogram bounds, bucket counts, or totals are inconsistent.
    InvalidHistogram,
    /// Distinct source series have the same final scope/metric/attribute identity.
    SeriesCollision,
    /// The shared explicit policy rejected a mapped model.
    Policy(OwnedOtlpPolicyError),
    /// The owned protobuf schema rejected the finite request.
    WireEnvelopeExceeded,
}

impl OtlpSdkMetricsError {
    /// Stable machine-readable diagnostic without telemetry or configuration text.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "otlp.sdk.metrics.invalid_configuration",
            Self::LimitExceeded => "otlp.sdk.metrics.limit_exceeded",
            Self::InvalidAttributes => "otlp.sdk.metrics.invalid_attributes",
            Self::InvalidNumericValue => "otlp.sdk.metrics.invalid_numeric_value",
            Self::InvalidTimestamp => "otlp.sdk.metrics.invalid_timestamp",
            Self::UnsupportedTemporality => "otlp.sdk.metrics.unsupported_temporality",
            Self::InvalidHistogram => "otlp.sdk.metrics.invalid_histogram",
            Self::SeriesCollision => "otlp.sdk.metrics.series_collision",
            Self::Policy(error) => error.code(),
            Self::WireEnvelopeExceeded => "otlp.sdk.metrics.wire_envelope_exceeded",
        }
    }
}

impl fmt::Display for OtlpSdkMetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for OtlpSdkMetricsError {}

impl From<OwnedOtlpPolicyError> for OtlpSdkMetricsError {
    fn from(error: OwnedOtlpPolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<SdkValueError> for OtlpSdkMetricsError {
    fn from(error: SdkValueError) -> Self {
        match error {
            SdkValueError::LimitExceeded => Self::LimitExceeded,
            SdkValueError::InvalidAttributes => Self::InvalidAttributes,
            SdkValueError::InvalidNumericValue => Self::InvalidNumericValue,
            SdkValueError::InvalidTimestamp => Self::InvalidTimestamp,
        }
    }
}

/// Finite, immutable limits admitted by [`OtlpSdkMetricExporter::try_with_config`].
///
/// The default admits at most 128 scopes, 4096 metrics, 16384 points, and 4 MiB
/// of input accounting and final encoded requests. Individual point/attribute
/// arrays, exemplars, and buckets also retain the owned protobuf schema bounds.
/// Container storage is charged conservatively before copying SDK input.
/// Collections produce at most 64 requests. Distinct SDK scopes retain their
/// metadata while sharing bounded requests. Large metrics split at point
/// boundaries without changing their cumulative start time or duplicating a
/// descriptor for the same scope within a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtlpSdkMetricsConfig {
    max_scopes: usize,
    max_metrics: usize,
    max_data_points: usize,
    max_collection_bytes: usize,
    max_request_bytes: usize,
}

impl Default for OtlpSdkMetricsConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl OtlpSdkMetricsConfig {
    /// Construct the finite defaults without creating a provider or worker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_scopes: MAX_SCOPES,
            max_metrics: MAX_METRICS,
            max_data_points: MAX_POINTS,
            max_collection_bytes: MAX_BYTES,
            max_request_bytes: MAX_BYTES,
        }
    }

    /// Set the collection's instrumentation-scope bound, at most 128.
    #[must_use]
    pub const fn with_max_scopes(mut self, limit: usize) -> Self {
        self.max_scopes = limit;
        self
    }

    /// Set the collection's metric bound, at most 4096.
    #[must_use]
    pub const fn with_max_metrics(mut self, limit: usize) -> Self {
        self.max_metrics = limit;
        self
    }

    /// Set the collection's data-point bound, at most 16384.
    #[must_use]
    pub const fn with_max_data_points(mut self, limit: usize) -> Self {
        self.max_data_points = limit;
        self
    }

    /// Set the input-accounting and aggregate encoded-request bound, at most 4 MiB.
    #[must_use]
    pub const fn with_max_collection_bytes(mut self, limit: usize) -> Self {
        self.max_collection_bytes = limit;
        self
    }

    /// Set the byte bound for each request, at most 4 MiB. The native channel's
    /// smaller configured limit still applies at atomic queue admission.
    #[must_use]
    pub const fn with_max_request_bytes(mut self, limit: usize) -> Self {
        self.max_request_bytes = limit;
        self
    }

    /// Admitted instrumentation scopes per collection.
    #[must_use]
    pub const fn max_scopes(&self) -> usize {
        self.max_scopes
    }
    /// Admitted metrics per collection.
    #[must_use]
    pub const fn max_metrics(&self) -> usize {
        self.max_metrics
    }
    /// Admitted points per collection.
    #[must_use]
    pub const fn max_data_points(&self) -> usize {
        self.max_data_points
    }
    /// Input accounting and aggregate encoded-request limit.
    #[must_use]
    pub const fn max_collection_bytes(&self) -> usize {
        self.max_collection_bytes
    }
    /// Encoded-request limit before any smaller native channel bound.
    #[must_use]
    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    fn validate(self) -> Result<(), OtlpSdkMetricsError> {
        if self.max_scopes == 0
            || self.max_scopes > MAX_SCOPES
            || self.max_metrics == 0
            || self.max_metrics > MAX_METRICS
            || self.max_data_points == 0
            || self.max_data_points > MAX_POINTS
            || self.max_collection_bytes == 0
            || self.max_collection_bytes > MAX_BYTES
            || self.max_request_bytes == 0
            || self.max_request_bytes > MAX_BYTES
        {
            return Err(OtlpSdkMetricsError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// An OpenTelemetry SDK metrics exporter backed by a caller-managed native queue.
///
/// Install this exporter into the caller's SDK reader/provider and start the
/// supplied queue with `spawn_queued` before SDK export. The adapter creates no
/// thread, reader cadence, global provider, or runtime. The managed child task
/// supplies the actual request `Cx`; a stale captured task context is not used.
///
/// Export success means every request has a terminal collector response,
/// including valid partial success. Rejections are inspectable through the
/// queue's signal-specific counters and are never replayed as a whole SDK
/// collection. Retries, when enabled on the queue, remain request-scoped.
///
/// SDK resource and scope metadata are authoritative. Transport resource
/// defaults are not reapplied to encoded SDK requests. The optional shared
/// policy overrides selected metadata and filters typed values before admission.
/// Metric names, descriptions, units, and producer timestamps are preserved.
/// Unsigned number/exemplar values above `i64::MAX` are rejected instead of
/// silently becoming zero. Histogram numeric fields use OTLP double conversion.
///
/// Synchronous flush waits at most five seconds; shutdown honors its supplied
/// timeout. Call blocking SDK lifecycle methods off the native runtime thread.
/// The queue rejects a blocking wait in an active native context when work is
/// pending. Use the managed handle's drain/join path for native async shutdown.
/// Upstream SDK observable callbacks and reader/provider blocking behavior are
/// outside this adapter's timeout guarantee.
///
/// Shutdown seals admission for **every clone sharing the supplied queue**.
/// Use a dedicated queue for each independently managed SDK provider. Existing
/// external providers and readers remain available and are not replaced.
#[derive(Clone)]
pub struct OtlpSdkMetricExporter {
    queue: QueuedOtlpGrpcExporter,
    config: OtlpSdkMetricsConfig,
    policy: OwnedOtlpExportPolicy,
}

impl fmt::Debug for OtlpSdkMetricExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpSdkMetricExporter")
            .field("config", &self.config)
            .field("policy", &self.policy)
            .field("queue", &self.queue)
            .finish()
    }
}

impl OtlpSdkMetricExporter {
    /// Wrap a caller-owned queue using finite default mapping limits.
    #[must_use]
    pub fn new(queue: QueuedOtlpGrpcExporter) -> Self {
        Self {
            queue,
            config: OtlpSdkMetricsConfig::new(),
            policy: OwnedOtlpExportPolicy::new(),
        }
    }

    /// Wrap a queue after validating every finite mapper limit.
    pub fn try_with_config(
        queue: QueuedOtlpGrpcExporter,
        config: OtlpSdkMetricsConfig,
    ) -> Result<Self, OtlpSdkMetricsError> {
        config.validate()?;
        Ok(Self {
            queue,
            config,
            policy: OwnedOtlpExportPolicy::new(),
        })
    }

    /// Apply an already validated immutable policy to future collections.
    #[must_use]
    pub fn with_policy(mut self, policy: OwnedOtlpExportPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The shared queue, for managed startup, async drain, and rejection counters.
    #[must_use]
    pub const fn queue(&self) -> &QueuedOtlpGrpcExporter {
        &self.queue
    }

    /// Validated immutable mapper limits.
    #[must_use]
    pub const fn config(&self) -> &OtlpSdkMetricsConfig {
        &self.config
    }
}

impl PushMetricExporter for OtlpSdkMetricExporter {
    async fn export(&self, metrics: &sdk::ResourceMetrics) -> OTelSdkResult {
        self.queue
            .ensure_managed_active()
            .map_err(|_| sdk_error("otlp.sdk.metrics.owner_unavailable"))?;
        let (requests, _) = map_metrics(metrics, &self.policy, &self.config)
            .map_err(|error| sdk_error(error.code()))?
            .into_parts();
        self.queue
            .enqueue_encoded_with_receipt(OtlpGrpcSignal::Metrics, requests)
            .map_err(|_| sdk_error("otlp.sdk.metrics.admission_refused"))?
            .await
            .map(|_| ())
            .map_err(|error| sdk_error(error.code()))
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.queue
            .force_flush_blocking(FLUSH_TIMEOUT)
            .map_err(|_| sdk_error("otlp.sdk.metrics.flush_incomplete"))
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.queue
            .shutdown_blocking(timeout)
            .map_err(|_| sdk_error("otlp.sdk.metrics.shutdown_incomplete"))
    }

    fn temporality(&self) -> Temporality {
        Temporality::Cumulative
    }
}

fn sdk_error(code: &'static str) -> OTelSdkError {
    OTelSdkError::InternalFailure(code.to_owned())
}

struct InputBudget {
    config: OtlpSdkMetricsConfig,
    values: ValueBudget,
    points: usize,
    metrics: usize,
    scopes: usize,
}

impl InputBudget {
    fn new(config: OtlpSdkMetricsConfig) -> Self {
        Self {
            config,
            values: ValueBudget::new(config.max_collection_bytes),
            points: 0,
            metrics: 0,
            scopes: 0,
        }
    }

    fn bytes(&mut self, amount: usize) -> Result<(), OtlpSdkMetricsError> {
        self.values.bytes(amount).map_err(Into::into)
    }

    fn text(&mut self, text: &str, limit: usize) -> Result<(), OtlpSdkMetricsError> {
        self.values.text(text, limit).map_err(Into::into)
    }

    fn attributes<'a>(
        &mut self,
        attributes: impl Iterator<Item = (&'a str, &'a Value)>,
    ) -> Result<(), OtlpSdkMetricsError> {
        self.values.attributes(attributes).map_err(Into::into)
    }

    fn point(&mut self, storage: usize) -> Result<(), OtlpSdkMetricsError> {
        self.points = self
            .points
            .checked_add(1)
            .filter(|count| *count <= self.config.max_data_points)
            .ok_or(OtlpSdkMetricsError::LimitExceeded)?;
        self.bytes(storage)
    }
}

trait Numeric: Copy {
    fn number(self) -> Result<NumberDataPointValue, OtlpSdkMetricsError>;
    fn double(self) -> Result<f64, OtlpSdkMetricsError>;

    fn exemplar(self) -> Result<ExemplarValue, OtlpSdkMetricsError> {
        self.number().map(|value| match value {
            NumberDataPointValue::Int(value) => ExemplarValue::Int(value),
            NumberDataPointValue::Double(value) => ExemplarValue::Double(value),
        })
    }
}

impl Numeric for u64 {
    fn number(self) -> Result<NumberDataPointValue, OtlpSdkMetricsError> {
        i64::try_from(self)
            .map(NumberDataPointValue::Int)
            .map_err(|_| OtlpSdkMetricsError::InvalidNumericValue)
    }
    fn double(self) -> Result<f64, OtlpSdkMetricsError> {
        Ok(self as f64)
    }
}

impl Numeric for i64 {
    fn number(self) -> Result<NumberDataPointValue, OtlpSdkMetricsError> {
        Ok(NumberDataPointValue::Int(self))
    }
    fn double(self) -> Result<f64, OtlpSdkMetricsError> {
        Ok(self as f64)
    }
}

impl Numeric for f64 {
    fn number(self) -> Result<NumberDataPointValue, OtlpSdkMetricsError> {
        finite(self).map(NumberDataPointValue::Double)
    }
    fn double(self) -> Result<f64, OtlpSdkMetricsError> {
        finite(self)
    }
}

fn finite(value: f64) -> Result<f64, OtlpSdkMetricsError> {
    common::finite(value).map_err(Into::into)
}

fn nanos(time: SystemTime, zero_allowed: bool) -> Result<u64, OtlpSdkMetricsError> {
    common::nanos(time, zero_allowed).map_err(Into::into)
}

fn times(start: Option<SystemTime>, end: SystemTime) -> Result<(u64, u64), OtlpSdkMetricsError> {
    let start = start
        .map(|time| nanos(time, true))
        .transpose()?
        .unwrap_or(0);
    let end = nanos(end, false)?;
    if start > end {
        return Err(OtlpSdkMetricsError::InvalidTimestamp);
    }
    Ok((start, end))
}

fn cumulative(temporality: Temporality) -> Result<i32, OtlpSdkMetricsError> {
    match temporality {
        Temporality::Cumulative => Ok(AggregationTemporality::Cumulative.as_raw()),
        _ => Err(OtlpSdkMetricsError::UnsupportedTemporality),
    }
}

fn preflight_exemplars<'a, T: Numeric + 'a>(
    values: impl Iterator<Item = &'a sdk::Exemplar<T>>,
    budget: &mut InputBudget,
) -> Result<(), OtlpSdkMetricsError> {
    for (index, exemplar) in values.enumerate() {
        if index == MAX_EXEMPLARS {
            return Err(OtlpSdkMetricsError::LimitExceeded);
        }
        budget.bytes(std::mem::size_of::<Exemplar>().saturating_add(24))?;
        budget.attributes(
            exemplar
                .filtered_attributes()
                .map(|kv| (kv.key.as_str(), &kv.value)),
        )?;
        exemplar.value.exemplar()?;
        nanos(exemplar.time(), false)?;
    }
    Ok(())
}

fn preflight_histogram_values<T: Numeric>(
    min: Option<T>,
    max: Option<T>,
    sum: T,
    count: u64,
) -> Result<(), OtlpSdkMetricsError> {
    let min = min.map(Numeric::double).transpose()?;
    let max = max.map(Numeric::double).transpose()?;
    let sum = sum.double()?;
    if min.zip(max).is_some_and(|(min, max)| min > max) || (count == 0 && sum != 0.0) {
        return Err(OtlpSdkMetricsError::InvalidHistogram);
    }
    Ok(())
}

fn preflight_bucket_counts(
    bucket: &sdk::ExponentialBucket,
    budget: &mut InputBudget,
) -> Result<u64, OtlpSdkMetricsError> {
    let mut len = 0usize;
    let mut total = 0u64;
    for count in bucket.counts() {
        if len == MAX_BUCKETS {
            return Err(OtlpSdkMetricsError::LimitExceeded);
        }
        budget.bytes(std::mem::size_of::<u64>())?;
        total = total
            .checked_add(count)
            .ok_or(OtlpSdkMetricsError::InvalidHistogram)?;
        len += 1;
    }
    if len > 0 {
        let extent = i32::try_from(len - 1).map_err(|_| OtlpSdkMetricsError::InvalidHistogram)?;
        bucket
            .offset()
            .checked_add(extent)
            .ok_or(OtlpSdkMetricsError::InvalidHistogram)?;
    }
    Ok(total)
}

fn preflight_data<T: Numeric>(
    data: &SdkMetricData<T>,
    budget: &mut InputBudget,
) -> Result<(), OtlpSdkMetricsError> {
    match data {
        SdkMetricData::Gauge(gauge) => {
            times(gauge.start_time(), gauge.time())?;
            for point in gauge.data_points() {
                budget.point(std::mem::size_of::<NumberDataPoint>())?;
                budget.attributes(point.attributes().map(|kv| (kv.key.as_str(), &kv.value)))?;
                point.value().number()?;
                preflight_exemplars(point.exemplars(), budget)?;
            }
        }
        SdkMetricData::Sum(sum) => {
            times(Some(sum.start_time()), sum.time())?;
            cumulative(sum.temporality())?;
            for point in sum.data_points() {
                budget.point(std::mem::size_of::<NumberDataPoint>())?;
                budget.attributes(point.attributes().map(|kv| (kv.key.as_str(), &kv.value)))?;
                point.value().number()?;
                preflight_exemplars(point.exemplars(), budget)?;
            }
        }
        SdkMetricData::Histogram(histogram) => {
            times(Some(histogram.start_time()), histogram.time())?;
            cumulative(histogram.temporality())?;
            for point in histogram.data_points() {
                budget.point(std::mem::size_of::<HistogramDataPoint>())?;
                budget.attributes(point.attributes().map(|kv| (kv.key.as_str(), &kv.value)))?;
                preflight_histogram_values(point.min(), point.max(), point.sum(), point.count())?;
                let mut bounds = 0usize;
                let mut previous = None;
                for value in point.bounds() {
                    finite(value)?;
                    if bounds >= MAX_BUCKETS - 1
                        || previous.is_some_and(|previous| value <= previous)
                    {
                        return Err(OtlpSdkMetricsError::InvalidHistogram);
                    }
                    budget.bytes(std::mem::size_of::<f64>())?;
                    previous = Some(value);
                    bounds += 1;
                }
                let mut buckets = 0usize;
                let mut total = 0u64;
                for count in point.bucket_counts() {
                    if buckets == MAX_BUCKETS {
                        return Err(OtlpSdkMetricsError::LimitExceeded);
                    }
                    budget.bytes(std::mem::size_of::<u64>())?;
                    total = total
                        .checked_add(count)
                        .ok_or(OtlpSdkMetricsError::InvalidHistogram)?;
                    buckets += 1;
                }
                if (buckets == 0 && bounds != 0)
                    || (buckets != 0 && (buckets != bounds + 1 || total != point.count()))
                {
                    return Err(OtlpSdkMetricsError::InvalidHistogram);
                }
                preflight_exemplars(point.exemplars(), budget)?;
            }
        }
        SdkMetricData::ExponentialHistogram(histogram) => {
            times(Some(histogram.start_time()), histogram.time())?;
            cumulative(histogram.temporality())?;
            for point in histogram.data_points() {
                budget.point(std::mem::size_of::<ExponentialHistogramDataPoint>())?;
                budget.attributes(point.attributes().map(|kv| (kv.key.as_str(), &kv.value)))?;
                let count = u64::try_from(point.count())
                    .map_err(|_| OtlpSdkMetricsError::InvalidHistogram)?;
                preflight_histogram_values(point.min(), point.max(), point.sum(), count)?;
                if finite(point.zero_threshold())? < 0.0 {
                    return Err(OtlpSdkMetricsError::InvalidHistogram);
                }
                let positive = preflight_bucket_counts(point.positive_bucket(), budget)?;
                let negative = preflight_bucket_counts(point.negative_bucket(), budget)?;
                let total = positive
                    .checked_add(negative)
                    .and_then(|value| value.checked_add(point.zero_count()));
                if total != Some(count) {
                    return Err(OtlpSdkMetricsError::InvalidHistogram);
                }
                preflight_exemplars(point.exemplars(), budget)?;
            }
        }
    }
    Ok(())
}

fn preflight(
    metrics: &sdk::ResourceMetrics,
    policy: &OwnedOtlpExportPolicy,
    config: &OtlpSdkMetricsConfig,
) -> Result<(), OtlpSdkMetricsError> {
    let mut budget = InputBudget::new(*config);
    budget.bytes(
        std::mem::size_of::<ResourceMetrics>().saturating_add(std::mem::size_of::<Resource>()),
    )?;
    budget.attributes(
        metrics
            .resource()
            .iter()
            .map(|(key, value)| (key.as_str(), value)),
    )?;
    budget.text(metrics.resource().schema_url().unwrap_or_default(), 2048)?;
    for scope in metrics.scope_metrics() {
        budget.scopes += 1;
        if budget.scopes > config.max_scopes {
            return Err(OtlpSdkMetricsError::LimitExceeded);
        }
        budget.bytes(
            std::mem::size_of::<ScopeMetrics>()
                .saturating_add(std::mem::size_of::<InstrumentationScope>()),
        )?;
        budget.text(scope.scope().name(), 1024)?;
        budget.text(scope.scope().version().unwrap_or_default(), 1024)?;
        budget.text(scope.scope().schema_url().unwrap_or_default(), 2048)?;
        budget.attributes(
            scope
                .scope()
                .attributes()
                .map(|kv| (kv.key.as_str(), &kv.value)),
        )?;
        for metric in scope.metrics() {
            budget.metrics += 1;
            if budget.metrics > config.max_metrics {
                return Err(OtlpSdkMetricsError::LimitExceeded);
            }
            budget.bytes(std::mem::size_of::<Metric>())?;
            budget.text(metric.name(), 1024)?;
            budget.text(metric.description(), 4096)?;
            budget.text(metric.unit(), 256)?;
            match metric.data() {
                AggregatedMetrics::F64(data) => preflight_data(data, &mut budget)?,
                AggregatedMetrics::U64(data) => preflight_data(data, &mut budget)?,
                AggregatedMetrics::I64(data) => preflight_data(data, &mut budget)?,
            }
        }
    }
    let (resource_bytes, scope_bytes) = policy.sdk_metadata_reserve();
    budget.bytes(resource_bytes.saturating_add(scope_bytes.saturating_mul(budget.scopes)))?;
    Ok(())
}

fn owned_attributes<'a>(
    attributes: impl Iterator<Item = (&'a str, &'a Value)>,
) -> Result<Vec<KeyValue>, OtlpSdkMetricsError> {
    common::owned_attributes(attributes).map_err(Into::into)
}

fn owned_exemplars<'a, T: Numeric + 'a>(
    values: impl Iterator<Item = &'a sdk::Exemplar<T>>,
) -> Result<Vec<Exemplar>, OtlpSdkMetricsError> {
    values
        .map(|exemplar| {
            Ok(Exemplar {
                time_unix_nano: nanos(exemplar.time(), false)?,
                value: Some(exemplar.value.exemplar()?),
                span_id: if exemplar.span_id().iter().any(|byte| *byte != 0) {
                    exemplar.span_id().to_vec()
                } else {
                    Vec::new()
                },
                trace_id: if exemplar.trace_id().iter().any(|byte| *byte != 0) {
                    exemplar.trace_id().to_vec()
                } else {
                    Vec::new()
                },
                filtered_attributes: owned_attributes(
                    exemplar
                        .filtered_attributes()
                        .map(|kv| (kv.key.as_str(), &kv.value)),
                )?,
                ..Exemplar::default()
            })
        })
        .collect()
}

fn owned_data<T: Numeric>(data: &SdkMetricData<T>) -> Result<MetricData, OtlpSdkMetricsError> {
    Ok(match data {
        SdkMetricData::Gauge(gauge) => {
            let (start_time_unix_nano, time_unix_nano) = times(gauge.start_time(), gauge.time())?;
            MetricData::Gauge(Gauge {
                data_points: gauge
                    .data_points()
                    .map(|point| {
                        Ok(NumberDataPoint {
                            start_time_unix_nano,
                            time_unix_nano,
                            value: Some(point.value().number()?),
                            exemplars: owned_exemplars(point.exemplars())?,
                            attributes: owned_attributes(
                                point.attributes().map(|kv| (kv.key.as_str(), &kv.value)),
                            )?,
                            ..NumberDataPoint::default()
                        })
                    })
                    .collect::<Result<Vec<_>, OtlpSdkMetricsError>>()?,
                ..Gauge::default()
            })
        }
        SdkMetricData::Sum(sum) => {
            let (start_time_unix_nano, time_unix_nano) = times(Some(sum.start_time()), sum.time())?;
            MetricData::Sum(Sum {
                aggregation_temporality: cumulative(sum.temporality())?,
                is_monotonic: sum.is_monotonic(),
                data_points: sum
                    .data_points()
                    .map(|point| {
                        Ok(NumberDataPoint {
                            start_time_unix_nano,
                            time_unix_nano,
                            value: Some(point.value().number()?),
                            exemplars: owned_exemplars(point.exemplars())?,
                            attributes: owned_attributes(
                                point.attributes().map(|kv| (kv.key.as_str(), &kv.value)),
                            )?,
                            ..NumberDataPoint::default()
                        })
                    })
                    .collect::<Result<Vec<_>, OtlpSdkMetricsError>>()?,
                ..Sum::default()
            })
        }
        SdkMetricData::Histogram(histogram) => {
            let (start_time_unix_nano, time_unix_nano) =
                times(Some(histogram.start_time()), histogram.time())?;
            MetricData::Histogram(Histogram {
                aggregation_temporality: cumulative(histogram.temporality())?,
                data_points: histogram
                    .data_points()
                    .map(|point| {
                        Ok(HistogramDataPoint {
                            start_time_unix_nano,
                            time_unix_nano,
                            count: point.count(),
                            sum: Some(point.sum().double()?),
                            min: point.min().map(Numeric::double).transpose()?,
                            max: point.max().map(Numeric::double).transpose()?,
                            bucket_counts: point.bucket_counts().collect(),
                            explicit_bounds: point.bounds().collect(),
                            exemplars: owned_exemplars(point.exemplars())?,
                            attributes: owned_attributes(
                                point.attributes().map(|kv| (kv.key.as_str(), &kv.value)),
                            )?,
                            ..HistogramDataPoint::default()
                        })
                    })
                    .collect::<Result<Vec<_>, OtlpSdkMetricsError>>()?,
                ..Histogram::default()
            })
        }
        SdkMetricData::ExponentialHistogram(histogram) => {
            let (start_time_unix_nano, time_unix_nano) =
                times(Some(histogram.start_time()), histogram.time())?;
            MetricData::ExponentialHistogram(ExponentialHistogram {
                aggregation_temporality: cumulative(histogram.temporality())?,
                data_points: histogram
                    .data_points()
                    .map(|point| {
                        Ok(ExponentialHistogramDataPoint {
                            start_time_unix_nano,
                            time_unix_nano,
                            count: u64::try_from(point.count())
                                .map_err(|_| OtlpSdkMetricsError::InvalidHistogram)?,
                            sum: Some(point.sum().double()?),
                            min: point.min().map(Numeric::double).transpose()?,
                            max: point.max().map(Numeric::double).transpose()?,
                            scale: i32::from(point.scale()),
                            zero_count: point.zero_count(),
                            zero_threshold: point.zero_threshold(),
                            positive: Some(ExponentialHistogramBuckets {
                                offset: point.positive_bucket().offset(),
                                bucket_counts: point.positive_bucket().counts().collect(),
                                ..ExponentialHistogramBuckets::default()
                            }),
                            negative: Some(ExponentialHistogramBuckets {
                                offset: point.negative_bucket().offset(),
                                bucket_counts: point.negative_bucket().counts().collect(),
                                ..ExponentialHistogramBuckets::default()
                            }),
                            exemplars: owned_exemplars(point.exemplars())?,
                            attributes: owned_attributes(
                                point.attributes().map(|kv| (kv.key.as_str(), &kv.value)),
                            )?,
                            ..ExponentialHistogramDataPoint::default()
                        })
                    })
                    .collect::<Result<Vec<_>, OtlpSdkMetricsError>>()?,
                ..ExponentialHistogram::default()
            })
        }
    })
}

fn metric_kind(metric: &Metric) -> (u8, i32, bool) {
    match metric.data.as_ref() {
        Some(MetricData::Gauge(_)) => (1, 0, false),
        Some(MetricData::Sum(data)) => (2, data.aggregation_temporality, data.is_monotonic),
        Some(MetricData::Histogram(data)) => (3, data.aggregation_temporality, false),
        Some(MetricData::ExponentialHistogram(data)) => (4, data.aggregation_temporality, false),
        Some(MetricData::Summary(_)) => (5, 0, false),
        None => (0, 0, false),
    }
}

fn compare_metric(left: &Metric, right: &Metric) -> Ordering {
    (left.name.as_str(), left.unit.as_str(), metric_kind(left)).cmp(&(
        right.name.as_str(),
        right.unit.as_str(),
        metric_kind(right),
    ))
}

fn point_attributes(metric: &Metric) -> Vec<&[KeyValue]> {
    match metric.data.as_ref() {
        Some(MetricData::Gauge(data)) => data
            .data_points
            .iter()
            .map(|point| point.attributes.as_slice())
            .collect(),
        Some(MetricData::Sum(data)) => data
            .data_points
            .iter()
            .map(|point| point.attributes.as_slice())
            .collect(),
        Some(MetricData::Histogram(data)) => data
            .data_points
            .iter()
            .map(|point| point.attributes.as_slice())
            .collect(),
        Some(MetricData::ExponentialHistogram(data)) => data
            .data_points
            .iter()
            .map(|point| point.attributes.as_slice())
            .collect(),
        Some(MetricData::Summary(data)) => data
            .data_points
            .iter()
            .map(|point| point.attributes.as_slice())
            .collect(),
        None => Vec::new(),
    }
}

fn sort_points(metric: &mut Metric) {
    match metric.data.as_mut() {
        Some(MetricData::Gauge(data)) => data
            .data_points
            .sort_by(|a, b| compare_policy_attributes(&a.attributes, &b.attributes)),
        Some(MetricData::Sum(data)) => data
            .data_points
            .sort_by(|a, b| compare_policy_attributes(&a.attributes, &b.attributes)),
        Some(MetricData::Histogram(data)) => data
            .data_points
            .sort_by(|a, b| compare_policy_attributes(&a.attributes, &b.attributes)),
        Some(MetricData::ExponentialHistogram(data)) => data
            .data_points
            .sort_by(|a, b| compare_policy_attributes(&a.attributes, &b.attributes)),
        Some(MetricData::Summary(data)) => data
            .data_points
            .sort_by(|a, b| compare_policy_attributes(&a.attributes, &b.attributes)),
        None => {}
    }
}

fn compare_scope(left: &ScopeMetrics, right: &ScopeMetrics) -> Ordering {
    // Every SDK scope is materialized before this helper is called.
    match (left.scope.as_ref(), right.scope.as_ref()) {
        (Some(left_scope), Some(right_scope)) => (
            left_scope.name.as_str(),
            left_scope.version.as_str(),
            left.schema_url.as_str(),
        )
            .cmp(&(
                right_scope.name.as_str(),
                right_scope.version.as_str(),
                right.schema_url.as_str(),
            ))
            .then_with(|| {
                compare_policy_attributes(&left_scope.attributes, &right_scope.attributes)
            }),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => left.schema_url.cmp(&right.schema_url),
    }
}

fn reject_series_collisions(scopes: &[ScopeMetrics]) -> Result<(), OtlpSdkMetricsError> {
    let mut identities = Vec::new();
    for scope in scopes {
        for metric in &scope.metrics {
            for attributes in point_attributes(metric) {
                identities.push((scope, metric, attributes));
            }
        }
    }
    let compare = |left: &(&ScopeMetrics, &Metric, &[KeyValue]),
                   right: &(&ScopeMetrics, &Metric, &[KeyValue])| {
        compare_scope(left.0, right.0)
            .then_with(|| compare_metric(left.1, right.1))
            .then_with(|| compare_policy_attributes(left.2, right.2))
    };
    identities.sort_by(compare);
    if identities
        .windows(2)
        .any(|pair| compare(&pair[0], &pair[1]).is_eq())
    {
        return Err(OtlpSdkMetricsError::SeriesCollision);
    }
    Ok(())
}

fn compare_scope_output(left: &ScopeMetrics, right: &ScopeMetrics) -> Ordering {
    let order = compare_scope(left, right);
    if !order.is_eq() {
        return order;
    }
    for (left, right) in left.metrics.iter().zip(&right.metrics) {
        let order = compare_metric(left, right);
        if !order.is_eq() {
            return order;
        }
        let left_attributes = point_attributes(left);
        let right_attributes = point_attributes(right);
        for (left, right) in left_attributes.iter().zip(&right_attributes) {
            let order = compare_policy_attributes(left, right);
            if !order.is_eq() {
                return order;
            }
        }
        let order = left_attributes.len().cmp(&right_attributes.len());
        if !order.is_eq() {
            return order;
        }
    }
    left.metrics.len().cmp(&right.metrics.len())
}

fn metric_nodes(metric: &Metric) -> usize {
    let exemplars = |values: &[Exemplar]| {
        values.iter().fold(0usize, |count, exemplar| {
            count.saturating_add(attribute_nodes(&exemplar.filtered_attributes))
        })
    };
    let points = match metric.data.as_ref() {
        Some(MetricData::Gauge(data)) => data.data_points.iter().fold(0usize, |count, point| {
            count
                .saturating_add(attribute_nodes(&point.attributes))
                .saturating_add(exemplars(&point.exemplars))
        }),
        Some(MetricData::Sum(data)) => data.data_points.iter().fold(0usize, |count, point| {
            count
                .saturating_add(attribute_nodes(&point.attributes))
                .saturating_add(exemplars(&point.exemplars))
        }),
        Some(MetricData::Histogram(data)) => {
            data.data_points.iter().fold(0usize, |count, point| {
                count
                    .saturating_add(attribute_nodes(&point.attributes))
                    .saturating_add(exemplars(&point.exemplars))
            })
        }
        Some(MetricData::ExponentialHistogram(data)) => {
            data.data_points.iter().fold(0usize, |count, point| {
                count
                    .saturating_add(attribute_nodes(&point.attributes))
                    .saturating_add(exemplars(&point.exemplars))
            })
        }
        Some(MetricData::Summary(data)) => data.data_points.iter().fold(0usize, |count, point| {
            count.saturating_add(attribute_nodes(&point.attributes))
        }),
        None => 0,
    };
    points.saturating_add(attribute_nodes(&metric.metadata))
}

fn point_count(metric: &Metric) -> usize {
    match metric.data.as_ref() {
        Some(MetricData::Gauge(data)) => data.data_points.len(),
        Some(MetricData::Sum(data)) => data.data_points.len(),
        Some(MetricData::Histogram(data)) => data.data_points.len(),
        Some(MetricData::ExponentialHistogram(data)) => data.data_points.len(),
        Some(MetricData::Summary(data)) => data.data_points.len(),
        None => 0,
    }
}

fn split_metric(metric: &mut Metric) -> Result<Metric, OtlpSdkMetricsError> {
    let middle = point_count(metric) / 2;
    if middle == 0 {
        return Err(OtlpSdkMetricsError::WireEnvelopeExceeded);
    }
    let data = match metric.data.as_mut() {
        Some(MetricData::Gauge(data)) => MetricData::Gauge(Gauge {
            data_points: data.data_points.split_off(middle),
            ..Gauge::default()
        }),
        Some(MetricData::Sum(data)) => MetricData::Sum(Sum {
            data_points: data.data_points.split_off(middle),
            aggregation_temporality: data.aggregation_temporality,
            is_monotonic: data.is_monotonic,
            ..Sum::default()
        }),
        Some(MetricData::Histogram(data)) => MetricData::Histogram(Histogram {
            data_points: data.data_points.split_off(middle),
            aggregation_temporality: data.aggregation_temporality,
            ..Histogram::default()
        }),
        Some(MetricData::ExponentialHistogram(data)) => {
            MetricData::ExponentialHistogram(ExponentialHistogram {
                data_points: data.data_points.split_off(middle),
                aggregation_temporality: data.aggregation_temporality,
                ..ExponentialHistogram::default()
            })
        }
        Some(MetricData::Summary(_)) | None => {
            return Err(OtlpSdkMetricsError::WireEnvelopeExceeded);
        }
    };
    Ok(Metric {
        name: metric.name.clone(),
        description: metric.description.clone(),
        unit: metric.unit.clone(),
        data: Some(data),
        metadata: metric.metadata.clone(),
        ..Metric::default()
    })
}

fn metric_items(metric: &Metric) -> usize {
    let base = point_count(metric).saturating_add(metric_nodes(metric).saturating_mul(2));
    let extras = match metric.data.as_ref() {
        Some(MetricData::Gauge(data)) => data
            .data_points
            .iter()
            .map(|point| point.exemplars.len())
            .sum::<usize>(),
        Some(MetricData::Sum(data)) => data
            .data_points
            .iter()
            .map(|point| point.exemplars.len())
            .sum::<usize>(),
        Some(MetricData::Histogram(data)) => data
            .data_points
            .iter()
            .map(|point| {
                point
                    .exemplars
                    .len()
                    .saturating_add(point.bucket_counts.len())
                    .saturating_add(point.explicit_bounds.len())
            })
            .sum::<usize>(),
        Some(MetricData::ExponentialHistogram(data)) => data
            .data_points
            .iter()
            .map(|point| {
                point
                    .exemplars
                    .len()
                    .saturating_add(
                        point
                            .positive
                            .as_ref()
                            .map_or(0, |buckets| buckets.bucket_counts.len()),
                    )
                    .saturating_add(
                        point
                            .negative
                            .as_ref()
                            .map_or(0, |buckets| buckets.bucket_counts.len()),
                    )
            })
            .sum::<usize>(),
        _ => 0,
    };
    base.saturating_add(extras)
}

struct MetricPart {
    metric: Metric,
    bytes: usize,
    nodes: usize,
    items: usize,
}

fn partition_metric(
    metric: Metric,
    byte_limit: usize,
    node_limit: usize,
    config: &OtlpSdkMetricsConfig,
) -> Result<Vec<MetricPart>, OtlpSdkMetricsError> {
    let mut pending = vec![metric];
    let mut parts = Vec::new();
    let mut encoded_parts_bytes = 0usize;
    while let Some(mut metric) = pending.pop() {
        let nodes = metric_nodes(&metric);
        let items = metric_items(&metric);
        let encoded = if point_count(&metric) <= POINTS_PER_METRIC_REQUEST
            && nodes <= node_limit
            && items <= 32_768
        {
            metric
                .encode_to_bytes(crate::observability::otel::otlp_request_limits(
                    config.max_request_bytes,
                ))
                .ok()
        } else {
            None
        };
        if let Some(bytes) = encoded.filter(|bytes| bytes.len().saturating_add(6) <= byte_limit) {
            // Bound repeated descriptor ownership before retaining every part.
            encoded_parts_bytes = encoded_parts_bytes
                .checked_add(bytes.len().saturating_add(6))
                .filter(|bytes| *bytes <= config.max_collection_bytes)
                .ok_or(OtlpSdkMetricsError::LimitExceeded)?;
            parts.push(MetricPart {
                bytes: bytes.len().saturating_add(6),
                nodes,
                items,
                metric,
            });
        } else {
            let right = split_metric(&mut metric)?;
            pending.push(right);
            pending.push(metric);
        }
        if parts.len().saturating_add(pending.len()) > MAX_POINTS {
            return Err(OtlpSdkMetricsError::LimitExceeded);
        }
    }
    Ok(parts)
}

fn encode_scopes(
    resource: &Resource,
    resource_schema: &str,
    scopes: Vec<ScopeMetrics>,
    config: &OtlpSdkMetricsConfig,
) -> Result<Vec<Vec<u8>>, OtlpSdkMetricsError> {
    let limits = crate::observability::otel::otlp_request_limits(config.max_request_bytes);
    let resource_bytes = resource
        .encode_to_bytes(limits)
        .map_err(|_| OtlpSdkMetricsError::WireEnvelopeExceeded)?
        .len();
    let mut requests = MetricsRequests::new(resource, resource_schema, config, resource_bytes);
    for mut scope in scopes {
        let scope_value = scope
            .scope
            .as_ref()
            .ok_or(OtlpSdkMetricsError::WireEnvelopeExceeded)?;
        let scope_bytes = scope_value
            .encode_to_bytes(limits)
            .map_err(|_| OtlpSdkMetricsError::WireEnvelopeExceeded)?
            .len();
        // Conservative maximum protobuf field/length prefixes for these
        // bounded envelopes. Actual output is checked once again on encoding.
        let overhead = resource_bytes
            .saturating_add(scope_bytes)
            .saturating_add(resource_schema.len())
            .saturating_add(scope.schema_url.len())
            .saturating_add(64);
        let byte_limit = config
            .max_request_bytes
            .checked_sub(overhead)
            .ok_or(OtlpSdkMetricsError::WireEnvelopeExceeded)?;
        let scope_nodes = attribute_nodes(&scope_value.attributes);
        let metadata_nodes = attribute_nodes(&resource.attributes).saturating_add(scope_nodes);
        let node_limit = 4096usize
            .checked_sub(metadata_nodes)
            .ok_or(OtlpSdkMetricsError::LimitExceeded)?;
        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;
        let mut batch_nodes = 0usize;
        let mut batch_items = 0usize;
        for metric in std::mem::take(&mut scope.metrics) {
            for part in partition_metric(metric, byte_limit, node_limit, config)? {
                if !batch.is_empty()
                    && (batch.len() == 256
                        || batch_bytes.saturating_add(part.bytes) > byte_limit
                        || batch_nodes.saturating_add(part.nodes) > node_limit
                        || batch_items.saturating_add(part.items) > 32_768
                        || batch
                            .iter()
                            .any(|metric| compare_metric(metric, &part.metric).is_eq()))
                {
                    let items = batch_items
                        .saturating_add(batch.len())
                        .saturating_add(scope_nodes.saturating_mul(2))
                        .saturating_add(1);
                    requests.push(
                        &scope,
                        std::mem::take(&mut batch),
                        batch_bytes
                            .saturating_add(scope_bytes)
                            .saturating_add(scope.schema_url.len())
                            .saturating_add(32),
                        batch_nodes.saturating_add(scope_nodes),
                        items,
                    )?;
                    batch_bytes = 0;
                    batch_nodes = 0;
                    batch_items = 0;
                }
                batch_bytes = batch_bytes.saturating_add(part.bytes);
                batch_nodes = batch_nodes.saturating_add(part.nodes);
                batch_items = batch_items.saturating_add(part.items);
                batch.push(part.metric);
            }
        }
        let items = batch_items
            .saturating_add(batch.len())
            .saturating_add(scope_nodes.saturating_mul(2))
            .saturating_add(1);
        requests.push(
            &scope,
            batch,
            batch_bytes
                .saturating_add(scope_bytes)
                .saturating_add(scope.schema_url.len())
                .saturating_add(32),
            batch_nodes.saturating_add(scope_nodes),
            items,
        )?;
    }
    requests.finish()
}

fn map_metrics(
    metrics: &sdk::ResourceMetrics,
    policy: &OwnedOtlpExportPolicy,
    config: &OtlpSdkMetricsConfig,
) -> Result<OwnedOtlpPolicyOutput<Vec<Vec<u8>>>, OtlpSdkMetricsError> {
    preflight(metrics, policy, config)?;
    let mut resource = Resource {
        attributes: owned_attributes(
            metrics
                .resource()
                .iter()
                .map(|(key, value)| (key.as_str(), value)),
        )?,
        ..Resource::default()
    };
    let mut resource_schema = metrics
        .resource()
        .schema_url()
        .unwrap_or_default()
        .to_owned();
    let mut report = OwnedOtlpPolicyReport::default();
    policy.sdk_resource(&mut resource, &mut resource_schema, &mut report)?;
    let mut scopes = Vec::new();
    for input in metrics.scope_metrics() {
        let mut scope = InstrumentationScope {
            name: input.scope().name().to_owned(),
            version: input.scope().version().unwrap_or_default().to_owned(),
            attributes: owned_attributes(
                input
                    .scope()
                    .attributes()
                    .map(|kv| (kv.key.as_str(), &kv.value)),
            )?,
            ..InstrumentationScope::default()
        };
        let mut schema_url = input.scope().schema_url().unwrap_or_default().to_owned();
        policy.sdk_scope(&mut scope, &mut schema_url, &mut report)?;
        let mut mapped = Vec::new();
        for input in input.metrics() {
            let data = match input.data() {
                AggregatedMetrics::F64(data) => owned_data(data)?,
                AggregatedMetrics::U64(data) => owned_data(data)?,
                AggregatedMetrics::I64(data) => owned_data(data)?,
            };
            let mut metric = Metric {
                name: input.name().to_owned(),
                description: input.description().to_owned(),
                unit: input.unit().to_owned(),
                data: Some(data),
                ..Metric::default()
            };
            policy.metric(&mut metric, &mut report)?;
            sort_points(&mut metric);
            mapped.push(metric);
        }
        mapped.sort_by(compare_metric);
        scopes.push(ScopeMetrics {
            scope: Some(scope),
            schema_url,
            metrics: mapped,
            ..ScopeMetrics::default()
        });
    }
    reject_series_collisions(&scopes)?;
    scopes.sort_by(compare_scope_output);
    let requests = if scopes.iter().all(|scope| scope.metrics.is_empty()) {
        Vec::new()
    } else {
        encode_scopes(&resource, &resource_schema, scopes, config)?
    };
    Ok(OwnedOtlpPolicyOutput::new(requests, report))
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
