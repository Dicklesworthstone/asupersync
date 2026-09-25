//! Caller-owned, asynchronous metrics export.
//!
//! Unlike the synchronous `MetricsExporter` compatibility surface, this path
//! can drive the native OTLP HTTP transport without blocking a runtime worker
//! or spawning an unowned exporter task. Timestamps are explicit: a runtime's
//! monotonic clock is not silently interpreted as a Unix timestamp.

use super::otel::{ExportError, MetricsSnapshot, OtlpHttpConfig, OtlpHttpExporter};
use super::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
use super::otlp_proto::common_and_resource::{
    AnyValue, AnyValueValue, InstrumentationScope, KeyValue, Resource,
};
use super::otlp_proto::metrics::{
    AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, MetricData,
    NumberDataPoint, NumberDataPointValue, ResourceMetrics, ScopeMetrics, Sum,
};
use crate::cx::Cx;
use crate::grpc::protobuf::{ProtoMessage, ProtobufWireLimits};
use std::collections::{BTreeMap, btree_map::Entry};
use std::future::Future;
use std::pin::Pin;

const MAX_POINTS: usize = 4096;
const MAX_POINTS_PER_METRIC: usize = 1000;
const MAX_ATTRIBUTES: usize = 128;
const MAX_ATTRIBUTE_VALUES: usize = 4096;
const MAX_OWNED_BYTES: usize = 3 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// One cumulative snapshot and its explicit Unix-nanosecond time interval.
///
/// Keep the start timestamp unchanged within an accumulation epoch. When
/// cumulative counters or histograms reset, start a new epoch. Gauge points
/// are instantaneous and are encoded without a start timestamp.
#[derive(Debug, Clone, Copy)]
pub struct MetricsExportBatch<'a> {
    snapshot: &'a MetricsSnapshot,
    start_time_unix_nano: u64,
    time_unix_nano: u64,
}

impl<'a> MetricsExportBatch<'a> {
    /// Validate the explicit accumulation interval. No ambient clock is read.
    pub fn new(
        snapshot: &'a MetricsSnapshot,
        start_time_unix_nano: u64,
        time_unix_nano: u64,
    ) -> Result<Self, ExportError> {
        if start_time_unix_nano == 0 || time_unix_nano < start_time_unix_nano {
            return Err(failure("invalid_timestamp"));
        }
        Ok(Self {
            snapshot,
            start_time_unix_nano,
            time_unix_nano,
        })
    }

    /// The borrowed snapshot, unchanged by export.
    #[must_use]
    pub const fn snapshot(self) -> &'a MetricsSnapshot {
        self.snapshot
    }

    /// Start of the cumulative accumulation epoch, in Unix nanoseconds.
    #[must_use]
    pub const fn start_time_unix_nano(self) -> u64 {
        self.start_time_unix_nano
    }

    /// Collection time, in Unix nanoseconds.
    #[must_use]
    pub const fn time_unix_nano(self) -> u64 {
        self.time_unix_nano
    }
}

/// An export future owned and polled by its caller, not a detached task.
pub type MetricsExportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>>;

/// Object-safe asynchronous counterpart to the synchronous metrics exporter.
///
/// Implementations must keep asynchronous work inside the returned future,
/// observe the supplied context, and document any effects that can remain
/// after cancellation. Successful completion means that exporter has finished
/// its operation; it must not merely acknowledge an unowned background queue.
pub trait AsyncMetricsExporter: Send + Sync {
    /// Export a borrowed snapshot inside the caller's cancellation envelope.
    fn export<'a>(&'a self, cx: &'a Cx, batch: MetricsExportBatch<'a>) -> MetricsExportFuture<'a>;
}

/// Native OTLP HTTP exporter for the existing `MetricsSnapshot` API.
///
/// The complete snapshot is validated and encoded before any network write.
/// This bounded path accepts at most 4096 points, 1000 points per metric,
/// 4096 attribute values, 3 MiB of owned strings, and a 4 MiB wire request.
/// Oversized snapshots fail rather than being partially exported. Duplicate
/// series, mixed metric kinds, non-finite sums and inexact integer conversion
/// also fail closed. Errors never echo metric names, labels or credentials.
///
/// A legacy histogram snapshot has only count and sum. It is represented by
/// one unbounded bucket, without inventing finite bounds, extrema or quantiles.
/// Empty snapshots make no HTTP request. Collector acknowledgement, retry,
/// TLS and cancellation semantics are those of `OtlpHttpExporter`; a cancelled
/// or failed HTTP request may already have reached the collector, so retrying
/// an entire export is not an exactly-once operation.
pub struct OtlpSnapshotExporter {
    http: OtlpHttpExporter,
    resource_attributes: Vec<(String, String)>,
}

impl std::fmt::Debug for OtlpSnapshotExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpSnapshotExporter")
            .field("resource_attribute_count", &self.resource_attributes.len())
            .finish_non_exhaustive()
    }
}

impl OtlpSnapshotExporter {
    /// Reuse an immutable, validated native transport configuration, including
    /// its resource attributes. No environment variables or clocks are read.
    #[must_use]
    pub fn from_config(config: OtlpHttpConfig) -> Self {
        let resource_attributes = config
            .resource_attributes()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        Self {
            http: OtlpHttpExporter::from_config(config),
            resource_attributes,
        }
    }

    /// Encode and send one complete cumulative snapshot using native async I/O.
    pub async fn export(
        &self,
        cx: &Cx,
        batch: MetricsExportBatch<'_>,
    ) -> Result<(), ExportError> {
        checkpoint(cx)?;
        let Some(bytes) = encode_snapshot(batch, &self.resource_attributes)? else {
            return Ok(());
        };
        checkpoint(cx)?;
        self.http.send_otlp_protobuf(cx, bytes).await
    }
}

impl AsyncMetricsExporter for OtlpSnapshotExporter {
    fn export<'a>(&'a self, cx: &'a Cx, batch: MetricsExportBatch<'a>) -> MetricsExportFuture<'a> {
        Box::pin(Self::export(self, cx, batch))
    }
}

fn checkpoint(cx: &Cx) -> Result<(), ExportError> {
    cx.checkpoint()
        .map_err(|_| failure("cancelled_or_budget_exhausted"))
}

fn failure(code: &'static str) -> ExportError {
    ExportError::new(format!("otlp.snapshot.{code}"))
}

type Attributes<'a> = Vec<(&'a str, &'a str)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Counter,
    Gauge,
    Histogram,
}

#[derive(Clone, Copy)]
enum Value {
    Counter(u64),
    Gauge(i64),
    Histogram(u64, f64),
}

impl Value {
    fn kind(self) -> Result<Kind, ExportError> {
        match self {
            Self::Counter(value) => {
                i64::try_from(value).map_err(|_| failure("counter_overflow"))?;
                Ok(Kind::Counter)
            }
            Self::Gauge(_) => Ok(Kind::Gauge),
            Self::Histogram(count, sum) => {
                if !sum.is_finite() || (count == 0 && sum != 0.0) {
                    return Err(failure("invalid_histogram"));
                }
                Ok(Kind::Histogram)
            }
        }
    }
}

struct MetricPoints<'a> {
    kind: Kind,
    points: BTreeMap<Attributes<'a>, Value>,
}

#[derive(Default)]
struct SnapshotBudget {
    owned_bytes: usize,
    attribute_values: usize,
}

impl SnapshotBudget {
    fn charge(&mut self, bytes: usize) -> Result<(), ExportError> {
        self.owned_bytes = self
            .owned_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_OWNED_BYTES)
            .ok_or_else(|| failure("string_limit"))?;
        Ok(())
    }

    fn attributes<'a>(
        &mut self,
        attributes: &'a [(String, String)],
    ) -> Result<Attributes<'a>, ExportError> {
        if attributes.len() > MAX_ATTRIBUTES {
            return Err(failure("attribute_limit"));
        }
        self.attribute_values = self
            .attribute_values
            .checked_add(attributes.len())
            .filter(|total| *total <= MAX_ATTRIBUTE_VALUES)
            .ok_or_else(|| failure("attribute_limit"))?;
        for (key, value) in attributes {
            if key.is_empty() || key.len() > 1024 || value.len() > 4096 {
                return Err(failure("invalid_attribute"));
            }
            self.charge(key.len() + value.len())?;
        }
        let mut normalized: Attributes<'_> = attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        normalized.sort_unstable();
        if normalized.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(failure("duplicate_attribute"));
        }
        Ok(normalized)
    }
}

fn owned_attributes(attributes: Attributes<'_>) -> Vec<KeyValue> {
    attributes
        .into_iter()
        .map(|(key, value)| KeyValue {
            key: key.to_owned(),
            value: Some(AnyValue {
                value: Some(AnyValueValue::String(value.to_owned())),
                ..AnyValue::default()
            }),
            ..KeyValue::default()
        })
        .collect()
}

fn encode_snapshot(
    batch: MetricsExportBatch<'_>,
    resource_attributes: &[(String, String)],
) -> Result<Option<Vec<u8>>, ExportError> {
    let snapshot = batch.snapshot;
    let count = snapshot
        .counters
        .len()
        .checked_add(snapshot.gauges.len())
        .and_then(|count| count.checked_add(snapshot.histograms.len()))
        .filter(|count| *count <= MAX_POINTS)
        .ok_or_else(|| failure("point_limit"))?;
    let mut budget = SnapshotBudget::default();
    let resource_attributes = budget.attributes(resource_attributes)?;
    if count == 0 {
        return Ok(None);
    }

    // Retain only bounded borrowed views until the entire input is validated.
    // BTreeMap orders names and normalized series keys deterministically.
    let mut groups: BTreeMap<&str, MetricPoints<'_>> = BTreeMap::new();
    let points = snapshot
        .counters
        .iter()
        .map(|(name, labels, value)| (name, labels, Value::Counter(*value)))
        .chain(
            snapshot
                .gauges
                .iter()
                .map(|(name, labels, value)| (name, labels, Value::Gauge(*value))),
        )
        .chain(snapshot.histograms.iter().map(|(name, labels, count, sum)| {
            (name, labels, Value::Histogram(*count, *sum))
        }));
    for (name, labels, value) in points {
        if name.is_empty() || name.len() > 1024 {
            return Err(failure("invalid_name"));
        }
        budget.charge(name.len())?;
        let kind = value.kind()?;
        let attributes = budget.attributes(labels)?;
        let group = groups.entry(name.as_str()).or_insert_with(|| MetricPoints {
            kind,
            points: BTreeMap::new(),
        });
        if group.kind != kind {
            return Err(failure("mixed_metric_kind"));
        }
        if group.points.len() >= MAX_POINTS_PER_METRIC {
            return Err(failure("metric_point_limit"));
        }
        match group.points.entry(attributes) {
            Entry::Vacant(entry) => {
                entry.insert(value);
            }
            Entry::Occupied(_) => return Err(failure("duplicate_series")),
        }
    }

    let mut metrics = Vec::with_capacity(groups.len());
    for (name, group) in groups {
        let mut sum = Sum {
            aggregation_temporality: AggregationTemporality::Cumulative.as_raw(),
            is_monotonic: true,
            ..Sum::default()
        };
        let mut gauge = Gauge::default();
        let mut histogram = Histogram {
            aggregation_temporality: AggregationTemporality::Cumulative.as_raw(),
            ..Histogram::default()
        };
        for (attributes, value) in group.points {
            let attributes = owned_attributes(attributes);
            match value {
                Value::Counter(value) => sum.data_points.push(NumberDataPoint {
                    attributes,
                    start_time_unix_nano: batch.start_time_unix_nano,
                    time_unix_nano: batch.time_unix_nano,
                    value: Some(NumberDataPointValue::Int(
                        i64::try_from(value).map_err(|_| failure("counter_overflow"))?,
                    )),
                    ..NumberDataPoint::default()
                }),
                Value::Gauge(value) => gauge.data_points.push(NumberDataPoint {
                    attributes,
                    time_unix_nano: batch.time_unix_nano,
                    value: Some(NumberDataPointValue::Int(value)),
                    ..NumberDataPoint::default()
                }),
                Value::Histogram(count, sum) => histogram.data_points.push(HistogramDataPoint {
                    attributes,
                    start_time_unix_nano: batch.start_time_unix_nano,
                    time_unix_nano: batch.time_unix_nano,
                    count,
                    sum: Some(sum),
                    bucket_counts: vec![count],
                    ..HistogramDataPoint::default()
                }),
            }
        }
        let data = match group.kind {
            Kind::Counter => MetricData::Sum(sum),
            Kind::Gauge => MetricData::Gauge(gauge),
            Kind::Histogram => MetricData::Histogram(histogram),
        };
        metrics.push(Metric {
            name: name.to_owned(),
            data: Some(data),
            ..Metric::default()
        });
    }
    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: owned_attributes(resource_attributes),
                ..Resource::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "asupersync.snapshot".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    ..InstrumentationScope::default()
                }),
                metrics,
                ..ScopeMetrics::default()
            }],
            ..ResourceMetrics::default()
        }],
        ..ExportMetricsServiceRequest::default()
    };
    request
        .encode_to_bytes(ProtobufWireLimits::for_message_size(MAX_REQUEST_BYTES))
        .map(|bytes| Some(bytes.to_vec()))
        .map_err(|_| failure("wire_envelope_exceeded"))
}

#[cfg(test)]
mod tests;
