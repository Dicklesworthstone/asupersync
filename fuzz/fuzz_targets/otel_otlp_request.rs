#![no_main]

use arbitrary::Arbitrary;
use asupersync::observability::MetricsSnapshot;
use asupersync::observability::otel::span_semantics::{SpanConformanceConfig, TestSpan};
use libfuzzer_sys::fuzz_target;
use opentelemetry::trace::{SpanKind, Status};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs, SeverityNumber};
use opentelemetry_proto::tonic::metrics::v1::metric::Data as MetricData;
use opentelemetry_proto::tonic::metrics::v1::{
    AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
    ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::SpanKind as ProtoSpanKind;
use opentelemetry_proto::tonic::trace::v1::status::StatusCode as ProtoStatusCode;
use opentelemetry_proto::tonic::trace::v1::{
    ResourceSpans, ScopeSpans, Span as ProtoSpan, Status as ProtoStatus, span,
};
use prost::Message;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_COUNTERS: usize = 8;
const MAX_GAUGES: usize = 8;
const MAX_HISTOGRAMS: usize = 8;
const MAX_LABELS: usize = 6;
const MAX_CHILD_SPANS: usize = 4;
const MAX_ATTRIBUTES: usize = 10;
const MAX_EVENTS: usize = 6;
const MAX_EVENT_ATTRIBUTES: usize = 4;
const MAX_LOG_SCOPES: usize = 4;
const MAX_LOG_RECORDS: usize = 6;
const MAX_TEXT_CHARS: usize = 48;
const OTEL_SCHEMA_URL: &str = "https://opentelemetry.io/schemas/1.37.0";
const OTEL_SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
struct LogRecordSpec {
    time_unix_nano: u64,
    observed_time_unix_nano: u64,
    severity_number: i32,
    severity_text: String,
    body: String,
    attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
struct ResourceLogsSpec {
    service_name: String,
    batch_sequence: u64,
    scope_name: String,
    log_records: Vec<LogRecordSpec>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    service_name: String,
    scope_name: String,
    batch_sequence: u16,
    metrics: MetricsInput,
    trace: TraceInput,
    logs: Vec<LogScopeInput>,
}

#[derive(Arbitrary, Debug)]
struct MetricsInput {
    counters: Vec<CounterInput>,
    gauges: Vec<GaugeInput>,
    histograms: Vec<HistogramInput>,
}

#[derive(Arbitrary, Debug)]
struct CounterInput {
    name: String,
    labels: Vec<LabelInput>,
    value: u64,
}

#[derive(Arbitrary, Debug)]
struct GaugeInput {
    name: String,
    labels: Vec<LabelInput>,
    value: i64,
}

#[derive(Arbitrary, Debug)]
struct HistogramInput {
    name: String,
    labels: Vec<LabelInput>,
    count: u16,
    sum: f32,
}

#[derive(Arbitrary, Debug)]
struct LabelInput {
    key: String,
    value: String,
}

#[derive(Arbitrary, Debug)]
struct TraceInput {
    max_attributes: u8,
    max_events: u8,
    max_attribute_length: Option<u8>,
    root: SpanInput,
    children: Vec<SpanInput>,
}

#[derive(Arbitrary, Debug)]
struct SpanInput {
    name: String,
    kind: u8,
    attributes: Vec<LabelInput>,
    events: Vec<EventInput>,
    status: StatusInput,
}

#[derive(Arbitrary, Debug)]
struct EventInput {
    name: String,
    attributes: Vec<LabelInput>,
}

#[derive(Arbitrary, Debug)]
enum StatusInput {
    Unset,
    Ok,
    Error(String),
}

#[derive(Arbitrary, Debug)]
struct LogScopeInput {
    service_name: String,
    scope_name: String,
    batch_sequence: u16,
    records: Vec<LogRecordInput>,
}

#[derive(Arbitrary, Debug)]
struct LogRecordInput {
    body: String,
    severity: u8,
    attributes: Vec<LabelInput>,
}

fn string_value(value: &str) -> AnyValue {
    AnyValue {
        value: Some(ProtoValue::StringValue(value.to_string())),
    }
}

fn key_value(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(string_value(&value.into())),
    }
}

fn ordered_proto_attributes(attributes: &HashMap<String, String>) -> Vec<KeyValue> {
    let mut ordered: Vec<_> = attributes.iter().collect();
    ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
        left_key
            .cmp(right_key)
            .then_with(|| left_value.cmp(right_value))
    });
    ordered
        .into_iter()
        .map(|(key, value)| key_value(key.clone(), value.clone()))
        .collect()
}

fn proto_labels(labels: &[(String, String)]) -> Vec<KeyValue> {
    let mut ordered = labels.to_vec();
    ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
        left_key
            .cmp(right_key)
            .then_with(|| left_value.cmp(right_value))
    });
    ordered
        .into_iter()
        .map(|(key, value)| key_value(key, value))
        .collect()
}

fn instrumentation_scope(name: &str) -> InstrumentationScope {
    InstrumentationScope {
        name: name.to_string(),
        version: OTEL_SCOPE_VERSION.to_string(),
        ..Default::default()
    }
}

fn resource_with_batch(service_name: &str, batch_sequence: u64) -> Resource {
    Resource {
        attributes: vec![
            key_value("service.name", service_name),
            key_value("batch.sequence", batch_sequence.to_string()),
            key_value("telemetry.sdk.name", "asupersync"),
        ],
        ..Default::default()
    }
}

fn unix_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos() as u64
}

fn metrics_request_from_snapshot(
    snapshot: &MetricsSnapshot,
    service_name: &str,
    batch_sequence: u64,
    scope_name: &str,
) -> ExportMetricsServiceRequest {
    let mut metrics = Vec::new();

    for (name, labels, value) in &snapshot.counters {
        metrics.push(Metric {
            name: name.clone(),
            data: Some(metric::Data::Sum(Sum {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                is_monotonic: true,
                data_points: vec![NumberDataPoint {
                    attributes: proto_labels(labels),
                    start_time_unix_nano: batch_sequence * 1_000 + 1,
                    time_unix_nano: batch_sequence * 1_000 + 2,
                    value: Some(number_data_point::Value::AsInt(*value as i64)),
                    ..Default::default()
                }],
            })),
            ..Default::default()
        });
    }

    for (name, labels, value) in &snapshot.gauges {
        metrics.push(Metric {
            name: name.clone(),
            data: Some(metric::Data::Gauge(Gauge {
                data_points: vec![NumberDataPoint {
                    attributes: proto_labels(labels),
                    time_unix_nano: batch_sequence * 1_000 + 3,
                    value: Some(number_data_point::Value::AsInt(*value)),
                    ..Default::default()
                }],
            })),
            ..Default::default()
        });
    }

    for (name, labels, count, sum) in &snapshot.histograms {
        metrics.push(Metric {
            name: name.clone(),
            data: Some(metric::Data::Histogram(Histogram {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                data_points: vec![HistogramDataPoint {
                    attributes: proto_labels(labels),
                    start_time_unix_nano: batch_sequence * 1_000 + 4,
                    time_unix_nano: batch_sequence * 1_000 + 5,
                    count: *count,
                    sum: Some(*sum),
                    bucket_counts: vec![*count],
                    ..Default::default()
                }],
            })),
            ..Default::default()
        });
    }

    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(resource_with_batch(service_name, batch_sequence)),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(instrumentation_scope(scope_name)),
                metrics,
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
            schema_url: OTEL_SCHEMA_URL.to_string(),
        }],
    }
}

fn proto_span_kind(kind: SpanKind) -> i32 {
    match kind {
        SpanKind::Internal => ProtoSpanKind::Internal as i32,
        SpanKind::Server => ProtoSpanKind::Server as i32,
        SpanKind::Client => ProtoSpanKind::Client as i32,
        SpanKind::Producer => ProtoSpanKind::Producer as i32,
        SpanKind::Consumer => ProtoSpanKind::Consumer as i32,
    }
}

fn proto_status(status: &Status) -> ProtoStatus {
    match status {
        Status::Unset => ProtoStatus {
            code: ProtoStatusCode::Unset as i32,
            message: String::new(),
        },
        Status::Ok => ProtoStatus {
            code: ProtoStatusCode::Ok as i32,
            message: String::new(),
        },
        Status::Error { description } => ProtoStatus {
            code: ProtoStatusCode::Error as i32,
            message: description.clone().into_owned(),
        },
    }
}

fn proto_span(span: &TestSpan) -> ProtoSpan {
    ProtoSpan {
        trace_id: span.context.trace_id().to_bytes().to_vec(),
        span_id: span.context.span_id().to_bytes().to_vec(),
        parent_span_id: span
            .parent_context
            .as_ref()
            .map_or_else(Vec::new, |parent| parent.span_id().to_bytes().to_vec()),
        name: span.name.clone(),
        kind: proto_span_kind(span.kind.clone()),
        start_time_unix_nano: unix_nanos(span.start_time),
        end_time_unix_nano: unix_nanos(span.end_time.expect("ended span")),
        attributes: ordered_proto_attributes(&span.attributes),
        events: span
            .events
            .iter()
            .map(|event| span::Event {
                time_unix_nano: unix_nanos(event.timestamp),
                name: event.name.clone(),
                attributes: ordered_proto_attributes(&event.attributes),
                ..Default::default()
            })
            .collect(),
        status: Some(proto_status(&span.status)),
        ..Default::default()
    }
}

fn traces_request(
    service_name: &str,
    batch_sequence: u64,
    scope_name: &str,
    spans: Vec<ProtoSpan>,
) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(resource_with_batch(service_name, batch_sequence)),
            scope_spans: vec![ScopeSpans {
                scope: Some(instrumentation_scope(scope_name)),
                spans,
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
            schema_url: OTEL_SCHEMA_URL.to_string(),
        }],
    }
}

fn log_record(spec: &LogRecordSpec) -> LogRecord {
    LogRecord {
        time_unix_nano: spec.time_unix_nano,
        observed_time_unix_nano: spec.observed_time_unix_nano,
        severity_number: spec.severity_number,
        severity_text: spec.severity_text.clone(),
        body: Some(string_value(&spec.body)),
        attributes: spec
            .attributes
            .iter()
            .map(|(key, value)| key_value(key.clone(), value.clone()))
            .collect(),
        ..Default::default()
    }
}

fn logs_request(resource_logs: Vec<ResourceLogsSpec>) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: resource_logs
            .into_iter()
            .map(|resource_logs| ResourceLogs {
                resource: Some(resource_with_batch(
                    &resource_logs.service_name,
                    resource_logs.batch_sequence,
                )),
                scope_logs: vec![ScopeLogs {
                    scope: Some(instrumentation_scope(&resource_logs.scope_name)),
                    log_records: resource_logs.log_records.iter().map(log_record).collect(),
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            })
            .collect(),
    }
}

fuzz_target!(|input: FuzzInput| {
    if input.metrics.counters.len() > MAX_COUNTERS
        || input.metrics.gauges.len() > MAX_GAUGES
        || input.metrics.histograms.len() > MAX_HISTOGRAMS
        || input.trace.children.len() > MAX_CHILD_SPANS
        || input.logs.len() > MAX_LOG_SCOPES
    {
        return;
    }
    if input
        .logs
        .iter()
        .any(|scope| scope.records.len() > MAX_LOG_RECORDS)
    {
        return;
    }

    let service_name = bounded_text(&input.service_name);
    let scope_name = bounded_scope_name(&input.scope_name);
    let batch_sequence = u64::from(input.batch_sequence);

    let metrics_snapshot = build_metrics_snapshot(input.metrics);
    let metrics_request = metrics_request_from_snapshot(
        &metrics_snapshot,
        &service_name,
        batch_sequence,
        &scope_name,
    );
    let decoded_metrics =
        ExportMetricsServiceRequest::decode(metrics_request.encode_to_vec().as_slice())
            .expect("metrics request should decode after encode");
    assert_eq!(decoded_metrics, metrics_request);
    assert_metrics_request_invariants(&decoded_metrics, &scope_name, &service_name, batch_sequence);

    let (trace_request, config) =
        build_trace_request(input.trace, &service_name, batch_sequence, &scope_name);
    let decoded_traces =
        ExportTraceServiceRequest::decode(trace_request.encode_to_vec().as_slice())
            .expect("trace request should decode after encode");
    assert_eq!(decoded_traces, trace_request);
    assert_trace_request_invariants(
        &decoded_traces,
        &scope_name,
        &service_name,
        batch_sequence,
        config.max_attribute_length,
    );

    let log_specs = build_log_specs(input.logs);
    let logs_request = logs_request(log_specs);
    let decoded_logs = ExportLogsServiceRequest::decode(logs_request.encode_to_vec().as_slice())
        .expect("logs request should decode after encode");
    assert_eq!(decoded_logs, logs_request);
    assert_logs_request_invariants(&decoded_logs);
});

fn build_metrics_snapshot(input: MetricsInput) -> MetricsSnapshot {
    let mut snapshot = MetricsSnapshot::new();
    for (idx, counter) in input.counters.into_iter().take(MAX_COUNTERS).enumerate() {
        snapshot.add_counter(
            bounded_metric_name("counter", idx, &counter.name),
            bounded_labels(counter.labels),
            counter.value,
        );
    }
    for (idx, gauge) in input.gauges.into_iter().take(MAX_GAUGES).enumerate() {
        snapshot.add_gauge(
            bounded_metric_name("gauge", idx, &gauge.name),
            bounded_labels(gauge.labels),
            gauge.value,
        );
    }
    for (idx, histogram) in input
        .histograms
        .into_iter()
        .take(MAX_HISTOGRAMS)
        .enumerate()
    {
        snapshot.add_histogram(
            bounded_metric_name("histogram", idx, &histogram.name),
            bounded_labels(histogram.labels),
            u64::from(histogram.count),
            f64::from(histogram.sum),
        );
    }
    snapshot
}

fn build_trace_request(
    input: TraceInput,
    service_name: &str,
    batch_sequence: u64,
    scope_name: &str,
) -> (ExportTraceServiceRequest, SpanConformanceConfig) {
    let config = SpanConformanceConfig {
        max_attributes: usize::from(input.max_attributes % (MAX_ATTRIBUTES as u8 + 1)),
        max_events: usize::from(input.max_events % (MAX_EVENTS as u8 + 1)),
        max_attribute_length: input
            .max_attribute_length
            .map(|limit| usize::from(limit % MAX_TEXT_CHARS as u8 + 1)),
        test_sampling: true,
        test_context_propagation: true,
    };

    let mut root = TestSpan::new_with_config(
        &bounded_scope_name(&input.root.name),
        span_kind(input.root.kind),
        &config,
    );
    apply_span_input(&mut root, input.root, config.max_attribute_length);
    let mut spans = Vec::with_capacity(input.children.len() + 1);

    for child_input in input.children.into_iter().take(MAX_CHILD_SPANS) {
        let mut child = root.new_child(
            &bounded_scope_name(&child_input.name),
            span_kind(child_input.kind),
        );
        apply_span_input(&mut child, child_input, config.max_attribute_length);
        child.end();
        spans.push(proto_span(&child));
    }

    root.end();
    spans.insert(0, proto_span(&root));

    (
        traces_request(service_name, batch_sequence, scope_name, spans),
        config,
    )
}

fn apply_span_input(span: &mut TestSpan, input: SpanInput, max_attribute_length: Option<usize>) {
    for attribute in input.attributes.into_iter().take(MAX_ATTRIBUTES) {
        let key = bounded_attribute_key(&attribute.key);
        let value = truncate_value(&bounded_text(&attribute.value), max_attribute_length);
        span.set_attribute(&key, &value);
    }
    for event in input.events.into_iter().take(MAX_EVENTS) {
        let name = bounded_scope_name(&event.name);
        let attributes = bounded_event_attributes(event.attributes, max_attribute_length);
        span.add_event(&name, attributes);
    }
    span.set_status(span_status(input.status));
}

fn build_log_specs(input: Vec<LogScopeInput>) -> Vec<ResourceLogsSpec> {
    input
        .into_iter()
        .take(MAX_LOG_SCOPES)
        .map(|scope| ResourceLogsSpec {
            service_name: bounded_text(&scope.service_name),
            batch_sequence: u64::from(scope.batch_sequence),
            scope_name: bounded_scope_name(&scope.scope_name),
            log_records: scope
                .records
                .into_iter()
                .take(MAX_LOG_RECORDS)
                .enumerate()
                .map(|(idx, record)| LogRecordSpec {
                    time_unix_nano: idx as u64 * 10 + 1,
                    observed_time_unix_nano: idx as u64 * 10 + 2,
                    severity_number: severity_number(record.severity),
                    severity_text: severity_text(record.severity),
                    body: bounded_text(&record.body),
                    attributes: bounded_labels(record.attributes),
                })
                .collect(),
        })
        .collect()
}

fn bounded_metric_name(prefix: &str, idx: usize, name: &str) -> String {
    let suffix = bounded_text(name);
    if suffix.is_empty() {
        format!("{prefix}.{idx}")
    } else {
        format!("{prefix}.{idx}.{}", suffix)
    }
}

fn bounded_scope_name(text: &str) -> String {
    let bounded = bounded_text(text);
    if bounded.is_empty() {
        "asupersync.fuzz".to_string()
    } else {
        bounded
    }
}

fn bounded_attribute_key(text: &str) -> String {
    let bounded = bounded_text(text);
    if bounded.is_empty() {
        "attr.fuzz".to_string()
    } else {
        bounded
    }
}

fn bounded_text(text: &str) -> String {
    text.chars().take(MAX_TEXT_CHARS).collect()
}

fn truncate_value(value: &str, max_len: Option<usize>) -> String {
    match max_len {
        Some(limit) => value.chars().take(limit).collect(),
        None => value.to_string(),
    }
}

fn bounded_labels(labels: Vec<LabelInput>) -> Vec<(String, String)> {
    labels
        .into_iter()
        .take(MAX_LABELS)
        .enumerate()
        .map(|(idx, label)| {
            let key = bounded_attribute_key(&label.key);
            let value = bounded_text(&label.value);
            let key = if key.is_empty() {
                format!("label.{idx}")
            } else {
                key
            };
            (key, value)
        })
        .collect()
}

fn bounded_event_attributes(
    labels: Vec<LabelInput>,
    max_attribute_length: Option<usize>,
) -> HashMap<String, String> {
    labels
        .into_iter()
        .take(MAX_EVENT_ATTRIBUTES)
        .enumerate()
        .map(|(idx, label)| {
            let key = bounded_attribute_key(&label.key);
            let key = if key.is_empty() {
                format!("event.attr.{idx}")
            } else {
                key
            };
            let value = truncate_value(&bounded_text(&label.value), max_attribute_length);
            (key, value)
        })
        .collect()
}

fn span_kind(kind: u8) -> SpanKind {
    match kind % 5 {
        0 => SpanKind::Internal,
        1 => SpanKind::Server,
        2 => SpanKind::Client,
        3 => SpanKind::Producer,
        _ => SpanKind::Consumer,
    }
}

fn span_status(status: StatusInput) -> Status {
    match status {
        StatusInput::Unset => Status::Unset,
        StatusInput::Ok => Status::Ok,
        StatusInput::Error(description) => Status::Error {
            description: bounded_text(&description).into(),
        },
    }
}

fn severity_number(raw: u8) -> i32 {
    match raw % 6 {
        0 => SeverityNumber::Trace as i32,
        1 => SeverityNumber::Debug as i32,
        2 => SeverityNumber::Info as i32,
        3 => SeverityNumber::Warn as i32,
        4 => SeverityNumber::Error as i32,
        _ => SeverityNumber::Fatal as i32,
    }
}

fn severity_text(raw: u8) -> String {
    match raw % 6 {
        0 => "TRACE",
        1 => "DEBUG",
        2 => "INFO",
        3 => "WARN",
        4 => "ERROR",
        _ => "FATAL",
    }
    .to_string()
}

fn assert_metrics_request_invariants(
    request: &ExportMetricsServiceRequest,
    scope_name: &str,
    service_name: &str,
    batch_sequence: u64,
) {
    for resource_metrics in &request.resource_metrics {
        assert_resource_attributes(
            resource_metrics.resource.as_ref().expect("resource"),
            service_name,
            batch_sequence,
        );
        let scope_metrics = &resource_metrics.scope_metrics[0];
        assert_eq!(scope_metrics.schema_url, OTEL_SCHEMA_URL);
        assert_eq!(
            scope_metrics.scope.as_ref().expect("scope").name,
            scope_name
        );
        for metric in &scope_metrics.metrics {
            match metric.data.as_ref().expect("metric data") {
                MetricData::Sum(sum) => {
                    assert!(sum.is_monotonic);
                    assert_sorted_attributes(&sum.data_points[0].attributes);
                }
                MetricData::Gauge(gauge) => {
                    assert_sorted_attributes(&gauge.data_points[0].attributes);
                }
                MetricData::Histogram(histogram) => {
                    assert_sorted_attributes(&histogram.data_points[0].attributes);
                    assert_eq!(
                        histogram.data_points[0].bucket_counts.iter().sum::<u64>(),
                        histogram.data_points[0].count
                    );
                }
                other => panic!("unexpected OTLP metric data variant: {other:?}"),
            }
        }
    }
}

fn assert_trace_request_invariants(
    request: &ExportTraceServiceRequest,
    scope_name: &str,
    service_name: &str,
    batch_sequence: u64,
    max_attribute_length: Option<usize>,
) {
    for resource_spans in &request.resource_spans {
        assert_resource_attributes(
            resource_spans.resource.as_ref().expect("resource"),
            service_name,
            batch_sequence,
        );
        let scope_spans = &resource_spans.scope_spans[0];
        assert_eq!(scope_spans.schema_url, OTEL_SCHEMA_URL);
        assert_eq!(scope_spans.scope.as_ref().expect("scope").name, scope_name);
        for span in &scope_spans.spans {
            assert_sorted_attributes(&span.attributes);
            for attribute in &span.attributes {
                assert!(attribute.key.chars().count() <= 1024);
                assert_any_value_within_limit(attribute, max_attribute_length);
            }
            for event in &span.events {
                assert_sorted_attributes(&event.attributes);
                for attribute in &event.attributes {
                    assert_any_value_within_limit(attribute, max_attribute_length);
                }
            }
        }
    }
}

fn assert_logs_request_invariants(request: &ExportLogsServiceRequest) {
    for resource_logs in &request.resource_logs {
        assert_eq!(resource_logs.schema_url, OTEL_SCHEMA_URL);
        let scope_logs = &resource_logs.scope_logs[0];
        assert_eq!(scope_logs.schema_url, OTEL_SCHEMA_URL);
        for record in &scope_logs.log_records {
            for attribute in &record.attributes {
                let value = key_value_str(attribute);
                assert!(value.chars().count() <= MAX_TEXT_CHARS);
            }
        }
    }
}

fn assert_resource_attributes(
    resource: &opentelemetry_proto::tonic::resource::v1::Resource,
    service_name: &str,
    batch_sequence: u64,
) {
    assert_eq!(resource.attributes.len(), 3);
    assert_eq!(resource.attributes[0].key, "service.name");
    assert_eq!(key_value_str(&resource.attributes[0]), service_name);
    assert_eq!(resource.attributes[1].key, "batch.sequence");
    assert_eq!(
        key_value_str(&resource.attributes[1]),
        batch_sequence.to_string()
    );
    assert_eq!(resource.attributes[2].key, "telemetry.sdk.name");
    assert_eq!(key_value_str(&resource.attributes[2]), "asupersync");
}

fn assert_sorted_attributes(attributes: &[KeyValue]) {
    for pair in attributes.windows(2) {
        let left = (&pair[0].key, key_value_str(&pair[0]));
        let right = (&pair[1].key, key_value_str(&pair[1]));
        assert!(left <= right);
    }
}

fn assert_any_value_within_limit(attribute: &KeyValue, max_attribute_length: Option<usize>) {
    let value = key_value_str(attribute);
    if let Some(limit) = max_attribute_length {
        assert!(value.chars().count() <= limit);
    }
}

fn key_value_str(attribute: &KeyValue) -> &str {
    match attribute
        .value
        .as_ref()
        .and_then(|value| value.value.as_ref())
    {
        Some(ProtoValue::StringValue(text)) => text.as_str(),
        other => panic!("expected string AnyValue, got {other:?}"),
    }
}
