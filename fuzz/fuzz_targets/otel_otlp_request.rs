#![no_main]

use arbitrary::Arbitrary;
use asupersync::observability::MetricsSnapshot;
use asupersync::observability::otel::otlp_request_builder::{
    OTEL_SCHEMA_URL, OtlpLogRecordInput, OtlpLogScopeInput, logs_request,
    metrics_request_from_snapshot, severity_number_from_bucket, severity_text_from_bucket,
    traces_request,
};
use asupersync::observability::otel::span_semantics::{SpanConformanceConfig, TestSpan};
use libfuzzer_sys::fuzz_target;
use opentelemetry::trace::{SpanKind, Status};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::logs::v1::LogRecord;
use opentelemetry_proto::tonic::metrics::v1::metric::Data as MetricData;
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;
use std::collections::HashMap;

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

    let log_scopes = build_log_scopes(input.logs);
    let logs_request = logs_request(&log_scopes);
    let decoded_logs = ExportLogsServiceRequest::decode(logs_request.encode_to_vec().as_slice())
        .expect("logs request should decode after encode");
    assert_eq!(decoded_logs, logs_request);
    assert_logs_request_invariants(&decoded_logs, &log_scopes);
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
        spans.push(child);
    }

    root.end();
    spans.insert(0, root);

    (
        traces_request(service_name, batch_sequence, scope_name, &spans),
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

fn build_log_scopes(input: Vec<LogScopeInput>) -> Vec<OtlpLogScopeInput> {
    input
        .into_iter()
        .take(MAX_LOG_SCOPES)
        .map(|scope| OtlpLogScopeInput {
            service_name: bounded_text(&scope.service_name),
            batch_sequence: u64::from(scope.batch_sequence),
            scope_name: bounded_scope_name(&scope.scope_name),
            log_records: scope
                .records
                .into_iter()
                .take(MAX_LOG_RECORDS)
                .enumerate()
                .map(|(idx, record)| OtlpLogRecordInput {
                    time_unix_nano: idx as u64 * 10 + 1,
                    observed_time_unix_nano: idx as u64 * 10 + 2,
                    severity_number: severity_number_from_bucket(record.severity),
                    severity_text: severity_text_from_bucket(record.severity),
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

fn assert_logs_request_invariants(
    request: &ExportLogsServiceRequest,
    expected_scopes: &[OtlpLogScopeInput],
) {
    assert_eq!(request.resource_logs.len(), expected_scopes.len());
    for (resource_logs, expected_scope) in request.resource_logs.iter().zip(expected_scopes) {
        assert_eq!(resource_logs.schema_url, OTEL_SCHEMA_URL);
        assert_resource_attributes(
            resource_logs.resource.as_ref().expect("resource"),
            &expected_scope.service_name,
            expected_scope.batch_sequence,
        );
        let scope_logs = &resource_logs.scope_logs[0];
        assert_eq!(scope_logs.schema_url, OTEL_SCHEMA_URL);
        assert_eq!(
            scope_logs.scope.as_ref().expect("scope").name,
            expected_scope.scope_name
        );
        assert_eq!(
            scope_logs.log_records.len(),
            expected_scope.log_records.len()
        );
        for (record, expected_record) in scope_logs
            .log_records
            .iter()
            .zip(&expected_scope.log_records)
        {
            assert_log_record(record, expected_record);
        }
    }
}

fn assert_log_record(record: &LogRecord, expected: &OtlpLogRecordInput) {
    assert_eq!(record.time_unix_nano, expected.time_unix_nano);
    assert_eq!(
        record.observed_time_unix_nano,
        expected.observed_time_unix_nano
    );
    assert_eq!(record.severity_number, expected.severity_number);
    assert_eq!(record.severity_text, expected.severity_text);
    assert_eq!(log_record_body(record), expected.body);
    assert_eq!(record.attributes.len(), expected.attributes.len());
    for (attribute, (expected_key, expected_value)) in
        record.attributes.iter().zip(&expected.attributes)
    {
        assert_eq!(attribute.key.as_str(), expected_key.as_str());
        assert_eq!(key_value_str(attribute), expected_value.as_str());
        assert!(expected_value.chars().count() <= MAX_TEXT_CHARS);
    }
}

fn assert_resource_attributes(resource: &Resource, service_name: &str, batch_sequence: u64) {
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

fn any_value_as_str(value: &AnyValue) -> &str {
    match value.value.as_ref() {
        Some(ProtoValue::StringValue(text)) => text.as_str(),
        other => panic!("expected string AnyValue, got {other:?}"),
    }
}

fn log_record_body(record: &LogRecord) -> &str {
    any_value_as_str(record.body.as_ref().expect("log body"))
}

fn key_value_str(attribute: &KeyValue) -> &str {
    any_value_as_str(attribute.value.as_ref().expect("attribute value"))
}
