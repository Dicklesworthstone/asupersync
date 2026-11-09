use super::*;
use crate::observability::level::LogLevel;
use crate::observability::metrics::MetricsProvider;
use crate::observability::otel::{
    OtlpLogBody, OtlpTraceEventInput, OtlpTraceLinkInput, OwnedOtlpLogConfig,
    OwnedOtlpMetricsConfig, OwnedOtlpTraceConfig,
};
use crate::observability::otlp_proto::collector::logs::ExportLogsServiceRequest;
use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
use crate::observability::otlp_proto::collector::trace::ExportTraceServiceRequest;
use crate::observability::otlp_proto::metrics::{
    ExponentialHistogram, ExponentialHistogramDataPoint, Gauge, Histogram, HistogramDataPoint,
    NumberDataPoint, NumberDataPointValue, Sum, Summary, SummaryDataPoint,
};

fn metrics() -> OwnedOtlpMetrics {
    OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap()
}

fn traces() -> OwnedOtlpTraces {
    OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new()).unwrap()
}

fn logs() -> OwnedOtlpLogs {
    OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).unwrap()
}

fn span(id: u8) -> OtlpTraceSpanInput<'static> {
    OtlpTraceSpanInput::new([1; 16], [id; 8], "operation", 10, 20)
}

fn decode<M: ProtoMessage>(bytes: &[u8]) -> M {
    M::decode_from_bytes(bytes, crate::grpc::protobuf::ProtobufWireLimits::default()).unwrap()
}

fn string_value(attribute: &KeyValue) -> &str {
    match attribute
        .value
        .as_ref()
        .and_then(|value| value.value.as_ref())
    {
        Some(AnyValueValue::String(value)) => value,
        other => panic!("expected string attribute, found {other:?}"),
    }
}

#[test]
fn default_policy_preserves_all_mapper_bytes_and_custom_log_identity() {
    let policy = OwnedOtlpExportPolicy::new();
    let resources = [("z", "last"), ("service.name", "example")];
    let metrics = metrics();
    metrics.task_stuck_detected("worker");
    let original = metrics.collect(30, &resources).unwrap();
    let filtered = metrics
        .collect_with_policy(30, &resources, &policy)
        .unwrap();
    assert_eq!(filtered.output(), &original);
    assert_eq!(*filtered.report(), OwnedOtlpPolicyReport::default());

    let spans = [
        span(2).with_dropped_attributes_count(5),
        span(3).with_trace_flags(0),
    ];
    let traces = traces();
    let original = traces.collect(&spans, &resources).unwrap();
    let filtered = traces
        .collect_with_policy(&spans, &resources, &policy)
        .unwrap();
    assert_eq!(filtered.output().sampled_spans(), 1);
    assert_eq!(filtered.output().unsampled_spans(), 1);
    assert_eq!(*filtered.report(), OwnedOtlpPolicyReport::default());
    assert_eq!(
        filtered.into_parts().0.into_requests(),
        original.into_requests()
    );

    let logs = OwnedOtlpLogs::try_new(
        OwnedOtlpLogConfig::new()
            .with_scope("custom-scope", "9")
            .with_schema_url("https://example.test/schema"),
    )
    .unwrap();
    let resources = [OtlpLogKeyValueInput::new("count", OtlpLogBody::Int(7))];
    let records = [
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("body"), 10)
            .with_dropped_attributes_count(11),
    ];
    let original = logs.collect(&records, &resources).unwrap();
    let filtered = logs
        .collect_with_policy(&records, &resources, &policy)
        .unwrap();
    assert_eq!(filtered.output().record_count(), 1);
    assert_eq!(filtered.output().producer_dropped_attributes(), 11);
    assert_eq!(*filtered.report(), OwnedOtlpPolicyReport::default());
    assert_eq!(
        filtered.into_parts().0.into_requests(),
        original.into_requests()
    );
}

#[test]
fn resource_override_scope_and_filter_counts_are_not_multiplied_by_batching() {
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_resource_attributes([
            ("service.name".to_owned(), "override".to_owned()),
            ("secret".to_owned(), "credential".to_owned()),
            ("z".to_owned(), "last".to_owned()),
        ])
        .unwrap()
        .try_with_scope("my-scope", "3")
        .unwrap()
        .try_with_schema_url("https://example.test/v3")
        .unwrap()
        .try_with_scope_attributes([
            ("secret".to_owned(), "credential".to_owned()),
            ("scope.kind".to_owned(), "runtime".to_owned()),
        ])
        .unwrap()
        .try_with_privacy(PrivacyConfig::new().with_drop_attribute("secret"))
        .unwrap();
    let mapper =
        OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new().with_max_spans_per_request(1))
            .unwrap();
    let filtered = mapper
        .collect_with_policy(
            &[span(2), span(3)],
            &[("service.name", "caller"), ("a", "first")],
            &policy,
        )
        .unwrap();
    assert_eq!(filtered.report().dropped_attributes, 2);
    let requests = filtered.into_parts().0.into_requests();
    assert_eq!(requests.len(), 2);
    for bytes in requests {
        let request: ExportTraceServiceRequest = decode(&bytes);
        let resource_spans = &request.resource_spans[0];
        let resource = resource_spans.resource.as_ref().unwrap();
        assert_eq!(resource.dropped_attributes_count, 1);
        assert_eq!(
            resource
                .attributes
                .iter()
                .map(|attribute| attribute.key.as_str())
                .collect::<Vec<_>>(),
            ["a", "service.name", "z"]
        );
        assert_eq!(string_value(&resource.attributes[1]), "override");
        let scope_spans = &resource_spans.scope_spans[0];
        let scope = scope_spans.scope.as_ref().unwrap();
        assert_eq!(scope.name, "my-scope");
        assert_eq!(scope.version, "3");
        assert_eq!(scope.dropped_attributes_count, 1);
        assert_eq!(scope.attributes[0].key, "scope.kind");
        assert_eq!(scope_spans.schema_url, "https://example.test/v3");
        assert_eq!(resource_spans.schema_url, scope_spans.schema_url);
    }
}

#[test]
fn privacy_is_frozen_and_uses_current_public_patterns() {
    let mut privacy = PrivacyConfig::new().with_pii_pattern("outdated");
    // A legacy caller can mutate the public rules after populating the cache.
    privacy.pii_patterns[0] = "credential-[a-z]+".to_owned();
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(privacy.clone())
        .unwrap();
    privacy.pii_patterns.clear();
    let records = [OtlpLogRecordInput::new(
        LogLevel::Info,
        OtlpLogBody::String("credential-private"),
        10,
    )];
    let result = logs().collect_with_policy(&records, &[], &policy).unwrap();
    assert_eq!(result.report().redacted_values, 1);
    let request: ExportLogsServiceRequest = decode(&result.output().requests[0]);
    assert_eq!(
        request.resource_logs[0].scope_logs[0].log_records[0]
            .body
            .as_ref()
            .unwrap()
            .value,
        Some(AnyValueValue::String("[REDACTED]".to_owned()))
    );
}

#[test]
fn policy_and_result_diagnostics_never_format_values() {
    let secret = "credential-in-config-or-payload";
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_scope(secret, secret)
        .unwrap()
        .try_with_schema_url(secret)
        .unwrap()
        .try_with_resource_attributes([(secret.to_owned(), secret.to_owned())])
        .unwrap()
        .try_with_scope_attributes([(secret.to_owned(), secret.to_owned())])
        .unwrap()
        .try_with_privacy(PrivacyConfig::new().with_pii_pattern(secret))
        .unwrap();
    let output = OwnedOtlpPolicyOutput::new(secret, OwnedOtlpPolicyReport::default());
    assert!(!format!("{policy:?}").contains(secret));
    assert!(!format!("{output:?}").contains(secret));
    let mut malformed = PrivacyConfig::new();
    malformed.pii_patterns.push(format!("{secret}["));
    let error = policy.try_with_privacy(malformed).unwrap_err();
    assert_eq!(error, OwnedOtlpPolicyError::InvalidPrivacyPattern);
    assert!(!format!("{error:?} {error}").contains(secret));
}

#[test]
fn policy_admission_has_finite_attributes_rules_and_pattern_budgets() {
    let duplicate = [
        ("key".to_owned(), "one".to_owned()),
        ("key".to_owned(), "two".to_owned()),
    ];
    assert_eq!(
        OwnedOtlpExportPolicy::new()
            .try_with_resource_attributes(duplicate)
            .unwrap_err(),
        OwnedOtlpPolicyError::InvalidConfiguration
    );
    assert!(OwnedOtlpExportPolicy::new().try_with_scope("", "").is_err());
    assert!(
        OwnedOtlpExportPolicy::new()
            .try_with_schema_url("x".repeat(MAX_SCHEMA_URL_BYTES + 1))
            .is_err()
    );
    assert!(
        OwnedOtlpExportPolicy::new()
            .try_with_resource_attributes(std::iter::repeat_with(|| (
                "key".to_owned(),
                "value".to_owned()
            )))
            .is_err()
    );
    let mut privacy = PrivacyConfig::new();
    privacy.drop_labels = vec!["key".to_owned(); MAX_PRIVACY_RULES_PER_KIND + 1];
    assert!(
        OwnedOtlpExportPolicy::new()
            .try_with_privacy(privacy)
            .is_err()
    );
    let mut privacy = PrivacyConfig::new();
    privacy.pii_patterns = vec!["pattern".to_owned(); MAX_PII_PATTERNS + 1];
    assert!(
        OwnedOtlpExportPolicy::new()
            .try_with_privacy(privacy)
            .is_err()
    );
    let attributes = (0..20).map(|index| (format!("key{index}"), "x".repeat(4096)));
    assert_eq!(
        OwnedOtlpExportPolicy::new()
            .try_with_resource_attributes(attributes)
            .unwrap_err(),
        OwnedOtlpPolicyError::LimitExceeded
    );
    let mut privacy = PrivacyConfig::new();
    privacy.pii_patterns.push("a{1000000}".to_owned());
    assert_eq!(
        OwnedOtlpExportPolicy::new()
            .try_with_privacy(privacy)
            .unwrap_err(),
        OwnedOtlpPolicyError::InvalidPrivacyPattern
    );
}

#[test]
fn attribute_merge_respects_mapper_limit_and_overrides_without_extra_slot() {
    let mapper =
        OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new().with_max_attributes_per_entity(1))
            .unwrap();
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_resource_attributes([("existing".to_owned(), "new".to_owned())])
        .unwrap();
    assert!(
        mapper
            .collect_with_policy(&[span(2)], &[("existing", "old")], &policy)
            .is_ok()
    );
    assert_eq!(
        mapper
            .collect_with_policy(&[span(2)], &[("other", "old")], &policy)
            .unwrap_err(),
        OwnedOtlpPolicyError::LimitExceeded
    );
}

#[test]
fn dropped_or_redacted_metric_labels_cannot_merge_cumulative_series() {
    let mapper = metrics();
    mapper.task_stuck_detected("first");
    mapper.task_stuck_detected("second");
    let dropped = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_drop_label("task_type"))
        .unwrap();
    assert_eq!(
        mapper.collect_with_policy(100, &[], &dropped).unwrap_err(),
        OwnedOtlpPolicyError::MetricSeriesCollision
    );
    let redacted = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_pii_pattern("first|second"))
        .unwrap();
    assert_eq!(
        mapper.collect_with_policy(100, &[], &redacted).unwrap_err(),
        OwnedOtlpPolicyError::MetricSeriesCollision
    );
    // A failed policy collection neither consumed points nor advanced time.
    let request: ExportMetricsServiceRequest = decode(&mapper.collect(20, &[]).unwrap()[0]);
    let Some(MetricData::Sum(sum)) = &request.resource_metrics[0].scope_metrics[0].metrics[0].data
    else {
        panic!("counter")
    };
    assert_eq!(sum.data_points.len(), 2);
    assert!(
        sum.data_points
            .iter()
            .all(|point| point.value == Some(NumberDataPointValue::Int(1)))
    );
}

#[test]
fn single_metric_series_can_drop_its_label_without_changing_measurement() {
    let mapper = metrics();
    mapper.task_stuck_detected("worker");
    mapper.task_stuck_detected("worker");
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_drop_label("task_type"))
        .unwrap();
    let output = mapper.collect_with_policy(20, &[], &policy).unwrap();
    assert_eq!(output.report().dropped_attributes, 1);
    let request: ExportMetricsServiceRequest = decode(&output.output()[0]);
    let Some(MetricData::Sum(sum)) = &request.resource_metrics[0].scope_metrics[0].metrics[0].data
    else {
        panic!("counter")
    };
    assert!(sum.data_points[0].attributes.is_empty());
    assert_eq!(sum.data_points[0].value, Some(NumberDataPointValue::Int(2)));
}

#[test]
fn collision_detection_covers_gauges_histograms_and_summaries() {
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_drop_label("tag"))
        .unwrap();
    let number_points = || {
        ["first", "second"]
            .map(|value| NumberDataPoint {
                attributes: vec![string_attribute("tag", value)],
                ..NumberDataPoint::default()
            })
            .to_vec()
    };
    let data = [
        MetricData::Gauge(Gauge {
            data_points: number_points(),
            ..Gauge::default()
        }),
        MetricData::Sum(Sum {
            data_points: number_points(),
            ..Sum::default()
        }),
        MetricData::Histogram(Histogram {
            data_points: ["first", "second"]
                .map(|value| HistogramDataPoint {
                    attributes: vec![string_attribute("tag", value)],
                    ..HistogramDataPoint::default()
                })
                .to_vec(),
            ..Histogram::default()
        }),
        MetricData::ExponentialHistogram(ExponentialHistogram {
            data_points: ["first", "second"]
                .map(|value| ExponentialHistogramDataPoint {
                    attributes: vec![string_attribute("tag", value)],
                    ..ExponentialHistogramDataPoint::default()
                })
                .to_vec(),
            ..ExponentialHistogram::default()
        }),
        MetricData::Summary(Summary {
            data_points: ["first", "second"]
                .map(|value| SummaryDataPoint {
                    attributes: vec![string_attribute("tag", value)],
                    ..SummaryDataPoint::default()
                })
                .to_vec(),
            ..Summary::default()
        }),
    ];
    for data in data {
        let mut metric = Metric {
            name: "example".to_owned(),
            data: Some(data),
            ..Metric::default()
        };
        assert_eq!(
            policy.metric(&mut metric, &mut OwnedOtlpPolicyReport::default()),
            Err(OwnedOtlpPolicyError::MetricSeriesCollision)
        );
    }
}

#[test]
fn trace_drop_counts_saturate_without_consuming_producer_event_or_link_counts() {
    let attributes = [("secret", "hidden"), ("keep", "visible")];
    let events = [OtlpTraceEventInput::new(15, "event")
        .with_attributes(&attributes)
        .with_dropped_attributes_count(u32::MAX)];
    let links = [OtlpTraceLinkInput::new([3; 16], [4; 8])
        .with_attributes(&attributes)
        .with_dropped_attributes_count(7)];
    let spans = [span(2)
        .with_attributes(&attributes)
        .with_dropped_attributes_count(u32::MAX)
        .with_events(&events)
        .with_links(&links)
        .with_dropped_events_count(9)
        .with_dropped_links_count(10)];
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_drop_attribute("secret"))
        .unwrap();
    let output = traces().collect_with_policy(&spans, &[], &policy).unwrap();
    assert_eq!(output.report().dropped_attributes, 3);
    let request: ExportTraceServiceRequest = decode(&output.output().requests[0]);
    let span = &request.resource_spans[0].scope_spans[0].spans[0];
    assert_eq!(span.dropped_attributes_count, u32::MAX);
    assert_eq!(span.events[0].dropped_attributes_count, u32::MAX);
    assert_eq!(span.links[0].dropped_attributes_count, 8);
    assert_eq!(span.dropped_events_count, 9);
    assert_eq!(span.dropped_links_count, 10);
    assert_eq!(span.attributes[0].key, "keep");
}

#[test]
fn structured_logs_filter_keys_and_strings_but_keep_opaque_bytes_and_types() {
    let nested = [
        OtlpLogKeyValueInput::string("secret", "drop-me"),
        OtlpLogKeyValueInput::string("visible", "credential-text"),
    ];
    let array = [
        OtlpLogBody::KeyValueList(&nested),
        OtlpLogBody::Bytes(b"credential-bytes"),
        OtlpLogBody::Int(42),
        OtlpLogBody::Bool(true),
    ];
    let attributes = [
        OtlpLogKeyValueInput::string("secret", "top-level"),
        OtlpLogKeyValueInput::new("structured", OtlpLogBody::KeyValueList(&nested)),
    ];
    let records = [
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Array(&array), 10)
            .with_attributes(&attributes)
            .with_dropped_attributes_count(7),
    ];
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(
            PrivacyConfig::new()
                .with_drop_attribute("secret")
                .with_pii_pattern("credential-[a-z]+"),
        )
        .unwrap();
    let output = logs().collect_with_policy(&records, &[], &policy).unwrap();
    assert_eq!(output.report().dropped_attributes, 1);
    assert_eq!(output.report().dropped_log_body_fields, 2);
    assert_eq!(output.report().redacted_values, 2);
    assert_eq!(output.output().producer_dropped_attributes(), 7);
    let request: ExportLogsServiceRequest = decode(&output.output().requests[0]);
    let record = &request.resource_logs[0].scope_logs[0].log_records[0];
    assert_eq!(record.dropped_attributes_count, 8);
    let Some(AnyValueValue::Array(body)) = &record.body.as_ref().unwrap().value else {
        panic!("array")
    };
    assert_eq!(
        body.values[1].value,
        Some(AnyValueValue::Bytes(b"credential-bytes".to_vec()))
    );
    assert_eq!(body.values[2].value, Some(AnyValueValue::Int(42)));
    assert_eq!(body.values[3].value, Some(AnyValueValue::Bool(true)));
    let Some(AnyValueValue::KeyValueList(nested)) = &body.values[0].value else {
        panic!("object")
    };
    assert_eq!(nested.values.len(), 1);
    assert_eq!(string_value(&nested.values[0]), "[REDACTED]");
}

#[test]
fn accepted_auto_pii_behavior_and_allowlist_are_shared() {
    let privacy = PrivacyConfig::new()
        .with_auto_pii_detection()
        .with_allowed_field("keep.*");
    let expected = privacy.redact_pii("keep.email", "owner@example.test");
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(privacy)
        .unwrap();
    let attrs = [
        OtlpLogKeyValueInput::string("keep.email", "owner@example.test"),
        OtlpLogKeyValueInput::string("drop.email", "owner@example.test"),
    ];
    let records = [
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Absent, 10).with_attributes(&attrs),
    ];
    let output = logs().collect_with_policy(&records, &[], &policy).unwrap();
    let request: ExportLogsServiceRequest = decode(&output.output().requests[0]);
    let record = &request.resource_logs[0].scope_logs[0].log_records[0];
    assert_eq!(record.attributes.len(), 1);
    assert_eq!(string_value(&record.attributes[0]), expected);
    assert_eq!(output.report().dropped_attributes, 1);
    assert_eq!(output.report().redacted_values, 1);
}

#[test]
fn original_collection_limits_cannot_be_bypassed_by_dropping_oversized_input() {
    let oversized = "x".repeat(OWNED_OTLP_MAX_ATTRIBUTE_VALUE_BYTES + 1);
    let attrs = [OtlpLogKeyValueInput::string("secret", &oversized)];
    let records = [
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Absent, 10).with_attributes(&attrs),
    ];
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_drop_attribute("secret"))
        .unwrap();
    assert!(logs().collect_with_policy(&records, &[], &policy).is_err());
    let unsampled = [span(2).with_trace_flags(0)];
    let output = traces()
        .collect_with_policy(&unsampled, &[("", "invalid-resource")], &policy)
        .unwrap();
    assert!(output.output().is_empty());
    assert_eq!(output.output().unsampled_spans(), 1);
    assert_eq!(*output.report(), OwnedOtlpPolicyReport::default());
}

#[test]
fn policy_metadata_and_redaction_growth_respect_collection_byte_budget() {
    let mapper = OwnedOtlpLogs::try_new(
        OwnedOtlpLogConfig::new()
            .with_scope("base", "")
            .with_schema_url("")
            .with_max_owned_bytes(64),
    )
    .unwrap();
    let records = [OtlpLogRecordInput::new(
        LogLevel::Info,
        OtlpLogBody::String("body"),
        10,
    )];
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_scope("x".repeat(64), "1")
        .unwrap();
    assert_eq!(
        mapper
            .collect_with_policy(&records, &[], &policy)
            .unwrap_err(),
        OwnedOtlpPolicyError::LimitExceeded
    );

    let mapper = OwnedOtlpLogs::try_new(
        OwnedOtlpLogConfig::new()
            .with_scope("s", "")
            .with_schema_url("")
            .with_max_owned_bytes(8),
    )
    .unwrap();
    let records = [OtlpLogRecordInput::new(
        LogLevel::Info,
        OtlpLogBody::String("x"),
        10,
    )];
    assert!(mapper.collect(&records, &[]).is_ok());
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_pii_pattern("^x$"))
        .unwrap();
    assert_eq!(
        mapper
            .collect_with_policy(&records, &[], &policy)
            .unwrap_err(),
        OwnedOtlpPolicyError::LimitExceeded
    );
}
