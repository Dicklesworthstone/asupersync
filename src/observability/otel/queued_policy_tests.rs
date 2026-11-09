use super::*;
use crate::observability::metrics::MetricsProvider;
use crate::observability::otlp_proto::collector::logs::ExportLogsServiceRequest;
use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
use crate::observability::otlp_proto::collector::trace::ExportTraceServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{AnyValueValue, KeyValue};
use crate::observability::otlp_proto::metrics::MetricData;

fn string_attribute<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a str> {
    match attributes
        .iter()
        .find(|attribute| attribute.key == key)?
        .value
        .as_ref()?
        .value
        .as_ref()?
    {
        AnyValueValue::String(value) => Some(value),
        _ => None,
    }
}

fn decode<M: ProtoMessage>(body: &[u8]) -> M {
    M::decode_from_bytes(body, otlp_request_limits(OWNED_OTLP_DEFAULT_REQUEST_BYTES)).unwrap()
}

#[test]
fn http_policy_admission_captures_filtered_bodies_and_the_exact_destination() {
    const ENDPOINT: &str = "http://127.0.0.1:4318/custom/collector";
    const SECRET: &str = "credential-private";
    let exporter = OtlpHttpExporter::from_config(
        OtlpHttpConfigBuilder::new(ENDPOINT)
            .with_resource_attribute("service.name", "transport-service")
            .with_resource_attribute("secret", SECRET)
            .build()
            .unwrap(),
    );
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_scope("shared-scope", "2")
        .unwrap()
        .try_with_resource_attributes([
            ("service.name".to_owned(), "policy-service".to_owned()),
            ("owner".to_owned(), SECRET.to_owned()),
        ])
        .unwrap()
        .try_with_scope_attributes([("secret".to_owned(), SECRET.to_owned())])
        .unwrap()
        .try_with_privacy(
            PrivacyConfig::new()
                .with_drop_attribute("secret")
                .with_pii_pattern("credential-[a-z]+"),
        )
        .unwrap();
    let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
    metrics.task_stuck_detected(SECRET);
    let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new()).unwrap();
    let spans = [OtlpTraceSpanInput::new([1; 16], [2; 8], SECRET, 2, 3)];
    let logs = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).unwrap();
    let records = [OtlpLogRecordInput::new(
        LogLevel::Info,
        OtlpLogBody::String(SECRET),
        3,
    )];
    let outputs = [
        exporter
            .enqueue_owned_metrics_with_policy(&metrics, 4, &policy)
            .unwrap(),
        exporter
            .enqueue_owned_traces_with_policy(&traces, &spans, &policy)
            .unwrap(),
        exporter
            .enqueue_owned_logs_with_policy(&logs, &records, &policy)
            .unwrap(),
    ];
    for output in outputs {
        assert_eq!(*output.output(), 1);
        assert_eq!(output.report().dropped_attributes, 2);
        assert_eq!(output.report().redacted_values, 2);
    }
    assert_eq!(exporter.queue_stats().retained_batches, 3);
    for expected_signal in [
        OtlpGrpcSignal::Metrics,
        OtlpGrpcSignal::Traces,
        OtlpGrpcSignal::Logs,
    ] {
        let delivery = exporter.export_queue.take().unwrap();
        let batch = delivery.batch.as_ref().unwrap();
        let Destination::Http { config, .. } = &batch.destination else {
            panic!("HTTP admission changed transport");
        };
        assert_eq!(config.endpoint(), ENDPOINT);
        let Payload::Encoded { signal, body } = &batch.payload else {
            panic!("policy admission must retain already filtered bytes");
        };
        assert_eq!(*signal, expected_signal);
        assert_eq!(batch.bytes, body.capacity() + config_bytes(config).unwrap());
        for forbidden in [SECRET, "transport-service"] {
            assert!(
                !body
                    .windows(forbidden.len())
                    .any(|window| window == forbidden.as_bytes())
            );
        }
        let (resource, scope) = match signal {
            OtlpGrpcSignal::Metrics => {
                let mut request: ExportMetricsServiceRequest = decode(body);
                let mut resource = request.resource_metrics.remove(0);
                let scope = resource.scope_metrics.remove(0);
                let Some(MetricData::Sum(sum)) = &scope.metrics[0].data else {
                    panic!("counter");
                };
                assert_eq!(
                    string_attribute(&sum.data_points[0].attributes, "task_type"),
                    Some("[REDACTED]")
                );
                (resource.resource.unwrap(), scope.scope.unwrap())
            }
            OtlpGrpcSignal::Traces => {
                let mut request: ExportTraceServiceRequest = decode(body);
                let mut resource = request.resource_spans.remove(0);
                let scope = resource.scope_spans.remove(0);
                assert_eq!(scope.spans[0].name, "[REDACTED]");
                (resource.resource.unwrap(), scope.scope.unwrap())
            }
            OtlpGrpcSignal::Logs => {
                let mut request: ExportLogsServiceRequest = decode(body);
                let mut resource = request.resource_logs.remove(0);
                let scope = resource.scope_logs.remove(0);
                assert_eq!(
                    scope.log_records[0].body.as_ref().unwrap().value,
                    Some(AnyValueValue::String("[REDACTED]".to_owned()))
                );
                (resource.resource.unwrap(), scope.scope.unwrap())
            }
        };
        assert_eq!(
            string_attribute(&resource.attributes, "service.name"),
            Some("policy-service")
        );
        assert_eq!(
            string_attribute(&resource.attributes, "owner"),
            Some("[REDACTED]")
        );
        assert_eq!(resource.dropped_attributes_count, 1);
        assert_eq!(scope.name, "shared-scope");
        assert_eq!(scope.version, "2");
        assert_eq!(scope.dropped_attributes_count, 1);
        drop(delivery);
    }
    assert_eq!(exporter.queue_stats().retained_batches, 0);
    assert_eq!(exporter.queue_stats().retained_bytes, 0);
}

#[test]
fn http_policy_admission_refuses_collisions_and_capacity_without_a_prefix() {
    let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/logs");
    let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
    metrics.task_stuck_detected("first");
    metrics.task_stuck_detected("second");
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_drop_label("task_type"))
        .unwrap();
    assert!(
        exporter
            .enqueue_owned_metrics_with_policy(&metrics, 100, &policy)
            .is_err()
    );
    assert_eq!(exporter.queue_stats(), OtlpExportQueueStats::default());
    assert!(
        metrics.collect(2, &[]).is_ok(),
        "a collision did not advance collection time"
    );

    let policy = OwnedOtlpExportPolicy::new();
    let logs =
        OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_records_per_request(1)).unwrap();
    let record = OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("retained"), 1);
    for _ in 0..OTLP_EXPORT_QUEUE_MAX_BATCHES - 1 {
        assert_eq!(
            *exporter
                .enqueue_owned_logs_with_policy(&logs, &[record], &policy)
                .unwrap()
                .output(),
            1
        );
    }
    let before = exporter.queue_stats();
    assert!(
        exporter
            .enqueue_owned_logs_with_policy(&logs, &[record, record], &policy)
            .is_err()
    );
    assert_eq!(exporter.queue_stats(), before);
    let delivery = exporter.export_queue.take().unwrap();
    assert!(
        exporter
            .enqueue_owned_logs_with_policy(&logs, &[record, record], &policy)
            .is_err()
    );
    assert_eq!(
        exporter.queue_stats().retained_batches,
        before.retained_batches
    );
    drop(delivery);
    assert_eq!(
        *exporter
            .enqueue_owned_logs_with_policy(&logs, &[record, record], &policy)
            .unwrap()
            .output(),
        2
    );
    assert_eq!(
        exporter.queue_stats().retained_batches,
        OTLP_EXPORT_QUEUE_MAX_BATCHES
    );
}
