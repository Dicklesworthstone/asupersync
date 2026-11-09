//! Export policy reaches real native collectors before transport publication.

use super::tests::{
    Captured, Signal, accept, flush, framed, listener, partial, read_request, run_native,
};
use super::{OTLP_GRPC_MAX_MESSAGE_BYTES, OtlpGrpcErrorKind, OtlpGrpcExporter, OtlpGrpcSignal};
use crate::Cx;
use crate::grpc::Code;
use crate::grpc::client::Channel;
use crate::grpc::protobuf::{ProtoMessage, ProtobufWireLimits};
use crate::http::h2::{Connection, Header};
use crate::observability::level::LogLevel;
use crate::observability::metrics::MetricsProvider;
use crate::observability::otel::{
    OtlpLogBody, OtlpLogKeyValueInput, OtlpLogRecordInput, OtlpTraceEventInput, OtlpTraceLinkInput,
    OtlpTraceSpanInput, OtlpTraceStatus, OwnedOtlpExportPolicy, OwnedOtlpLogConfig, OwnedOtlpLogs,
    OwnedOtlpMetrics, OwnedOtlpMetricsConfig, OwnedOtlpPolicyError, OwnedOtlpPolicyReport,
    OwnedOtlpStatusCode, OwnedOtlpTraceConfig, OwnedOtlpTraces, PrivacyConfig,
    QueuedOtlpGrpcExporter,
};
use crate::observability::otlp_proto::collector::logs::ExportLogsServiceRequest;
use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
use crate::observability::otlp_proto::collector::trace::ExportTraceServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{
    AnyValueValue, InstrumentationScope, KeyValue, Resource,
};
use crate::observability::otlp_proto::metrics::{MetricData, NumberDataPointValue};
use crate::types::CancelKind;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;

const SECRET: &str = "credential-sensitive";
const REDACTED: &str = "[REDACTED]";
const SCHEMA: &str = "https://schemas.example.test/v2";

fn privacy() -> PrivacyConfig {
    PrivacyConfig::new()
        .with_drop_attribute("secret")
        .with_pii_pattern("credential-[a-z]+")
}

fn policy() -> OwnedOtlpExportPolicy {
    OwnedOtlpExportPolicy::new()
        .try_with_scope("policy-scope", "2")
        .unwrap()
        .try_with_schema_url(SCHEMA)
        .unwrap()
        .try_with_resource_attributes([
            ("service.name".to_owned(), "policy-service".to_owned()),
            ("secret".to_owned(), SECRET.to_owned()),
            ("owner".to_owned(), SECRET.to_owned()),
        ])
        .unwrap()
        .try_with_scope_attributes([
            ("secret".to_owned(), SECRET.to_owned()),
            ("scope.owner".to_owned(), SECRET.to_owned()),
        ])
        .unwrap()
        .try_with_privacy(privacy())
        .unwrap()
}

fn respond(
    socket: &mut impl Write,
    connection: &mut Connection,
    stream: u32,
    body: &[u8],
    status: &str,
) {
    connection
        .send_headers(
            stream,
            vec![
                Header::new(":status", "200"),
                Header::new("content-type", "application/grpc"),
            ],
            false,
        )
        .unwrap();
    connection.send_data(stream, framed(body), false).unwrap();
    connection
        .send_headers(stream, vec![Header::new("grpc-status", status)], true)
        .unwrap();
    flush(socket, connection);
}

fn payload(captured: &Captured, signal: OtlpGrpcSignal) -> &[u8] {
    assert_eq!(captured.header(":method"), Some("POST"));
    assert_eq!(captured.header(":path"), Some(signal.method_path()));
    assert_eq!(captured.header("content-type"), Some("application/grpc"));
    assert!(captured.body.len() >= 5);
    assert_eq!(captured.body[0], 0, "uncompressed owned request");
    let length = u32::from_be_bytes(captured.body[1..5].try_into().unwrap()) as usize;
    assert_eq!(length, captured.body.len() - 5, "one complete gRPC message");
    &captured.body[5..]
}

fn decode<M: ProtoMessage>(body: &[u8]) -> M {
    // Nested schema validation charges work beyond raw payload length, as on
    // the owned encoder. Use its admitted envelope instead of a wire-sized
    // budget that can reject a small but valid nested metric request.
    let limits = ProtobufWireLimits::for_message_size(OTLP_GRPC_MAX_MESSAGE_BYTES)
        .with_max_fields(OTLP_GRPC_MAX_MESSAGE_BYTES);
    M::decode_from_bytes(body, limits).unwrap()
}

fn string_attribute<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a str> {
    match attributes
        .iter()
        .find(|entry| entry.key == key)?
        .value
        .as_ref()?
        .value
        .as_ref()?
    {
        AnyValueValue::String(value) => Some(value),
        other => panic!("expected string attribute {key}: {other:?}"),
    }
}

fn common_metadata(resource: &Resource, scope: &InstrumentationScope, schema: &str) {
    assert_eq!(
        string_attribute(&resource.attributes, "service.name"),
        Some("policy-service")
    );
    assert_eq!(
        string_attribute(&resource.attributes, "shared"),
        Some("inherited")
    );
    assert_eq!(
        string_attribute(&resource.attributes, "owner"),
        Some(REDACTED)
    );
    assert_eq!(string_attribute(&resource.attributes, "secret"), None);
    assert_eq!(resource.dropped_attributes_count, 1);
    assert_eq!(scope.name, "policy-scope");
    assert_eq!(scope.version, "2");
    assert_eq!(schema, SCHEMA);
    assert_eq!(
        string_attribute(&scope.attributes, "scope.owner"),
        Some(REDACTED)
    );
    assert_eq!(string_attribute(&scope.attributes, "secret"), None);
    assert_eq!(scope.dropped_attributes_count, 1);
}

fn assert_policy_wire(captured: &Captured, signal: OtlpGrpcSignal) {
    let body = payload(captured, signal);
    for forbidden in [SECRET, "transport-service"] {
        assert!(
            !body
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "collector received a forbidden value"
        );
    }
    match signal {
        OtlpGrpcSignal::Metrics => {
            let decoded: ExportMetricsServiceRequest = decode(body);
            assert_eq!(decoded.resource_metrics.len(), 1);
            let resource = &decoded.resource_metrics[0];
            assert_eq!(resource.schema_url, SCHEMA);
            assert_eq!(resource.scope_metrics.len(), 1);
            let scope = &resource.scope_metrics[0];
            common_metadata(
                resource.resource.as_ref().unwrap(),
                scope.scope.as_ref().unwrap(),
                &scope.schema_url,
            );
            assert_eq!(scope.metrics.len(), 1);
            assert_eq!(
                scope.metrics[0].name,
                "asupersync.task.stuck_detected_total"
            );
            let Some(MetricData::Sum(sum)) = &scope.metrics[0].data else {
                panic!("expected cumulative counter")
            };
            assert!(sum.is_monotonic);
            assert_eq!(sum.data_points.len(), 1);
            assert_eq!(sum.data_points[0].value, Some(NumberDataPointValue::Int(1)));
            assert_eq!(
                string_attribute(&sum.data_points[0].attributes, "task_type"),
                Some(REDACTED)
            );
        }
        OtlpGrpcSignal::Traces => {
            let decoded: ExportTraceServiceRequest = decode(body);
            assert_eq!(decoded.resource_spans.len(), 1);
            let resource = &decoded.resource_spans[0];
            assert_eq!(resource.schema_url, SCHEMA);
            assert_eq!(resource.scope_spans.len(), 1);
            let scope = &resource.scope_spans[0];
            common_metadata(
                resource.resource.as_ref().unwrap(),
                scope.scope.as_ref().unwrap(),
                &scope.schema_url,
            );
            assert_eq!(scope.spans.len(), 1);
            let span = &scope.spans[0];
            assert_eq!(span.trace_id, vec![1; 16]);
            assert_eq!(span.span_id, vec![2; 8]);
            assert_eq!(span.name, REDACTED);
            assert!(span.trace_state.is_empty());
            assert_eq!(span.status.as_ref().unwrap().message, REDACTED);
            assert_eq!(span.dropped_attributes_count, 3);
            assert_eq!(string_attribute(&span.attributes, "owner"), Some(REDACTED));
            assert_eq!(span.events.len(), 1);
            assert_eq!(span.events[0].name, REDACTED);
            assert_eq!(span.events[0].dropped_attributes_count, 4);
            assert_eq!(span.links.len(), 1);
            assert!(span.links[0].trace_state.is_empty());
            assert_eq!(span.links[0].dropped_attributes_count, 5);
        }
        OtlpGrpcSignal::Logs => {
            let decoded: ExportLogsServiceRequest = decode(body);
            assert_eq!(decoded.resource_logs.len(), 1);
            let resource = &decoded.resource_logs[0];
            assert_eq!(resource.schema_url, SCHEMA);
            assert_eq!(resource.scope_logs.len(), 1);
            let scope = &resource.scope_logs[0];
            common_metadata(
                resource.resource.as_ref().unwrap(),
                scope.scope.as_ref().unwrap(),
                &scope.schema_url,
            );
            assert_eq!(scope.log_records.len(), 1);
            let record = &scope.log_records[0];
            assert_eq!(record.event_name, REDACTED);
            assert_eq!(record.dropped_attributes_count, 8);
            let Some(AnyValueValue::KeyValueList(body)) =
                record.body.as_ref().and_then(|body| body.value.as_ref())
            else {
                panic!("expected structured body")
            };
            assert_eq!(string_attribute(&body.values, "owner"), Some(REDACTED));
            assert!(body.values.iter().all(|field| field.key != "secret"));
            let values = body
                .values
                .iter()
                .find(|field| field.key == "children")
                .unwrap();
            let Some(AnyValueValue::Array(values)) =
                values.value.as_ref().and_then(|value| value.value.as_ref())
            else {
                panic!("expected body array")
            };
            assert_eq!(
                values.values[0].value,
                Some(AnyValueValue::String(REDACTED.to_owned()))
            );
            assert_eq!(values.values[1].value, Some(AnyValueValue::Bool(true)));
        }
    }
}

async fn export_fixture(
    cx: &Cx,
    signal: OtlpGrpcSignal,
    exporter: OtlpGrpcExporter,
    policy: &OwnedOtlpExportPolicy,
    queued: bool,
) -> OwnedOtlpPolicyReport {
    let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
    metrics.task_stuck_detected(SECRET);
    let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new()).unwrap();
    let attributes = [("secret", SECRET), ("owner", SECRET)];
    let events = [OtlpTraceEventInput::new(3, SECRET)
        .with_attributes(&attributes)
        .with_dropped_attributes_count(3)];
    let links = [OtlpTraceLinkInput::new([3; 16], [4; 8])
        .with_trace_state("vendor=credential-sensitive")
        .with_attributes(&attributes)
        .with_dropped_attributes_count(4)];
    let spans = [OtlpTraceSpanInput::new([1; 16], [2; 8], SECRET, 2, 4)
        .with_trace_state("vendor=credential-sensitive")
        .with_attributes(&attributes)
        .with_dropped_attributes_count(2)
        .with_events(&events)
        .with_links(&links)
        .with_status(OtlpTraceStatus::new(OwnedOtlpStatusCode::Error, SECRET))];
    let logs = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).unwrap();
    let log_attributes = [
        OtlpLogKeyValueInput::string("secret", SECRET),
        OtlpLogKeyValueInput::string("owner", SECRET),
    ];
    let children = [OtlpLogBody::String(SECRET), OtlpLogBody::Bool(true)];
    let body = [
        OtlpLogKeyValueInput::string("secret", SECRET),
        OtlpLogKeyValueInput::string("owner", SECRET),
        OtlpLogKeyValueInput::new("children", OtlpLogBody::Array(&children)),
    ];
    let records = [
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::KeyValueList(&body), 4)
            .with_attributes(&log_attributes)
            .with_dropped_attributes_count(7)
            .with_event_name(SECRET),
    ];
    if queued {
        let queue = QueuedOtlpGrpcExporter::new(exporter);
        let result = match signal {
            OtlpGrpcSignal::Metrics => queue.enqueue_owned_metrics_with_policy(&metrics, 5, policy),
            OtlpGrpcSignal::Traces => {
                queue.enqueue_owned_traces_with_policy(&traces, &spans, policy)
            }
            OtlpGrpcSignal::Logs => queue.enqueue_owned_logs_with_policy(&logs, &records, policy),
        }
        .unwrap();
        let (count, report) = result.into_parts();
        assert_eq!(count, 1);
        assert_eq!(queue.queue_stats().queue.queued_batches, 1);
        queue.flush_queued(cx).await.unwrap();
        let stats = queue.queue_stats();
        assert_eq!(stats.queue.delivered_batches, 1);
        assert_eq!(stats.queue.retained_batches, 0);
        assert_eq!(stats.queue.retained_bytes, 0);
        report
    } else {
        let result = match signal {
            OtlpGrpcSignal::Metrics => {
                exporter
                    .send_owned_metrics_with_policy(cx, &metrics, 5, policy)
                    .await
            }
            OtlpGrpcSignal::Traces => {
                exporter
                    .send_owned_traces_with_policy(cx, &traces, &spans, policy)
                    .await
            }
            OtlpGrpcSignal::Logs => {
                exporter
                    .send_owned_logs_with_policy(cx, &logs, &records, policy)
                    .await
            }
        }
        .unwrap();
        let (receipts, report) = result.into_parts();
        assert_eq!(receipts.responses().len(), 1);
        assert_eq!(receipts.responses()[0].signal(), signal);
        report
    }
}

#[test]
fn native_and_queued_policies_scrub_every_signal_before_the_collector() {
    for queued in [false, true] {
        for signal in [
            OtlpGrpcSignal::Metrics,
            OtlpGrpcSignal::Traces,
            OtlpGrpcSignal::Logs,
        ] {
            let (listener, address) = listener();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let (mut connection, captured) = read_request(&mut socket);
                assert_policy_wire(&captured, signal);
                respond(&mut socket, &mut connection, captured.stream, &[], "0");
            });
            run_native(|cx| async move {
                let channel = Channel::connect(format!("http://{address}")).await.unwrap();
                let exporter = OtlpGrpcExporter::new(channel)
                    .unwrap()
                    .try_with_resource_attributes([
                        ("service.name".to_owned(), "transport-service".to_owned()),
                        ("shared".to_owned(), "inherited".to_owned()),
                    ])
                    .unwrap();
                let report = export_fixture(&cx, signal, exporter, &policy(), queued).await;
                assert_eq!(
                    report.dropped_attributes,
                    match signal {
                        OtlpGrpcSignal::Metrics => 2,
                        OtlpGrpcSignal::Traces => 5,
                        OtlpGrpcSignal::Logs => 3,
                    }
                );
                assert_eq!(
                    report.dropped_log_body_fields,
                    usize::from(signal == OtlpGrpcSignal::Logs)
                );
                assert_eq!(
                    report.redacted_values,
                    match signal {
                        OtlpGrpcSignal::Metrics => 3,
                        OtlpGrpcSignal::Traces => 10,
                        OtlpGrpcSignal::Logs => 6,
                    }
                );
                assert!(!format!("{report:?}").contains(SECRET));
            });
            peer.join().unwrap();
        }
    }
}

#[test]
fn default_policy_preserves_legacy_bytes_and_custom_log_scope() {
    let policy = OwnedOtlpExportPolicy::new();
    let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
    metrics.task_stuck_detected("worker");
    let attributes = [("service.name", "legacy")];
    let expected = metrics.collect(4, &attributes).unwrap();
    let actual = metrics
        .collect_with_policy(4, &attributes, &policy)
        .unwrap();
    assert_eq!(actual.output(), &expected);
    assert_eq!(actual.report(), &OwnedOtlpPolicyReport::default());

    let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new()).unwrap();
    let spans = [OtlpTraceSpanInput::new([1; 16], [2; 8], "work", 2, 3)];
    let expected = traces.collect(&spans, &attributes).unwrap();
    let actual = traces
        .collect_with_policy(&spans, &attributes, &policy)
        .unwrap();
    assert_eq!(actual.output(), &expected);
    assert_eq!(actual.report(), &OwnedOtlpPolicyReport::default());

    let logs = OwnedOtlpLogs::try_new(
        OwnedOtlpLogConfig::new()
            .with_scope("legacy-scope", "17")
            .with_schema_url("https://schemas.example.test/legacy"),
    )
    .unwrap();
    let records = [OtlpLogRecordInput::new(
        LogLevel::Info,
        OtlpLogBody::String("legacy body"),
        3,
    )];
    let attributes = [OtlpLogKeyValueInput::string("service.name", "legacy")];
    let expected = logs.collect(&records, &attributes).unwrap();
    let actual = logs
        .collect_with_policy(&records, &attributes, &policy)
        .unwrap();
    assert_eq!(actual.output(), &expected);
    assert_eq!(actual.report(), &OwnedOtlpPolicyReport::default());
}

#[test]
fn metric_series_collisions_refuse_direct_and_queued_exports_before_dialing() {
    let (listener, address) = listener();
    run_native(|cx| async move {
        let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
        metrics.task_stuck_detected("first");
        metrics.task_stuck_detected("second");
        let policy = OwnedOtlpExportPolicy::new()
            .try_with_privacy(PrivacyConfig::new().with_drop_label("task_type"))
            .unwrap();
        let mapping = metrics.collect_with_policy(4, &[], &policy).unwrap_err();
        assert!(matches!(
            mapping,
            OwnedOtlpPolicyError::MetricSeriesCollision
        ));
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let error = exporter
            .send_owned_metrics_with_policy(&cx, &metrics, 4, &policy)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), OtlpGrpcErrorKind::Mapping);
        assert_eq!(error.mapping_code(), Some(mapping.code()));
        assert!(error.completed_responses().is_empty());
        assert!(error.policy_report().is_none());
        let queue = QueuedOtlpGrpcExporter::new(exporter);
        assert!(
            queue
                .enqueue_owned_metrics_with_policy(&metrics, 4, &policy)
                .is_err()
        );
        assert_eq!(queue.queue_stats().queue.retained_batches, 0);
        assert_eq!(queue.queue_stats().queue.retained_bytes, 0);
        assert_eq!(
            metrics.rejected_updates(),
            0,
            "policy did not mutate provider admission"
        );
        assert_eq!(
            metrics.collect(4, &[]).unwrap().len(),
            1,
            "unfiltered collector remains available explicitly"
        );
    });
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn policy_collections_preflight_every_request_without_io_or_a_queue_prefix() {
    let (listener, address) = listener();
    run_native(|cx| async move {
        let logs =
            OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_records_per_request(1))
                .unwrap();
        let large = "x".repeat(512);
        let attributes = [OtlpLogKeyValueInput::string("secret", SECRET)];
        let records = [
            OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("small"), 1)
                .with_attributes(&attributes),
            OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String(&large), 2)
                .with_attributes(&attributes),
        ];
        let policy = OwnedOtlpExportPolicy::new()
            .try_with_privacy(privacy())
            .unwrap();
        let mapped = logs.collect_with_policy(&records, &[], &policy).unwrap();
        assert_eq!(mapped.output().requests().len(), 2);
        assert_eq!(mapped.report().dropped_attributes, 2);
        let first_size = mapped.output().requests()[0].len();
        assert!(first_size < mapped.output().requests()[1].len());
        let channel = Channel::builder(format!("http://{address}"))
            .max_send_message_size(first_size)
            .connect()
            .await
            .unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let error = exporter
            .send_owned_logs_with_policy(&cx, &logs, &records, &policy)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), OtlpGrpcErrorKind::RequestTooLarge);
        assert_eq!(error.policy_report(), Some(mapped.report()));
        assert!(error.completed_responses().is_empty());
        let queue = QueuedOtlpGrpcExporter::new(exporter);
        assert!(
            queue
                .enqueue_owned_logs_with_policy(&logs, &records, &policy)
                .is_err()
        );
        let stats = queue.queue_stats().queue;
        assert_eq!(stats.retained_batches, 0);
        assert_eq!(stats.retained_bytes, 0);
        assert_eq!(stats.queued_batches, 0);

        // A later invalid record must also refuse the entire borrowed input,
        // even though the first record fits and its secret field is dropped.
        let bounded =
            OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_owned_bytes(128)).unwrap();
        assert!(
            queue
                .enqueue_owned_logs_with_policy(&bounded, &records, &policy)
                .is_err()
        );
        assert_eq!(queue.queue_stats().queue.retained_batches, 0);
    });
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn policy_counts_and_partial_receipts_survive_a_later_native_failure() {
    let (listener, address) = listener();
    let peer = std::thread::spawn(move || {
        for status in ["0", "14"] {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            let body = payload(&captured, OtlpGrpcSignal::Logs);
            assert!(
                !body
                    .windows(SECRET.len())
                    .any(|window| window == SECRET.as_bytes())
            );
            let request: ExportLogsServiceRequest = decode(body);
            let record = &request.resource_logs[0].scope_logs[0].log_records[0];
            assert_eq!(
                record.body.as_ref().unwrap().value,
                Some(AnyValueValue::String(REDACTED.to_owned()))
            );
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                &partial(1, SECRET),
                status,
            );
        }
    });
    run_native(|cx| async move {
        let logs =
            OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_records_per_request(1))
                .unwrap();
        let records = [
            OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String(SECRET), 1),
            OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String(SECRET), 2),
        ];
        let policy = OwnedOtlpExportPolicy::new()
            .try_with_privacy(privacy())
            .unwrap();
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let error = exporter
            .send_owned_logs_with_policy(&cx, &logs, &records, &policy)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), OtlpGrpcErrorKind::Rpc);
        assert_eq!(error.grpc_code(), Some(Code::Unavailable));
        assert_eq!(error.completed_responses().len(), 1);
        let receipt = &error.completed_responses()[0];
        assert!(receipt.is_partial_success());
        assert_eq!(receipt.rejected_items(), 1);
        assert_eq!(
            receipt.error_message(),
            SECRET,
            "collector diagnostics remain explicit access only"
        );
        let report = error.policy_report().unwrap();
        assert_eq!(report.redacted_values, 2);
        assert_eq!(report.dropped_attributes, 0);
        assert!(!format!("{error:?} {error}").contains(SECRET));
    });
    peer.join().unwrap();
}

#[test]
fn parked_policy_export_cancels_with_report_and_retires_the_native_socket() {
    let (listener, address) = listener();
    let witness = Arc::new(Signal::default());
    let observed = Arc::clone(&witness);
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        let (_connection, captured) = read_request(&mut socket);
        let body = payload(&captured, OtlpGrpcSignal::Logs);
        let request: ExportLogsServiceRequest = decode(body);
        let record = &request.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(
            record.body.as_ref().unwrap().value,
            Some(AnyValueValue::String(REDACTED.to_owned()))
        );
        observed.publish();
        let mut remaining = [0; 1024];
        loop {
            match socket.read(&mut remaining) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("cancelled policy export did not retire its socket: {error}"),
            }
        }
    });
    run_native(|owner| async move {
        let driver = Cx::current().unwrap();
        assert_ne!(owner.task_id(), driver.task_id());
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let logs = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).unwrap();
        let records = [OtlpLogRecordInput::new(
            LogLevel::Info,
            OtlpLogBody::String(SECRET),
            1,
        )];
        let policy = OwnedOtlpExportPolicy::new()
            .try_with_privacy(privacy())
            .unwrap();
        let mut call =
            Box::pin(exporter.send_owned_logs_with_policy(&owner, &logs, &records, &policy));
        let mut cancelled = false;
        let result = poll_fn(|task| {
            *witness.waiter.lock().unwrap() = Some(task.waker().clone());
            if let Poll::Ready(result) = call.as_mut().poll(task) {
                return Poll::Ready(result);
            }
            if witness.ready.load(Ordering::Acquire) && !cancelled {
                cancelled = true;
                owner.cancel_with(CancelKind::User, Some("stop policy export"));
            }
            Poll::Pending
        })
        .await;
        drop(call);
        assert!(
            cancelled,
            "peer witnessed a real request before cancellation"
        );
        let error = result.unwrap_err();
        assert_eq!(error.grpc_code(), Some(Code::Cancelled));
        assert_eq!(error.policy_report().unwrap().redacted_values, 1);
        assert!(error.completed_responses().is_empty());
        assert!(!driver.is_cancel_requested());
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
    });
    peer.join().unwrap();
}
