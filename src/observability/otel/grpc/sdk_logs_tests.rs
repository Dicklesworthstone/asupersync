//! External SDK logging reaches native collector acknowledgements and shutdown.

use super::queue_receipt_tests::{
    data_was_consumed, native, no_more_connections, read_request, response_data, response_end,
};
use super::tests::{Captured, accept, listener, partial};
use super::{OTLP_GRPC_MAX_MESSAGE_BYTES, OtlpGrpcExporter, OtlpGrpcRetryPolicy, OtlpGrpcSignal};
use crate::channel::oneshot;
use crate::grpc::Channel;
use crate::grpc::protobuf::{ProtoMessage, ProtobufWireLimits};
use crate::observability::otel::{
    ManagedOtlpOutcome, OtlpSdkLogExporter, OwnedOtlpExportPolicy, PrivacyConfig,
    QueuedOtlpGrpcExporter,
};
use crate::observability::otlp_proto::collector::logs::ExportLogsServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{AnyValueValue, KeyValue};
use opentelemetry::logs::{
    AnyValue as SdkValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity,
};
use opentelemetry::trace::{SpanContext, TraceContextExt as _, TraceState};
use opentelemetry::{
    Context, InstrumentationScope, Key, KeyValue as SdkAttribute, SpanId, TraceFlags, TraceId,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogRecord, SdkLoggerProvider};
use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::{Mutex, mpsc};
use std::task::Poll;
use std::time::{Duration, UNIX_EPOCH};

const WATCHDOG: Duration = Duration::from_secs(10);
const RESOURCE_SCHEMA: &str = "https://schemas.example/log-resource/v2";
const SCOPE_SCHEMA: &str = "https://schemas.example/log-scope/v1";
const SECRET: &str = "credential-sensitive";
const TRANSPORT_DEFAULT: &str = "transport-default";
const TRACE_ID: [u8; 16] = [0x11; 16];
const SPAN_ID: [u8; 8] = [0x22; 8];

fn attribute<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a AnyValueValue> {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)?
        .value
        .as_ref()?
        .value
        .as_ref()
}

fn nested_body() -> SdkValue {
    SdkValue::Map(Box::new(HashMap::from([
        (
            Key::new("message"),
            SdkValue::from("body credential-sensitive"),
        ),
        (Key::new("count"), SdkValue::Int(7)),
        (Key::new("secret"), SdkValue::from(SECRET)),
        (
            Key::new("nested"),
            SdkValue::ListAny(Box::new(vec![
                SdkValue::Boolean(true),
                SdkValue::Double(1.5),
                SdkValue::Map(Box::new(HashMap::from([
                    (Key::new("owner"), SdkValue::from(SECRET)),
                    (Key::new("secret"), SdkValue::from(SECRET)),
                    (
                        Key::new("bytes"),
                        SdkValue::Bytes(Box::new(vec![0, 255, 1])),
                    ),
                ]))),
            ])),
        ),
    ])))
}

fn assert_sdk_log(captured: &Captured, override_scope: bool) {
    assert_eq!(captured.header(":method"), Some("POST"));
    assert_eq!(
        captured.header(":path"),
        Some(OtlpGrpcSignal::Logs.method_path())
    );
    assert_eq!(captured.header("content-type"), Some("application/grpc"));
    assert_eq!(captured.header("te"), Some("trailers"));
    assert!(captured.body.len() >= 5);
    assert_eq!(captured.body[0], 0);
    let length = u32::from_be_bytes(captured.body[1..5].try_into().unwrap()) as usize;
    assert_eq!(
        length,
        captured.body.len() - 5,
        "one complete SDK log request"
    );
    let body = &captured.body[5..];
    for forbidden in [SECRET, TRANSPORT_DEFAULT, "original-sdk-log-scope"] {
        assert!(
            !body
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "privacy and target/policy metadata are applied before wire publication"
        );
    }
    let limits = ProtobufWireLimits::for_message_size(OTLP_GRPC_MAX_MESSAGE_BYTES)
        .with_max_fields(OTLP_GRPC_MAX_MESSAGE_BYTES);
    let request = ExportLogsServiceRequest::decode_from_bytes(body, limits).unwrap();
    assert_eq!(request.resource_logs.len(), 1);
    let resource = &request.resource_logs[0];
    assert_eq!(resource.schema_url, RESOURCE_SCHEMA);
    let attributes = &resource.resource.as_ref().unwrap().attributes;
    assert_eq!(
        attribute(attributes, "service.name"),
        Some(&AnyValueValue::String("native-sdk-logs".to_owned()))
    );
    assert_eq!(
        attribute(attributes, "enabled"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(attribute(attributes, "shard"), Some(&AnyValueValue::Int(2)));
    assert_eq!(
        attribute(attributes, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(attribute(attributes, "secret"), None);
    assert_eq!(
        resource.resource.as_ref().unwrap().dropped_attributes_count,
        1
    );
    assert_eq!(resource.scope_logs.len(), 1);
    let group = &resource.scope_logs[0];
    assert_eq!(group.schema_url, SCOPE_SCHEMA);
    let scope = group.scope.as_ref().unwrap();
    assert_eq!(
        scope.name,
        if override_scope {
            "policy-log-scope"
        } else {
            "component [REDACTED]"
        }
    );
    assert_eq!(scope.version, if override_scope { "2" } else { "1.2" });
    assert_eq!(
        attribute(&scope.attributes, "lane"),
        Some(&AnyValueValue::Int(3))
    );
    assert_eq!(attribute(&scope.attributes, "secret"), None);
    assert_eq!(scope.dropped_attributes_count, 1);
    assert_eq!(group.log_records.len(), 1);
    let record = &group.log_records[0];
    assert_eq!(record.time_unix_nano, 100_000_000_000);
    assert_eq!(record.observed_time_unix_nano, 101_000_000_000);
    assert_eq!(
        record.severity_number, 14,
        "SDK WARN2 severity is preserved"
    );
    assert_eq!(record.severity_text, "WARN [REDACTED]");
    assert_eq!(record.event_name, "event [REDACTED]");
    assert_eq!(record.trace_id.as_slice(), TRACE_ID);
    assert_eq!(record.span_id.as_slice(), SPAN_ID);
    assert_eq!(
        record.flags, 1,
        "logger context correlation retains sampled flag"
    );
    assert_eq!(
        attribute(&record.attributes, "active"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(
        attribute(&record.attributes, "code"),
        Some(&AnyValueValue::Int(23))
    );
    assert_eq!(
        attribute(&record.attributes, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(attribute(&record.attributes, "secret"), None);
    assert_eq!(record.dropped_attributes_count, 1);
    let Some(AnyValueValue::Array(structured)) = attribute(&record.attributes, "structured") else {
        panic!("SDK log attributes retain their nested typed values")
    };
    assert_eq!(structured.values.len(), 3);
    assert_eq!(structured.values[0].value, Some(AnyValueValue::Int(9)));
    assert_eq!(structured.values[1].value, Some(AnyValueValue::Bool(false)));
    assert_eq!(
        structured.values[2].value,
        Some(AnyValueValue::String("[REDACTED]".to_owned()))
    );
    let Some(AnyValueValue::KeyValueList(body)) =
        record.body.as_ref().and_then(|body| body.value.as_ref())
    else {
        panic!("SDK body map remains an OTLP key-value list")
    };
    assert_eq!(body.values.len(), 3);
    assert_eq!(attribute(&body.values, "secret"), None);
    assert_eq!(
        attribute(&body.values, "count"),
        Some(&AnyValueValue::Int(7))
    );
    assert_eq!(
        attribute(&body.values, "message"),
        Some(&AnyValueValue::String("body [REDACTED]".to_owned()))
    );
    let Some(AnyValueValue::Array(nested)) = attribute(&body.values, "nested") else {
        panic!("mixed body array preserves its element types")
    };
    assert_eq!(nested.values.len(), 3);
    assert_eq!(nested.values[0].value, Some(AnyValueValue::Bool(true)));
    assert_eq!(nested.values[1].value, Some(AnyValueValue::Double(1.5)));
    let Some(AnyValueValue::KeyValueList(inner)) = &nested.values[2].value else {
        panic!("nested body map")
    };
    assert_eq!(inner.values.len(), 2);
    assert_eq!(attribute(&inner.values, "secret"), None);
    assert_eq!(
        attribute(&inner.values, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(
        attribute(&inner.values, "bytes"),
        Some(&AnyValueValue::Bytes(vec![0, 255, 1]))
    );
}

#[test]
fn simple_sdk_logs_wait_for_native_ack_and_preserve_typed_data_and_policy() {
    native(|cx| async move {
        for override_scope in [false, true] {
            let (listener, address) = listener();
            let channel = Channel::builder(format!("http://{address}"))
                .connect_timeout(WATCHDOG)
                .timeout(WATCHDOG)
                .connect()
                .await
                .unwrap();
            let transport = OtlpGrpcExporter::new(channel)
                .unwrap()
                .try_with_resource_attributes([(
                    "service.name".to_owned(),
                    TRANSPORT_DEFAULT.to_owned(),
                )])
                .unwrap();
            let queue = QueuedOtlpGrpcExporter::new(transport).with_retry_policy(
                OtlpGrpcRetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
                    .unwrap()
                    .with_jitter(false),
            );
            let mut service = queue.spawn_queued(&cx).await.unwrap();
            let mut policy = OwnedOtlpExportPolicy::new()
                .try_with_privacy(
                    PrivacyConfig::new()
                        .with_drop_attribute("secret")
                        .with_pii_pattern("credential-[a-z]+"),
                )
                .unwrap();
            if override_scope {
                policy = policy.try_with_scope("policy-log-scope", "2").unwrap();
            }
            let exporter = OtlpSdkLogExporter::new(queue.clone()).with_policy(policy);
            let (emitted, mut emit_result) = oneshot::channel();
            let (shutdown, mut shutdown_result) = oneshot::channel();
            let (stop, stopping) = mpsc::channel();
            let sdk = std::thread::spawn(move || {
                assert!(crate::Cx::current().is_none());
                let resource = Resource::builder_empty()
                    .with_schema_url(
                        [
                            SdkAttribute::new("service.name", "native-sdk-logs"),
                            SdkAttribute::new("enabled", true),
                            SdkAttribute::new("shard", 2_i64),
                            SdkAttribute::new("owner", SECRET),
                            SdkAttribute::new("secret", SECRET),
                        ],
                        RESOURCE_SCHEMA,
                    )
                    .build();
                let provider = SdkLoggerProvider::builder()
                    .with_simple_exporter(exporter)
                    .with_resource(resource)
                    .build();
                let scope = InstrumentationScope::builder("original-sdk-log-scope")
                    .with_version("1.2")
                    .with_schema_url(SCOPE_SCHEMA)
                    .with_attributes([
                        SdkAttribute::new("lane", 3_i64),
                        SdkAttribute::new("secret", SECRET),
                    ])
                    .build();
                let logger = provider.logger_with_scope(scope);
                let parent = SpanContext::new(
                    TraceId::from_bytes(TRACE_ID),
                    SpanId::from_bytes(SPAN_ID),
                    TraceFlags::SAMPLED,
                    true,
                    TraceState::default(),
                );
                let _context = Context::new().with_remote_span_context(parent).attach();
                let mut record = logger.create_log_record();
                record.set_timestamp(UNIX_EPOCH + Duration::from_secs(100));
                record.set_observed_timestamp(UNIX_EPOCH + Duration::from_secs(101));
                record.set_target("component credential-sensitive");
                record.set_event_name("event credential-sensitive");
                record.set_severity_number(Severity::Warn2);
                record.set_severity_text("WARN credential-sensitive");
                record.set_body(nested_body());
                record.add_attribute("active", true);
                record.add_attribute("code", 23_i64);
                record.add_attribute("owner", SECRET);
                record.add_attribute("secret", SECRET);
                record.add_attribute(
                    "structured",
                    SdkValue::ListAny(Box::new(vec![
                        SdkValue::Int(9),
                        SdkValue::Boolean(false),
                        SdkValue::from(SECRET),
                    ])),
                );
                assert!(
                    record.trace_context().is_none(),
                    "SDK logger must attach context at emission"
                );
                // SimpleLogProcessor synchronously block_on's the exporter.
                // Its force_flush is a no-op, so emit completion is the witness.
                logger.emit(record);
                emitted.send_blocking(()).unwrap();
                stopping.recv_timeout(WATCHDOG).unwrap();
                let result = provider.shutdown_with_timeout(WATCHDOG);
                drop(logger);
                drop(provider);
                shutdown.send_blocking(result).unwrap();
            });

            let (arrived, mut arrival) = oneshot::channel();
            let (release, released) = mpsc::channel();
            let (finished, finishing) = mpsc::channel();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let (mut connection, captured) = read_request(&mut socket);
                assert_sdk_log(&captured, override_scope);
                response_data(
                    &mut socket,
                    &mut connection,
                    captured.stream,
                    &partial(1, "collector rejected one log record"),
                );
                data_was_consumed(&mut socket, &mut connection);
                arrived.send_blocking(()).unwrap();
                released.recv_timeout(WATCHDOG).unwrap();
                response_end(&mut socket, &mut connection, captured.stream, "0");
                finishing.recv_timeout(WATCHDOG).unwrap();
                no_more_connections(&listener);
            });

            arrival.recv(&cx).await.unwrap();
            let mut emit_wait = Box::pin(emit_result.recv(&cx));
            poll_fn(|task| {
                assert!(
                    emit_wait.as_mut().poll(task).is_pending(),
                    "SDK emit cannot finish on DATA without grpc-status"
                );
                Poll::Ready(())
            })
            .await;
            let parked = queue.queue_stats().queue;
            assert_eq!(parked.retained_batches, 1);
            assert_eq!(parked.delivered_batches, 0);
            assert!(parked.consumer_active);
            release.send(()).unwrap();
            emit_wait.await.unwrap();
            let acknowledged = queue.queue_stats();
            assert_eq!(acknowledged.queue.retained_batches, 0);
            assert_eq!(acknowledged.queue.retained_bytes, 0);
            assert_eq!(acknowledged.queue.delivered_batches, 1);
            assert_eq!(acknowledged.queue.failed_batches, 0);
            assert_eq!(acknowledged.partial_success_batches, 1);
            assert_eq!(acknowledged.rejected_log_records, 1);

            stop.send(()).unwrap();
            shutdown_result.recv(&cx).await.unwrap().unwrap();
            let managed = service.join(&cx).await.unwrap();
            assert!(matches!(
                managed.delivery,
                Some(ManagedOtlpOutcome::Drained)
            ));
            assert!(managed.task.is_ok());
            let stats = queue.queue_stats();
            assert_eq!(stats.queue.delivered_batches, 1);
            assert_eq!(stats.queue.failed_batches, 0);
            assert_eq!(stats.queue.retained_batches, 0);
            assert_eq!(stats.queue.retained_bytes, 0);
            assert!(!stats.queue.consumer_active);
            assert_eq!(stats.partial_success_batches, 1);
            assert_eq!(stats.rejected_log_records, 1);
            assert_eq!(managed.queue, stats.queue);
            assert!(
                queue
                    .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
                    .is_err()
            );
            finished.send(()).unwrap();
            sdk.join().unwrap();
            peer.join().unwrap();
        }
    });
}

type CapturedLogs = Vec<(SdkLogRecord, InstrumentationScope)>;

#[derive(Debug)]
struct CaptureLogs(Mutex<Option<oneshot::Sender<CapturedLogs>>>);

impl LogExporter for CaptureLogs {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let values = batch
            .iter()
            .map(|(record, scope)| (record.clone(), scope.clone()))
            .collect();
        let sender = self.0.lock().unwrap().take().unwrap();
        sender.send_blocking(values).unwrap();
        Ok(())
    }
}

#[test]
fn active_native_context_refuses_sdk_logs_before_queue_admission() {
    native(|cx| async move {
        let (listener, address) = listener();
        let channel = Channel::builder(format!("http://{address}"))
            .connect_timeout(WATCHDOG)
            .timeout(WATCHDOG)
            .connect()
            .await
            .unwrap();
        let queue = QueuedOtlpGrpcExporter::new(OtlpGrpcExporter::new(channel).unwrap());
        let mut service = queue.spawn_queued(&cx).await.unwrap();
        let exporter = OtlpSdkLogExporter::new(queue.clone());
        let (captured, mut capture) = oneshot::channel();
        let sdk = std::thread::spawn(move || {
            assert!(crate::Cx::current().is_none());
            let provider = SdkLoggerProvider::builder()
                .with_simple_exporter(CaptureLogs(Mutex::new(Some(captured))))
                .build();
            let logger = provider.logger("native-context-refusal");
            let mut record = logger.create_log_record();
            record.set_body(SdkValue::from("captured SDK log"));
            logger.emit(record);
            provider.shutdown_with_timeout(WATCHDOG).unwrap();
        });
        let values = capture.recv(&cx).await.unwrap();
        sdk.join().unwrap();
        assert_eq!(values.len(), 1, "real nonempty SDK log export input");
        assert!(
            values[0].0.observed_timestamp().is_some(),
            "the actual logger added observed time"
        );
        assert!(crate::Cx::current().is_some());
        let before = queue.queue_stats();
        assert!(before.queue.consumer_active);
        let references: Vec<_> = values
            .iter()
            .map(|(record, scope)| (record, scope))
            .collect();
        let error = exporter
            .export(LogBatch::new(&references))
            .await
            .unwrap_err();
        let OTelSdkError::InternalFailure(code) = error else {
            panic!("native-context refusal must be a value-free exporter error")
        };
        assert_eq!(code, "otlp.sdk.logs.native_context");
        assert_eq!(
            queue.queue_stats(),
            before,
            "refusal publishes no queue prefix"
        );
        no_more_connections(&listener);
        service.begin_drain();
        let managed = service.join(&cx).await.unwrap();
        assert!(matches!(
            managed.delivery,
            Some(ManagedOtlpOutcome::Drained)
        ));
        assert!(managed.task.is_ok());
        let stats = queue.queue_stats().queue;
        assert_eq!(stats.delivered_batches, 0);
        assert_eq!(stats.failed_batches, 0);
        assert_eq!(stats.retained_batches, 0);
        assert_eq!(stats.retained_bytes, 0);
        assert!(!stats.consumer_active);
        no_more_connections(&listener);
    });
}
