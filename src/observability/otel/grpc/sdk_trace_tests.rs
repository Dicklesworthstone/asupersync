//! Real SDK spans retain their semantics through native acknowledged delivery.

use super::queue_receipt_tests::{
    data_was_consumed, native, no_more_connections, read_request, response_data, response_end,
};
use super::tests::{Captured, accept, listener, partial};
use super::{OTLP_GRPC_MAX_MESSAGE_BYTES, OtlpGrpcExporter, OtlpGrpcRetryPolicy, OtlpGrpcSignal};
use crate::channel::oneshot;
use crate::grpc::Channel;
use crate::grpc::protobuf::{ProtoMessage, ProtobufWireLimits};
use crate::observability::otel::{
    ManagedOtlpOutcome, OtlpSdkSpanExporter, OwnedOtlpExportPolicy, PrivacyConfig,
    QueuedOtlpGrpcExporter,
};
use crate::observability::otlp_proto::collector::trace::ExportTraceServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{AnyValueValue, KeyValue};
use crate::observability::otlp_proto::trace::{SpanKind as WireSpanKind, StatusCode};
use opentelemetry::trace::{
    Event, Link, Span as _, SpanContext, SpanId, SpanKind, Status, TraceContextExt as _,
    TraceFlags, TraceId, TraceState, Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context, InstrumentationScope, KeyValue as SdkAttribute};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider, SpanData, SpanExporter, SpanLimits};
use std::future::{Future, poll_fn};
use std::sync::{Mutex, mpsc};
use std::task::Poll;
use std::time::{Duration, UNIX_EPOCH};

const WATCHDOG: Duration = Duration::from_secs(10);
const RESOURCE_SCHEMA: &str = "https://schemas.example/trace-resource/v2";
const SCOPE_SCHEMA: &str = "https://schemas.example/trace-scope/v1";
const SECRET: &str = "credential-sensitive";
const TRANSPORT_DEFAULT: &str = "transport-default";
const TRACE_ID: [u8; 16] = [0x11; 16];
const PARENT_ID: [u8; 8] = [0x22; 8];
const LINK_TRACE_ID: [u8; 16] = [0x33; 16];
const LINK_SPAN_ID: [u8; 8] = [0x44; 8];

fn attribute<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a AnyValueValue> {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)?
        .value
        .as_ref()?
        .value
        .as_ref()
}

fn assert_sdk_span(captured: &Captured, span_id: [u8; 8]) {
    assert_eq!(captured.header(":method"), Some("POST"));
    assert_eq!(
        captured.header(":path"),
        Some(OtlpGrpcSignal::Traces.method_path())
    );
    assert_eq!(captured.header("content-type"), Some("application/grpc"));
    assert_eq!(captured.header("te"), Some("trailers"));
    assert!(captured.body.len() >= 5);
    assert_eq!(captured.body[0], 0);
    let length = u32::from_be_bytes(captured.body[1..5].try_into().unwrap()) as usize;
    assert_eq!(length, captured.body.len() - 5, "one complete SDK request");
    let body = &captured.body[5..];
    for forbidden in [SECRET, TRANSPORT_DEFAULT, "dropped-event"] {
        assert!(
            !body
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "source privacy and SDK truncation apply before transport publication"
        );
    }
    let limits = ProtobufWireLimits::for_message_size(OTLP_GRPC_MAX_MESSAGE_BYTES)
        .with_max_fields(OTLP_GRPC_MAX_MESSAGE_BYTES);
    let request = ExportTraceServiceRequest::decode_from_bytes(body, limits).unwrap();
    assert_eq!(request.resource_spans.len(), 1);
    let resource = &request.resource_spans[0];
    assert_eq!(resource.schema_url, RESOURCE_SCHEMA);
    let attributes = &resource.resource.as_ref().unwrap().attributes;
    assert_eq!(
        attribute(attributes, "service.name"),
        Some(&AnyValueValue::String("native-sdk-traces".to_owned()))
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
    assert_eq!(resource.scope_spans.len(), 1);
    let group = &resource.scope_spans[0];
    assert_eq!(group.schema_url, SCOPE_SCHEMA);
    let scope = group.scope.as_ref().unwrap();
    assert_eq!(scope.name, "native-sdk-trace-scope");
    assert_eq!(scope.version, "1.2");
    assert_eq!(
        attribute(&scope.attributes, "lane"),
        Some(&AnyValueValue::Int(3))
    );
    assert_eq!(attribute(&scope.attributes, "secret"), None);
    assert_eq!(scope.dropped_attributes_count, 1);
    assert_eq!(group.spans.len(), 1);
    let span = &group.spans[0];
    assert_eq!(span.trace_id.as_slice(), TRACE_ID);
    assert_eq!(span.span_id.as_slice(), span_id);
    assert_eq!(span.parent_span_id.as_slice(), PARENT_ID);
    assert_eq!(span.name, "request [REDACTED]");
    assert_eq!(span.kind, WireSpanKind::Server.as_raw());
    assert_eq!(span.flags, 0x301, "sampled span with a known remote parent");
    assert!(
        span.trace_state.is_empty(),
        "sensitive opaque tracestate is cleared"
    );
    assert_eq!(span.start_time_unix_nano, 100_000_000_000);
    assert_eq!(span.end_time_unix_nano, 102_000_000_000);
    assert_eq!(
        attribute(&span.attributes, "active"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(
        attribute(&span.attributes, "attempt"),
        Some(&AnyValueValue::Int(4))
    );
    assert_eq!(
        attribute(&span.attributes, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(attribute(&span.attributes, "secret"), None);
    assert_eq!(attribute(&span.attributes, "source-overflow"), None);
    assert_eq!(span.dropped_attributes_count, 2, "SDK and policy drops add");
    let status = span.status.as_ref().unwrap();
    assert_eq!(status.code, StatusCode::Error.as_raw());
    assert_eq!(status.message, "failure [REDACTED]");
    assert_eq!(span.events.len(), 1);
    assert_eq!(span.dropped_events_count, 1);
    let event = &span.events[0];
    assert_eq!(event.name, "event [REDACTED]");
    assert_eq!(event.time_unix_nano, 101_000_000_000);
    assert_eq!(
        attribute(&event.attributes, "sequence"),
        Some(&AnyValueValue::Int(5))
    );
    assert_eq!(
        attribute(&event.attributes, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(attribute(&event.attributes, "secret"), None);
    assert_eq!(attribute(&event.attributes, "source-overflow"), None);
    assert_eq!(event.dropped_attributes_count, 2);
    assert_eq!(span.links.len(), 1);
    assert_eq!(span.dropped_links_count, 1);
    let link = &span.links[0];
    assert_eq!(link.trace_id.as_slice(), LINK_TRACE_ID);
    assert_eq!(link.span_id.as_slice(), LINK_SPAN_ID);
    assert_eq!(
        link.flags, 0x101,
        "linked context is known local, independently of parent"
    );
    assert!(link.trace_state.is_empty());
    assert_eq!(
        attribute(&link.attributes, "local"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(
        attribute(&link.attributes, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(attribute(&link.attributes, "secret"), None);
    assert_eq!(attribute(&link.attributes, "source-overflow"), None);
    assert_eq!(link.dropped_attributes_count, 2);
}

#[test]
fn simple_sdk_span_waits_for_native_ack_and_preserves_trace_semantics() {
    native(|cx| async move {
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
        let policy = OwnedOtlpExportPolicy::new()
            .try_with_privacy(
                PrivacyConfig::new()
                    .with_drop_attribute("secret")
                    .with_pii_pattern("credential-[a-z]+"),
            )
            .unwrap();
        let exporter = OtlpSdkSpanExporter::new(queue.clone()).with_policy(policy);
        let (ended, mut end_result) = oneshot::channel();
        let (shutdown, mut shutdown_result) = oneshot::channel();
        let (stop, stopping) = mpsc::channel();
        let (expected, expected_span) = mpsc::channel();
        let sdk = std::thread::spawn(move || {
            assert!(crate::Cx::current().is_none());
            let resource = Resource::builder_empty()
                .with_schema_url(
                    [
                        SdkAttribute::new("service.name", "native-sdk-traces"),
                        SdkAttribute::new("enabled", true),
                        SdkAttribute::new("shard", 2_i64),
                        SdkAttribute::new("owner", SECRET),
                        SdkAttribute::new("secret", SECRET),
                    ],
                    RESOURCE_SCHEMA,
                )
                .build();
            let provider = SdkTracerProvider::builder()
                .with_simple_exporter(exporter)
                .with_resource(resource)
                .with_sampler(Sampler::AlwaysOn)
                .with_span_limits(SpanLimits {
                    max_attributes_per_span: 4,
                    max_events_per_span: 1,
                    max_links_per_span: 1,
                    max_attributes_per_event: 3,
                    max_attributes_per_link: 3,
                })
                .build();
            let scope = InstrumentationScope::builder("native-sdk-trace-scope")
                .with_version("1.2")
                .with_schema_url(SCOPE_SCHEMA)
                .with_attributes([
                    SdkAttribute::new("lane", 3_i64),
                    SdkAttribute::new("secret", SECRET),
                ])
                .build();
            let tracer = provider.tracer_with_scope(scope);
            let trace_state = TraceState::from_key_value([("vendor", SECRET)]).unwrap();
            let parent = SpanContext::new(
                TraceId::from_bytes(TRACE_ID),
                SpanId::from_bytes(PARENT_ID),
                TraceFlags::SAMPLED,
                true,
                trace_state.clone(),
            );
            let link = SpanContext::new(
                TraceId::from_bytes(LINK_TRACE_ID),
                SpanId::from_bytes(LINK_SPAN_ID),
                TraceFlags::SAMPLED,
                false,
                trace_state,
            );
            let parent = Context::new().with_remote_span_context(parent);
            let mut span = tracer
                .span_builder("request credential-sensitive")
                .with_kind(SpanKind::Server)
                .with_start_time(UNIX_EPOCH + Duration::from_secs(100))
                .with_attributes([
                    SdkAttribute::new("active", true),
                    SdkAttribute::new("attempt", 4_i64),
                    SdkAttribute::new("owner", SECRET),
                    SdkAttribute::new("secret", SECRET),
                    SdkAttribute::new("source-overflow", SECRET),
                ])
                .with_events(vec![
                    Event::new(
                        "event credential-sensitive",
                        UNIX_EPOCH + Duration::from_secs(101),
                        vec![
                            SdkAttribute::new("sequence", 5_i64),
                            SdkAttribute::new("owner", SECRET),
                            SdkAttribute::new("secret", SECRET),
                            SdkAttribute::new("source-overflow", SECRET),
                        ],
                        0,
                    ),
                    Event::new(
                        "dropped-event",
                        UNIX_EPOCH + Duration::from_secs(101),
                        Vec::new(),
                        0,
                    ),
                ])
                .with_links(vec![
                    Link::new(
                        link.clone(),
                        vec![
                            SdkAttribute::new("local", true),
                            SdkAttribute::new("owner", SECRET),
                            SdkAttribute::new("secret", SECRET),
                            SdkAttribute::new("source-overflow", SECRET),
                        ],
                        0,
                    ),
                    Link::with_context(link),
                ])
                .start_with_context(&tracer, &parent);
            assert_eq!(
                span.span_context().trace_state().header(),
                "vendor=credential-sensitive",
                "the SDK supplies the sensitive parent state before policy filtering"
            );
            expected
                .send(span.span_context().span_id().to_bytes())
                .unwrap();
            span.set_status(Status::error("failure credential-sensitive"));
            // SimpleSpanProcessor synchronously awaits exporter.export here.
            // Provider force_flush is a no-op for that processor in SDK 0.32.
            span.end_with_timestamp(UNIX_EPOCH + Duration::from_secs(102));
            ended.send_blocking(()).unwrap();
            drop(span);
            stopping.recv_timeout(WATCHDOG).unwrap();
            let result = provider.shutdown_with_timeout(WATCHDOG);
            drop(tracer);
            drop(provider);
            shutdown.send_blocking(result).unwrap();
        });

        let (arrived, mut arrival) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let (finished, finishing) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            assert_sdk_span(&captured, expected_span.recv_timeout(WATCHDOG).unwrap());
            response_data(
                &mut socket,
                &mut connection,
                captured.stream,
                &partial(1, "collector rejected one span"),
            );
            data_was_consumed(&mut socket, &mut connection);
            arrived.send_blocking(()).unwrap();
            released.recv_timeout(WATCHDOG).unwrap();
            response_end(&mut socket, &mut connection, captured.stream, "0");
            // SimpleSpanProcessor shutdown has no final collection. A terminal
            // partial response must not generate another attempt or span.
            finishing.recv_timeout(WATCHDOG).unwrap();
            no_more_connections(&listener);
        });

        arrival.recv(&cx).await.unwrap();
        let mut end_wait = Box::pin(end_result.recv(&cx));
        poll_fn(|task| {
            assert!(
                end_wait.as_mut().poll(task).is_pending(),
                "span completion must wait for grpc-status after consuming response DATA"
            );
            Poll::Ready(())
        })
        .await;
        let parked = queue.queue_stats().queue;
        assert_eq!(parked.retained_batches, 1);
        assert_eq!(parked.delivered_batches, 0);
        assert!(parked.consumer_active);
        release.send(()).unwrap();
        end_wait.await.unwrap();
        let acknowledged = queue.queue_stats();
        assert_eq!(acknowledged.queue.retained_batches, 0);
        assert_eq!(acknowledged.queue.retained_bytes, 0);
        assert_eq!(acknowledged.queue.delivered_batches, 1);
        assert_eq!(acknowledged.queue.failed_batches, 0);
        assert_eq!(acknowledged.partial_success_batches, 1);
        assert_eq!(acknowledged.rejected_spans, 1);

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
        assert_eq!(stats.rejected_spans, 1);
        assert_eq!(managed.queue, stats.queue);
        assert!(
            queue
                .enqueue_encoded(OtlpGrpcSignal::Traces, Vec::new())
                .is_err()
        );
        finished.send(()).unwrap();
        sdk.join().unwrap();
        peer.join().unwrap();
    });
}

#[derive(Debug)]
struct CaptureSpan(Mutex<Option<oneshot::Sender<Vec<SpanData>>>>);

impl SpanExporter for CaptureSpan {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let sender = self.0.lock().unwrap().take().unwrap();
        sender.send_blocking(batch).unwrap();
        Ok(())
    }
}

#[test]
fn active_native_context_refuses_sdk_span_export_before_queue_admission() {
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
        let exporter = OtlpSdkSpanExporter::new(queue.clone());
        let (captured, mut capture) = oneshot::channel();
        let sdk = std::thread::spawn(move || {
            assert!(crate::Cx::current().is_none());
            let provider = SdkTracerProvider::builder()
                .with_simple_exporter(CaptureSpan(Mutex::new(Some(captured))))
                .with_sampler(Sampler::AlwaysOn)
                .build();
            let tracer = provider.tracer("native-context-refusal");
            let mut span = tracer.start("captured SDK span");
            span.end();
            provider.shutdown_with_timeout(WATCHDOG).unwrap();
        });
        let batch = capture.recv(&cx).await.unwrap();
        sdk.join().unwrap();
        assert_eq!(batch.len(), 1, "real nonempty SDK export input");
        assert!(crate::Cx::current().is_some());
        let before = queue.queue_stats();
        assert!(
            before.queue.consumer_active,
            "the actual managed owner is ready"
        );
        let error = exporter.export(batch).await.unwrap_err();
        let OTelSdkError::InternalFailure(code) = error else {
            panic!("native-context refusal must be a value-free exporter error")
        };
        assert_eq!(code, "otlp.sdk.traces.native_context");
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
