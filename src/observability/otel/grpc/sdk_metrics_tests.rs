//! The external SDK reaches the real managed queue and collector acknowledgement.

use super::queue_receipt_tests::{
    data_was_consumed, native, no_more_connections, read_request, response_data, response_end,
};
use super::tests::{Captured, accept, listener, partial};
use super::{OTLP_GRPC_MAX_MESSAGE_BYTES, OtlpGrpcExporter, OtlpGrpcSignal};
use crate::channel::oneshot;
use crate::grpc::Channel;
use crate::grpc::protobuf::{ProtoMessage, ProtobufWireLimits};
use crate::observability::otel::{
    ManagedOtlpOutcome, OtlpSdkMetricExporter, OwnedOtlpExportPolicy, PrivacyConfig,
    QueuedOtlpGrpcExporter,
};
use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{AnyValueValue, KeyValue};
use crate::observability::otlp_proto::metrics::{
    AggregationTemporality, MetricData, NumberDataPointValue,
};
use opentelemetry::metrics::MeterProvider;
use opentelemetry::{InstrumentationScope, KeyValue as SdkAttribute};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use std::future::{Future, poll_fn};
use std::sync::mpsc;
use std::task::Poll;
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(10);
const RESOURCE_SCHEMA: &str = "https://schemas.example/resource/v2";
const SCOPE_SCHEMA: &str = "https://schemas.example/scope/v1";
const SECRET: &str = "credential-sensitive";
const TRANSPORT_DEFAULT: &str = "transport-default";

fn attribute<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a AnyValueValue> {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)?
        .value
        .as_ref()?
        .value
        .as_ref()
}

fn assert_sdk_request(captured: &Captured) {
    assert_eq!(captured.header(":method"), Some("POST"));
    assert_eq!(
        captured.header(":path"),
        Some(OtlpGrpcSignal::Metrics.method_path())
    );
    assert_eq!(captured.header("content-type"), Some("application/grpc"));
    assert_eq!(captured.header("te"), Some("trailers"));
    assert!(captured.body.len() >= 5);
    assert_eq!(captured.body[0], 0);
    let length = u32::from_be_bytes(captured.body[1..5].try_into().unwrap()) as usize;
    assert_eq!(length, captured.body.len() - 5, "one complete SDK request");
    let body = &captured.body[5..];
    for forbidden in [SECRET, TRANSPORT_DEFAULT] {
        assert!(
            !body
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "source credentials and transport resource defaults stay off the wire"
        );
    }
    let limits = ProtobufWireLimits::for_message_size(OTLP_GRPC_MAX_MESSAGE_BYTES)
        .with_max_fields(OTLP_GRPC_MAX_MESSAGE_BYTES);
    let request = ExportMetricsServiceRequest::decode_from_bytes(body, limits).unwrap();
    assert_eq!(request.resource_metrics.len(), 1);
    let resource = &request.resource_metrics[0];
    assert_eq!(resource.schema_url, RESOURCE_SCHEMA);
    let attributes = &resource.resource.as_ref().unwrap().attributes;
    assert_eq!(
        attribute(attributes, "service.name"),
        Some(&AnyValueValue::String("native-sdk".to_owned()))
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
    assert_eq!(resource.scope_metrics.len(), 1);
    let group = &resource.scope_metrics[0];
    assert_eq!(group.schema_url, SCOPE_SCHEMA);
    let scope = group.scope.as_ref().unwrap();
    assert_eq!(scope.name, "native-sdk-scope");
    assert_eq!(scope.version, "1.2");
    assert_eq!(
        attribute(&scope.attributes, "lane"),
        Some(&AnyValueValue::Int(3))
    );
    assert_eq!(attribute(&scope.attributes, "secret"), None);
    assert_eq!(scope.dropped_attributes_count, 1);
    assert_eq!(group.metrics.len(), 1);
    let metric = &group.metrics[0];
    assert_eq!(metric.name, "requests");
    assert_eq!(metric.description, "Native SDK requests");
    assert_eq!(metric.unit, "{request}");
    let Some(MetricData::Sum(sum)) = &metric.data else {
        panic!("SDK counter must remain an OTLP sum")
    };
    assert!(sum.is_monotonic);
    assert_eq!(
        sum.aggregation_temporality,
        AggregationTemporality::Cumulative.as_raw()
    );
    assert_eq!(sum.data_points.len(), 1);
    let point = &sum.data_points[0];
    assert_eq!(point.value, Some(NumberDataPointValue::Int(7)));
    assert!(point.start_time_unix_nano > 0);
    assert!(point.time_unix_nano >= point.start_time_unix_nano);
    assert_eq!(
        attribute(&point.attributes, "active"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(
        attribute(&point.attributes, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(attribute(&point.attributes, "secret"), None);
}

#[test]
fn sdk_flush_waits_for_native_acknowledgement_and_shutdown_drains_owned_delivery() {
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
        let queue = QueuedOtlpGrpcExporter::new(transport);
        let mut service = queue.spawn_queued(&cx).await.unwrap();
        let policy = OwnedOtlpExportPolicy::new()
            .try_with_privacy(
                PrivacyConfig::new()
                    .with_drop_attribute("secret")
                    .with_pii_pattern("credential-[a-z]+"),
            )
            .unwrap();
        let exporter = OtlpSdkMetricExporter::new(queue.clone()).with_policy(policy);
        let (flushed, mut flush_result) = oneshot::channel();
        let (shutdown, mut shutdown_result) = oneshot::channel();
        let (stop, stopping) = mpsc::channel();
        let sdk = std::thread::spawn(move || {
            let reader = PeriodicReader::builder(exporter)
                .with_interval(Duration::from_secs(3600))
                .build();
            let resource = Resource::builder_empty()
                .with_schema_url(
                    [
                        SdkAttribute::new("service.name", "native-sdk"),
                        SdkAttribute::new("enabled", true),
                        SdkAttribute::new("shard", 2_i64),
                        SdkAttribute::new("owner", SECRET),
                        SdkAttribute::new("secret", SECRET),
                    ],
                    RESOURCE_SCHEMA,
                )
                .build();
            let provider = SdkMeterProvider::builder()
                .with_resource(resource)
                .with_reader(reader)
                .build();
            let scope = InstrumentationScope::builder("native-sdk-scope")
                .with_version("1.2")
                .with_schema_url(SCOPE_SCHEMA)
                .with_attributes([
                    SdkAttribute::new("lane", 3_i64),
                    SdkAttribute::new("secret", SECRET),
                ])
                .build();
            let meter = provider.meter_with_scope(scope);
            let counter = meter
                .u64_counter("requests")
                .with_description("Native SDK requests")
                .with_unit("{request}")
                .build();
            counter.add(
                7,
                &[
                    SdkAttribute::new("active", true),
                    SdkAttribute::new("owner", SECRET),
                    SdkAttribute::new("secret", SECRET),
                ],
            );
            // SDK lifecycle calls are deliberately off the native owner thread.
            flushed.send_blocking(provider.force_flush()).unwrap();
            stopping.recv_timeout(WATCHDOG).unwrap();
            let result = provider.shutdown_with_timeout(WATCHDOG);
            drop(provider);
            shutdown.send_blocking(result).unwrap();
        });

        let (arrived, mut arrival) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let (finished, finishing) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut first = accept(&listener);
            let (mut connection, captured) = read_request(&mut first);
            assert_sdk_request(&captured);
            response_data(
                &mut first,
                &mut connection,
                captured.stream,
                &partial(1, "collector rejected one measurement"),
            );
            data_was_consumed(&mut first, &mut connection);
            arrived.send_blocking(()).unwrap();
            released.recv_timeout(WATCHDOG).unwrap();
            response_end(&mut first, &mut connection, captured.stream, "0");

            // SDK 0.32 PeriodicReader performs a final cumulative collection on
            // shutdown. This is a second requested export, never a partial retry.
            let mut second = accept(&listener);
            let (mut connection, captured) = read_request(&mut second);
            assert_sdk_request(&captured);
            response_data(&mut second, &mut connection, captured.stream, &[]);
            response_end(&mut second, &mut connection, captured.stream, "0");
            finishing.recv_timeout(WATCHDOG).unwrap();
            no_more_connections(&listener);
        });

        arrival.recv(&cx).await.unwrap();
        let mut flush_wait = Box::pin(flush_result.recv(&cx));
        poll_fn(|task| {
            assert!(
                flush_wait.as_mut().poll(task).is_pending(),
                "SDK flush must await final grpc-status after consuming response DATA"
            );
            Poll::Ready(())
        })
        .await;
        let parked = queue.queue_stats().queue;
        assert_eq!(parked.retained_batches, 1);
        assert_eq!(parked.delivered_batches, 0);
        assert!(parked.consumer_active);
        release.send(()).unwrap();
        flush_wait.await.unwrap().unwrap();
        let acknowledged = queue.queue_stats();
        assert_eq!(acknowledged.queue.retained_batches, 0);
        assert_eq!(acknowledged.queue.retained_bytes, 0);
        assert_eq!(acknowledged.queue.delivered_batches, 1);
        assert_eq!(acknowledged.partial_success_batches, 1);
        assert_eq!(acknowledged.rejected_data_points, 1);

        stop.send(()).unwrap();
        shutdown_result.recv(&cx).await.unwrap().unwrap();
        let managed = service.join(&cx).await.unwrap();
        assert!(matches!(
            managed.delivery,
            Some(ManagedOtlpOutcome::Drained)
        ));
        assert!(managed.task.is_ok());
        let stats = queue.queue_stats();
        assert_eq!(stats.queue.delivered_batches, 2);
        assert_eq!(stats.queue.failed_batches, 0);
        assert_eq!(stats.queue.retained_batches, 0);
        assert_eq!(stats.queue.retained_bytes, 0);
        assert!(!stats.queue.consumer_active);
        assert_eq!(stats.partial_success_batches, 1);
        assert_eq!(stats.rejected_data_points, 1);
        assert_eq!(managed.queue, stats.queue);
        assert!(
            queue
                .enqueue_encoded(OtlpGrpcSignal::Metrics, Vec::new())
                .is_err()
        );
        finished.send(()).unwrap();
        sdk.join().unwrap();
        peer.join().unwrap();
    });
}
