//! External SDK providers reach the acknowledged native HTTP transport.

use super::*;
use crate::channel::oneshot;
use crate::grpc::protobuf::ProtoMessage;
use crate::observability::otel::queued::http::tests::{
    Captured, accept, listener, native, no_more_connections, partial, producer, request, respond,
};
use crate::observability::otel::{
    ManagedOtlpOutcome, PrivacyConfig, drive_otlp_request_with_deadline,
    drive_otlp_request_with_timeout, otlp_request_limits,
};
use crate::observability::otlp_proto::collector::logs::ExportLogsServiceRequest;
use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
use crate::observability::otlp_proto::collector::trace::ExportTraceServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{AnyValueValue, KeyValue};
use crate::observability::otlp_proto::metrics::MetricData;
use opentelemetry::logs::{
    AnyValue as SdkLogValue, LogRecord as _, Logger as _, LoggerProvider as _,
};
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::trace::{
    Span as _, SpanKind, Status, TraceContextExt, Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context as OtelContext, InstrumentationScope, KeyValue as SdkAttribute};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkError;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{
    Aggregation, Instrument, PeriodicReader, SdkMeterProvider, Stream,
};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::io::Write;
use std::sync::mpsc;
use std::task::{Context, Poll, Waker};
use std::time::UNIX_EPOCH;

const WATCHDOG: Duration = Duration::from_secs(10);
const SECRET: &str = "credential-sensitive";
const RESOURCE_SCHEMA: &str = "https://schemas.example/http-resource/v1";
const SCOPE_SCHEMA: &str = "https://schemas.example/http-scope/v2";

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("expected an immediate refusal/completion"),
    }
}

fn clock_owner() -> (
    Arc<crate::time::VirtualClock>,
    crate::time::TimerDriverHandle,
    crate::Cx,
) {
    let clock = Arc::new(crate::time::VirtualClock::new());
    let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = crate::Cx::new_with_drivers(
        crate::types::RegionId::new_for_test(301, 0),
        crate::types::TaskId::new_for_test(302, 0),
        crate::types::Budget::INFINITE,
        None,
        None,
        None,
        Some(timer.clone()),
        None,
    );
    (clock, timer, cx)
}

#[test]
fn acknowledged_absolute_deadline_cannot_be_renewed_after_preparation_or_a_ready_poll() {
    let (clock, timer, cx) = clock_owner();
    let deadline = crate::types::Time::from_secs(1);
    // Model time spent by compression/header preparation before entering I/O.
    clock.advance(1_000_000_000);
    let touched = Cell::new(false);
    let result = ready(drive_otlp_request_with_deadline(
        &cx,
        WATCHDOG,
        Some(deadline),
        async {
            touched.set(true);
            7
        },
    ));
    assert_eq!(
        result.unwrap_err().to_string(),
        "OTLP error: OTLP request timeout"
    );
    assert!(
        !touched.get(),
        "expired preparation must not poll DNS/network"
    );
    assert_eq!(timer.pending_count(), 0);

    // A single synchronous continuation can cross the budget with either
    // Ready or Pending; neither result permits acknowledgement or another poll.
    for completes in [false, true] {
        let (clock, timer, cx) = clock_owner();
        let polls = Cell::new(0);
        let result = ready(drive_otlp_request_with_deadline(
            &cx,
            WATCHDOG,
            Some(deadline),
            poll_fn(|_| {
                polls.set(polls.get() + 1);
                clock.advance(1_000_000_000);
                if completes {
                    Poll::Ready(7)
                } else {
                    Poll::Pending
                }
            }),
        ));
        assert_eq!(
            result.unwrap_err().to_string(),
            "OTLP error: OTLP request timeout"
        );
        assert_eq!(polls.get(), 1);
        assert_eq!(timer.pending_count(), 0);
    }

    // Existing non-acknowledged callers still keep completed-at-boundary work.
    let (clock, _, cx) = clock_owner();
    assert_eq!(
        ready(drive_otlp_request_with_timeout(
            &cx,
            Duration::from_secs(1),
            async {
                clock.advance(1_000_000_000);
                7
            }
        ))
        .unwrap(),
        7,
    );
}

#[test]
fn acknowledged_ready_request_cannot_hide_owner_cancellation() {
    let (_, timer, cx) = clock_owner();
    let result = ready(drive_otlp_request_with_deadline(
        &cx,
        WATCHDOG,
        Some(crate::types::Time::from_secs(5)),
        async {
            cx.set_cancel_reason(crate::types::CancelReason::user("cancel within Ready"));
            7
        },
    ));
    assert_eq!(
        result.unwrap_err().to_string(),
        "OTLP error: OTLP request failed: request cancelled",
    );
    assert_eq!(timer.pending_count(), 0);
}

fn policy() -> OwnedOtlpExportPolicy {
    OwnedOtlpExportPolicy::new()
        .try_with_privacy(
            PrivacyConfig::new()
                .with_drop_attribute("secret")
                .with_pii_pattern("credential-[a-z]+"),
        )
        .unwrap()
}

fn resource() -> Resource {
    Resource::builder_empty()
        .with_schema_url(
            [
                SdkAttribute::new("service.name", "sdk-http"),
                SdkAttribute::new("enabled", true),
                SdkAttribute::new("shard", 2_i64),
                SdkAttribute::new("owner", SECRET),
                SdkAttribute::new("secret", SECRET),
            ],
            RESOURCE_SCHEMA,
        )
        .build()
}

fn scope() -> InstrumentationScope {
    InstrumentationScope::builder("sdk-http-scope")
        .with_version("1.2")
        .with_schema_url(SCOPE_SCHEMA)
        .with_attributes([
            SdkAttribute::new("lane", 3_i64),
            SdkAttribute::new("secret", SECRET),
        ])
        .build()
}

/// Capture the exact existing mapper output for the very SDK batch sent by the
/// public HTTP adapter. Timestamp/context generation therefore cannot hide a
/// transport-specific remapping or an added protobuf/gRPC framing layer.
#[derive(Debug)]
struct MetricsWitness {
    inner: OtlpSdkHttpMetricExporter,
    expected: mpsc::Sender<Vec<Vec<u8>>>,
}

impl PushMetricExporter for MetricsWitness {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let bytes = map_metrics(metrics, &self.inner.policy, &self.inner.config)
            .unwrap()
            .into_parts()
            .0;
        self.expected.send(bytes).unwrap();
        self.inner.export(metrics).await
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }
    fn temporality(&self) -> Temporality {
        self.inner.temporality()
    }
}

#[derive(Debug)]
struct TraceWitness {
    inner: OtlpSdkHttpSpanExporter,
    expected: mpsc::Sender<Vec<Vec<u8>>>,
}

impl SpanExporter for TraceWitness {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let bytes = map_traces(
            &batch,
            self.inner.resource.as_ref().unwrap(),
            &self.inner.policy,
            &self.inner.config,
        )
        .unwrap()
        .into_parts()
        .0;
        self.expected.send(bytes).unwrap();
        self.inner.export(batch).await
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[derive(Debug)]
struct LogsWitness {
    inner: OtlpSdkHttpLogExporter,
    expected: mpsc::Sender<Vec<Vec<u8>>>,
}

impl LogExporter for LogsWitness {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let bytes = map_logs(
            &batch,
            self.inner.resource.as_ref().unwrap(),
            &self.inner.policy,
            &self.inner.config,
        )
        .unwrap()
        .into_parts()
        .0;
        self.expected.send(bytes).unwrap();
        self.inner.export(batch).await
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

fn attribute<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a AnyValueValue> {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)?
        .value
        .as_ref()?
        .value
        .as_ref()
}

fn metadata(
    resource: &crate::observability::otlp_proto::common_and_resource::Resource,
    resource_schema: &str,
    scope: &crate::observability::otlp_proto::common_and_resource::InstrumentationScope,
    scope_schema: &str,
    signal: OtlpSignal,
) {
    assert_eq!(resource_schema, RESOURCE_SCHEMA);
    assert_eq!(scope_schema, SCOPE_SCHEMA);
    assert_eq!(
        attribute(&resource.attributes, "service.name"),
        Some(&AnyValueValue::String("sdk-http".to_owned()))
    );
    assert_eq!(
        attribute(&resource.attributes, "enabled"),
        Some(&AnyValueValue::Bool(true))
    );
    assert_eq!(
        attribute(&resource.attributes, "shard"),
        Some(&AnyValueValue::Int(2))
    );
    assert_eq!(
        attribute(&resource.attributes, "owner"),
        Some(&AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(attribute(&resource.attributes, "secret"), None);
    assert_eq!(resource.dropped_attributes_count, 1);
    assert_eq!(
        scope.name,
        if signal == OtlpSignal::Logs {
            "sdk-http-target"
        } else {
            "sdk-http-scope"
        }
    );
    assert_eq!(scope.version, "1.2");
    assert_eq!(
        attribute(&scope.attributes, "lane"),
        Some(&AnyValueValue::Int(3))
    );
    assert_eq!(scope.dropped_attributes_count, 1);
}

fn assert_request(captured: &Captured, expected: Vec<Vec<u8>>, signal: OtlpSignal) {
    assert_eq!(expected.len(), 1);
    assert_eq!(
        captured.body, expected[0],
        "shared mapper bytes reach HTTP without rewriting"
    );
    let path = match signal {
        OtlpSignal::Metrics => "/custom/metrics?target=metrics",
        OtlpSignal::Traces => "/custom/traces?target=traces",
        OtlpSignal::Logs => "/custom/logs?target=logs",
    };
    assert_eq!(captured.target, path);
    assert_eq!(
        captured.header("content-type"),
        Some("application/x-protobuf")
    );
    assert_eq!(captured.header("te"), None);
    assert!(
        !captured
            .body
            .windows(SECRET.len())
            .any(|bytes| bytes == SECRET.as_bytes())
    );
    let limits = otlp_request_limits(4 * 1024 * 1024);
    match signal {
        OtlpSignal::Metrics => {
            let decoded =
                ExportMetricsServiceRequest::decode_from_bytes(&captured.body, limits).unwrap();
            assert_eq!(decoded.resource_metrics.len(), 1);
            let resource = &decoded.resource_metrics[0];
            assert_eq!(resource.scope_metrics.len(), 1);
            let group = &resource.scope_metrics[0];
            metadata(
                resource.resource.as_ref().unwrap(),
                &resource.schema_url,
                group.scope.as_ref().unwrap(),
                &group.schema_url,
                signal,
            );
            assert_eq!(group.metrics.len(), 4);
            let mut families = [0; 4];
            for metric in &group.metrics {
                match metric.data.as_ref().unwrap() {
                    MetricData::Sum(value) => {
                        families[0] += 1;
                        assert_eq!(value.aggregation_temporality, 2);
                        assert!(value.is_monotonic);
                        assert_eq!(value.data_points.len(), 1);
                    }
                    MetricData::Gauge(value) => {
                        families[1] += 1;
                        assert_eq!(value.data_points.len(), 1);
                    }
                    MetricData::Histogram(value) => {
                        families[2] += 1;
                        assert_eq!(value.data_points[0].count, 1);
                    }
                    MetricData::ExponentialHistogram(value) => {
                        families[3] += 1;
                        assert_eq!(value.data_points[0].count, 1);
                    }
                    _ => panic!("unexpected SDK aggregation"),
                }
            }
            assert_eq!(families, [1, 1, 1, 1]);
        }
        OtlpSignal::Traces => {
            let decoded =
                ExportTraceServiceRequest::decode_from_bytes(&captured.body, limits).unwrap();
            assert_eq!(decoded.resource_spans.len(), 1);
            let resource = &decoded.resource_spans[0];
            assert_eq!(resource.scope_spans.len(), 1);
            let group = &resource.scope_spans[0];
            metadata(
                resource.resource.as_ref().unwrap(),
                &resource.schema_url,
                group.scope.as_ref().unwrap(),
                &group.schema_url,
                signal,
            );
            assert_eq!(group.spans.len(), 1);
            let span = &group.spans[0];
            assert_eq!(span.name, "span [REDACTED]");
            assert_eq!(span.flags, 0x301);
            assert_eq!(span.parent_span_id, vec![0x22; 8]);
            assert_eq!(span.dropped_attributes_count, 1);
            assert_eq!(span.events.len(), 1);
            assert_eq!(span.events[0].name, "event [REDACTED]");
            assert_eq!(span.links.len(), 1);
            assert_eq!(span.links[0].flags, 0x101);
            assert_eq!(span.status.as_ref().unwrap().message, "failure [REDACTED]");
        }
        OtlpSignal::Logs => {
            let decoded =
                ExportLogsServiceRequest::decode_from_bytes(&captured.body, limits).unwrap();
            assert_eq!(decoded.resource_logs.len(), 1);
            let resource = &decoded.resource_logs[0];
            assert_eq!(resource.scope_logs.len(), 1);
            let group = &resource.scope_logs[0];
            metadata(
                resource.resource.as_ref().unwrap(),
                &resource.schema_url,
                group.scope.as_ref().unwrap(),
                &group.schema_url,
                signal,
            );
            assert_eq!(group.log_records.len(), 1);
            let record = &group.log_records[0];
            assert_eq!(record.severity_number, 14);
            assert_eq!(record.severity_text, "WARN [REDACTED]");
            assert_eq!(record.event_name, "event [REDACTED]");
            assert_eq!(record.trace_id, vec![0x11; 16]);
            assert_eq!(record.span_id, vec![0x22; 8]);
            assert_eq!(record.flags, 1);
            assert_eq!(record.dropped_attributes_count, 1);
            let Some(AnyValueValue::Array(values)) =
                record.body.as_ref().and_then(|v| v.value.as_ref())
            else {
                panic!("typed log body array");
            };
            assert_eq!(values.values.len(), 4);
            assert_eq!(values.values[0].value, Some(AnyValueValue::Int(9)));
            assert_eq!(values.values[1].value, Some(AnyValueValue::Bool(false)));
            assert_eq!(
                values.values[2].value,
                Some(AnyValueValue::String("[REDACTED]".to_owned()))
            );
            assert_eq!(
                values.values[3].value,
                Some(AnyValueValue::Bytes(vec![0, 255, 1]))
            );
        }
    }
}

fn parent(remote: bool) -> opentelemetry::trace::SpanContext {
    use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};
    SpanContext::new(
        TraceId::from_bytes([0x11; 16]),
        SpanId::from_bytes([0x22; 8]),
        TraceFlags::SAMPLED,
        remote,
        TraceState::default(),
    )
}

#[test]
fn all_sdk_providers_share_mapper_bytes_and_wait_for_http_collector_acknowledgements() {
    for signal in [OtlpSignal::Metrics, OtlpSignal::Traces, OtlpSignal::Logs] {
        native(move |cx| async move {
            let (listener, address) = listener();
            let queue = producer(address);
            let mut service = queue.spawn_queued(&cx).await.unwrap();
            let (expected, expected_body) = mpsc::channel();
            let (emitted, mut emission) = oneshot::channel();
            let (shutdown, mut shutdown_result) = oneshot::channel();
            let (stop, stopping) = mpsc::channel();
            let source_queue = queue.clone();
            let sdk = std::thread::spawn(move || {
                assert!(crate::Cx::current().is_none());
                let result = match signal {
                    OtlpSignal::Metrics => {
                        let exporter = MetricsWitness {
                            inner: OtlpSdkHttpMetricExporter::new(source_queue)
                                .with_policy(policy()),
                            expected,
                        };
                        let reader = PeriodicReader::builder(exporter)
                            .with_interval(Duration::from_secs(3600))
                            .build();
                        let provider = SdkMeterProvider::builder()
                            .with_resource(resource())
                            .with_reader(reader)
                            .with_view(|instrument: &Instrument| {
                                if instrument.name() == "exp.histogram" {
                                    Stream::builder()
                                        .with_aggregation(Aggregation::Base2ExponentialHistogram {
                                            max_size: 160,
                                            max_scale: 20,
                                            record_min_max: true,
                                        })
                                        .build()
                                        .ok()
                                } else {
                                    None
                                }
                            })
                            .build();
                        let meter = provider.meter_with_scope(scope());
                        let attrs = [
                            SdkAttribute::new("owner", SECRET),
                            SdkAttribute::new("secret", SECRET),
                        ];
                        let counter = meter.u64_counter("counter").build();
                        let gauge = meter.f64_gauge("gauge").build();
                        let histogram = meter.f64_histogram("histogram").build();
                        let exponential = meter.f64_histogram("exp.histogram").build();
                        counter.add(7, &attrs);
                        gauge.record(1.5, &attrs);
                        histogram.record(3.0, &attrs);
                        exponential.record(4.0, &attrs);
                        emitted.send_blocking(provider.force_flush()).unwrap();
                        stopping.recv_timeout(WATCHDOG).unwrap();
                        // SDK 0.32 performs another cumulative collection on shutdown.
                        provider.shutdown_with_timeout(WATCHDOG)
                    }
                    OtlpSignal::Traces => {
                        let exporter = TraceWitness {
                            inner: OtlpSdkHttpSpanExporter::new(source_queue).with_policy(policy()),
                            expected,
                        };
                        let provider = SdkTracerProvider::builder()
                            .with_simple_exporter(exporter)
                            .with_resource(resource())
                            .with_sampler(Sampler::AlwaysOn)
                            .build();
                        let tracer = provider.tracer_with_scope(scope());
                        let owner = OtelContext::new().with_remote_span_context(parent(true));
                        let mut span = tracer
                            .span_builder("span credential-sensitive")
                            .with_kind(SpanKind::Server)
                            .with_start_time(UNIX_EPOCH + Duration::from_secs(100))
                            .with_attributes([
                                SdkAttribute::new("owner", SECRET),
                                SdkAttribute::new("secret", SECRET),
                            ])
                            .with_links(vec![opentelemetry::trace::Link::with_context(parent(
                                false,
                            ))])
                            .start_with_context(&tracer, &owner);
                        span.add_event_with_timestamp(
                            "event credential-sensitive",
                            UNIX_EPOCH + Duration::from_secs(101),
                            vec![SdkAttribute::new("owner", SECRET)],
                        );
                        span.set_status(Status::error("failure credential-sensitive"));
                        span.end_with_timestamp(UNIX_EPOCH + Duration::from_secs(102));
                        emitted.send_blocking(Ok(())).unwrap();
                        stopping.recv_timeout(WATCHDOG).unwrap();
                        provider.shutdown_with_timeout(WATCHDOG)
                    }
                    OtlpSignal::Logs => {
                        let exporter = LogsWitness {
                            inner: OtlpSdkHttpLogExporter::new(source_queue).with_policy(policy()),
                            expected,
                        };
                        let provider = SdkLoggerProvider::builder()
                            .with_simple_exporter(exporter)
                            .with_resource(resource())
                            .build();
                        let logger = provider.logger_with_scope(scope());
                        let _attached = OtelContext::new()
                            .with_remote_span_context(parent(true))
                            .attach();
                        let mut record = logger.create_log_record();
                        record.set_timestamp(UNIX_EPOCH + Duration::from_secs(100));
                        record.set_observed_timestamp(UNIX_EPOCH + Duration::from_secs(101));
                        record.set_target("sdk-http-target");
                        record.set_event_name("event credential-sensitive");
                        record.set_severity_number(Severity::Warn2);
                        record.set_severity_text("WARN credential-sensitive");
                        record.set_body(SdkLogValue::ListAny(Box::new(vec![
                            SdkLogValue::Int(9),
                            SdkLogValue::Boolean(false),
                            SdkLogValue::from(SECRET),
                            SdkLogValue::Bytes(Box::new(vec![0, 255, 1])),
                        ])));
                        record.add_attribute("owner", SECRET);
                        record.add_attribute("secret", SECRET);
                        logger.emit(record);
                        emitted.send_blocking(Ok(())).unwrap();
                        stopping.recv_timeout(WATCHDOG).unwrap();
                        provider.shutdown_with_timeout(WATCHDOG)
                    }
                };
                shutdown.send_blocking(result).unwrap();
            });

            let (arrived, mut arrival) = oneshot::channel();
            let (release, released) = mpsc::channel();
            let peer = std::thread::spawn(move || {
                let mut first = accept(&listener);
                let captured = request(&mut first);
                assert_request(
                    &captured,
                    expected_body.recv_timeout(WATCHDOG).unwrap(),
                    signal,
                );
                let body = partial(1, "collector credential-sensitive");
                write!(first,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len(),
                ).unwrap();
                first.write_all(&body[..body.len() - 1]).unwrap();
                first.flush().unwrap();
                arrived.send_blocking(()).unwrap();
                released.recv_timeout(WATCHDOG).unwrap();
                first.write_all(&body[body.len() - 1..]).unwrap();
                first.flush().unwrap();
                drop(first);
                if signal == OtlpSignal::Metrics {
                    let mut second = accept(&listener);
                    let captured = request(&mut second);
                    assert_request(
                        &captured,
                        expected_body.recv_timeout(WATCHDOG).unwrap(),
                        signal,
                    );
                    respond(&mut second, 200, &[], Some("application/x-protobuf"), &[]);
                }
                listener
            });

            arrival.recv(&cx).await.unwrap();
            let mut wait = Box::pin(emission.recv(&cx));
            poll_fn(|task| {
                assert!(
                    wait.as_mut().poll(task).is_pending(),
                    "SDK completion must wait for the full HTTP protobuf response"
                );
                Poll::Ready(())
            })
            .await;
            let parked = queue.queue_stats().queue;
            assert_eq!(parked.retained_batches, 1);
            assert!(parked.retained_bytes > 0);
            assert_eq!(parked.delivered_batches, 0);
            // Blocking SDK flush is refused promptly on the active native owner.
            let check = OtlpSdkHttpMetricExporter::new(queue.clone());
            assert!(check.force_flush().is_err());
            release.send(()).unwrap();
            wait.await.unwrap().unwrap();
            let ack = queue.queue_stats();
            assert_eq!(ack.partial_success_batches, 1);
            assert_eq!(
                ack.rejected_data_points,
                u64::from(signal == OtlpSignal::Metrics)
            );
            assert_eq!(ack.rejected_spans, u64::from(signal == OtlpSignal::Traces));
            assert_eq!(
                ack.rejected_log_records,
                u64::from(signal == OtlpSignal::Logs)
            );
            assert_eq!(ack.queue.retained_batches, 0);
            assert_eq!(ack.queue.retained_bytes, 0);
            assert!(!format!("{queue:?}").contains(SECRET));

            stop.send(()).unwrap();
            shutdown_result.recv(&cx).await.unwrap().unwrap();
            let report = service.join(&cx).await.unwrap();
            assert!(report.task.is_ok());
            assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Drained)));
            let stats = queue.queue_stats().queue;
            assert_eq!(
                stats.delivered_batches,
                if signal == OtlpSignal::Metrics { 2 } else { 1 }
            );
            assert_eq!(stats.failed_batches, 0);
            assert_eq!(stats.retained_batches, 0);
            assert_eq!(stats.retained_bytes, 0);
            assert!(
                queue.enqueue_encoded(signal, Vec::new()).is_err(),
                "SDK shutdown seals all clones"
            );
            sdk.join().unwrap();
            no_more_connections(&peer.join().unwrap());
        });
    }
}

#[test]
fn sdk_http_guard_order_configuration_and_resource_latch_remain_value_free() {
    let queue = producer("127.0.0.1:1".parse().unwrap());
    let metrics = OtlpSdkHttpMetricExporter::new(queue.clone());
    assert_eq!(metrics.temporality(), Temporality::Cumulative);
    assert!(
        OtlpSdkHttpMetricExporter::try_with_config(
            queue.clone(),
            OtlpSdkMetricsConfig::new().with_max_collection_bytes(0),
        )
        .is_err()
    );
    assert!(
        OtlpSdkHttpSpanExporter::try_with_config(
            queue.clone(),
            OtlpSdkTraceConfig::new().with_max_collection_bytes(0),
        )
        .is_err()
    );
    assert!(
        OtlpSdkHttpLogExporter::try_with_config(
            queue.clone(),
            OtlpSdkLogConfig::new().with_max_collection_bytes(0),
        )
        .is_err()
    );
    let error = ready(metrics.export(&ResourceMetrics::default())).unwrap_err();
    assert!(
        matches!(error, OTelSdkError::InternalFailure(code) if code == "otlp.sdk.metrics.owner_unavailable")
    );
    let trace = OtlpSdkHttpSpanExporter::new(queue.clone());
    let error = ready(trace.export(Vec::new())).unwrap_err();
    assert!(
        matches!(error, OTelSdkError::InternalFailure(code) if code == "otlp.sdk.traces.owner_unavailable")
    );
    let logs = OtlpSdkHttpLogExporter::new(queue);
    let error = ready(logs.export(LogBatch::new(&[]))).unwrap_err();
    assert!(
        matches!(error, OTelSdkError::InternalFailure(code) if code == "otlp.sdk.logs.owner_unavailable")
    );

    native(|cx| async move {
        let (listener, address) = listener();
        let queue = producer(address);
        // Native refusal precedes an absent owner and even an empty source batch.
        let trace = OtlpSdkHttpSpanExporter::new(queue.clone());
        let error = trace.export(Vec::new()).await.unwrap_err();
        assert!(
            matches!(error, OTelSdkError::InternalFailure(code) if code == "otlp.sdk.traces.native_context")
        );
        let logs = OtlpSdkHttpLogExporter::new(queue.clone());
        let error = logs.export(LogBatch::new(&[])).await.unwrap_err();
        assert!(
            matches!(error, OTelSdkError::InternalFailure(code) if code == "otlp.sdk.logs.native_context")
        );
        assert_eq!(queue.queue_stats().queue.retained_batches, 0);
        no_more_connections(&listener);

        let mut service = queue.spawn_queued(&cx).await.unwrap();
        let source_queue = queue.clone();
        let (finished, mut completion) = oneshot::channel();
        let sdk = std::thread::spawn(move || {
            let invalid = Resource::builder_empty()
                .with_attributes([SdkAttribute::new("secret", SECRET.repeat(4096))])
                .build();
            let mut trace = OtlpSdkHttpSpanExporter::try_with_config(
                source_queue.clone(),
                OtlpSdkTraceConfig::new().with_max_collection_bytes(1024),
            )
            .unwrap();
            let mut logs = OtlpSdkHttpLogExporter::try_with_config(
                source_queue.clone(),
                OtlpSdkLogConfig::new().with_max_collection_bytes(1024),
            )
            .unwrap();
            trace.set_resource(&invalid);
            logs.set_resource(&invalid);
            for output in [
                ready(trace.export(Vec::new())),
                ready(logs.export(LogBatch::new(&[]))),
            ] {
                let error = output.unwrap_err();
                let text = error.to_string();
                assert!(text.contains("limit_exceeded"));
                assert!(!text.contains(SECRET));
            }
            assert!(!format!("{trace:?} {logs:?}").contains(SECRET));
            assert_eq!(source_queue.queue_stats().queue.retained_batches, 0);
            let empty = Resource::builder_empty().build();
            trace.set_resource(&empty);
            logs.set_resource(&empty);
            ready(trace.export(Vec::new())).unwrap();
            ready(logs.export(LogBatch::new(&[]))).unwrap();
            trace.force_flush().unwrap();
            logs.force_flush_queue(WATCHDOG).unwrap();
            finished.send_blocking(()).unwrap();
        });
        completion.recv(&cx).await.unwrap();
        service.begin_drain();
        let report = service.join(&cx).await.unwrap();
        assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Drained)));
        assert_eq!(queue.queue_stats().queue.delivered_batches, 0);
        assert_eq!(queue.queue_stats().queue.retained_bytes, 0);
        no_more_connections(&listener);
        sdk.join().unwrap();
    });
}
