//! Snapshot adapter integration against an independent native HTTP/2 collector.

use super::*;
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder as _;
use crate::grpc::Channel;
use crate::grpc::protobuf::{ProtoMessage, ProtobufWireLimits};
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::observability::async_export::{AsyncExportOutcome, AsyncMultiExporter};
use crate::observability::otel::{InMemoryExporter, MetricsSnapshot};
use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
use crate::observability::otlp_proto::common_and_resource::AnyValueValue;
use crate::observability::otlp_proto::metrics::{MetricData, NumberDataPointValue};
use crate::runtime::{Runtime, RuntimeBuilder};
use crate::types::{Budget, CancelKind};
use std::future::Future;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);
const METRICS_PATH: &str = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export";

fn runtime(workers: usize) -> Runtime {
    if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .expect("snapshot exporter runtime")
}

async fn within<T>(cx: &Cx, future: impl Future<Output = T>) -> T {
    crate::time::timeout(cx.now(), WATCHDOG, future)
        .await
        .expect("snapshot exporter watchdog")
}

fn batch(snapshot: &MetricsSnapshot) -> MetricsExportBatch<'_> {
    MetricsExportBatch::new(snapshot, 1000, 2000).unwrap()
}

async fn exporter(listener: &TcpListener) -> OtlpGrpcSnapshotExporter {
    let channel = Channel::builder(format!("http://{}", listener.local_addr().unwrap()))
        .connect_timeout(WATCHDOG)
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();
    OtlpGrpcSnapshotExporter::new(
        OtlpGrpcExporter::new(channel)
            .unwrap()
            .try_with_resource_attributes([(
                "service.name".into(),
                "private-resource-value".into(),
            )])
            .unwrap(),
    )
}

struct Captured {
    headers: Vec<Header>,
    body: Vec<u8>,
}

fn flush(socket: &mut TcpStream, connection: &mut Connection) {
    let mut bytes = BytesMut::new();
    while let Some(frame) = connection.next_frame() {
        frame.encode(&mut bytes).unwrap();
    }
    socket.write_all(&bytes).unwrap();
}

// Exactly one request, with bounded accept and I/O. The response protobuf is
// supplied independently of the production encoder and collector parser.
fn collector(listener: &TcpListener, response: Vec<u8>) -> std::thread::JoinHandle<Captured> {
    listener.set_nonblocking(true).unwrap();
    let listener = listener.try_clone().unwrap();
    std::thread::spawn(move || {
        let until = Instant::now() + WATCHDOG;
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < until, "collector accept watchdog");
                    std::thread::park_timeout(Duration::from_millis(1));
                }
                Err(error) => panic!("collector accept: {error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(WATCHDOG)).unwrap();
        socket.set_write_timeout(Some(WATCHDOG)).unwrap();
        let mut connection = Connection::server(Settings::server());
        connection.queue_initial_settings();
        flush(&mut socket, &mut connection);
        let mut preface = [0; 24];
        socket.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, CLIENT_PREFACE);
        let mut decoder = FrameCodec::new();
        let mut incoming = BytesMut::new();
        let mut captured = Captured {
            headers: Vec::new(),
            body: Vec::new(),
        };
        let stream = 'request: loop {
            let mut bytes = [0; 4096];
            let read = socket.read(&mut bytes).unwrap();
            assert_ne!(read, 0, "caller closed before request completion");
            incoming.extend_from_slice(&bytes[..read]);
            while let Some(frame) = decoder.decode(&mut incoming).unwrap() {
                match connection.process_frame(frame).unwrap() {
                    Some(ReceivedFrame::Headers {
                        stream_id,
                        headers,
                        end_stream,
                    }) => {
                        captured.headers.extend(headers);
                        if end_stream {
                            break 'request stream_id;
                        }
                    }
                    Some(ReceivedFrame::Data {
                        stream_id,
                        data,
                        end_stream,
                    }) => {
                        captured.body.extend_from_slice(&data);
                        if end_stream {
                            break 'request stream_id;
                        }
                    }
                    _ => {}
                }
            }
            flush(&mut socket, &mut connection);
        };
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
        let mut framed = Vec::with_capacity(response.len() + 5);
        framed.push(0);
        framed.extend_from_slice(&u32::try_from(response.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(&response);
        connection
            .send_data(stream, Bytes::from(framed), false)
            .unwrap();
        connection
            .send_headers(stream, vec![Header::new("grpc-status", "0")], true)
            .unwrap();
        flush(&mut socket, &mut connection);
        captured
    })
}

fn assert_no_replay(listener: &TcpListener) {
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "one export must not initiate another collector connection"
    );
}

fn partial(rejected: u8) -> Vec<u8> {
    // ExportResponse.partial_success { rejected_*: n, error_message: ... }.
    let diagnostic = b"private-collector-diagnostic";
    let mut fields = vec![
        0x08,
        rejected,
        0x12,
        u8::try_from(diagnostic.len()).unwrap(),
    ];
    fields.extend_from_slice(diagnostic);
    let mut response = vec![0x0a, u8::try_from(fields.len()).unwrap()];
    response.extend_from_slice(&fields);
    response
}

#[test]
fn snapshot_export_preserves_owned_metric_semantics_over_native_grpc() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = collector(&listener, Vec::new());
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let exporter = exporter(&listener).await;
            assert!(!format!("{exporter:?}").contains("private-resource-value"));
            let mut snapshot = MetricsSnapshot::new();
            snapshot.add_counter("requests", vec![("route".into(), "/test".into())], 42);
            snapshot.add_gauge("active", Vec::new(), -7);
            snapshot.add_histogram("duration", Vec::new(), 3, 1.25);
            let response = within(&cx, exporter.export_with_response(&cx, batch(&snapshot)))
                .await
                .unwrap()
                .unwrap();
            assert!(!response.is_partial_success());
            assert_eq!(response.rejected_items(), 0);
        });
        let captured = peer.join().expect("independent collector assertions");
        assert!(
            captured
                .headers
                .iter()
                .any(|h| h.name == ":path" && h.value == METRICS_PATH)
        );
        assert!(
            captured
                .headers
                .iter()
                .any(|h| h.name == "content-type" && h.value == "application/grpc")
        );
        assert_eq!(captured.body[0], 0);
        assert_eq!(
            usize::try_from(u32::from_be_bytes(captured.body[1..5].try_into().unwrap())).unwrap(),
            captured.body.len() - 5
        );
        let request = ExportMetricsServiceRequest::decode_from_bytes(
            &captured.body[5..],
            ProtobufWireLimits::for_message_size(4 * 1024 * 1024),
        )
        .unwrap();
        let resource = &request.resource_metrics[0];
        let attr = &resource.resource.as_ref().unwrap().attributes[0];
        assert_eq!(attr.key, "service.name");
        assert_eq!(
            attr.value.as_ref().unwrap().value,
            Some(AnyValueValue::String("private-resource-value".into()))
        );
        let metrics = &resource.scope_metrics[0].metrics;
        assert_eq!(metrics.len(), 3);
        let Some(MetricData::Gauge(gauge)) = &metrics[0].data else {
            panic!("gauge")
        };
        assert_eq!(
            gauge.data_points[0].value,
            Some(NumberDataPointValue::Int(-7))
        );
        assert_eq!(gauge.data_points[0].start_time_unix_nano, 0);
        assert_eq!(gauge.data_points[0].time_unix_nano, 2000);
        let Some(MetricData::Histogram(histogram)) = &metrics[1].data else {
            panic!("histogram")
        };
        assert_eq!(histogram.data_points[0].count, 3);
        assert_eq!(histogram.data_points[0].sum, Some(1.25));
        assert_eq!(histogram.data_points[0].bucket_counts, [3]);
        let Some(MetricData::Sum(counter)) = &metrics[2].data else {
            panic!("counter")
        };
        assert!(counter.is_monotonic);
        assert_eq!(
            counter.data_points[0].value,
            Some(NumberDataPointValue::Int(42))
        );
        assert_eq!(counter.data_points[0].start_time_unix_nano, 1000);
        assert_eq!(counter.data_points[0].time_unix_nano, 2000);
        assert_no_replay(&listener);
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn empty_invalid_and_cancelled_snapshots_never_open_a_connection() {
    let runtime = runtime(1);
    let cancelled = runtime.request_cx_with_budget(Budget::INFINITE);
    cancelled.cancel_with(CancelKind::User, Some("cancel before export"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let exporter = exporter(&listener).await;
        let empty = MetricsSnapshot::new();
        assert!(
            exporter
                .export_with_response(&cx, batch(&empty))
                .await
                .unwrap()
                .is_none()
        );
        let mut invalid = MetricsSnapshot::new();
        invalid.add_counter("too_large", Vec::new(), u64::MAX);
        assert!(exporter.export(&cx, batch(&invalid)).await.is_err());
        let mut valid = MetricsSnapshot::new();
        valid.add_counter("requests", Vec::new(), 1);
        let error = exporter
            .export(&cancelled, batch(&valid))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cancelled_or_budget_exhausted"));
    });
    assert_no_replay(&listener);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn snapshot_response_retains_partial_rejections_and_warning_without_replay() {
    for rejected in [0, 2] {
        let runtime = runtime(1);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = collector(&listener, partial(rejected));
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let exporter = exporter(&listener).await;
            let mut snapshot = MetricsSnapshot::new();
            snapshot.add_counter("requests", Vec::new(), 7);
            let response = within(&cx, exporter.export_with_response(&cx, batch(&snapshot)))
                .await
                .unwrap()
                .unwrap();
            assert!(response.is_partial_success());
            assert_eq!(response.rejected_items(), u64::from(rejected));
            assert_eq!(response.error_message(), "private-collector-diagnostic");
            assert!(!format!("{response:?}").contains("private-collector-diagnostic"));
        });
        peer.join().unwrap();
        assert_no_replay(&listener);
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn async_fanout_preserves_other_destinations_and_redacts_partial_rejection() {
    for rejected in [0, 2] {
        let runtime = runtime(2);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = collector(&listener, partial(rejected));
        let first = Arc::new(InMemoryExporter::new());
        let last = Arc::new(InMemoryExporter::new());
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let grpc = exporter(&listener).await;
            let exporters = AsyncMultiExporter::try_new(vec![
                Box::new(Arc::clone(&first)),
                Box::new(grpc),
                Box::new(Arc::clone(&last)),
            ])
            .unwrap();
            let mut snapshot = MetricsSnapshot::new();
            snapshot.add_gauge("active", Vec::new(), 1);
            let report = within(&cx, exporters.export_all(&cx, batch(&snapshot))).await;
            assert!(!report.was_interrupted());
            assert!(matches!(
                report.outcomes()[0],
                AsyncExportOutcome::Succeeded
            ));
            assert!(matches!(
                report.outcomes()[2],
                AsyncExportOutcome::Succeeded
            ));
            if rejected == 0 {
                assert!(report.is_success());
            } else {
                let AsyncExportOutcome::Failed(error) = &report.outcomes()[1] else {
                    panic!("partial rejection must remain visible")
                };
                assert!(error.to_string().contains("do not retry this batch"));
                assert!(!error.to_string().contains("private-collector-diagnostic"));
                assert!(!format!("{report:?}").contains("private-collector-diagnostic"));
                assert_eq!(report.succeeded(), 2);
                assert_eq!(report.failed(), 1);
            }
            assert_eq!(report.not_attempted(), 0);
        });
        peer.join().unwrap();
        assert_eq!(first.total_metrics(), 1);
        assert_eq!(last.total_metrics(), 1);
        assert_no_replay(&listener);
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}
