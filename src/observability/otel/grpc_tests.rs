//! Native H2 peers exercise the actual exporter wire path, not loopback echo.

use super::*;
use crate::bytes::BytesMut;
use crate::codec::Decoder as _;
#[cfg(not(feature = "compression"))]
use crate::grpc::client::ChannelConfig;
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::observability::level::LogLevel;
use crate::observability::metrics::MetricsProvider;
use crate::observability::otel::{
    OtlpLogBody, OwnedOtlpLogConfig, OwnedOtlpMetricsConfig, OwnedOtlpTraceConfig,
};
use crate::runtime::RuntimeBuilder;
use crate::types::Budget;
use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Poll, Waker};
use std::time::Instant;

const WATCHDOG: Duration = Duration::from_secs(10);
const SECRET: &str = "fake-collector-secret";

#[derive(Default)]
pub(super) struct Signal {
    pub(super) ready: AtomicBool,
    pub(super) waiter: Mutex<Option<Waker>>,
}

impl Signal {
    pub(super) fn publish(&self) {
        self.ready.store(true, Ordering::Release);
        let waiter = self.waiter.lock().unwrap().take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

pub(super) struct WallWatchdog {
    pub(super) signal: Arc<Signal>,
    stop: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WallWatchdog {
    pub(super) fn new() -> Self {
        let signal = Arc::new(Signal::default());
        let expired = Arc::clone(&signal);
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(
                stopped.recv_timeout(WATCHDOG),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                expired.publish();
            }
        });
        Self {
            signal,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for WallWatchdog {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) fn run_native<F, Fut>(test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    // The operation's owner deliberately differs from its ambient poller.
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
    let watchdog = WallWatchdog::new();
    runtime.block_on_with_cx(
        driver,
        Box::pin(async {
            let mut future = Box::pin(test(owner));
            poll_fn(|task| {
                *watchdog.signal.waiter.lock().unwrap() = Some(task.waker().clone());
                assert!(
                    !watchdog.signal.ready.load(Ordering::Acquire),
                    "OTLP/gRPC wall watchdog elapsed"
                );
                future.as_mut().poll(task)
            })
            .await;
        }),
    );
    drop(watchdog);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

pub(super) fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

pub(super) fn accept(listener: &TcpListener) -> TcpStream {
    let until = Instant::now() + WATCHDOG;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(WATCHDOG)).unwrap();
                socket.set_write_timeout(Some(WATCHDOG)).unwrap();
                return socket;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < until, "collector was never contacted");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("collector accept failed: {error}"),
        }
    }
}

pub(super) fn flush(io: &mut impl Write, connection: &mut Connection) {
    let mut bytes = BytesMut::new();
    while let Some(frame) = connection.next_frame() {
        frame.encode(&mut bytes).unwrap();
    }
    io.write_all(&bytes).unwrap();
    io.flush().unwrap();
}

pub(super) fn framed(payload: &[u8]) -> Bytes {
    let mut bytes = Vec::with_capacity(payload.len() + 5);
    bytes.push(0);
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    Bytes::from(bytes)
}

pub(super) struct Captured {
    pub(super) stream: u32,
    headers: Vec<Header>,
    pub(super) body: Vec<u8>,
}

pub(super) fn read_request(io: &mut (impl Read + Write)) -> (Connection, Captured) {
    let mut preface = [0; 24];
    io.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, CLIENT_PREFACE);
    let mut connection = Connection::server(Settings::server());
    connection.queue_initial_settings();
    flush(io, &mut connection);
    let mut codec = FrameCodec::new();
    let mut inbound = BytesMut::new();
    let mut headers = Vec::new();
    let mut body = Vec::new();
    let mut stream = None;
    loop {
        if let Some(frame) = codec.decode(&mut inbound).unwrap() {
            let ended = match connection.process_frame(frame).unwrap() {
                Some(ReceivedFrame::Headers {
                    stream_id,
                    headers: received,
                    end_stream,
                }) => {
                    assert!(stream.is_none(), "one initial request header block");
                    stream = Some(stream_id);
                    headers = received;
                    end_stream
                }
                Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                }) => {
                    assert_eq!(Some(stream_id), stream);
                    body.extend_from_slice(&data);
                    assert!(body.len() <= OTLP_GRPC_MAX_MESSAGE_BYTES + 5);
                    end_stream
                }
                _ => false,
            };
            flush(io, &mut connection);
            if ended {
                return (
                    connection,
                    Captured {
                        stream: stream.unwrap(),
                        headers,
                        body,
                    },
                );
            }
        } else {
            let mut bytes = [0; 4096];
            let received = io.read(&mut bytes).expect("native HTTP/2 request");
            assert_ne!(received, 0, "request ended before half-close");
            inbound.extend_from_slice(&bytes[..received]);
        }
    }
}

impl Captured {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name == name)
            .map(|header| header.value.as_str())
    }

    pub(super) fn assert_request(&self, signal: OtlpGrpcSignal, body: &[u8]) {
        assert_eq!(self.header(":method"), Some("POST"));
        assert_eq!(self.header(":path"), Some(signal.method_path()));
        assert_eq!(self.header("content-type"), Some("application/grpc"));
        assert_eq!(self.header("te"), Some("trailers"));
        assert_eq!(
            self.body,
            framed(body).to_vec(),
            "one frame around the owned protobuf bytes"
        );
    }

    pub(super) fn assert_timeout(&self, maximum: Duration) {
        let timeout =
            crate::grpc::server::parse_grpc_timeout(self.header("grpc-timeout").unwrap()).unwrap();
        assert!(!timeout.is_zero() && timeout <= maximum);
    }
}

fn respond(
    io: &mut impl Write,
    connection: &mut Connection,
    stream: u32,
    messages: &[Vec<u8>],
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
    for message in messages {
        connection
            .send_data(stream, framed(message), false)
            .unwrap();
    }
    connection
        .send_headers(
            stream,
            vec![
                Header::new("grpc-status", status),
                Header::new("grpc-message", SECRET),
                Header::new("grpc-status-details-bin", "ZmFrZS1jb2xsZWN0b3Itc2VjcmV0"),
            ],
            true,
        )
        .unwrap();
    flush(io, connection);
}

pub(super) fn partial(rejected: u8, diagnostic: &str) -> Vec<u8> {
    // Independent canonical protobuf bytes: outer partial_success field1;
    // inner int64 rejected field1 and string diagnostic field2.
    assert!(rejected < 128 && diagnostic.len() < 120);
    let mut bytes = vec![
        0x0a,
        u8::try_from(diagnostic.len() + 4).unwrap(),
        0x08,
        rejected,
        0x12,
        u8::try_from(diagnostic.len()).unwrap(),
    ];
    bytes.extend_from_slice(diagnostic.as_bytes());
    bytes
}

fn require_send<T: Send>(value: T) -> T {
    value
}

#[test]
fn every_signal_uses_native_unary_path_owned_bytes_and_framed_empty_success() {
    for (signal, path) in [
        (
            OtlpGrpcSignal::Metrics,
            "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
        ),
        (
            OtlpGrpcSignal::Traces,
            "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        ),
        (
            OtlpGrpcSignal::Logs,
            "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
        ),
    ] {
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_request(signal, &[0x0a, 0x02, 0x12, 0x00]);
            assert_eq!(captured.header(":path"), Some(path));
            assert_eq!(
                captured.header(":authority"),
                Some(address.to_string().as_str())
            );
            captured.assert_timeout(OTLP_GRPC_DEFAULT_TIMEOUT);
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                &[Vec::new()],
                "0",
            );
        });
        run_native(|cx| async move {
            let channel = Channel::connect(format!("http://{address}/ignored-uri-path"))
                .await
                .unwrap();
            assert!(channel.config().timeout.is_none());
            let exporter = OtlpGrpcExporter::new(channel).unwrap();
            let response =
                require_send(exporter.send_once(&cx, signal, vec![0x0a, 0x02, 0x12, 0x00]))
                    .await
                    .unwrap();
            assert_eq!(response.signal(), signal);
            assert!(!response.is_partial_success());
            assert_eq!(response.rejected_items(), 0);
            assert!(response.error_message().is_empty());
        });
        peer.join().unwrap();
    }
}

#[test]
fn partial_success_warning_and_empty_presence_are_terminal_redacted_receipts() {
    for (body, rejected, diagnostic) in [
        (partial(2, SECRET), 2, SECRET),
        (partial(0, SECRET), 0, SECRET),
        (vec![0x0a, 0x00], 0, ""),
    ] {
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Logs, &[]);
            respond(&mut socket, &mut connection, captured.stream, &[body], "0");
            // No replay connection is accepted by this single-attempt fixture.
        });
        run_native(|cx| async move {
            let channel = Channel::connect(format!("http://{address}")).await.unwrap();
            let exporter = OtlpGrpcExporter::new(channel).unwrap();
            let receipt = exporter
                .send_once(&cx, OtlpGrpcSignal::Logs, Vec::new())
                .await
                .unwrap();
            assert!(receipt.is_partial_success());
            assert_eq!(receipt.rejected_items(), rejected);
            assert_eq!(receipt.error_message(), diagnostic);
            assert!(!format!("{receipt:?}").contains(SECRET));
        });
        peer.join().unwrap();
    }
}

#[test]
fn response_requires_one_message_valid_otlp_and_final_ok_status() {
    for (messages, status, kind, code) in [
        (
            vec![partial(1, SECRET)],
            "14",
            OtlpGrpcErrorKind::Rpc,
            Some(Code::Unavailable),
        ),
        (
            vec![vec![0x0a, 0xff]],
            "0",
            OtlpGrpcErrorKind::InvalidResponse,
            None,
        ),
        (
            vec![vec![0x0a, 0xff]],
            "14",
            OtlpGrpcErrorKind::Rpc,
            Some(Code::Unavailable),
        ),
        (
            Vec::new(),
            "0",
            OtlpGrpcErrorKind::Rpc,
            Some(Code::Internal),
        ),
        (
            vec![Vec::new(), Vec::new()],
            "0",
            OtlpGrpcErrorKind::Rpc,
            Some(Code::Internal),
        ),
    ] {
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                &messages,
                status,
            );
        });
        run_native(|cx| async move {
            let channel = Channel::connect(format!("http://{address}")).await.unwrap();
            let exporter = OtlpGrpcExporter::new(channel).unwrap();
            let error = exporter
                .send_once(&cx, OtlpGrpcSignal::Metrics, Vec::new())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.grpc_code(), code);
            assert!(error.completed_responses().is_empty());
            assert!(!format!("{error:?} {error}").contains(SECRET));
            assert!(!format!("{error:?} {error}").contains("ZmFrZS1jb2xsZWN0b3Itc2VjcmV0"));
        });
        peer.join().unwrap();
    }
}

#[test]
fn smaller_channel_and_exporter_deadlines_are_preserved_on_wire() {
    for (channel_timeout, exporter_timeout) in [(3, 5), (5, 3)] {
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_timeout(Duration::from_secs(3));
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                &[Vec::new()],
                "0",
            );
        });
        run_native(|cx| async move {
            let channel = Channel::builder(format!("http://{address}"))
                .timeout(Duration::from_secs(channel_timeout))
                .connect()
                .await
                .unwrap();
            let exporter = OtlpGrpcExporter::new(channel)
                .unwrap()
                .try_with_timeout(Duration::from_secs(exporter_timeout))
                .unwrap();
            exporter
                .send_once(&cx, OtlpGrpcSignal::Traces, Vec::new())
                .await
                .unwrap();
        });
        peer.join().unwrap();
    }
}

#[test]
fn configuration_and_request_preflight_refuse_work_before_dial() {
    let (listener, address) = listener();
    run_native(|cx| async move {
        let uri = format!("http://{address}");
        for uri in ["http://loopback", "http://user:secret@LOOPBACK:4317"] {
            let channel = Channel::connect(uri).await.unwrap();
            assert_eq!(
                OtlpGrpcExporter::new(channel).unwrap_err().kind(),
                OtlpGrpcErrorKind::InvalidChannel
            );
        }
        for (send, receive) in [
            (0, 10),
            (10, 0),
            (OTLP_GRPC_MAX_MESSAGE_BYTES + 1, 10),
            (10, OTLP_GRPC_MAX_MESSAGE_BYTES + 1),
        ] {
            let channel = Channel::builder(&uri)
                .max_send_message_size(send)
                .max_recv_message_size(receive)
                .connect()
                .await
                .unwrap();
            assert_eq!(
                OtlpGrpcExporter::new(channel).unwrap_err().kind(),
                OtlpGrpcErrorKind::InvalidLimit
            );
        }
        let channel = Channel::builder(&uri)
            .max_send_message_size(1)
            .connect()
            .await
            .unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        assert_eq!(
            exporter
                .clone()
                .try_with_timeout(Duration::ZERO)
                .unwrap_err()
                .kind(),
            OtlpGrpcErrorKind::InvalidTimeout
        );
        let mut authorization = Metadata::new();
        assert!(authorization.insert("authorization", SECRET));
        assert_eq!(
            exporter
                .clone()
                .try_with_metadata(authorization)
                .unwrap_err()
                .kind(),
            OtlpGrpcErrorKind::InsecureMetadata
        );
        for key in [
            "grpc-timeout",
            "grpc-encoding",
            "grpc-custom",
            "content-length",
            "connection",
            "proxy-authorization",
        ] {
            let mut metadata = Metadata::new();
            assert!(metadata.insert(key, "value"));
            assert_eq!(
                exporter
                    .clone()
                    .try_with_metadata(metadata)
                    .unwrap_err()
                    .kind(),
                OtlpGrpcErrorKind::InvalidMetadata
            );
        }
        let mut repeated = Metadata::new();
        assert!(repeated.insert("authorization", SECRET));
        assert!(repeated.insert("Authorization", SECRET));
        assert_eq!(
            exporter
                .clone()
                .try_with_metadata(repeated)
                .unwrap_err()
                .kind(),
            OtlpGrpcErrorKind::InvalidMetadata
        );
        let mut binary = Metadata::new();
        assert!(binary.insert_bin("credentials-bin", Bytes::from(vec![0; 6144])));
        assert_eq!(
            exporter
                .clone()
                .try_with_metadata(binary)
                .unwrap_err()
                .kind(),
            OtlpGrpcErrorKind::InvalidMetadata
        );
        let mut excessive = Metadata::new();
        for index in 0..33 {
            assert!(excessive.insert(format!("key-{index}"), "value"));
        }
        assert_eq!(
            exporter
                .clone()
                .try_with_metadata(excessive)
                .unwrap_err()
                .kind(),
            OtlpGrpcErrorKind::InvalidMetadata
        );
        let error = exporter
            .clone()
            .try_with_resource_attributes([
                ("service.name".to_owned(), SECRET.to_owned()),
                ("service.name".to_owned(), SECRET.to_owned()),
            ])
            .unwrap_err();
        assert_eq!(error.kind(), OtlpGrpcErrorKind::InvalidResourceAttributes);
        assert!(!format!("{error:?} {error}").contains(SECRET));
        let error = exporter
            .send_once(&cx, OtlpGrpcSignal::Metrics, vec![0, 0])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), OtlpGrpcErrorKind::RequestTooLarge);
        let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
        assert_eq!(
            exporter
                .send_owned_metrics(&cx, &metrics, 0)
                .await
                .unwrap_err()
                .mapping_code(),
            Some("otlp.metrics.invalid_timestamp")
        );
        let logs = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).unwrap();
        assert!(
            exporter
                .send_owned_logs(&cx, &logs, &[])
                .await
                .unwrap()
                .responses()
                .is_empty()
        );
        let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new()).unwrap();
        assert!(
            exporter
                .send_owned_traces(&cx, &traces, &[])
                .await
                .unwrap()
                .responses()
                .is_empty()
        );
    });
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[cfg(not(feature = "compression"))]
#[test]
fn unavailable_gzip_is_refused_instead_of_silently_downgraded() {
    run_native(|_cx| async {
        for config in [
            ChannelConfig {
                send_compression: Some(CompressionEncoding::Gzip),
                ..Default::default()
            },
            ChannelConfig {
                accept_compression: vec![CompressionEncoding::Gzip],
                ..Default::default()
            },
        ] {
            let channel = Channel::connect_with_config("http://127.0.0.1:4317", config)
                .await
                .unwrap();
            assert_eq!(
                OtlpGrpcExporter::new(channel).unwrap_err().kind(),
                OtlpGrpcErrorKind::UnsupportedCompression
            );
        }
    });
}

#[test]
fn channel_receive_limit_rejects_oversized_collector_message() {
    let (listener, address) = listener();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        let (mut connection, captured) = read_request(&mut socket);
        respond(
            &mut socket,
            &mut connection,
            captured.stream,
            &[partial(1, SECRET)],
            "0",
        );
    });
    run_native(|cx| async move {
        let channel = Channel::builder(format!("http://{address}"))
            .max_recv_message_size(4)
            .connect()
            .await
            .unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let error = exporter
            .send_once(&cx, OtlpGrpcSignal::Logs, Vec::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), OtlpGrpcErrorKind::Rpc);
        assert_eq!(error.grpc_code(), Some(Code::ResourceExhausted));
    });
    peer.join().unwrap();
}

#[test]
fn owned_collections_preserve_encoder_bytes_resources_and_receipts() {
    for signal in [
        OtlpGrpcSignal::Metrics,
        OtlpGrpcSignal::Traces,
        OtlpGrpcSignal::Logs,
    ] {
        let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
        metrics.task_stuck_detected("worker");
        let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new()).unwrap();
        let spans = [OtlpTraceSpanInput::new([1; 16], [2; 8], "work", 2, 3)];
        let logs = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).unwrap();
        let records = [OtlpLogRecordInput::new(
            LogLevel::Info,
            OtlpLogBody::String("work finished"),
            3,
        )];
        let expected = match signal {
            OtlpGrpcSignal::Metrics => metrics
                .collect(4, &[("service.name", "native-test")])
                .unwrap(),
            OtlpGrpcSignal::Traces => traces
                .collect(&spans, &[("service.name", "native-test")])
                .unwrap()
                .into_requests(),
            OtlpGrpcSignal::Logs => logs
                .collect(
                    &records,
                    &[OtlpLogKeyValueInput::string("service.name", "native-test")],
                )
                .unwrap()
                .into_requests(),
        };
        assert_eq!(expected.len(), 1);
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_request(signal, &expected[0]);
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                &[Vec::new()],
                "0",
            );
        });
        run_native(|cx| async move {
            let channel = Channel::connect(format!("http://{address}")).await.unwrap();
            let exporter = OtlpGrpcExporter::new(channel)
                .unwrap()
                .try_with_resource_attributes([(
                    "service.name".to_owned(),
                    "native-test".to_owned(),
                )])
                .unwrap();
            let report = match signal {
                OtlpGrpcSignal::Metrics => exporter.send_owned_metrics(&cx, &metrics, 4).await,
                OtlpGrpcSignal::Traces => exporter.send_owned_traces(&cx, &traces, &spans).await,
                OtlpGrpcSignal::Logs => exporter.send_owned_logs(&cx, &logs, &records).await,
            }
            .unwrap();
            assert_eq!(report.responses().len(), 1);
            assert_eq!(report.responses()[0].signal(), signal);
        });
        peer.join().unwrap();
    }
}

#[test]
fn acknowledged_batches_survive_a_later_failure_without_replay() {
    let logs =
        OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_records_per_request(1)).unwrap();
    let records = [
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("first"), 1),
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("second"), 2),
    ];
    let expected = logs.collect(&records, &[]).unwrap().into_requests();
    assert_eq!(expected.len(), 2);
    let (listener, address) = listener();
    let peer = std::thread::spawn(move || {
        for (index, body) in expected.into_iter().enumerate() {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Logs, &body);
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                &[partial(0, SECRET)],
                if index == 0 { "0" } else { "14" },
            );
        }
    });
    run_native(|cx| async move {
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let error = exporter
            .send_owned_logs(&cx, &logs, &records)
            .await
            .unwrap_err();
        assert_eq!(error.grpc_code(), Some(Code::Unavailable));
        assert_eq!(error.completed_responses().len(), 1);
        assert!(error.completed_responses()[0].is_partial_success());
        assert_eq!(error.completed_responses()[0].error_message(), SECRET);
        assert!(!format!("{error:?} {error}").contains(SECRET));
    });
    peer.join().unwrap();
}

#[test]
fn whole_collection_send_limit_preflight_dials_no_peer() {
    let (listener, address) = listener();
    run_native(|cx| async move {
        let logs =
            OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_records_per_request(1))
                .unwrap();
        let large = "x".repeat(512);
        let records = [
            OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("small"), 1),
            OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String(&large), 2),
        ];
        let bodies = logs.collect(&records, &[]).unwrap().into_requests();
        assert!(bodies[0].len() < bodies[1].len());
        let channel = Channel::builder(format!("http://{address}"))
            .max_send_message_size(bodies[0].len())
            .connect()
            .await
            .unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let error = exporter
            .send_owned_logs(&cx, &logs, &records)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), OtlpGrpcErrorKind::RequestTooLarge);
        assert!(error.completed_responses().is_empty());
    });
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn parked_native_export_observes_explicit_owner_cancellation() {
    let (listener, address) = listener();
    let witness = Arc::new(Signal::default());
    let observed = Arc::clone(&witness);
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        let (_connection, captured) = read_request(&mut socket);
        captured.assert_request(OtlpGrpcSignal::Metrics, &[]);
        observed.publish();
        // The client may send a final SETTINGS acknowledgement before closing.
        let mut remaining = [0; 1024];
        loop {
            match socket.read(&mut remaining) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("cancelled native exchange did not close: {error}"),
            }
        }
    });
    run_native(|owner| async move {
        let driver = Cx::current().unwrap();
        assert_ne!(driver.task_id(), owner.task_id());
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let exporter = OtlpGrpcExporter::new(channel).unwrap();
        let mut call = Box::pin(exporter.send_once(&owner, OtlpGrpcSignal::Metrics, Vec::new()));
        let mut cancelled = false;
        let result = poll_fn(|task| {
            *witness.waiter.lock().unwrap() = Some(task.waker().clone());
            if let Poll::Ready(result) = call.as_mut().poll(task) {
                return Poll::Ready(result);
            }
            if witness.ready.load(Ordering::Acquire) && !cancelled {
                cancelled = true;
                owner.cancel_with(CancelKind::User, Some("stop native telemetry"));
            }
            Poll::Pending
        })
        .await;
        drop(call);
        assert!(cancelled);
        assert_eq!(result.unwrap_err().grpc_code(), Some(Code::Cancelled));
        assert!(!driver.is_cancel_requested());
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
    });
    peer.join().unwrap();
}

#[cfg(feature = "tls")]
const CERT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls/server.crt"
));

#[cfg(feature = "tls")]
fn tls_server(io: TcpStream) -> rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let key = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/server.key"
    ));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_slice(CERT).unwrap()],
        PrivateKeyDer::from_pem_slice(key).unwrap(),
    )
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    rustls::StreamOwned::new(rustls::ServerConnection::new(Arc::new(config)).unwrap(), io)
}

#[cfg(feature = "tls")]
fn tls_connector() -> crate::tls::TlsConnector {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CERT).unwrap())
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    crate::tls::TlsConnector::new(config)
}

#[cfg(feature = "tls")]
#[test]
fn caller_tls_channel_preserves_authority_auth_metadata_and_redaction() {
    let (listener, address) = listener();
    let peer = std::thread::spawn(move || {
        let mut tls = tls_server(accept(&listener));
        let (mut connection, captured) = read_request(&mut tls);
        captured.assert_request(OtlpGrpcSignal::Traces, &[]);
        assert_eq!(captured.header(":authority"), Some("collector.invalid"));
        assert_eq!(captured.header(":scheme"), Some("https"));
        assert_eq!(captured.header("authorization"), Some(SECRET));
        assert_eq!(captured.header("x-tenant"), Some("private-tenant"));
        assert_eq!(captured.header("proof-bin"), Some("AQID"));
        assert_eq!(tls.conn.server_name(), Some("localhost"));
        respond(
            &mut tls,
            &mut connection,
            captured.stream,
            &[partial(0, SECRET)],
            "0",
        );
    });
    run_native(|cx| async move {
        let channel = Channel::builder("https://collector.invalid")
            .tls_connector(tls_connector())
            .tls_server_name("localhost")
            .dial_addr(address)
            .connect()
            .await
            .unwrap();
        let mut metadata = Metadata::new();
        assert!(metadata.insert("authorization", SECRET));
        assert!(metadata.insert("x-tenant", "private-tenant"));
        assert!(metadata.insert_bin("proof-bin", Bytes::from(vec![1, 2, 3])));
        let exporter = OtlpGrpcExporter::new(channel)
            .unwrap()
            .try_with_metadata(metadata)
            .unwrap()
            .try_with_resource_attributes([("private-resource".to_owned(), SECRET.to_owned())])
            .unwrap();
        let debug = format!("{exporter:?}");
        for sensitive in [
            SECRET,
            "private-tenant",
            "private-resource",
            "collector.invalid",
        ] {
            assert!(!debug.contains(sensitive));
        }
        let receipt = exporter
            .send_once(&cx, OtlpGrpcSignal::Traces, Vec::new())
            .await
            .unwrap();
        assert_eq!(receipt.error_message(), SECRET);
        assert!(!format!("{receipt:?}").contains(SECRET));
    });
    peer.join().unwrap();
}

#[cfg(feature = "tls")]
#[test]
fn metadata_admission_compacts_ascii_and_binary_backing_before_queue_retention() {
    use crate::observability::otel::{OTLP_EXPORT_QUEUE_MAX_BATCHES, QueuedOtlpGrpcExporter};

    let (listener, address) = listener();
    run_native(|_cx| async move {
        let channel = Channel::builder("https://collector.invalid")
            .tls_connector(tls_connector())
            .tls_server_name("localhost")
            .dial_addr(address)
            .connect()
            .await
            .unwrap();
        let mut ascii = String::with_capacity(1024 * 1024);
        ascii.push_str(SECRET);
        let old_ascii_capacity = ascii.capacity();
        let mut storage = vec![0x55; 1024 * 1024];
        storage[100..103].copy_from_slice(&[0, 0xff, 1]);
        let backing = Bytes::from(storage);
        let tiny_slice = backing.slice(100..103);
        let old_binary_pointer = tiny_slice.as_ptr();
        let mut metadata = Metadata::new();
        metadata.reserve(16_384);
        assert!(metadata.insert("authorization", ascii));
        assert!(metadata.insert_bin("proof-bin", tiny_slice));

        let exporter = OtlpGrpcExporter::new(channel)
            .unwrap()
            .try_with_metadata(metadata)
            .unwrap();
        assert_eq!(exporter.metadata.len(), 2);
        let Some(MetadataValue::Ascii(stored_ascii)) = exporter.metadata.get("authorization")
        else {
            panic!("ASCII credential retained its type");
        };
        assert_eq!(stored_ascii, SECRET);
        assert!(stored_ascii.capacity() < old_ascii_capacity);
        assert!(stored_ascii.capacity() <= OTLP_HTTP_MAX_AUTH_HEADER_VALUE_BYTES);
        let Some(MetadataValue::Binary(stored_binary)) = exporter.metadata.get("proof-bin") else {
            panic!("binary credential retained its type");
        };
        assert_eq!(stored_binary.as_ref(), &[0, 0xff, 1]);
        assert!(
            !std::ptr::eq(stored_binary.as_ptr(), old_binary_pointer),
            "a tiny binary view must not retain the caller's large backing allocation"
        );
        // Keep the original allocation alive across the pointer assertion, so
        // allocator address reuse cannot masquerade as retained ownership.
        assert_eq!(&backing[100..103], &[0, 0xff, 1]);
        let charge = exporter.configuration_bytes();
        assert!(
            charge < 1024,
            "retained configuration follows compact values"
        );
        let debug = format!("{exporter:?}");
        for sensitive in [SECRET, "authorization", "proof-bin", "collector.invalid"] {
            assert!(!debug.contains(sensitive));
        }

        let queue = QueuedOtlpGrpcExporter::new(exporter);
        for _ in 0..OTLP_EXPORT_QUEUE_MAX_BATCHES {
            queue
                .enqueue_encoded(OtlpGrpcSignal::Metrics, Vec::new())
                .unwrap();
        }
        let stats = queue.queue_stats().queue;
        assert_eq!(stats.retained_batches, OTLP_EXPORT_QUEUE_MAX_BATCHES);
        assert_eq!(stats.retained_bytes, charge * OTLP_EXPORT_QUEUE_MAX_BATCHES);
        assert_eq!(stats.delivered_batches, 0);
        assert_eq!(stats.failed_batches, 0);
    });
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[cfg(feature = "tls")]
#[test]
fn metadata_compaction_preserves_count_limits_and_refuses_invalid_raw_entries() {
    let (listener, address) = listener();
    run_native(|_cx| async move {
        let channel = Channel::builder("https://collector.invalid")
            .tls_connector(tls_connector())
            .tls_server_name("localhost")
            .dial_addr(address)
            .connect()
            .await
            .unwrap();
        let mut maximum = Metadata::new();
        maximum.reserve(16_384);
        for index in 0..32 {
            assert!(maximum.insert(format!("x-{index}"), SECRET));
        }
        let exporter = OtlpGrpcExporter::new(channel.clone())
            .unwrap()
            .try_with_metadata(maximum)
            .unwrap();
        assert_eq!(exporter.metadata.len(), 32);
        for index in 0..32 {
            let Some(MetadataValue::Ascii(value)) = exporter.metadata.get(&format!("x-{index}"))
            else {
                panic!("metadata compaction preserves every valid field");
            };
            assert_eq!(value, SECRET);
        }

        let mut excessive = exporter.metadata.clone();
        assert!(excessive.insert("one-too-many", SECRET));
        let raw_invalid = [
            // Rebuilding before validation would normalize this into a valid
            // lowercase credential field and accidentally admit it.
            Metadata::from_raw_entries_for_tests(vec![(
                "Authorization".to_owned(),
                MetadataValue::Ascii(SECRET.to_owned()),
            )]),
            Metadata::from_raw_entries_for_tests(vec![(
                "authorization".to_owned(),
                MetadataValue::Ascii(format!("{SECRET}\r\n")),
            )]),
            Metadata::from_raw_entries_for_tests(vec![(
                "proof".to_owned(),
                MetadataValue::Binary(Bytes::from_static(b"private-proof")),
            )]),
            excessive,
        ];
        for metadata in raw_invalid {
            let error = OtlpGrpcExporter::new(channel.clone())
                .unwrap()
                .try_with_metadata(metadata)
                .unwrap_err();
            assert_eq!(error.kind(), OtlpGrpcErrorKind::InvalidMetadata);
            let text = format!("{error:?} {error}");
            for sensitive in [
                SECRET,
                "authorization",
                "private-proof",
                "collector.invalid",
            ] {
                assert!(!text.contains(sensitive));
            }
        }
    });
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn native_queue_charges_resource_string_capacity_and_refuses_oversized_configuration() {
    use crate::observability::otel::{
        OTLP_EXPORT_QUEUE_MAX_BYTES, OtlpGrpcQueueStats, QueuedOtlpGrpcExporter,
    };

    let (listener, address) = listener();
    run_native(|_cx| async move {
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let uri_bytes = channel.uri().len();
        for oversized_key in [false, true] {
            let mut key = String::with_capacity(if oversized_key {
                OTLP_EXPORT_QUEUE_MAX_BYTES + 1
            } else {
                "service.name".len()
            });
            key.push_str("service.name");
            let mut value = String::with_capacity(if oversized_key {
                SECRET.len()
            } else {
                OTLP_EXPORT_QUEUE_MAX_BYTES + 1
            });
            value.push_str(SECRET);
            let capacity = key.capacity() + value.capacity();
            let exporter = OtlpGrpcExporter::new(channel.clone())
                .unwrap()
                .try_with_resource_attributes([(key, value)])
                .unwrap();
            assert_eq!(exporter.configuration_bytes(), uri_bytes + capacity);
            let queue = QueuedOtlpGrpcExporter::new(exporter);
            let error = queue
                .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
                .unwrap_err();
            assert_eq!(queue.queue_stats(), OtlpGrpcQueueStats::default());
            assert!(!format!("{error:?} {error}").contains(SECRET));
        }

        let mut key = String::with_capacity(1024);
        key.push_str("service.name");
        let mut value = String::with_capacity(4096);
        value.push_str(SECRET);
        let capacity = key.capacity() + value.capacity();
        let exporter = OtlpGrpcExporter::new(channel)
            .unwrap()
            .try_with_resource_attributes([(key, value)])
            .unwrap();
        let queue = QueuedOtlpGrpcExporter::new(exporter);
        queue
            .enqueue_encoded(OtlpGrpcSignal::Traces, Vec::new())
            .unwrap();
        let stats = queue.queue_stats().queue;
        assert_eq!(stats.retained_batches, 1);
        assert_eq!(stats.retained_bytes, uri_bytes + capacity);
        assert_eq!(stats.delivered_batches, 0);
    });
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}
