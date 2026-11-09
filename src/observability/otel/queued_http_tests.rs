//! Native HTTP collector acknowledgements and shared queue ownership.

use super::super::{OTLP_EXPORT_QUEUE_MAX_BATCHES, OTLP_EXPORT_QUEUE_MAX_BYTES};
use super::*;
use crate::channel::oneshot;
use crate::cx::ChildRegionSpec;
use crate::observability::level::LogLevel;
use crate::observability::metrics::MetricsProvider;
use crate::observability::otel::{
    ManagedOtlpOutcome, OtlpHttpConfigBuilder, OtlpLogBody, OtlpLogRecordInput, OtlpTraceSpanInput,
    OwnedOtlpLogConfig, OwnedOtlpLogs, OwnedOtlpMetrics, OwnedOtlpMetricsConfig,
    OwnedOtlpTraceConfig, OwnedOtlpTraces,
};
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::types::CancelReason;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::mpsc;
use std::task::{Context, Waker};
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);

pub(in crate::observability::otel) fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                let builder = if workers == 1 {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::new().worker_threads(workers)
                };
                let runtime = builder.build().unwrap();
                runtime.block_on(async {
                    let root = Cx::current().unwrap();
                    let mut task = root.spawn(scenario).unwrap();
                    task.join(&root).await.unwrap();
                });
                let report = runtime.shutdown_drained(WATCHDOG);
                assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                assert_eq!(report.live_tasks, 0);
                assert_eq!(report.pending_spawns, 0);
                assert_eq!(report.pending_obligations, 0);
            }
        }));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30)).unwrap();
    thread.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

pub(in crate::observability::otel) fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

pub(in crate::observability::otel) fn accept(listener: &TcpListener) -> TcpStream {
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
                assert!(Instant::now() < until, "collector was not contacted");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("collector accept: {error}"),
        }
    }
}

pub(in crate::observability::otel) struct Captured {
    pub(in crate::observability::otel) target: String,
    pub(in crate::observability::otel) headers: Vec<(String, String)>,
    pub(in crate::observability::otel) body: Vec<u8>,
}

impl Captured {
    pub(in crate::observability::otel) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub(in crate::observability::otel) fn request(socket: &mut TcpStream) -> Captured {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16 * 1024);
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap().split(' ').collect::<Vec<_>>();
    assert_eq!(first.len(), 3);
    assert_eq!(first[0], "POST");
    assert_eq!(first[2], "HTTP/1.1");
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (key, value) = line.split_once(':').unwrap();
            (key.to_owned(), value.trim().to_owned())
        })
        .collect::<Vec<_>>();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .unwrap()
        .1
        .parse()
        .unwrap();
    assert!(length <= 4 * 1024 * 1024);
    let mut body = vec![0; length];
    socket.read_exact(&mut body).unwrap();
    Captured {
        target: first[1].to_owned(),
        headers,
        body,
    }
}

pub(in crate::observability::otel) fn respond(
    socket: &mut TcpStream,
    status: u16,
    body: &[u8],
    content_type: Option<&str>,
    extra: &[(&str, &str)],
) {
    write!(
        socket,
        "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )
    .unwrap();
    if let Some(content_type) = content_type {
        write!(socket, "Content-Type: {content_type}\r\n").unwrap();
    }
    for (name, value) in extra {
        write!(socket, "{name}: {value}\r\n").unwrap();
    }
    socket.write_all(b"\r\n").unwrap();
    socket.write_all(body).unwrap();
    socket.flush().unwrap();
}

pub(in crate::observability::otel) fn observe_close(socket: &mut TcpStream) {
    let mut bytes = [0; 1024];
    loop {
        match socket.read(&mut bytes) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return,
            Err(error) => panic!("native HTTP request did not retire its socket: {error}"),
        }
    }
}

pub(in crate::observability::otel) fn no_more_connections(listener: &TcpListener) {
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "completed/abandoned requests must not be replayed"
    );
}

pub(in crate::observability::otel) fn config(
    address: SocketAddr,
    signal: &str,
    retries: u32,
    timeout: Duration,
) -> OtlpHttpConfig {
    OtlpHttpConfigBuilder::new(format!("http://{address}/custom/{signal}?target={signal}"))
        .with_timeout(timeout)
        .with_retry_config(retries, Duration::from_millis(1), Duration::from_millis(2))
        .build()
        .unwrap()
}

pub(in crate::observability::otel) fn producer(address: SocketAddr) -> QueuedOtlpHttpExporter {
    QueuedOtlpHttpExporter::new(
        config(address, "metrics", 1, WATCHDOG),
        config(address, "traces", 1, WATCHDOG),
        config(address, "logs", 1, WATCHDOG),
    )
}

pub(in crate::observability::otel) fn partial(rejected: u8, diagnostic: &str) -> Vec<u8> {
    assert!(rejected < 128 && diagnostic.len() < 120);
    let mut inner = vec![0x08, rejected, 0x12, diagnostic.len() as u8];
    inner.extend_from_slice(diagnostic.as_bytes());
    let mut body = vec![0x0a, inner.len() as u8];
    body.extend_from_slice(&inner);
    body
}

#[test]
fn admission_charges_backing_capacity_and_inflight_credit_without_publishing_a_prefix() {
    let queue = producer("127.0.0.1:4318".parse().unwrap());
    let oversized = Vec::with_capacity(OTLP_EXPORT_QUEUE_MAX_BYTES + 1);
    assert!(queue.enqueue_encoded(OtlpSignal::Logs, oversized).is_err());
    assert_eq!(queue.queue_stats(), OtlpHttpQueueStats::default());
    assert!(
        queue
            .enqueue_encoded_with_receipt(
                OtlpSignal::Logs,
                vec![Vec::new(), vec![0; 4 * 1024 * 1024 + 1]],
            )
            .is_err()
    );
    assert_eq!(queue.queue_stats(), OtlpHttpQueueStats::default());
    for _ in 0..OTLP_EXPORT_QUEUE_MAX_BATCHES - 1 {
        queue
            .enqueue_encoded(OtlpSignal::Metrics, Vec::new())
            .unwrap();
    }
    let before = queue.queue_stats();
    assert!(
        queue
            .enqueue_encoded_with_receipt(OtlpSignal::Traces, vec![Vec::new(), Vec::new()],)
            .is_err()
    );
    assert_eq!(queue.queue_stats(), before);
    let consumer = queue.queue.consumer().unwrap();
    let delivery = queue.queue.take().unwrap();
    assert_eq!(
        queue.queue_stats().queue.retained_batches,
        OTLP_EXPORT_QUEUE_MAX_BATCHES - 1
    );
    assert!(
        queue
            .enqueue_encoded_with_receipt(OtlpSignal::Traces, vec![Vec::new(), Vec::new()],)
            .is_err()
    );
    drop(delivery);
    let receipt = queue
        .enqueue_encoded_with_receipt(OtlpSignal::Traces, vec![Vec::new(), Vec::new()])
        .unwrap();
    drop(receipt);
    assert_eq!(
        queue.queue_stats().queue.retained_batches,
        OTLP_EXPORT_QUEUE_MAX_BATCHES
    );
    drop(consumer);
    let weak_queue = Arc::downgrade(&queue.queue);
    let weak_config = Arc::downgrade(&queue.traces);
    drop(queue);
    assert!(weak_queue.upgrade().is_none());
    assert!(weak_config.upgrade().is_none());

    assert!(
        OtlpHttpConfigBuilder::new("http://127.0.0.1:4318/v1/metrics")
            .with_bearer_token("credential-private")
            .build()
            .is_err()
    );
}

#[test]
fn acknowledged_delivery_requires_the_explicit_timer_before_contacting_a_peer() {
    let (listener, address) = listener();
    let queue = producer(address);
    queue
        .enqueue_encoded(OtlpSignal::Metrics, Vec::new())
        .unwrap();
    let owner = Cx::for_testing();
    let mut future = std::pin::pin!(queue.flush_queued(&owner));
    let Poll::Ready(Err(error)) = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("missing timer must fail before native I/O");
    };
    assert_eq!(error.message, "otlp.http.timer_required");
    assert_eq!(queue.queue_stats().queue.failed_batches, 1);
    assert_eq!(queue.queue_stats().queue.retained_bytes, 0);
    no_more_connections(&listener);
}

#[test]
fn all_signals_keep_exact_http_paths_and_owned_bytes_and_count_terminal_partials() {
    native(|cx| async move {
        let (listener, address) = listener();
        let queue = producer(address);
        let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
        metrics.task_stuck_detected("worker");
        let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new()).unwrap();
        let logs = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).unwrap();
        let bodies = [
            (
                OtlpSignal::Metrics,
                "metrics",
                metrics.collect(4, &[]).unwrap().remove(0),
                2,
                "",
            ),
            (
                OtlpSignal::Traces,
                "traces",
                traces
                    .collect(
                        &[OtlpTraceSpanInput::new([1; 16], [1; 8], "span", 10, 20)],
                        &[],
                    )
                    .unwrap()
                    .into_requests()
                    .remove(0),
                3,
                "",
            ),
            (
                OtlpSignal::Logs,
                "logs",
                logs.collect(
                    &[OtlpLogRecordInput::new(
                        LogLevel::Info,
                        OtlpLogBody::Bool(true),
                        3,
                    )],
                    &[],
                )
                .unwrap()
                .into_requests()
                .remove(0),
                4,
                "credential-private",
            ),
            (OtlpSignal::Logs, "logs", Vec::new(), 0, "warning"),
            (OtlpSignal::Logs, "logs", Vec::new(), 0, ""),
        ];
        let mut receipts = Vec::new();
        for (signal, _, body, _, _) in &bodies {
            receipts.push(
                queue
                    .enqueue_encoded_with_receipt(*signal, vec![body.clone()])
                    .unwrap(),
            );
        }
        let peer = std::thread::spawn(move || {
            for (index, (_, signal, body, rejected, diagnostic)) in bodies.into_iter().enumerate() {
                let mut socket = accept(&listener);
                let captured = request(&mut socket);
                assert_eq!(captured.target, format!("/custom/{signal}?target={signal}"));
                assert_eq!(
                    captured.header("content-type"),
                    Some("application/x-protobuf")
                );
                assert_eq!(captured.body, body, "HTTP bodies have no gRPC frame prefix");
                let response = if index == 4 {
                    Vec::new()
                } else {
                    partial(rejected, diagnostic)
                };
                respond(
                    &mut socket,
                    200,
                    &response,
                    Some("application/x-protobuf"),
                    &[],
                );
            }
            listener
        });
        let mut service = queue.spawn_queued(&cx).await.unwrap();
        service.begin_drain();
        assert!(queue.enqueue_encoded(OtlpSignal::Logs, Vec::new()).is_err());
        let joined = service.join(&cx).await.unwrap();
        assert!(matches!(joined.delivery, Some(ManagedOtlpOutcome::Drained)));
        assert!(joined.task.is_ok());
        assert_ne!(joined.region_id, cx.region_id());
        for (index, receipt) in receipts.into_iter().enumerate() {
            let report = receipt.await.unwrap();
            assert_eq!(report.responses().len(), 1);
            assert_eq!(report.responses()[0].is_partial_success(), index != 4);
            if index == 2 {
                assert_eq!(report.responses()[0].error_message(), "credential-private");
                assert!(!format!("{report:?}").contains("credential-private"));
            }
        }
        let stats = queue.queue_stats();
        assert_eq!(stats.queue, joined.queue);
        assert_eq!(stats.queue.delivered_batches, 5);
        assert_eq!(stats.queue.failed_batches, 0);
        assert_eq!(stats.queue.retained_batches, 0);
        assert_eq!(stats.queue.retained_bytes, 0);
        assert_eq!(stats.partial_success_batches, 4);
        assert_eq!(stats.rejected_data_points, 2);
        assert_eq!(stats.rejected_spans, 3);
        assert_eq!(stats.rejected_log_records, 4);
        no_more_connections(&peer.join().unwrap());
    });
}

#[test]
fn non_collector_statuses_encodings_and_malformed_or_oversized_bodies_never_acknowledge() {
    for case in 0..11 {
        native(move |cx| async move {
            let (listener, address) = listener();
            let queue = producer(address);
            let receipt = queue
                .enqueue_encoded_with_receipt(OtlpSignal::Metrics, vec![Vec::new()])
                .unwrap();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let _ = request(&mut socket);
                match case {
                    0..=5 => {
                        let status = [202, 204, 408, 400, 405, 500][case];
                        respond(
                            &mut socket,
                            status,
                            &[],
                            Some("application/x-protobuf"),
                            &[("Allow", "credential-private")],
                        );
                    }
                    6 => respond(&mut socket, 200, &[], None, &[]),
                    7 => respond(&mut socket, 200, &[], Some("application/json"), &[]),
                    8 => respond(
                        &mut socket,
                        200,
                        &[0x0a, 0x80],
                        Some("application/x-protobuf"),
                        &[],
                    ),
                    9 => respond(
                        &mut socket,
                        200,
                        &[],
                        Some("application/x-protobuf"),
                        &[("Content-Encoding", "gzip")],
                    ),
                    10 => {
                        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            4 * 1024 * 1024 + 1).unwrap();
                        socket.flush().unwrap();
                        observe_close(&mut socket);
                    }
                    _ => unreachable!(),
                }
                listener
            });
            let mut service = queue.spawn_queued(&cx).await.unwrap();
            service.begin_drain();
            let joined = service.join(&cx).await.unwrap();
            assert!(matches!(
                joined.delivery,
                Some(ManagedOtlpOutcome::Failed(_))
            ));
            assert_eq!(joined.queue.delivered_batches, 0);
            assert_eq!(joined.queue.failed_batches, 1);
            assert_eq!(joined.queue.retained_bytes, 0);
            let error = receipt.await.unwrap_err();
            assert!(error.completed_responses().is_empty());
            assert!(error.grpc_code().is_none());
            assert!(!format!("{error} {error:?} {joined:?}").contains("credential-private"));
            no_more_connections(&peer.join().unwrap());
        });
    }
}

#[test]
fn existing_http_exporter_retains_its_legacy_success_status_contract() {
    native(|cx| async move {
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let _ = request(&mut socket);
            respond(&mut socket, 204, &[], None, &[]);
        });
        let exporter = OtlpHttpExporter::from_config(config(address, "metrics", 0, WATCHDOG));
        exporter.send_otlp_protobuf(&cx, Vec::new()).await.unwrap();
        peer.join().unwrap();
    });
}

#[test]
fn a_later_failure_retains_prior_acknowledgements_and_retires_unattempted_backlog() {
    native(|cx| async move {
        let (listener, address) = listener();
        let queue = producer(address);
        let receipt = queue
            .enqueue_encoded_with_receipt(
                OtlpSignal::Logs,
                vec![Vec::new(), Vec::new(), Vec::new()],
            )
            .unwrap();
        let peer = std::thread::spawn(move || {
            let mut first = accept(&listener);
            let _ = request(&mut first);
            respond(
                &mut first,
                200,
                &partial(1, "credential-private"),
                Some("application/x-protobuf"),
                &[],
            );
            let mut second = accept(&listener);
            let _ = request(&mut second);
            respond(
                &mut second,
                405,
                &[],
                Some("application/x-protobuf"),
                &[("Allow", "credential-private")],
            );
            listener
        });
        let mut service = queue.spawn_queued(&cx).await.unwrap();
        service.begin_drain();
        let joined = service.join(&cx).await.unwrap();
        let error = receipt.await.unwrap_err();
        assert_eq!(error.code(), "otlp.http.export_failed");
        assert_eq!(error.completed_responses().len(), 1);
        assert_eq!(error.completed_responses()[0].rejected_items(), 1);
        assert_eq!(
            error.completed_responses()[0].error_message(),
            "credential-private"
        );
        assert!(!format!("{error:?} {joined:?}").contains("credential-private"));
        assert_eq!(joined.queue.delivered_batches, 1);
        assert_eq!(joined.queue.failed_batches, 2);
        assert_eq!(joined.queue.retained_batches, 0);
        assert_eq!(joined.queue.retained_bytes, 0);
        assert_eq!(queue.queue_stats().rejected_log_records, 1);
        no_more_connections(&peer.join().unwrap());
    });
}

#[test]
fn retry_retains_one_credit_until_the_complete_collector_response() {
    native(|cx| async move {
        let (listener, address) = listener();
        let queue = producer(address);
        let mut receipt = queue
            .enqueue_encoded_with_receipt(OtlpSignal::Traces, vec![Vec::new()])
            .unwrap();
        let retained = queue.queue_stats().queue.retained_bytes;
        let (arrived, mut arrival) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut first = accept(&listener);
            let first_body = request(&mut first).body;
            respond(&mut first, 503, &[], Some("application/x-protobuf"), &[]);
            let mut retry = accept(&listener);
            let second_body = request(&mut retry).body;
            assert_eq!(first_body, second_body);
            arrived.send_blocking(()).unwrap();
            released.recv_timeout(WATCHDOG).unwrap();
            respond(&mut retry, 200, &[], Some("application/x-protobuf"), &[]);
            listener
        });
        let consumer = queue.clone();
        let mut flushing = cx
            .spawn(move |owner| async move { consumer.flush_queued(&owner).await })
            .unwrap();
        arrival.recv(&cx).await.unwrap();
        let stats = queue.queue_stats().queue;
        assert_eq!(stats.queued_batches, 0);
        assert_eq!(stats.retained_batches, 1);
        assert_eq!(stats.retained_bytes, retained);
        assert_eq!(stats.delivered_batches, 0);
        poll_fn(|task| {
            assert!(Pin::new(&mut receipt).poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        assert_eq!(flushing.join(&cx).await.unwrap().unwrap(), 1);
        assert_eq!(receipt.await.unwrap().responses().len(), 1);
        assert_eq!(queue.queue_stats().queue.retained_bytes, 0);
        assert_eq!(queue.queue_stats().queue.delivered_batches, 1);
        no_more_connections(&peer.join().unwrap());
    });
}

#[test]
fn retry_after_minimum_cannot_be_shortened_to_escape_the_total_delivery_budget() {
    native(|cx| async move {
        let (listener, address) = listener();
        let short = Duration::from_millis(150);
        let queue = QueuedOtlpHttpExporter::new(
            config(address, "metrics", 3, short),
            config(address, "traces", 3, short),
            config(address, "logs", 3, short),
        );
        let receipt = queue
            .enqueue_encoded_with_receipt(OtlpSignal::Metrics, vec![Vec::new()])
            .unwrap();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let _ = request(&mut socket);
            respond(
                &mut socket,
                429,
                &[],
                Some("application/x-protobuf"),
                &[("Retry-After", "2")],
            );
            observe_close(&mut socket);
            listener
        });
        let start = Instant::now();
        assert!(queue.flush_queued(&cx).await.is_err());
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(
            receipt.await.unwrap_err().code(),
            "otlp.http.deadline_exceeded"
        );
        assert_eq!(queue.queue_stats().queue.failed_batches, 1);
        assert_eq!(queue.queue_stats().queue.retained_bytes, 0);
        no_more_connections(&peer.join().unwrap());
    });
}

#[test]
fn parked_managed_abort_and_owner_cancellation_retire_io_backlog_and_receipts() {
    for abort in [true, false] {
        native(move |cx| async move {
            let boundary = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let (listener, address) = listener();
            let queue = producer(address);
            let receipt = queue
                .enqueue_encoded_with_receipt(OtlpSignal::Metrics, vec![Vec::new(), Vec::new()])
                .unwrap();
            let (arrived, mut arrival) = oneshot::channel();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let _ = request(&mut socket);
                arrived.send_blocking(()).unwrap();
                observe_close(&mut socket);
                listener
            });
            let mut service = queue.spawn_queued(boundary.cx()).await.unwrap();
            arrival.recv(&cx).await.unwrap();
            assert_eq!(queue.queue_stats().queue.retained_batches, 2);
            if abort {
                service.abort();
            } else {
                boundary
                    .cancel(CancelReason::user("cancel parked HTTP exporter"))
                    .unwrap();
            }
            let joined = service.join(&cx).await.unwrap();
            if abort {
                assert!(matches!(joined.delivery, Some(ManagedOtlpOutcome::Aborted)));
            } else {
                assert!(matches!(
                    joined.delivery,
                    Some(ManagedOtlpOutcome::Cancelled(_))
                ));
            }
            assert!(receipt.await.is_err());
            assert_eq!(joined.queue.delivered_batches, 0);
            assert_eq!(joined.queue.failed_batches, 2);
            assert_eq!(joined.queue.retained_batches, 0);
            assert_eq!(joined.queue.retained_bytes, 0);
            assert!(!joined.queue.consumer_active);
            boundary.close().await.unwrap();
            no_more_connections(&peer.join().unwrap());
        });
    }
}

#[cfg(feature = "compression")]
#[test]
fn unsupported_compression_is_terminal_and_never_replays_an_acknowledged_http_request() {
    native(|cx| async move {
        let (listener, address) = listener();
        let compressed = OtlpHttpConfigBuilder::new(format!("http://{address}/custom/metrics"))
            .with_timeout(WATCHDOG)
            .with_compression(true)
            .build()
            .unwrap();
        let queue = QueuedOtlpHttpExporter::new(
            compressed,
            config(address, "traces", 0, WATCHDOG),
            config(address, "logs", 0, WATCHDOG),
        );
        let receipt = queue
            .enqueue_encoded_with_receipt(OtlpSignal::Metrics, vec![Vec::new()])
            .unwrap();
        let peer = std::thread::spawn(move || {
            let mut first = accept(&listener);
            let captured = request(&mut first);
            assert_eq!(captured.header("content-encoding"), Some("gzip"));
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(captured.body.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            assert!(decoded.is_empty());
            respond(&mut first, 415, &[], Some("application/x-protobuf"), &[]);
            listener
        });
        assert!(queue.flush_queued(&cx).await.is_err());
        assert_eq!(receipt.await.unwrap_err().code(), "otlp.http.export_failed");
        assert_eq!(queue.queue_stats().queue.delivered_batches, 0);
        assert_eq!(queue.queue_stats().queue.failed_batches, 1);
        assert_eq!(queue.queue_stats().queue.retained_bytes, 0);
        no_more_connections(&peer.join().unwrap());
    });
}
