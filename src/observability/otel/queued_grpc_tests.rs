//! Real native collector and child-region journeys for the all-signal queue.

use super::super::{
    Destination, OTLP_EXPORT_QUEUE_MAX_BATCHES, OTLP_EXPORT_QUEUE_MAX_BYTES, Payload,
};
use super::*;
use crate::bytes::{Bytes, BytesMut};
use crate::channel::oneshot;
use crate::codec::Decoder as _;
use crate::cx::ChildRegionSpec;
use crate::grpc::client::Channel;
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::observability::level::LogLevel;
use crate::observability::metrics::MetricsProvider;
use crate::observability::otel::{
    ManagedOtlpOutcome, OtlpHttpExporter, OtlpLogBody, OwnedOtlpLogConfig, OwnedOtlpMetricsConfig,
    OwnedOtlpTraceConfig,
};
use crate::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder};
use crate::types::CancelReason;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::mpsc;
use std::task::Poll;
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);

fn native<F, Fut>(scenario: F)
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
    let result = receive
        .recv_timeout(Duration::from_secs(30))
        .expect("native queue service must finish and quiesce");
    thread.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

fn accept(listener: &TcpListener) -> TcpStream {
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
            Err(error) => panic!("collector accept: {error}"),
        }
    }
}

fn flush(socket: &mut TcpStream, connection: &mut Connection) {
    let mut bytes = BytesMut::new();
    while let Some(frame) = connection.next_frame() {
        frame.encode(&mut bytes).unwrap();
    }
    socket.write_all(&bytes).unwrap();
}

fn frame(body: &[u8]) -> Bytes {
    let mut framed = vec![0];
    framed.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(body);
    Bytes::from(framed)
}

struct Captured {
    stream: u32,
    headers: Vec<Header>,
    body: Vec<u8>,
}

impl Captured {
    fn assert_request(&self, signal: OtlpGrpcSignal, body: &[u8]) {
        let path = self
            .headers
            .iter()
            .find(|header| header.name == ":path")
            .unwrap();
        assert_eq!(path.value, signal.method_path());
        assert_eq!(self.body, frame(body).to_vec());
    }
}

fn request(socket: &mut TcpStream) -> (Connection, Captured) {
    let mut preface = [0; 24];
    socket.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, CLIENT_PREFACE);
    let mut connection = Connection::server(Settings::server());
    connection.queue_initial_settings();
    flush(socket, &mut connection);
    let mut decoder = FrameCodec::new();
    let mut inbound = BytesMut::new();
    let mut headers = Vec::new();
    let mut body = Vec::new();
    let mut stream = None;
    loop {
        if let Some(frame) = decoder.decode(&mut inbound).unwrap() {
            let ended = match connection.process_frame(frame).unwrap() {
                Some(ReceivedFrame::Headers {
                    stream_id,
                    headers: received,
                    end_stream,
                }) => {
                    assert!(stream.is_none());
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
                    assert!(body.len() <= 4 * 1024 * 1024 + 5);
                    end_stream
                }
                _ => false,
            };
            flush(socket, &mut connection);
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
            let count = socket.read(&mut bytes).unwrap();
            assert_ne!(count, 0, "request ended before its half-close");
            inbound.extend_from_slice(&bytes[..count]);
        }
    }
}

fn respond(
    socket: &mut TcpStream,
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
    connection.send_data(stream, frame(body), false).unwrap();
    connection
        .send_headers(stream, vec![Header::new("grpc-status", status)], true)
        .unwrap();
    flush(socket, connection);
}

fn observe_close(socket: &mut TcpStream) {
    let mut pending = [0; 1024];
    loop {
        match socket.read(&mut pending) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return,
            Err(error) => panic!("in-flight native call did not close: {error}"),
        }
    }
}

async fn producer(address: SocketAddr) -> QueuedOtlpGrpcExporter {
    let channel = Channel::connect(format!("http://{address}")).await.unwrap();
    QueuedOtlpGrpcExporter::new(OtlpGrpcExporter::new(channel).unwrap())
}

fn traces() -> OwnedOtlpTraces {
    OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new().with_max_spans_per_request(1)).unwrap()
}

fn two_spans() -> [OtlpTraceSpanInput<'static>; 2] {
    [
        OtlpTraceSpanInput::new([1; 16], [1; 8], "first", 10, 20),
        OtlpTraceSpanInput::new([1; 16], [2; 8], "second", 10, 20),
    ]
}

#[test]
fn collection_capacity_is_atomic_and_inflight_credit_is_retained() {
    native(|_cx| async {
        let queue = producer("127.0.0.1:4317".parse().unwrap()).await;
        for _ in 0..OTLP_EXPORT_QUEUE_MAX_BATCHES - 1 {
            queue
                .enqueue_encoded(OtlpGrpcSignal::Metrics, Vec::new())
                .unwrap();
        }
        let before = queue.queue_stats();
        assert!(queue.enqueue_owned_traces(&traces(), &two_spans()).is_err());
        assert_eq!(queue.queue_stats(), before);
        let consumer = queue.queue.consumer().unwrap();
        let delivery = queue.queue.take().unwrap();
        assert_eq!(
            queue.queue_stats().queue.retained_batches,
            before.queue.retained_batches
        );
        assert!(queue.enqueue_owned_traces(&traces(), &two_spans()).is_err());
        drop(delivery);
        assert_eq!(
            queue.enqueue_owned_traces(&traces(), &two_spans()).unwrap(),
            2
        );
        let full = queue.queue_stats();
        assert_eq!(full.queue.retained_batches, OTLP_EXPORT_QUEUE_MAX_BATCHES);
        assert_eq!(full.queue.failed_batches, 1);
        drop(consumer);
        // No transport owns its queue, even while pending batches own transports.
        let queue_weak = Arc::downgrade(&queue.queue);
        let transport_weak = Arc::downgrade(&queue.transport);
        drop(queue);
        assert!(queue_weak.upgrade().is_none());
        assert!(transport_weak.upgrade().is_none());
    });
}

#[test]
fn backing_capacity_and_late_invalid_requests_are_refused_before_admission() {
    native(|_cx| async {
        let queue = producer("127.0.0.1:4317".parse().unwrap()).await;
        let oversized_allocation = Vec::with_capacity(OTLP_EXPORT_QUEUE_MAX_BYTES + 1);
        assert!(
            queue
                .enqueue_encoded(OtlpGrpcSignal::Logs, oversized_allocation)
                .is_err()
        );
        assert_eq!(queue.queue_stats(), OtlpGrpcQueueStats::default());
        let body = vec![0; 4 * 1024 * 1024];
        assert!(
            queue
                .admit(OtlpGrpcSignal::Logs, vec![body.clone(), body])
                .is_err()
        );
        assert_eq!(queue.queue_stats(), OtlpGrpcQueueStats::default());

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
        let channel = Channel::builder("http://127.0.0.1:4317")
            .max_send_message_size(bodies[0].len())
            .connect()
            .await
            .unwrap();
        let limited = QueuedOtlpGrpcExporter::new(OtlpGrpcExporter::new(channel).unwrap());
        assert!(limited.enqueue_owned_logs(&logs, &records).is_err());
        assert_eq!(limited.queue_stats(), OtlpGrpcQueueStats::default());
        let invalid = OtlpTraceSpanInput::new([1; 16], [3; 8], "invalid", 20, 10);
        assert!(
            limited
                .enqueue_owned_traces(&traces(), &[two_spans()[0], invalid])
                .is_err()
        );
        assert_eq!(
            limited
                .enqueue_owned_traces(&traces(), &[two_spans()[0].with_trace_flags(0)])
                .unwrap(),
            0
        );
        assert_eq!(limited.enqueue_owned_logs(&logs, &[]).unwrap(), 0);
        assert_eq!(limited.queue_stats(), OtlpGrpcQueueStats::default());
    });
}

#[test]
fn managed_all_signal_drain_preserves_owned_bytes_and_counts_partial_receipts() {
    native(|cx| async move {
        let (listener, address) = listener();
        let channel = Channel::connect(format!("http://{address}")).await.unwrap();
        let transport = OtlpGrpcExporter::new(channel)
            .unwrap()
            .try_with_resource_attributes([("service.name".to_owned(), "queued-native".to_owned())])
            .unwrap();
        let queue = QueuedOtlpGrpcExporter::new(transport);
        let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
        metrics.task_stuck_detected("worker");
        let traces = traces();
        let spans = [two_spans()[0]];
        let logs = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).unwrap();
        let records = [OtlpLogRecordInput::new(
            LogLevel::Info,
            OtlpLogBody::Bool(true),
            3,
        )];
        let attributes = [("service.name", "queued-native")];
        let expected = [
            (
                OtlpGrpcSignal::Metrics,
                metrics.collect(4, &attributes).unwrap().remove(0),
                2,
            ),
            (
                OtlpGrpcSignal::Traces,
                traces
                    .collect(&spans, &attributes)
                    .unwrap()
                    .into_requests()
                    .remove(0),
                3,
            ),
            (
                OtlpGrpcSignal::Logs,
                logs.collect(
                    &records,
                    &[OtlpLogKeyValueInput::string(
                        "service.name",
                        "queued-native",
                    )],
                )
                .unwrap()
                .into_requests()
                .remove(0),
                4,
            ),
            (OtlpGrpcSignal::Logs, Vec::new(), 0),
        ];
        assert_eq!(queue.enqueue_owned_metrics(&metrics, 4).unwrap(), 1);
        assert_eq!(queue.enqueue_owned_traces(&traces, &spans).unwrap(), 1);
        assert_eq!(queue.enqueue_owned_logs(&logs, &records).unwrap(), 1);
        queue
            .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
            .unwrap();
        let peer = std::thread::spawn(move || {
            for (signal, body, rejected) in expected {
                let mut socket = accept(&listener);
                let (mut connection, captured) = request(&mut socket);
                captured.assert_request(signal, &body);
                // Independent wire vector: partial_success { rejected_items }.
                let receipt = [0x0a, 0x02, 0x08, rejected];
                respond(&mut socket, &mut connection, captured.stream, &receipt, "0");
            }
        });
        let mut service = queue.spawn_queued(&cx).await.unwrap();
        service.begin_drain();
        assert!(
            queue
                .clone()
                .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
                .is_err()
        );
        assert!(
            queue.flush_queued(&cx).await.is_err(),
            "managed task exclusively owns delivery"
        );
        let report = service.join(&cx).await.unwrap();
        assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Drained)));
        assert!(report.task.is_ok());
        assert_ne!(report.region_id, cx.region_id());
        let stats = queue.queue_stats();
        assert_eq!(report.queue, stats.queue);
        assert_eq!(stats.queue.delivered_batches, 4);
        assert_eq!(stats.queue.failed_batches, 0);
        assert_eq!(stats.queue.retained_batches, 0);
        assert_eq!(stats.queue.retained_bytes, 0);
        assert!(!stats.queue.consumer_active);
        assert_eq!(stats.partial_success_batches, 4);
        assert_eq!(stats.rejected_data_points, 2);
        assert_eq!(stats.rejected_spans, 3);
        assert_eq!(stats.rejected_log_records, 4);
        peer.join().unwrap();
    });
}

#[test]
fn manual_parked_cancellation_retires_once_and_later_backlog_can_flush() {
    native(|cx| async move {
        let boundary = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        let (listener, address) = listener();
        let queue = producer(address).await;
        queue
            .enqueue_encoded(OtlpGrpcSignal::Metrics, Vec::new())
            .unwrap();
        queue
            .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
            .unwrap();
        let (arrived, mut arrival) = oneshot::channel();
        let peer = std::thread::spawn(move || {
            let mut first = accept(&listener);
            let (_, captured) = request(&mut first);
            captured.assert_request(OtlpGrpcSignal::Metrics, &[]);
            arrived.send_blocking(()).unwrap();
            observe_close(&mut first);
            let mut later = accept(&listener);
            let (mut connection, captured) = request(&mut later);
            captured.assert_request(OtlpGrpcSignal::Logs, &[]);
            respond(&mut later, &mut connection, captured.stream, &[], "0");
        });
        let consumer = queue.clone();
        let mut flushing = boundary
            .cx()
            .spawn(move |owner| async move { consumer.flush_queued(&owner).await })
            .unwrap();
        arrival.recv(&cx).await.unwrap();
        assert_eq!(queue.queue_stats().queue.retained_batches, 2);
        boundary
            .cancel(CancelReason::user("stop manual delivery"))
            .unwrap();
        match flushing.join(&cx).await {
            Ok(Err(_)) | Err(JoinError::Cancelled(_)) => {}
            other => panic!("cancelled delivery did not retire as failed: {other:?}"),
        }
        let interrupted = queue.queue_stats();
        assert_eq!(interrupted.queue.failed_batches, 1);
        assert_eq!(interrupted.queue.retained_batches, 1);
        assert_eq!(interrupted.queue.queued_batches, 1);
        assert!(!interrupted.queue.consumer_active);
        boundary.close().await.unwrap();
        assert_eq!(queue.flush_queued(&cx).await.unwrap(), 1);
        let final_stats = queue.queue_stats();
        assert_eq!(final_stats.queue.failed_batches, 1);
        assert_eq!(final_stats.queue.delivered_batches, 1);
        assert_eq!(final_stats.queue.retained_bytes, 0);
        peer.join().unwrap();
    });
}

#[test]
fn managed_abort_and_owner_region_cancellation_close_io_and_retire_backlog() {
    for abort in [true, false] {
        native(move |cx| async move {
            let boundary = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let (listener, address) = listener();
            let queue = producer(address).await;
            queue.enqueue_owned_traces(&traces(), &two_spans()).unwrap();
            let (arrived, mut arrival) = oneshot::channel();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let _ = request(&mut socket);
                arrived.send_blocking(()).unwrap();
                observe_close(&mut socket);
            });
            let mut service = queue.spawn_queued(boundary.cx()).await.unwrap();
            arrival.recv(&cx).await.unwrap();
            if abort {
                service.abort();
            } else {
                boundary
                    .cancel(CancelReason::user("close native queue owner"))
                    .unwrap();
            }
            let report = service.join(&cx).await.unwrap();
            if abort {
                assert!(matches!(report.delivery, Some(ManagedOtlpOutcome::Aborted)));
            } else {
                assert!(matches!(
                    report.delivery,
                    Some(ManagedOtlpOutcome::Cancelled(_))
                ));
            }
            assert_eq!(report.queue.delivered_batches, 0);
            assert_eq!(report.queue.failed_batches, 2);
            assert_eq!(report.queue.retained_batches, 0);
            assert_eq!(report.queue.retained_bytes, 0);
            assert!(!report.queue.consumer_active);
            assert_eq!(queue.queue_stats().partial_success_batches, 0);
            assert!(
                queue
                    .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
                    .is_err()
            );
            boundary.close().await.unwrap();
            peer.join().unwrap();
        });
    }
}

#[test]
fn continuous_consumer_wakes_for_admission_and_cancels_when_idle() {
    native(|cx| async move {
        let boundary = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        let (listener, address) = listener();
        let queue = producer(address).await;
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Logs, &[]);
            respond(&mut socket, &mut connection, captured.stream, &[], "0");
        });
        let (started, mut start) = oneshot::channel();
        let (drained, mut drain) = oneshot::channel();
        let consumer = queue.clone();
        let mut running = boundary
            .cx()
            .spawn(move |owner| async move {
                let mut operation = Box::pin(consumer.run_queued(&owner));
                let mut started = Some(started);
                let mut drained = Some(drained);
                poll_fn(|task| {
                    if let Poll::Ready(result) = operation.as_mut().poll(task) {
                        return Poll::Ready(result);
                    }
                    // Publish readiness only after the actual admitted task has
                    // parked in the consumer, initially and after its delivery.
                    if let Some(started) = started.take() {
                        started.send_blocking(()).unwrap();
                    }
                    if consumer.queue_stats().queue.delivered_batches == 1
                        && let Some(drained) = drained.take()
                    {
                        drained.send_blocking(()).unwrap();
                    }
                    Poll::Pending
                })
                .await
            })
            .unwrap();
        start.recv(&cx).await.unwrap();
        assert!(queue.queue_stats().queue.consumer_active);
        queue
            .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
            .unwrap();
        drain.recv(&cx).await.unwrap();
        boundary
            .cancel(CancelReason::user("stop idle native queue"))
            .unwrap();
        match running.join(&cx).await {
            Ok(Err(_)) | Err(JoinError::Cancelled(_)) => {}
            other => panic!("cancelled idle consumer did not retire: {other:?}"),
        }
        assert!(!queue.queue_stats().queue.consumer_active);
        assert_eq!(queue.queue_stats().queue.retained_batches, 0);
        boundary.close().await.unwrap();
        peer.join().unwrap();
    });
}

#[test]
fn retry_policy_is_captured_at_admission_and_retry_keeps_delivery_credit() {
    native(|cx| async move {
        let (listener, address) = listener();
        let queue = producer(address).await;
        queue
            .enqueue_encoded(OtlpGrpcSignal::Metrics, Vec::new())
            .unwrap();
        let retrying = queue.clone().with_retry_policy(
            OtlpGrpcRetryPolicy::new(1, Duration::from_millis(1), Duration::from_millis(2))
                .unwrap()
                .with_jitter(false),
        );
        retrying
            .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
            .unwrap();
        let (arrived, mut arrival) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            // Earlier default-policy batch fails once, even when the consumer
            // is a clone configured to retry future admissions.
            let mut first = accept(&listener);
            let (mut connection, captured) = request(&mut first);
            captured.assert_request(OtlpGrpcSignal::Metrics, &[]);
            respond(&mut first, &mut connection, captured.stream, &[], "14");
            let mut retry = accept(&listener);
            let (mut connection, captured) = request(&mut retry);
            captured.assert_request(OtlpGrpcSignal::Logs, &[]);
            respond(&mut retry, &mut connection, captured.stream, &[], "14");
            let mut success = accept(&listener);
            let (mut connection, captured) = request(&mut success);
            captured.assert_request(OtlpGrpcSignal::Logs, &[]);
            arrived.send_blocking(()).unwrap();
            released.recv_timeout(WATCHDOG).unwrap();
            respond(&mut success, &mut connection, captured.stream, &[], "0");
        });
        assert!(retrying.flush_queued(&cx).await.is_err());
        assert_eq!(queue.queue_stats().queue.failed_batches, 1);
        let retained = queue.queue_stats().queue.retained_bytes;
        let consumer = retrying.clone();
        let mut flushing = cx
            .spawn(move |owner| async move { consumer.flush_queued(&owner).await })
            .unwrap();
        arrival.recv(&cx).await.unwrap();
        let in_flight = queue.queue_stats().queue;
        assert_eq!(in_flight.queued_batches, 0);
        assert_eq!(in_flight.retained_batches, 1);
        assert_eq!(in_flight.retained_bytes, retained);
        assert_eq!(in_flight.failed_batches, 1);
        assert_eq!(in_flight.delivered_batches, 0);
        release.send(()).unwrap();
        assert_eq!(flushing.join(&cx).await.unwrap().unwrap(), 1);
        assert_eq!(queue.queue_stats().queue.retained_bytes, 0);
        assert_eq!(queue.queue_stats().queue.delivered_batches, 1);
        assert_eq!(queue.queue_stats().queue.failed_batches, 1);
        peer.join().unwrap();
    });
}

#[test]
fn dropping_a_delivery_during_retry_backoff_does_not_requeue_it() {
    native(|cx| async move {
        let (listener, address) = listener();
        let queue = producer(address).await;
        let retrying = queue.clone().with_retry_policy(
            OtlpGrpcRetryPolicy::new(1, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap()
                .with_jitter(false),
        );
        retrying
            .enqueue_encoded(OtlpGrpcSignal::Metrics, Vec::new())
            .unwrap();
        queue
            .enqueue_encoded(OtlpGrpcSignal::Logs, Vec::new())
            .unwrap();
        let (closed, mut response_closed) = oneshot::channel();
        let peer = std::thread::spawn(move || {
            let mut first = accept(&listener);
            let (mut connection, captured) = request(&mut first);
            captured.assert_request(OtlpGrpcSignal::Metrics, &[]);
            respond(&mut first, &mut connection, captured.stream, &[], "14");
            // A non-pooled native unary exchange retires its socket after
            // receiving final status. This witnesses that the first RPC has
            // finished before we observe the pending retry wait.
            observe_close(&mut first);
            closed.send_blocking(()).unwrap();
            let mut next = accept(&listener);
            let (mut connection, captured) = request(&mut next);
            captured.assert_request(OtlpGrpcSignal::Logs, &[]);
            respond(&mut next, &mut connection, captured.stream, &[], "0");
        });
        let mut flushing = Box::pin(retrying.flush_queued(&cx));
        let mut witnessed = Box::pin(response_closed.recv(&cx));
        poll_fn(|task| {
            assert!(flushing.as_mut().poll(task).is_pending());
            if let Poll::Ready(result) = witnessed.as_mut().poll(task) {
                result.unwrap();
                // Drive once after the final-response close witness: the call
                // must now be suspended in its bounded five-second backoff.
                assert!(flushing.as_mut().poll(task).is_pending());
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
        drop(witnessed);
        assert_eq!(queue.queue_stats().queue.retained_batches, 2);
        assert_eq!(queue.queue_stats().queue.queued_batches, 1);
        drop(flushing);
        let retired = queue.queue_stats().queue;
        assert_eq!(retired.failed_batches, 1);
        assert_eq!(retired.retained_batches, 1);
        assert!(!retired.consumer_active);
        assert_eq!(queue.flush_queued(&cx).await.unwrap(), 1);
        assert_eq!(queue.queue_stats().queue.failed_batches, 1);
        assert_eq!(queue.queue_stats().queue.delivered_batches, 1);
        assert_eq!(queue.queue_stats().queue.retained_bytes, 0);
        peer.join().unwrap();
    });
}

#[test]
fn http_owned_metrics_and_structured_logs_share_atomic_encoded_admission() {
    let metrics = OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1)).unwrap();
    metrics.task_stuck_detected("worker");
    let metrics_exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/custom-metrics");
    assert_eq!(
        metrics_exporter.enqueue_owned_metrics(&metrics, 4).unwrap(),
        1
    );
    let delivery = metrics_exporter.export_queue.take().unwrap();
    let batch = delivery.batch.as_ref().unwrap();
    let Payload::Encoded {
        signal: OtlpGrpcSignal::Metrics,
        body,
    } = &batch.payload
    else {
        panic!("owned metrics must retain their preencoded timestamp");
    };
    assert_eq!(body, &metrics.collect(4, &[]).unwrap()[0]);
    let Destination::Http { config, .. } = &batch.destination else {
        panic!("HTTP destination")
    };
    assert_eq!(config.endpoint, "http://127.0.0.1:4318/custom-metrics");
    drop(delivery);

    let logs =
        OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_records_per_request(1)).unwrap();
    let body = [OtlpLogBody::Int(7), OtlpLogBody::Bool(true)];
    let records = [
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Array(&body), 2),
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Bytes(b"opaque"), 3),
    ];
    let logs_exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/custom-logs");
    assert_eq!(
        logs_exporter.enqueue_owned_logs(&logs, &records).unwrap(),
        2
    );
    let expected = logs.collect(&records, &[]).unwrap().into_requests();
    for expected in expected {
        let delivery = logs_exporter.export_queue.take().unwrap();
        let batch = delivery.batch.as_ref().unwrap();
        let Payload::Encoded {
            signal: OtlpGrpcSignal::Logs,
            body,
        } = &batch.payload
        else {
            panic!("typed log bodies must retain owned encoding");
        };
        assert_eq!(body, &expected);
        let Destination::Http { config, .. } = &batch.destination else {
            panic!("HTTP destination")
        };
        assert_eq!(config.endpoint, "http://127.0.0.1:4318/custom-logs");
    }
}
