//! Acknowledged collections driven by real native H2 and admitted task owners.

use super::tests::{Captured, accept, flush, framed, listener, partial};
use super::{OtlpGrpcExporter, OtlpGrpcRetryPolicy, OtlpGrpcSignal};
use crate::Cx;
use crate::bytes::BytesMut;
use crate::channel::oneshot;
use crate::codec::Decoder as _;
use crate::cx::ChildRegionSpec;
use crate::grpc::{Channel, Code};
use crate::http::h2::frame::PingFrame;
use crate::http::h2::{Connection, Frame, FrameCodec, Header};
use crate::observability::otel::{
    ManagedOtlpOutcome, OTLP_EXPORT_QUEUE_MAX_BATCHES, OtlpGrpcQueueStats, QueuedOtlpGrpcExporter,
};
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::types::CancelReason;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::Pin;
use std::sync::mpsc;
use std::task::Poll;
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(10);
const DIAGNOSTIC: &str = "private-collector-acknowledgement";

pub(super) fn native<F, Fut>(scenario: F)
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
        .expect("acknowledged native queue must finish and quiesce");
    thread.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

async fn queue(address: SocketAddr) -> QueuedOtlpGrpcExporter {
    let channel = Channel::builder(format!("http://{address}"))
        .connect_timeout(WATCHDOG)
        .timeout(WATCHDOG)
        .connect()
        .await
        .unwrap();
    QueuedOtlpGrpcExporter::new(OtlpGrpcExporter::new(channel).unwrap())
}

// A bounded, independently encoded unknown protobuf field distinguishes batches
// without depending on the production signal mapper or on application contents.
fn body(tag: u8) -> Vec<u8> {
    vec![0x78, tag]
}

// The general request fixture may read beyond END_STREAM and discard its input
// suffix. These tests continue reading the same socket for a PING acknowledgement,
// so make the small request reads exact and preserve every subsequent frame byte.
pub(super) fn read_request(socket: &mut TcpStream) -> (Connection, Captured) {
    struct ExactReads<'a>(&'a mut TcpStream);

    impl Read for ExactReads<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = buffer.len().min(1);
            self.0.read(&mut buffer[..count])
        }
    }

    impl Write for ExactReads<'_> {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    super::tests::read_request(&mut ExactReads(socket))
}

pub(super) fn response_data(
    socket: &mut TcpStream,
    connection: &mut Connection,
    stream: u32,
    body: &[u8],
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
    flush(socket, connection);
}

pub(super) fn response_end(
    socket: &mut TcpStream,
    connection: &mut Connection,
    stream: u32,
    status: &str,
) {
    connection
        .send_headers(
            stream,
            vec![
                Header::new("grpc-status", status),
                Header::new("grpc-message", DIAGNOSTIC),
            ],
            true,
        )
        .unwrap();
    flush(socket, connection);
}

fn respond(
    socket: &mut TcpStream,
    connection: &mut Connection,
    stream: u32,
    body: &[u8],
    status: &str,
) {
    response_data(socket, connection, stream, body);
    response_end(socket, connection, stream, status);
}

// A PING sent after response DATA is acknowledged only after the actual native
// connection driver has processed that DATA. Trailers remain withheld, so a
// queue receipt cannot mistake protobuf receipt bytes for a successful RPC.
pub(super) fn data_was_consumed(socket: &mut TcpStream, connection: &mut Connection) {
    let nonce = *b"receipt!";
    let mut output = BytesMut::new();
    Frame::Ping(PingFrame::new(nonce))
        .encode(&mut output)
        .unwrap();
    socket.write_all(&output).unwrap();
    socket.flush().unwrap();
    let mut decoder = FrameCodec::new();
    let mut inbound = BytesMut::new();
    let mut frames = 0;
    loop {
        if let Some(frame) = decoder.decode(&mut inbound).unwrap() {
            frames += 1;
            assert!(frames <= 64, "bounded response witness");
            if matches!(&frame, Frame::Ping(ping) if ping.ack && ping.opaque_data == nonce) {
                return;
            }
            let _ = connection.process_frame(frame).unwrap();
            flush(socket, connection);
        } else {
            let mut buffer = [0; 1024];
            let count = socket.read(&mut buffer).unwrap();
            assert_ne!(count, 0, "native call ended before its final status");
            inbound.extend_from_slice(&buffer[..count]);
        }
    }
}

fn closed(socket: &mut TcpStream) {
    let mut bytes_left = 64 * 1024_usize;
    let mut buffer = [0; 1024];
    loop {
        match socket.read(&mut buffer) {
            Ok(0) => return,
            Ok(count) => {
                bytes_left = bytes_left
                    .checked_sub(count)
                    .expect("bounded residual H2 output")
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return;
            }
            Err(error) => panic!("native collector socket was not retired: {error}"),
        }
    }
}

pub(super) fn no_more_connections(listener: &TcpListener) {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        _ => panic!("completed or abandoned collection was replayed"),
    }
}

#[test]
fn receipt_waits_for_final_status_preserves_partial_success_and_retires_credit() {
    native(|cx| async move {
        let (listener, address) = listener();
        let queue = queue(address).await.with_retry_policy(
            OtlpGrpcRetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
                .unwrap()
                .with_jitter(false),
        );
        let mut receipt = queue
            .enqueue_encoded_with_receipt(OtlpGrpcSignal::Metrics, vec![body(1), body(2)])
            .unwrap();
        poll_fn(|task| {
            assert!(
                Pin::new(&mut receipt).poll(task).is_pending(),
                "admission is not acknowledgement"
            );
            Poll::Ready(())
        })
        .await;
        let retained = queue.queue_stats().queue.retained_bytes;
        let (arrived, mut arrival) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let (finished, finishing) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut first = accept(&listener);
            let (mut connection, captured) = read_request(&mut first);
            captured.assert_request(OtlpGrpcSignal::Metrics, &body(1));
            response_data(
                &mut first,
                &mut connection,
                captured.stream,
                &partial(2, DIAGNOSTIC),
            );
            data_was_consumed(&mut first, &mut connection);
            arrived.send_blocking(()).unwrap();
            released.recv_timeout(WATCHDOG).unwrap();
            response_end(&mut first, &mut connection, captured.stream, "0");
            let mut second = accept(&listener);
            let (mut connection, captured) = read_request(&mut second);
            captured.assert_request(OtlpGrpcSignal::Metrics, &body(2));
            respond(&mut second, &mut connection, captured.stream, &[], "0");
            finishing.recv_timeout(WATCHDOG).unwrap();
            no_more_connections(&listener);
        });
        let mut service = queue.spawn_queued(&cx).await.unwrap();
        service.begin_drain();
        arrival.recv(&cx).await.unwrap();
        poll_fn(|task| {
            assert!(
                Pin::new(&mut receipt).poll(task).is_pending(),
                "DATA alone cannot acknowledge unary export"
            );
            Poll::Ready(())
        })
        .await;
        let parked = queue.queue_stats().queue;
        assert_eq!(parked.retained_batches, 2);
        assert_eq!(parked.queued_batches, 1);
        assert_eq!(parked.retained_bytes, retained);
        assert_eq!(parked.delivered_batches, 0);
        release.send(()).unwrap();
        let report = receipt.await.unwrap();
        assert_eq!(report.responses().len(), 2);
        assert!(report.responses()[0].is_partial_success());
        assert_eq!(report.responses()[0].rejected_items(), 2);
        assert_eq!(report.responses()[0].error_message(), DIAGNOSTIC);
        assert_eq!(report.responses()[0].signal(), OtlpGrpcSignal::Metrics);
        assert!(!report.responses()[1].is_partial_success());
        assert!(!format!("{report:?}").contains(DIAGNOSTIC));
        let stats = queue.queue_stats();
        assert_eq!(
            stats.queue.retained_batches, 0,
            "receipt follows credit retirement"
        );
        assert_eq!(stats.queue.retained_bytes, 0);
        assert_eq!(stats.queue.delivered_batches, 2);
        assert_eq!(stats.queue.failed_batches, 0);
        assert_eq!(stats.partial_success_batches, 1);
        assert_eq!(stats.rejected_data_points, 2);
        let managed = service.join(&cx).await.unwrap();
        assert!(matches!(
            managed.delivery,
            Some(ManagedOtlpOutcome::Drained)
        ));
        assert!(managed.task.is_ok());
        assert_eq!(managed.queue, queue.queue_stats().queue);
        finished.send(()).unwrap();
        peer.join().unwrap();
    });
}

#[test]
fn later_failure_preserves_earlier_receipts_and_managed_exit_settles_backlog() {
    native(|cx| async move {
        let (listener, address) = listener();
        let queue = queue(address).await;
        let first = queue
            .enqueue_encoded_with_receipt(OtlpGrpcSignal::Traces, vec![body(1), body(2), body(3)])
            .unwrap();
        let backlog = queue
            .enqueue_encoded_with_receipt(OtlpGrpcSignal::Logs, vec![body(4), body(5)])
            .unwrap();
        let (finished, finishing) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Traces, &body(1));
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                &partial(3, DIAGNOSTIC),
                "0",
            );
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Traces, &body(2));
            respond(&mut socket, &mut connection, captured.stream, &[], "7");
            finishing.recv_timeout(WATCHDOG).unwrap();
            no_more_connections(&listener);
        });
        let mut service = queue.spawn_queued(&cx).await.unwrap();
        let error = first.await.expect_err("second collector call failed");
        assert_eq!(error.code(), "otlp.grpc.rpc");
        assert_eq!(error.grpc_code(), Some(Code::PermissionDenied));
        assert_eq!(error.completed_responses().len(), 1);
        assert_eq!(
            error.completed_responses()[0].signal(),
            OtlpGrpcSignal::Traces
        );
        assert_eq!(error.completed_responses()[0].rejected_items(), 3);
        assert_eq!(error.completed_responses()[0].error_message(), DIAGNOSTIC);
        assert!(!format!("{error} {error:?}").contains(DIAGNOSTIC));
        let abandoned = backlog.await.expect_err("unattempted backlog retired");
        assert_eq!(abandoned.code(), "otlp.queue.abandoned");
        assert_eq!(abandoned.grpc_code(), None);
        assert!(abandoned.completed_responses().is_empty());
        let managed = service.join(&cx).await.unwrap();
        assert!(matches!(
            managed.delivery,
            Some(ManagedOtlpOutcome::Failed(_))
        ));
        assert_eq!(managed.queue.delivered_batches, 1);
        assert_eq!(managed.queue.failed_batches, 4);
        assert_eq!(managed.queue.retained_batches, 0);
        assert_eq!(managed.queue.retained_bytes, 0);
        assert!(!managed.queue.consumer_active);
        assert_eq!(queue.queue_stats().rejected_spans, 3);
        assert!(
            queue
                .enqueue_encoded(OtlpGrpcSignal::Logs, body(6))
                .is_err()
        );
        finished.send(()).unwrap();
        peer.join().unwrap();
    });
}

#[test]
fn dropping_parked_receipt_does_not_cancel_or_abandon_accepted_work() {
    native(|cx| async move {
        let (listener, address) = listener();
        let queue = queue(address).await;
        let mut receipt = queue
            .enqueue_encoded_with_receipt(OtlpGrpcSignal::Logs, vec![body(1), body(2)])
            .unwrap();
        let (arrived, mut arrival) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let (finished, finishing) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Logs, &body(1));
            arrived.send_blocking(()).unwrap();
            released.recv_timeout(WATCHDOG).unwrap();
            respond(
                &mut socket,
                &mut connection,
                captured.stream,
                &partial(0, DIAGNOSTIC),
                "0",
            );
            let mut socket = accept(&listener);
            let (mut connection, captured) = read_request(&mut socket);
            captured.assert_request(OtlpGrpcSignal::Logs, &body(2));
            respond(&mut socket, &mut connection, captured.stream, &[], "0");
            finishing.recv_timeout(WATCHDOG).unwrap();
            no_more_connections(&listener);
        });
        let mut service = queue.spawn_queued(&cx).await.unwrap();
        service.begin_drain();
        arrival.recv(&cx).await.unwrap();
        poll_fn(|task| {
            assert!(Pin::new(&mut receipt).poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        let retained = queue.queue_stats();
        drop(receipt);
        assert_eq!(
            queue.queue_stats(),
            retained,
            "dropping observation does not retire payloads"
        );
        release.send(()).unwrap();
        let managed = service.join(&cx).await.unwrap();
        assert!(matches!(
            managed.delivery,
            Some(ManagedOtlpOutcome::Drained)
        ));
        assert_eq!(managed.queue.delivered_batches, 2);
        assert_eq!(managed.queue.failed_batches, 0);
        assert_eq!(managed.queue.retained_batches, 0);
        assert_eq!(managed.queue.retained_bytes, 0);
        assert_eq!(queue.queue_stats().partial_success_batches, 1);
        assert_eq!(queue.queue_stats().rejected_log_records, 0);
        finished.send(()).unwrap();
        peer.join().unwrap();
    });
}

#[test]
fn owner_cancel_or_abort_resolves_every_receipt_and_retires_parked_native_io() {
    for abort in [false, true] {
        native(move |cx| async move {
            let boundary = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let (listener, address) = listener();
            let queue = queue(address).await;
            let mut first = queue
                .enqueue_encoded_with_receipt(
                    OtlpGrpcSignal::Metrics,
                    vec![body(1), body(2), body(3)],
                )
                .unwrap();
            let mut backlog = queue
                .enqueue_encoded_with_receipt(OtlpGrpcSignal::Traces, vec![body(4), body(5)])
                .unwrap();
            let (arrived, mut arrival) = oneshot::channel();
            let (retired, mut retirement) = oneshot::channel();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let (_, captured) = read_request(&mut socket);
                captured.assert_request(OtlpGrpcSignal::Metrics, &body(1));
                arrived.send_blocking(()).unwrap();
                closed(&mut socket);
                no_more_connections(&listener);
                retired.send_blocking(()).unwrap();
            });
            let mut service = queue.spawn_queued(boundary.cx()).await.unwrap();
            arrival.recv(&cx).await.unwrap();
            poll_fn(|task| {
                assert!(Pin::new(&mut first).poll(task).is_pending());
                assert!(Pin::new(&mut backlog).poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            if abort {
                service.abort();
            } else {
                boundary
                    .cancel(CancelReason::user("stop receipt owner"))
                    .unwrap();
            }
            let error = first.await.expect_err("active collection interrupted");
            assert!(matches!(
                error.code(),
                "otlp.queue.abandoned" | "otlp.grpc.rpc" | "otlp.grpc.context"
            ));
            assert!(error.grpc_code().is_none_or(|code| code == Code::Cancelled));
            assert!(error.completed_responses().is_empty());
            let error = backlog.await.expect_err("managed backlog retired");
            assert_eq!(error.code(), "otlp.queue.abandoned");
            assert!(error.completed_responses().is_empty());
            let managed = service.join(&cx).await.unwrap();
            if abort {
                assert!(matches!(
                    managed.delivery,
                    Some(ManagedOtlpOutcome::Aborted)
                ));
            } else {
                assert!(matches!(
                    managed.delivery,
                    Some(ManagedOtlpOutcome::Cancelled(_))
                ));
            }
            assert_eq!(managed.queue.delivered_batches, 0);
            assert_eq!(managed.queue.failed_batches, 5);
            assert_eq!(managed.queue.retained_batches, 0);
            assert_eq!(managed.queue.retained_bytes, 0);
            assert!(!managed.queue.consumer_active);
            retirement.recv(&cx).await.unwrap();
            boundary.close().await.unwrap();
            peer.join().unwrap();
        });
    }
}

#[test]
fn receipt_admission_is_atomic_and_empty_collections_need_no_consumer_or_io() {
    native(|_cx| async move {
        let (listener, address) = listener();
        let channel = Channel::builder(format!("http://{address}"))
            .max_send_message_size(1)
            .connect()
            .await
            .unwrap();
        let queue = QueuedOtlpGrpcExporter::new(OtlpGrpcExporter::new(channel).unwrap());
        let empty = queue
            .enqueue_encoded_with_receipt(OtlpGrpcSignal::Metrics, Vec::new())
            .unwrap();
        assert!(empty.await.unwrap().responses().is_empty());
        assert_eq!(queue.queue_stats(), OtlpGrpcQueueStats::default());
        assert!(
            queue
                .enqueue_encoded_with_receipt(OtlpGrpcSignal::Metrics, vec![Vec::new(), vec![0; 2]])
                .is_err()
        );
        assert_eq!(
            queue.queue_stats(),
            OtlpGrpcQueueStats::default(),
            "no valid prefix was published"
        );
        for _ in 0..OTLP_EXPORT_QUEUE_MAX_BATCHES - 1 {
            queue
                .enqueue_encoded(OtlpGrpcSignal::Metrics, Vec::new())
                .unwrap();
        }
        let before = queue.queue_stats();
        assert!(
            queue
                .enqueue_encoded_with_receipt(OtlpGrpcSignal::Metrics, vec![Vec::new(), Vec::new()])
                .is_err()
        );
        assert_eq!(queue.queue_stats(), before);
        no_more_connections(&listener);
    });
}
