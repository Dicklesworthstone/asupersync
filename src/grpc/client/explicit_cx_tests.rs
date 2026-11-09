//! Explicit-context unary calls over real HTTP/2 sockets.
//! asupersync-5z2scg.2.6: the caller owns the runtime and transport policy.

use super::*;
use crate::channel::oneshot;
use crate::codec::Decoder as _;
use crate::cx::Cx;
use crate::runtime::{Runtime, RuntimeBuilder};
use crate::types::{Budget, CancelKind, TaskId};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::sync::mpsc;
use std::task::Waker;
use std::time::Instant;

const WATCHDOG: Duration = Duration::from_secs(10);
const PATH: &str = "/test.ExplicitContext/Unary";
type CallResult = Result<Response<Bytes>, Status>;

fn runtime(workers: usize) -> Runtime {
    if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .expect("explicit-context unary runtime")
}

async fn within<T>(cx: &Cx, future: impl Future<Output = T>) -> T {
    crate::time::timeout(cx.now(), WATCHDOG, future)
        .await
        .expect("explicit-context unary watchdog")
}

fn assert_send<F: Future + Send>(future: F) -> F {
    future
}

fn hostile_context() -> Cx {
    let cx = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(crate::types::Time::ZERO));
    cx.cancel_with(CancelKind::User, Some("unrelated ambient caller"));
    cx
}

fn poll_with_foreign<F: Future>(
    future: Pin<&mut F>,
    task: &mut Context<'_>,
    foreign: &Cx,
) -> Poll<F::Output> {
    let previous = Cx::current().map(|cx| cx.task_id());
    let ambient = foreign.clone().set_current_restricted();
    let result = future.poll(task);
    assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
    assert!(Cx::current().unwrap().is_cancel_requested());
    drop(ambient);
    assert_eq!(Cx::current().map(|cx| cx.task_id()), previous);
    result
}

struct ExpectOwner(TaskId);

impl ClientInterceptor for ExpectOwner {
    fn intercept(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        let current = Cx::current().expect("explicit owner during interceptor");
        assert_eq!(current.task_id(), self.0);
        assert!(!current.is_cancel_requested());
        assert!(request.metadata_mut().insert("x-explicit-owner", "present"));
        Ok(())
    }
}

#[derive(Debug)]
struct Observation {
    headers: Vec<Header>,
    body: Bytes,
}

enum Reply {
    Success,
    AwaitClose,
}

struct PeerStep {
    observed: oneshot::Receiver<Observation>,
    reply: mpsc::SyncSender<Reply>,
    closed: oneshot::Receiver<()>,
}

fn flush(socket: &mut TcpStream, connection: &mut Connection) {
    let mut bytes = BytesMut::new();
    while let Some(frame) = connection.next_frame() {
        frame.encode(&mut bytes).expect("peer frame encoding");
    }
    socket.write_all(&bytes).expect("peer frame write");
}

// Each step accepts one real connection and waits for an explicit reply gate.
// No serving task survives the test; every accept/read/control wait is bounded.
fn peer(listener: &TcpListener, count: usize) -> (Vec<PeerStep>, std::thread::JoinHandle<()>) {
    listener.set_nonblocking(true).unwrap();
    let listener = listener.try_clone().unwrap();
    let mut steps = Vec::new();
    let mut script = Vec::new();
    for _ in 0..count {
        let (seen, observed) = oneshot::channel();
        let (reply, command) = mpsc::sync_channel(1);
        let (retired, closed) = oneshot::channel();
        steps.push(PeerStep {
            observed,
            reply,
            closed,
        });
        script.push((seen, command, retired));
    }
    let task = std::thread::spawn(move || {
        for (seen, command, retired) in script {
            let until = Instant::now() + WATCHDOG;
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < until, "peer accept watchdog");
                        std::thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) => panic!("peer accept: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(WATCHDOG)).unwrap();
            socket.set_write_timeout(Some(WATCHDOG)).unwrap();
            let mut connection = Connection::server(crate::http::h2::Settings::server());
            connection.queue_initial_settings();
            flush(&mut socket, &mut connection);
            let mut preface = [0; 24];
            socket.read_exact(&mut preface).expect("HTTP/2 preface");
            assert_eq!(&preface, CLIENT_PREFACE);
            let mut decoder = FrameCodec::new();
            let mut incoming = BytesMut::new();
            let mut headers = Vec::new();
            let mut body = BytesMut::new();
            let stream = 'request: loop {
                let mut bytes = [0; 4096];
                let read = socket.read(&mut bytes).expect("peer request read");
                assert_ne!(read, 0, "caller closed before its request completed");
                incoming.extend_from_slice(&bytes[..read]);
                while let Some(frame) = decoder.decode(&mut incoming).expect("peer frame decode") {
                    match connection.process_frame(frame).expect("peer HTTP/2 state") {
                        Some(ReceivedFrame::Headers {
                            stream_id,
                            headers: received,
                            end_stream,
                        }) => {
                            headers.extend(received);
                            if end_stream {
                                break 'request stream_id;
                            }
                        }
                        Some(ReceivedFrame::Data {
                            stream_id,
                            data,
                            end_stream,
                        }) => {
                            body.extend_from_slice(&data);
                            if end_stream {
                                break 'request stream_id;
                            }
                        }
                        _ => {}
                    }
                }
                flush(&mut socket, &mut connection);
            };
            flush(&mut socket, &mut connection);
            seen.send_blocking(Observation {
                headers,
                body: body.freeze(),
            })
            .expect("controller receives the native request");
            if matches!(
                command.recv_timeout(WATCHDOG).expect("peer reply gate"),
                Reply::Success
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
                // A real zero-length unary message, not a trailers-only success.
                connection
                    .send_data(stream, Bytes::from_static(&[0; 5]), false)
                    .unwrap();
                connection
                    .send_headers(
                        stream,
                        vec![
                            Header::new("grpc-status", "0"),
                            Header::new("x-native-receipt", "complete"),
                        ],
                        true,
                    )
                    .unwrap();
                flush(&mut socket, &mut connection);
            }
            let mut scratch = [0; 4096];
            loop {
                match socket.read(&mut scratch) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
                    Err(error) => panic!("peer transport retirement: {error}"),
                }
            }
            retired
                .send_blocking(())
                .expect("controller observes transport retirement");
        }
    });
    (steps, task)
}

async fn channel(listener: &TcpListener, admission: bool) -> Channel {
    let mut builder = Channel::builder(format!("http://{}", listener.local_addr().unwrap()))
        .connect_timeout(WATCHDOG)
        .timeout(WATCHDOG)
        .max_send_message_size(1024)
        .max_recv_message_size(1024);
    if admission {
        builder = builder
            .unary_admission(UnaryAdmissionLimits::new(NonZeroUsize::new(1).unwrap(), 1).unwrap());
    }
    builder.connect().await.expect("native unary channel")
}

async fn parked_request<F: Future<Output = CallResult>>(
    mut call: Pin<&mut F>,
    step: &mut PeerStep,
    controller: &Cx,
    foreign: &Cx,
) -> Observation {
    let mut observed = std::pin::pin!(step.observed.recv(controller));
    within(
        controller,
        poll_fn(|task| {
            // The peer withholds the response. When its observation becomes Ready,
            // this same poll has witnessed the native RPC still Pending.
            assert!(poll_with_foreign(call.as_mut(), task, foreign).is_pending());
            observed.as_mut().poll(task)
        }),
    )
    .await
    .expect("peer witnessed request before the parked poll")
}

fn assert_request(observed: &Observation, payload: &[u8]) {
    assert!(
        observed
            .headers
            .iter()
            .any(|h| h.name == ":path" && h.value == PATH)
    );
    assert!(
        observed
            .headers
            .iter()
            .any(|h| h.name == "content-type" && h.value == "application/grpc")
    );
    assert_eq!(observed.body[0], 0);
    assert_eq!(
        usize::try_from(u32::from_be_bytes(observed.body[1..5].try_into().unwrap())).unwrap(),
        payload.len()
    );
    assert_eq!(&observed.body[5..], payload);
}

fn assert_response(response: Response<Bytes>) {
    assert!(response.get_ref().is_empty());
    assert!(matches!(response.metadata().get("x-native-receipt"),
        Some(MetadataValue::Ascii(value)) if value == "complete"));
}

#[test]
fn explicit_unary_without_ambient_context_is_send_and_uses_real_http2() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut steps, peer) = peer(&listener, 1);
        runtime.block_on(async {
            let controller = Cx::current().unwrap();
            let channel = channel(&listener, false).await;
            let (sent, mut result) = oneshot::channel();
            let client = std::thread::spawn(move || {
                assert!(Cx::current().is_none());
                let mut client =
                    GrpcClient::new(channel).with_interceptor(ExpectOwner(owner.task_id()));
                let mut call = std::pin::pin!(assert_send(client.unary_with_cx::<Bytes, Bytes>(
                    &owner,
                    PATH,
                    Request::new(Bytes::from_static(b"outside-runtime-thread")),
                )));
                let mut pending = 0;
                let outcome = futures_lite::future::block_on(poll_fn(|task| {
                    assert!(Cx::current().is_none());
                    let polled = call.as_mut().poll(task);
                    assert!(
                        Cx::current().is_none(),
                        "explicit context leaked across a poll"
                    );
                    if polled.is_pending() {
                        pending += 1;
                    }
                    polled
                }));
                assert!(
                    pending > 0,
                    "the real response gate required a suspended poll"
                );
                sent.send_blocking(outcome)
                    .expect("controller receives client result");
            });
            let observed = within(&controller, steps[0].observed.recv(&controller))
                .await
                .unwrap();
            assert_request(&observed, b"outside-runtime-thread");
            assert!(
                observed
                    .headers
                    .iter()
                    .any(|h| h.name == "x-explicit-owner" && h.value == "present")
            );
            steps[0].reply.send(Reply::Success).unwrap();
            assert_response(
                within(&controller, result.recv(&controller))
                    .await
                    .unwrap()
                    .unwrap(),
            );
            within(&controller, steps[0].closed.recv(&controller))
                .await
                .unwrap();
            client.join().expect("ambient-free client assertions");
        });
        peer.join().expect("native peer assertions");
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn explicit_unary_restores_hostile_ambient_context_after_pending_and_ready() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut steps, peer) = peer(&listener, 1);
        runtime.block_on(async {
            let controller = Cx::current().unwrap();
            let foreign = hostile_context();
            let mut client = GrpcClient::new(channel(&listener, false).await)
                .with_interceptor(ExpectOwner(owner.task_id()));
            let mut call = std::pin::pin!(assert_send(client.unary_with_cx::<Bytes, Bytes>(
                &owner,
                PATH,
                Request::new(Bytes::from_static(b"explicit-authority")),
            )));
            let observed =
                parked_request(call.as_mut(), &mut steps[0], &controller, &foreign).await;
            assert_request(&observed, b"explicit-authority");
            steps[0].reply.send(Reply::Success).unwrap();
            let response = within(
                &controller,
                poll_fn(|task| poll_with_foreign(call.as_mut(), task, &foreign)),
            )
            .await
            .unwrap();
            assert_response(response);
            assert!(!owner.is_cancel_requested());
            within(&controller, steps[0].closed.recv(&controller))
                .await
                .unwrap();
        });
        peer.join().expect("native peer assertions");
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn explicit_unary_cancellation_wakes_a_parked_native_call_and_retires_its_socket() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut steps, peer) = peer(&listener, 1);
        runtime.block_on(async {
            let controller = Cx::current().unwrap();
            let foreign = hostile_context();
            let mut client = GrpcClient::new(channel(&listener, false).await);
            let mut call = std::pin::pin!(client.unary_with_cx::<Bytes, Bytes>(
                &owner,
                PATH,
                Request::new(Bytes::from_static(b"cancel-after-request")),
            ));
            let observed =
                parked_request(call.as_mut(), &mut steps[0], &controller, &foreign).await;
            assert_request(&observed, b"cancel-after-request");
            steps[0].reply.send(Reply::AwaitClose).unwrap();
            owner.cancel_with(CancelKind::User, Some("explicit unary owner stopped"));
            let status = within(
                &controller,
                poll_fn(|task| poll_with_foreign(call.as_mut(), task, &foreign)),
            )
            .await
            .unwrap_err();
            assert_eq!(status.code(), Code::Cancelled);
            assert!(!controller.is_cancel_requested());
            within(&controller, steps[0].closed.recv(&controller))
                .await
                .unwrap();
        });
        peer.join().expect("cancelled transport retired");
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn explicit_unary_caller_deadline_bounds_the_wire_and_parked_response() {
    let runtime = runtime(2);
    let clock = runtime.request_cx_with_budget(Budget::INFINITE);
    let caller_timeout = Duration::from_secs(2);
    let owner = runtime
        .request_cx_with_budget(Budget::INFINITE.with_deadline(clock.now() + caller_timeout));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut steps, peer) = peer(&listener, 1);
    runtime.block_on(async {
        let controller = Cx::current().unwrap();
        let foreign = hostile_context();
        let mut client = GrpcClient::new(channel(&listener, false).await);
        let mut call = std::pin::pin!(client.unary_with_cx::<Bytes, Bytes>(
            &owner,
            PATH,
            Request::new(Bytes::from_static(b"caller-deadline")),
        ));
        let observed = parked_request(call.as_mut(), &mut steps[0], &controller, &foreign).await;
        assert_request(&observed, b"caller-deadline");
        let timeouts = observed
            .headers
            .iter()
            .filter(|h| h.name == "grpc-timeout")
            .collect::<Vec<_>>();
        assert_eq!(timeouts.len(), 1);
        let forwarded = crate::grpc::parse_grpc_timeout(&timeouts[0].value).unwrap();
        assert!(!forwarded.is_zero() && forwarded <= caller_timeout);
        steps[0].reply.send(Reply::AwaitClose).unwrap();
        let status = within(
            &controller,
            poll_fn(|task| poll_with_foreign(call.as_mut(), task, &foreign)),
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), Code::DeadlineExceeded);
        assert!(!controller.is_cancel_requested());
        within(&controller, steps[0].closed.recv(&controller))
            .await
            .unwrap();
    });
    peer.join().expect("deadline retired the native transport");
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn explicit_unary_preserves_shared_admission_and_cancelled_queue_capacity() {
    let runtime = runtime(2);
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let queued_owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut steps, peer) = peer(&listener, 2);
    runtime.block_on(async {
        let controller = Cx::current().unwrap();
        let foreign = hostile_context();
        let channel = channel(&listener, true).await;
        let mut first_client = GrpcClient::new(channel.clone());
        let mut first = std::pin::pin!(first_client.unary_with_cx::<Bytes, Bytes>(
            &owner,
            PATH,
            Request::new(Bytes::from_static(b"active")),
        ));
        parked_request(first.as_mut(), &mut steps[0], &controller, &foreign).await;
        {
            let mut client = GrpcClient::new(channel.clone());
            let mut queued = std::pin::pin!(client.unary_with_cx::<Bytes, Bytes>(
                &queued_owner,
                PATH,
                Request::new(Bytes::from_static(b"cancelled-before-dial")),
            ));
            poll_fn(|task| {
                assert!(poll_with_foreign(queued.as_mut(), task, &foreign).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
            queued_owner.cancel_with(CancelKind::User, Some("cancel queued explicit call"));
            let status = within(
                &controller,
                poll_fn(|task| poll_with_foreign(queued.as_mut(), task, &foreign)),
            )
            .await
            .unwrap_err();
            assert_eq!(status.code(), Code::Cancelled);
        }
        let mut successor_client = GrpcClient::new(channel);
        let mut successor = std::pin::pin!(successor_client.unary_with_cx::<Bytes, Bytes>(
            &controller,
            PATH,
            Request::new(Bytes::from_static(b"successor")),
        ));
        poll_fn(|task| {
            assert!(
                poll_with_foreign(successor.as_mut(), task, &foreign).is_pending(),
                "cancelled queue slot must admit the successor"
            );
            Poll::Ready(())
        })
        .await;
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        steps[0].reply.send(Reply::Success).unwrap();
        assert_response(
            within(
                &controller,
                poll_fn(|task| poll_with_foreign(first.as_mut(), task, &foreign)),
            )
            .await
            .unwrap(),
        );
        within(&controller, steps[0].closed.recv(&controller))
            .await
            .unwrap();
        let observed =
            parked_request(successor.as_mut(), &mut steps[1], &controller, &foreign).await;
        assert_request(&observed, b"successor");
        steps[1].reply.send(Reply::Success).unwrap();
        assert_response(
            within(
                &controller,
                poll_fn(|task| poll_with_foreign(successor.as_mut(), task, &foreign)),
            )
            .await
            .unwrap(),
        );
        within(&controller, steps[1].closed.recv(&controller))
            .await
            .unwrap();
    });
    peer.join()
        .expect("admission peer accepted exactly the committed calls");
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn explicit_unary_restores_ambient_context_when_an_interceptor_panics() {
    struct Panics(TaskId);
    impl ClientInterceptor for Panics {
        fn intercept(&self, _: &mut Request<Bytes>) -> Result<(), Status> {
            assert_eq!(Cx::current().unwrap().task_id(), self.0);
            assert!(!Cx::current().unwrap().is_cancel_requested());
            panic!("explicit unary interceptor panic");
        }
    }
    let owner = Cx::for_testing();
    let foreign = hostile_context();
    let channel = futures_lite::future::block_on(Channel::connect("http://127.0.0.1:9")).unwrap();
    let mut client = GrpcClient::new(channel).with_interceptor(Panics(owner.task_id()));
    let mut call = std::pin::pin!(client.unary_with_cx::<Bytes, Bytes>(
        &owner,
        PATH,
        Request::new(Bytes::new()),
    ));
    let previous = Cx::current().map(|cx| cx.task_id());
    let ambient = foreign.clone().set_current_restricted();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    }))
    .expect_err("interceptor panic must propagate");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"explicit unary interceptor panic")
    );
    assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
    drop(ambient);
    assert_eq!(Cx::current().map(|cx| cx.task_id()), previous);
}
