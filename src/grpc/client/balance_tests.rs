//! Endpoint balancing over native HTTP/2, including shared pools and the
//! boundaries where replay would duplicate an application-side effect.

use super::*;
use crate::bytes::{Bytes, BytesMut};
use crate::channel::oneshot;
use crate::codec::Decoder as _;
use crate::grpc::client::UnaryAdmissionLimits;
use crate::grpc::{Code, MetadataValue, NativeDuplexEvent};
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::runtime::{Runtime, RuntimeBuilder};
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, Time};
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);
const PATH: &str = "/test.Balanced/Echo";
type CallResult = Result<Response<Bytes>, Status>;

// Deliberately neither Clone nor Sync: each call receives one owned codec.
struct NonCloneCodec {
    encoded: Arc<AtomicUsize>,
    clock: Option<Arc<VirtualClock>>,
    encode_nanos: u64,
    decode_nanos: u64,
    _not_sync: std::cell::Cell<()>,
}

impl NonCloneCodec {
    fn new(encoded: Arc<AtomicUsize>) -> Self {
        Self {
            encoded,
            clock: None,
            encode_nanos: 0,
            decode_nanos: 0,
            _not_sync: std::cell::Cell::new(()),
        }
    }
}

impl Codec for NonCloneCodec {
    type Encode = Bytes;
    type Decode = Bytes;
    type Error = Infallible;

    fn encode(&mut self, item: &Bytes) -> Result<Bytes, Infallible> {
        self.encoded.fetch_add(1, Ordering::SeqCst);
        if let Some(clock) = &self.clock {
            clock.advance(self.encode_nanos);
        }
        Ok(item.clone())
    }

    fn decode(&mut self, bytes: &Bytes) -> Result<Bytes, Infallible> {
        if let Some(clock) = &self.clock {
            clock.advance(self.decode_nanos);
        }
        Ok(bytes.clone())
    }
}

struct Callback<F>(F);

impl<F> ClientInterceptor for Callback<F>
where
    F: Fn(&mut Request<Bytes>) -> Result<(), Status> + Send + Sync,
{
    fn intercept(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        (self.0)(request)
    }
}

fn runtime(workers: usize) -> Runtime {
    if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .expect("balanced native runtime")
}

fn timed_runtime(clock: &Arc<VirtualClock>) -> (Runtime, TimerDriverHandle) {
    let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(clock));
    let runtime = RuntimeBuilder::current_thread()
        .with_timer_driver(driver.clone())
        .build()
        .expect("balanced explicit-clock runtime");
    (runtime, driver)
}

async fn within<T>(_cx: &Cx, future: impl Future<Output = T>) -> T {
    // This watchdog has a separately driven wall clock. The call under test
    // may deliberately retain a frozen virtual clock or a cancelled Cx.
    let mut watchdog = pin!(crate::time::Sleep::with_wall_clock(
        crate::time::raw_wall_now() + WATCHDOG,
    ));
    let mut future = pin!(future);
    poll_fn(|task| {
        assert!(
            watchdog.as_mut().poll_deadline(task).is_pending(),
            "balanced native test watchdog"
        );
        future.as_mut().poll(task)
    })
    .await
}

fn assert_send<F: Future + Send>(future: F) -> F {
    future
}

fn assert_owned<T: Send + 'static>(value: T) -> T {
    value
}

async fn immediately<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    poll_fn(|task| match future.as_mut().poll(task) {
        Poll::Ready(value) => Poll::Ready(value),
        Poll::Pending => panic!("local refusal must finish before waiting for transport"),
    })
    .await
}

async fn channel(listener: &TcpListener, pool: usize, queue: Option<usize>) -> Channel {
    let mut builder = Channel::builder(format!("http://{}", listener.local_addr().unwrap()))
        .connect_timeout(WATCHDOG)
        .timeout(WATCHDOG)
        .max_recv_message_size(4096)
        .max_send_message_size(4096)
        .reuse_connections(pool);
    if let Some(queue) = queue {
        builder = builder.unary_admission(
            UnaryAdmissionLimits::new(NonZeroUsize::new(1).unwrap(), queue).unwrap(),
        );
    }
    builder.connect().await.expect("native endpoint channel")
}

#[derive(Debug)]
struct Observation {
    stream: u32,
    headers: Vec<Header>,
    body: Bytes,
}

impl Observation {
    fn payload(&self) -> &[u8] {
        assert_eq!(self.body[0], 0);
        let length = u32::from_be_bytes(self.body[1..5].try_into().unwrap());
        assert_eq!(usize::try_from(length).unwrap(), self.body.len() - 5);
        &self.body[5..]
    }

    fn timeout(&self) -> Duration {
        let mut timeouts = self
            .headers
            .iter()
            .filter(|header| header.name == "grpc-timeout");
        let timeout = crate::grpc::parse_grpc_timeout(&timeouts.next().unwrap().value).unwrap();
        assert!(timeouts.next().is_none(), "one timeout header per call");
        timeout
    }
}

enum Reply {
    Echo,
    Messages(Vec<Bytes>),
    Unavailable,
    Disconnect,
    AwaitClose,
}

struct PeerStep {
    observed: oneshot::Receiver<Observation>,
    reply: mpsc::SyncSender<Reply>,
}

fn flush(socket: &mut TcpStream, connection: &mut Connection) {
    let mut bytes = BytesMut::new();
    while let Some(frame) = connection.next_frame() {
        frame.encode(&mut bytes).expect("peer frame encoding");
    }
    socket.write_all(&bytes).expect("peer frame write");
}

fn wait_closed(socket: &mut TcpStream) {
    let mut bytes = [0; 4096];
    loop {
        match socket.read(&mut bytes) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            error => panic!("balanced call did not close its socket: {error:?}"),
        }
    }
}

// One real socket handles exactly `calls` sequential HTTP/2 streams. Keeping
// the socket open across gates lets tests distinguish reuse from redialing.
fn peer(
    listener: &TcpListener,
    calls: usize,
) -> (
    Vec<PeerStep>,
    oneshot::Receiver<()>,
    std::thread::JoinHandle<()>,
) {
    listener.set_nonblocking(true).unwrap();
    let listener = listener.try_clone().unwrap();
    let mut steps = Vec::new();
    let mut script = Vec::new();
    for _ in 0..calls {
        let (seen, observed) = oneshot::channel();
        let (reply, command) = mpsc::sync_channel(1);
        steps.push(PeerStep { observed, reply });
        script.push((seen, command));
    }
    let (retired, closed) = oneshot::channel();
    let task = std::thread::spawn(move || {
        let until = Instant::now() + WATCHDOG;
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < until, "balanced peer accept watchdog");
                    std::thread::park_timeout(Duration::from_millis(1));
                }
                error => panic!("balanced peer accept: {error:?}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(WATCHDOG)).unwrap();
        socket.set_write_timeout(Some(WATCHDOG)).unwrap();
        let mut connection = Connection::server(Settings::server());
        connection.queue_initial_settings();
        flush(&mut socket, &mut connection);
        let mut preface = [0; 24];
        socket
            .read_exact(&mut preface)
            .expect("native HTTP/2 preface");
        assert_eq!(&preface, CLIENT_PREFACE);
        let mut decoder = FrameCodec::new();
        let mut incoming = BytesMut::new();
        for (seen, command) in script {
            let mut headers = Vec::new();
            let mut body = BytesMut::new();
            let stream = 'request: loop {
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
                let mut bytes = [0; 4096];
                let read = socket.read(&mut bytes).expect("peer request read");
                assert_ne!(read, 0, "caller closed before its request completed");
                incoming.extend_from_slice(&bytes[..read]);
            };
            flush(&mut socket, &mut connection);
            let body = body.freeze();
            seen.send_blocking(Observation {
                stream,
                headers,
                body: body.clone(),
            })
            .expect("controller receives native request");
            let reply = command.recv_timeout(WATCHDOG).expect("peer reply gate");
            match reply {
                Reply::Disconnect => break,
                Reply::AwaitClose => {
                    wait_closed(&mut socket);
                    break;
                }
                _ => {}
            }
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
            let failed = matches!(reply, Reply::Unavailable);
            match reply {
                Reply::Echo => connection.send_data(stream, body, false).unwrap(),
                Reply::Messages(messages) => {
                    let mut encoded = BytesMut::new();
                    for message in messages {
                        encoded.extend_from_slice(&[0]);
                        encoded.extend_from_slice(
                            &u32::try_from(message.len()).unwrap().to_be_bytes(),
                        );
                        encoded.extend_from_slice(&message);
                    }
                    connection
                        .send_data(stream, encoded.freeze(), false)
                        .unwrap();
                }
                Reply::Unavailable => {}
                Reply::Disconnect | Reply::AwaitClose => unreachable!(),
            }
            connection
                .send_headers(
                    stream,
                    vec![
                        Header::new("grpc-status", if failed { "14" } else { "0" }),
                        Header::new("x-balanced-receipt", "complete"),
                    ],
                    true,
                )
                .unwrap();
            flush(&mut socket, &mut connection);
        }
        drop(socket);
        retired
            .send_blocking(())
            .expect("controller observes transport retirement");
    });
    (steps, closed, task)
}

fn assert_no_connection(listener: &TcpListener) {
    listener.set_nonblocking(true).unwrap();
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

async fn observe_pending<F: Future<Output = CallResult>>(
    mut call: Pin<&mut F>,
    step: &mut PeerStep,
    cx: &Cx,
) -> Observation {
    let mut observed = pin!(step.observed.recv(cx));
    within(
        cx,
        poll_fn(|task| {
            assert!(call.as_mut().poll(task).is_pending());
            observed.as_mut().poll(task)
        }),
    )
    .await
    .expect("peer observed the parked request")
}

#[test]
fn bounded_endpoint_set_shares_selection_and_availability() {
    futures_lite::future::block_on(async {
        assert_eq!(
            BalancedChannel::new(Vec::new()).unwrap_err().code(),
            Code::InvalidArgument
        );
        let first = Channel::connect("http://127.0.0.1:50051").await.unwrap();
        let second = Channel::connect("http://127.0.0.1:50052").await.unwrap();
        assert_eq!(
            BalancedChannel::new(vec![first.clone(); MAX_BALANCED_ENDPOINTS + 1])
                .unwrap_err()
                .code(),
            Code::InvalidArgument,
        );
        let loopback = Channel::connect("http://loopback:50051").await.unwrap();
        assert_eq!(
            BalancedChannel::new(vec![loopback]).unwrap_err().code(),
            Code::InvalidArgument
        );
        let set = BalancedChannel::new(vec![first, second]).unwrap();
        let clone = set.clone();
        assert_eq!(set.endpoints().len(), 2);
        assert_eq!(set.select().unwrap().uri(), "http://127.0.0.1:50051");
        assert_eq!(clone.select().unwrap().uri(), "http://127.0.0.1:50052");
        clone.set_available(0, false).unwrap();
        assert_eq!(set.is_available(0), Some(false));
        assert_eq!(set.select().unwrap().uri(), "http://127.0.0.1:50052");
        set.set_available(1, false).unwrap();
        assert_eq!(clone.select().unwrap_err().code(), Code::Unavailable);
        clone.set_available(0, true).unwrap();
        assert_eq!(set.select().unwrap().uri(), "http://127.0.0.1:50051");
        assert!(set.endpoint(2).is_none());
        assert_eq!(set.is_available(2), None);
        assert_eq!(
            set.set_available(usize::MAX, true).unwrap_err().code(),
            Code::InvalidArgument
        );
    });
}

#[test]
fn native_round_robin_clones_reuse_only_the_selected_endpoints_pool() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut a, mut a_closed, a_peer) = peer(&first, 2);
        let (mut b, mut b_closed, b_peer) = peer(&second, 2);
        runtime.block_on(Box::pin(async {
            let cx = Cx::current().unwrap();
            let set = BalancedChannel::new(vec![
                channel(&first, 1, Some(1)).await,
                channel(&second, 1, Some(1)).await,
            ])
            .unwrap();
            let factories = Arc::new(AtomicUsize::new(0));
            let encoded = Arc::new(AtomicUsize::new(0));
            let client = BalancedGrpcClient::with_codec_factory(set.clone(), {
                let factories = Arc::clone(&factories);
                let encoded = Arc::clone(&encoded);
                move || {
                    factories.fetch_add(1, Ordering::SeqCst);
                    NonCloneCodec::new(Arc::clone(&encoded))
                }
            });
            let clone = client.clone();
            for index in 0..2 {
                for (selected, steps, listener, payload) in [
                    (&client, &mut a, &first, &b"endpoint-a"[..]),
                    (&clone, &mut b, &second, &b"endpoint-b"[..]),
                ] {
                    steps[index].reply.send(Reply::Echo).unwrap();
                    let response = within(
                        &cx,
                        assert_send(selected.unary(
                            &cx,
                            PATH,
                            Request::new(Bytes::copy_from_slice(payload)),
                        )),
                    )
                    .await
                    .unwrap();
                    assert_eq!(response.get_ref().as_ref(), payload);
                    let observed = within(&cx, steps[index].observed.recv(&cx)).await.unwrap();
                    assert_eq!(observed.payload(), payload);
                    assert_eq!(observed.stream, if index == 0 { 1 } else { 3 });
                    let authority = listener.local_addr().unwrap().to_string();
                    assert!(
                        observed
                            .headers
                            .iter()
                            .any(|header| header.name == ":authority" && header.value == authority)
                    );
                    assert!(observed.timeout() <= WATCHDOG);
                }
            }
            assert_no_connection(&first);
            assert_no_connection(&second);
            assert_eq!(factories.load(Ordering::SeqCst), 4);
            assert_eq!(encoded.load(Ordering::SeqCst), 4);
            within(&cx, a_closed.recv(&cx)).await.unwrap();
            within(&cx, b_closed.recv(&cx)).await.unwrap();
        }));
        a_peer.join().unwrap();
        b_peer.join().unwrap();
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn a_delivered_failure_is_returned_without_replaying_the_rpc() {
    for disconnect in [false, true] {
        let runtime = runtime(1);
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut a, mut a_closed, a_peer) = peer(&first, 1);
        runtime.block_on(Box::pin(async {
            let cx = Cx::current().unwrap();
            let set = BalancedChannel::new(vec![
                channel(&first, 0, None).await,
                channel(&second, 0, None).await,
            ])
            .unwrap();
            let client = BalancedGrpcClient::new(set.clone());
            a[0].reply
                .send(if disconnect {
                    Reply::Disconnect
                } else {
                    Reply::Unavailable
                })
                .unwrap();
            let error = within(
                &cx,
                client.unary(
                    &cx,
                    PATH,
                    Request::new(Bytes::from_static(b"side-effect-already-delivered")),
                ),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), Code::Unavailable);
            let observed = within(&cx, a[0].observed.recv(&cx)).await.unwrap();
            assert_eq!(observed.payload(), b"side-effect-already-delivered");
            assert_no_connection(&second);
            assert_eq!(
                set.is_available(0),
                Some(true),
                "failures do not infer health"
            );
            assert_eq!(set.select().unwrap().uri(), set.endpoint(1).unwrap().uri());
            within(&cx, a_closed.recv(&cx)).await.unwrap();
        }));
        a_peer.join().unwrap();
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn disabled_cancelled_and_unauthorized_calls_do_not_run_the_factory() {
    let runtime = runtime(1);
    let cancelled = runtime.request_cx_with_budget(Budget::INFINITE);
    cancelled.cancel_with(CancelKind::User, Some("caller already stopped"));
    runtime.block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let set = BalancedChannel::new(vec![
            channel(&first, 0, None).await,
            channel(&second, 0, None).await,
        ])
        .unwrap();
        let invoked = Arc::new(AtomicUsize::new(0));
        let client = BalancedGrpcClient::with_codec_factory(set.clone(), {
            let invoked = Arc::clone(&invoked);
            move || {
                invoked.fetch_add(1, Ordering::SeqCst);
                IdentityCodec
            }
        });
        let no_io = Cx::for_testing();
        assert_eq!(
            immediately(client.unary(&no_io, PATH, Request::new(Bytes::new())))
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            immediately(client.unary(&cancelled, PATH, Request::new(Bytes::new())))
                .await
                .unwrap_err()
                .code(),
            Code::Cancelled
        );
        set.set_available(0, false).unwrap();
        set.set_available(1, false).unwrap();
        assert_eq!(
            immediately(client.unary(&cx, PATH, Request::new(Bytes::new())))
                .await
                .unwrap_err()
                .code(),
            Code::Unavailable
        );
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        set.set_available(0, true).unwrap();
        set.set_available(1, true).unwrap();
        assert_eq!(set.select().unwrap().uri(), set.endpoint(0).unwrap().uri());
        assert_no_connection(&first);
        assert_no_connection(&second);
    }));
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn endpoint_admission_deadline_and_cancellation_never_reroute() {
    for cancel in [false, true] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
        let (runtime, driver) = timed_runtime(&clock);
        let queued_owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut a, mut a_closed, a_peer) = peer(&first, 1);
        let (mut b, mut b_closed, b_peer) = peer(&second, 1);
        runtime.block_on(Box::pin(async {
            let cx = Cx::current().unwrap();
            let set = BalancedChannel::new(vec![
                channel(&first, 0, Some(1)).await,
                channel(&second, 0, Some(0)).await,
            ])
            .unwrap();
            set.set_available(1, false).unwrap();
            let client = BalancedGrpcClient::new(set.clone());
            let active = client.unary(&cx, PATH, Request::new(Bytes::from_static(b"occupy-a")));
            // Guard composition as well as execution on the default stack:
            // context/deadline wrappers must not embed native dial buffers.
            assert!(
                std::mem::size_of_val(&active) <= 16 * 1024,
                "balanced unary future grew to {} bytes",
                std::mem::size_of_val(&active),
            );
            let mut active = Box::pin(active);
            observe_pending(active.as_mut(), &mut a[0], &cx).await;

            let mut request = Request::new(Bytes::from_static(b"queued-only-at-a"));
            if !cancel {
                assert!(request.metadata_mut().insert("grpc-timeout", "50m"));
            }
            let mut queued = Box::pin(assert_send(client.unary(&queued_owner, PATH, request)));
            poll_fn(|task| {
                assert!(
                    queued.as_mut().poll(task).is_pending(),
                    "selected endpoint is occupied"
                );
                Poll::Ready(())
            })
            .await;
            // Availability changes apply to future selections. They do not
            // migrate the already parked call onto B when A is disabled.
            set.set_available(0, false).unwrap();
            set.set_available(1, true).unwrap();
            if cancel {
                queued_owner.cancel_with(CancelKind::User, Some("queued caller stopped"));
            } else {
                clock.advance(50_000_000);
                let _ = driver.process_timers();
            }
            let error = within(&cx, queued.as_mut()).await.unwrap_err();
            assert_eq!(
                error.code(),
                if cancel {
                    Code::Cancelled
                } else {
                    Code::DeadlineExceeded
                }
            );
            drop(queued);
            assert_no_connection(&first);
            assert_no_connection(&second);

            // B has its own admission capacity while A's original call is
            // still parked. The disabled A call remains usable until it ends.
            b[0].reply.send(Reply::Echo).unwrap();
            let response = within(
                &cx,
                client.unary(
                    &cx,
                    PATH,
                    Request::new(Bytes::from_static(b"independent-b")),
                ),
            )
            .await
            .unwrap();
            assert_eq!(response.get_ref().as_ref(), b"independent-b");
            assert_eq!(
                within(&cx, b[0].observed.recv(&cx))
                    .await
                    .unwrap()
                    .payload(),
                b"independent-b"
            );
            a[0].reply.send(Reply::Echo).unwrap();
            let response = within(&cx, active.as_mut()).await.unwrap();
            assert_eq!(response.get_ref().as_ref(), b"occupy-a");
            within(&cx, a_closed.recv(&cx)).await.unwrap();
            within(&cx, b_closed.recv(&cx)).await.unwrap();
        }));
        a_peer.join().unwrap();
        b_peer.join().unwrap();
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn one_absolute_deadline_charges_factory_interceptors_and_encoding() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
    let (runtime, _) = timed_runtime(&clock);
    let owner =
        runtime.request_cx_with_budget(Budget::INFINITE.with_deadline(Time::from_secs(108)));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut steps, mut closed, peer) = peer(&listener, 1);
    runtime.block_on(Box::pin(async {
        let controller = Cx::current().unwrap();
        let encoded = Arc::new(AtomicUsize::new(0));
        let owner_task = owner.task_id();
        let client = BalancedGrpcClient::with_codec_factory(
            BalancedChannel::new(vec![channel(&listener, 0, None).await]).unwrap(),
            {
                let clock = Arc::clone(&clock);
                let encoded = Arc::clone(&encoded);
                move || {
                    assert_eq!(Cx::current().unwrap().task_id(), owner_task);
                    clock.advance(2_000_000_000);
                    let mut codec = NonCloneCodec::new(Arc::clone(&encoded));
                    codec.clock = Some(Arc::clone(&clock));
                    codec.encode_nanos = 1_000_000_000;
                    codec
                }
            },
        )
        .with_interceptor(Callback({
            let clock = Arc::clone(&clock);
            move |request: &mut Request<Bytes>| {
                assert_eq!(Cx::current().unwrap().task_id(), owner_task);
                clock.advance(3_000_000_000);
                assert!(request.metadata_mut().insert("x-explicit-owner", "yes"));
                Ok(())
            }
        }));
        let mut request = Request::new(Bytes::from_static(b"deadline-includes-user-work"));
        assert!(request.metadata_mut().insert("grpc-timeout", "30S"));
        steps[0].reply.send(Reply::Echo).unwrap();
        let response = within(
            &controller,
            assert_send(client.unary(&owner, PATH, request)),
        )
        .await
        .unwrap();
        assert_eq!(response.get_ref().as_ref(), b"deadline-includes-user-work");
        let observed = within(&controller, steps[0].observed.recv(&controller))
            .await
            .unwrap();
        // min(request 30 s, channel 10 s, caller 8 s) - factory 2 s
        // - interceptor 3 s - encoder 1 s = exactly two seconds on the wire.
        assert_eq!(observed.timeout(), Duration::from_secs(2));
        assert!(
            observed
                .headers
                .iter()
                .any(|header| header.name == "x-explicit-owner" && header.value == "yes")
        );
        assert_eq!(encoded.load(Ordering::SeqCst), 1);
        within(&controller, closed.recv(&controller)).await.unwrap();
    }));
    peer.join().unwrap();
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn expired_or_cancelled_callbacks_stop_before_more_user_work_or_dialing() {
    // Expiration in factory, first interceptor, encoder; then cancellation
    // inside the first interceptor. Every case retains the selected endpoint.
    for stage in 0..4 {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
        let (runtime, _) = timed_runtime(&clock);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        runtime.block_on(Box::pin(async {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let second = TcpListener::bind("127.0.0.1:0").unwrap();
            let encoded = Arc::new(AtomicUsize::new(0));
            let later = Arc::new(AtomicUsize::new(0));
            let set = BalancedChannel::new(vec![
                channel(&listener, 0, None).await,
                channel(&second, 0, None).await,
            ])
            .unwrap();
            let client = BalancedGrpcClient::with_codec_factory(set.clone(), {
                let clock = Arc::clone(&clock);
                let encoded = Arc::clone(&encoded);
                move || {
                    if stage == 0 {
                        clock.advance(11_000_000_000);
                    }
                    let mut codec = NonCloneCodec::new(Arc::clone(&encoded));
                    codec.clock = Some(Arc::clone(&clock));
                    if stage == 2 {
                        codec.encode_nanos = 11_000_000_000;
                    }
                    codec
                }
            })
            .with_interceptor(Callback({
                let clock = Arc::clone(&clock);
                let owner = owner.clone();
                move |_: &mut Request<Bytes>| {
                    if stage == 1 {
                        clock.advance(11_000_000_000);
                    }
                    if stage == 3 {
                        owner.cancel_with(CancelKind::User, Some("interceptor stopped"));
                    }
                    Ok(())
                }
            }))
            .with_interceptor(Callback({
                let later = Arc::clone(&later);
                move |_: &mut Request<Bytes>| {
                    later.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }));
            let status = immediately(client.unary(&owner, PATH, Request::new(Bytes::new())))
                .await
                .unwrap_err();
            assert_eq!(
                status.code(),
                if stage == 3 {
                    Code::Cancelled
                } else {
                    Code::DeadlineExceeded
                }
            );
            assert_eq!(encoded.load(Ordering::SeqCst), usize::from(stage == 2));
            assert_eq!(later.load(Ordering::SeqCst), usize::from(stage == 2));
            assert_eq!(set.select().unwrap().uri(), set.endpoint(1).unwrap().uri());
            assert_no_connection(&listener);
            assert_no_connection(&second);
        }));
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[test]
fn interceptor_tightening_survives_later_header_removal() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
    let (runtime, _) = timed_runtime(&clock);
    runtime.block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let encoded = Arc::new(AtomicUsize::new(0));
        let client = BalancedGrpcClient::with_codec_factory(
            BalancedChannel::new(vec![channel(&listener, 0, None).await]).unwrap(),
            {
                let encoded = Arc::clone(&encoded);
                move || NonCloneCodec::new(Arc::clone(&encoded))
            },
        )
        .with_interceptor(Callback(|request: &mut Request<Bytes>| {
            assert!(
                request
                    .metadata_mut()
                    .insert_or_replace("grpc-timeout", "1S")
            );
            Ok(())
        }))
        .with_interceptor(Callback({
            let clock = Arc::clone(&clock);
            move |request: &mut Request<Bytes>| {
                request.metadata_mut().remove("grpc-timeout");
                clock.advance(500_000_000);
                Ok(())
            }
        }))
        .with_interceptor(Callback({
            let clock = Arc::clone(&clock);
            move |_: &mut Request<Bytes>| {
                clock.advance(600_000_000);
                Ok(())
            }
        }));
        let status = immediately(client.unary(&cx, PATH, Request::new(Bytes::new())))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::DeadlineExceeded);
        assert_eq!(encoded.load(Ordering::SeqCst), 0);
        assert_no_connection(&listener);
    }));
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn response_decoding_cannot_complete_after_the_original_deadline() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
    let (runtime, _) = timed_runtime(&clock);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut steps, mut closed, peer) = peer(&listener, 1);
    runtime.block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let client = BalancedGrpcClient::with_codec_factory(
            BalancedChannel::new(vec![channel(&listener, 0, None).await]).unwrap(),
            {
                let clock = Arc::clone(&clock);
                move || {
                    let mut codec = NonCloneCodec::new(Arc::new(AtomicUsize::new(0)));
                    codec.clock = Some(Arc::clone(&clock));
                    codec.decode_nanos = 11_000_000_000;
                    codec
                }
            },
        );
        steps[0].reply.send(Reply::Echo).unwrap();
        let status = within(
            &cx,
            client.unary(&cx, PATH, Request::new(Bytes::from_static(b"late-decoder"))),
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), Code::DeadlineExceeded);
        assert_eq!(
            within(&cx, steps[0].observed.recv(&cx))
                .await
                .unwrap()
                .payload(),
            b"late-decoder"
        );
        within(&cx, closed.recv(&cx)).await.unwrap();
    }));
    peer.join().unwrap();
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

fn poll_under_foreign<F: Future>(
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

#[test]
fn pending_unary_keeps_explicit_context_and_cancels_without_endpoint_reselection() {
    let runtime = runtime(2);
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut steps, mut closed, peer) = peer(&listener, 1);
    runtime.block_on(Box::pin(async {
        let controller = Cx::current().unwrap();
        let foreign = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::ZERO));
        foreign.cancel_with(CancelKind::User, Some("unrelated polling task"));
        let set = BalancedChannel::new(vec![
            channel(&listener, 0, Some(1)).await,
            channel(&second, 0, Some(1)).await,
        ])
        .unwrap();
        let owner_task = owner.task_id();
        let client = BalancedGrpcClient::with_codec_factory(set.clone(), move || {
            assert_eq!(Cx::current().unwrap().task_id(), owner_task);
            IdentityCodec
        })
        .with_interceptor(Callback(move |_: &mut Request<Bytes>| {
            assert_eq!(Cx::current().unwrap().task_id(), owner_task);
            assert!(!Cx::current().unwrap().is_cancel_requested());
            Ok(())
        }));
        let mut call = Box::pin(assert_send(client.unary(
            &owner,
            PATH,
            Request::new(Bytes::from_static(b"owned-even-under-foreign-polls")),
        )));
        let mut observed = Box::pin(steps[0].observed.recv(&controller));
        let observation = within(
            &controller,
            poll_fn(|task| {
                assert!(poll_under_foreign(call.as_mut(), task, &foreign).is_pending());
                observed.as_mut().poll(task)
            }),
        )
        .await
        .unwrap();
        drop(observed);
        assert_eq!(observation.payload(), b"owned-even-under-foreign-polls");
        assert!(!owner.is_cancel_requested());
        steps[0].reply.send(Reply::AwaitClose).unwrap();
        owner.cancel_with(CancelKind::User, Some("explicit owner stopped its call"));
        let status = within(
            &controller,
            poll_fn(|task| poll_under_foreign(call.as_mut(), task, &foreign)),
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), Code::Cancelled);
        drop(call);
        within(&controller, closed.recv(&controller)).await.unwrap();
        assert_no_connection(&second);
        assert_eq!(set.select().unwrap().uri(), set.endpoint(1).unwrap().uri());
    }));
    peer.join().unwrap();
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn owned_streams_outlive_client_borrows_and_keep_their_selected_endpoints() {
    let runtime = runtime(1);
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut a, mut a_closed, a_peer) = peer(&first, 1);
    let (mut b, mut b_closed, b_peer) = peer(&second, 1);
    runtime.block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let set = BalancedChannel::new(vec![
            channel(&first, 1, Some(0)).await,
            channel(&second, 1, Some(0)).await,
        ])
        .unwrap();
        a[0].reply
            .send(Reply::Messages(vec![
                Bytes::from_static(b"watch-one"),
                Bytes::from_static(b"watch-two"),
            ]))
            .unwrap();
        b[0].reply
            .send(Reply::Messages(vec![
                Bytes::from_static(b"upload-one"),
                Bytes::from_static(b"upload-two"),
            ]))
            .unwrap();
        let (mut responses, mut duplex) = {
            let client = BalancedGrpcClient::new(set.clone());
            let owner = cx.clone();
            let path = PATH.to_string();
            let responses = within(
                &cx,
                assert_send(client.server_streaming(
                    &owner,
                    &path,
                    Request::new(Bytes::from_static(b"watch-a")),
                )),
            )
            .await
            .unwrap();
            let duplex = within(
                &cx,
                assert_send(client.duplex(&owner, &path, Request::new(()))),
            )
            .await
            .unwrap();
            // These assertions enforce independent owned returns, including
            // no captured lifetime of client, owner or the path String.
            (assert_owned(responses), assert_owned(duplex))
        };
        set.set_available(0, false).unwrap();
        set.set_available(1, false).unwrap();
        assert_eq!(
            within(&cx, responses.message())
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            b"watch-one"
        );
        assert_eq!(
            within(&cx, responses.message())
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            b"watch-two"
        );
        assert!(within(&cx, responses.message()).await.unwrap().is_none());
        assert!(
            matches!(responses.trailers().unwrap().get("x-balanced-receipt"),
            Some(MetadataValue::Ascii(value)) if value == "complete")
        );

        let mut sent = false;
        let mut half_closed = false;
        let mut replies = Vec::new();
        while let Some(event) = within(&cx, duplex.next_event()).await.unwrap() {
            match event {
                NativeDuplexEvent::RequestFlushed if !sent => {
                    duplex
                        .queue_message(&Bytes::from_static(b"upload-b"))
                        .unwrap();
                    sent = true;
                }
                NativeDuplexEvent::RequestFlushed if !half_closed => {
                    duplex.close_requests().unwrap();
                    half_closed = true;
                }
                NativeDuplexEvent::Message(message) => replies.push(message),
                NativeDuplexEvent::RequestFlushed => {}
            }
        }
        assert!(sent && half_closed);
        assert_eq!(
            replies,
            vec![
                Bytes::from_static(b"upload-one"),
                Bytes::from_static(b"upload-two")
            ]
        );
        assert!(
            matches!(duplex.trailers().unwrap().get("x-balanced-receipt"),
            Some(MetadataValue::Ascii(value)) if value == "complete")
        );
        assert_eq!(
            within(&cx, a[0].observed.recv(&cx))
                .await
                .unwrap()
                .payload(),
            b"watch-a"
        );
        assert_eq!(
            within(&cx, b[0].observed.recv(&cx))
                .await
                .unwrap()
                .payload(),
            b"upload-b"
        );
        within(&cx, a_closed.recv(&cx)).await.unwrap();
        within(&cx, b_closed.recv(&cx)).await.unwrap();
    }));
    a_peer.join().unwrap();
    b_peer.join().unwrap();
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn returned_stream_keeps_the_deadline_captured_before_its_codec_factory() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
    let (runtime, driver) = timed_runtime(&clock);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut steps, mut closed, peer) = peer(&listener, 1);
    runtime.block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        steps[0].reply.send(Reply::AwaitClose).unwrap();
        let mut responses = {
            let client = BalancedGrpcClient::with_codec_factory(
                BalancedChannel::new(vec![channel(&listener, 0, None).await]).unwrap(),
                {
                    let clock = Arc::clone(&clock);
                    move || {
                        clock.advance(4_000_000_000);
                        IdentityCodec
                    }
                },
            );
            assert_owned(
                within(
                    &cx,
                    client.server_streaming(
                        &cx,
                        PATH,
                        Request::new(Bytes::from_static(b"keep-original-deadline")),
                    ),
                )
                .await
                .unwrap(),
            )
        };
        let observation = within(&cx, steps[0].observed.recv(&cx)).await.unwrap();
        assert_eq!(observation.timeout(), Duration::from_secs(6));
        let mut message = Box::pin(responses.message());
        poll_fn(|task| {
            assert!(message.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        clock.advance(6_000_000_000);
        let _ = driver.process_timers();
        let error = within(&cx, message.as_mut()).await.unwrap_err();
        assert_eq!(error.code(), Code::DeadlineExceeded);
        drop(message);
        within(&cx, closed.recv(&cx)).await.unwrap();
    }));
    peer.join().unwrap();
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

// A pooled attempt can deliver a complete non-idempotent RPC before the
// transport reports a flush error. Exercise the public clients and their
// actual retry loop with a fault at that boundary, not a stand-alone status
// classifier. Explicit HTTP/2 non-processing signals must still permit retry.
mod pooled_replay {
    use super::*;
    use crate::codec::Decoder as _;
    use crate::grpc::client::{NativeH2Conn, NativeH2Io, NativeH2TestIo, lock_unpoisoned};
    use crate::http::h2::ErrorCode;
    use crate::http::h2::frame::{Frame, GoAwayFrame, RstStreamFrame, Setting, SettingsFrame};
    use crate::io::{AsyncRead, AsyncWrite};
    use std::sync::Mutex;

    const FLUSH_ERROR: &str = "complete unary request accepted before flush failure";
    const PAYLOAD: &[u8] = b"apply non-idempotent operation once";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Attempt {
        FlushFailure,
        LocalRefusal,
        RefusedStream,
        GoAwayBeforeStream,
        GoAwayIncludingStream,
    }

    #[derive(Debug, Default)]
    struct Evidence {
        wire: Vec<u8>,
        flush_failures: usize,
        drops: usize,
    }

    #[derive(Debug)]
    struct AttemptIo {
        attempt: Attempt,
        reply: BytesMut,
        evidence: Arc<Mutex<Evidence>>,
    }

    impl NativeH2TestIo for AttemptIo {}

    impl AsyncRead for AttemptIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _task: &mut Context<'_>,
            buffer: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            // refresh() must see an idle connection; the scripted signal is
            // observable only after this RPC's request was actually accepted.
            if self.reply.is_empty() || lock_unpoisoned(&self.evidence).wire.is_empty() {
                return Poll::Pending;
            }
            let length = buffer.remaining().min(self.reply.len());
            buffer.put_slice(&self.reply.split_to(length));
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AttemptIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _task: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            lock_unpoisoned(&self.evidence).wire.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            if self.attempt == Attempt::FlushFailure {
                let mut evidence = lock_unpoisoned(&self.evidence);
                // Prove the complete RPC reached the transport before its
                // failure: HEADERS, the full framed message, and END_STREAM.
                let requests = decode_requests(&evidence.wire);
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].payload(), PAYLOAD);
                evidence.flush_failures += 1;
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    FLUSH_ERROR,
                )));
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _task: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Drop for AttemptIo {
        fn drop(&mut self) {
            lock_unpoisoned(&self.evidence).drops += 1;
        }
    }

    fn decode_requests(wire: &[u8]) -> Vec<Observation> {
        let mut connection = Connection::server(Settings::server());
        // The injected connection is already established and pooled.
        connection
            .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .unwrap();
        let mut decoder = FrameCodec::new();
        let mut input = BytesMut::from(wire);
        let mut requests = Vec::new();
        let mut headers = Vec::new();
        let mut body = BytesMut::new();
        while let Some(frame) = decoder.decode(&mut input).unwrap() {
            let (stream, ended) = match connection.process_frame(frame).unwrap() {
                Some(ReceivedFrame::Headers {
                    stream_id,
                    headers: received,
                    end_stream,
                }) => {
                    headers.extend(received);
                    (stream_id, end_stream)
                }
                Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                }) => {
                    body.extend_from_slice(&data);
                    (stream_id, end_stream)
                }
                _ => continue,
            };
            if ended {
                requests.push(Observation {
                    stream,
                    headers: std::mem::take(&mut headers),
                    body: std::mem::take(&mut body).freeze(),
                });
            }
        }
        assert!(input.is_empty(), "no partial frame may count as delivery");
        assert!(body.is_empty(), "no partial message may count as delivery");
        assert!(headers.is_empty(), "no partial request may count as delivery");
        requests
    }

    fn seed(channel: &Channel, attempt: Attempt) -> Arc<Mutex<Evidence>> {
        let mut connection = Connection::client(crate::http::h2::SettingsBuilder::client().build());
        let settings = if attempt == Attempt::LocalRefusal {
            vec![Setting::MaxConcurrentStreams(0)]
        } else {
            Vec::new()
        };
        connection
            .process_frame(Frame::Settings(SettingsFrame::new(settings)))
            .unwrap();
        while connection.next_frame().is_some() {}
        let mut reply = BytesMut::new();
        let frame = match attempt {
            Attempt::RefusedStream => Some(Frame::RstStream(RstStreamFrame::new(
                1,
                ErrorCode::RefusedStream,
            ))),
            Attempt::GoAwayBeforeStream => {
                Some(Frame::GoAway(GoAwayFrame::new(0, ErrorCode::NoError)))
            }
            Attempt::GoAwayIncludingStream => {
                Some(Frame::GoAway(GoAwayFrame::new(1, ErrorCode::InternalError)))
            }
            Attempt::FlushFailure | Attempt::LocalRefusal => None,
        };
        if let Some(frame) = frame {
            frame.encode(&mut reply).unwrap();
        }
        let evidence = Arc::new(Mutex::new(Evidence::default()));
        channel.unary_pool.as_ref().unwrap().put(
            NativeH2Conn {
                io: NativeH2Io::Injected(Box::new(AttemptIo {
                    attempt,
                    reply,
                    evidence: Arc::clone(&evidence),
                })),
                connection,
                codec: FrameCodec::new(),
                inbound: BytesMut::new(),
                idle_since: crate::grpc::client::native_now(),
            },
            crate::grpc::client::native_now(),
        );
        evidence
    }

    #[test]
    fn native_unary_never_replays_ambiguous_dispatch() {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(Box::pin(async {
                for balanced in [false, true] {
                    for attempt in [Attempt::FlushFailure, Attempt::GoAwayIncludingStream] {
                        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                        let channel = channel(&listener, 1, None).await;
                        let evidence = seed(&channel, attempt);
                        let cx = Cx::current().unwrap();
                        let result = if balanced {
                            let client = BalancedGrpcClient::new(
                                BalancedChannel::new(vec![channel.clone()]).unwrap(),
                            );
                            immediately(client.unary(
                                &cx,
                                PATH,
                                Request::new(Bytes::from_static(PAYLOAD)),
                            ))
                            .await
                        } else {
                            let mut client = GrpcClient::new(channel.clone());
                            immediately(client.unary::<Bytes, Bytes>(
                                PATH,
                                Request::new(Bytes::from_static(PAYLOAD)),
                            ))
                            .await
                        };
                        let status = result.expect_err("ambiguous delivery must not be replayed");
                        assert_eq!(status.code(), Code::Unavailable);
                        if attempt == Attempt::FlushFailure {
                            assert!(status.message().contains(FLUSH_ERROR), "{status}");
                        }
                        let evidence = lock_unpoisoned(&evidence);
                        let requests = decode_requests(&evidence.wire);
                        assert_eq!(requests.len(), 1);
                        assert_eq!(requests[0].payload(), PAYLOAD);
                        assert_eq!(
                            evidence.flush_failures,
                            usize::from(attempt == Attempt::FlushFailure),
                        );
                        assert_eq!(evidence.drops, 1, "the failed transport was retired");
                        assert!(
                            lock_unpoisoned(&channel.unary_pool.as_ref().unwrap().idle).is_empty()
                        );
                        assert_no_connection(&listener);
                    }
                }
            }));
            assert!(runtime.shutdown_timeout(WATCHDOG));
        }
    }

    #[test]
    fn native_unary_retries_only_explicitly_unprocessed_attempts() {
        for attempt in [
            Attempt::LocalRefusal,
            Attempt::RefusedStream,
            Attempt::GoAwayBeforeStream,
        ] {
            let runtime = runtime(2);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let (mut steps, mut closed, peer_task) = peer(&listener, 1);
            runtime.block_on(Box::pin(async {
                let cx = Cx::current().unwrap();
                let channel = channel(&listener, 1, None).await;
                let evidence = seed(&channel, attempt);
                steps[0].reply.send(Reply::Echo).unwrap();
                let mut client = GrpcClient::new(channel.clone());
                let response = within(
                    &cx,
                    client.unary::<Bytes, Bytes>(
                        PATH,
                        Request::new(Bytes::from_static(PAYLOAD)),
                    ),
                )
                .await
                .expect("a proven unprocessed call may retry on one fresh connection");
                assert_eq!(response.get_ref().as_ref(), PAYLOAD);
                let request = within(&cx, steps[0].observed.recv(&cx)).await.unwrap();
                assert_eq!(request.payload(), PAYLOAD);
                assert_eq!(request.stream, 1, "the retry used a fresh connection");
                {
                    let evidence = lock_unpoisoned(&evidence);
                    let requests = decode_requests(&evidence.wire);
                    assert_eq!(
                        requests.len(),
                        usize::from(attempt != Attempt::LocalRefusal),
                    );
                    if attempt == Attempt::LocalRefusal {
                        assert!(evidence.wire.is_empty(), "local refusal must not dispatch bytes");
                    } else {
                        assert_eq!(requests[0].payload(), PAYLOAD);
                    }
                    assert_eq!(evidence.flush_failures, 0);
                    assert_eq!(evidence.drops, 1);
                }
                drop(client);
                drop(channel);
                within(&cx, closed.recv(&cx)).await.unwrap();
                assert_no_connection(&listener);
            }));
            peer_task.join().unwrap();
            assert!(runtime.shutdown_timeout(WATCHDOG));
        }
    }
}
