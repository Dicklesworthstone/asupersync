//! Native unary admission regressions. The peer withholds real HTTP/2
//! responses; queue witnesses are emitted only after the RPC returned Pending.

use super::*;
use crate::bytes::{Bytes, BytesMut};
use crate::channel::oneshot;
use crate::codec::Decoder as _;
use crate::grpc::client::{Channel, GrpcClient, encode_grpc_timeout, native_now};
use crate::grpc::{Code, Request, Response};
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::runtime::{RuntimeBuilder, TaskHandle};
use crate::types::CancelKind;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Wake, Waker};
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);
type CallResult = Result<Response<Bytes>, Status>;

async fn within<T>(future: impl Future<Output = T>) -> T {
    crate::time::timeout(native_now(), WATCHDOG, future)
        .await
        .expect("native unary admission watchdog elapsed")
}

fn run_native<F, Fut>(workers: usize, test: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .expect("native unary admission runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("runtime context");
        within(test(cx)).await;
    });
    assert!(runtime.shutdown_timeout(WATCHDOG), "runtime drains");
}

fn limits(active: usize, queued: usize) -> UnaryAdmissionLimits {
    UnaryAdmissionLimits::new(NonZeroUsize::new(active).unwrap(), queued).unwrap()
}

async fn channel(listener: &TcpListener, queued: usize, reuse: usize) -> Channel {
    Channel::builder(format!("http://{}", listener.local_addr().unwrap()))
        .connect_timeout(WATCHDOG)
        .timeout(WATCHDOG)
        .unary_admission(limits(1, queued))
        .reuse_connections(reuse)
        .connect()
        .await
        .expect("bounded channel")
}

async fn call(channel: Channel, body: &'static [u8], timeout: Option<Duration>) -> CallResult {
    let mut request = Request::new(Bytes::from_static(body));
    if let Some(timeout) = timeout {
        assert!(request
            .metadata_mut()
            .insert("grpc-timeout", encode_grpc_timeout(timeout)));
    }
    GrpcClient::new(channel)
        .unary("/test.Admission/Echo", request)
        .await
}

fn pressure(channel: &Channel) -> (usize, usize, usize) {
    let admission = channel.unary_admission.as_ref().expect("admission enabled");
    let active = admission.active.telemetry_snapshot(1);
    let total = admission.total.telemetry_snapshot(2);
    (active.occupied_units, active.waiter_count, total.available_units)
}

fn registrations(cx: &Cx) -> usize {
    cx.inner.read().cancel_waker_registrations.len()
}

fn assert_no_extra_connection(listener: &TcpListener) {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("a queued/rejected call opened an extra TCP connection: {other:?}"),
    }
}

#[derive(Debug)]
struct Observation {
    body: Bytes,
    timeout: Option<Duration>,
    socket: TcpStream,
}

struct PeerStep {
    observed: oneshot::Receiver<Observation>,
    reply: mpsc::SyncSender<Reply>,
}

#[derive(Clone, Copy)]
enum Reply {
    Echo,
    Stop,
}

fn flush(socket: &mut TcpStream, connection: &mut Connection) {
    let mut encoded = BytesMut::new();
    while let Some(frame) = connection.next_frame() {
        frame.encode(&mut encoded).expect("peer frame encode");
    }
    socket.write_all(&encoded).expect("peer frame write");
}

/// One connection, a finite sequence of request/response gates, and bounded
/// native read/write waits. No task or listener is left serving after success.
fn peer(listener: &TcpListener, calls: usize) -> (Vec<PeerStep>, std::thread::JoinHandle<()>) {
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
    let task = std::thread::spawn(move || {
        let until = Instant::now() + WATCHDOG;
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < until =>
                {
                    // Only bounds the fixture's nonblocking accept loop;
                    // correctness is synchronized by request/Pending witnesses.
                    std::thread::sleep(Duration::from_millis(1));
                }
                error => panic!("peer accept failed: {error:?}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(WATCHDOG)).unwrap();
        socket.set_write_timeout(Some(WATCHDOG)).unwrap();
        let mut connection = Connection::server(Settings::server());
        connection.queue_initial_settings();
        flush(&mut socket, &mut connection);
        let mut preface = [0; 24];
        socket.read_exact(&mut preface).expect("client preface");
        assert_eq!(&preface, CLIENT_PREFACE);
        let mut decoder = FrameCodec::new();
        let mut inbound = BytesMut::new();
        let mut bodies: HashMap<u32, BytesMut> = HashMap::new();
        let mut deadlines = HashMap::new();
        let mut script = script.into_iter();
        let mut answered = 0;
        loop {
            let mut bytes = [0; 4096];
            let read = socket.read(&mut bytes).expect("peer request read");
            assert_ne!(read, 0, "caller closed before its expected request");
            inbound.extend_from_slice(&bytes[..read]);
            while let Some(frame) = decoder.decode(&mut inbound).expect("peer frame decode") {
                let (stream, ended) = match connection.process_frame(frame).expect("peer frame") {
                    Some(ReceivedFrame::Headers {
                        stream_id,
                        headers,
                        end_stream,
                    }) => {
                        let mut timeouts = headers
                            .iter()
                            .filter(|header| header.name == "grpc-timeout");
                        deadlines.insert(
                            stream_id,
                            timeouts
                                .next()
                                .and_then(|header| crate::grpc::parse_grpc_timeout(&header.value)),
                        );
                        assert!(timeouts.next().is_none(), "one grpc-timeout per request");
                        bodies.entry(stream_id).or_default();
                        (stream_id, end_stream)
                    }
                    Some(ReceivedFrame::Data {
                        stream_id,
                        data,
                        end_stream,
                    }) => {
                        bodies.entry(stream_id).or_default().extend_from_slice(&data);
                        (stream_id, end_stream)
                    }
                    _ => continue,
                };
                if !ended {
                    continue;
                }
                flush(&mut socket, &mut connection);
                let body = bodies.remove(&stream).unwrap_or_default().freeze();
                let (seen, command) = script.next().expect("expected request");
                seen.send_blocking(Observation {
                    body: body.clone(),
                    timeout: deadlines.remove(&stream).flatten(),
                    socket: socket.try_clone().unwrap(),
                })
                .expect("test observes the request before releasing its response");
                match command.recv_timeout(WATCHDOG).expect("peer response gate") {
                    Reply::Stop => return,
                    Reply::Echo => {}
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
                connection.send_data(stream, body, false).unwrap();
                connection
                    .send_headers(stream, vec![Header::new("grpc-status", "0")], true)
                    .unwrap();
                flush(&mut socket, &mut connection);
                answered += 1;
                if answered == calls {
                    return;
                }
            }
            flush(&mut socket, &mut connection);
        }
    });
    (steps, task)
}

struct ParkWitness<F> {
    future: Pin<Box<F>>,
    owner: Cx,
    parked: Option<oneshot::Sender<Cx>>,
    close_probe: Option<Arc<CloseProbe>>,
}

impl<F: Future> Future for ParkWitness<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let output = if let Some(probe) = &this.close_probe {
            let waker = Waker::from(Arc::new(CloseWake {
                next: task.waker().clone(),
                probe: Arc::clone(probe),
            }));
            this.future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
        } else {
            this.future.as_mut().poll(task)
        };
        if output.is_pending()
            && let Some(parked) = this.parked.take()
        {
            parked
                .send_blocking(this.owner.clone())
                .expect("controller waits for Pending");
        }
        output
    }
}

fn queued_call(
    cx: &Cx,
    channel: Channel,
    body: &'static [u8],
    timeout: Option<Duration>,
    close_probe: Option<Arc<CloseProbe>>,
) -> (TaskHandle<CallResult>, oneshot::Receiver<Cx>) {
    let (parked, observed) = oneshot::channel();
    let task = cx
        .spawn(move |owner| ParkWitness {
            future: Box::pin(call(channel, body, timeout)),
            owner,
            parked: Some(parked),
            close_probe,
        })
        .expect("spawn queued unary call");
    (task, observed)
}

/// The semaphore invokes this waker when active capacity becomes available.
/// At that exact publication point the prior connection must already be closed.
struct CloseProbe {
    socket: Mutex<TcpStream>,
    state: AtomicUsize,
}

struct CloseWake {
    next: Waker,
    probe: Arc<CloseProbe>,
}

impl Wake for CloseWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self
            .probe
            .state
            .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let mut socket = self.probe.socket.lock().unwrap();
            let mut closed = false;
            let mut bytes = [0; 4096];
            // Drain any already-buffered SETTINGS acknowledgement before EOF.
            for _ in 0..32 {
                match socket.read(&mut bytes) {
                    Ok(0) => {
                        closed = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                        closed = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            self.probe
                .state
                .store(if closed { 2 } else { 3 }, Ordering::SeqCst);
        }
        self.next.wake_by_ref();
    }
}

#[test]
fn unary_admission_limits_reject_overflow_and_default_stays_disabled() {
    assert_eq!(
        UnaryAdmissionLimits::new(NonZeroUsize::new(1).unwrap(), usize::MAX)
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    let configured = limits(3, 7);
    assert_eq!(configured.max_active(), 3);
    assert_eq!(configured.max_queued(), 7);
    let default = futures_lite::future::block_on(Channel::connect("http://loopback:80")).unwrap();
    assert_eq!(default.unary_admission_limits(), None);
}

#[test]
fn unary_admission_unpolled_and_abandoned_waits_retire_owned_registrations() {
    let cx = Cx::for_testing();
    let admission = UnaryAdmission::new(limits(1, 1));
    let permit = futures_lite::future::block_on(admission.acquire(&cx)).unwrap();
    let before = registrations(&cx);
    let unpolled = admission.acquire(&cx);
    drop(unpolled);
    assert_eq!(admission.total.telemetry_snapshot(0).available_units, 1);
    assert_eq!(registrations(&cx), before);
    let mut waiting = Box::pin(admission.acquire(&cx));
    assert!(
        waiting
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(admission.active.telemetry_snapshot(0).waiter_count, 1);
    assert_eq!(registrations(&cx), before + 1);
    drop(waiting);
    assert_eq!(admission.active.telemetry_snapshot(0).waiter_count, 0);
    assert_eq!(registrations(&cx), before);
    drop(permit);
    assert_eq!(admission.active.telemetry_snapshot(0).available_units, 1);
    assert_eq!(admission.total.telemetry_snapshot(0).available_units, 2);
}

#[test]
fn unary_admission_zero_queue_refuses_without_changing_active_capacity() {
    let cx = Cx::for_testing();
    let admission = UnaryAdmission::new(limits(2, 0));
    let first = futures_lite::future::block_on(admission.acquire(&cx)).unwrap();
    let second = futures_lite::future::block_on(admission.acquire(&cx)).unwrap();
    let status = futures_lite::future::block_on(admission.acquire(&cx))
        .err()
        .expect("the third exchange is rejected");
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(status.message(), "native gRPC unary admission queue is full");
    assert_eq!(admission.active.telemetry_snapshot(0).waiter_count, 0);
    drop(first);
    let recovered = futures_lite::future::block_on(admission.acquire(&cx)).unwrap();
    drop((second, recovered));
    assert_eq!(admission.total.telemetry_snapshot(0).available_units, 2);
}

#[test]
fn native_unary_admission_shares_fifo_capacity_and_reuses_the_connection() {
    for workers in [1, 2] {
        run_native(workers, |cx| async move {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let (mut steps, peer) = peer(&listener, 3);
            let channel = channel(&listener, 2, 1).await;
            let clone = channel.clone();
            assert!(Arc::ptr_eq(
                channel.unary_admission.as_ref().unwrap(),
                clone.unary_admission.as_ref().unwrap()
            ));
            assert_eq!(clone.unary_admission_limits(), Some(limits(1, 2)));
            let first_channel = channel.clone();
            let mut first = cx
                .spawn(move |_| call(first_channel, b"first", None))
                .unwrap();
            let first_seen = within(steps[0].observed.recv(&cx)).await.unwrap();
            assert_eq!(&first_seen.body[5..], b"first");
            assert_eq!(pressure(&channel), (1, 0, 2));

            let (mut second, mut second_parked) =
                queued_call(&cx, clone, b"second", None, None);
            within(second_parked.recv(&cx)).await.unwrap();
            assert_eq!(pressure(&channel), (1, 1, 1));
            let (mut third, mut third_parked) =
                queued_call(&cx, channel.clone(), b"third", None, None);
            within(third_parked.recv(&cx)).await.unwrap();
            assert_eq!(pressure(&channel), (1, 2, 0));

            let refused = within(call(channel.clone(), b"overflow", None))
                .await
                .unwrap_err();
            assert_eq!(refused.code(), Code::ResourceExhausted);
            assert_eq!(refused.message(), "native gRPC unary admission queue is full");
            assert_eq!(pressure(&channel), (1, 2, 0));
            assert_no_extra_connection(&listener);

            steps[0].reply.send(Reply::Echo).unwrap();
            let first_response = within(first.join(&cx)).await.unwrap().unwrap();
            assert_eq!(first_response.get_ref(), &Bytes::from_static(b"first"));
            let second_seen = within(steps[1].observed.recv(&cx)).await.unwrap();
            assert_eq!(&second_seen.body[5..], b"second", "FIFO head runs first");
            assert!(
                second_seen.timeout.unwrap() < WATCHDOG,
                "wire deadline subtracts the time spent in the admission queue"
            );
            assert_eq!(pressure(&channel), (1, 1, 1));
            steps[1].reply.send(Reply::Echo).unwrap();
            let third_seen = within(steps[2].observed.recv(&cx)).await.unwrap();
            assert_eq!(&third_seen.body[5..], b"third", "FIFO successor follows");
            steps[2].reply.send(Reply::Echo).unwrap();

            for (task, expected) in [
                (&mut second, b"second".as_slice()),
                (&mut third, b"third".as_slice()),
            ] {
                let response = within(task.join(&cx)).await.unwrap().unwrap();
                assert_eq!(response.get_ref().as_ref(), expected);
            }
            assert_eq!(pressure(&channel), (0, 0, 3));
            assert_no_extra_connection(&listener);
            peer.join().unwrap();
        });
    }
}

#[test]
fn native_unary_admission_cancellation_deadline_and_abandonment_restore_the_queue() {
    for workers in [1, 2] {
        run_native(workers, |cx| async move {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let (mut steps, peer) = peer(&listener, 2);
            let channel = channel(&listener, 1, 1).await;
            let first_channel = channel.clone();
            let mut first = cx
                .spawn(move |_| call(first_channel, b"held", None))
                .unwrap();
            let held = within(steps[0].observed.recv(&cx)).await.unwrap();
            assert_eq!(&held.body[5..], b"held");
            assert_eq!(pressure(&channel), (1, 0, 1));

            for (kind, code, message) in [
                (CancelKind::User, Code::Cancelled, "native gRPC caller cancelled"),
                (
                    CancelKind::Deadline,
                    Code::DeadlineExceeded,
                    "native gRPC caller deadline elapsed",
                ),
                (
                    CancelKind::PollQuota,
                    Code::ResourceExhausted,
                    "native gRPC caller budget exhausted",
                ),
            ] {
                let (mut cancelled, mut parked) =
                    queued_call(&cx, channel.clone(), b"cancelled", None, None);
                let owner = within(parked.recv(&cx)).await.unwrap();
                assert_eq!(pressure(&channel), (1, 1, 0));
                assert!(registrations(&owner) > 0, "parked cancellation observer");
                assert_no_extra_connection(&listener);
                // Publish directly to the parked Cx. No capacity release,
                // self-wake or timer may be needed to deliver cancellation.
                owner.cancel_with(kind, Some("cancel a queued unary exchange"));
                let status = within(cancelled.join(&cx))
                    .await
                    .unwrap()
                    .unwrap_err();
                assert_eq!(status.code(), code);
                assert_eq!(status.message(), message);
                assert_eq!(pressure(&channel), (1, 0, 1));
                assert_no_extra_connection(&listener);
            }

            let (mut expired, mut parked) = queued_call(
                &cx,
                channel.clone(),
                b"expired",
                Some(Duration::from_secs(1)),
                None,
            );
            within(parked.recv(&cx)).await.unwrap();
            assert_eq!(pressure(&channel), (1, 1, 0));
            let status = within(expired.join(&cx)).await.unwrap().unwrap_err();
            assert_eq!(status.code(), Code::DeadlineExceeded);
            assert_eq!(
                status.message(),
                "native HTTP/2 gRPC call exceeded its 1s deadline"
            );
            assert_eq!(pressure(&channel), (1, 0, 1));
            assert_no_extra_connection(&listener);

            let before = registrations(&cx);
            let unpolled = call(channel.clone(), b"unpolled", None);
            drop(unpolled);
            assert_eq!(pressure(&channel), (1, 0, 1));
            assert_eq!(registrations(&cx), before);

            let mut abandoned = Box::pin(call(channel.clone(), b"abandoned", None));
            poll_fn(|task| {
                assert!(abandoned.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(pressure(&channel), (1, 1, 0));
            assert_eq!(registrations(&cx), before + 1);
            drop(abandoned);
            assert_eq!(pressure(&channel), (1, 0, 1));
            assert_eq!(registrations(&cx), before);
            assert_no_extra_connection(&listener);

            let (mut recovered, mut parked) =
                queued_call(&cx, channel.clone(), b"recovered", None, None);
            within(parked.recv(&cx)).await.unwrap();
            assert_eq!(pressure(&channel), (1, 1, 0));
            steps[0].reply.send(Reply::Echo).unwrap();
            let recovered_seen = within(steps[1].observed.recv(&cx)).await.unwrap();
            assert_eq!(&recovered_seen.body[5..], b"recovered");
            steps[1].reply.send(Reply::Echo).unwrap();
            assert_eq!(
                within(first.join(&cx)).await.unwrap().unwrap().get_ref(),
                &Bytes::from_static(b"held")
            );
            assert_eq!(
                within(recovered.join(&cx)).await.unwrap().unwrap().get_ref(),
                &Bytes::from_static(b"recovered")
            );
            assert_eq!(pressure(&channel), (0, 0, 2));
            assert_no_extra_connection(&listener);
            peer.join().unwrap();
        });
    }
}

#[test]
fn native_unary_admission_drops_the_socket_before_waking_its_successor() {
    for workers in [1, 2] {
        run_native(workers, |cx| async move {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let (mut held_steps, held_peer) = peer(&listener, 1);
            let channel = channel(&listener, 1, 0).await;
            let mut active = Box::pin(call(channel.clone(), b"drop-active", None));
            // Poll the active RPC and the real peer's request witness together.
            // Both can park: only socket readiness / peer publication wake us.
            let held = {
                let mut observed = Box::pin(held_steps[0].observed.recv(&cx));
                within(poll_fn(|task| {
                    assert!(active.as_mut().poll(task).is_pending());
                    observed.as_mut().poll(task)
                }))
                .await
                .unwrap()
            };
            assert_eq!(&held.body[5..], b"drop-active");
            assert_eq!(pressure(&channel), (1, 0, 1));
            // A bounded kernel-only wait tolerates FIN delivery latency and
            // needs no runtime progress. With incorrect drop ordering, the
            // socket destructor cannot run until the wake callback returns.
            held.socket.set_nonblocking(false).unwrap();
            held.socket
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let probe = Arc::new(CloseProbe {
                socket: Mutex::new(held.socket),
                state: AtomicUsize::new(0),
            });
            let (mut successor, mut parked) = queued_call(
                &cx,
                channel.clone(),
                b"successor",
                None,
                Some(Arc::clone(&probe)),
            );
            within(parked.recv(&cx)).await.unwrap();
            assert_eq!(pressure(&channel), (1, 1, 0));
            assert_no_extra_connection(&listener);

            let (mut next_steps, next_peer) = peer(&listener, 1);
            probe.state.store(1, Ordering::SeqCst);
            drop(active);
            assert_eq!(
                probe.state.load(Ordering::SeqCst),
                2,
                "the successor's capacity wake must observe EOF on the old socket"
            );
            held_steps[0].reply.send(Reply::Stop).unwrap();

            let next = within(next_steps[0].observed.recv(&cx)).await.unwrap();
            assert_eq!(&next.body[5..], b"successor");
            next_steps[0].reply.send(Reply::Echo).unwrap();
            let response = within(successor.join(&cx)).await.unwrap().unwrap();
            assert_eq!(response.get_ref(), &Bytes::from_static(b"successor"));
            assert_eq!(pressure(&channel), (0, 0, 2));
            assert_no_extra_connection(&listener);
            held_peer.join().unwrap();
            next_peer.join().unwrap();
        });
    }
}
