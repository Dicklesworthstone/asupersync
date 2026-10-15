//! Connect the request channel to the native transport's existing owner.

use super::{NativeRequestSender, NativeRequestStream, native_request_channel};
use crate::cx::Cx;
use crate::grpc::client::GrpcClient;
use crate::grpc::codec::Codec;
use crate::grpc::native_upload::{NativeBidiStream, NativeClientStreamingCall};
use crate::grpc::status::Status;
use crate::grpc::streaming::Request;
use crate::io::{AsyncRead, AsyncWrite};
use std::sync::Arc;

impl<C: Codec> GrpcClient<C>
where
    C::Encode: Send,
{
    /// Start a native bidirectional RPC with a bounded request sender.
    ///
    /// Request metadata and extensions use the same interceptor and connection
    /// path as `into_native_bidi_streaming`. `capacity` bounds queued message
    /// objects, not their heap allocations; transport message-size limits apply
    /// when each request is encoded. Invalid capacity refuses before connecting.
    ///
    /// Drive `responses.message()` concurrently with capacity-waiting sends,
    /// using an explicitly owned producer task or polling both futures. This
    /// method does not spawn a driver. `sender.close()` drains accepted requests
    /// before half-close; dropping an open sender aborts instead. A producer
    /// task should use `sender.send_with_cx(&child_cx, message)` so its own abort
    /// also interrupts a full-queue wait without cancelling the RPC parent.
    /// A producer
    /// failure wakes and terminates this call even when the peer grants zero
    /// upload credit, without waiting for another request-source poll.
    ///
    /// Terminal response status closes the input queue and wakes blocked sends.
    /// A send refusal reports local input closure; inspect the response owner
    /// for the peer's actual status. Accepted input is not proof of remote
    /// delivery, and an early peer terminal may discard unconsumed input.
    pub async fn into_native_bidi_channel(
        self,
        cx: &Cx,
        path: &str,
        request: Request<()>,
        capacity: usize,
    ) -> Result<(
        NativeRequestSender<C::Encode>,
        NativeBidiStream<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, C, NativeRequestStream<C::Encode>>,
    ), Status> {
        let (sender, source) = native_request_channel(cx, capacity)?;
        let control = Arc::clone(&sender.control);
        let mut responses = self.into_native_bidi_streaming(cx, path, request.map(|()| source)).await?;
        responses.request_control = Some(control);
        Ok((sender, responses))
    }

    /// Start a bounded native upload with one trailer-validated response.
    ///
    /// This has the same sender/backpressure and out-of-band failure semantics
    /// as `into_native_bidi_channel`. Poll `call.response()` while producing
    /// requests; it drives both directions and does not report the first reply
    /// as success until final gRPC status is validated. A late peer error is
    /// preserved. Dropping a borrowing response wait preserves all call state;
    /// dropping the owner retires the socket and wakes a blocked producer.
    /// Legacy codec-free client-streaming methods remain unchanged.
    pub async fn into_native_client_streaming_channel(
        self,
        cx: &Cx,
        path: &str,
        request: Request<()>,
        capacity: usize,
    ) -> Result<(
        NativeRequestSender<C::Encode>,
        NativeClientStreamingCall<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, C, NativeRequestStream<C::Encode>>,
    ), Status> {
        let (sender, source) = native_request_channel(cx, capacity)?;
        let control = Arc::clone(&sender.control);
        let call = self.into_native_client_streaming(cx, path, request.map(|()| source)).await?;
        Ok((sender, call.with_request_control(control)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{Bytes, BytesMut};
    use crate::codec::Decoder as _;
    use crate::grpc::{Channel, Code, FramedCodec, IdentityCodec};
    use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
    use crate::http::h2::{Connection, FrameCodec, Header, Settings};
    use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
    use std::future::{Future, poll_fn};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};

    const LIMIT: Duration = Duration::from_secs(8);
    const MESSAGE_BYTES: usize = 128 * 1024;

    #[derive(Clone, Copy)]
    enum Mode { Bidi, Aggregate, ZeroWindow, EarlyError }

    struct Peer {
        address: SocketAddr,
        fail: mpsc::Sender<()>,
        worker: std::thread::JoinHandle<(usize, bool)>,
    }

    fn flush(socket: &mut TcpStream, connection: &mut Connection) {
        while let Some(frame) = connection.next_frame() {
            let mut bytes = BytesMut::new();
            frame.encode(&mut bytes).unwrap();
            socket.write_all(&bytes).unwrap();
        }
    }

    fn reply(connection: &mut Connection, codec: &mut FramedCodec<IdentityCodec>, value: &[u8]) {
        let mut bytes = BytesMut::new();
        codec.encode_message(&Bytes::copy_from_slice(value), &mut bytes).unwrap();
        connection.send_data(1, bytes.freeze(), false).unwrap();
    }

    fn peer(mode: Mode) -> Peer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (fail, failure) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + LIMIT;
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "request-channel accept watchdog");
                        std::thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) => panic!("request-channel accept: {error}"),
                }
            };
            socket.set_read_timeout(Some(LIMIT)).unwrap();
            socket.set_write_timeout(Some(LIMIT)).unwrap();
            let mut connection = Connection::server(Settings {
                initial_window_size: if matches!(mode, Mode::ZeroWindow | Mode::EarlyError) { 0 } else { 65535 },
                ..Settings::server()
            });
            connection.queue_initial_settings();
            flush(&mut socket, &mut connection);
            let mut preface = [0; 24];
            socket.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, CLIENT_PREFACE);
            let mut frames = FrameCodec::new();
            let mut input = BytesMut::new();
            let mut body = BytesMut::new();
            let mut codec = FramedCodec::with_message_size_limits(IdentityCodec, MESSAGE_BYTES, MESSAGE_BYTES);
            let mut count = 0;
            let mut headers = false;
            let mut half_closed = false;
            let mut buffer = [0; 16 * 1024];
            loop {
                let n = match socket.read(&mut buffer) {
                    Ok(n) => n,
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe) => 0,
                    Err(error) => panic!("request-channel peer read: {error}"),
                };
                if n == 0 { return (count, half_closed); }
                input.extend_from_slice(&buffer[..n]);
                while let Some(frame) = frames.decode(&mut input).unwrap() {
                    match connection.process_frame(frame).unwrap() {
                        Some(ReceivedFrame::Headers { stream_id, end_stream, .. }) => {
                            assert_eq!(stream_id, 1);
                            assert!(!headers && !end_stream);
                            headers = true;
                            connection.send_headers(1, vec![
                                Header::new(":status", "200"), Header::new("content-type", "application/grpc"),
                                Header::new("x-initial", "channel"),
                            ], false).unwrap();
                            if matches!(mode, Mode::ZeroWindow | Mode::EarlyError) {
                                reply(&mut connection, &mut codec, b"ready");
                                flush(&mut socket, &mut connection);
                                if matches!(mode, Mode::EarlyError) {
                                    // The caller releases this only after witnessing a
                                    // real producer wait against the full input queue.
                                    failure.recv_timeout(LIMIT).unwrap();
                                    connection.send_headers(1, vec![
                                        Header::new("grpc-status", "7"),
                                        Header::new("grpc-message", "peer-refused"),
                                    ], true).unwrap();
                                }
                            }
                        }
                        Some(ReceivedFrame::Data { stream_id, data, end_stream }) => {
                            assert_eq!(stream_id, 1);
                            assert!(headers && !half_closed);
                            assert!(matches!(mode, Mode::Bidi | Mode::Aggregate), "zero credit must prevent request DATA");
                            body.extend_from_slice(&data);
                            while let Some(message) = codec.decode_message(&mut body).unwrap() {
                                assert_eq!(message.len(), MESSAGE_BYTES);
                                assert!(message.iter().all(|byte| usize::from(*byte) == count));
                                count += 1;
                                if matches!(mode, Mode::Bidi) { reply(&mut connection, &mut codec, &[count as u8]); }
                            }
                            if end_stream {
                                assert!(body.is_empty());
                                half_closed = true;
                                if matches!(mode, Mode::Aggregate) { reply(&mut connection, &mut codec, &[count as u8]); }
                                connection.send_headers(1, vec![
                                    Header::new("grpc-status", "0"), Header::new("x-terminal", "closed"),
                                ], true).unwrap();
                            }
                        }
                        _ => {}
                    }
                    flush(&mut socket, &mut connection);
                }
            }
        });
        Peer { address, fail, worker }
    }

    fn bounded(test: impl FnOnce() + Send + 'static) {
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
            let _ = send.send(result);
        });
        let result = receive.recv_timeout(Duration::from_secs(45)).expect("request-channel native scenario must finish");
        worker.join().unwrap();
        if let Err(payload) = result { std::panic::resume_unwind(payload); }
    }

    fn runtime(workers: usize) -> Runtime {
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) };
        builder.build().unwrap()
    }

    fn drained(runtime: &Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    async fn client(address: SocketAddr) -> GrpcClient<IdentityCodec> {
        GrpcClient::new(Channel::builder(format!("http://{address}"))
            .timeout(LIMIT).max_send_message_size(MESSAGE_BYTES).connect().await.unwrap())
    }

    #[test]
    fn bounded_sender_streams_large_requests_and_bidi_replies_without_a_driver_task() {
        bounded(|| {
            for workers in [1, 2] {
                let peer = peer(Mode::Bidi);
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (mut sender, mut responses) = client(peer.address).await
                        .into_native_bidi_channel(&cx, "/test.Channel/Bidi", Request::new(()), 1).await.unwrap();
                    let mut producer = cx.spawn(move |child| async move {
                        for index in 0..3 { sender.send_with_cx(&child, Bytes::from(vec![index; MESSAGE_BYTES])).await.unwrap(); }
                        sender.close().unwrap();
                    }).unwrap();
                    let mut replies = Vec::new();
                    while let Some(message) = responses.message().await.unwrap() { replies.push(message); }
                    producer.join(&cx).await.unwrap();
                    assert_eq!(replies.iter().map(|value| value[0]).collect::<Vec<_>>(), [1, 2, 3]);
                    assert_eq!(responses.status().unwrap().code(), Code::Ok);
                    assert!(responses.initial_metadata().unwrap().get("x-initial").is_some());
                    assert!(responses.trailers().unwrap().get("x-terminal").is_some());
                    assert!(!cx.is_cancel_requested());
                });
                assert_eq!(peer.worker.join().unwrap(), (3, true));
                drained(&runtime);
            }
        });
    }

    #[test]
    fn client_streaming_channel_drains_empty_and_large_uploads_before_validated_response() {
        bounded(|| {
            for workers in [1, 2] {
                for count in [0_u8, 3] {
                    let peer = peer(Mode::Aggregate);
                    let runtime = runtime(workers);
                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        let (mut sender, mut call) = client(peer.address).await
                            .into_native_client_streaming_channel(&cx, "/test.Channel/Upload", Request::new(()), 1).await.unwrap();
                        let mut producer = cx.spawn(move |child| async move {
                            for index in 0..count { sender.send_with_cx(&child, Bytes::from(vec![index; MESSAGE_BYTES])).await.unwrap(); }
                            sender.close().unwrap();
                        }).unwrap();
                        let response = call.response().await.unwrap();
                        assert_eq!(response.get_ref().as_ref(), &[count]);
                        assert!(response.metadata().get("x-initial").is_some());
                        assert!(call.trailers().unwrap().get("x-terminal").is_some());
                        producer.join(&cx).await.unwrap();
                        assert_eq!(call.status().unwrap().code(), Code::Ok);
                    });
                    assert_eq!(peer.worker.join().unwrap(), (usize::from(count), true));
                    drained(&runtime);
                }
            }
        });
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    #[test]
    fn producer_failure_and_abandonment_interrupt_a_zero_window_with_a_full_queue() {
        bounded(|| {
            for workers in [1, 2] {
                for abandon in [false, true] {
                    let peer = peer(Mode::ZeroWindow);
                    let runtime = runtime(workers);
                    runtime.block_on(async {
                        let cx = Cx::current().unwrap();
                        let (mut sender, mut responses) = client(peer.address).await
                            .into_native_bidi_channel(&cx, "/test.Channel/Bidi", Request::new(()), 1).await.unwrap();
                        assert_eq!(responses.message().await.unwrap().unwrap().as_ref(), b"ready");
                        sender.try_send(Bytes::from(vec![0; MESSAGE_BYTES])).unwrap();
                        // The queue becoming free witnesses that the source handed
                        // one message to the native encoded slot. No DATA can leave.
                        let second = Bytes::from(vec![1; MESSAGE_BYTES]);
                        let mut waiting = Box::pin(responses.message());
                        poll_fn(|task| {
                            assert!(waiting.as_mut().poll(task).is_pending());
                            match sender.try_send(second.clone()) {
                                Ok(()) => Poll::Ready(()),
                                Err(error) => {
                                    assert_eq!(error.status().code(), Code::ResourceExhausted);
                                    Poll::Pending
                                }
                            }
                        }).await;
                        let wakes = Arc::new(Wakes::default());
                        let waker = Waker::from(Arc::clone(&wakes));
                        assert!(waiting.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                        drop(waiting);
                        let mut sending = Box::pin(sender.send(Bytes::from_static(b"third")));
                        assert!(sending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                        drop(sending);
                        if abandon { drop(sender); }
                        else { sender.fail(Status::resource_exhausted("producer-stopped")).unwrap(); }
                        assert!(wakes.0.load(Ordering::SeqCst) > 0, "failure must wake the blocked transport");
                        let status = responses.message().await.unwrap_err();
                        assert_eq!(status.code(), if abandon { Code::Cancelled } else { Code::ResourceExhausted });
                        if !abandon { assert_eq!(status.message(), "producer-stopped"); }
                        assert!(responses.message().await.unwrap().is_none());
                        assert!(!cx.is_cancel_requested());
                    });
                    assert_eq!(peer.worker.join().unwrap(), (0, false));
                    drained(&runtime);
                }
            }
        });
    }

    #[test]
    fn early_peer_failure_releases_a_blocked_sender_and_preserves_peer_status() {
        bounded(|| {
            for workers in [1, 2] {
                let peer = peer(Mode::EarlyError);
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (mut sender, mut responses) = client(peer.address).await
                        .into_native_bidi_channel(&cx, "/test.Channel/Bidi", Request::new(()), 1).await.unwrap();
                    assert_eq!(responses.message().await.unwrap().unwrap().as_ref(), b"ready");
                    sender.try_send(Bytes::from_static(b"queued")).unwrap();
                    let wakes = Arc::new(Wakes::default());
                    let waker = Waker::from(Arc::clone(&wakes));
                    let mut sending = Box::pin(sender.send(Bytes::from_static(b"waiting")));
                    assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                    peer.fail.send(()).unwrap();
                    let status = responses.message().await.unwrap_err();
                    assert_eq!(status.code(), Code::PermissionDenied);
                    assert_eq!(status.message(), "peer-refused");
                    assert!(wakes.0.load(Ordering::SeqCst) > 0);
                    // This send has not been repolled since Pending, so it
                    // cannot have committed its message before peer retirement.
                    assert_eq!(sending.await.unwrap_err().code(), Code::FailedPrecondition);
                    assert!(sender.is_closed());
                    assert!(!cx.is_cancel_requested());
                });
                assert_eq!(peer.worker.join().unwrap(), (0, false));
                drained(&runtime);
            }
        });
    }

    #[test]
    fn dropping_response_owner_wakes_a_sender_parked_before_network_progress() {
        bounded(|| {
            for workers in [1, 2] {
                let peer = peer(Mode::ZeroWindow);
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (mut sender, mut responses) = client(peer.address).await
                        .into_native_bidi_channel(&cx, "/test.Channel/Bidi", Request::new(()), 1).await.unwrap();
                    assert_eq!(responses.message().await.unwrap().unwrap().as_ref(), b"ready");
                    sender.try_send(Bytes::from_static(b"queued")).unwrap();
                    let wakes = Arc::new(Wakes::default());
                    let waker = Waker::from(Arc::clone(&wakes));
                    let mut sending = Box::pin(sender.send(Bytes::from_static(b"waiting")));
                    assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                    drop(responses);
                    assert!(wakes.0.load(Ordering::SeqCst) > 0);
                    assert_eq!(sending.await.unwrap_err().code(), Code::FailedPrecondition);
                    assert!(sender.is_closed());
                });
                assert_eq!(peer.worker.join().unwrap(), (0, false));
                drained(&runtime);
            }
        });
    }

    #[test]
    fn aborting_a_capacity_blocked_producer_does_not_cancel_the_rpc_parent() {
        bounded(|| {
            for workers in [1, 2] {
                let peer = peer(Mode::ZeroWindow);
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (mut sender, mut responses) = client(peer.address).await
                        .into_native_bidi_channel(&cx, "/test.Channel/Bidi", Request::new(()), 1).await.unwrap();
                    assert_eq!(responses.message().await.unwrap().unwrap().as_ref(), b"ready");
                    sender.try_send(Bytes::from_static(b"queued")).unwrap();
                    let (parked, mut witness) = crate::channel::oneshot::channel();
                    let mut producer = cx.spawn(move |child| async move {
                        let mut sending = Box::pin(sender.send_with_cx(&child, Bytes::from_static(b"waiting")));
                        poll_fn(|task| {
                            assert!(sending.as_mut().poll(task).is_pending());
                            Poll::Ready(())
                        }).await;
                        parked.send_blocking(()).unwrap();
                        sending.await
                    }).unwrap();
                    witness.recv(&cx).await.unwrap();
                    producer.abort();
                    let result = producer.join(&cx).await.unwrap();
                    assert_eq!(result.unwrap_err().code(), Code::Cancelled);
                    assert!(!cx.is_cancel_requested());
                    assert_eq!(responses.message().await.unwrap_err().code(), Code::Cancelled);
                    assert!(responses.message().await.unwrap().is_none());
                });
                assert_eq!(peer.worker.join().unwrap(), (0, false));
                drained(&runtime);
            }
        });
    }

    #[test]
    fn invalid_capacity_precedes_native_connection_setup_for_both_constructors() {
        bounded(|| {
            let runtime = runtime(1);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let channel = Channel::connect("http://loopback:50051").await.unwrap();
                let error = GrpcClient::new(channel).into_native_bidi_channel(
                    &cx, "/test.Channel/Bidi", Request::new(()), 0,
                ).await.unwrap_err();
                assert_eq!(error.code(), Code::InvalidArgument);
                let channel = Channel::connect("http://loopback:50051").await.unwrap();
                let error = GrpcClient::new(channel).into_native_client_streaming_channel(
                    &cx, "/test.Channel/Upload", Request::new(()), usize::MAX,
                ).await.unwrap_err();
                assert_eq!(error.code(), Code::InvalidArgument);
            });
            drained(&runtime);
        });
    }
}
