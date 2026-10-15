//! Real native TCP/H2 requests; the peer uses the crate's framing, so these
//! establish native interoperability within this crate, not independent gRPC conformance.
use super::*;
use crate::grpc::codec::IdentityCodec;
use crate::net::TcpStream;
use crate::runtime::RuntimeBuilder;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Instant;

const LIMIT: Duration = Duration::from_secs(8);
const MESSAGE_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug)]
enum PeerMode {
    ClientStreaming,
    Bidi,
    Cancel,
    Deadline,
    Drop,
}

#[derive(Clone, Copy, Debug)]
enum DialMode {
    Preconnected,
    Address,
    Hostname,
}

fn response_headers(connection: &mut Connection) {
    connection
        .send_headers(
            1,
            vec![
                Header::new(":status", "200"),
                Header::new("content-type", "application/grpc"),
                Header::new("x-initial", "native"),
            ],
            false,
        )
        .unwrap();
}

fn write_pending(socket: &mut std::net::TcpStream, connection: &mut Connection) {
    while let Some(frame) = connection.next_frame() {
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded).unwrap();
        socket.write_all(&encoded).unwrap();
    }
}

fn reply(connection: &mut Connection, codec: &mut FramedCodec<IdentityCodec>, value: &[u8]) {
    let mut encoded = BytesMut::new();
    codec
        .encode_message(&Bytes::copy_from_slice(value), &mut encoded)
        .unwrap();
    connection.send_data(1, encoded.freeze(), false).unwrap();
}

fn peer(
    mode: PeerMode,
    witnessed: mpsc::Receiver<Cx>,
) -> (SocketAddr, std::thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let until = Instant::now() + LIMIT;
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < until, "native duplex accept watchdog");
                    std::thread::park_timeout(Duration::from_millis(1));
                }
                Err(error) => panic!("native duplex accept: {error}"),
            }
        };
        socket.set_read_timeout(Some(LIMIT)).unwrap();
        socket.set_write_timeout(Some(LIMIT)).unwrap();
        let parked = matches!(mode, PeerMode::Cancel | PeerMode::Deadline | PeerMode::Drop);
        let settings = Settings {
            initial_window_size: if parked { 0 } else { 65535 },
            ..Settings::server()
        };
        let mut connection = Connection::server(settings);
        connection.queue_initial_settings();
        write_pending(&mut socket, &mut connection);
        let mut preface = [0; 24];
        socket.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, CLIENT_PREFACE);
        let mut frames = FrameCodec::new();
        let mut inbound = BytesMut::new();
        let mut body = BytesMut::new();
        let mut codec =
            FramedCodec::with_message_size_limits(IdentityCodec, MESSAGE_BYTES, MESSAGE_BYTES);
        let mut messages = 0usize;
        let mut head = false;
        loop {
            let mut data = [0; FRAME_BYTES];
            let read = socket.read(&mut data).expect("native duplex peer read");
            assert_ne!(read, 0, "peer expected complete request before EOF");
            inbound.extend_from_slice(&data[..read]);
            while let Some(frame) = frames.decode(&mut inbound).unwrap() {
                match connection.process_frame(frame).unwrap() {
                    Some(ReceivedFrame::Headers {
                        stream_id,
                        headers,
                        end_stream,
                    }) => {
                        assert_eq!(stream_id, 1);
                        assert!(
                            !head && !end_stream,
                            "streaming request starts with an open body"
                        );
                        assert!(
                            headers
                                .iter()
                                .any(|h| h.name == "content-type" && h.value == "application/grpc")
                        );
                        head = true;
                        if !matches!(mode, PeerMode::ClientStreaming) {
                            response_headers(&mut connection);
                            reply(&mut connection, &mut codec, b"ready");
                        }
                        write_pending(&mut socket, &mut connection);
                        if parked {
                            let owner = witnessed
                                .recv_timeout(LIMIT)
                                .expect("actual window-blocked Pending witness");
                            if matches!(mode, PeerMode::Cancel) {
                                owner.cancel_with(
                                    CancelKind::User,
                                    Some("native duplex window cancellation"),
                                );
                            }
                            // The peer grants zero upload credit. Only cancellation,
                            // deadline, or owner destruction can close this socket.
                            loop {
                                let n = socket.read(&mut data).expect("duplex retirement EOF");
                                if n == 0 {
                                    return 0;
                                }
                                inbound.extend_from_slice(&data[..n]);
                                while let Some(frame) = frames.decode(&mut inbound).unwrap() {
                                    assert!(
                                        !matches!(frame, crate::http::h2::Frame::Data(_)),
                                        "zero window must prevent any request DATA"
                                    );
                                }
                            }
                        }
                    }
                    Some(ReceivedFrame::Data {
                        stream_id,
                        data,
                        end_stream,
                    }) => {
                        assert!(head);
                        assert_eq!(stream_id, 1);
                        body.extend_from_slice(&data);
                        while let Some(message) = codec.decode_message(&mut body).unwrap() {
                            assert_eq!(message.len(), MESSAGE_BYTES);
                            assert!(message.iter().all(|byte| usize::from(*byte) == messages));
                            messages += 1;
                            if matches!(mode, PeerMode::Bidi) {
                                reply(&mut connection, &mut codec, &[messages as u8]);
                            }
                        }
                        if end_stream {
                            assert!(body.is_empty());
                            assert_eq!(
                                messages, 3,
                                "every queued message arrived once and in order"
                            );
                            if matches!(mode, PeerMode::ClientStreaming) {
                                // A client-streaming server may need the entire
                                // request before it can send even response HEADERS.
                                response_headers(&mut connection);
                                reply(&mut connection, &mut codec, b"three requests");
                            }
                            connection
                                .send_headers(
                                    1,
                                    vec![
                                        Header::new("grpc-status", "0"),
                                        Header::new("x-terminal", "complete"),
                                    ],
                                    true,
                                )
                                .unwrap();
                            write_pending(&mut socket, &mut connection);
                            // Let the client consume trailers and close its
                            // transport. Dropping with unread control frames
                            // could reset TCP before the terminal bytes arrive.
                            let mut trailing = [0; 1024];
                            while socket.read(&mut trailing).expect("successful duplex EOF") != 0 {}
                            return messages;
                        }
                    }
                    _ => {}
                }
                write_pending(&mut socket, &mut connection);
            }
        }
    });
    (address, worker)
}

fn scenario(workers: usize, mode: PeerMode, dial: DialMode) {
    let (witness, witnessed) = mpsc::channel();
    let (address, peer) = peer(mode, witnessed);
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .unwrap();
    let completed = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&completed);
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().unwrap();
        let timeout = if matches!(mode, PeerMode::Deadline) {
            Duration::from_secs(2)
        } else {
            LIMIT
        };
        let config = NativeStreamConfig {
            max_send_message_size: MESSAGE_BYTES,
            max_recv_message_size: 64,
            timeout: Some(timeout),
            ..NativeStreamConfig::default()
        };
        let mut stream = match dial {
            DialMode::Preconnected => {
                let io = TcpStream::connect_timeout(address, LIMIT).await.unwrap();
                NativeDuplexStream::new(
                    &cx,
                    io,
                    "localhost",
                    "/test.Duplex/Exchange",
                    Request::new(()),
                    IdentityCodec,
                    config,
                )
                .unwrap()
            }
            DialMode::Address | DialMode::Hostname => {
                let endpoint = if matches!(dial, DialMode::Hostname) {
                    NativeStreamEndpoint::from_host("localhost", address.port(), "localhost", LIMIT)
                } else {
                    NativeStreamEndpoint::new(address, "localhost", LIMIT)
                }
                .unwrap();
                endpoint
                    .connect_duplex_tcp(
                        &cx,
                        "/test.Duplex/Exchange",
                        Request::new(()),
                        IdentityCodec,
                        config,
                    )
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            stream.queue_message(&Bytes::new()).unwrap_err().code(),
            Code::FailedPrecondition
        );
        let parked = matches!(mode, PeerMode::Cancel | PeerMode::Deadline | PeerMode::Drop);
        if parked {
            loop {
                if let Some(NativeDuplexEvent::Message(message)) =
                    stream.next_event().await.unwrap()
                {
                    assert_eq!(message.as_ref(), b"ready");
                    break;
                }
            }
            assert!(stream.request_ready());
            stream
                .queue_message(&Bytes::from(vec![0; MESSAGE_BYTES]))
                .unwrap();
            {
                let mut waiting = std::pin::pin!(stream.next_event());
                poll_fn(|task| {
                    assert!(
                        waiting.as_mut().poll(task).is_pending(),
                        "zero stream window parks actual upload"
                    );
                    Poll::Ready(())
                })
                .await;
            }
            // Recreate the borrowing wait after witnessing and abandoning it.
            witness.send(cx.clone()).unwrap();
            if matches!(mode, PeerMode::Drop) {
                drop(stream);
                assert!(!cx.is_cancel_requested());
            } else {
                let expected = if matches!(mode, PeerMode::Cancel) {
                    Code::Cancelled
                } else {
                    Code::DeadlineExceeded
                };
                assert_eq!(stream.next_event().await.unwrap_err().code(), expected);
                assert_eq!(stream.status().unwrap().code(), expected);
                assert_eq!(stream.buffered_data_bytes(), 0);
                assert!(stream.next_event().await.unwrap().is_none());
                assert_eq!(cx.is_cancel_requested(), matches!(mode, PeerMode::Cancel));
                if matches!(mode, PeerMode::Cancel) {
                    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::User);
                }
            }
        } else {
            let mut queued = 0_u8;
            let mut closed = false;
            let mut responses = Vec::new();
            while let Some(event) = stream.next_event().await.unwrap() {
                match event {
                    NativeDuplexEvent::RequestFlushed if !closed => {
                        assert!(stream.request_ready());
                        if queued < 3 {
                            stream
                                .queue_message(&Bytes::from(vec![queued; MESSAGE_BYTES]))
                                .unwrap();
                            queued += 1;
                            assert!(!stream.request_ready());
                            assert_eq!(
                                stream.queue_message(&Bytes::new()).unwrap_err().code(),
                                Code::FailedPrecondition
                            );
                        } else {
                            stream.close_requests().unwrap();
                            closed = true;
                            assert_eq!(
                                stream.close_requests().unwrap_err().code(),
                                Code::FailedPrecondition
                            );
                        }
                    }
                    NativeDuplexEvent::RequestFlushed => {}
                    NativeDuplexEvent::Message(message) => responses.push(message.to_vec()),
                }
                assert!(stream.buffered_data_bytes() <= 64 + 5 + FRAME_BYTES);
            }
            assert!(closed);
            assert_eq!(queued, 3);
            let expected = if matches!(mode, PeerMode::Bidi) {
                vec![b"ready".to_vec(), vec![1], vec![2], vec![3]]
            } else {
                vec![b"three requests".to_vec()]
            };
            assert_eq!(responses, expected);
            assert_eq!(stream.status().unwrap().code(), Code::Ok);
            assert!(stream.trailers().unwrap().get("x-terminal").is_some());
            assert!(stream.next_event().await.unwrap().is_none());
        }
        completed.store(true, Ordering::Release);
    }));
    assert!(
        observed.load(Ordering::Acquire),
        "native duplex task completed its assertions"
    );
    let messages = peer
        .join()
        .expect("native H2 peer observed terminal or EOF");
    assert!(runtime.shutdown_timeout(LIMIT));
    eprintln!(
        "{}",
        serde_json::json!({"bead":"asupersync-bi2462.105", "workers":workers,
        "mode":format!("{mode:?}"), "dial":format!("{dial:?}"),
        "peer_messages":messages, "bytes_per_message":MESSAGE_BYTES})
    );
}

fn with_watchdog(workers: usize, mode: PeerMode, dial: DialMode) {
    let (done, received) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        scenario(workers, mode, dial);
        done.send(()).unwrap();
    });
    received
        .recv_timeout(Duration::from_secs(20))
        .expect("native duplex wall watchdog");
    thread.join().unwrap();
}

#[test]
fn native_request_streaming_and_bidi_cross_h2_windows_without_collecting_upload() {
    for workers in [1, 2] {
        for mode in [PeerMode::ClientStreaming, PeerMode::Bidi] {
            with_watchdog(workers, mode, DialMode::Preconnected);
        }
    }
}

#[test]
fn native_window_blocked_upload_cancels_expires_and_drops_after_actual_pending() {
    for workers in [1, 2] {
        for mode in [PeerMode::Cancel, PeerMode::Deadline, PeerMode::Drop] {
            with_watchdog(workers, mode, DialMode::Preconnected);
        }
    }
}

#[test]
fn native_endpoints_resolve_and_upload_before_response_headers_with_owned_interruption() {
    for workers in [1, 2] {
        for dial in [DialMode::Address, DialMode::Hostname] {
            for mode in [
                PeerMode::ClientStreaming,
                PeerMode::Bidi,
                PeerMode::Cancel,
                PeerMode::Drop,
            ] {
                with_watchdog(workers, mode, dial);
            }
        }
        with_watchdog(workers, PeerMode::Deadline, DialMode::Hostname);
    }
}

mod keepalive {
    use super::*;
    use crate::grpc::{Channel, GrpcClient};
    use crate::http::h2::Frame;
    use crate::http::h2::frame::PingFrame;
    use crate::runtime::RootDrainOutcome;

    #[derive(Clone, Copy, Debug)]
    enum Mode {
        Ack,
        Silent,
        WrongAck,
        Cancel,
        SlowUpload,
        EchoingUpload,
        PackedEchoes,
        EarlyStatus,
    }

    /// Small response messages a PackedEchoes peer puts in each of two
    /// back-to-back 16 KiB DATA frames after the first upload.
    const PACKED_PER_FRAME: usize = FRAME_BYTES / 9;

    /// Response frames an EchoingUpload peer queues ahead of each PING ACK:
    /// more than the uploads that fit in one keepalive timeout at one frame
    /// per flush (br-asupersync-sm29gx).
    const ECHOES_PER_PROBE: usize = 16;

    fn write_ping(socket: &mut std::net::TcpStream, ping: PingFrame) {
        let mut encoded = BytesMut::new();
        Frame::Ping(ping).encode(&mut encoded).unwrap();
        socket.write_all(&encoded).unwrap();
    }

    fn terminal(connection: &mut Connection) {
        connection.send_headers(1, vec![
            Header::new("grpc-status", "0"), Header::new("x-terminal", "keepalive"),
        ], true).unwrap();
    }

    fn heartbeat_peer(
        mode: Mode,
        watch: bool,
        witnessed: mpsc::Receiver<Cx>,
    ) -> (SocketAddr, std::thread::JoinHandle<(usize, usize, usize)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let until = Instant::now() + LIMIT;
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < until, "keepalive accept watchdog");
                        std::thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) => panic!("keepalive accept: {error}"),
                }
            };
            socket.set_read_timeout(Some(LIMIT)).unwrap();
            socket.set_write_timeout(Some(LIMIT)).unwrap();
            let mut connection = Connection::server(Settings::server());
            connection.queue_initial_settings();
            write_pending(&mut socket, &mut connection);
            let mut preface = [0; 24];
            socket.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, CLIENT_PREFACE);
            let mut frames = FrameCodec::new();
            let mut input = BytesMut::new();
            let mut body = BytesMut::new();
            let mut codec = FramedCodec::new(IdentityCodec);
            let mut received_data = false;
            let mut probes = 0;
            let mut peer_acks = 0;
            let mut uploads = 0;
            let mut previous_probe = None;
            let mut terminated = false;
            loop {
                let mut bytes = [0; FRAME_BYTES];
                let read = socket.read(&mut bytes).expect("keepalive peer read or retirement EOF");
                if read == 0 {
                    assert!(received_data && body.is_empty());
                    return (probes, peer_acks, uploads);
                }
                input.extend_from_slice(&bytes[..read]);
                while let Some(frame) = frames.decode(&mut input).unwrap() {
                    if let Frame::Ping(ping) = &frame {
                        if ping.ack {
                            if ping.opaque_data == 99_u64.to_be_bytes() { peer_acks += 1; }
                        } else if !received_data {
                            // A slow test worker may spend an idle interval
                            // before uploading; acknowledge setup probes too.
                            write_ping(&mut socket, PingFrame::ack(ping.opaque_data));
                        } else {
                            probes += 1;
                            assert_ne!(previous_probe, Some(ping.opaque_data));
                            previous_probe = Some(ping.opaque_data);
                            match mode {
                                Mode::Ack => {
                                    write_ping(&mut socket, PingFrame::ack(ping.opaque_data));
                                    if probes == 1 {
                                        write_ping(&mut socket, PingFrame::new(99_u64.to_be_bytes()));
                                    }
                                    reply(&mut connection, &mut codec, b"beat");
                                    if watch && probes == 2 { terminal(&mut connection); }
                                }
                                Mode::WrongAck => {
                                    let mut wrong = ping.opaque_data;
                                    wrong[0] ^= 0x80;
                                    write_ping(&mut socket, PingFrame::ack(wrong));
                                    write_ping(&mut socket, PingFrame::new(99_u64.to_be_bytes()));
                                    reply(&mut connection, &mut codec, b"noise");
                                }
                                Mode::Silent => {}
                                Mode::SlowUpload | Mode::PackedEchoes | Mode::EarlyStatus => {
                                    write_ping(&mut socket, PingFrame::ack(ping.opaque_data));
                                }
                                Mode::EchoingUpload => {
                                    // Queue response DATA ahead of the ACK. The
                                    // client must read past all of it before the
                                    // probe deadline (br-asupersync-sm29gx).
                                    for _ in 0..ECHOES_PER_PROBE {
                                        if terminated {
                                            break;
                                        }
                                        reply(&mut connection, &mut codec, b"echo");
                                    }
                                    write_pending(&mut socket, &mut connection);
                                    write_ping(&mut socket, PingFrame::ack(ping.opaque_data));
                                }
                                Mode::Cancel => {
                                    let owner = witnessed.recv_timeout(LIMIT)
                                        .expect("actual parked native owner witness");
                                    owner.cancel_with(CancelKind::User, Some("keepalive parked call"));
                                }
                            }
                            write_pending(&mut socket, &mut connection);
                        }
                        // Deliberately control ACK policy. Connection would
                        // otherwise acknowledge even the silent-peer fixture.
                        continue;
                    }
                    match connection.process_frame(frame).unwrap() {
                        Some(ReceivedFrame::Headers { stream_id, .. }) => {
                            assert_eq!(stream_id, 1);
                            response_headers(&mut connection);
                        }
                        Some(ReceivedFrame::Data { data, end_stream, .. }) => {
                            body.extend_from_slice(&data);
                            while let Some(message) = codec.decode_message(&mut body).unwrap() {
                                assert_eq!(message.as_ref(), b"upload");
                                if matches!(
                                    mode,
                                    Mode::SlowUpload
                                        | Mode::EchoingUpload
                                        | Mode::PackedEchoes
                                        | Mode::EarlyStatus
                                ) {
                                    // No response DATA between probes, so the
                                    // client stays idle long enough to probe,
                                    // and nothing gives it a reason to read.
                                    // EchoingUpload answers each probe with
                                    // response DATA queued ahead of its ACK.
                                    uploads += 1;
                                    received_data = true;
                                    if matches!(mode, Mode::PackedEchoes) && uploads == 1 {
                                        // Two full frames of small messages in
                                        // one write: a single flush drain sees
                                        // both before decoding any of them.
                                        let mut packed = BytesMut::new();
                                        for _ in 0..2 * PACKED_PER_FRAME {
                                            codec
                                                .encode_message(
                                                    &Bytes::from_static(b"echo"),
                                                    &mut packed,
                                                )
                                                .unwrap();
                                        }
                                        let packed = packed.freeze();
                                        let half = packed.len() / 2;
                                        connection
                                            .send_data(1, packed.slice(..half), false)
                                            .unwrap();
                                        connection
                                            .send_data(1, packed.slice(half..), false)
                                            .unwrap();
                                    }
                                    if matches!(mode, Mode::EarlyStatus) && uploads == 2 {
                                        connection
                                            .send_headers(
                                                1,
                                                vec![
                                                    Header::new("grpc-status", "7"),
                                                    Header::new("grpc-message", "early refusal"),
                                                ],
                                                true,
                                            )
                                            .unwrap();
                                        terminated = true;
                                    }
                                    continue;
                                }
                                assert!(!received_data, "request message is sent exactly once");
                                received_data = true;
                                reply(&mut connection, &mut codec, b"echo");
                            }
                            if end_stream && !watch {
                                if !matches!(
                                    mode,
                                    Mode::SlowUpload
                                        | Mode::EchoingUpload
                                        | Mode::PackedEchoes
                                        | Mode::EarlyStatus
                                ) {
                                    assert!(matches!(mode, Mode::Ack));
                                    assert_eq!(probes, 2);
                                }
                                if !terminated {
                                    terminal(&mut connection);
                                    terminated = true;
                                }
                            }
                        }
                        _ => {}
                    }
                    write_pending(&mut socket, &mut connection);
                }
            }
        });
        (address, thread)
    }

    fn scenario(workers: usize, mode: Mode, watch: bool) {
        let (witness, witnessed) = mpsc::channel();
        let (address, peer) = heartbeat_peer(mode, watch, witnessed);
        let runtime = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) }.build().unwrap();
        let result = runtime.block_on(runtime.handle().spawn_checked(async move {
            let cx = Cx::current().unwrap();
            let channel = Channel::builder(format!("http://{address}"))
                .keepalive_interval(Duration::from_millis(100))
                .keepalive_timeout(Duration::from_secs(1))
                .connect_timeout(LIMIT)
                .connect().await.unwrap();
            let mut beats = 0;
            let mut echoed = false;
            let result = if watch {
                let mut stream = GrpcClient::new(channel).into_native_server_streaming(
                    &cx, "/svc/Watch", Request::new(Bytes::from_static(b"upload")),
                ).await.unwrap();
                let result = loop {
                    match stream.message().await {
                        Ok(Some(message)) if message.as_ref() == b"echo" => echoed = true,
                        Ok(Some(message)) => {
                            assert_eq!(message.as_ref(), b"beat");
                            beats += 1;
                        }
                        Ok(None) => break Ok(()),
                        Err(status) => break Err(status),
                    }
                };
                assert_eq!(stream.buffered_data_bytes(), 0);
                assert_eq!(stream.status().unwrap().code(), result.as_ref().err().map_or(Code::Ok, Status::code));
                assert!(stream.message().await.unwrap().is_none());
                result
            } else {
                let mut stream = GrpcClient::new(channel).into_native_duplex(
                    &cx, "/svc/Exchange", Request::new(()),
                ).await.unwrap();
                let mut uploaded = false;
                let mut witness = Some(witness);
                let result = loop {
                    match stream.next_event().await {
                        Ok(Some(NativeDuplexEvent::RequestFlushed)) if !uploaded => {
                            stream.queue_message(&Bytes::from_static(b"upload")).unwrap();
                            uploaded = true;
                        }
                        Ok(Some(NativeDuplexEvent::RequestFlushed)) => {}
                        Ok(Some(NativeDuplexEvent::Message(message))) if message.as_ref() == b"echo" => {
                            echoed = true;
                            if matches!(mode, Mode::Cancel) {
                                // The cancelling peer waits for this actual
                                // socket/heartbeat Pending witness. Other peer
                                // modes may already have a ready response.
                                let mut parked = false;
                                for _ in 0..2 {
                                    let outcome = {
                                        let mut wait = std::pin::pin!(stream.next_event());
                                        poll_fn(|task| Poll::Ready(wait.as_mut().poll(task))).await
                                    };
                                    match outcome {
                                        Poll::Pending => { parked = true; break; }
                                        Poll::Ready(Ok(Some(NativeDuplexEvent::RequestFlushed))) => {}
                                        other @ Poll::Ready(_) => panic!("unexpected call progress before cancellation: {other:?}"),
                                    }
                                }
                                assert!(parked, "one queued send boundary precedes the actual read wait");
                                witness.take().unwrap().send(cx.clone()).unwrap();
                            }
                        }
                        Ok(Some(NativeDuplexEvent::Message(message))) => {
                            if matches!(mode, Mode::WrongAck) {
                                assert_eq!(message.as_ref(), b"noise");
                            } else {
                                assert_eq!(message.as_ref(), b"beat");
                                beats += 1;
                                if beats == 2 { stream.close_requests().unwrap(); }
                            }
                        }
                        Ok(None) => break Ok(()),
                        Err(status) => break Err(status),
                    }
                };
                assert!(uploaded);
                assert_eq!(stream.buffered_data_bytes(), 0);
                assert_eq!(stream.status().unwrap().code(), result.as_ref().err().map_or(Code::Ok, Status::code));
                assert!(stream.next_event().await.unwrap().is_none());
                result
            };
            assert!(echoed, "actual request and response DATA precede the idle probe");
            assert_eq!(beats, if matches!(mode, Mode::Ack) { 2 } else { 0 });
            assert_eq!(cx.is_cancel_requested(), matches!(mode, Mode::Cancel));
            if matches!(mode, Mode::Cancel) {
                assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::User);
            }
            result
        })).expect("cooperatively acknowledged cancellation retains the typed RPC result");
        match mode {
            Mode::Ack => assert!(result.is_ok()),
            Mode::Silent | Mode::WrongAck => {
                let status = result.unwrap_err();
                assert_eq!(status.code(), Code::Unavailable);
                assert!(status.message().contains("keepalive"));
            }
            Mode::Cancel => assert_eq!(result.unwrap_err().code(), Code::Cancelled),
            Mode::SlowUpload | Mode::EchoingUpload | Mode::PackedEchoes | Mode::EarlyStatus => {
                unreachable!("slow uploads run through slow_upload")
            }
        }
        let (probes, peer_acks, _) = peer.join().expect("peer observed transport retirement EOF");
        assert_eq!(probes, if matches!(mode, Mode::Ack) { 2 } else { 1 });
        assert_eq!(peer_acks, usize::from(matches!(mode, Mode::Ack | Mode::WrongAck)));
        let report = runtime.shutdown_drained(LIMIT);
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent);
        assert_eq!(report.live_tasks + report.pending_obligations + report.live_regions
            + report.queued_finalizers + report.pending_spawns, 0);
        assert!(!report.has_pending_obligation_posts);
        assert!(runtime.shutdown_timeout(LIMIT));
    }

    /// A healthy peer acknowledges every probe, but a slow upload keeps
    /// flushing far inside its send window, so the owner only ever published
    /// send boundaries and never read the acknowledgement. The call must
    /// outlive several interval + timeout periods instead of failing with a
    /// false keepalive UNAVAILABLE (br-asupersync-ymueix).
    fn slow_upload(workers: usize, mode: Mode) {
        const UPLOADS: usize = 40;
        let (_witness, witnessed) = mpsc::channel();
        let (address, peer) = heartbeat_peer(mode, false, witnessed);
        let runtime = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) }.build().unwrap();
        let (result, sent, echoes) = runtime.block_on(runtime.handle().spawn_checked(async move {
            let cx = Cx::current().unwrap();
            let mut builder = Channel::builder(format!("http://{address}"))
                .keepalive_interval(Duration::from_millis(100))
                .keepalive_timeout(Duration::from_millis(300))
                .connect_timeout(LIMIT);
            if matches!(mode, Mode::PackedEchoes) {
                // Retention bound = 64 + 5 + one frame: two full frames of
                // small messages exceed it unless the flush drain stops.
                builder = builder.max_recv_message_size(64);
            }
            let channel = builder.connect().await.unwrap();
            let mut stream = GrpcClient::new(channel).into_native_duplex(
                &cx, "/svc/Upload", Request::new(()),
            ).await.unwrap();
            let mut sent = 0;
            let mut echoes = 0;
            let mut closed = false;
            let result = loop {
                match stream.next_event().await {
                    Ok(Some(NativeDuplexEvent::RequestFlushed)) if sent < UPLOADS => {
                        if sent > 0 {
                            crate::time::sleep(cx.now(), Duration::from_millis(25)).await;
                        }
                        stream.queue_message(&Bytes::from_static(b"upload")).unwrap();
                        sent += 1;
                    }
                    Ok(Some(NativeDuplexEvent::RequestFlushed)) => {
                        if !closed {
                            stream.close_requests().unwrap();
                            closed = true;
                        }
                    }
                    Ok(Some(NativeDuplexEvent::Message(message)))
                        if matches!(mode, Mode::EchoingUpload | Mode::PackedEchoes) =>
                    {
                        assert_eq!(message.as_ref(), b"echo");
                        echoes += 1;
                    }
                    Ok(Some(NativeDuplexEvent::Message(message))) => {
                        panic!("the slow-upload peer sends no messages: {message:?}");
                    }
                    Ok(None) => break Ok(()),
                    Err(status) => break Err(status),
                }
            };
            (result, sent, echoes)
        })).expect("slow upload owner completes");
        let (probes, _, uploads) = peer.join().expect("slow-upload peer observed retirement EOF");
        let outcome = format!("workers={workers} mode={mode:?} sent={sent} uploads={uploads} echoes={echoes} probes={probes} result={:?}",
            result.as_ref().map_err(Status::code));
        if matches!(mode, Mode::EarlyStatus) {
            // The flush drain read the peer's terminal status. The call
            // reports it instead of a send boundary that the next
            // queue_message would refuse with FAILED_PRECONDITION.
            let status = result.unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{outcome}");
            assert!((2..UPLOADS).contains(&sent), "{outcome}");
            assert_eq!(echoes, 0, "{outcome}");
        } else {
            assert!(
                result.is_ok(),
                "a healthy acknowledging peer must not fail the upload: {outcome}"
            );
            assert_eq!((sent, uploads), (UPLOADS, UPLOADS), "{outcome}");
            if matches!(mode, Mode::EchoingUpload) {
                // Every burst ahead of an ACK arrived whole, over several probes.
                assert!(
                    echoes >= 2 * ECHOES_PER_PROBE && echoes % ECHOES_PER_PROBE == 0,
                    "{outcome}"
                );
            } else if matches!(mode, Mode::PackedEchoes) {
                assert_eq!(echoes, 2 * PACKED_PER_FRAME, "{outcome}");
            } else {
                assert_eq!(echoes, 0, "{outcome}");
            }
            assert!(probes >= 2, "the upload outlived several acknowledged probes: {outcome}");
        }
        let report = runtime.shutdown_drained(LIMIT);
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent);
        assert!(runtime.shutdown_timeout(LIMIT));
    }

    fn checked(workers: usize, mode: Mode, watch: bool) {
        let (done, finished) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(
                mode,
                Mode::SlowUpload | Mode::EchoingUpload | Mode::PackedEchoes | Mode::EarlyStatus
            ) {
                slow_upload(workers, mode);
            } else {
                scenario(workers, mode, watch);
            }
            done.send(()).unwrap();
        });
        finished.recv_timeout(Duration::from_secs(20)).expect("keepalive native wall watchdog");
        thread.join().unwrap();
    }

    #[test]
    fn native_channel_keepalive_drives_idle_watch_and_bidi_with_live_data_and_peer_probes() {
        for workers in [1, 2] {
            for watch in [false, true] { checked(workers, Mode::Ack, watch); }
        }
    }

    #[test]
    fn native_channel_keepalive_silent_wrong_ack_and_parked_cancellation_retire_ownership() {
        for workers in [1, 2] {
            for mode in [Mode::Silent, Mode::WrongAck, Mode::Cancel] {
                checked(workers, mode, false);
            }
        }
    }

    #[test]
    fn native_channel_keepalive_reads_acks_while_a_slow_upload_keeps_flushing() {
        for workers in [1, 2] {
            checked(workers, Mode::SlowUpload, false);
        }
    }

    #[test]
    fn native_channel_keepalive_reads_acks_behind_echoed_response_frames() {
        for workers in [1, 2] {
            checked(workers, Mode::EchoingUpload, false);
        }
    }

    /// The flush drain decodes nothing, so it stops before another DATA frame
    /// could pass the response retention bound. Two packed frames read in one
    /// drain used to fail a healthy call with RESOURCE_EXHAUSTED.
    #[test]
    fn native_channel_keepalive_flush_drain_respects_the_retention_bound() {
        for workers in [1, 2] {
            checked(workers, Mode::PackedEchoes, false);
        }
    }

    /// A terminal status the flush drain read is reported, not hidden behind
    /// a send boundary that the next queue_message refuses.
    #[test]
    fn native_channel_keepalive_flush_drain_reports_an_early_terminal_status() {
        for workers in [1, 2] {
            checked(workers, Mode::EarlyStatus, false);
        }
    }
}
