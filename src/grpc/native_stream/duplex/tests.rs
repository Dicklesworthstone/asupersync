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
                        if !matches!(mode, PeerMode::ClientStreaming) {
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

fn scenario(workers: usize, mode: PeerMode) {
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
        let io = TcpStream::connect_timeout(address, LIMIT).await.unwrap();
        let timeout = if matches!(mode, PeerMode::Deadline) {
            Duration::from_secs(2)
        } else {
            LIMIT
        };
        let mut stream = NativeDuplexStream::new(
            &cx,
            io,
            "localhost",
            "/test.Duplex/Exchange",
            Request::new(()),
            IdentityCodec,
            NativeStreamConfig {
                max_send_message_size: MESSAGE_BYTES,
                max_recv_message_size: 64,
                timeout: Some(timeout),
                ..NativeStreamConfig::default()
            },
        )
        .unwrap();
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
        "mode":format!("{mode:?}"), "peer_messages":messages, "bytes_per_message":MESSAGE_BYTES})
    );
}

fn with_watchdog(workers: usize, mode: PeerMode) {
    let (done, received) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        scenario(workers, mode);
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
            with_watchdog(workers, mode);
        }
    }
}

#[test]
fn native_window_blocked_upload_cancels_expires_and_drops_after_actual_pending() {
    for workers in [1, 2] {
        for mode in [PeerMode::Cancel, PeerMode::Deadline, PeerMode::Drop] {
            with_watchdog(workers, mode);
        }
    }
}
