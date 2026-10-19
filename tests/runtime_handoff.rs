//! Public-API loopback reproduction supplied in GitHub issue #85.
//!
//! Keep the original current-thread and two-worker cases together so the
//! pre-fix run establishes the reported failure and its worker control.

use asupersync::io::AsyncReadExt;
use asupersync::net::TcpStream;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::time::{timeout, wall_now};
use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn build(current_thread: bool) -> Runtime {
    let builder = if current_thread {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(2)
    };
    builder.build().expect("runtime builds")
}

fn watchdog(label: &'static str) -> Arc<AtomicBool> {
    let done = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&done);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        if !seen.load(Ordering::SeqCst) {
            eprintln!("{label}: runtime B's block_on did not return within 30 s (hang)");
            std::process::exit(99);
        }
    });
    done
}

fn handoff(current_thread: bool) -> (Result<Vec<u8>, String>, Duration) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let _server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        go_rx.recv().expect("go signal");
        std::thread::sleep(Duration::from_millis(200));
        conn.write_all(b"pong").expect("server write");
        std::thread::sleep(Duration::from_secs(15));
    });

    let stream = std::thread::spawn(move || {
        let rt = build(current_thread);
        rt.block_on(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            let mut buf = [0u8; 4];
            let parked =
                timeout(wall_now(), Duration::from_millis(100), stream.read(&mut buf)).await;
            assert!(parked.is_err(), "nothing was sent yet, so the read must park");
            stream
        })
    })
    .join()
    .expect("runtime A thread");

    let rt = build(current_thread);
    go_tx.send(()).expect("go");
    let started = Instant::now();
    let outcome = rt.block_on(async move {
        let mut stream = stream;
        let mut buf = [0u8; 4];
        match timeout(wall_now(), Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(n)) => Ok(buf[..n].to_vec()),
            Ok(Err(error)) => Err(format!("read error: {error}")),
            Err(_) => Err("read did not complete within 10 s".to_owned()),
        }
    });
    (outcome, started.elapsed())
}

#[test]
fn current_thread_stream_reads_under_a_new_runtime_after_the_first_is_dropped() {
    let done = watchdog("current_thread");
    let (outcome, took) = handoff(true);
    done.store(true, Ordering::SeqCst);
    eprintln!("current_thread: {outcome:?} after {took:?}");
    assert_eq!(outcome, Ok(b"pong".to_vec()));
}

#[test]
fn worker_threads_stream_reads_under_a_new_runtime_after_the_first_is_dropped() {
    let done = watchdog("worker_threads(2)");
    let (outcome, took) = handoff(false);
    done.store(true, Ordering::SeqCst);
    eprintln!("worker_threads(2): {outcome:?} after {took:?}");
    assert_eq!(outcome, Ok(b"pong".to_vec()));
}

/// Native lifecycle coverage supplements the reporter's unchanged reproducer.
/// Every release of peer traffic follows an observed socket `Poll::Pending`;
/// the wall-clock watchdog only bounds failures and never establishes ordering.
#[cfg(not(target_arch = "wasm32"))]
mod lifecycle {
    use super::build;
    use asupersync::Cx;
    use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use asupersync::net::TcpStream;
    use asupersync::runtime::{Runtime, yield_now};
    use std::future::{Future, poll_fn};
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::task::Poll;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    const ACK: &[u8] = b"client retained socket ownership";
    const RESPONSE: &[u8] = b"readiness crossed the runtime boundary";
    const DUPLEX_RESPONSE: &[u8] = b"concurrent split readiness";

    struct Deadline {
        done: mpsc::Sender<()>,
        thread: Option<JoinHandle<()>>,
    }

    impl Deadline {
        fn new(label: &'static str) -> Self {
            let (done, receiver) = mpsc::channel();
            let thread = thread::spawn(move || {
                if receiver.recv_timeout(Duration::from_secs(30))
                    == Err(mpsc::RecvTimeoutError::Timeout)
                {
                    eprintln!("{label}: native socket lifecycle test exceeded 30 seconds");
                    std::process::exit(99);
                }
            });
            Self {
                done,
                thread: Some(thread),
            }
        }
    }

    impl Drop for Deadline {
        fn drop(&mut self) {
            let _ = self.done.send(());
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    enum PeerCommand {
        Write(Vec<u8>),
        Duplex { request_bytes: usize },
        Finish,
        Stop,
    }

    struct Peer {
        commands: mpsc::Sender<PeerCommand>,
        interrupt: std::net::TcpStream,
        thread: Option<JoinHandle<io::Result<Vec<u8>>>>,
    }

    impl Peer {
        fn connect(runtime: &Runtime) -> (TcpStream, Self) {
            Self::connect_with_receive_buffer(runtime, None)
        }

        fn connect_with_receive_buffer(
            runtime: &Runtime,
            receive_buffer: Option<usize>,
        ) -> (TcpStream, Self) {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind lifecycle peer");
            if let Some(bytes) = receive_buffer {
                // Configure the listener before the handshake so the accepted
                // socket negotiates its initial receive window with this cap.
                socket2::SockRef::from(&listener)
                    .set_recv_buffer_size(bytes)
                    .expect("bound receive buffer before connecting");
            }
            let address = listener.local_addr().expect("peer address");
            // TCP connect completes against the listening socket's backlog;
            // accept needs no unjoined helper thread if connection setup fails.
            let stream = runtime
                .block_on(TcpStream::connect(address))
                .expect("connect lifecycle stream");
            let (mut socket, remote) = listener.accept().expect("accept lifecycle stream");
            assert_eq!(remote, stream.local_addr().expect("client address"));
            socket
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("bound fixture reads");
            socket
                .set_write_timeout(Some(Duration::from_secs(30)))
                .expect("bound fixture writes");
            let interrupt = socket.try_clone().expect("fixture cleanup handle");
            let (commands, receiver) = mpsc::channel();
            let thread = thread::spawn(move || {
                let mut received = Vec::new();
                while let Ok(command) = receiver.recv() {
                    match command {
                        PeerCommand::Write(bytes) => socket.write_all(&bytes)?,
                        PeerCommand::Duplex { request_bytes } => {
                            socket.write_all(DUPLEX_RESPONSE)?;
                            let mut request = vec![0_u8; request_bytes];
                            socket.read_exact(&mut request)?;
                            received.extend_from_slice(&request);
                        }
                        PeerCommand::Finish => {
                            socket.shutdown(Shutdown::Write)?;
                            socket.read_to_end(&mut received)?;
                            return Ok(received);
                        }
                        PeerCommand::Stop => break,
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fixture stopped before the client completed EOF cleanup",
                ))
            });
            (
                stream,
                Self {
                    commands,
                    interrupt,
                    thread: Some(thread),
                },
            )
        }

        fn join(mut self, expected: &[u8]) {
            let received = self
                .thread
                .take()
                .expect("fixture thread")
                .join()
                .expect("fixture thread did not panic")
                .expect("fixture completed exact traffic and client EOF");
            assert_eq!(
                received, expected,
                "peer observed exact client bytes and EOF"
            );
        }
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                // A failing assertion must still release a server blocked in
                // either its command receiver or a real socket operation.
                let _ = self.commands.send(PeerCommand::Stop);
                let _ = self.interrupt.shutdown(Shutdown::Both);
                let _ = thread.join();
            }
        }
    }

    fn identity(stream: &TcpStream) -> (SocketAddr, SocketAddr) {
        (
            stream.local_addr().expect("local socket identity"),
            stream.peer_addr().expect("remote socket identity"),
        )
    }

    async fn park_read<R: AsyncRead + Unpin>(reader: &mut R) {
        let mut byte = [0xa5_u8];
        let mut read = std::pin::pin!(reader.read(&mut byte));
        poll_fn(|cx| {
            assert!(
                read.as_mut().poll(cx).is_pending(),
                "source socket must register an actual pending read before handoff",
            );
            Poll::Ready(())
        })
        .await;
        // Dropping this pending borrow keeps ownership of the socket; a
        // subsequent runtime must replace its retained readiness registration.
    }

    async fn after_pending<F: Future>(future: F, release: impl FnOnce()) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut release = Some(release);
        poll_fn(|cx| {
            let result = future.as_mut().poll(cx);
            if let Some(release) = release.take() {
                assert!(
                    result.is_pending(),
                    "destination must register readiness before peer traffic is released",
                );
                release();
            }
            result
        })
        .await
    }

    async fn receive<R: AsyncRead + Unpin>(
        reader: &mut R,
        commands: &mpsc::Sender<PeerCommand>,
        expected: &[u8],
    ) {
        let mut bytes = vec![0_u8; expected.len()];
        after_pending(reader.read_exact(&mut bytes), || {
            commands
                .send(PeerCommand::Write(expected.to_vec()))
                .expect("release peer after pending read");
        })
        .await
        .expect("read complete payload after runtime handoff");
        assert_eq!(bytes, expected, "handoff preserves every payload byte");
    }

    async fn finish(stream: &mut TcpStream, commands: &mpsc::Sender<PeerCommand>) {
        stream
            .write_all(ACK)
            .await
            .expect("transferred socket remains writable");
        stream.shutdown(Shutdown::Write).expect("client half-close");
        let mut byte = [0_u8];
        let count = after_pending(stream.read(&mut byte), || {
            commands
                .send(PeerCommand::Finish)
                .expect("release peer EOF");
        })
        .await
        .expect("EOF wakes the transferred stream");
        assert_eq!(count, 0, "the peer's write-half close is a clean EOF");
    }

    #[test]
    fn pending_read_survives_drop_and_explicit_shutdown_in_all_runtime_flavors() {
        let _deadline = Deadline::new("drop and explicit shutdown matrix");
        for source_current in [true, false] {
            for destination_current in [true, false] {
                for explicit_shutdown in [false, true] {
                    let source = build(source_current);
                    let (mut stream, peer) = Peer::connect(&source);
                    let original = identity(&stream);
                    source.block_on(park_read(&mut stream));
                    if explicit_shutdown {
                        assert!(
                            source.shutdown_timeout(Duration::from_secs(5)),
                            "source teardown completes with a live socket: current={source_current}",
                        );
                    } else {
                        drop(source);
                    }
                    let destination = build(destination_current);
                    destination.block_on(async {
                        receive(&mut stream, &peer.commands, RESPONSE).await;
                        assert_eq!(identity(&stream), original);
                        finish(&mut stream, &peer.commands).await;
                    });
                    drop(stream);
                    peer.join(ACK);
                    assert!(destination.shutdown_timeout(Duration::from_secs(5)));
                }
            }
        }
    }

    #[test]
    fn nested_destination_reads_while_the_live_source_worker_is_on_loan() {
        let _deadline = Deadline::new("live source worker on loan");
        for destination_current in [true, false] {
            let source = build(true);
            let destination = build(destination_current);
            let (mut stream, peer) = Peer::connect(&source);
            let original = identity(&stream);
            source.block_on(async {
                park_read(&mut stream).await;
                // A's current-thread worker is held by this root until B
                // returns. Its background thread cannot service A's reactor.
                destination.block_on(async {
                    receive(&mut stream, &peer.commands, RESPONSE).await;
                    assert_eq!(identity(&stream), original);
                    finish(&mut stream, &peer.commands).await;
                });
            });
            drop(stream);
            peer.join(ACK);
            assert!(source.shutdown_timeout(Duration::from_secs(5)));
            assert!(destination.shutdown_timeout(Duration::from_secs(5)));
        }
    }

    #[test]
    fn repeated_nested_transfers_preserve_registration_and_socket_ownership() {
        let _deadline = Deadline::new("repeated nested runtime transfers");
        for destination_current in [true, false] {
            let source = build(true);
            let destination = build(destination_current);
            let (mut stream, peer) = Peer::connect(&source);
            let original = identity(&stream);
            source.block_on(async {
                for round in 0_u8..4 {
                    park_read(&mut stream).await;
                    destination.block_on(async {
                        receive(&mut stream, &peer.commands, &[b'B', round]).await;
                        assert_eq!(identity(&stream), original);
                    });
                    receive(&mut stream, &peer.commands, &[b'A', round]).await;
                    assert_eq!(identity(&stream), original);
                }
                finish(&mut stream, &peer.commands).await;
            });
            drop(stream);
            peer.join(ACK);
            assert!(source.shutdown_timeout(Duration::from_secs(5)));
            assert!(destination.shutdown_timeout(Duration::from_secs(5)));
        }
    }

    #[test]
    fn spawned_tasks_transfer_pending_streams_between_runtime_flavors() {
        let _deadline = Deadline::new("spawned task runtime transfers");
        for source_current in [true, false] {
            for destination_current in [true, false] {
                let source = build(source_current);
                let (mut stream, peer) = Peer::connect(&source);
                let original = identity(&stream);
                let task = source.handle().spawn(async move {
                    park_read(&mut stream).await;
                    stream
                });
                let mut stream = source.block_on(task);
                assert!(source.shutdown_timeout(Duration::from_secs(5)));
                let destination = build(destination_current);
                let commands = peer.commands.clone();
                let task = destination.handle().spawn(async move {
                    receive(&mut stream, &commands, RESPONSE).await;
                    assert_eq!(identity(&stream), original);
                    finish(&mut stream, &commands).await;
                    stream
                });
                drop(destination.block_on(task));
                peer.join(ACK);
                assert!(destination.shutdown_timeout(Duration::from_secs(5)));
            }
        }
    }

    #[test]
    fn root_panic_after_pending_read_does_not_pin_the_socket_to_that_runtime() {
        let _deadline = Deadline::new("root panic and reactor teardown");
        for source_current in [true, false] {
            let source = build(source_current);
            let (mut stream, peer) = Peer::connect(&source);
            let original = identity(&stream);
            let panic = catch_unwind(AssertUnwindSafe(|| {
                source.block_on(async {
                    park_read(&mut stream).await;
                    panic!("intentional root panic after a parked socket read");
                });
            }))
            .expect_err("root panic must propagate through block_on");
            assert_eq!(
                panic.downcast_ref::<&str>(),
                Some(&"intentional root panic after a parked socket read"),
            );
            assert!(source.shutdown_timeout(Duration::from_secs(5)));
            let destination = build(true);
            destination.block_on(async {
                receive(&mut stream, &peer.commands, RESPONSE).await;
                assert_eq!(identity(&stream), original);
                finish(&mut stream, &peer.commands).await;
            });
            drop(stream);
            peer.join(ACK);
            assert!(destination.shutdown_timeout(Duration::from_secs(5)));
        }
    }

    #[test]
    fn cancelled_parked_task_returns_its_socket_for_a_new_runtime() {
        let _deadline = Deadline::new("cancelled read preserves transferable ownership");
        for source_current in [true, false] {
            let source = build(source_current);
            let (mut stream, peer) = Peer::connect(&source);
            let original = identity(&stream);
            let mut stream = source.block_on(source.handle().spawn(async move {
                let cx = Cx::current().expect("native parent task context");
                let parked = Arc::new(AtomicBool::new(false));
                let witness = Arc::clone(&parked);
                let mut task = cx
                    .spawn(move |_| async move {
                        let mut bytes = [0xa5_u8; 4];
                        let result = {
                            let mut read = std::pin::pin!(stream.read(&mut bytes));
                            poll_fn(|poll_cx| {
                                let result = read.as_mut().poll(poll_cx);
                                if result.is_pending() {
                                    witness.store(true, Ordering::Release);
                                }
                                result
                            })
                            .await
                        };
                        (result, bytes, stream)
                    })
                    .expect("spawn child owning the socket");
                while !parked.load(Ordering::Acquire) {
                    yield_now().await;
                }
                task.abort();
                let (result, bytes, stream) = task
                    .join(&cx)
                    .await
                    .expect("acknowledged cancellation preserves the child's cleanup result");
                assert_eq!(
                    result.expect_err("read reports cancellation").kind(),
                    io::ErrorKind::Interrupted,
                );
                assert_eq!(bytes, [0xa5_u8; 4], "cancelled read consumes no bytes");
                stream
            }));
            assert!(source.shutdown_timeout(Duration::from_secs(5)));
            let destination = build(true);
            destination.block_on(async {
                receive(&mut stream, &peer.commands, RESPONSE).await;
                assert_eq!(identity(&stream), original);
                finish(&mut stream, &peer.commands).await;
            });
            drop(stream);
            peer.join(ACK);
            assert!(destination.shutdown_timeout(Duration::from_secs(5)));
        }
    }

    fn release_duplex(
        parked: &AtomicUsize,
        direction: usize,
        commands: &mpsc::Sender<PeerCommand>,
        request_bytes: usize,
    ) {
        if parked.fetch_or(direction, Ordering::AcqRel) | direction == 3 {
            commands
                .send(PeerCommand::Duplex { request_bytes })
                .expect("release traffic only after both split directions parked");
        }
    }

    #[test]
    fn split_read_and_write_rehome_concurrently_then_reunite() {
        const REQUEST_BYTES: usize = 256 * 1024;
        let _deadline = Deadline::new("concurrent split readiness after source shutdown");
        let source = build(true);
        let (stream, peer) = Peer::connect_with_receive_buffer(&source, Some(16 * 1024));
        let original = identity(&stream);
        {
            let socket = socket2::SockRef::from(&stream);
            socket
                .set_send_buffer_size(4096)
                .expect("bound client send buffer");
            assert!(socket.send_buffer_size().expect("send buffer size") < REQUEST_BYTES / 2);
            let server_socket = socket2::SockRef::from(&peer.interrupt);
            assert!(
                server_socket
                    .recv_buffer_size()
                    .expect("receive buffer size")
                    < REQUEST_BYTES / 2
            );
        }
        let (mut reader, mut writer) = stream.into_split();
        source.block_on(park_read(&mut reader));
        assert!(source.shutdown_timeout(Duration::from_secs(5)));

        let reader_runtime = build(true);
        let writer_runtime = build(false);
        let parked = Arc::new(AtomicUsize::new(0));
        let writer_parked = Arc::clone(&parked);
        let commands = peer.commands.clone();
        let write = writer_runtime.handle().spawn(async move {
            let request = vec![0x5a_u8; REQUEST_BYTES];
            after_pending(writer.write_all(&request), || {
                release_duplex(&writer_parked, 2, &commands, REQUEST_BYTES);
            })
            .await
            .expect("write readiness survives concurrent read registration");
            writer
        });
        reader_runtime.block_on(async {
            let mut response = vec![0_u8; DUPLEX_RESPONSE.len()];
            after_pending(reader.read_exact(&mut response), || {
                release_duplex(&parked, 1, &peer.commands, REQUEST_BYTES);
            })
            .await
            .expect("read readiness survives concurrent write registration");
            assert_eq!(response, DUPLEX_RESPONSE);
        });
        let writer = writer_runtime.block_on(write);
        assert_eq!(
            parked.load(Ordering::Acquire),
            3,
            "both directions returned Pending"
        );
        let mut stream = reader.reunite(writer).expect("same socket halves reunite");
        assert_eq!(identity(&stream), original);
        reader_runtime.block_on(finish(&mut stream, &peer.commands));
        drop(stream);
        let mut expected = vec![0x5a_u8; REQUEST_BYTES];
        expected.extend_from_slice(ACK);
        peer.join(&expected);
        assert!(reader_runtime.shutdown_timeout(Duration::from_secs(5)));
        assert!(writer_runtime.shutdown_timeout(Duration::from_secs(5)));
    }
}
