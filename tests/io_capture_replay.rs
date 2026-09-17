//! Public native TCP capture followed by offline native/lab/process replay.
//! Persisted fixtures contain fixed public protocol data, never captured secrets.

#![cfg(all(feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::io::replay::{
    IoCaptureError, IoCaptureLimits, IoReplayCompletionError, IoReplayError, IoReplayMismatch,
    IoTape, IoTapeDecodeLimits, RecordingIo,
};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::TcpStream;
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::util::entropy_replay::{
    EntropyCaptureLimits, EntropyForkMatching, RecordingEntropy,
};
use asupersync::util::{EntropySource, OsEntropy};
use asupersync::{Budget, Cx};
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const COMMAND: &[u8; 8] = b"GET item";
const BODY: &[u8] = b"real TCP response";
type ResultShape = Result<Vec<u8>, io::ErrorKind>;

fn limits() -> IoCaptureLimits {
    IoCaptureLimits::new(256, 4096, 4096, 32)
}
fn decode_limits() -> IoTapeDecodeLimits {
    IoTapeDecodeLimits::new(65536, limits(), 65536)
}

fn run_native<T: Send + 'static>(
    workers: usize,
    entropy: Option<Arc<dyn EntropySource>>,
    future: impl Future<Output = T> + Send + 'static,
) -> T {
    let mut builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    };
    if let Some(entropy) = entropy {
        builder = builder.with_entropy_source(entropy);
    }
    let runtime = builder.build().unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(future);
    let result = runtime.block_on(runtime.handle().spawn(future));
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "native work failed to drain"
        );
        runtime.block_on(yield_now());
    }
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    result
}

#[derive(Clone, Copy)]
enum Reply {
    Valid,
    BadChecksum,
    Truncated,
}

struct Peer {
    address: SocketAddr,
    release: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<[u8; 8]>>,
}

impl Peer {
    fn new(reply: Reply, gated: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (release, wait) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let start = Instant::now();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            start.elapsed() < Duration::from_secs(15),
                            "client never connected"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            drop(listener);
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut command = [0; 8];
            stream.read_exact(&mut command).unwrap();
            if gated {
                wait.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            stream
                .write_all(&(BODY.len() as u32).to_le_bytes())
                .unwrap();
            match reply {
                Reply::Truncated => stream.write_all(&BODY[..3]).unwrap(),
                Reply::Valid | Reply::BadChecksum => {
                    for chunk in BODY.chunks(3) {
                        stream.write_all(chunk).unwrap();
                    }
                    let checksum = BODY.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
                    stream
                        .write_all(&[checksum ^ u8::from(matches!(reply, Reply::BadChecksum))])
                        .unwrap();
                }
            }
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            command
        });
        Self {
            address,
            release,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> [u8; 8] {
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("real peer must finish successfully")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

async fn read_reply<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = u32::from_le_bytes(header) as usize;
    if length > 128 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let mut checksum = [0; 1];
    stream.read_exact(&mut checksum).await?;
    let mut eof = [0; 1];
    if stream.read(&mut eof).await? != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    stream.shutdown().await?;
    if bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != checksum[0] {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(bytes)
}

async fn transaction<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    command: &[u8; 8],
) -> ResultShape {
    async {
        stream.write_all(command).await?;
        stream.flush().await?;
        read_reply(stream).await
    }
    .await
    .map_err(|error: io::Error| error.kind())
}

fn capture(
    workers: usize,
    reply: Reply,
    cap: IoCaptureLimits,
) -> (ResultShape, Result<IoTape, IoCaptureError>) {
    let peer = Peer::new(reply, false);
    let address = peer.address;
    let result = run_native(workers, None, async move {
        let socket = TcpStream::connect(address).await.unwrap();
        let mut captured = RecordingIo::new(socket, cap);
        let result = transaction(&mut captured, COMMAND).await;
        let (socket, tape) = captured.into_parts();
        drop(socket);
        (result, tape)
    });
    assert_eq!(
        peer.finish(),
        *COMMAND,
        "the consumer must contact the real peer"
    );
    result
}

fn replay_in_lab(tape: IoTape) -> ResultShape {
    let mut lab = LabRuntime::new(LabConfig::new(912).worker_count(2).max_steps(2000));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let output = Arc::new(Mutex::new(None));
    let stored = Arc::clone(&output);
    let (id, _) = lab
        .state
        .create_task(region, Budget::INFINITE, async move {
            let mut replay = tape.replay();
            let result = transaction(&mut replay, COMMAND).await;
            replay.verify_complete().unwrap();
            *stored.lock().unwrap() = Some(result);
        })
        .unwrap();
    lab.scheduler.lock().schedule(id, 0);
    lab.run_until_quiescent();
    assert!(lab.is_quiescent());
    assert_eq!(lab.state.live_task_count(), 0);
    output
        .lock()
        .unwrap()
        .take()
        .expect("a panicked replay cannot look successful")
}

#[test]
fn native_tcp_conversation_replays_after_peer_and_source_runtime_are_gone() {
    for workers in [1, 2] {
        let (original, tape) = capture(workers, Reply::Valid, limits());
        assert_eq!(original, Ok(BODY.to_vec()));
        let tape = tape.unwrap();
        let encoded = tape.to_canonical_bytes(65536).unwrap();
        assert_eq!(
            replay_in_lab(IoTape::from_canonical_bytes(encoded.as_ref(), decode_limits()).unwrap()),
            original
        );
        let actual = run_native(workers, None, async move {
            let mut replay = tape.replay();
            let result = transaction(&mut replay, COMMAND).await;
            replay.verify_complete().unwrap();
            result
        });
        assert_eq!(actual, original);
    }
}

#[test]
fn real_protocol_failure_and_truncated_reply_are_reproduced_offline() {
    for (reply, kind) in [
        (Reply::BadChecksum, io::ErrorKind::InvalidData),
        (Reply::Truncated, io::ErrorKind::UnexpectedEof),
    ] {
        let (original, tape) = capture(2, reply, limits());
        assert_eq!(original, Err(kind));
        assert_eq!(replay_in_lab(tape.unwrap()), Err(kind));
    }
}

#[test]
fn capture_limit_refusal_does_not_break_the_live_transaction() {
    let (original, tape) = capture(1, Reply::Valid, IoCaptureLimits::new(1, 0, 32, 0));
    assert_eq!(original, Ok(BODY.to_vec()));
    assert!(matches!(tape, Err(IoCaptureError::Limit("operations"))));
}

#[test]
fn changed_request_is_sticky_even_when_the_consumer_ignores_the_error() {
    let (_, tape) = capture(1, Reply::Valid, limits());
    run_native(1, None, async move {
        let mut replay = tape.unwrap().replay();
        let error = replay.write_all(b"GET Item").await.unwrap_err();
        let failure = *error
            .get_ref()
            .unwrap()
            .downcast_ref::<IoReplayError>()
            .unwrap();
        assert_eq!(failure.reason, IoReplayMismatch::Request);
        assert_eq!(failure.index, 0);
        let mut buffer = [0xa5; 4];
        let later = replay.read(&mut buffer).await.unwrap_err();
        assert_eq!(
            later.get_ref().unwrap().downcast_ref::<IoReplayError>(),
            Some(&failure)
        );
        assert_eq!(buffer, [0xa5; 4]);
        assert_eq!(
            replay.verify_complete(),
            Err(IoReplayCompletionError::Diverged(failure))
        );
    });
}

#[test]
fn dropping_a_witnessed_pending_read_does_not_capture_fabricated_eof() {
    let peer = Peer::new(Reply::Valid, true);
    let address = peer.address;
    let release = peer.release.clone();
    let tape = run_native(1, None, async move {
        let socket = TcpStream::connect(address).await.unwrap();
        let mut captured = RecordingIo::new(socket, limits());
        captured.write_all(COMMAND).await.unwrap();
        captured.flush().await.unwrap();
        let mut bytes = [0xa5; 4];
        {
            let mut waiting = Box::pin(captured.read(&mut bytes));
            assert!(
                waiting
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "peer is gated until after the pending read is dropped"
            );
        }
        assert_eq!(bytes, [0xa5; 4]);
        release.send(()).unwrap();
        assert_eq!(read_reply(&mut captured).await.unwrap(), BODY);
        let (socket, tape) = captured.into_parts();
        drop(socket);
        tape.unwrap()
    });
    assert_eq!(peer.finish(), *COMMAND);
    assert_eq!(replay_in_lab(tape), Ok(BODY.to_vec()));
}

#[test]
fn native_context_entropy_and_io_replay_together_without_original_providers() {
    for workers in [1, 2] {
        let entropy = Arc::new(
            RecordingEntropy::new(
                Arc::new(OsEntropy),
                EntropyCaptureLimits::new(256, 4096, 64),
            )
            .unwrap(),
        );
        let peer = Peer::new(Reply::Valid, false);
        let address = peer.address;
        let (tape, expected_request) = run_native(workers, Some(entropy.clone()), async move {
            let cx = Cx::current().unwrap();
            let mut request = [0; 8];
            cx.random_bytes(&mut request);
            let socket = TcpStream::connect(address).await.unwrap();
            let mut capture = RecordingIo::new(socket, limits());
            assert_eq!(transaction(&mut capture, &request).await, Ok(BODY.to_vec()));
            let (socket, tape) = capture.into_parts();
            drop(socket);
            (tape.unwrap(), request)
        });
        assert_eq!(peer.finish(), expected_request);
        let saved = entropy.finish().unwrap();
        drop(entropy);
        // Fresh arenas are aligned by the same logical root-spawn topology.
        // This test does not equate native scheduling with the recorded schedule.
        let replay_entropy = saved.replay_with(EntropyForkMatching::ForkOrder);
        run_native(
            workers,
            Some(Arc::new(replay_entropy.clone())),
            async move {
                let cx = Cx::current().unwrap();
                let mut request = [0; 8];
                cx.random_bytes(&mut request);
                assert_eq!(request, expected_request);
                let mut replay = tape.replay();
                assert_eq!(transaction(&mut replay, &request).await, Ok(BODY.to_vec()));
                replay.verify_complete().unwrap();
            },
        );
        replay_entropy.verify_complete().unwrap();
    }
}

#[test]
fn persisted_io_capture_replays_in_an_independent_process() {
    const CHILD: &str = "ASUPERSYNC_IO_REPLAY_CHILD_FIXTURE";
    if let Some(directory) = std::env::var_os(CHILD) {
        let directory = std::path::PathBuf::from(directory);
        let encoded = std::fs::read(directory.join("public-io.tape")).unwrap();
        let tape = IoTape::from_canonical_bytes(&encoded, decode_limits()).unwrap();
        assert_eq!(replay_in_lab(tape), Err(io::ErrorKind::InvalidData));
        std::fs::write(directory.join("replayed"), b"exact bad-checksum result").unwrap();
        return;
    }
    let (original, tape) = capture(1, Reply::BadChecksum, limits());
    assert_eq!(original, Err(io::ErrorKind::InvalidData));
    let encoded = tape.unwrap().to_canonical_bytes(65536).unwrap();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "asupersync-io-replay-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("public-io.tape"), encoded.as_ref()).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "persisted_io_capture_replays_in_an_independent_process",
            "--nocapture",
        ])
        .env(CHILD, &directory)
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(15) {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("offline child failed to terminate");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(status.success());
    assert_eq!(
        std::fs::read(directory.join("replayed")).unwrap(),
        b"exact bad-checksum result",
        "a zero-test child cannot masquerade as replay proof"
    );
}
