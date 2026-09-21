//! Capture a real TCP failure, protect it, and replay in a fresh offline process.
//! Only authenticated ciphertext crosses the process boundary. The subprocess
//! constructs no original socket, entropy source or clock provider for replay.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use asupersync::io::replay_archive::{ReplayArchiveBinding, ReplayArchiveKey};
use asupersync::io::replay_session::ordered::{
    OrderedRecordingSession, OrderedSessionDecodeLimits, PendingIoCaptureLimits,
};
use asupersync::io::replay_session::{SessionCaptureLimits, SessionDecodeLimits};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimeSource, VirtualClock};
use asupersync::types::Budget;
use asupersync::util::DetEntropy;
use asupersync::util::entropy::EntropySource;
use asupersync::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use asupersync::time::replay::TimeTapeDecodeLimits;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

// Public, deterministic FIXTURE key and binding. Not production key generation.
const KEY: [u8; 32] = [0x59; 32];
const BINDING: ReplayArchiveBinding = ReplayArchiveBinding { source: [0x31; 32], capture: [0x72; 32] };
const MAX_ENCRYPTED: usize = 1024 * 1024;
const CHILD_FLAG: &str = "ASUP_REPLAY_ARCHIVE_OFFLINE_CHILD";
const SENTINEL: &str = "ENCRYPTED_REPLAY_VERIFIED";

// Ensure a captured pending write independently of OS readiness timing. This
// wrapper preserves the real TCP stream for every successful read/write. The
// ordered recorder must not erase this pending request on encrypted export.
struct PendingOnce<S> { inner: S, first: bool }
impl<S: AsyncRead + Unpin> AsyncRead for PendingOnce<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for PendingOnce<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if std::mem::take(&mut this.first) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn consumer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S, entropy: &dyn EntropySource, clock: &dyn TimeSource,
) -> Result<(), io::ErrorKind> {
    let mut request = [0; 24];
    request[..8].copy_from_slice(b"REPLAY!!");
    request[8..16].copy_from_slice(&entropy.next_u64().to_le_bytes());
    request[16..].copy_from_slice(&clock.now().as_nanos().to_le_bytes());
    stream.write_all(&request).await.map_err(|error| error.kind())?;
    stream.flush().await.map_err(|error| error.kind())?;
    let mut response = [0; 4];
    stream.read_exact(&mut response).await.map_err(|error| error.kind())?;
    match &response {
        b"FAIL" => Err(io::ErrorKind::PermissionDenied),
        b"PASS" => Ok(()),
        _ => Err(io::ErrorKind::InvalidData),
    }
}

fn capture_limits() -> SessionCaptureLimits {
    SessionCaptureLimits {
        io: IoCaptureLimits::new(256, 1024, 65_536, 16),
        entropy: EntropyCaptureLimits::new(32, 4096, 8),
        clock_observations: 32,
    }
}
fn decode_limits() -> OrderedSessionDecodeLimits {
    let capture = capture_limits();
    OrderedSessionDecodeLimits {
        max_encoded_bytes: MAX_ENCRYPTED,
        max_effects: 4096,
        max_order_bytes: 512 * 1024,
        components: SessionDecodeLimits {
            max_encoded_bytes: MAX_ENCRYPTED,
            io: IoTapeDecodeLimits::new(256 * 1024, capture.io, 256 * 1024),
            entropy: EntropyTapeDecodeLimits::new(64 * 1024, capture.entropy, 64 * 1024),
            clock: TimeTapeDecodeLimits::new(4096, 32, 4096),
        },
    }
}

fn capture_network_failure(multithread: bool) -> Vec<u8> {
    // Establish explicit test sockets before runtime execution; no bind-address
    // guessing or sleep is used as a witness of readiness.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = StdTcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (socket, _) = listener.accept().unwrap();
    drop(listener);
    socket.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    let server = std::thread::spawn(move || {
        let mut request = [0; 24];
        peer.read_exact(&mut request).unwrap();
        assert_eq!(&request[..8], b"REPLAY!!");
        peer.write_all(b"FAIL").unwrap();
        request
    });
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let (captured, outcome) = runtime.block_on_with_cx(owner, async move {
        let socket = TcpStream::from_std(socket).unwrap();
        let mut capture = OrderedRecordingSession::new_with_pending_io(
            PendingOnce { inner: socket, first: true },
            Arc::new(DetEntropy::new(9)), Arc::new(VirtualClock::new()),
            capture_limits(), 4096, PendingIoCaptureLimits::new(2048, 65_536, 16),
        ).unwrap();
        let entropy = capture.entropy();
        let clock = capture.clock();
        let result = consumer(capture.io(), entropy.as_ref(), clock.as_ref()).await;
        let (socket, tape) = capture.into_parts();
        drop(socket);
        (tape.unwrap(), result)
    });
    let request = server.join().unwrap();
    drop(runtime);
    assert_eq!(&request[..8], b"REPLAY!!");
    assert_eq!(outcome, Err(io::ErrorKind::PermissionDenied));
    assert!(captured.is_poll_aware());
    assert!(captured.pending_io_polls() >= 1);
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([0x88; 16]);
    let archive = sealer.seal_ordered(&captured, BINDING, MAX_ENCRYPTED).unwrap();
    drop(captured);
    drop(sealer);
    // A different process receives ONLY this encrypted envelope. No live
    // recorder/provider is passed or retained by the test's replay branch.
    archive.as_ref().to_vec()
}

fn replay_offline(multithread: bool) {
    let mut encoded = Vec::new();
    io::stdin().lock().take(u64::try_from(MAX_ENCRYPTED).unwrap() + 1)
        .read_to_end(&mut encoded).unwrap();
    assert!(encoded.len() <= MAX_ENCRYPTED);
    let key = ReplayArchiveKey::new(KEY);
    let capture = key.open_poll_aware(&encoded, BINDING, MAX_ENCRYPTED, decode_limits()).unwrap();
    assert!(capture.is_poll_aware());
    assert!(capture.pending_io_polls() >= 1);
    drop(encoded);
    drop(key);
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let replay = runtime.block_on_with_cx(owner, capture.replay().run(4096, |inputs| {
        Box::pin(consumer(inputs.io, inputs.entropy, inputs.clock))
    }));
    assert_eq!(replay.unwrap(), Err(io::ErrorKind::PermissionDenied));
    println!("{SENTINEL}");
}

// Test-only subprocess ownership. Even a failed assertion retires the spawned
// child rather than leaving an orphan. No user process or file is modified.
struct ChildOwner(Option<Child>);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn journey(multithread: bool, test_name: &str) {
    if matches!(std::env::var(CHILD_FLAG).as_deref(), Ok(name) if name == test_name) {
        replay_offline(multithread);
        return;
    }
    let bytes = capture_network_failure(multithread);
    let child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact").arg(test_name).arg("--nocapture")
        .env(CHILD_FLAG, test_name)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    let mut owner = ChildOwner(Some(child));
    let mut input = owner.0.as_mut().unwrap().stdin.take().unwrap();
    input.write_all(&bytes).unwrap();
    drop(input); // terminate this one bounded input envelope, not a long-lived pipe
    let started = Instant::now();
    loop {
        if owner.0.as_mut().unwrap().try_wait().unwrap().is_some() { break; }
        assert!(started.elapsed() < Duration::from_secs(30), "offline replay subprocess must terminate");
        // Watchdog cadence only: this sleep is NOT the I/O Pending witness.
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = owner.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "child stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(SENTINEL), "must execute replay, not merely launch a test process");
    assert!(stdout.contains("1 passed"), "exactly selected replay journey must pass");
}

#[test]
fn encrypted_tcp_failure_replays_in_fresh_process_current_thread() {
    journey(false, "encrypted_tcp_failure_replays_in_fresh_process_current_thread");
}

#[test]
fn encrypted_tcp_failure_replays_in_fresh_process_two_workers() {
    journey(true, "encrypted_tcp_failure_replays_in_fresh_process_two_workers");
}
