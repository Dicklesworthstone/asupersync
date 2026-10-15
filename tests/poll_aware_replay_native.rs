//! Real native Pending read -> persisted poll-aware replay in owned native/lab tasks.
//! The peer does not send until the actual TcpStream poll returns Pending.
//! No synthetic Pending, live fallback, detached consumer, or fixture file.
#![cfg(all(feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use asupersync::io::replay_session::{SessionCaptureLimits, SessionDecodeLimits};
use asupersync::io::replay_session::ordered::{
    OrderedRecordedSession, OrderedRecordingSession, OrderedRunError, OrderedSessionBytes,
    OrderedSessionDecodeLimits, PendingIoCaptureLimits,
};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::TcpStream;
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::time::{TimeSource, WallClock, timeout, wall_now};
use asupersync::time::replay::TimeTapeDecodeLimits;
use asupersync::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use asupersync::util::{DetEntropy, EntropySource};
use asupersync::Budget;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

type Reply = Result<(bool, [u8; 2]), io::ErrorKind>;
const RESPONSE: [u8; 2] = [0x35, 0x7a];

fn capture_limits() -> SessionCaptureLimits {
    SessionCaptureLimits {
        io: IoCaptureLimits::new(1024, 8192, 131_072, 8),
        entropy: EntropyCaptureLimits::new(16, 128, 2),
        clock_observations: 16,
    }
}
fn decode_limits() -> OrderedSessionDecodeLimits {
    OrderedSessionDecodeLimits {
        max_encoded_bytes: 524_288, max_effects: 4096, max_order_bytes: 524_288,
        components: SessionDecodeLimits {
            max_encoded_bytes: 262_144,
            io: IoTapeDecodeLimits::new(262_144, capture_limits().io, 262_144),
            entropy: EntropyTapeDecodeLimits::new(4096, capture_limits().entropy, 8192),
            clock: TimeTapeDecodeLimits::new(4096, 16, 128),
        },
    }
}

fn run_native<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).with_sharded_state(true) };
    let runtime = builder.build().unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(async move {
        timeout(wall_now(), Duration::from_secs(10), future).await.expect("native consumer deadline")
    });
    let result = runtime.block_on(runtime.handle().spawn(future));
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(start.elapsed() < Duration::from_secs(5), "owned native task failed to drain");
        runtime.block_on(yield_now());
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    result
}

struct Peer {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<io::Result<()>>>,
}
impl Peer {
    fn new(pending: mpsc::Receiver<()>, truncated: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let worker = std::thread::spawn(move || {
            let start = Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Acquire) || start.elapsed() > Duration::from_secs(10) {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            };
            drop(listener);
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut request = [0; 16];
            stream.read_exact(&mut request)?;
            // A timeout/disconnected sender fails, never releases a synthetic reply.
            pending.recv_timeout(Duration::from_secs(5))
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            stream.write_all(if truncated { &RESPONSE[..1] } else { &RESPONSE })?;
            stream.shutdown(std::net::Shutdown::Write)?;
            Ok(())
        });
        Self { address, stopped, worker: Some(worker) }
    }
    fn finish(mut self) {
        self.worker.take().unwrap().join().expect("native peer panicked").expect("native peer failed");
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

// Forward the REAL socket's result unchanged. Notify the peer after its first
// actual Pending result, not from a timer, sleep, fake socket or a synthetic poll.
struct PendingSignal {
    socket: TcpStream,
    release: Option<mpsc::Sender<()>>,
    pending_reads: Arc<AtomicUsize>,
}
impl AsyncRead for PendingSignal {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.socket).poll_read(cx, buf);
        if result.is_pending() {
            this.pending_reads.fetch_add(1, Ordering::Relaxed);
            if let Some(release) = this.release.take() { release.send(()).expect("peer must remain connected"); }
        }
        result
    }
}
impl AsyncWrite for PendingSignal {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().socket).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
    }
}

async fn send_request<S, E, C>(io: &mut S, entropy: &E, clock: &C) -> io::Result<()>
where
    S: AsyncWrite + Unpin + Send,
    E: EntropySource + ?Sized,
    C: TimeSource + ?Sized,
{
    let nonce = entropy.next_u64();
    let time = clock.now();
    let mut request = [0; 16];
    request[..8].copy_from_slice(&nonce.to_le_bytes());
    request[8..].copy_from_slice(&time.as_nanos().to_le_bytes());
    io.write_all(&request).await?;
    io.flush().await
}

async fn transaction<S, E, C>(io: &mut S, entropy: &E, clock: &C) -> Reply
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    E: EntropySource + ?Sized,
    C: TimeSource + ?Sized,
{
    async {
        send_request(io, entropy, clock).await?;
        let mut body = [0; 2];
        // The alternative is ready on this poll. Record/replay must agree on
        // its winner even though we subsequently drain the read in both cases.
        let (read_won, count) = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut body);
            match Pin::new(&mut *io).poll_read(cx, &mut buf) {
                Poll::Pending => Poll::Ready(Ok((false, 0))),
                Poll::Ready(result) => Poll::Ready(result.map(|()| (true, buf.filled().len()))),
            }
        }).await?;
        io.read_exact(&mut body[count..]).await?;
        io.shutdown().await?;
        Ok((read_won, body))
    }.await.map_err(|error: io::Error| error.kind())
}

fn capture(workers: usize, truncated: bool) -> (Reply, OrderedSessionBytes) {
    let (release, wait) = mpsc::channel();
    let peer = Peer::new(wait, truncated);
    let address = peer.address;
    let pending_reads = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&pending_reads);
    let (original, tape) = run_native(workers, async move {
        let socket = TcpStream::connect(address).await.unwrap();
        let socket = PendingSignal { socket, release: Some(release), pending_reads: seen };
        let mut recording = OrderedRecordingSession::new_with_pending_io(
            socket, Arc::new(DetEntropy::new(42)), Arc::new(WallClock::new()),
            capture_limits(), 4096, PendingIoCaptureLimits::new(2048, 131_072, 8),
        ).unwrap();
        let entropy = recording.entropy(); let clock = recording.clock();
        let result = transaction(recording.io(), entropy.as_ref(), clock.as_ref()).await;
        drop(entropy); drop(clock);
        let (socket, tape) = recording.into_parts();
        drop(socket);
        (result, tape.unwrap())
    });
    peer.finish();
    let pending = pending_reads.load(Ordering::Relaxed);
    assert!(pending > 0, "actual native socket must have suspended");
    assert!(tape.is_poll_aware());
    assert!(tape.pending_io_polls() >= pending);
    let bytes = tape.to_canonical_bytes(524_288).unwrap();
    drop(tape);
    (original, bytes)
}

fn replay_lab(bytes: &[u8]) -> Reply {
    let replay = OrderedRecordedSession::from_poll_aware_bytes(bytes, decode_limits()).unwrap().replay();
    let mut lab = LabRuntime::new(LabConfig::new(2117).worker_count(2).max_steps(4096));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let output = Arc::new(Mutex::new(None));
    let stored = Arc::clone(&output);
    let (task, _) = lab.state.create_task(region, Budget::INFINITE, async move {
        let result = replay.run_send(4096, |p| Box::pin(transaction(p.io, p.entropy, p.clock))).await;
        *stored.lock().unwrap() = Some(result);
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_quiescent();
    assert!(lab.is_quiescent());
    assert_eq!(lab.state.live_task_count(), 0);
    let result = output.lock().unwrap().take().expect("lab replay must reach a terminal result");
    result.unwrap()
}

#[test]
fn real_socket_pending_race_replays_after_source_peer_and_runtime_shutdown() {
    for workers in [1, 2] {
        let (original, bytes) = capture(workers, false);
        assert_eq!(original, Ok((false, RESPONSE)));
        assert_eq!(replay_lab(bytes.as_ref()), original);
        let replay = OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), decode_limits()).unwrap().replay();
        drop(bytes);
        assert_eq!(run_native(workers, replay.run_send(4096, |p| Box::pin(transaction(p.io, p.entropy, p.clock)))).unwrap(), original);
    }
}

#[test]
fn real_socket_truncation_after_pending_reproduces_original_eof_error() {
    let (original, bytes) = capture(1, true);
    assert_eq!(original, Err(io::ErrorKind::UnexpectedEof));
    assert_eq!(replay_lab(bytes.as_ref()), original);
}

#[test]
fn native_replay_rejects_changed_pending_read_capacity_even_when_error_is_ignored() {
    let (_, bytes) = capture(2, false);
    let replay = OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), decode_limits()).unwrap().replay();
    drop(bytes);
    let result = run_native(2, replay.run_send(4096, |p| Box::pin(async move {
        send_request(p.io, p.entropy, p.clock).await.unwrap();
        let _ = p.io.read_exact(&mut [0; 3]).await; // Recorded pending capacity was 2.
        "ignored error"
    })));
    assert!(matches!(result, Err(OrderedRunError::Replay(_))));
}
