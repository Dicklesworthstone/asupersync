//! A real socket must first return Pending before the peer may reply.
//! Reproduction runs after that peer and its runtime have been destroyed.
#![cfg(all(feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use asupersync::io::replay_session::{SessionCaptureLimits, SessionDecodeLimits};
use asupersync::io::replay_session::ordered::{OrderedRecordingSession, OrderedSessionDecodeLimits};
use asupersync::io::replay_session::ordered::poll::{PollCaptureLimits, PolledDecodeLimits, PolledRecordedSession, PolledSessionBytes};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::TcpStream;
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::time::{TimeSource, WallClock, timeout, wall_now};
use asupersync::time::replay::TimeTapeDecodeLimits;
use asupersync::util::{DetEntropy, EntropySource};
use asupersync::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use asupersync::Budget;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const COMMAND: &[u8; 8] = b"GET poll";
const BODY: &[u8] = b"genuine TCP reply";
type Reply = Result<(Vec<u8>, Vec<(u64, u64)>), io::ErrorKind>;

fn poll_limits() -> PollCaptureLimits {
    PollCaptureLimits { max_polls: 2048, max_io_polls: 4096, max_write_bytes: 65_536, max_vectored_slices: 16 }
}
fn component_limits() -> SessionCaptureLimits {
    SessionCaptureLimits {
        io: IoCaptureLimits::new(2048, 8192, 65_536, 16),
        entropy: EntropyCaptureLimits::new(4096, 65_536, 16), clock_observations: 4096,
    }
}
fn decode_limits() -> PolledDecodeLimits {
    PolledDecodeLimits {
        max_encoded_bytes: 2_097_152, polls: poll_limits(), max_poll_bytes: 1_048_576,
        ordered: OrderedSessionDecodeLimits {
            max_encoded_bytes: 2_097_152, max_effects: 12_288, max_order_bytes: 1_048_576,
            components: SessionDecodeLimits {
                max_encoded_bytes: 2_097_152,
                io: IoTapeDecodeLimits::new(1_048_576, component_limits().io, 1_048_576),
                entropy: EntropyTapeDecodeLimits::new(1_048_576, component_limits().entropy, 1_048_576),
                clock: TimeTapeDecodeLimits::new(65_536, 4096, 65_536),
            },
        },
    }
}
fn run_native<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).with_sharded_state(true) };
    let runtime = builder.build().unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(async move {
        timeout(wall_now(), Duration::from_secs(10), future).await.expect("native deadline")
    });
    let output = runtime.block_on(runtime.handle().spawn(future));
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(start.elapsed() < Duration::from_secs(5), "owned native task must drain");
        runtime.block_on(yield_now());
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    output
}

struct PendingProbe {
    inner: TcpStream,
    first_pending: Option<mpsc::Sender<()>>,
    observed: Arc<AtomicBool>,
}
impl AsyncRead for PendingProbe {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if result.is_pending() {
            this.observed.store(true, Ordering::Release);
            if let Some(sender) = this.first_pending.take() { let _ = sender.send(()); }
        }
        result
    }
}
impl AsyncWrite for PendingProbe {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// The same Future implementation is used for native capture, native replay,
// and lab replay. Clock AND entropy are observed again on every read poll.
async fn transaction<I, E, C>(io: &mut I, entropy: &E, clock: &C) -> Reply
where I: AsyncRead + AsyncWrite + Unpin + Send, E: EntropySource + ?Sized, C: TimeSource + ?Sized {
    io.write_all(COMMAND).await.map_err(|e| e.kind())?;
    io.flush().await.map_err(|e| e.kind())?;
    let mut data = Vec::new(); let mut observations = Vec::new();
    loop {
        let mut storage = [0; 4];
        let n = poll_fn(|cx| {
            observations.push((clock.now().as_nanos(), entropy.next_u64()));
            let mut buf = ReadBuf::new(&mut storage);
            Pin::new(&mut *io).poll_read(cx, &mut buf)
                .map(|r| r.map(|()| buf.filled().len()).map_err(|e| e.kind()))
        }).await?;
        if n == 0 { return Ok((data, observations)); }
        data.extend_from_slice(&storage[..n]);
        if data.len() > 4096 { return Err(io::ErrorKind::InvalidData); }
    }
}

struct PeerGuard(Option<std::thread::JoinHandle<()>>);
impl PeerGuard {
    fn finish(mut self) { self.0.take().unwrap().join().unwrap(); }
}
impl Drop for PeerGuard {
    fn drop(&mut self) { if let Some(thread) = self.0.take() { let _ = thread.join(); } }
}
fn capture(workers: usize) -> (Reply, PolledSessionBytes) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let peer = PeerGuard(Some(std::thread::spawn(move || {
        let start = Instant::now();
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < Duration::from_secs(10));
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        drop(listener);
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = [0; 8]; stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, COMMAND);
        rx.recv_timeout(Duration::from_secs(5)).expect("real socket must return Pending before peer replies");
        stream.write_all(BODY).unwrap(); stream.shutdown(std::net::Shutdown::Write).unwrap();
    })));
    let observed = Arc::new(AtomicBool::new(false)); let probe = Arc::clone(&observed);
    let (original, tape) = run_native(workers, async move {
        let io = PendingProbe { inner: TcpStream::connect(address).await.unwrap(), first_pending: Some(tx), observed: probe };
        let session = OrderedRecordingSession::new(io, Arc::new(DetEntropy::new(42)), Arc::new(WallClock::new()), component_limits(), 12_288).unwrap();
        let (original, io, tape) = session.record_polls_send(poll_limits(), |p| Box::pin(transaction(p.io, p.entropy, p.clock))).await;
        drop(io);
        (original, tape.unwrap())
    });
    peer.finish();
    assert!(observed.load(Ordering::Acquire));
    assert!(tape.consumer_polls() >= 2);
    let bytes = tape.to_canonical_bytes(2_097_152).unwrap(); drop(tape);
    (original, bytes)
}
fn replay_lab(bytes: &[u8]) -> Reply {
    let tape = PolledRecordedSession::from_canonical_bytes(bytes, decode_limits()).unwrap();
    let mut lab = LabRuntime::new(LabConfig::new(823).worker_count(2).max_steps(8192));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let output = Arc::new(Mutex::new(None)); let stored = Arc::clone(&output);
    let (id, _) = lab.state.create_task(region, Budget::INFINITE, async move {
        let result = tape.run_send(2048, |p| Box::pin(transaction(p.io, p.entropy, p.clock))).await;
        *stored.lock().unwrap() = Some(result);
    }).unwrap();
    lab.scheduler.lock().schedule(id, 0); lab.run_until_quiescent();
    assert!(lab.is_quiescent()); assert_eq!(lab.state.live_task_count(), 0);
    let result = output.lock().unwrap().take().expect("replay must finish, not park or panic");
    result.unwrap()
}

#[test]
fn actual_pending_tcp_replays_with_exact_clock_entropy_observations_after_source_shutdown() {
    for workers in [1, 2] {
        let (original, bytes) = capture(workers);
        assert_eq!(original.as_ref().unwrap().0, BODY);
        assert_eq!(replay_lab(bytes.as_ref()), original);
        let tape = PolledRecordedSession::from_canonical_bytes(bytes.as_ref(), decode_limits()).unwrap(); drop(bytes);
        assert_eq!(run_native(workers, tape.run_send(2048, |p| Box::pin(transaction(p.io, p.entropy, p.clock)))).unwrap(), original);
    }
}

#[test]
fn native_replay_rejects_a_consumer_that_finishes_before_recorded_pending_boundaries() {
    let (_, bytes) = capture(2);
    let tape = PolledRecordedSession::from_canonical_bytes(bytes.as_ref(), decode_limits()).unwrap(); drop(bytes);
    let result = run_native(2, tape.run_send(2048, |_| Box::pin(async { "premature success" })));
    assert!(result.is_err());
}
