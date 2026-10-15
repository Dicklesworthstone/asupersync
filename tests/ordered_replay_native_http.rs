//! Real native TCP/HTTP capture, source shutdown, then offline native/lab replay.
//! Fixed response/entropy fixtures; live clock samples are retained only in memory.
#![cfg(all(feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::http::h1::{Http1Client, HttpError, Method, Request, Version};
use asupersync::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use asupersync::io::replay_session::{SessionCaptureLimits, SessionDecodeLimits};
use asupersync::io::replay_session::ordered::{
    OrderCompletionError, OrderReplayMismatch, OrderedRecordedSession,
    OrderedRecordingSession, OrderedReplayError, OrderedRunError,
    OrderedSessionBytes, OrderedSessionDecodeLimits,
};
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::TcpStream;
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::time::{TimeSource, WallClock, timeout, wall_now};
use asupersync::time::replay::TimeTapeDecodeLimits;
use asupersync::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use asupersync::util::{DetEntropy, EntropySource};
use asupersync::Budget;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Reply = Result<(u16, Vec<u8>), HttpError>;
const VALID: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nyes\r\n0\r\nX-End: done\r\n\r\n";
const INVALID: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\n";

fn capture_limits() -> SessionCaptureLimits {
    SessionCaptureLimits {
        io: IoCaptureLimits::new(1024, 8192, 131_072, 8),
        entropy: EntropyCaptureLimits::new(16, 128, 2),
        clock_observations: 16,
    }
}
fn decode_limits() -> OrderedSessionDecodeLimits {
    OrderedSessionDecodeLimits {
        max_encoded_bytes: 262_144, max_effects: 2048, max_order_bytes: 131_072,
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
        assert!(start.elapsed() < Duration::from_secs(5), "owned native task did not drain");
        runtime.block_on(yield_now());
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    result
}

struct Peer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
}
impl Peer {
    fn new(response: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let start = Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if stopped.load(Ordering::Acquire) || start.elapsed() > Duration::from_secs(10) {
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
            let mut request = Vec::new();
            let mut buf = [0; 64];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = stream.read(&mut buf)?;
                if count == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
                request.extend_from_slice(&buf[..count]);
                if request.len() > 4096 { return Err(io::ErrorKind::InvalidData.into()); }
            }
            for chunk in response.chunks(7) { stream.write_all(chunk)?; }
            stream.shutdown(std::net::Shutdown::Write)?;
            Ok(request)
        });
        Self { address, stop, worker: Some(worker) }
    }
    fn finish(mut self) {
        let request = self.worker.take().unwrap().join().unwrap().unwrap();
        assert!(request.starts_with(b"GET /ordered HTTP/1.1\r\n"));
        assert!(request.windows(8).any(|part| part == b"X-Nonce:"));
        assert!(request.windows(7).any(|part| part == b"X-Time:"));
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

async fn transaction<S, E, C>(io: &mut S, entropy: &E, clock: &C) -> Reply
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    E: EntropySource + ?Sized,
    C: TimeSource + ?Sized,
{
    let nonce = entropy.next_u64();
    let stamp = clock.now();
    let request = Request {
        method: Method::Get, uri: "/ordered".into(), version: Version::Http11,
        headers: vec![
            ("Host".into(), "localhost".into()),
            ("X-Nonce".into(), format!("{nonce:016x}")),
            ("X-Time".into(), stamp.as_nanos().to_string()),
        ],
        body: Vec::new(), trailers: Vec::new(), peer_addr: None,
    };
    Http1Client::request_with_io_and_max_body_size(io, request, 1024)
        .await.map(|(response, _, _)| (response.status, response.body))
}

fn capture(workers: usize, response: &'static [u8]) -> (Reply, OrderedSessionBytes) {
    let peer = Peer::new(response);
    let address = peer.address;
    let (original, tape) = run_native(workers, async move {
        let socket = TcpStream::connect(address).await.unwrap();
        let mut recording = OrderedRecordingSession::new(
            socket, Arc::new(DetEntropy::new(42)), Arc::new(WallClock::new()), capture_limits(), 2048,
        ).unwrap();
        let entropy = recording.entropy(); let clock = recording.clock();
        let result = transaction(recording.io(), entropy.as_ref(), clock.as_ref()).await;
        drop(entropy); drop(clock);
        let (socket, tape) = recording.into_parts();
        drop(socket);
        (result, tape.unwrap())
    });
    peer.finish(); // The real peer AND source runtime are gone before replay.
    let bytes = tape.to_canonical_bytes(262_144).unwrap();
    drop(tape);
    (original, bytes)
}

fn replay_lab(bytes: &[u8]) -> Reply {
    let replay = OrderedRecordedSession::from_canonical_bytes(bytes, decode_limits()).unwrap().replay();
    let mut lab = LabRuntime::new(LabConfig::new(977).worker_count(2).max_steps(2048));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let output = Arc::new(Mutex::new(None));
    let stored = Arc::clone(&output);
    let (id, _) = lab.state.create_task(region, Budget::INFINITE, async move {
        let result = replay.run_send(2048, |p| Box::pin(transaction(p.io, p.entropy, p.clock))).await;
        *stored.lock().unwrap() = Some(result);
    }).unwrap();
    lab.scheduler.lock().schedule(id, 0);
    lab.run_until_quiescent();
    assert!(lab.is_quiescent());
    assert_eq!(lab.state.live_task_count(), 0);
    let result = output.lock().unwrap().take().expect("replay must reach a terminal result");
    result.unwrap()
}

#[test]
fn real_http_capture_replays_in_native_tasks_and_lab_after_source_shutdown() {
    for workers in [1, 2] {
        let (original, bytes) = capture(workers, VALID);
        let original = original.unwrap();
        assert_eq!(original, (200, b"yes".to_vec()));
        assert_eq!(replay_lab(bytes.as_ref()).unwrap(), original);
        let replay = OrderedRecordedSession::from_canonical_bytes(bytes.as_ref(), decode_limits()).unwrap().replay();
        drop(bytes);
        let reproduced = run_native(workers, replay.run_send(2048, |p| Box::pin(transaction(p.io, p.entropy, p.clock))));
        assert_eq!(reproduced.unwrap().unwrap(), original);
    }
}

#[test]
fn malformed_native_response_replays_its_original_http_parser_error() {
    let (original, bytes) = capture(1, INVALID);
    assert!(matches!(original, Err(HttpError::BadContentLength)));
    assert!(matches!(replay_lab(bytes.as_ref()), Err(HttpError::BadContentLength)));
}

#[test]
fn restored_native_task_rejects_ignored_cross_provider_reordering() {
    let (_, bytes) = capture(2, VALID);
    let replay = OrderedRecordedSession::from_canonical_bytes(bytes.as_ref(), decode_limits()).unwrap().replay();
    drop(bytes);
    let error = run_native(2, replay.run_send(10, |p| Box::pin(async move {
        let _ = p.clock.try_now(); // Captured entropy must happen first.
        "ignored refusal"
    }))).unwrap_err();
    assert!(matches!(error, OrderedRunError::Replay(OrderedReplayError {
        order: Some(OrderCompletionError::Diverged(error)), ..
    }) if error.index == 0 && error.reason == OrderReplayMismatch::Effect));
}
