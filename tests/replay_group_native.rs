//! Two real connections captured together, then replayed offline in a new process.
//! The peer cannot respond before a read has actually returned Pending. The
//! offline consumer reverses its polling preference, while group order remains
//! authoritative. Only authenticated ciphertext crosses the process boundary.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use asupersync::io::replay_archive::{ReplayArchiveBinding, ReplayArchiveKey};
use asupersync::io::replay_group::{IoGroupCaptureLimits, IoGroupDecodeLimits, IoRecordingGroup};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::Budget;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const CHILD: &str = "ASUPERSYNC_IO_GROUP_REPLAY_CHILD";
const MAX_BYTES: usize = 16_384;
// Public test-only key: never use fixed/replayable secrets for real archives.
const KEY: [u8; 32] = [39; 32];
fn binding() -> ReplayArchiveBinding { ReplayArchiveBinding { source: [11; 32], capture: [12; 32] } }
fn decode_limits() -> IoGroupDecodeLimits {
    IoGroupDecodeLimits { max_encoded_bytes: MAX_BYTES, max_streams: 2, max_events: 32, max_group_bytes: 8192,
        per_stream: IoTapeDecodeLimits::new(8192, IoCaptureLimits::new(16, 64, 64, 4), 4096) }
}

struct Witness<T> { io: T, observed: Option<mpsc::Sender<()>> }
impl<T: AsyncRead + Unpin> AsyncRead for Witness<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut(); let result = Pin::new(&mut this.io).poll_read(cx, buf);
        if result.is_pending() {
            if let Some(observed) = this.observed.take() { observed.send(()).unwrap(); }
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Witness<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> { Pin::new(&mut self.get_mut().io).poll_write(cx, buf) }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().io).poll_flush(cx) }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().io).poll_shutdown(cx) }
}

fn pair() -> (TcpStream, StdTcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = StdTcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (local, _) = listener.accept().unwrap();
    local.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    (TcpStream::from_std(local).unwrap(), peer)
}
async fn leg(io: &mut (impl AsyncRead + AsyncWrite + Unpin), request: u8) -> io::Result<u8> {
    io.write_all(&[request]).await?;
    let mut response = [0]; io.read_exact(&mut response).await?; Ok(response[0])
}
async fn exchange(
    a: &mut (impl AsyncRead + AsyncWrite + Unpin),
    b: &mut (impl AsyncRead + AsyncWrite + Unpin),
    reverse: bool,
) -> io::Result<Result<(u8, u8), &'static str>> {
    let mut a = std::pin::pin!(leg(a, b'A'));
    let mut b = std::pin::pin!(leg(b, b'B'));
    let mut ra = None; let mut rb = None;
    let (ra, rb) = poll_fn(|cx| {
        if reverse {
            if rb.is_none() { if let Poll::Ready(result) = b.as_mut().poll(cx) { rb = Some(result); } }
            if ra.is_none() { if let Poll::Ready(result) = a.as_mut().poll(cx) { ra = Some(result); } }
        } else {
            if ra.is_none() { if let Poll::Ready(result) = a.as_mut().poll(cx) { ra = Some(result); } }
            if rb.is_none() { if let Poll::Ready(result) = b.as_mut().poll(cx) { rb = Some(result); } }
        }
        if ra.is_some() && rb.is_some() { Poll::Ready((ra.take().unwrap(), rb.take().unwrap())) }
        else { Poll::Pending }
    }).await;
    let (ra, rb) = (ra?, rb?);
    Ok(if rb == b'N' { Err("peer-b-denied") } else { Ok((ra, rb)) })
}

fn child_replay() {
    // The bound applies before allocating/decoding a supplied capture. This child
    // constructs no runtime, socket, original provider, entropy source or clock.
    let mut encrypted = Vec::new();
    io::stdin().take((MAX_BYTES + 1) as u64).read_to_end(&mut encrypted).unwrap();
    assert!(encrypted.len() <= MAX_BYTES);
    let restored = ReplayArchiveKey::new(KEY).open_io_group(&encrypted, binding(), MAX_BYTES, decode_limits()).unwrap();
    assert_eq!(restored.stream_ids().collect::<Vec<_>>(), vec![17, 29]);
    let replay = restored.replay(); let mut a = replay.open(17).unwrap(); let mut b = replay.open(29).unwrap();
    let result = futures_lite::future::block_on(exchange(&mut a, &mut b, true)).unwrap();
    assert_eq!(result, Err("peer-b-denied"));
    drop(a); drop(b); replay.verify_complete().unwrap();
}

fn fresh_process(test_name: &str, ciphertext: &[u8]) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD, "1").stdin(Stdio::piped()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().unwrap();
    {
        let mut input = child.stdin.take().unwrap(); input.write_all(ciphertext).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() { assert!(status.success(), "offline child failed"); break; }
        if Instant::now() >= deadline {
            let _ = child.kill(); let _ = child.wait(); panic!("offline replay child did not terminate");
        }
        // Watchdog only, never used to choose an I/O or replay schedule.
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn parent(multithread: bool, test_name: &'static str) {
    let (a, mut peer_a) = pair(); let (b, mut peer_b) = pair();
    let (observed, witness) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut request_a = [0]; let mut request_b = [0];
        peer_a.read_exact(&mut request_a).unwrap(); peer_b.read_exact(&mut request_b).unwrap();
        assert_eq!((request_a, request_b), (*b"A", *b"B"));
        witness.recv_timeout(Duration::from_secs(10)).expect("actual pending read before peer response");
        peer_a.write_all(b"Y").unwrap(); peer_b.write_all(b"N").unwrap();
    });
    let runtime = if multithread { RuntimeBuilder::new().worker_threads(2).build().unwrap() }
        else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let tape = runtime.block_on_with_cx(owner, async move {
        let group = IoRecordingGroup::new(IoGroupCaptureLimits { max_streams: 2, max_events: 32, per_stream: IoCaptureLimits::new(16, 64, 64, 4) });
        // Different concrete provider types share the same group.
        let mut a = group.register(17, Witness { io: a, observed: Some(observed) }).unwrap();
        let mut b = group.register(29, b).unwrap();
        assert_eq!(exchange(&mut a, &mut b, false).await.unwrap(), Err("peer-b-denied"));
        drop(a.into_inner()); drop(b.into_inner());
        group.finish().unwrap()
    });
    peer.join().unwrap(); drop(runtime); // original network/providers are gone
    assert_eq!(tape.streams(), 2); assert!(tape.operations() >= 4);
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([if multithread { 2 } else { 1 }; 16]);
    let archive = sealer.seal_io_group(&tape, binding(), MAX_BYTES).unwrap(); drop(tape);
    fresh_process(test_name, archive.as_ref());
}
fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test)); let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(40)).expect("native capture/replay journey must terminate");
    worker.join().unwrap(); if let Err(payload) = result { std::panic::resume_unwind(payload); }
}
#[test]
fn multi_stream_capture_and_fresh_process_replay_current_thread() {
    if std::env::var_os(CHILD).is_some() { child_replay(); }
    else { bounded(|| parent(false, "multi_stream_capture_and_fresh_process_replay_current_thread")); }
}
#[test]
fn multi_stream_capture_and_fresh_process_replay_two_workers() {
    if std::env::var_os(CHILD).is_some() { child_replay(); }
    else { bounded(|| parent(true, "multi_stream_capture_and_fresh_process_replay_two_workers")); }
}
