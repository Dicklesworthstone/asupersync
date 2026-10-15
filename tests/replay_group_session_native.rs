//! Actual two-connection capture plus clock/entropy, replayed in a fresh process.
//! Only authenticated ciphertext crosses the pipe. Test-only fixed keys are not
//! key-provisioning advice. Related br-asupersync-bi2462.8; not scheduler replay.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use asupersync::io::replay_archive::{ReplayArchiveBinding, ReplayArchiveKey};
use asupersync::io::replay_group_session::{GroupSessionCaptureLimits, GroupSessionDecodeLimits, RecordingGroupSession};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::TimeSource;
use asupersync::time::replay::TimeTapeDecodeLimits;
use asupersync::types::{Budget, TaskId, Time};
use asupersync::util::DetEntropy;
use asupersync::util::entropy::EntropySource;
use asupersync::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const CHILD: &str = "ASUPERSYNC_GROUP_SESSION_REPLAY_CHILD";
const MAX_BYTES: usize = 32_768;
const KEY: [u8; 32] = [89; 32];
fn binding() -> ReplayArchiveBinding { ReplayArchiveBinding { source: [61; 32], capture: [62; 32] } }
fn limits() -> GroupSessionDecodeLimits {
    GroupSessionDecodeLimits { max_encoded_bytes: MAX_BYTES, max_streams: 2, max_effects: 32, max_group_bytes: 8192,
        per_stream: IoTapeDecodeLimits::new(8192, IoCaptureLimits::new(16, 64, 64, 4), 4096),
        entropy: EntropyTapeDecodeLimits::new(8192, EntropyCaptureLimits::new(16, 64, 4), 4096),
        clock: TimeTapeDecodeLimits::new(8192, 8, 4096) }
}
struct Clock(Instant);
impl TimeSource for Clock {
    fn now(&self) -> Time { Time::from_nanos(u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX)) }
}
struct Witness<T> { io: T, pending: Option<mpsc::Sender<()>> }
impl<T: AsyncRead + Unpin> AsyncRead for Witness<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut(); let result = Pin::new(&mut this.io).poll_read(cx, buf);
        if result.is_pending() && let Some(sender) = this.pending.take() { sender.send(()).unwrap(); }
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
    let (local, _) = listener.accept().unwrap(); local.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    (TcpStream::from_std(local).unwrap(), peer)
}
async fn response(io: &mut (impl AsyncRead + Unpin)) -> io::Result<u8> {
    let mut byte = [0]; io.read_exact(&mut byte).await?; Ok(byte[0])
}
async fn consume(
    a: &mut (impl AsyncRead + AsyncWrite + Unpin), b: &mut (impl AsyncRead + AsyncWrite + Unpin),
    entropy: &dyn EntropySource, clock: &dyn TimeSource, reverse: bool, tamper: bool,
) -> io::Result<Result<(), &'static str>> {
    let nonce = entropy.next_u64(); let start = clock.now();
    a.write_all(&[nonce as u8 ^ u8::from(tamper)]).await?;
    b.write_all(&[(nonce >> 8) as u8]).await?;
    let (ra, rb) = {
        let mut a = std::pin::pin!(response(a)); let mut b = std::pin::pin!(response(b));
        let (mut ra, mut rb) = (None, None);
        poll_fn(|cx| {
            if reverse {
                if rb.is_none() && let Poll::Ready(result) = b.as_mut().poll(cx) { rb = Some(result); }
                if ra.is_none() && let Poll::Ready(result) = a.as_mut().poll(cx) { ra = Some(result); }
            } else {
                if ra.is_none() && let Poll::Ready(result) = a.as_mut().poll(cx) { ra = Some(result); }
                if rb.is_none() && let Poll::Ready(result) = b.as_mut().poll(cx) { rb = Some(result); }
            }
            if ra.is_some() && rb.is_some() { Poll::Ready((ra.take().unwrap(), rb.take().unwrap())) }
            else { Poll::Pending }
        }).await
    };
    let (ra, rb) = (ra?, rb?);
    let child = entropy.fork(TaskId::new_for_test(7, 3));
    let marker = child.next_u64().to_le_bytes(); a.write_all(&marker).await?;
    assert!(clock.now() >= start);
    assert_eq!(ra, b'Y');
    Ok(if rb == b'N' { Err("peer-b-denied") } else { Ok(()) })
}
fn require_send<T: Send>(value: T) -> T { value }
fn child() {
    let mut bytes = Vec::new(); io::stdin().take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= MAX_BYTES);
    let key = ReplayArchiveKey::new(KEY);
    let replay = key.open_group_session(&bytes, binding(), MAX_BYTES, limits()).unwrap().replay();
    let result = futures_lite::future::block_on(require_send(replay.run_send(128, |session| Box::pin(async move {
        let mut a = session.open(17).unwrap(); let mut b = session.open(29).unwrap();
        consume(&mut a, &mut b, session.entropy(), session.clock(), true, false).await
    })))).unwrap().unwrap();
    assert_eq!(result, Err("peer-b-denied"));
    // Causal negative: valid archive, same providers and startup, changed write.
    let bad = key.open_group_session(&bytes, binding(), MAX_BYTES, limits()).unwrap().replay();
    let negative = futures_lite::future::block_on(require_send(bad.run_send(128, |session| Box::pin(async move {
        let mut a = session.open(17).unwrap(); let mut b = session.open(29).unwrap();
        let _ = consume(&mut a, &mut b, session.entropy(), session.clock(), true, true).await;
    }))));
    assert!(negative.is_err(), "ignored changed-write error cannot pass");
}
fn fresh_process(test: &str, bytes: &[u8]) {
    let mut child = Command::new(std::env::current_exe().unwrap()).args(["--exact", test, "--nocapture"])
        .env(CHILD, "1").stdin(Stdio::piped()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() { assert!(status.success()); break; }
        if Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("offline replay watchdog"); }
        std::thread::sleep(Duration::from_millis(10)); // watchdog, not replay scheduling
    }
}
fn parent(multi: bool, test: &'static str) {
    let (a, mut pa) = pair(); let (b, mut pb) = pair();
    let (sender, pending) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let expected = DetEntropy::new(101); let nonce = expected.next_u64();
        let mut qa = [0]; let mut qb = [0]; pa.read_exact(&mut qa).unwrap(); pb.read_exact(&mut qb).unwrap();
        assert_eq!((qa[0], qb[0]), (nonce as u8, (nonce >> 8) as u8));
        pending.recv_timeout(Duration::from_secs(10)).expect("actual Pending before peer responds");
        pa.write_all(b"Y").unwrap(); pb.write_all(b"N").unwrap();
        let mut marker = [0; 8]; pa.read_exact(&mut marker).unwrap();
        assert_eq!(marker, expected.fork(TaskId::new_for_test(7, 3)).next_u64().to_le_bytes());
    });
    let runtime = if multi { RuntimeBuilder::new().worker_threads(2).build().unwrap() }
        else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let tape = runtime.block_on_with_cx(owner, async move {
        let session = RecordingGroupSession::new(Arc::new(DetEntropy::new(101)), Arc::new(Clock(Instant::now())), GroupSessionCaptureLimits {
            max_streams: 2, max_effects: 32, per_stream: IoCaptureLimits::new(16, 64, 64, 4),
            entropy: EntropyCaptureLimits::new(16, 64, 4), clock_observations: 8,
        }).unwrap();
        let mut a = session.register(17, Witness { io: a, pending: Some(sender) }).unwrap();
        let mut b = session.register(29, b).unwrap();
        assert_eq!(consume(&mut a, &mut b, session.entropy().as_ref(), session.clock().as_ref(), false, false).await.unwrap(), Err("peer-b-denied"));
        drop(a.into_inner()); drop(b.into_inner()); session.finish().unwrap()
    });
    peer.join().unwrap(); drop(runtime);
    assert_eq!(tape.streams(), 2); assert!(tape.effects() >= 10);
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([if multi { 72 } else { 71 }; 16]);
    let archive = sealer.seal_group_session(&tape, binding(), MAX_BYTES).unwrap(); drop(tape); drop(sealer);
    fresh_process(test, archive.as_ref());
}
fn bounded(work: impl FnOnce() + Send + 'static) {
    let (sender, receiver) = mpsc::channel();
    let thread = std::thread::spawn(move || { let _ = sender.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))); });
    let result = receiver.recv_timeout(Duration::from_secs(40)).expect("native group session watchdog");
    thread.join().unwrap(); if let Err(payload) = result { std::panic::resume_unwind(payload); }
}
#[test]
fn joint_group_capture_offline_replay_current_thread() {
    if std::env::var_os(CHILD).is_some() { child(); }
    else { bounded(|| parent(false, "joint_group_capture_offline_replay_current_thread")); }
}
#[test]
fn joint_group_capture_offline_replay_two_workers() {
    if std::env::var_os(CHILD).is_some() { child(); }
    else { bounded(|| parent(true, "joint_group_capture_offline_replay_two_workers")); }
}
