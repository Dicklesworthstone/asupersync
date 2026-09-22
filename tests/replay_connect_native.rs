//! Real refused TCP connect, two successes, and the same consumer in an offline child.
//! Related br-asupersync-bi2462.8. Ciphertext crosses stdin; nonsecret endpoint
//! configuration and an expected output digest are passed explicitly. This is
//! connection-result replay, not DNS/TLS, original readiness or scheduler replay.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use asupersync::io::replay_archive::{ReplayArchiveBinding, ReplayArchiveKey};
use asupersync::io::replay_group_session::{
    ConnectionAttempt, GroupReplayIo, GroupSessionCaptureLimits, GroupSessionDecodeLimits,
    GroupSessionRunError, RecordingConnection, RecordingGroupSession, ReplayGroupSession,
};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::TimeSource;
use asupersync::time::replay::TimeTapeDecodeLimits;
use asupersync::types::{Budget, Time};
use asupersync::util::DetEntropy;
use asupersync::util::entropy::EntropySource;
use asupersync::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const CHILD: &str = "ASUPERSYNC_CONNECT_REPLAY_CHILD";
const TARGETS: &str = "ASUPERSYNC_CONNECT_REPLAY_TARGETS";
const EXPECTED: &str = "ASUPERSYNC_CONNECT_REPLAY_EXPECTED";
const MAX_BYTES: usize = 32_768;
// Public test fixture only. Production keys/prefixes must be securely provisioned.
const KEY: [u8; 32] = [107; 32];

#[derive(Clone, Copy)]
struct Targets { refused: SocketAddr, first: SocketAddr, second: SocketAddr }
impl Targets {
    fn encode(self) -> String { format!("{},{},{}", self.refused, self.first, self.second) }
    fn decode(text: &str) -> Self {
        let addresses: Vec<_> = text.split(',').map(|part| part.parse().unwrap()).collect();
        assert_eq!(addresses.len(), 3);
        Self { refused: addresses[0], first: addresses[1], second: addresses[2] }
    }
    fn binding(self) -> ReplayArchiveBinding {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.connect-native-test.v1\0");
        hash.update(self.encode().as_bytes());
        ReplayArchiveBinding { source: hash.finalize().into(), capture: [108; 32] }
    }
}
fn attempt(n: u64) -> ConnectionAttempt { ConnectionAttempt::new(n * 2, n * 2 + 1).unwrap() }
fn limits() -> GroupSessionDecodeLimits {
    GroupSessionDecodeLimits {
        max_encoded_bytes: MAX_BYTES, max_streams: 5, max_effects: 64, max_group_bytes: 8192,
        per_stream: IoTapeDecodeLimits::new(8192, IoCaptureLimits::new(16, 64, 256, 3), 4096),
        entropy: EntropyTapeDecodeLimits::new(1024, EntropyCaptureLimits::new(8, 64, 1), 1024),
        clock: TimeTapeDecodeLimits::new(1024, 8, 1024),
    }
}
struct Clock(Instant);
impl TimeSource for Clock {
    fn now(&self) -> Time { Time::from_nanos(u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX)) }
}
struct Witness<T> { io: T, pending: Option<mpsc::Sender<()>> }
impl<T: AsyncRead + Unpin> AsyncRead for Witness<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.io).poll_read(cx, buf);
        if result.is_pending() && let Some(pending) = this.pending.take() { pending.send(()).unwrap(); }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Witness<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

// The application below is identical for live and offline execution. These
// adapters change capabilities only; neither reimplements its retry decisions.
trait Backend: Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;
    fn connect(&self, id: ConnectionAttempt, target: SocketAddr)
        -> impl Future<Output = io::Result<Self::Stream>> + Send;
    fn finish(&self, stream: Self::Stream);
    fn now(&self) -> Time;
    fn nonce(&self) -> u64;
}
struct Live<'a> { session: &'a RecordingGroupSession<Clock>, pending: &'a mpsc::Sender<()> }
impl Backend for Live<'_> {
    type Stream = Witness<RecordingConnection<TcpStream>>;
    async fn connect(&self, id: ConnectionAttempt, target: SocketAddr) -> io::Result<Self::Stream> {
        Ok(Witness { io: self.session.connect_tcp(id, target).await?, pending: Some(self.pending.clone()) })
    }
    fn finish(&self, stream: Self::Stream) { drop(stream.io.into_inner()); }
    fn now(&self) -> Time { self.session.clock().now() }
    fn nonce(&self) -> u64 { self.session.entropy().next_u64() }
}
struct Offline<'a>(&'a ReplayGroupSession);
impl Backend for Offline<'_> {
    type Stream = GroupReplayIo;
    async fn connect(&self, id: ConnectionAttempt, target: SocketAddr) -> io::Result<Self::Stream> {
        self.0.connect_tcp(id, target).await
    }
    fn finish(&self, stream: Self::Stream) { drop(stream); }
    fn now(&self) -> Time { self.0.clock().now() }
    fn nonce(&self) -> u64 { self.0.entropy().next_u64() }
}

#[derive(Debug)]
struct Observation {
    connect_error: io::ErrorKind,
    raw_error: Option<i32>,
    start: u64,
    end: u64,
    nonce: u64,
    replies: (u8, u8),
}
impl Observation {
    fn digest(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.connect-observation.v1\0");
        hash.update(format!("{:?}:{:?}", self.connect_error, self.raw_error).as_bytes());
        hash.update(self.start.to_le_bytes());
        hash.update(self.end.to_le_bytes());
        hash.update(self.nonce.to_le_bytes());
        hash.update([self.replies.0, self.replies.1]);
        format!("{:x}", hash.finalize())
    }
    fn decision(&self) -> Result<(), &'static str> {
        if self.replies.1 == b'N' { Err("peer-b-denied") } else { Ok(()) }
    }
}
async fn leg(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), tag: u8, nonce: u64) -> io::Result<u8> {
    let mut request = [0; 9];
    request[0] = tag; request[1..].copy_from_slice(&nonce.to_le_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0]; stream.read_exact(&mut reply).await?;
    Ok(reply[0])
}
async fn application<B: Backend>(backend: &B, targets: Targets, reverse: bool) -> io::Result<Observation> {
    let error = match backend.connect(attempt(0), targets.refused).await {
        Err(error) => error,
        Ok(stream) => {
            backend.finish(stream);
            return Err(io::Error::other("negative control unexpectedly connected"));
        }
    };
    let start = backend.now().as_nanos();
    let nonce = backend.nonce();
    let mut a = backend.connect(attempt(1), targets.first).await?;
    let mut b = backend.connect(attempt(2), targets.second).await?;
    let (ra, rb) = {
        let mut a = std::pin::pin!(leg(&mut a, b'A', nonce));
        let mut b = std::pin::pin!(leg(&mut b, b'B', nonce));
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
    backend.finish(a); backend.finish(b);
    Ok(Observation {
        connect_error: error.kind(), raw_error: error.raw_os_error(),
        start, end: backend.now().as_nanos(), nonce, replies: (ra?, rb?),
    })
}

fn accept(listener: &TcpListener) -> StdTcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                return stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "native peer accept watchdog");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("peer accept failed: {error}"),
        }
    }
}
fn require_send<T: Send>(value: T) -> T { value }
fn offline_child() {
    let targets = Targets::decode(&std::env::var(TARGETS).unwrap());
    let expected = std::env::var(EXPECTED).unwrap();
    let mut bytes = Vec::new();
    io::stdin().take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= MAX_BYTES);
    let key = ReplayArchiveKey::new(KEY);
    let replay = key.open_group_session(&bytes, targets.binding(), MAX_BYTES, limits()).unwrap().replay();
    // No runtime, socket, live clock or entropy provider is constructed here.
    let observation = futures_lite::future::block_on(require_send(replay.run_send(128, move |session| {
        Box::pin(async move { application(&Offline(session), targets, true).await })
    }))).unwrap().unwrap();
    assert_eq!(observation.digest(), expected);
    assert_eq!(observation.decision(), Err("peer-b-denied"));

    // Causal negative: the valid failed attempt and the same clock/entropy prefix
    // replay first. Only the next destination changes. Ignoring that error must
    // not let the consumer's nominal successful output escape run_send.
    let replay = key.open_group_session(&bytes, targets.binding(), MAX_BYTES, limits()).unwrap().replay();
    let negative = futures_lite::future::block_on(require_send(replay.run_send(128, move |session| {
        Box::pin(async move {
            assert_eq!(session.connect_tcp(attempt(0), targets.refused).await.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
            session.clock().try_now().unwrap();
            session.entropy().try_next_u64().unwrap();
            assert!(session.connect_tcp(attempt(1), targets.second).await.is_err());
            "must-not-be-accepted"
        })
    })));
    assert!(matches!(negative, Err(GroupSessionRunError::Replay(_))));
}
fn fresh_process(test: &str, bytes: &[u8], targets: Targets, expected: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, "1").env(TARGETS, targets.encode()).env(EXPECTED, expected)
        .stdin(Stdio::piped()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() { assert!(status.success(), "offline child failed"); break; }
        if Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("offline replay watchdog"); }
        std::thread::sleep(Duration::from_millis(10)); // watchdog only, not replay scheduling
    }
}
fn parent(multi: bool, test: &'static str) {
    // Bind but DO NOT listen. Keeping this socket alive reserves the negative
    // target throughout the attempt, avoiding a close-and-rebind port race.
    let refused = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    refused.bind(&SockAddr::from(SocketAddr::from(([127, 0, 0, 1], 0)))).unwrap();
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let targets = Targets {
        refused: refused.local_addr().unwrap().as_socket().unwrap(),
        first: first.local_addr().unwrap(), second: second.local_addr().unwrap(),
    };
    first.set_nonblocking(true).unwrap(); second.set_nonblocking(true).unwrap();
    let (sender, receiver) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut a = accept(&first); let mut b = accept(&second);
        let mut qa = [0; 9]; let mut qb = [0; 9];
        a.read_exact(&mut qa).unwrap(); b.read_exact(&mut qb).unwrap();
        let nonce = DetEntropy::new(101).next_u64().to_le_bytes();
        assert_eq!((qa[0], qb[0]), (b'A', b'B'));
        assert_eq!(&qa[1..], &nonce); assert_eq!(&qb[1..], &nonce);
        receiver.recv_timeout(Duration::from_secs(10)).expect("real Pending read before peer response");
        a.write_all(&[nonce[0] ^ 0xa5]).unwrap(); b.write_all(b"N").unwrap();
    });
    let runtime = if multi { RuntimeBuilder::new().worker_threads(2).build().unwrap() }
        else { RuntimeBuilder::current_thread().build().unwrap() };
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let (tape, observation) = runtime.block_on_with_cx(owner, async move {
        let session = RecordingGroupSession::new(
            Arc::new(DetEntropy::new(101)), Arc::new(Clock(Instant::now())),
            GroupSessionCaptureLimits {
                max_streams: 5, max_effects: 64, per_stream: IoCaptureLimits::new(16, 64, 256, 3),
                entropy: EntropyCaptureLimits::new(8, 64, 1), clock_observations: 8,
            },
        ).unwrap();
        let result = application(&Live { session: &session, pending: &sender }, targets, false).await.unwrap();
        (session.finish().unwrap(), result)
    });
    peer.join().unwrap(); drop(refused); drop(runtime);
    assert_eq!(observation.connect_error, io::ErrorKind::ConnectionRefused);
    assert_eq!(observation.replies.0, observation.nonce.to_le_bytes()[0] ^ 0xa5);
    assert!(observation.end >= observation.start);
    assert_eq!(observation.decision(), Err("peer-b-denied"));
    assert_eq!(tape.streams(), 5); // three journals and two actual connections
    assert!(tape.effects() >= 13); // six connection + four byte + three source effects
    let expected = observation.digest();
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([if multi { 110 } else { 109 }; 16]);
    let bytes = sealer.seal_group_session(&tape, targets.binding(), MAX_BYTES).unwrap();
    drop(tape); drop(sealer);
    fresh_process(test, bytes.as_ref(), targets, &expected);
}
fn bounded(work: impl FnOnce() + Send + 'static) {
    let (sender, receiver) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _ = sender.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)));
    });
    let result = receiver.recv_timeout(Duration::from_secs(40)).expect("native connect replay watchdog");
    thread.join().unwrap();
    if let Err(payload) = result { std::panic::resume_unwind(payload); }
}
#[test]
fn failed_connect_retry_and_fresh_process_replay_current_thread() {
    if std::env::var_os(CHILD).is_some() { offline_child(); }
    else { bounded(|| parent(false, "failed_connect_retry_and_fresh_process_replay_current_thread")); }
}
#[test]
fn failed_connect_retry_and_fresh_process_replay_two_workers() {
    if std::env::var_os(CHILD).is_some() { offline_child(); }
    else { bounded(|| parent(true, "failed_connect_retry_and_fresh_process_replay_two_workers")); }
}
