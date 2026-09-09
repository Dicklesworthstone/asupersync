//! GH#67 follow-up (asupersync-tx9j0f): every socket type that selects its
//! reactor from the current `Cx` must park, not spin, when polled under the
//! documented caller-driven composition — a plain executor
//! (`futures_lite::block_on`) with no runtime turning a reactor and no
//! ambient `Cx` at all.
//!
//! GH#67 (commit 616af91b5) fixed this for `UdpSocket` by parking driverless
//! registrations on a process-global fallback I/O driver; `TcpStream`,
//! `UnixStream`, `UnixDatagram` and `UnixListener` kept the immediate
//! self-wake, so a bounded wait on any of them burned a full core. This test
//! measures process CPU (`utime + stime` from `/proc/self/stat`) across an
//! idle window for each of the four socket types while its peer stays silent,
//! then releases the wait and checks the socket saw exactly the readiness it
//! was promised.
//!
//! The idle window opens only after the waiting side has acknowledged its
//! first `Pending` poll (an explicit handshake, not a settle sleep), and every
//! wait on the helper is bounded so a regression fails instead of hanging.
//!
//! Gating: `test-internals` (for the fallback driver probe) and Linux (the CPU
//! accounting reads `/proc/self/stat`). This file intentionally holds a single
//! test so the process-wide CPU accounting is not polluted by sibling tests on
//! other threads; the four socket types are measured one after another.

#![cfg(all(feature = "test-internals", target_os = "linux"))]
#![allow(missing_docs)]

use std::future::poll_fn;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::net::{UnixDatagram as StdUnixDatagram, UnixStream as StdUnixStream};
use std::pin::Pin;
use std::sync::mpsc::{self, Sender};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::unix::{UnixDatagram, UnixListener, UnixStream};
use asupersync::net::{TcpStream, fallback_io_driver_probe};
use futures_lite::future::block_on;

/// The idle window measured per socket type.
const IDLE_WINDOW: Duration = Duration::from_millis(800);
/// Bound on every wait for the helper thread: its first `Pending` poll, and
/// its completion after the peer releases it.
const HELPER_BOUND: Duration = Duration::from_secs(10);
/// Generous bound: a parked wait costs ~0 %, the defect costs ~100 %. The
/// slack absorbs shared-worker noise.
const MAX_IDLE_CPU_PERCENT: u64 = 15;
/// `/proc/self/stat` utime/stime are reported in `USER_HZ` ticks, which Linux
/// fixes at 100 for the procfs ABI independent of the kernel's `CONFIG_HZ`.
const USER_HZ: u64 = 100;

/// Process CPU time in `USER_HZ` ticks: field 14 (`utime`) + field 15
/// (`stime`) of `/proc/self/stat`, indexed after the `)` that terminates the
/// command name so a space in the name cannot shift the fields.
fn process_cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    let close = stat.rfind(')').expect("process stat comm terminator");
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let user: u64 = fields[11].parse().expect("process utime ticks");
    let system: u64 = fields[12].parse().expect("process stime ticks");
    user + system
}

#[derive(Debug, Clone, Copy)]
struct IdleOutcome {
    wall_ms: u64,
    cpu_ms: u64,
    cpu_fraction_percent: u64,
}

/// Handed to the waiting side; it reports every `Pending` poll so the
/// measuring side knows the wait has actually parked (or started spinning)
/// before the idle window opens.
#[derive(Clone)]
struct PendingSignal(Sender<()>);

impl PendingSignal {
    fn note<T>(&self, poll: Poll<T>) -> Poll<T> {
        if poll.is_pending() {
            let _ = self.0.send(());
        }
        poll
    }
}

/// Runs `wait` on a helper thread under `futures_lite::block_on` (no runtime,
/// no ambient `Cx`), opens the idle window once the helper has reported its
/// first `Pending` poll, accounts process CPU across the window while the peer
/// stays silent, then runs `release` (which makes the fd ready) and waits,
/// bounded, for the helper's result.
fn measure_driverless_wait<T: Send + 'static>(
    label: &str,
    wait: impl FnOnce(PendingSignal) -> T + Send + 'static,
    release: impl FnOnce(),
) -> (IdleOutcome, T) {
    let (pending_tx, pending_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let helper = thread::spawn(move || {
        assert!(
            Cx::current().is_none(),
            "the helper must poll with no ambient Cx"
        );
        let value = wait(PendingSignal(pending_tx));
        let _ = result_tx.send(value);
    });
    pending_rx
        .recv_timeout(HELPER_BOUND)
        .unwrap_or_else(|_| panic!("{label}: the wait never reported a Pending poll"));

    let ticks_before = process_cpu_ticks();
    let started = Instant::now();
    thread::sleep(IDLE_WINDOW);
    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let ticks = process_cpu_ticks().saturating_sub(ticks_before);
    let cpu_ms = ticks.saturating_mul(1000) / USER_HZ;
    let outcome = IdleOutcome {
        wall_ms,
        cpu_ms,
        cpu_fraction_percent: cpu_ms.saturating_mul(100) / wall_ms.max(1),
    };

    release();
    let value = result_rx
        .recv_timeout(HELPER_BOUND)
        .unwrap_or_else(|_| panic!("{label}: the wait did not complete after its peer released it"));
    helper
        .join()
        .unwrap_or_else(|_| panic!("{label}: helper thread panicked"));
    (outcome, value)
}

/// Records a spinning wait instead of panicking immediately, so one run
/// reports every socket type that still spins (the old-code RED receipt
/// names all four, not just the first).
fn note_if_spinning(failures: &mut Vec<String>, label: &str, outcome: IdleOutcome) {
    if outcome.cpu_fraction_percent > MAX_IDLE_CPU_PERCENT {
        failures.push(format!(
            "{label}: a driverless wait must park, not spin (GH#67 / tx9j0f): \
             {cpu} ms of CPU over a {wall} ms idle window ({percent} %, limit {limit} %)",
            cpu = outcome.cpu_ms,
            wall = outcome.wall_ms,
            percent = outcome.cpu_fraction_percent,
            limit = MAX_IDLE_CPU_PERCENT,
        ));
    }
}

/// Reads one chunk from an `AsyncRead` under `block_on`, reporting every
/// `Pending` poll on `signal`, and returns the bytes.
fn read_one_chunk<R: AsyncRead + Unpin>(mut reader: R, signal: &PendingSignal) -> Vec<u8> {
    block_on(poll_fn(|cx: &mut Context<'_>| {
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);
        let poll = match Pin::new(&mut reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(read_buf.filled().to_vec()),
            Poll::Ready(Err(err)) => panic!("driverless read failed: {err}"),
            Poll::Pending => Poll::Pending,
        };
        signal.note(poll)
    }))
}

#[test]
fn driverless_socket_waits_park_instead_of_spinning() {
    assert!(Cx::current().is_none(), "test must run without an ambient Cx");
    let before = fallback_io_driver_probe().unwrap_or_default();
    let mut failures = Vec::new();

    // TCP stream: the async side connects (driverless connect completes on
    // loopback), the std peer stays silent for the window, then writes.
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind std listener");
    let addr: SocketAddr = listener.local_addr().expect("listener addr");
    let (accept_tx, accept_rx) = mpsc::channel();
    let acceptor = thread::spawn(move || {
        let (peer, _) = listener.accept().expect("accept the async side");
        accept_tx.send(()).expect("report accept");
        peer
    });
    let (tcp_outcome, tcp_bytes) = measure_driverless_wait(
        "tcp stream read",
        move |signal| {
            let stream = block_on(TcpStream::connect(addr)).expect("driverless connect");
            read_one_chunk(stream, &signal)
        },
        || {
            accept_rx
                .recv_timeout(HELPER_BOUND)
                .expect("async side accepted");
            let mut peer = acceptor.join().expect("acceptor thread");
            peer.write_all(b"tcp").expect("peer write");
        },
    );
    note_if_spinning(&mut failures, "tcp stream read", tcp_outcome);
    assert_eq!(tcp_bytes, b"tcp", "tcp stream read returned the released bytes");

    // Unix stream pair.
    let (unix_stream, unix_peer) = UnixStream::pair().expect("unix stream pair");
    let (unix_outcome, unix_bytes) = measure_driverless_wait(
        "unix stream read",
        move |signal| read_one_chunk(unix_stream, &signal),
        || {
            let mut writer = unix_peer.as_std();
            writer.write_all(b"unix").expect("peer write");
        },
    );
    note_if_spinning(&mut failures, "unix stream read", unix_outcome);
    assert_eq!(
        unix_bytes, b"unix",
        "unix stream read returned the released bytes"
    );

    // Unix datagram pair: readiness poll on the async side, std peer sends.
    let (dgram_std, dgram_peer) = StdUnixDatagram::pair().expect("unix datagram pair");
    let mut dgram = UnixDatagram::from_std(dgram_std).expect("wrap datagram");
    let (dgram_outcome, dgram_bytes) = measure_driverless_wait(
        "unix datagram recv",
        move |signal| {
            block_on(poll_fn(|cx| signal.note(dgram.poll_recv_ready(cx)))).expect("recv readiness");
            let mut buf = [0u8; 16];
            let len = dgram.as_std().recv(&mut buf).expect("recv the datagram");
            buf[..len].to_vec()
        },
        || {
            dgram_peer.send(b"dgram").expect("peer send");
        },
    );
    note_if_spinning(&mut failures, "unix datagram recv", dgram_outcome);
    assert_eq!(
        dgram_bytes, b"dgram",
        "unix datagram recv returned the released datagram"
    );

    // Unix listener: accept waits for a std peer to connect.
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("driverless_idle.sock");
    let unix_listener = block_on(UnixListener::bind(&path)).expect("bind unix listener");
    let connect_path = path.clone();
    let (accept_outcome, accepted) = measure_driverless_wait(
        "unix listener accept",
        move |signal| {
            block_on(poll_fn(|cx| signal.note(unix_listener.poll_accept(cx)))).map(|_| ())
        },
        || {
            let _peer = StdUnixStream::connect(&connect_path).expect("peer connect");
            // Keep the peer alive until the accept has returned.
            thread::sleep(Duration::from_millis(200));
        },
    );
    note_if_spinning(&mut failures, "unix listener accept", accept_outcome);
    accepted.expect("unix listener accepted the released connection");

    assert!(
        failures.is_empty(),
        "driverless waits that spun instead of parking:\n{}",
        failures.join("\n")
    );

    let after = fallback_io_driver_probe().expect("driverless polls start the fallback driver");
    assert!(
        after.fallback_registrations >= before.fallback_registrations + 4,
        "each socket type must register on the fallback driver: {after:?} vs {before:?}"
    );
    assert_eq!(
        after.fallback_self_wakes, before.fallback_self_wakes,
        "no driverless poll may fall back to a self-wake: {after:?} vs {before:?}"
    );
}
