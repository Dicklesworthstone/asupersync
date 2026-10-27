//! Progress-aware keepalive through the production stream owner. Virtual time
//! pins read boundaries; native runtimes prove a parked writer's timer wake.

use super::*;
use crate::runtime::RuntimeBuilder;
use std::sync::atomic::AtomicBool;

fn policy() -> NativeStreamKeepalive {
    NativeStreamKeepalive::new(Duration::from_secs(2), Duration::from_secs(1))
        .unwrap().with_progress_aware_timeout()
}

fn ack(sequence: u64) -> Vec<u8> {
    // Independent HTTP/2 PING encoding: length 8, type 6, ACK flag, stream 0.
    let mut wire = vec![0, 0, 8, 6, 1, 0, 0, 0, 0];
    wire.extend_from_slice(&sequence.to_be_bytes());
    wire
}

fn probe_count(probe: &Probe) -> usize {
    let writes = probe.writes.lock().unwrap();
    assert!(writes.starts_with(CLIENT_PREFACE));
    let mut bytes = BytesMut::from(&writes[CLIENT_PREFACE.len()..]);
    let mut decoder = FrameCodec::new();
    let mut count = 0;
    while let Some(frame) = decoder.decode(&mut bytes).unwrap() {
        if matches!(frame, Frame::Ping(ping) if !ping.ack) { count += 1; }
    }
    assert!(bytes.is_empty(), "outbound probe must be complete");
    count
}

fn owner(cx: &Cx, io: FixtureIo) -> NativeServerStream<FixtureIo, IdentityCodec> {
    NativeServerStream::new(cx, io, "localhost", "/svc/Watch",
        Request::new(Bytes::new()), IdentityCodec, NativeStreamConfig::default())
        .unwrap().with_keepalive(policy()).unwrap()
}

#[test]
fn progress_keepalive_does_not_expire_an_unsent_probe_between_buffered_messages() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
    let cx = timed_cx(&clock);
    let mut bytes = start();
    let mut payload = message(b"one");
    payload.extend(message(b"two"));
    payload.extend(message(b"three"));
    bytes.extend(frame(0, 0, &payload));
    let (io, probe) = fixture(bytes, FRAME_BYTES, false);
    let mut stream = owner(&cx, io);
    assert_eq!(run(stream.message()).unwrap().unwrap().as_ref(), b"one");
    clock.advance_to(Time::from_secs(22));
    assert_eq!(run(stream.message()).unwrap().unwrap().as_ref(), b"two");
    clock.advance_to(Time::from_secs(30));
    assert_eq!(run(stream.message()).unwrap().unwrap().as_ref(), b"three");
    assert_eq!(probe_count(&probe), 0, "consumption has not admitted a PING");

    let mut task = Context::from_waker(Waker::noop());
    assert!(stream.poll_message(&mut task).is_pending());
    assert_eq!(probe_count(&probe), 1);
    assert_eq!(stream.keepalive.as_ref().unwrap().at, Time::from_secs(31));
    clock.advance_to(Time::from_secs(31));
    assert_eq!(run(stream.message()).unwrap_err().code(), Code::Unavailable);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    assert!(run(stream.message()).unwrap().is_none());
    eprintln!("progress_keepalive case=buffered_consumer probes=1 unsent_timeout=false silent_peer=unavailable drops=1");
}

#[test]
fn progress_keepalive_resumes_an_unread_matching_ack_and_arms_the_next_probe() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
    let cx = timed_cx(&clock);
    let mut bytes = start();
    let initial = bytes.len();
    bytes.extend(ack(1));
    bytes.extend(frame(0, 0, &message(b"after-ack")));
    let (io, probe) = fixture(bytes, FRAME_BYTES, false);
    probe.readable.store(initial, Ordering::SeqCst);
    let mut stream = owner(&cx, io);
    run(stream.headers()).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    clock.advance_to(Time::from_secs(22));
    assert!(stream.poll_message(&mut task).is_pending());
    assert_eq!(probe_count(&probe), 1);
    probe.readable.store(usize::MAX, Ordering::SeqCst);
    clock.advance_to(Time::from_secs(30));
    assert_eq!(run(stream.message()).unwrap().unwrap().as_ref(), b"after-ack");
    assert!(matches!(stream.keepalive.as_ref().unwrap().state, ProbeState::Idle));
    assert_eq!(stream.keepalive.as_ref().unwrap().at, Time::from_secs(32));
    assert!(stream.status().is_none());
    clock.advance_to(Time::from_secs(32));
    assert!(stream.poll_message(&mut task).is_pending());
    assert_eq!(probe_count(&probe), 2);
    clock.advance_to(Time::from_secs(33));
    assert_eq!(run(stream.message()).unwrap_err().code(), Code::Unavailable);
    assert!(!cx.is_cancel_requested());
    eprintln!("progress_keepalive case=unread_ack resumed=true probes=2 next_timeout=unavailable");
}

#[test]
fn progress_keepalive_noise_gets_one_bounded_read_pass() {
    for noise in [POLL_STEPS - 1, POLL_STEPS] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
        let cx = timed_cx(&clock);
        let mut bytes = start();
        let initial = bytes.len();
        for _ in 0..noise { bytes.extend(ack(99)); }
        bytes.extend(ack(1));
        bytes.extend(frame(0, 0, &message(b"alive")));
        let (io, probe) = fixture(bytes, FRAME_BYTES, false);
        probe.readable.store(initial, Ordering::SeqCst);
        let mut stream = owner(&cx, io);
        run(stream.headers()).unwrap();
        let mut task = Context::from_waker(Waker::noop());
        clock.advance_to(Time::from_secs(22));
        assert!(stream.poll_message(&mut task).is_pending());
        probe.readable.store(usize::MAX, Ordering::SeqCst);
        clock.advance_to(Time::from_secs(23));
        let reads_before = probe.read_calls.load(Ordering::SeqCst);
        let result = stream.poll_message(&mut task);
        if noise < POLL_STEPS {
            assert!(matches!(result, Poll::Ready(Some(Ok(ref value))) if value.as_ref() == b"alive"));
            stream.cancel();
        } else {
            assert!(matches!(result, Poll::Ready(Some(Err(ref status))) if status.code() == Code::Unavailable));
            assert!(stream.keepalive.is_none());
        }
        assert!(probe.read_calls.load(Ordering::SeqCst) - reads_before <= POLL_STEPS);
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        eprintln!("progress_keepalive case=noise frames={noise} recovered={} drops=1", noise < POLL_STEPS);
    }
}

#[test]
fn progress_keepalive_ready_traffic_cannot_recover_exhausted_probe_identifiers() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
    let cx = timed_cx(&clock);
    let mut bytes = start();
    let initial = bytes.len();
    bytes.extend(ack(99));
    bytes.extend(frame(0, 0, &message(b"still-open")));
    let (io, probe) = fixture(bytes, FRAME_BYTES, false);
    probe.readable.store(initial, Ordering::SeqCst);
    let mut stream = owner(&cx, io);
    run(stream.headers()).unwrap();
    stream.keepalive.as_mut().unwrap().sequence = u64::MAX;
    probe.readable.store(usize::MAX, Ordering::SeqCst);
    clock.advance_to(Time::from_secs(22));
    let error = run(stream.message()).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(error.message().contains("identifiers exhausted"));
    assert_eq!(probe_count(&probe), 0);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    eprintln!("progress_keepalive case=identifier_exhaustion recovered=false probes=0 drops=1");
}

#[test]
fn progress_keepalive_does_not_wait_for_an_incomplete_ack_or_replace_terminal_status() {
    for terminal in [false, true] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
        let cx = timed_cx(&clock);
        let mut bytes = start();
        let initial = bytes.len();
        if terminal {
            bytes.extend(headers(&[("grpc-status", "7"), ("grpc-message", "finished")], true));
        } else {
            bytes.extend(ack(1));
        }
        let (io, probe) = fixture(bytes, FRAME_BYTES, false);
        probe.readable.store(initial, Ordering::SeqCst);
        let mut stream = owner(&cx, io);
        run(stream.headers()).unwrap();
        let mut task = Context::from_waker(Waker::noop());
        clock.advance_to(Time::from_secs(22));
        assert!(stream.poll_message(&mut task).is_pending());
        probe.readable.store(if terminal { usize::MAX } else { initial + 12 }, Ordering::SeqCst);
        clock.advance_to(Time::from_secs(23));
        let error = run(stream.message()).unwrap_err();
        assert_eq!(error.code(), if terminal { Code::PermissionDenied } else { Code::Unavailable });
        if terminal { assert_eq!(error.message(), "finished"); }
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        assert!(run(stream.message()).unwrap().is_none());
        eprintln!("progress_keepalive case=ready_input terminal={terminal} status={:?} drops=1", error.code());
    }
}

struct AdvanceOnRead {
    inner: FixtureIo,
    clock: Arc<VirtualClock>,
    armed: Arc<AtomicBool>,
}

impl AsyncRead for AdvanceOnRead {
    fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_read(task, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && this.armed.swap(false, Ordering::SeqCst) {
            this.clock.advance_to(Time::from_secs(23));
        }
        polled
    }
}

impl AsyncWrite for AdvanceOnRead {
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(task, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(task)
    }

    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(task)
    }
}

#[test]
fn progress_keepalive_checks_ready_frames_when_a_read_crosses_the_deadline() {
    for terminal in [false, true] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
        let cx = timed_cx(&clock);
        let mut bytes = start();
        let initial = bytes.len();
        // The first frame crosses the deadline without satisfying the probe.
        // gate must then inspect the following ready ACK/terminal, boundedly.
        bytes.extend(ack(99));
        if terminal {
            bytes.extend(headers(&[("grpc-status", "7")], true));
        } else {
            bytes.extend(ack(1));
            bytes.extend(frame(0, 0, &message(b"crossed")));
        }
        let (inner, probe) = fixture(bytes, FRAME_BYTES, false);
        probe.readable.store(initial, Ordering::SeqCst);
        let armed = Arc::new(AtomicBool::new(false));
        let io = AdvanceOnRead { inner, clock: Arc::clone(&clock), armed: Arc::clone(&armed) };
        let mut stream = NativeServerStream::new(&cx, io, "localhost", "/svc/Watch",
            Request::new(Bytes::new()), IdentityCodec, NativeStreamConfig::default())
            .unwrap().with_keepalive(policy()).unwrap();
        run(stream.headers()).unwrap();
        let mut task = Context::from_waker(Waker::noop());
        clock.advance_to(Time::from_secs(22));
        assert!(stream.poll_message(&mut task).is_pending());
        probe.readable.store(usize::MAX, Ordering::SeqCst);
        armed.store(true, Ordering::SeqCst);
        let result = run(stream.message());
        assert!(!armed.load(Ordering::SeqCst), "the real read path must cross the deadline");
        if terminal {
            assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
        } else {
            assert_eq!(result.unwrap().unwrap().as_ref(), b"crossed");
            stream.cancel();
        }
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        eprintln!("progress_keepalive case=read_crossing terminal={terminal} timeout_overridden=true drops=1");
    }
}

fn native_case<F, Fut>(multithread: bool, scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    let complete = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&complete);
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("native progress keepalive context");
        let clock = cx.timer_driver().unwrap();
        crate::time::timeout(clock.now(), Duration::from_secs(5), scenario(cx))
            .await.expect("native progress keepalive watchdog");
        complete.store(true, Ordering::Release);
    }));
    assert!(observed.load(Ordering::Acquire), "native progress keepalive assertions did not finish");
}

#[test]
fn native_progress_keepalive_survives_consumer_pauses_and_unread_ack() {
    for multithread in [false, true] {
        native_case(multithread, move |cx| async move {
            let mut bytes = start();
            let mut payload = message(b"one");
            payload.extend(message(b"two"));
            payload.extend(message(b"three"));
            bytes.extend(frame(0, 0, &payload));
            let before_ack = bytes.len();
            bytes.extend(ack(1));
            bytes.extend(frame(0, 0, &message(b"four")));
            let (io, probe) = fixture(bytes, FRAME_BYTES, false);
            probe.readable.store(before_ack, Ordering::SeqCst);
            let mut stream = NativeServerStream::new(&cx, io, "localhost", "/svc/Watch",
                Request::new(Bytes::new()), IdentityCodec, NativeStreamConfig::default()).unwrap();
            assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"one");
            let mut stream = stream.with_keepalive(NativeStreamKeepalive::new(
                Duration::from_millis(25), Duration::from_millis(25),
            ).unwrap().with_progress_aware_timeout()).unwrap();
            let clock = cx.timer_driver().unwrap();
            Sleep::with_timer_driver(stream.keepalive.as_ref().unwrap().at, clock.clone()).await;
            assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"two");
            Sleep::with_timer_driver(clock.now() + Duration::from_millis(50), clock.clone()).await;
            assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"three");
            assert_eq!(probe_count(&probe), 0);
            {
                let mut wait = Box::pin(stream.message());
                poll_fn(|task| {
                    assert!(wait.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
            }
            assert_eq!(probe_count(&probe), 1);
            probe.readable.store(usize::MAX, Ordering::SeqCst);
            Sleep::with_timer_driver(stream.keepalive.as_ref().unwrap().at, clock).await;
            assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"four");
            assert!(stream.status().is_none());
            stream.cancel();
            assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
            assert!(!cx.is_cancel_requested());
            eprintln!("progress_keepalive case=native_pause multithread={multithread} queued_probe_survived=true unread_ack_recovered=true drops=1");
        });
    }
}

struct WriteGate {
    allowance: AtomicUsize,
    block_flush: AtomicBool,
    parked: AtomicUsize,
}

struct GatedIo { inner: FixtureIo, gate: Arc<WriteGate> }

impl AsyncRead for GatedIo {
    fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(task, buf)
    }
}

impl AsyncWrite for GatedIo {
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let allowance = this.gate.allowance.load(Ordering::SeqCst);
        if allowance == 0 {
            this.gate.parked.fetch_add(1, Ordering::SeqCst);
            return Poll::Pending; // No I/O wake: only the admitted timer can rescue the owner.
        }
        let polled = Pin::new(&mut this.inner).poll_write(task, &bytes[..bytes.len().min(allowance)]);
        if let Poll::Ready(Ok(written)) = &polled {
            if allowance != usize::MAX { this.gate.allowance.fetch_sub(*written, Ordering::SeqCst); }
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.gate.block_flush.load(Ordering::SeqCst) {
            this.gate.parked.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        } else {
            Pin::new(&mut this.inner).poll_flush(task)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(task)
    }
}

#[test]
fn native_progress_keepalive_timer_retires_never_waking_partial_writes_and_flushes() {
    for multithread in [false, true] {
        for block_flush in [false, true] {
            native_case(multithread, move |cx| async move {
                let (inner, probe) = fixture(start(), FRAME_BYTES, false);
                let gate = Arc::new(WriteGate { allowance: AtomicUsize::new(usize::MAX),
                    block_flush: AtomicBool::new(false), parked: AtomicUsize::new(0) });
                let io = GatedIo { inner, gate: Arc::clone(&gate) };
                let mut stream = NativeServerStream::new(&cx, io, "localhost", "/svc/Watch",
                    Request::new(Bytes::new()), IdentityCodec, NativeStreamConfig::default()).unwrap();
                stream.headers().await.unwrap();
                let before = probe.writes.lock().unwrap().len();
                gate.block_flush.store(block_flush, Ordering::SeqCst);
                if !block_flush { gate.allowance.store(5, Ordering::SeqCst); }
                let mut stream = stream.with_keepalive(NativeStreamKeepalive::new(
                    Duration::from_millis(25), Duration::from_millis(25),
                ).unwrap().with_progress_aware_timeout()).unwrap();
                let started = std::time::Instant::now();
                let error = stream.message().await.unwrap_err();
                assert_eq!(error.code(), Code::Unavailable);
                assert!(error.message().contains("keepalive"));
                // The outer five-second watchdog must not supply the wake
                // that a missing admission-time timer registration would lose.
                assert!(started.elapsed() < Duration::from_secs(2), "probe timer did not wake its parked owner");
                let parked = gate.parked.load(Ordering::SeqCst);
                assert!(parked > 0 && parked <= 32, "deadline must retire without spinning: {parked}");
                assert_eq!(probe.writes.lock().unwrap().len() - before, if block_flush { 17 } else { 5 });
                assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
                assert!(stream.keepalive.is_none() && stream.outbound.is_empty());
                assert!(stream.message().await.unwrap().is_none());
                assert!(!cx.is_cancel_requested());
                eprintln!("progress_keepalive case=native_park multithread={multithread} flush={block_flush} parked_polls={parked} status=unavailable drops=1");
            });
        }
    }
}
