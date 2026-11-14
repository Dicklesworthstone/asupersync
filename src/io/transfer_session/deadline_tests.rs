use super::*;
use crate::io::{AsyncReadVectored, AsyncWrite, BidirectionalCopySession, CopySession};
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelReason, RegionId, TaskId};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Wake, Waker};

const DEADLINE: Time = Time::from_millis(100);

fn owner(budget: Budget, driver: TimerDriverHandle) -> Cx {
    Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(0, 0),
        budget,
        None,
        None,
        None,
        Some(driver),
        None,
    )
}

fn virtual_owner(budget: Budget) -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::new());
    let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    (owner(budget, driver.clone()), clock, driver)
}

fn registrations(cx: &Cx) -> usize {
    cx.inner.read().cancel_waker_registrations.len()
}

#[derive(Default)]
struct Probe {
    read: AtomicUsize,
    written: parking_lot::Mutex<Vec<u8>>,
    polls: AtomicUsize,
    pending: AtomicUsize,
    flushes: AtomicUsize,
    shutdowns: AtomicUsize,
}

struct Endpoint {
    input: &'static [u8],
    pos: usize,
    read_limit: usize,
    write_limit: usize,
    release: Arc<AtomicBool>,
    probe: Arc<Probe>,
}

impl Endpoint {
    fn new(
        input: &'static [u8],
        read_limit: usize,
        write_limit: usize,
        release: &Arc<AtomicBool>,
    ) -> (Self, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        (
            Self {
                input,
                pos: 0,
                read_limit,
                write_limit,
                release: Arc::clone(release),
                probe: Arc::clone(&probe),
            },
            probe,
        )
    }
}

impl AsyncRead for Endpoint {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.probe.polls.fetch_add(1, Ordering::SeqCst);
        if this.pos == this.input.len() {
            return Poll::Ready(Ok(()));
        }
        let limit = if this.release.load(Ordering::Acquire) {
            this.input.len()
        } else {
            this.read_limit.min(this.input.len())
        };
        if this.pos >= limit {
            this.probe.pending.fetch_add(1, Ordering::SeqCst);
            return Poll::Pending;
        }
        let n = buffer.remaining().min(limit - this.pos);
        buffer.put_slice(&this.input[this.pos..this.pos + n]);
        this.pos += n;
        this.probe.read.fetch_add(n, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

// Exercise the public scalar fallback while the session owns a vectored cursor.
impl AsyncReadVectored for Endpoint {}

impl AsyncWrite for Endpoint {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.probe.polls.fetch_add(1, Ordering::SeqCst);
        let mut written = this.probe.written.lock();
        let remaining = if this.release.load(Ordering::Acquire) {
            bytes.len()
        } else {
            this.write_limit.saturating_sub(written.len())
        };
        if remaining == 0 && !bytes.is_empty() {
            this.probe.pending.fetch_add(1, Ordering::SeqCst);
            return Poll::Pending;
        }
        let n = remaining.min(bytes.len());
        written.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.probe.flushes.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.probe.shutdowns.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn dropping_a_bounded_run_keeps_the_read_prefix_and_retires_its_waits() {
    let (cx, _, driver) = virtual_owner(Budget::INFINITE);
    let release = Arc::new(AtomicBool::new(false));
    let (reader, probe) = Endpoint::new(b"abcdef", 2, usize::MAX, &release);
    let mut buffer = [0; 6];
    let mut session = ReadExactSession::new(reader, &mut buffer);
    let mut task = Context::from_waker(Waker::noop());
    let mut run = Box::pin(session.run_until(&cx, DEADLINE));
    assert!(run.as_mut().poll(&mut task).is_pending());
    assert_eq!(driver.pending_count(), 1);
    assert_eq!(registrations(&cx), 2);
    drop(run);
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    assert_eq!(session.filled(), b"ab");
    assert_eq!(session.bytes_read(), 2);
    release.store(true, Ordering::Release);
    let mut run = Box::pin(session.run_until(&cx, DEADLINE));
    assert!(matches!(run.as_mut().poll(&mut task), Poll::Ready(Ok(6))));
    // Resources retire at Ready, even while the completed future is retained.
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    drop(run);
    assert_eq!(session.filled(), b"abcdef");
    assert_eq!(probe.read.load(Ordering::SeqCst), 6);
}

#[test]
fn dropping_a_bounded_copy_keeps_both_endpoints_and_unwritten_read_ahead() {
    let (cx, _, driver) = virtual_owner(Budget::INFINITE);
    let release = Arc::new(AtomicBool::new(false));
    let (reader, reads) = Endpoint::new(b"abcdef", usize::MAX, usize::MAX, &release);
    let (writer, writes) = Endpoint::new(b"", usize::MAX, 2, &release);
    let mut session = CopySession::new(reader, writer);
    let mut task = Context::from_waker(Waker::noop());
    let mut run = Box::pin(session.run_until(&cx, DEADLINE));
    assert!(run.as_mut().poll(&mut task).is_pending());
    assert_eq!(driver.pending_count(), 1);
    assert_eq!(registrations(&cx), 2);
    drop(run);
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    assert_eq!(session.progress().read, 6);
    assert_eq!(session.progress().written, 2);
    assert_eq!(session.pending_bytes(), b"cdef");
    release.store(true, Ordering::Release);
    let mut run = Box::pin(session.run_until(&cx, DEADLINE));
    assert!(matches!(run.as_mut().poll(&mut task), Poll::Ready(Ok(6))));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    drop(run);
    assert!(session.is_complete());
    assert_eq!(reads.read.load(Ordering::SeqCst), 6);
    assert_eq!(&*writes.written.lock(), b"abcdef");
    assert_eq!(writes.flushes.load(Ordering::SeqCst), 1);
}

#[test]
fn timeout_preserves_a_completed_half_close_while_the_other_direction_is_parked() {
    let (cx, clock, driver) = virtual_owner(Budget::INFINITE);
    let release = Arc::new(AtomicBool::new(false));
    let (a, a_probe) = Endpoint::new(b"", usize::MAX, 2, &release);
    let (b, b_probe) = Endpoint::new(b"uvwxyz", usize::MAX, usize::MAX, &release);
    let mut session = BidirectionalCopySession::new(a, b);
    let mut task = Context::from_waker(Waker::noop());
    let mut run = Box::pin(session.run_until(&cx, DEADLINE));
    assert!(run.as_mut().poll(&mut task).is_pending());
    assert_eq!(b_probe.shutdowns.load(Ordering::SeqCst), 1);
    clock.advance_to(DEADLINE);
    assert_eq!(driver.process_timers(), 1);
    assert!(matches!(run.as_mut().poll(&mut task), Poll::Ready(Err(error))
        if error.kind() == io::ErrorKind::TimedOut));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    drop(run);
    assert!(session.progress().a_to_b.write_shutdown);
    assert_eq!(session.pending_b_to_a(), b"wxyz");
    release.store(true, Ordering::Release);
    let mut run = Box::pin(session.run_until(&cx, Time::from_millis(200)));
    assert!(matches!(run.as_mut().poll(&mut task), Poll::Ready(Ok((0, 6)))));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    drop(run);
    assert!(session.is_complete());
    assert_eq!(&*a_probe.written.lock(), b"uvwxyz");
    assert_eq!(a_probe.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(b_probe.shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_active_sessions_do_not_poll_but_completed_sessions_keep_their_result() {
    let (cx, _, driver) = virtual_owner(Budget::INFINITE);
    let release = Arc::new(AtomicBool::new(true));
    let (reader, probe) = Endpoint::new(b"abcdef", 6, usize::MAX, &release);
    let mut buffer = [0; 6];
    let mut session = ReadExactSession::new(reader, &mut buffer);
    let mut task = Context::from_waker(Waker::noop());
    let mut expired = Box::pin(session.run_until(&cx, Time::ZERO));
    assert!(matches!(expired.as_mut().poll(&mut task), Poll::Ready(Err(error))
        if error.kind() == io::ErrorKind::TimedOut));
    drop(expired);
    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
    let mut run = Box::pin(session.run_until(&cx, DEADLINE));
    assert!(matches!(run.as_mut().poll(&mut task), Poll::Ready(Ok(6))));
    drop(run);
    cx.cancel_with_reason(CancelReason::user("already finished"));
    let mut cached = Box::pin(session.run_until(&cx, Time::ZERO));
    assert!(matches!(cached.as_mut().poll(&mut task), Poll::Ready(Ok(6))));
    assert_eq!(probe.polls.load(Ordering::SeqCst), 1);
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn masked_owner_budget_rearms_once_and_explicit_deadline_still_expires() {
    let (cx, clock, driver) =
        virtual_owner(Budget::INFINITE.with_deadline(Time::from_millis(10)));
    let release = Arc::new(AtomicBool::new(false));
    let (reader, _) = Endpoint::new(b"abcdef", 2, usize::MAX, &release);
    let mut buffer = [0; 6];
    let mut session = ReadExactSession::new(reader, &mut buffer);
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut task = Context::from_waker(&waker);
    let mut run = Box::pin(session.run_until(&cx, DEADLINE));
    cx.masked(|| {
        assert!(run.as_mut().poll(&mut task).is_pending());
        assert_eq!(driver.next_deadline(), Some(Time::from_millis(10)));
        clock.advance_to(Time::from_millis(10));
        assert_eq!(driver.process_timers(), 1);
        wakes.0.store(0, Ordering::SeqCst);
        for _ in 0..3 {
            assert!(run.as_mut().poll(&mut task).is_pending());
            assert_eq!(driver.pending_count(), 1);
            assert_eq!(driver.next_deadline(), Some(DEADLINE));
            assert_eq!(registrations(&cx), 2);
            assert_eq!(wakes.0.load(Ordering::SeqCst), 0, "no masked spin");
        }
        clock.advance_to(DEADLINE);
        assert_eq!(driver.process_timers(), 1);
        assert!(matches!(run.as_mut().poll(&mut task), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::TimedOut));
        assert!(driver.is_empty());
        assert_eq!(registrations(&cx), 0);
    });
    drop(run);
    assert_eq!(session.filled(), b"ab");
}

#[test]
fn masked_cancellation_keeps_the_unmask_wake_without_advancing_time() {
    for request_before_poll in [false, true] {
        let (cx, _, driver) = virtual_owner(Budget::INFINITE);
        let release = Arc::new(AtomicBool::new(false));
        let (reader, _) = Endpoint::new(b"abcdef", 2, usize::MAX, &release);
        let mut buffer = [0; 6];
        let mut session = ReadExactSession::new(reader, &mut buffer);
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task = Context::from_waker(&waker);
        let mut run = Box::pin(session.run_until(&cx, DEADLINE));
        let reason = CancelReason::user("masked owner stopped");
        cx.masked(|| {
            if request_before_poll {
                cx.cancel_with_reason(reason.clone());
            }
            assert!(run.as_mut().poll(&mut task).is_pending());
            if !request_before_poll {
                cx.cancel_with_reason(reason.clone());
            }
            assert!(run.as_mut().poll(&mut task).is_pending());
            assert_eq!(registrations(&cx), 2);
            wakes.0.store(0, Ordering::SeqCst);
        });
        assert!(wakes.0.load(Ordering::SeqCst) > 0, "unmask must wake the run");
        assert!(matches!(run.as_mut().poll(&mut task), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::Interrupted));
        assert_eq!(cx.cancel_reason(), Some(reason));
        assert_eq!(driver.now(), Time::ZERO);
        assert!(driver.is_empty());
        assert_eq!(registrations(&cx), 0);
    }
}

struct CrossingReader {
    clock: Arc<VirtualClock>,
    error: bool,
}

impl AsyncRead for CrossingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.clock.advance_to(Time::from_millis(101));
        if self.error {
            Poll::Ready(Err(io::Error::from_raw_os_error(17)))
        } else {
            buffer.put_slice(b"abcdef");
            Poll::Ready(Ok(()))
        }
    }
}

#[test]
fn synchronous_ready_results_preserve_their_identity_when_crossing_the_deadline() {
    for error in [false, true] {
        let (cx, clock, driver) = virtual_owner(Budget::INFINITE);
        let mut buffer = [0; 6];
        let mut session = ReadExactSession::new(CrossingReader { clock, error }, &mut buffer);
        let mut run = Box::pin(session.run_until(&cx, DEADLINE));
        let result = run.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        if error {
            assert!(matches!(result, Poll::Ready(Err(error)) if error.raw_os_error() == Some(17)));
        } else {
            assert!(matches!(result, Poll::Ready(Ok(6))));
        }
        assert!(driver.is_empty());
        assert_eq!(registrations(&cx), 0);
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use crate::sync::Notify;
    use crate::types::{CancelKind, Outcome};
    use std::io::{IoSlice, IoSliceMut};
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Read,
        Write,
        ReadVectored,
        WriteVectored,
        Copy,
        Bidirectional,
    }

    const KINDS: [Kind; 6] = [
        Kind::Read,
        Kind::Write,
        Kind::ReadVectored,
        Kind::WriteVectored,
        Kind::Copy,
        Kind::Bidirectional,
    ];

    #[derive(Clone, Copy, Debug)]
    enum Stop {
        Deadline,
        OwnerBudget,
        Cancel,
        MaskedCancel,
    }

    fn reason() -> CancelReason {
        CancelReason::user("native I/O owner stopped")
            .with_cause(CancelReason::shutdown().with_message("service ended"))
    }

    #[derive(Default)]
    struct Controls {
        release: Arc<AtomicBool>,
        parked: AtomicBool,
        waker: parking_lot::Mutex<Option<Waker>>,
    }

    impl Controls {
        fn rescue(&self) {
            self.release.store(true, Ordering::Release);
            let waker = self.waker.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    struct Watchdog {
        done: Option<mpsc::Sender<()>>,
        thread: Option<JoinHandle<()>>,
    }

    impl Watchdog {
        fn start(controls: Arc<Controls>, started: Arc<Notify>, fired: Arc<AtomicBool>) -> Self {
            let (done, receiver) = mpsc::channel();
            let thread = thread::spawn(move || {
                if matches!(
                    receiver.recv_timeout(Duration::from_secs(5)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    fired.store(true, Ordering::Release);
                    controls.rescue();
                    let _ = started.notify_one();
                }
            });
            Self {
                done: Some(done),
                thread: Some(thread),
            }
        }
    }

    impl Drop for Watchdog {
        fn drop(&mut self) {
            if let Some(done) = self.done.take() {
                let _ = done.send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    async fn stopped<T>(
        future: impl Future<Output = io::Result<T>>,
        cx: &Cx,
        driver: &TimerDriverHandle,
        controls: &Controls,
        started: &Notify,
        stop: Stop,
    ) {
        let mut future = std::pin::pin!(future);
        let result = poll_fn(|task| {
            let old = controls.waker.lock().replace(task.waker().clone());
            drop(old);
            let mut poll = || {
                let result = future.as_mut().poll(task);
                if result.is_pending() && !controls.parked.swap(true, Ordering::AcqRel) {
                    assert_eq!(driver.pending_count(), 1);
                    assert_eq!(registrations(cx), 2);
                    let _ = started.notify_one();
                }
                result
            };
            if matches!(stop, Stop::MaskedCancel) && !controls.parked.load(Ordering::Acquire) {
                cx.masked(|| {
                    // No observer exists when this request is made. Only the
                    // mask-exit wake can release the subsequent parked run.
                    cx.cancel_with_reason(reason());
                    poll()
                })
            } else {
                poll()
            }
        })
        .await;
        let waker = controls.waker.lock().take();
        drop(waker);
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("the parked session must reach its {stop:?} boundary"),
        };
        let expected = match stop {
            Stop::Deadline => io::ErrorKind::TimedOut,
            Stop::OwnerBudget | Stop::Cancel | Stop::MaskedCancel => io::ErrorKind::Interrupted,
        };
        assert_eq!(error.kind(), expected);
        assert!(driver.is_empty(), "completion retires the timer before drop");
        assert_eq!(registrations(cx), 0);
    }

    async fn exercise(
        kind: Kind,
        cx: &Cx,
        driver: &TimerDriverHandle,
        controls: &Controls,
        started: &Notify,
        stop: Stop,
    ) {
        let fresh = owner(Budget::INFINITE, driver.clone());
        let resume_at = Time::from_millis(200);
        let (endpoint, probe) = Endpoint::new(
            b"abcdef",
            if matches!(kind, Kind::Read | Kind::ReadVectored) {
                2
            } else {
                usize::MAX
            },
            2,
            &controls.release,
        );
        match kind {
            Kind::Read => {
                let mut buffer = [0; 6];
                let mut session = ReadExactSession::new(endpoint, &mut buffer);
                stopped(session.run_until(cx, DEADLINE), cx, driver, controls, started, stop).await;
                assert_eq!(session.filled(), b"ab");
                assert_eq!(session.bytes_read(), 2);
                controls.release.store(true, Ordering::Release);
                assert_eq!(session.run_until(&fresh, resume_at).await.unwrap(), 6);
                assert_eq!(session.filled(), b"abcdef");
                let polls = probe.polls.load(Ordering::SeqCst);
                assert_eq!(session.run_until(cx, Time::ZERO).await.unwrap(), 6);
                assert_eq!(probe.polls.load(Ordering::SeqCst), polls);
            }
            Kind::Write => {
                let mut session = WriteAllSession::new(endpoint, b"abcdef");
                stopped(session.run_until(cx, DEADLINE), cx, driver, controls, started, stop).await;
                assert_eq!(session.bytes_written(), 2);
                assert_eq!(session.pending_bytes(), b"cdef");
                controls.release.store(true, Ordering::Release);
                assert_eq!(session.run_until(&fresh, resume_at).await.unwrap(), 6);
                assert_eq!(&*probe.written.lock(), b"abcdef");
                let polls = probe.polls.load(Ordering::SeqCst);
                assert_eq!(session.run_until(cx, Time::ZERO).await.unwrap(), 6);
                assert_eq!(probe.polls.load(Ordering::SeqCst), polls);
            }
            Kind::ReadVectored => {
                let mut prefix = [0; 2];
                let mut suffix = [0; 4];
                let mut empty = [];
                let mut plan = [
                    IoSliceMut::new(&mut prefix),
                    IoSliceMut::new(&mut empty),
                    IoSliceMut::new(&mut suffix),
                ];
                let mut session = ReadExactVectoredSession::new(endpoint, &mut plan).unwrap();
                stopped(session.run_until(cx, DEADLINE), cx, driver, controls, started, stop).await;
                assert_eq!(session.bytes_read(), 2);
                assert_eq!(
                    session.filled_slices().flatten().copied().collect::<Vec<_>>(),
                    b"ab"
                );
                controls.release.store(true, Ordering::Release);
                assert_eq!(session.run_until(&fresh, resume_at).await.unwrap(), 6);
                assert_eq!(
                    session.filled_slices().flatten().copied().collect::<Vec<_>>(),
                    b"abcdef"
                );
                let polls = probe.polls.load(Ordering::SeqCst);
                assert_eq!(session.run_until(cx, Time::ZERO).await.unwrap(), 6);
                assert_eq!(probe.polls.load(Ordering::SeqCst), polls);
            }
            Kind::WriteVectored => {
                let plan = [IoSlice::new(b"ab"), IoSlice::new(b""), IoSlice::new(b"cdef")];
                let mut session = WriteAllVectoredSession::new(endpoint, &plan).unwrap();
                stopped(session.run_until(cx, DEADLINE), cx, driver, controls, started, stop).await;
                assert_eq!(session.bytes_written(), 2);
                assert_eq!(session.remaining(), 4);
                controls.release.store(true, Ordering::Release);
                assert_eq!(session.run_until(&fresh, resume_at).await.unwrap(), 6);
                assert_eq!(&*probe.written.lock(), b"abcdef");
                let polls = probe.polls.load(Ordering::SeqCst);
                assert_eq!(session.run_until(cx, Time::ZERO).await.unwrap(), 6);
                assert_eq!(probe.polls.load(Ordering::SeqCst), polls);
            }
            Kind::Copy => {
                let (writer, writes) = Endpoint::new(b"", usize::MAX, 2, &controls.release);
                let mut session = CopySession::new(endpoint, writer);
                stopped(session.run_until(cx, DEADLINE), cx, driver, controls, started, stop).await;
                assert_eq!(session.progress().read, 6);
                assert_eq!(session.progress().written, 2);
                assert_eq!(session.pending_bytes(), b"cdef");
                controls.release.store(true, Ordering::Release);
                assert_eq!(session.run_until(&fresh, resume_at).await.unwrap(), 6);
                assert_eq!(&*writes.written.lock(), b"abcdef");
                let polls = writes.polls.load(Ordering::SeqCst);
                assert_eq!(session.run_until(cx, Time::ZERO).await.unwrap(), 6);
                assert_eq!(writes.polls.load(Ordering::SeqCst), polls);
                assert_eq!(writes.flushes.load(Ordering::SeqCst), 1);
                assert_eq!(writes.shutdowns.load(Ordering::SeqCst), 0);
                assert!(writes.pending.load(Ordering::SeqCst) > 0);
            }
            Kind::Bidirectional => {
                let (peer, peer_probe) = Endpoint::new(b"uvwxyz", usize::MAX, 2, &controls.release);
                let mut session = BidirectionalCopySession::new(endpoint, peer);
                stopped(session.run_until(cx, DEADLINE), cx, driver, controls, started, stop).await;
                assert_eq!(session.progress().a_to_b.written, 2);
                assert_eq!(session.progress().b_to_a.written, 2);
                assert_eq!(session.pending_a_to_b(), b"cdef");
                assert_eq!(session.pending_b_to_a(), b"wxyz");
                controls.release.store(true, Ordering::Release);
                assert_eq!(session.run_until(&fresh, resume_at).await.unwrap(), (6, 6));
                assert_eq!(&*peer_probe.written.lock(), b"abcdef");
                assert_eq!(&*probe.written.lock(), b"uvwxyz");
                let polls = probe.polls.load(Ordering::SeqCst);
                let peer_polls = peer_probe.polls.load(Ordering::SeqCst);
                assert_eq!(session.run_until(cx, Time::ZERO).await.unwrap(), (6, 6));
                assert_eq!(probe.polls.load(Ordering::SeqCst), polls);
                assert_eq!(peer_probe.polls.load(Ordering::SeqCst), peer_polls);
                assert_eq!(probe.flushes.load(Ordering::SeqCst), 1);
                assert_eq!(peer_probe.flushes.load(Ordering::SeqCst), 1);
                assert_eq!(probe.shutdowns.load(Ordering::SeqCst), 1);
                assert_eq!(peer_probe.shutdowns.load(Ordering::SeqCst), 1);
                assert!(peer_probe.pending.load(Ordering::SeqCst) > 0);
            }
        }
        if !matches!(kind, Kind::Copy) {
            assert!(probe.pending.load(Ordering::SeqCst) > 0);
        }
        assert!(driver.is_empty());
        assert_eq!(registrations(&fresh), 0);
    }

    fn parked_session(kind: Kind, stop: Stop, multithread: bool) {
        let budget = if matches!(stop, Stop::OwnerBudget) {
            Budget::INFINITE.with_deadline(Time::from_millis(10))
        } else {
            Budget::INFINITE
        };
        let (cx, clock, driver) = virtual_owner(budget);
        // The ambient clock is already beyond the explicit deadline. Only the
        // supplied owner's clock may decide or wake this operation's boundary.
        let ambient_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
        let ambient = TimerDriverHandle::with_virtual_clock(ambient_clock);
        let builder = if multithread {
            RuntimeBuilder::new().worker_threads(2).with_sharded_state(true)
        } else {
            RuntimeBuilder::current_thread()
        };
        let runtime = builder.with_timer_driver(ambient.clone()).build().unwrap();
        let controls = Arc::new(Controls::default());
        let started = Arc::new(Notify::new());
        let fired = Arc::new(AtomicBool::new(false));
        let watchdog = Watchdog::start(
            Arc::clone(&controls),
            Arc::clone(&started),
            Arc::clone(&fired),
        );
        let check_cx = cx.clone();
        let check_driver = driver.clone();
        runtime.block_on(runtime.handle().spawn(async move {
            let root = Cx::current().expect("native root context");
            let child_cx = cx.clone();
            let child_driver = driver.clone();
            let child_controls = Arc::clone(&controls);
            let child_started = Arc::clone(&started);
            let mut child = root
                .spawn(move |_| async move {
                    exercise(
                        kind,
                        &child_cx,
                        &child_driver,
                        &child_controls,
                        &child_started,
                        stop,
                    )
                    .await;
                    Outcome::<(), io::Error>::Ok(())
                })
                .unwrap();
            started.notified().await;
            assert!(controls.parked.load(Ordering::Acquire), "{kind:?} must actually park");
            let reason = reason();
            match stop {
                Stop::Deadline => {
                    clock.advance_to(DEADLINE);
                    assert_eq!(driver.process_timers(), 1);
                }
                Stop::OwnerBudget => {
                    clock.advance_to(Time::from_millis(10));
                    assert_eq!(driver.process_timers(), 1);
                }
                Stop::Cancel => {
                    let cancel_cx = cx.clone();
                    let reason = reason.clone();
                    thread::spawn(move || cancel_cx.cancel_with_reason(reason)).join().unwrap();
                }
                Stop::MaskedCancel => {}
            }
            let joined = child.join(&root).await;
            assert!(matches!(&joined, Ok(Outcome::Ok(()))), "{kind:?} {stop:?}: {joined:?}");
            match stop {
                Stop::Deadline => assert!(!cx.is_cancel_requested()),
                Stop::OwnerBudget => {
                    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::Deadline);
                }
                Stop::Cancel | Stop::MaskedCancel => {
                    assert_eq!(cx.cancel_reason(), Some(reason));
                    assert_eq!(driver.now(), Time::ZERO);
                }
            }
        }));
        drop(watchdog);
        assert!(!fired.load(Ordering::Acquire), "{kind:?} {stop:?} needed the rescue wake");
        assert!(check_driver.is_empty());
        assert!(ambient.is_empty());
        assert_eq!(registrations(&check_cx), 0);
        let drain = runtime.shutdown_drained(Duration::from_secs(3));
        assert_eq!(drain.outcome, RootDrainOutcome::Quiescent, "{drain:?}");
        assert_eq!(drain.live_tasks, 0);
        assert_eq!(drain.live_regions, 0);
        assert_eq!(drain.pending_spawns, 0);
        assert_eq!(drain.pending_obligations, 0);
        assert_eq!(drain.queued_finalizers, 0);
        assert!(!drain.has_pending_obligation_posts);
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn every_native_session_expires_and_resumes_on_the_foreign_owner_clock() {
        for multithread in [false, true] {
            for kind in KINDS {
                parked_session(kind, Stop::Deadline, multithread);
            }
        }
    }

    #[test]
    fn every_native_session_wakes_on_its_foreign_owner_budget_and_resumes() {
        for multithread in [false, true] {
            for kind in KINDS {
                parked_session(kind, Stop::OwnerBudget, multithread);
            }
        }
    }

    #[test]
    fn every_native_session_cancels_cross_thread_and_resumes_without_losing_bytes() {
        for multithread in [false, true] {
            for kind in KINDS {
                parked_session(kind, Stop::Cancel, multithread);
            }
        }
    }

    #[test]
    fn every_native_session_wakes_on_foreign_owner_unmask_without_a_timer_tick() {
        for multithread in [false, true] {
            for kind in KINDS {
                parked_session(kind, Stop::MaskedCancel, multithread);
            }
        }
    }
}
