//! GH #83: deterministic role assignment, real task polls, and no latency SLA.
use super::*;
use crate::runtime::reactor::{Events, Interest, Reactor, Source, Token};
use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

const WATCHDOG: Duration = Duration::from_secs(5);
// Only the epoll-backed blocking-poll tests below use it.
#[cfg(any(target_os = "linux", target_os = "android"))]
const BLOCKER_WATCHDOG: Duration = Duration::from_secs(30);

fn waiter_is_committed(parker: &Parker) -> bool {
    let until = Instant::now() + WATCHDOG;
    while !parker.wait_committed_for_test() && Instant::now() < until {
        thread::yield_now();
    }
    parker.wait_committed_for_test()
}

#[test]
fn promotion_has_no_busy_worker_fallback_and_is_a_noop_without_a_peer() {
    for count in [0, 1, 2, 3, 16] {
        let parkers: SmallVec<[Parker; 16]> = (0..count).map(|_| Parker::new()).collect();
        let coordinator = WorkerCoordinator::new(parkers.clone(), None);
        assert!(!coordinator.promote_follower());
        assert!(parkers.iter().all(|p| !p.notification_pending_for_test()));
    }
}

#[test]
fn promotion_finds_a_waiter_across_a_wrapping_non_power_of_two_cursor() {
    let parkers: SmallVec<[Parker; 16]> = (0..3).map(|_| Parker::new()).collect();
    let coordinator = WorkerCoordinator::new(parkers.clone(), None);
    coordinator.next_wake.store(usize::MAX, Ordering::Relaxed);
    let parked = parkers[2].clone();
    let (done_tx, done_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        parked.park();
        let _ = done_tx.send(());
    });
    let published = waiter_is_committed(&parkers[2]);
    let promoted = coordinator.promote_follower();
    let done = done_rx.recv_timeout(WATCHDOG);
    for parker in &parkers {
        // Delay rescue until after capturing both the result and busy slots.
        if parker.waiting_count_for_test() != 0 {
            parker.unpark();
        }
    }
    waiter.join().expect("promoted waiter");
    assert!(published);
    assert!(promoted);
    assert_eq!(done, Ok(()));
    assert!(!parkers[0].notification_pending_for_test());
    assert!(!parkers[1].notification_pending_for_test());
}

struct FailingReactor {
    polls: AtomicUsize,
}

impl Reactor for FailingReactor {
    fn register(&self, _: &dyn Source, _: Token, _: Interest) -> io::Result<()> {
        Ok(())
    }
    fn modify(&self, _: Token, _: Interest) -> io::Result<()> {
        Ok(())
    }
    fn deregister(&self, _: Token) -> io::Result<()> {
        Ok(())
    }
    fn poll(&self, events: &mut Events, _: Option<Duration>) -> io::Result<usize> {
        events.clear();
        self.polls.fetch_add(1, Ordering::Relaxed);
        Err(io::Error::other("persistent injected poll failure"))
    }
    fn wake(&self) -> io::Result<()> {
        Ok(())
    }
    fn registration_count(&self) -> usize {
        0
    }
}

#[test]
fn a_poll_error_is_not_a_follower_and_releases_the_election() {
    let reactor = Arc::new(FailingReactor { polls: AtomicUsize::new(0) });
    let io = IoDriverHandle::new(reactor.clone());
    let mut state = RuntimeState::new();
    state.set_io_driver(io.clone());
    let state = Arc::new(ContendedMutex::new("runtime_state", state));
    let mut scheduler = ThreeLaneScheduler::new(1, &state);
    let worker = scheduler.take_workers().remove(0);
    for _ in 0..3 {
        assert_eq!(worker.drive_io_phase(false), IoPhaseOutcome::PollError);
        assert!(!io.is_polling());
    }
    assert_eq!(reactor.polls.load(Ordering::Relaxed), 3);
    assert_eq!(io.poll_error_count(), 3);
}

#[test]
fn error_retries_are_bounded_and_do_not_discard_shared_deadlines() {
    let now = Time::from_nanos(10_000_000);
    let near = Time::from_nanos(10_000_007);
    let far = Time::from_nanos(20_000_000);
    assert_eq!(poll_error_retry_nanos(None, now), IO_POLL_ERROR_RETRY_NANOS);
    assert_eq!(poll_error_retry_nanos(Some(now), now), IO_POLL_ERROR_RETRY_NANOS);
    assert_eq!(poll_error_retry_nanos(Some(Time::ZERO), now), IO_POLL_ERROR_RETRY_NANOS);
    assert_eq!(poll_error_retry_nanos(Some(near), now), 7);
    assert_eq!(poll_error_retry_nanos(Some(far), now), IO_POLL_ERROR_RETRY_NANOS);
    assert_eq!(select_backoff_deadline(IoPhaseOutcome::PollError, Some(near), None, Some(far)), Some(near));
    assert_eq!(select_backoff_deadline(IoPhaseOutcome::Follower, Some(near), None, Some(far)), None);
}

#[test]
fn persistent_errors_return_to_the_poll_loop_through_a_timed_park() {
    let reactor = Arc::new(FailingReactor { polls: AtomicUsize::new(0) });
    let io = IoDriverHandle::new(reactor.clone());
    let mut state = RuntimeState::new();
    state.set_io_driver(io);
    let state = Arc::new(ContendedMutex::new("runtime_state", state));
    let mut scheduler = ThreeLaneScheduler::new(1, &state);
    let mut worker = scheduler.take_workers().remove(0);
    let parker = worker.parker.clone();
    let shutdown = worker.shutdown.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let worker_thread = thread::spawn(move || {
        worker.run_loop_until(&mut || reactor.polls.load(Ordering::Relaxed) >= 2, false);
        let metrics = &worker.preemption_metrics;
        let _ = done_tx.send((metrics.backoff_timeout_parks_total, metrics.follower_indefinite_parks));
    });
    let result = done_rx.recv_timeout(WATCHDOG);
    shutdown.store(true, Ordering::Release);
    parker.unpark();
    worker_thread.join().expect("error-retry worker");
    let (timed, indefinite) = result.expect("no external wake was needed to retry the failed poll");
    assert!(timed >= 1);
    assert_eq!(indefinite, 0);
}

/// A peer consumes the mailbox work that forced a nonblocking reactor turn.
/// No socket or task wake is generated, so the scheduler itself must arrange
/// the next reactor turn rather than waiting forever on its Parker.
#[test]
fn an_empty_quick_turn_reenters_election_without_losing_idle_return() {
    use crate::runtime::spawn_mailbox::SpawnMailbox;
    use crate::types::CancelReason;
    use crate::time::VirtualClock;

    struct DrainedMailboxReactor {
        mailbox: Arc<SpawnMailbox>,
        polls: AtomicUsize,
        timeouts: Mutex<Vec<Option<Duration>>>,
        clock_to_advance: Option<Arc<VirtualClock>>,
    }

    impl Reactor for DrainedMailboxReactor {
        fn register(&self, _: &dyn Source, _: Token, _: Interest) -> io::Result<()> {
            Ok(())
        }

        fn modify(&self, _: Token, _: Interest) -> io::Result<()> {
            Ok(())
        }

        fn deregister(&self, _: Token) -> io::Result<()> {
            Ok(())
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            events.clear();
            self.timeouts.lock().push(timeout);
            if self.polls.fetch_add(1, Ordering::Relaxed) == 0 {
                // next_task's two 16-command drains leave eight commands.
                // Draining them here models an idle peer consuming that work
                // after the leader selected ZERO but before its poll returns.
                assert_eq!(timeout, Some(Duration::ZERO));
                let mut commands = Vec::new();
                assert_eq!(self.mailbox.dequeue_handle_cancels_into(40, &mut commands), 8);
                assert!(self.mailbox.is_empty());
                if let Some(clock) = &self.clock_to_advance {
                    // Make a real timer due after next_task's timer pass.
                    // No waker runs until the next dispatch iteration.
                    clock.advance(1_000_000_000);
                }
            }
            Ok(0)
        }

        fn wake(&self) -> io::Result<()> {
            Ok(())
        }

        fn registration_count(&self) -> usize {
            0
        }
    }

    for (return_when_idle, timer_becomes_due) in [(false, false), (false, true), (true, false)] {
        let clock = Arc::new(VirtualClock::new());
        let timers = TimerDriverHandle::with_virtual_clock(clock.clone());
        let mailbox = Arc::new(SpawnMailbox::new());
        let reactor = Arc::new(DrainedMailboxReactor {
            mailbox: mailbox.clone(),
            polls: AtomicUsize::new(0),
            timeouts: Mutex::new(Vec::new()),
            clock_to_advance: timer_becomes_due.then_some(clock),
        });
        let io = IoDriverHandle::new(reactor.clone());
        let mut state = RuntimeState::new();
        state.set_io_driver(io);
        state.set_timer_driver(timers.clone());
        let _timer = timer_becomes_due.then(|| {
            timers.register(Time::from_secs(1), Waker::noop().clone())
        });
        let state = Arc::new(ContendedMutex::new("runtime_state", state));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        scheduler.attach_spawn_mailbox(mailbox.clone());
        for index in 0..40_u32 {
            mailbox.enqueue_handle_cancel(
                TaskId::new_for_test(9_000 + index, 1),
                CancelReason::user("quick-poll mailbox race"),
            );
        }
        let mut worker = scheduler.take_workers().remove(0);
        let shutdown = worker.shutdown.clone();
        let parker = worker.parker.clone();
        // Discard only setup's coalesced permit. Nothing wakes this Parker
        // until the assertion outcome has been captured or rescue is needed.
        parker.park_timeout(Duration::ZERO);
        let (done_tx, done_rx) = mpsc::channel();
        let worker_thread = thread::spawn(move || {
            // Both modes use the same stop condition. In idle-return mode
            // the loop must return after ONE poll on its own, not via this.
            worker.run_loop_until(
                &mut || reactor.polls.load(Ordering::Relaxed) >= 2,
                return_when_idle,
            );
            let _ = done_tx.send((
                reactor.timeouts.lock().clone(),
                worker.preemption_metrics.backoff_indefinite_parks,
                worker.preemption_metrics.backoff_timeout_parks_total,
            ));
        });
        let result = done_rx.recv_timeout(WATCHDOG);
        shutdown.store(true, Ordering::Release);
        parker.unpark();
        worker_thread.join().expect("quick-miss worker shuts down");
        let (timeouts, indefinite_parks, timeout_parks) =
            result.expect("a quick miss must not require an external wake");
        let expected = if return_when_idle {
            vec![Some(Duration::ZERO)]
        } else {
            vec![Some(Duration::ZERO), Some(IDLE_IO_POLL_MAX_TIMEOUT)]
        };
        assert_eq!(timeouts, expected);
        assert_eq!(indefinite_parks, 0);
        assert_eq!(timeout_parks, u64::from(timer_becomes_due),
            "quick-miss re-election must retain the due-deadline kernel backoff");
        assert_eq!(timers.pending_count(), 0);
    }
}

// Use the real Linux/Android readiness backend. No unsafe code, network access,
// background runtime, or millisecond sleep is needed to establish the race.
#[cfg(any(target_os = "linux", target_os = "android"))]
mod native {
    use super::*;
    use crate::runtime::io_driver::IoRegistration;
    use crate::runtime::reactor::EpollReactor;
    use crate::time::VirtualClock;
    use crate::types::Budget;
    use std::future::{Future, poll_fn};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::pin::Pin;

    struct ReadByte {
        // Deregister while the source's fd is still alive.
        registration: Option<IoRegistration>,
        stream: UnixStream,
        io: IoDriverHandle,
    }

    impl Future for ReadByte {
        type Output = u8;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u8> {
            let this = self.get_mut();
            let mut byte = [0_u8];
            match this.stream.read(&mut byte) {
                Ok(1) => Poll::Ready(byte[0]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if let Some(registration) = &this.registration {
                        assert!(this.io.update_waker(registration.token(), cx.waker().clone()));
                    } else {
                        this.registration = Some(this.io.register(
                            &this.stream, Interest::READABLE, cx.waker().clone(),
                        ).expect("register a genuinely WouldBlock socket"));
                    }
                    Poll::Pending
                }
                result => panic!("expected one byte or WouldBlock, got {result:?}"),
            }
        }
    }

    struct GatedReactor {
        inner: EpollReactor,
        turns: AtomicUsize,
        entered: mpsc::Sender<(usize, thread::ThreadId)>,
        gates: Mutex<VecDeque<mpsc::Receiver<()>>>,
        virtual_timeout_on_second: bool,
    }

    impl Reactor for GatedReactor {
        fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
            self.inner.register(source, token, interest)
        }
        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.inner.modify(token, interest)
        }
        fn deregister(&self, token: Token) -> io::Result<()> {
            self.inner.deregister(token)
        }
        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            let turn = self.turns.fetch_add(1, Ordering::Relaxed);
            let gate = self.gates.lock().pop_front();
            if let Some(gate) = gate {
                let _ = self.entered.send((turn, thread::current().id()));
                gate.recv_timeout(BLOCKER_WATCHDOG)
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test poll gate"))?;
            }
            if turn == 1 && self.virtual_timeout_on_second {
                // The controller advanced the shared clock before releasing
                // this gate. Model that poll timeout, without waking a Parker.
                events.clear();
                return Ok(0);
            }
            self.inner.poll(events, timeout)
        }
        fn wake(&self) -> io::Result<()> {
            self.inner.wake()
        }
        fn registration_count(&self) -> usize {
            self.inner.registration_count()
        }
    }

    struct RunningWorkers {
        shutdown: Arc<AtomicBool>,
        io: IoDriverHandle,
        parkers: Vec<Parker>,
        releases: Vec<mpsc::Sender<()>>,
        threads: Vec<thread::JoinHandle<()>>,
    }

    impl RunningWorkers {
        fn stop(&mut self) -> bool {
            self.shutdown.store(true, Ordering::Release);
            for release in &self.releases {
                let _ = release.send(());
            }
            let _ = self.io.wake();
            for parker in &self.parkers {
                parker.unpark();
            }
            let mut joined = true;
            for worker in self.threads.drain(..) {
                joined &= worker.join().is_ok();
            }
            joined
        }
    }
    impl Drop for RunningWorkers {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    fn assert_peer_progress(timer_peer: bool, busy_leader: bool) {
        // The busy path skips empty drivers. Its case retains B's real socket
        // registration, but deliberately generates no readiness in turn zero.
        assert!(!busy_leader || !timer_peer);
        let (first_tx, first_rx) = mpsc::channel();
        let (second_tx, second_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let reactor = Arc::new(GatedReactor {
            inner: EpollReactor::new().expect("epoll backend"),
            turns: AtomicUsize::new(0),
            entered: entered_tx,
            gates: Mutex::new(VecDeque::from([first_rx, second_rx])),
            virtual_timeout_on_second: timer_peer,
        });
        let io = IoDriverHandle::new(reactor.clone());
        let clock = Arc::new(VirtualClock::new());
        let timers = TimerDriverHandle::with_virtual_clock(clock.clone());
        let (mut a_peer, a_socket) = UnixStream::pair().expect("leader socket");
        let (mut b_peer, b_socket) = UnixStream::pair().expect("peer socket");
        a_socket.set_nonblocking(true).expect("nonblocking A");
        b_socket.set_nonblocking(true).expect("nonblocking B");
        let (started_tx, started_rx) = mpsc::channel();
        let (release_task_tx, release_task_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let left_blocking_poll = Arc::new(AtomicBool::new(false));
        let left_task = left_blocking_poll.clone();
        let mut state = RuntimeState::new();
        state.set_io_driver(io.clone());
        state.set_timer_driver(timers.clone());
        let root = state.create_root_region(Budget::INFINITE);
        let a_io = io.clone();
        let (a_task, _a_join) = state.create_task(root, Budget::INFINITE, async move {
            if !busy_leader {
                assert_eq!(ReadByte { registration: None, stream: a_socket, io: a_io }.await, 0xa1);
            }
            let _ = started_tx.send(thread::current().id());
            let released = release_task_rx.recv_timeout(BLOCKER_WATCHDOG);
            left_task.store(true, Ordering::Release);
            assert!(released.is_ok(), "blocked task needed watchdog rescue");
        }).expect("create leader's task");
        let b_io = io.clone();
        let b_timers = timers.clone();
        let (b_task, _b_join) = state.create_task(root, Budget::INFINITE, async move {
            let value = if timer_peer {
                let deadline = Time::from_secs(1);
                let mut timer = None;
                poll_fn(move |cx| {
                    if b_timers.now() >= deadline {
                        Poll::Ready(0xb2)
                    } else {
                        if timer.is_none() {
                            timer = Some(b_timers.register(deadline, cx.waker().clone()));
                        }
                        Poll::Pending
                    }
                }).await
            } else {
                ReadByte { registration: None, stream: b_socket, io: b_io }.await
            };
            let _ = progress_tx.send((value, thread::current().id()));
        }).expect("create peer's task");
        let state = Arc::new(ContendedMutex::new("runtime_state", state));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);
        let mut workers = scheduler.take_workers();
        let mut follower = workers.pop().expect("worker 1");
        let mut leader = workers.pop().expect("worker 0");
        // Establish real parked futures and registrations before scheduling:
        // no work injection may accidentally unpark the follower later.
        if !busy_leader {
            leader.execute(a_task);
        }
        follower.execute(b_task);
        assert_eq!(io.waker_count(), usize::from(!busy_leader) + usize::from(!timer_peer));
        assert_eq!(timers.pending_count(), usize::from(timer_peer));
        let mut drained = Events::with_capacity(16);
        assert_eq!(reactor.inner.poll(&mut drained, Some(Duration::ZERO)).expect("drain registration wakes"), 0);
        leader.parker.park_timeout(Duration::ZERO);
        follower.parker.park_timeout(Duration::ZERO);
        let follower_parker = follower.parker.clone();
        let mut running = RunningWorkers {
            shutdown: leader.shutdown.clone(),
            io: io.clone(),
            parkers: vec![leader.parker.clone(), follower.parker.clone()],
            releases: vec![first_tx.clone(), second_tx.clone(), release_task_tx],
            threads: Vec::new(),
        };
        running.threads.push(thread::spawn(move || {
            if busy_leader {
                // Exercise the same interval gate used by dispatch and root
                // pumps. With no ready socket, this produces no ordinary task
                // wake that could accidentally perform the missing handoff.
                leader.busy_turns_since_io = BUSY_IO_POLL_INTERVAL - 1;
                leader.poll_busy_io_if_due();
                leader.execute(a_task);
            }
            leader.run_loop();
        }));
        let (first_turn, leader_id) = entered_rx.recv_timeout(WATCHDOG).expect("leader owns poll gate");
        assert_eq!(first_turn, 0);
        assert!(io.is_polling());
        running.threads.push(thread::spawn(move || follower.run_loop()));
        assert!(waiter_is_committed(&follower_parker), "follower is parked before the leader leaves I/O");
        assert!(!follower_parker.notification_pending_for_test());
        if !busy_leader {
            a_peer.write_all(&[0xa1]).expect("make A readable");
        }
        first_tx.send(()).expect("release the leader's poll");
        assert_eq!(started_rx.recv_timeout(WATCHDOG), Ok(leader_id));
        let second_turn = entered_rx.recv_timeout(WATCHDOG);
        // Do not rescue or externally unpark a follower to make this succeed.
        if let Ok((turn, follower_id)) = second_turn {
            assert_eq!(turn, 1);
            assert_ne!(follower_id, leader_id, "another worker must drive I/O");
            if timer_peer {
                clock.advance(1_000_000_000);
            } else {
                b_peer.write_all(&[0xb2]).expect("make B readable");
            }
            second_tx.send(()).expect("release follower's poll");
        }
        let progress = if second_turn.is_ok() {
            progress_rx.recv_timeout(WATCHDOG)
        } else {
            Err(mpsc::RecvTimeoutError::Timeout)
        };
        let still_blocked = !left_blocking_poll.load(Ordering::Acquire);
        let joined = running.stop();
        assert!(joined, "workers shut down without panic");
        assert!(second_turn.is_ok(), "parked follower did not re-enter reactor election");
        let (value, executing_peer) = progress.expect("peer progressed without releasing the leader's task");
        assert_eq!(value, 0xb2);
        assert_ne!(executing_peer, leader_id);
        assert!(still_blocked, "progress happened only after the blocking task returned");
        assert_eq!(timers.pending_count(), 0);
        assert_eq!(io.waker_count(), 0);
    }

    #[test]
    fn a_socket_wakes_while_the_previous_reactor_leader_is_in_a_blocking_poll() {
        assert_peer_progress(false, false);
    }

    #[test]
    fn a_busy_reactor_turn_promotes_a_follower_before_the_next_task_poll() {
        assert_peer_progress(false, true);
    }

    #[test]
    fn a_shared_timer_fires_while_the_previous_reactor_leader_is_in_a_blocking_poll() {
        assert_peer_progress(true, false);
    }


    /// A handoff is a responsibility to keep I/O live, not a promise that the
    /// woken worker will reach drive_io_phase before selecting another task.
    /// In particular an owner-local wake can coalesce onto that same worker,
    /// without waking the third worker or making its task stealable.
    #[test]
    fn a_promoted_follower_passes_free_reactor_on_before_owner_local_work() {
        let (first_tx, first_rx) = mpsc::channel();
        let (second_tx, second_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let reactor = Arc::new(GatedReactor {
            inner: EpollReactor::new().expect("epoll backend"),
            turns: AtomicUsize::new(0),
            entered: entered_tx,
            gates: Mutex::new(VecDeque::from([first_rx, second_rx])),
            virtual_timeout_on_second: false,
        });
        let io = IoDriverHandle::new(reactor.clone());
        let timers = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
        let (mut leader_writer, leader_socket) = UnixStream::pair().expect("leader socket");
        let (mut probe_writer, probe_socket) = UnixStream::pair().expect("probe socket");
        leader_socket.set_nonblocking(true).expect("nonblocking leader");
        probe_socket.set_nonblocking(true).expect("nonblocking probe");
        let (leader_started_tx, leader_started_rx) = mpsc::channel();
        let (local_started_tx, local_started_rx) = mpsc::channel();
        let (release_leader_tx, release_leader_rx) = mpsc::channel();
        let (release_local_tx, release_local_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let completed_blockers = Arc::new(AtomicUsize::new(0));
        let leader_finished = completed_blockers.clone();
        let local_finished = completed_blockers.clone();
        let mut state = RuntimeState::new();
        state.set_io_driver(io.clone());
        state.set_timer_driver(timers);
        let root = state.create_root_region(Budget::INFINITE);
        let leader_io = io.clone();
        let (leader_task, _leader_join) = state.create_task(root, Budget::INFINITE, async move {
            assert_eq!(ReadByte {
                registration: None, stream: leader_socket, io: leader_io,
            }.await, 0xa1);
            let _ = leader_started_tx.send(thread::current().id());
            let released = release_leader_rx.recv_timeout(BLOCKER_WATCHDOG);
            leader_finished.fetch_add(1, Ordering::Release);
            assert!(released.is_ok(), "leader task needed watchdog rescue");
        }).expect("create original leader task");
        let (local_task, _local_join) = state.create_task(root, Budget::INFINITE, async move {
            let _ = local_started_tx.send(thread::current().id());
            let released = release_local_rx.recv_timeout(BLOCKER_WATCHDOG);
            local_finished.fetch_add(1, Ordering::Release);
            assert!(released.is_ok(), "owner-local task needed watchdog rescue");
        }).expect("create owner-local queue task");
        let probe_io = io.clone();
        let (probe_task, _probe_join) = state.create_task(root, Budget::INFINITE, async move {
            let value = ReadByte {
                registration: None, stream: probe_socket, io: probe_io,
            }.await;
            let _ = progress_tx.send((value, thread::current().id()));
        }).expect("create socket probe task");
        let state = Arc::new(ContendedMutex::new("runtime_state", state));
        let mut scheduler = ThreeLaneScheduler::new(3, &state);
        let coordinator = scheduler.coordinator.clone();
        let mut workers = scheduler.take_workers();
        let mut successor = workers.pop().expect("worker 2");
        let mut follower = workers.pop().expect("worker 1");
        let mut leader = workers.pop().expect("worker 0");
        leader.execute(leader_task);
        successor.execute(probe_task);
        assert_eq!(io.waker_count(), 2);
        let mut drained = Events::with_capacity(16);
        assert_eq!(reactor.inner.poll(&mut drained, Some(Duration::ZERO))
            .expect("drain setup wake permits"), 0);
        for worker in [&leader, &follower, &successor] {
            worker.parker.park_timeout(Duration::ZERO);
        }
        let follower_queue = follower.local_ready.clone();
        let follower_parker = follower.parker.clone();
        let successor_parker = successor.parker.clone();
        let pause_follower = Arc::new(AtomicBool::new(false));
        let pause = pause_follower.clone();
        let (follower_returned_tx, follower_returned_rx) = mpsc::channel();
        let (continue_follower_tx, continue_follower_rx) = mpsc::channel();
        let mut running = RunningWorkers {
            shutdown: leader.shutdown.clone(),
            io: io.clone(),
            parkers: vec![leader.parker.clone(), follower_parker.clone(), successor_parker.clone()],
            releases: vec![first_tx.clone(), second_tx.clone(), release_leader_tx,
                release_local_tx, continue_follower_tx.clone()],
            threads: Vec::new(),
        };
        running.threads.push(thread::spawn(move || leader.run_loop()));
        let (turn, leader_id) = entered_rx.recv_timeout(WATCHDOG).expect("original leader owns reactor");
        assert_eq!(turn, 0);
        running.threads.push(thread::spawn(move || {
            let mut paused = false;
            follower.run_loop_until(&mut || {
                if !paused && pause.load(Ordering::Acquire) {
                    paused = true;
                    let _ = follower_returned_tx.send(thread::current().id());
                    assert!(continue_follower_rx.recv_timeout(BLOCKER_WATCHDOG).is_ok(),
                        "controller must release the promoted follower");
                }
                false
            }, false);
        }));
        let follower_id = running.threads.last().expect("follower thread").thread().id();
        running.threads.push(thread::spawn(move || successor.run_loop()));
        let successor_id = running.threads.last().expect("successor thread").thread().id();
        assert!(waiter_is_committed(&follower_parker));
        assert!(waiter_is_committed(&successor_parker));
        assert!(!follower_parker.notification_pending_for_test());
        assert!(!successor_parker.notification_pending_for_test());
        // Both final park checks precede the first release. The next stop
        // predicate call can therefore only occur after follower promotion.
        pause_follower.store(true, Ordering::Release);
        coordinator.next_wake.store(1, Ordering::Relaxed);
        leader_writer.write_all(&[0xa1]).expect("wake original leader's task");
        first_tx.send(()).expect("release first reactor gate");
        assert_eq!(leader_started_rx.recv_timeout(WATCHDOG), Ok(leader_id));
        assert_eq!(follower_returned_rx.recv_timeout(WATCHDOG), Ok(follower_id));
        assert!(!io.is_polling(), "promoted follower has not reached election");
        assert!(successor_parker.wait_committed_for_test());
        assert!(!successor_parker.notification_pending_for_test());
        // Route the task through the real non-stealable queue. This is a
        // controlled queue-placement fixture, not a spawn_local API test.
        // Match its targeted Parker + reactor wake, with no global wake that
        // could conceal the missing responsibility transfer to worker 2.
        state.lock().unwrap().task(local_task).expect("live local task").wake_state.notify();
        follower_queue.lock().push_back(local_task);
        follower_parker.unpark();
        io.wake().expect("owner-local wake reaches the reactor only");
        continue_follower_tx.send(()).expect("allow owner-local dispatch");
        assert_eq!(local_started_rx.recv_timeout(WATCHDOG), Ok(follower_id));
        let next_poll = entered_rx.recv_timeout(WATCHDOG);
        let progress = if let Ok((turn, worker_id)) = next_poll {
            assert_eq!(turn, 1);
            assert_eq!(worker_id, successor_id, "third worker must take the passed-on reactor");
            probe_writer.write_all(&[0xc3]).expect("make third socket readable");
            second_tx.send(()).expect("release successor's reactor turn");
            progress_rx.recv_timeout(WATCHDOG)
        } else {
            Err(mpsc::RecvTimeoutError::Timeout)
        };
        let blockers_still_running = completed_blockers.load(Ordering::Acquire) == 0;
        let joined = running.stop();
        assert!(joined, "all workers shut down without panic");
        assert!(next_poll.is_ok(), "promoted follower dropped reactor responsibility at dispatch");
        assert_eq!(progress, Ok((0xc3, successor_id)));
        assert!(blockers_still_running, "socket progress waited for a blocking task to return");
        assert_eq!(io.waker_count(), 0);
    }
}
