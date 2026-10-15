//! GH#83: task polls must not monopolize shared reactor progress.
//! Channels establish ordering; timeouts are deadlock watchdogs, not latency budgets.
use super::*;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

const WATCHDOG: Duration = Duration::from_secs(5);

fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + WATCHDOG;
    while !condition() {
        if Instant::now() >= end {
            return false;
        }
        thread::yield_now();
    }
    true
}

#[test]
fn conditional_parking_publishes_waiter_before_checking_both_paths() {
    for timed in [false, true] {
        let parker = Parker::new();
        let ready = || {
            assert_eq!(parker.waiting_count_for_test(), 1);
            true
        };
        if timed {
            parker.park_timeout_unless(WATCHDOG, ready);
        } else {
            parker.park_unless(ready);
        }
        assert_eq!(parker.waiting_count_for_test(), 0);
        assert!(!parker.notification_pending_for_test());
        assert!(!parker.unpark_if_waiting());
    }
}

#[test]
fn conditional_parking_consumes_existing_permit_without_calling_guard() {
    for timed in [false, true] {
        let parker = Parker::new();
        parker.unpark();
        if timed {
            parker.park_timeout_unless(WATCHDOG, || panic!("permit already present"));
        } else {
            parker.park_unless(|| panic!("permit already present"));
        }
        assert_eq!(parker.waiting_count_for_test(), 0);
        assert!(!parker.notification_pending_for_test());
    }
}

#[test]
fn conditional_parking_checks_outside_mutex_and_cleans_up_panics() {
    for timed in [false, true] {
        let parker = Parker::new();
        let ready = || {
            // Re-entering the wake path would deadlock under the mutex.
            assert!(parker.unpark_if_waiting());
            false
        };
        if timed {
            parker.park_timeout_unless(WATCHDOG, ready);
        } else {
            parker.park_unless(ready);
        }
        assert_eq!(parker.waiting_count_for_test(), 0);
        let result = std::panic::catch_unwind(|| {
            if timed {
                parker.park_timeout_unless(WATCHDOG, || panic!("guard panic"));
            } else {
                parker.park_unless(|| panic!("guard panic"));
            }
        });
        assert!(result.is_err());
        assert_eq!(parker.waiting_count_for_test(), 0);
        assert!(!parker.unpark_if_waiting());
    }
}

#[test]
fn promotion_before_condvar_wait_is_not_lost() {
    for timed in [false, true] {
        let parker = Parker::new();
        let coordinator = WorkerCoordinator::new(
            smallvec::smallvec![Parker::new(), parker.clone()], None,
        );
        let (published_tx, published_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let parked = parker.clone();
        let join = thread::spawn(move || {
            let ready = || {
                published_tx.send(()).unwrap();
                release_rx.recv_timeout(WATCHDOG).unwrap();
                false // Force the stale leadership observation.
            };
            if timed {
                parked.park_timeout_unless(WATCHDOG, ready);
            } else {
                parked.park_unless(ready);
            }
            done_tx.send(()).unwrap();
        });
        let published = published_rx.recv_timeout(WATCHDOG).is_ok();
        coordinator.promote_follower();
        let had_permit = parker.notification_pending_for_test();
        let _ = release_tx.send(());
        let completed = done_rx.recv_timeout(WATCHDOG).is_ok();
        parker.unpark();
        join.join().unwrap();
        assert!(published && had_permit && completed);
    }
}

#[test]
fn promotion_does_not_leave_permits_on_busy_or_single_workers() {
    for count in [0, 1, 2, 3] {
        let parkers: SmallVec<[Parker; 16]> = (0..count).map(|_| Parker::new()).collect();
        let coordinator = WorkerCoordinator::new(parkers.clone(), None);
        coordinator.next_wake.store(usize::MAX, Ordering::Relaxed);
        coordinator.promote_follower();
        assert!(parkers.iter().all(|p| !p.notification_pending_for_test()));
    }
}

#[test]
fn promotion_wakes_exactly_one_live_peer_even_when_cursor_wraps() {
    let parkers: SmallVec<[Parker; 16]> = (0..3).map(|_| Parker::new()).collect();
    let coordinator = WorkerCoordinator::new(parkers.clone(), None);
    let (done_tx, done_rx) = mpsc::channel();
    let joins: Vec<_> = parkers[1..].iter().cloned().map(|parker| {
        let tx = done_tx.clone();
        thread::spawn(move || {
            parker.park_timeout(WATCHDOG);
            let _ = tx.send(());
        })
    }).collect();
    let waiting = eventually(|| parkers[1..].iter().all(|p| p.waiting_count_for_test() == 1));
    coordinator.next_wake.store(usize::MAX, Ordering::Relaxed);
    coordinator.promote_follower();
    let first = done_rx.recv_timeout(WATCHDOG).is_ok();
    let remaining = parkers[1..].iter().map(Parker::waiting_count_for_test).sum::<usize>();
    let busy_permit = parkers[0].notification_pending_for_test();
    for parker in &parkers { parker.unpark(); }
    for join in joins { join.join().unwrap(); }
    assert!(waiting && first);
    assert_eq!(remaining, 1, "promotion must wake only one actual follower");
    assert!(!busy_permit);
}

#[test]
fn poll_errors_are_not_followers_and_have_bounded_retry_deadlines() {
    assert_eq!(classify_io_phase(Ok(None), None, false), IoPhaseOutcome::Follower);
    assert_eq!(classify_io_phase(Err(std::io::Error::other("poll failed")), None, false), IoPhaseOutcome::PollError);
    assert_eq!(classify_io_phase(Err(std::io::Error::other("poll failed")), None, true), IoPhaseOutcome::Progress);
    assert_eq!(classify_io_phase(Ok(Some(0)), Some(Duration::ZERO), false), IoPhaseOutcome::NoProgress);
    assert_eq!(classify_io_phase(Ok(Some(0)), Some(WATCHDOG), false), IoPhaseOutcome::Progress);
    let now = Time::from_nanos(10_000_000);
    let retry = Time::from_nanos(11_000_000);
    assert_eq!(io_error_retry_deadline(now, None), retry);
    assert_eq!(io_error_retry_deadline(now, Some(now)), retry);
    assert_eq!(io_error_retry_deadline(now, Some(Time::ZERO)), retry);
    assert_eq!(io_error_retry_deadline(now, Some(Time::from_nanos(20_000_000))), retry);
    let nearer = Time::from_nanos(10_100_000);
    assert_eq!(io_error_retry_deadline(now, Some(nearer)), nearer);
    assert_eq!(io_error_retry_deadline(Time::from_nanos(u64::MAX), None), Time::from_nanos(u64::MAX));
}

#[cfg(target_os = "linux")]
mod live {
    use super::*;
    use crate::runtime::io_driver::IoRegistration;
    use crate::runtime::reactor::{EpollReactor, Interest};
    use crate::time::VirtualClock;
    use crate::types::Budget;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let writer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (reader, _) = listener.accept().unwrap();
        reader.set_nonblocking(true).unwrap();
        (reader, writer)
    }

    async fn read_byte(io: IoDriverHandle, mut stream: TcpStream) {
        let mut registration: Option<IoRegistration> = None;
        std::future::poll_fn(|cx| {
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(1) => Poll::Ready(()),
                Ok(_) => panic!("unexpected EOF"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(registration) = &mut registration {
                        assert!(registration.rearm(Interest::READABLE, cx.waker()).unwrap());
                    } else {
                        registration = Some(io.register(&stream, Interest::READABLE, cx.waker().clone()).unwrap());
                    }
                    Poll::Pending
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(error) => panic!("socket read: {error}"),
            }
        }).await;
    }

    struct RunningWorkers {
        shutdown: Arc<AtomicBool>,
        coordinator: Arc<WorkerCoordinator>,
        joins: Vec<thread::JoinHandle<()>>,
    }

    impl Drop for RunningWorkers {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Release);
            self.coordinator.wake_all();
            for join in self.joins.drain(..) {
                let _ = join.join();
            }
        }
    }

    struct Signal(mpsc::Sender<()>);
    impl Wake for Signal {
        fn wake(self: Arc<Self>) {
            let _ = self.0.send(());
        }
    }

    fn progress_while_leader_is_in_task(shared_timer: bool) {
        let io = IoDriverHandle::new(Arc::new(EpollReactor::new().unwrap()));
        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let mut state = RuntimeState::new();
        state.set_io_driver(io.clone());
        state.set_timer_driver(timer.clone());
        let region = state.create_root_region(Budget::INFINITE);
        let (reader_a, mut writer_a) = socket_pair();
        let (reader_b, mut writer_b) = socket_pair();
        let (started_tx, started_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let io_a = io.clone();
        let (a, _a_handle) = state.create_task(region, Budget::INFINITE, async move {
            read_byte(io_a, reader_a).await;
            started_tx.send(thread::current().id()).unwrap();
            // Only the OTHER worker can satisfy this while A's poll blocks.
            // The test thread never drives the reactor or timer wheel.
            let progressed = progress_rx.recv_timeout(WATCHDOG).is_ok();
            let _ = result_tx.send(progressed);
        }).unwrap();
        let deadline = Time::from_nanos(10_000_000);
        let mut b_task = None;
        let mut b_handle = None;
        let mut timer_handle = None;
        if shared_timer {
            timer_handle = Some(timer.register(deadline, Waker::from(Arc::new(Signal(progress_tx)))));
        } else {
            let io_b = io.clone();
            let (b, handle) = state.create_task(region, Budget::INFINITE, async move {
                read_byte(io_b, reader_b).await;
                let _ = progress_tx.send(());
            }).unwrap();
            b_task = Some(b);
            b_handle = Some(handle);
        }
        let state = Arc::new(ContendedMutex::new("handoff_test", state));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);
        scheduler.spawn(a, 0);
        if let Some(b) = b_task { scheduler.spawn(b, 0); }
        // Register sockets before launching the two worker threads.
        scheduler.workers[0].run_loop_until(&mut || false, true);
        let mut leader = scheduler.workers.remove(0);
        let mut follower = scheduler.workers.remove(0);
        let follower_parker = follower.parker.clone();
        let leader_join = thread::spawn(move || leader.run_loop());
        let leader_id = leader_join.thread().id();
        let mut running = RunningWorkers {
            shutdown: scheduler.shutdown.clone(),
            coordinator: scheduler.coordinator.clone(),
            joins: vec![leader_join],
        };
        assert!(eventually(|| io.is_polling()), "leader never entered the reactor");
        running.joins.push(thread::spawn(move || follower.run_loop()));
        assert!(eventually(|| follower_parker.waiting_count_for_test() == 1), "follower never parked");
        writer_a.write_all(&[1]).unwrap();
        assert_eq!(started_rx.recv_timeout(WATCHDOG).unwrap(), leader_id, "the idle reactor leader must keep A's first wake");
        if shared_timer { clock.advance_to(deadline); } else { writer_b.write_all(&[2]).unwrap(); }
        let result = result_rx.recv_timeout(WATCHDOG + WATCHDOG);
        drop(running);
        if let Some(handle) = timer_handle { timer.cancel(handle); }
        drop(b_handle);
        assert_eq!(result, Ok(true), "the parked follower must drive progress before task A's poll returns");
    }

    #[test]
    fn second_socket_progresses_while_reactor_leader_executes_a_blocked_task() {
        progress_while_leader_is_in_task(false);
    }

    #[test]
    fn shared_timer_progresses_while_reactor_leader_executes_a_blocked_task() {
        progress_while_leader_is_in_task(true);
    }
}
