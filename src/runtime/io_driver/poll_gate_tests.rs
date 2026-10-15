//! Ordered tests of the actual gate and IoDriverHandle path. The backend is
//! an explicit injected probe; these are not epoll or throughput benchmarks.
use super::*;
use super::super::{Event, Events, Interest, IoDriverHandle, Reactor, Source, Token};
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

const WATCHDOG: Duration = Duration::from_secs(5);

fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + WATCHDOG;
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::yield_now();
    }
    true
}

#[derive(Default)]
struct Probe {
    polls: AtomicUsize,
    wakes: AtomicUsize,
    fail_wake: AtomicBool,
    panic_poll: AtomicBool,
    timeout: Mutex<Option<Option<Duration>>>,
}

impl Reactor for Probe {
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
        self.polls.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic_poll.swap(false, Ordering::SeqCst), "injected poll panic");
        *self.timeout.lock() = Some(timeout);
        events.clear();
        Ok(0)
    }
    fn wake(&self) -> io::Result<()> {
        self.wakes.fetch_add(1, Ordering::SeqCst);
        if self.fail_wake.load(Ordering::SeqCst) {
            Err(io::Error::other("injected backend wake refusal"))
        } else {
            Ok(())
        }
    }
    fn registration_count(&self) -> usize {
        0
    }
}

#[test]
fn own_wake_interrupts_timed_and_indefinite_handle_turns_before_gate_release() {
    for timeout in [None, Some(WATCHDOG + WATCHDOG)] {
        let backend = Arc::new(Probe::default());
        let leader = IoDriverHandle::new(backend.clone());
        let participant = IoDriverHandle::new(backend.clone());
        let gate = leader._shared_owner.poll_gate.lock();
        let worker_handle = participant.clone();
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = sent.send(worker_handle.try_turn_with(timeout, |_, _| {}));
        });
        let parked = eventually(|| leader._shared_owner.poll_gate.waiting_count() == 1);
        let wake = participant.wake();
        let result = received.recv_timeout(WATCHDOG);
        let polled_while_owned = backend.polls.load(Ordering::SeqCst);
        // Rescue and join even when the old implementation misses this wake.
        drop(gate);
        worker.join().unwrap();
        assert!(parked);
        wake.unwrap();
        assert_eq!(result.expect("own wake, not gate release, must end the wait").unwrap(), Some(0));
        assert_eq!(polled_while_owned, 0, "never overlap physical polls");
        assert!(!participant.is_polling.load(Ordering::Acquire));
        assert_eq!(participant.try_turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), Some(0));
        assert_eq!(backend.polls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn wake_published_before_admission_is_not_lost_behind_a_competing_gate() {
    let backend = Arc::new(Probe::default());
    let leader = IoDriverHandle::new(backend.clone());
    let participant = IoDriverHandle::new(backend.clone());
    let gate = leader._shared_owner.poll_gate.lock();
    participant.wake().unwrap();
    let (sent, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        let _ = sent.send(participant.try_turn_with(None, |_, _| {}));
    });
    let result = received.recv_timeout(WATCHDOG);
    drop(gate);
    worker.join().unwrap();
    assert_eq!(result.expect("retained wake must end the contended turn").unwrap(), Some(0));
    assert_eq!(backend.polls.load(Ordering::SeqCst), 0);
}

#[test]
fn backend_wake_failure_does_not_strand_the_local_gate_waiter() {
    let backend = Arc::new(Probe::default());
    backend.fail_wake.store(true, Ordering::SeqCst);
    let leader = IoDriverHandle::new(backend.clone());
    let participant = IoDriverHandle::new(backend.clone());
    let gate = leader._shared_owner.poll_gate.lock();
    let worker_handle = participant.clone();
    let (sent, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        let _ = sent.send(worker_handle.try_turn_with(None, |_, _| {}));
    });
    let parked = eventually(|| leader._shared_owner.poll_gate.waiting_count() == 1);
    let wake = participant.wake();
    let result = received.recv_timeout(WATCHDOG);
    drop(gate);
    worker.join().unwrap();
    assert!(parked);
    assert!(wake.is_err(), "backend failure remains visible to the publisher");
    assert_eq!(result.expect("gate notification precedes backend wake").unwrap(), Some(0));
    assert_eq!(backend.polls.load(Ordering::SeqCst), 0);
}

#[test]
fn each_participant_consumes_only_its_own_wake() {
    let backend = Arc::new(Probe::default());
    let leader = IoDriverHandle::new(backend.clone());
    let first = IoDriverHandle::new(backend.clone());
    let second = IoDriverHandle::new(backend.clone());
    let gate = leader._shared_owner.poll_gate.lock();
    let (first_tx, first_rx) = mpsc::channel();
    let (second_tx, second_rx) = mpsc::channel();
    let a = first.clone();
    let b = second.clone();
    let workers = [
        thread::spawn(move || { let _ = first_tx.send(a.try_turn_with(None, |_, _| {})); }),
        thread::spawn(move || { let _ = second_tx.send(b.try_turn_with(None, |_, _| {})); }),
    ];
    let both_parked = eventually(|| leader._shared_owner.poll_gate.waiting_count() == 2);
    let first_wake = first.wake();
    let first_result = first_rx.recv_timeout(WATCHDOG);
    let second_still_pending = matches!(second_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
    let second_wake = second.wake();
    let second_result = second_rx.recv_timeout(WATCHDOG);
    drop(gate);
    for worker in workers { worker.join().unwrap(); }
    assert!(both_parked && second_still_pending);
    first_wake.unwrap();
    second_wake.unwrap();
    assert_eq!(first_result.unwrap().unwrap(), Some(0));
    assert_eq!(second_result.unwrap().unwrap(), Some(0));
    assert_eq!(backend.polls.load(Ordering::SeqCst), 0);
}

#[test]
fn wake_at_waiter_publication_cannot_be_lost() {
    for _ in 0..32 {
        let gate = Arc::new(PollGate::default());
        let held = gate.lock();
        let woken = Arc::new(AtomicBool::new(false));
        let worker_gate = gate.clone();
        let worker_woken = woken.clone();
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let interrupted = worker_gate.acquire(&worker_woken, None).is_none();
            let _ = sent.send(interrupted);
        });
        let published = eventually(|| gate.waiting_count() == 1);
        woken.store(true, Ordering::Release);
        gate.interrupt_waiters();
        let result = received.recv_timeout(WATCHDOG);
        drop(held);
        worker.join().unwrap();
        assert!(published);
        assert_eq!(result, Ok(true));
        assert_eq!(gate.waiting_count(), 0);
        assert!(!woken.load(Ordering::Acquire));
    }
}

#[test]
fn release_notifies_a_successor_and_preserves_remaining_budget() {
    let backend = Arc::new(Probe::default());
    let leader = IoDriverHandle::new(backend.clone());
    let participant = IoDriverHandle::new(backend.clone());
    let gate = leader._shared_owner.poll_gate.lock();
    let (sent, received) = mpsc::channel();
    let budget = Duration::MAX;
    let worker = thread::spawn(move || {
        let _ = sent.send(participant.try_turn_with(Some(budget), |_, _| {}));
    });
    let parked = eventually(|| leader._shared_owner.poll_gate.waiting_count() == 1);
    drop(gate);
    let result = received.recv_timeout(WATCHDOG);
    leader._shared_owner.poll_gate.interrupt_waiters();
    worker.join().unwrap();
    assert!(parked);
    assert_eq!(result.unwrap().unwrap(), Some(0));
    let Some(Some(remaining)) = *backend.timeout.lock() else {
        panic!("backend must receive the remaining finite budget");
    };
    assert!(remaining <= budget);
    assert_eq!(backend.polls.load(Ordering::SeqCst), 1);
}

#[test]
fn finite_wait_expires_without_a_gate_release_or_backend_poll() {
    let gate = Arc::new(PollGate::default());
    let held = gate.lock();
    let worker_gate = gate.clone();
    let (sent, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        let expired = worker_gate.acquire(&AtomicBool::new(false), Some(Duration::from_millis(10))).is_none();
        let _ = sent.send(expired);
    });
    let result = received.recv_timeout(WATCHDOG);
    drop(held);
    worker.join().unwrap();
    assert_eq!(result, Ok(true));
    assert_eq!(gate.waiting_count(), 0);
}

#[test]
fn zero_budget_never_parks_behind_an_owner() {
    let gate = PollGate::default();
    let _held = gate.lock();
    assert!(gate.acquire(&AtomicBool::new(false), Some(Duration::ZERO)).is_none());
    assert_eq!(gate.waiting_count(), 0);
}

#[test]
fn a_panicking_backend_releases_both_physical_and_participant_ownership() {
    let backend = Arc::new(Probe::default());
    let first = IoDriverHandle::new(backend.clone());
    let second = IoDriverHandle::new(backend.clone());
    backend.panic_poll.store(true, Ordering::SeqCst);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        first.try_turn_with(Some(Duration::ZERO), |_: &Event, _| {})
    }));
    assert!(result.is_err());
    assert!(!first.is_polling.load(Ordering::Acquire));
    assert_eq!(second.try_turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), Some(0));
    assert_eq!(backend.polls.load(Ordering::SeqCst), 2);
}

#[test]
fn a_woken_successor_cannot_strand_other_waiters_on_a_free_gate() {
    let gate = Arc::new(PollGate::default());
    let held = gate.lock();
    let flags: Vec<_> = (0..4).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let (sent, received) = mpsc::channel();
    let workers: Vec<_> = flags.iter().map(|flag| {
        let gate = gate.clone();
        let flag = flag.clone();
        let sent = sent.clone();
        thread::spawn(move || {
            let claim = gate.acquire(&flag, None);
            let claimed = claim.is_some();
            drop(claim);
            let _ = sent.send(claimed);
        })
    }).collect();
    let parked = eventually(|| gate.waiting_count() == flags.len());
    {
        // Crossing the predicate mutex after every waiter is published puts
        // them on the wait side of the atomic unlock-and-wait. Set wake bits
        // without a notification so only release's notify_one starts the chain.
        let _predicate = gate.claimed.lock();
        for flag in &flags { flag.store(true, Ordering::Release); }
    }
    drop(held);
    let results: Vec<_> = (0..flags.len()).map(|_| received.recv_timeout(WATCHDOG)).collect();
    // Rescue on a regression before joining; rescue does not repair results.
    gate.interrupt_waiters();
    for worker in workers { worker.join().unwrap(); }
    assert!(parked);
    assert!(results.iter().all(|result| *result == Ok(true)));
    assert_eq!(gate.waiting_count(), 0);
}

#[test]
fn zero_timeout_does_not_wait_for_the_predicate_mutex_either() {
    let gate = Arc::new(PollGate::default());
    let predicate = gate.claimed.lock();
    let worker_gate = gate.clone();
    let (sent, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        let missed = worker_gate
            .acquire(&AtomicBool::new(false), Some(Duration::ZERO))
            .is_none();
        let _ = sent.send(missed);
    });
    let result = received.recv_timeout(WATCHDOG);
    drop(predicate);
    worker.join().unwrap();
    assert_eq!(result, Ok(true));
}
