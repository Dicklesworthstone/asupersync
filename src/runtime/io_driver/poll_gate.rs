//! Wake-interruptible, FIFO ownership of a shared backend poll.
//!
//! A physical reactor wake may be consumed by another participant. Waiting for
//! that participant's mutex was therefore not a wait for our own wake. Native
//! contenders enroll in an ordered queue and retain their own wake predicate.
//! A releasing poller cannot barge ahead of an enrolled successor. This is an
//! enrollment-order guarantee, not a bound on backend or OS scheduling latency.
//! No backend callback executes under the short predicate mutex.

#[cfg(not(target_arch = "wasm32"))]
use parking_lot::Condvar;
use parking_lot::Mutex;
#[cfg(not(target_arch = "wasm32"))]
use std::collections::VecDeque;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Default)]
struct GateState {
    held: bool,
    // One private condition variable per synchronous claimant lets release
    // notify the actual head, not an arbitrary peer that must go back to sleep.
    // Identity is allocation-based: no wrapping ticket can alias a live waiter.
    #[cfg(not(target_arch = "wasm32"))]
    queue: VecDeque<Arc<Condvar>>,
}

impl GateState {
    fn available(&self) -> bool {
        if self.held {
            return false;
        }
        #[cfg(not(target_arch = "wasm32"))]
        if !self.queue.is_empty() {
            return false;
        }
        true
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn notify_front(&self) {
        if let Some(next) = self.queue.front() {
            next.notify_one();
        }
    }
}

#[derive(Default)]
pub(super) struct PollGate {
    claimed: Mutex<GateState>,
    // The queue length, readable without the predicate mutex: a wake with no
    // enrolled waiter (every single-runtime wake) skips that mutex.
    #[cfg(not(target_arch = "wasm32"))]
    waiting: AtomicUsize,
}

/// Removes this exact enrollment on wake, timeout or unwind. Declare it before
/// the predicate guard so an unwind releases the mutex before this Drop locks it.
#[cfg(not(target_arch = "wasm32"))]
struct QueuedPoll<'a> {
    gate: &'a PollGate,
    changed: Arc<Condvar>,
    enrolled: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for QueuedPoll<'_> {
    fn drop(&mut self) {
        if !self.enrolled {
            return;
        }
        let mut state = self.gate.claimed.lock();
        if let Some(index) = state
            .queue
            .iter()
            .position(|waiter| Arc::ptr_eq(waiter, &self.changed))
        {
            let _ = state.queue.remove(index);
            self.gate.waiting.fetch_sub(1, Ordering::SeqCst);
            if index == 0 && !state.held {
                // A cancelled head must pass a free gate to its successor.
                state.notify_front();
            }
        }
    }
}

impl PollGate {
    /// None means this participant was woken, its timeout elapsed, or a
    /// nonblocking/browser turn encountered contention. It does NOT mean that
    /// another worker of this participant is driving its timers.
    ///
    /// Finite waits charge initial predicate-mutex contention and queued
    /// ownership contention to the same budget. An uncontended acquisition
    /// does not read the host clock. This does not bound the driver's later
    /// mutation fence, backend callback or OS scheduling delay.
    pub(super) fn acquire(
        &self,
        woken: &AtomicBool,
        timeout: Option<Duration>,
    ) -> Option<(PollPermit<'_>, Option<Duration>)> {
        #[cfg(not(target_arch = "wasm32"))]
        let mut queued;
        #[cfg(not(target_arch = "wasm32"))]
        let mut started: Option<std::time::Instant> = None;
        #[cfg(target_arch = "wasm32")]
        let mut claimed = self.claimed.try_lock()?;
        #[cfg(not(target_arch = "wasm32"))]
        let mut claimed = match self.claimed.try_lock() {
            Some(claimed) => claimed,
            None => match timeout {
                Some(budget) if budget.is_zero() => return None,
                Some(budget) => {
                    // Start before waiting for the predicate, not afterwards:
                    // a finite turn must not inherit an unbounded mutex wait.
                    started = Some(std::time::Instant::now());
                    self.claimed.try_lock_for(budget)?
                }
                None => self.claimed.lock(),
            },
        };
        if claimed.available() {
            claimed.held = true;
            #[cfg(not(target_arch = "wasm32"))]
            let timeout = timeout.map(|budget| {
                started.map_or(budget, |start| budget.saturating_sub(start.elapsed()))
            });
            return Some((PollPermit(self), timeout));
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = woken;
            None
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            // A nonblocking contender neither allocates nor takes an older
            // waiter's position. Retained wakes remain available to its owner.
            if timeout.is_some_and(|duration| duration.is_zero()) {
                return None;
            }
            if woken.swap(false, Ordering::AcqRel) {
                return None;
            }
            // Carry the original start through both contended phases. A
            // notification or transition to the FIFO must not restart a budget.
            let start = started.unwrap_or_else(std::time::Instant::now);
            queued = QueuedPoll {
                gate: self,
                changed: Arc::new(Condvar::new()),
                enrolled: false,
            };
            self.enroll(&mut claimed, &queued.changed);
            queued.enrolled = true;

            loop {
                let remaining = timeout.map(|budget| budget.saturating_sub(start.elapsed()));
                let at_front = claimed
                    .queue
                    .front()
                    .is_some_and(|waiter| Arc::ptr_eq(waiter, &queued.changed));
                if !claimed.held && at_front {
                    let _ = claimed.queue.pop_front();
                    self.waiting.fetch_sub(1, Ordering::SeqCst);
                    queued.enrolled = false;
                    claimed.held = true;
                    // Preserve a crossing wake: the participant consumes it
                    // before its backend poll and selects a zero timeout.
                    return Some((PollPermit(self), remaining));
                }
                if woken.swap(false, Ordering::SeqCst) {
                    return None;
                }
                match remaining {
                    Some(remaining) if remaining.is_zero() => return None,
                    Some(remaining) => {
                        queued.changed.wait_for(&mut claimed, remaining);
                    }
                    None => queued.changed.wait(&mut claimed),
                }
            }
        }
    }

    /// Enrolls a waiter; interrupt_waiters documents the count's ordering.
    #[cfg(not(target_arch = "wasm32"))]
    fn enroll(&self, state: &mut GateState, waiter: &Arc<Condvar>) {
        state.queue.push_back(Arc::clone(waiter));
        self.waiting.fetch_add(1, Ordering::SeqCst);
    }

    /// The caller publishes its wake bit (SeqCst) BEFORE calling this method.
    /// Holding the predicate mutex pairs that publication with each waiter's
    /// check and atomic unlock-and-wait. All participants recheck their own
    /// wake bit; ordinary ownership release notifies only the oldest enrollment.
    pub(super) fn interrupt_waiters(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Dekker pairing: the caller's SeqCst store, then this SeqCst load;
            // a waiter's SeqCst enrollment, then its SeqCst wake-bit check. If
            // this load reads zero, a later enrollee observes the bit before it
            // waits, so no enrolled waiter can be left to sleep.
            if self.waiting.load(Ordering::SeqCst) == 0 {
                return;
            }
            let state = self.claimed.lock();
            for waiter in &state.queue {
                waiter.notify_one();
            }
        }
    }

    #[cfg(all(test, unix, not(target_arch = "wasm32")))]
    pub(super) fn lock(&self) -> PollPermit<'_> {
        self.acquire(&AtomicBool::new(false), None)
            .expect("test claim without cancellation or timeout")
            .0
    }

    #[cfg(all(test, unix, not(target_arch = "wasm32")))]
    pub(super) fn waiting_count(&self) -> usize {
        let state = self.claimed.lock();
        assert_eq!(self.waiting.load(Ordering::SeqCst), state.queue.len());
        state.queue.len()
    }
}

/// Logical poll ownership, not a mutex guard: backend callbacks and mutation
/// wakeups may reenter the gate's notification path without deadlocking.
#[must_use]
pub(super) struct PollPermit<'a>(&'a PollGate);

impl Drop for PollPermit<'_> {
    fn drop(&mut self) {
        let mut claimed = self.0.claimed.lock();
        claimed.held = false;
        #[cfg(not(target_arch = "wasm32"))]
        claimed.notify_front();
    }
}

#[cfg(all(test, unix, not(target_arch = "wasm32")))]
#[path = "poll_gate_tests.rs"]
mod tests;

#[cfg(all(test, unix, not(target_arch = "wasm32")))]
mod ordered_tests {
    use super::super::{Events, Interest, IoDriverHandle, Reactor, Source, Token};
    use super::{AtomicBool, Condvar, Duration, Mutex, Ordering, PollGate, QueuedPoll};
    use std::io;
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Instant;

    const WATCHDOG: Duration = Duration::from_secs(5);

    fn enrolled(gate: &PollGate, count: usize) -> bool {
        let start = Instant::now();
        while gate.waiting_count() != count {
            if start.elapsed() >= WATCHDOG {
                return false;
            }
            thread::yield_now();
        }
        true
    }

    #[test]
    fn queued_pollers_acquire_in_enrollment_order() {
        let gate = Arc::new(PollGate::default());
        let owner = gate.lock();
        let (sent, received) = mpsc::channel();
        let mut workers = Vec::new();
        let mut witnessed = true;
        for index in 0..4 {
            let worker_gate = Arc::clone(&gate);
            let sender = sent.clone();
            workers.push(thread::spawn(move || {
                let claim = worker_gate.acquire(&AtomicBool::new(false), Some(WATCHDOG * 2));
                let _ = sender.send((index, claim.is_some()));
                drop(claim);
            }));
            witnessed &= enrolled(&gate, index + 1);
        }
        drop(owner);
        let results: Vec<_> = (0..4).map(|_| received.recv_timeout(WATCHDOG)).collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(witnessed, "every claimant was queued before the release");
        assert_eq!(
            results,
            vec![Ok((0, true)), Ok((1, true)), Ok((2, true)), Ok((3, true))]
        );
        assert_eq!(gate.waiting_count(), 0);
    }

    #[test]
    fn releasing_poller_cannot_barge_ahead_of_a_published_successor() {
        let gate = Arc::new(PollGate::default());
        let owner = gate.lock();
        let worker_gate = Arc::clone(&gate);
        let (claimed_tx, claimed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let claim = worker_gate.acquire(&AtomicBool::new(false), Some(WATCHDOG * 2));
            let claimed = claim.is_some();
            let _ = claimed_tx.send(claimed);
            let released = release_rx.recv_timeout(WATCHDOG * 2).is_ok();
            drop(claim);
            (claimed, released)
        });
        let witnessed = enrolled(&gate, 1);
        drop(owner);
        // Before the successor runs, its enrollment reserves the free gate.
        // After it runs, its permit stays held until the explicit release.
        let mut barged = false;
        for _ in 0..1_024 {
            let claim = gate.acquire(&AtomicBool::new(false), Some(Duration::ZERO));
            barged |= claim.is_some();
            drop(claim);
        }
        let claimed = claimed_rx.recv_timeout(WATCHDOG);
        let _ = release_tx.send(());
        let joined = worker.join().unwrap();
        assert!(witnessed);
        assert!(!barged, "the releasing poller stole a queued peer's turn");
        assert_eq!(claimed, Ok(true));
        assert_eq!(joined, (true, true));
        assert_eq!(gate.waiting_count(), 0);
    }

    #[test]
    fn interrupted_head_and_middle_leave_survivors_in_order() {
        for interrupted in [0, 1] {
            let gate = Arc::new(PollGate::default());
            let owner = gate.lock();
            let flags: Vec<_> = (0..3)
                .map(|_| Arc::new(AtomicBool::new(false)))
                .collect();
            let (sent, received) = mpsc::channel();
            let mut workers = Vec::new();
            let mut witnessed = true;
            for (index, flag) in flags.iter().enumerate() {
                let worker_gate = Arc::clone(&gate);
                let flag = Arc::clone(flag);
                let sender = sent.clone();
                workers.push(thread::spawn(move || {
                    let claim = worker_gate.acquire(&flag, Some(WATCHDOG * 2));
                    let _ = sender.send((index, claim.is_some()));
                    drop(claim);
                }));
                witnessed &= enrolled(&gate, index + 1);
            }
            flags[interrupted].store(true, Ordering::Release);
            gate.interrupt_waiters();
            let cancelled = received.recv_timeout(WATCHDOG);
            let remaining = gate.waiting_count();
            drop(owner);
            let survivors: Vec<_> = (0..2).map(|_| received.recv_timeout(WATCHDOG)).collect();
            for worker in workers {
                worker.join().unwrap();
            }
            assert!(witnessed);
            assert_eq!(cancelled, Ok((interrupted, false)));
            assert_eq!(remaining, 2);
            let expected: Vec<_> = (0..3)
                .filter(|index| *index != interrupted)
                .map(|index| Ok((index, true)))
                .collect();
            assert_eq!(survivors, expected);
            assert!(flags.iter().all(|flag| !flag.load(Ordering::Acquire)));
            assert_eq!(gate.waiting_count(), 0);
        }
    }

    #[test]
    fn an_unwinding_enrollment_releases_a_free_gate_to_its_successor() {
        let gate = Arc::new(PollGate::default());
        // Hold an actual queue enrollment out of the wait loop to put its
        // destructor precisely at the free-gate handoff boundary.
        let abandoned = QueuedPoll {
            gate: &gate,
            changed: Arc::new(Condvar::new()),
            enrolled: true,
        };
        gate.enroll(&mut gate.claimed.lock(), &abandoned.changed);
        let worker_gate = Arc::clone(&gate);
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let claim = worker_gate.acquire(&AtomicBool::new(false), Some(WATCHDOG * 2));
            let _ = sent.send(claim.is_some());
            drop(claim);
        });
        let witnessed = enrolled(&gate, 2);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _abandoned = abandoned;
            panic!("injected enrollment unwind");
        }));
        let result = received.recv_timeout(WATCHDOG);
        worker.join().unwrap();
        assert!(witnessed && unwound.is_err());
        assert_eq!(result, Ok(true));
        assert_eq!(gate.waiting_count(), 0);
    }

    #[derive(Default)]
    struct RecordedPolls(Mutex<Vec<thread::ThreadId>>);

    impl Reactor for RecordedPolls {
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
            self.0.lock().push(thread::current().id());
            events.clear();
            Ok(0)
        }
        fn wake(&self) -> io::Result<()> {
            Ok(())
        }
        fn registration_count(&self) -> usize {
            0
        }
    }

    #[test]
    fn independently_constructed_handles_reach_the_backend_in_enrollment_order() {
        let backend = Arc::new(RecordedPolls::default());
        let owner = IoDriverHandle::new(backend.clone());
        let held = owner._shared_owner.poll_gate.lock();
        let mut workers = Vec::new();
        let mut expected = Vec::new();
        let mut witnessed = true;
        for index in 0..4 {
            let handle = IoDriverHandle::new(backend.clone());
            let worker =
                thread::spawn(move || handle.try_turn_with(Some(WATCHDOG * 2), |_, _| {}));
            expected.push(worker.thread().id());
            workers.push(worker);
            witnessed &= enrolled(&owner._shared_owner.poll_gate, index + 1);
        }
        drop(held);
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(witnessed);
        assert!(results.iter().all(|result| matches!(result, Ok(Some(0)))));
        assert_eq!(*backend.0.lock(), expected);
        assert_eq!(owner._shared_owner.poll_gate.waiting_count(), 0);
        assert_eq!(owner.stats().unknown_tokens, 0);
    }

    #[test]
    fn finite_budget_expires_while_the_predicate_mutex_stays_locked() {
        for wake_pending in [false, true] {
            let gate = Arc::new(PollGate::default());
            let predicate = gate.claimed.lock();
            let worker_gate = Arc::clone(&gate);
            let woken = Arc::new(AtomicBool::new(wake_pending));
            let worker_woken = Arc::clone(&woken);
            let (sent, received) = mpsc::channel();
            let worker = thread::spawn(move || {
                let claim = worker_gate
                    .acquire(&worker_woken, Some(Duration::from_millis(10)));
                let _ = sent.send(claim.is_none());
                drop(claim);
            });
            // This guard stays held through receipt: a successful result cannot
            // have come from an uncontended or merely queued ownership path.
            let expired = received.recv_timeout(WATCHDOG);
            drop(predicate); // Rescue old code before joining and asserting.
            worker.join().unwrap();
            assert_eq!(expired, Ok(true));
            assert_eq!(gate.waiting_count(), 0, "no expired enrollment remains");
            assert_eq!(woken.load(Ordering::Acquire), wake_pending);
            assert!(gate.acquire(&woken, Some(Duration::ZERO)).is_some());
        }
    }

    #[test]
    fn expired_head_does_not_hold_up_a_live_successor() {
        let gate = Arc::new(PollGate::default());
        let owner = gate.lock();
        let first_gate = Arc::clone(&gate);
        let (first_tx, first_rx) = mpsc::channel();
        let first = thread::spawn(move || {
            let claim = first_gate
                .acquire(&AtomicBool::new(false), Some(Duration::from_secs(1)));
            let _ = first_tx.send(claim.is_none());
            drop(claim);
        });
        let first_queued = enrolled(&gate, 1);
        let second_gate = Arc::clone(&gate);
        let (second_tx, second_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            let claim = second_gate.acquire(&AtomicBool::new(false), Some(WATCHDOG * 2));
            let _ = second_tx.send(claim.is_some());
            drop(claim);
        });
        let both_queued = enrolled(&gate, 2);
        // Hold ownership until the first claimant's own budget expires.
        let expired = first_rx.recv_timeout(WATCHDOG);
        let remaining = gate.waiting_count();
        let still_waiting = matches!(second_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
        drop(owner);
        let succeeded = second_rx.recv_timeout(WATCHDOG);
        first.join().unwrap();
        second.join().unwrap();
        assert!(first_queued && both_queued);
        assert_eq!(expired, Ok(true));
        assert_eq!(remaining, 1);
        assert!(still_waiting);
        assert_eq!(succeeded, Ok(true));
        assert_eq!(gate.waiting_count(), 0);
    }
}
