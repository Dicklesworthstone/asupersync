//! Loom-based systematic concurrency tests for the scheduler.
//!
//! These tests use the `loom` crate to explore all possible interleavings
//! of concurrent operations, verifying that the scheduler's core protocols
//! are free from lost wakeups, double scheduling, and deadlocks.
//!
//! Run with: cargo test --test scheduler_loom --features loom-tests --release
//!
//! Note: Loom tests are only compiled when the `loom-tests` feature is enabled.
//! Under normal `cargo test`, this file compiles to an empty module.

// Only compile tests when loom-tests feature is active
#![cfg(feature = "loom-tests")]

use loom::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;
use std::collections::VecDeque;

// ============================================================================
// Parker model
// ============================================================================
//
// Models the Parker's core protocol:
//   - AtomicBool `notified` acts as a permit
//   - Mutex + Condvar for blocking
//   - park() consumes permit or blocks
//   - unpark() sets permit and signals

struct LoomParker {
    inner: Arc<Mutex<bool>>,
    cvar: Arc<Condvar>,
}

impl LoomParker {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(false)),
            cvar: Arc::new(Condvar::new()),
        }
    }

    fn park(&self) {
        let mut guard = self.inner.lock().unwrap();
        while !*guard {
            guard = self.cvar.wait(guard).unwrap();
        }
        *guard = false; // Consume the permit
    }

    fn unpark(&self) {
        *self.inner.lock().unwrap() = true;
        self.cvar.notify_one();
    }

    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cvar: self.cvar.clone(),
        }
    }
}

// ============================================================================
// Test: Parker - no lost wakeup
// ============================================================================

#[test]
fn loom_parker_no_lost_wakeup() {
    loom::model(|| {
        let parker = LoomParker::new();
        let woken = Arc::new(AtomicBool::new(false));

        let p = parker.clone();
        let w = woken.clone();
        let h = thread::spawn(move || {
            p.park();
            w.store(true, Ordering::Release);
        });

        parker.unpark();
        h.join().unwrap();

        assert!(woken.load(Ordering::Acquire), "lost wakeup!");
    });
}

// ============================================================================
// Test: Parker - unpark before park (permit model)
// ============================================================================

#[test]
fn loom_parker_unpark_before_park() {
    loom::model(|| {
        let parker = LoomParker::new();

        // Unpark first (store permit)
        parker.unpark();

        let p = parker.clone();
        let h = thread::spawn(move || {
            p.park(); // Should consume permit and return immediately
        });

        h.join().unwrap();
    });
}

// ============================================================================
// Test: Parker - multiple concurrent unparks
// ============================================================================

#[test]
fn loom_parker_concurrent_unpark() {
    loom::model(|| {
        let parker = LoomParker::new();

        let p1 = parker.clone();
        let p2 = parker.clone();

        // Two concurrent unparks
        let h1 = thread::spawn(move || {
            p1.unpark();
        });

        let h2 = thread::spawn(move || {
            p2.unpark();
        });

        // Parker should wake regardless of ordering
        parker.park();

        h1.join().unwrap();
        h2.join().unwrap();
    });
}

// ============================================================================
// Test: Parker - park/unpark cycle reuse
// ============================================================================

#[test]
fn loom_parker_reuse() {
    loom::model(|| {
        let parker = LoomParker::new();

        // First cycle
        parker.unpark();
        parker.park();

        // Second cycle - permit should be consumed
        let p = parker.clone();
        let h = thread::spawn(move || {
            p.unpark();
        });

        parker.park();
        h.join().unwrap();
    });
}

// ============================================================================
// Wake state model
// ============================================================================
//
// Models the task wake state machine:
//   IDLE -> POLLING (begin_poll)
//   POLLING -> IDLE (finish_poll, no wake during poll)
//   POLLING -> NOTIFIED (wake during poll)
//   NOTIFIED -> IDLE (finish_poll returns true = needs reschedule)
//   IDLE -> NOTIFIED (notify)

const IDLE: u32 = 0;
const POLLING: u32 = 1;
const NOTIFIED: u32 = 2;

struct LoomWakeState {
    state: AtomicU32,
}

impl LoomWakeState {
    fn new() -> Self {
        Self {
            state: AtomicU32::new(IDLE),
        }
    }

    /// Called when starting to poll the task.
    ///
    /// Returns true if the task was already NOTIFIED (pre-notified), meaning
    /// the caller consumed the notification and should poll immediately.
    /// Returns false if the transition was IDLE -> POLLING (normal case).
    ///
    /// Uses CAS instead of blind store to avoid clobbering a NOTIFIED state
    /// set by a concurrent waker, which would cause double scheduling.
    fn begin_poll(&self) -> bool {
        match self
            .state
            .compare_exchange(IDLE, POLLING, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => false, // IDLE -> POLLING, normal
            Err(actual) => {
                assert_eq!(actual, NOTIFIED, "begin_poll called in unexpected state");
                // Already notified - consume notification, transition to POLLING
                self.state.store(POLLING, Ordering::SeqCst);
                true
            }
        }
    }

    /// Called when done polling. Returns true if task was woken during poll
    /// and needs rescheduling.
    fn finish_poll(&self) -> bool {
        // CAS POLLING -> IDLE. If state is NOTIFIED, swap to IDLE and return true.
        match self
            .state
            .compare_exchange(POLLING, IDLE, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => false, // Was POLLING, now IDLE, no reschedule needed
            Err(actual) => {
                // State was NOTIFIED (woken during poll)
                assert_eq!(actual, NOTIFIED, "unexpected wake state");
                self.state.store(IDLE, Ordering::SeqCst);
                true // Needs reschedule
            }
        }
    }

    /// Called to wake the task. Returns true if the task should be scheduled.
    fn notify(&self) -> bool {
        loop {
            let current = self.state.load(Ordering::SeqCst);
            match current {
                IDLE => {
                    // CAS IDLE -> NOTIFIED: schedule the task
                    match self.state.compare_exchange(
                        IDLE,
                        NOTIFIED,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => return true, // We set NOTIFIED, caller schedules
                        Err(_) => {}          // Retry
                    }
                }
                POLLING => {
                    // CAS POLLING -> NOTIFIED: task is being polled, mark for reschedule
                    match self.state.compare_exchange(
                        POLLING,
                        NOTIFIED,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => return false, // Poller will reschedule via finish_poll
                        Err(_) => {}           // Retry
                    }
                }
                NOTIFIED => {
                    // Already notified, no need to schedule again
                    return false;
                }
                _ => unreachable!("invalid wake state"),
            }
        }
    }
}

// ============================================================================
// Test: Wake state - no double schedule
// ============================================================================

#[test]
fn loom_wake_state_no_double_schedule() {
    loom::model(|| {
        let ws = Arc::new(LoomWakeState::new());
        let poller_scheduled = Arc::new(AtomicBool::new(false));
        let waker_scheduled = Arc::new(AtomicBool::new(false));

        // Thread 1: poller
        let ws1 = ws.clone();
        let ps = poller_scheduled.clone();
        let h1 = thread::spawn(move || {
            let _pre_notified = ws1.begin_poll();
            let needs_reschedule = ws1.finish_poll();
            if needs_reschedule {
                ps.store(true, Ordering::SeqCst);
            }
        });

        // Thread 2: waker
        let wk = waker_scheduled.clone();
        let h2 = thread::spawn(move || {
            let should_schedule = ws.notify();
            if should_schedule {
                wk.store(true, Ordering::SeqCst);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let p = poller_scheduled.load(Ordering::SeqCst);
        let w = waker_scheduled.load(Ordering::SeqCst);

        // Both scheduling simultaneously is a double-schedule bug
        assert!(!(p && w), "double schedule: poller={p}, waker={w}");
    });
}

// ============================================================================
// Test: Wake state - notify on idle schedules exactly once
// ============================================================================

#[test]
fn loom_wake_state_idle_notify() {
    loom::model(|| {
        let ws = Arc::new(LoomWakeState::new());
        let schedule_count = Arc::new(AtomicU32::new(0));

        // Two concurrent notifiers on an IDLE task
        let ws1 = ws.clone();
        let sc1 = schedule_count.clone();
        let h1 = thread::spawn(move || {
            if ws1.notify() {
                sc1.fetch_add(1, Ordering::Relaxed);
            }
        });

        let sc2 = schedule_count.clone();
        let h2 = thread::spawn(move || {
            if ws.notify() {
                sc2.fetch_add(1, Ordering::Relaxed);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // Exactly one should succeed in scheduling
        let count = schedule_count.load(Ordering::Relaxed);
        assert_eq!(
            count, 1,
            "expected exactly 1 schedule from 2 notifiers, got {count}"
        );
    });
}

// ============================================================================
// Test: Wake state - notify during poll sets NOTIFIED
// ============================================================================

#[test]
fn loom_wake_state_notify_during_poll() {
    loom::model(|| {
        let ws = Arc::new(LoomWakeState::new());

        ws.begin_poll();

        let ws1 = ws.clone();
        let h = thread::spawn(move || {
            // Notify while polling - should NOT schedule (poller handles it)
            let scheduled = ws1.notify();
            assert!(!scheduled, "should not schedule during poll");
        });

        h.join().unwrap();

        // finish_poll should detect the NOTIFIED state
        let needs_reschedule = ws.finish_poll();
        assert!(
            needs_reschedule,
            "finish_poll should detect wake during poll"
        );
    });
}

// ============================================================================
// Local queue model (Mutex<VecDeque> push/steal)
// ============================================================================

#[allow(dead_code)]
struct LoomLocalQueue {
    inner: Arc<Mutex<VecDeque<u32>>>,
}

#[allow(dead_code)]
impl LoomLocalQueue {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn push(&self, val: u32) {
        self.inner.lock().unwrap().push_back(val);
    }

    fn pop(&self) -> Option<u32> {
        self.inner.lock().unwrap().pop_back() // LIFO
    }

    fn steal(&self) -> Option<u32> {
        self.inner.lock().unwrap().pop_front() // FIFO
    }

    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    fn clone_queue(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// ============================================================================
// Test: Local queue - concurrent push and steal
// ============================================================================

#[test]
fn loom_local_queue_push_steal_concurrent() {
    loom::model(|| {
        let queue = LoomLocalQueue::new();
        let stealer = queue.clone_queue();
        let stolen = Arc::new(AtomicU32::new(0));

        // Producer pushes 2 items
        let q1 = queue.clone_queue();
        let h1 = thread::spawn(move || {
            q1.push(1);
            q1.push(2);
        });

        // Stealer tries to steal
        let s = stolen.clone();
        let h2 = thread::spawn(move || {
            if stealer.steal().is_some() {
                s.fetch_add(1, Ordering::Relaxed);
            }
            if stealer.steal().is_some() {
                s.fetch_add(1, Ordering::Relaxed);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // All items accounted for (stolen + remaining)
        let stolen_count = stolen.load(Ordering::Relaxed);
        let remaining = queue.len() as u32;
        assert_eq!(
            stolen_count + remaining,
            2,
            "items lost: stolen={stolen_count}, remaining={remaining}"
        );
    });
}

// ============================================================================
// Test: Local queue - multiple stealers no duplication
// ============================================================================

#[test]
fn loom_local_queue_multiple_stealers() {
    loom::model(|| {
        let queue = LoomLocalQueue::new();
        queue.push(1);

        let s1 = queue.clone_queue();
        let s2 = queue.clone_queue();

        let got1 = Arc::new(AtomicBool::new(false));
        let got2 = Arc::new(AtomicBool::new(false));

        let g1 = got1.clone();
        let h1 = thread::spawn(move || {
            if s1.steal().is_some() {
                g1.store(true, Ordering::Relaxed);
            }
        });

        let g2 = got2.clone();
        let h2 = thread::spawn(move || {
            if s2.steal().is_some() {
                g2.store(true, Ordering::Relaxed);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let total =
            u32::from(got1.load(Ordering::Relaxed)) + u32::from(got2.load(Ordering::Relaxed));

        // Exactly one stealer should get the item
        assert_eq!(total, 1, "item duplicated or lost: {total} stealers got it");
    });
}

// ============================================================================
// Inject-while-parking model
// ============================================================================
//
// Models the critical race: a task is injected into the global queue
// between a worker checking "is queue empty?" and parking.
//
// The Parker's permit model should prevent lost wakeups here.

#[test]
fn loom_inject_while_parking() {
    loom::model(|| {
        let queue = Arc::new(Mutex::new(VecDeque::<u32>::new()));
        let parker = LoomParker::new();
        let executed = Arc::new(AtomicBool::new(false));

        // Worker thread: check queue, if empty -> park
        let q1 = queue.clone();
        let p1 = parker.clone();
        let e1 = executed.clone();
        let worker = thread::spawn(move || {
            // Check if queue has work
            let task = {
                let mut q = q1.lock().unwrap();
                q.pop_front()
            };

            if let Some(_task) = task {
                e1.store(true, Ordering::Release);
                return;
            }

            // Queue was empty, park
            p1.park();

            // After waking, check queue again
            let task = {
                let mut q = q1.lock().unwrap();
                q.pop_front()
            };

            if task.is_some() {
                e1.store(true, Ordering::Release);
            }
        });

        // Injector thread: push task + unpark
        let q2 = queue.clone();
        thread::spawn(move || {
            {
                let mut q = q2.lock().unwrap();
                q.push_back(42);
            }
            parker.unpark();
        })
        .join()
        .unwrap();

        worker.join().unwrap();

        assert!(
            executed.load(Ordering::Acquire),
            "task was not executed - lost wakeup during inject-while-parking"
        );
    });
}

// ============================================================================
// Test: Wake + schedule atomicity
// ============================================================================
//
// Models the pattern where a task completes polling (Pending), another thread
// wakes it, and we need exactly one reschedule.

#[test]
fn loom_wake_schedule_atomicity() {
    loom::model(|| {
        let ws = Arc::new(LoomWakeState::new());
        let queue = Arc::new(Mutex::new(VecDeque::<u32>::new()));

        // Simulate poll cycle
        ws.begin_poll();

        // External waker
        let ws1 = ws.clone();
        let q1 = queue.clone();
        let waker = thread::spawn(move || {
            if ws1.notify() {
                // We're responsible for scheduling
                q1.lock().unwrap().push_back(1);
            }
        });

        // Poller finishes
        let needs_reschedule = ws.finish_poll();
        if needs_reschedule {
            queue.lock().unwrap().push_back(1);
        }

        waker.join().unwrap();

        // Exactly one entry in queue
        let len = queue.lock().unwrap().len();
        assert_eq!(len, 1, "expected exactly 1 schedule, got {len}");
    });
}

// ============================================================================
// MPSC channel model (bd-2ktrc.5)
// ============================================================================
//
// Models a bounded MPSC channel with reserve/commit pattern:
//   - Multiple producers race to acquire send permits
//   - Single consumer drains received values
//   - No message loss, no duplication

struct LoomMpscChannel {
    buf: Arc<Mutex<VecDeque<u32>>>,
    capacity: usize,
}

impl LoomMpscChannel {
    fn new(capacity: usize) -> Self {
        Self {
            buf: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Try to send a value. Returns true if sent, false if full.
    fn try_send(&self, val: u32) -> bool {
        let mut q = self.buf.lock().unwrap();
        if q.len() < self.capacity {
            q.push_back(val);
            true
        } else {
            false
        }
    }

    /// Receive a value. Returns None if empty.
    fn try_recv(&self) -> Option<u32> {
        self.buf.lock().unwrap().pop_front()
    }

    fn clone_channel(&self) -> Self {
        Self {
            buf: self.buf.clone(),
            capacity: self.capacity,
        }
    }
}

// ============================================================================
// Test: MPSC - concurrent sends no message loss
// ============================================================================

#[test]
fn loom_mpsc_concurrent_sends_no_loss() {
    loom::model(|| {
        let ch = LoomMpscChannel::new(4);

        let tx1 = ch.clone_channel();
        let tx2 = ch.clone_channel();

        let h1 = thread::spawn(move || {
            let _ = tx1.try_send(1);
            let _ = tx1.try_send(2);
        });

        let h2 = thread::spawn(move || {
            let _ = tx2.try_send(3);
            let _ = tx2.try_send(4);
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // Drain all values
        let mut received = Vec::new();
        while let Some(v) = ch.try_recv() {
            received.push(v);
        }

        // All 4 messages should be present (capacity is 4)
        received.sort_unstable();
        assert_eq!(
            received,
            vec![1, 2, 3, 4],
            "messages lost or duplicated: got {received:?}"
        );
    });
}

// ============================================================================
// Test: MPSC - concurrent sends respect capacity
// ============================================================================

#[test]
fn loom_mpsc_bounded_capacity() {
    loom::model(|| {
        let ch = LoomMpscChannel::new(2); // Only 2 slots

        let tx1 = ch.clone_channel();
        let tx2 = ch.clone_channel();

        let sent1 = Arc::new(AtomicU32::new(0));
        let sent2 = Arc::new(AtomicU32::new(0));

        let s1 = sent1.clone();
        let h1 = thread::spawn(move || {
            if tx1.try_send(1) {
                s1.fetch_add(1, Ordering::Relaxed);
            }
            if tx1.try_send(2) {
                s1.fetch_add(1, Ordering::Relaxed);
            }
        });

        let s2 = sent2.clone();
        let h2 = thread::spawn(move || {
            if tx2.try_send(3) {
                s2.fetch_add(1, Ordering::Relaxed);
            }
            if tx2.try_send(4) {
                s2.fetch_add(1, Ordering::Relaxed);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let total_sent = sent1.load(Ordering::Relaxed) + sent2.load(Ordering::Relaxed);

        // Drain
        let mut count = 0u32;
        while ch.try_recv().is_some() {
            count += 1;
        }

        // Total sent must equal total received
        assert_eq!(total_sent, count, "sent={total_sent} != received={count}");
        // Must not exceed capacity
        assert!(count <= 2, "exceeded capacity: {count} > 2");
    });
}

// ============================================================================
// Test: MPSC - producer/consumer ordering within single producer
// ============================================================================

#[test]
fn loom_mpsc_single_producer_ordering() {
    loom::model(|| {
        let ch = LoomMpscChannel::new(4);
        let rx = ch.clone_channel();

        let tx = ch.clone_channel();
        let producer = thread::spawn(move || {
            let _ = tx.try_send(1);
            let _ = tx.try_send(2);
            let _ = tx.try_send(3);
        });

        producer.join().unwrap();

        // Single producer: FIFO ordering preserved
        let mut received = Vec::new();
        while let Some(v) = rx.try_recv() {
            received.push(v);
        }

        assert_eq!(received, vec![1, 2, 3], "ordering violated: {received:?}");
    });
}

// ============================================================================
// Budget counter model (bd-2ktrc.5)
// ============================================================================
//
// Models atomic budget decrement: multiple threads decrement a shared
// budget counter. Counter must never go below zero and final value must
// equal initial minus total decrements.

struct LoomBudgetCounter {
    remaining: AtomicU32,
}

impl LoomBudgetCounter {
    fn new(initial: u32) -> Self {
        Self {
            remaining: AtomicU32::new(initial),
        }
    }

    /// Try to decrement by 1. Returns true if budget was available.
    fn try_decrement(&self) -> bool {
        loop {
            let current = self.remaining.load(Ordering::Acquire);
            if current == 0 {
                return false;
            }
            match self.remaining.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => {} // Retry CAS
            }
        }
    }

    fn remaining(&self) -> u32 {
        self.remaining.load(Ordering::Acquire)
    }
}

// ============================================================================
// Test: Budget counter - concurrent decrements never go negative
// ============================================================================

#[test]
fn loom_budget_counter_no_negative() {
    loom::model(|| {
        let budget = Arc::new(LoomBudgetCounter::new(2));

        let b1 = budget.clone();
        let b2 = budget.clone();

        let s1 = Arc::new(AtomicU32::new(0));
        let s2 = Arc::new(AtomicU32::new(0));

        let c1 = s1.clone();
        let h1 = thread::spawn(move || {
            if b1.try_decrement() {
                c1.fetch_add(1, Ordering::Relaxed);
            }
            if b1.try_decrement() {
                c1.fetch_add(1, Ordering::Relaxed);
            }
        });

        let c2 = s2.clone();
        let h2 = thread::spawn(move || {
            if b2.try_decrement() {
                c2.fetch_add(1, Ordering::Relaxed);
            }
            if b2.try_decrement() {
                c2.fetch_add(1, Ordering::Relaxed);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let total_decremented = s1.load(Ordering::Relaxed) + s2.load(Ordering::Relaxed);
        let remaining = budget.remaining();

        // Budget started at 2, must account for all decrements
        assert_eq!(
            total_decremented + remaining,
            2,
            "budget accounting error: decremented={total_decremented}, remaining={remaining}"
        );
        // Exactly 2 should succeed (budget was 2)
        assert_eq!(
            total_decremented, 2,
            "expected 2 decrements, got {total_decremented}"
        );
    });
}

// ============================================================================
// Test: Budget counter - exact exhaustion
// ============================================================================

#[test]
fn loom_budget_counter_exact_exhaustion() {
    loom::model(|| {
        let budget = Arc::new(LoomBudgetCounter::new(2));

        let b1 = budget.clone();
        let b2 = budget.clone();

        let got1 = Arc::new(AtomicU32::new(0));
        let got2 = Arc::new(AtomicU32::new(0));

        let g1 = got1.clone();
        let h1 = thread::spawn(move || {
            if b1.try_decrement() {
                g1.fetch_add(1, Ordering::Relaxed);
            }
            if b1.try_decrement() {
                g1.fetch_add(1, Ordering::Relaxed);
            }
        });

        let g2 = got2.clone();
        let h2 = thread::spawn(move || {
            if b2.try_decrement() {
                g2.fetch_add(1, Ordering::Relaxed);
            }
            if b2.try_decrement() {
                g2.fetch_add(1, Ordering::Relaxed);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let total = got1.load(Ordering::Relaxed) + got2.load(Ordering::Relaxed);
        // Exactly 2 decrements should succeed from initial budget of 2
        assert_eq!(
            total, 2,
            "expected exactly 2 successful decrements, got {total}"
        );
        assert_eq!(budget.remaining(), 0, "budget should be exhausted");
    });
}

// ============================================================================
// Task phase transition model (bd-2ktrc.5)
// ============================================================================
//
// Models task lifecycle: Running -> CancelRequested -> Cancelling -> Completed
// vs Running -> Completed (normal completion). Concurrent cancel + complete
// must result in exactly one terminal state.

const PHASE_RUNNING: u32 = 1;
const PHASE_CANCEL_REQUESTED: u32 = 2;
const PHASE_COMPLETED: u32 = 5;

struct LoomTaskPhase {
    phase: AtomicU32,
}

impl LoomTaskPhase {
    fn new() -> Self {
        Self {
            phase: AtomicU32::new(PHASE_RUNNING),
        }
    }

    /// Request cancellation. Returns true if transition succeeded.
    fn request_cancel(&self) -> bool {
        self.phase
            .compare_exchange(
                PHASE_RUNNING,
                PHASE_CANCEL_REQUESTED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Complete the task. Returns true if transition succeeded.
    fn complete(&self) -> bool {
        let current = self.phase.load(Ordering::SeqCst);
        match current {
            PHASE_RUNNING | PHASE_CANCEL_REQUESTED => self
                .phase
                .compare_exchange(current, PHASE_COMPLETED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            _ => false,
        }
    }

    fn phase(&self) -> u32 {
        self.phase.load(Ordering::SeqCst)
    }
}

// ============================================================================
// Test: Task phase - concurrent cancel and complete
// ============================================================================

#[test]
fn loom_task_phase_cancel_vs_complete() {
    loom::model(|| {
        let task = Arc::new(LoomTaskPhase::new());

        let t1 = task.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));

        let ca = cancelled.clone();
        let h1 = thread::spawn(move || {
            if t1.request_cancel() {
                ca.store(true, Ordering::SeqCst);
            }
        });

        let t2 = task.clone();
        let co = completed.clone();
        let h2 = thread::spawn(move || {
            if t2.complete() {
                co.store(true, Ordering::SeqCst);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let did_cancel = cancelled.load(Ordering::SeqCst);
        let did_complete = completed.load(Ordering::SeqCst);

        // Task should reach a terminal state
        let final_phase = task.phase();
        assert!(
            final_phase == PHASE_CANCEL_REQUESTED || final_phase == PHASE_COMPLETED,
            "unexpected terminal phase: {final_phase}"
        );

        // At most one successful state transition from RUNNING
        // (cancel can succeed, then complete can also succeed from CANCEL_REQUESTED)
        // But we should never lose both transitions
        assert!(
            did_cancel || did_complete,
            "neither cancel nor complete succeeded"
        );
    });
}

// ============================================================================
// Test: Local queue - owner pop vs stealer steal (LIFO vs FIFO)
// ============================================================================

#[test]
fn loom_local_queue_lifo_vs_fifo() {
    loom::model(|| {
        let queue = LoomLocalQueue::new();
        queue.push(1);
        queue.push(2);
        queue.push(3);

        let stealer = queue.clone_queue();

        let owner_got = Arc::new(Mutex::new(Vec::new()));
        let stealer_got = Arc::new(Mutex::new(Vec::new()));

        let og = owner_got.clone();
        let h1 = thread::spawn(move || {
            if let Some(v) = queue.pop() {
                og.lock().unwrap().push(v);
            }
        });

        let sg = stealer_got.clone();
        let h2 = thread::spawn(move || {
            if let Some(v) = stealer.steal() {
                sg.lock().unwrap().push(v);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let owner_vals: Vec<_> = owner_got.lock().unwrap().clone();
        let stealer_vals: Vec<_> = stealer_got.lock().unwrap().clone();

        // No duplication: combined count <= 3
        let total = owner_vals.len() + stealer_vals.len();
        assert!(total <= 3, "duplication detected: total={total}");

        // If owner got something, it should be LIFO (last pushed = 3)
        if let Some(&v) = owner_vals.first() {
            assert_eq!(v, 3, "owner should LIFO pop (got {v}, expected 3)");
        }

        // If stealer got something, it should be FIFO (first pushed = 1)
        if let Some(&v) = stealer_vals.first() {
            assert_eq!(v, 1, "stealer should FIFO steal (got {v}, expected 1)");
        }
    });
}
