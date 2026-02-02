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
    notified: AtomicBool,
    mutex: Mutex<()>,
    cvar: Condvar,
}

impl LoomParker {
    fn new() -> Self {
        Self {
            notified: AtomicBool::new(false),
            mutex: Mutex::new(()),
            cvar: Condvar::new(),
        }
    }

    fn park(&self) {
        // Fast path: consume permit without blocking
        if self.notified.swap(false, Ordering::Acquire) {
            return;
        }

        let mut guard = self.mutex.lock().unwrap();
        while !self.notified.swap(false, Ordering::Acquire) {
            guard = self.cvar.wait(guard).unwrap();
        }
        drop(guard);
    }

    fn unpark(&self) {
        self.notified.store(true, Ordering::Release);
        let _guard = self.mutex.lock().unwrap();
        self.cvar.notify_one();
    }
}

// ============================================================================
// Test: Parker - no lost wakeup
// ============================================================================

#[test]
fn loom_parker_no_lost_wakeup() {
    loom::model(|| {
        let parker = Arc::new(LoomParker::new());
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
        let parker = Arc::new(LoomParker::new());

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
        let parker = Arc::new(LoomParker::new());

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
        let parker = Arc::new(LoomParker::new());

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
    fn begin_poll(&self) {
        self.state.store(POLLING, Ordering::Release);
    }

    /// Called when done polling. Returns true if task was woken during poll
    /// and needs rescheduling.
    fn finish_poll(&self) -> bool {
        // CAS POLLING -> IDLE. If state is NOTIFIED, swap to IDLE and return true.
        match self
            .state
            .compare_exchange(POLLING, IDLE, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => false, // Was POLLING, now IDLE, no reschedule needed
            Err(actual) => {
                // State was NOTIFIED (woken during poll)
                assert_eq!(actual, NOTIFIED, "unexpected wake state");
                self.state.store(IDLE, Ordering::Release);
                true // Needs reschedule
            }
        }
    }

    /// Called to wake the task. Returns true if the task should be scheduled.
    fn notify(&self) -> bool {
        loop {
            let current = self.state.load(Ordering::Acquire);
            match current {
                IDLE => {
                    // CAS IDLE -> NOTIFIED: schedule the task
                    match self.state.compare_exchange_weak(
                        IDLE,
                        NOTIFIED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return true, // We set NOTIFIED, caller schedules
                        Err(_) => continue,   // Retry
                    }
                }
                POLLING => {
                    // CAS POLLING -> NOTIFIED: task is being polled, mark for reschedule
                    match self.state.compare_exchange_weak(
                        POLLING,
                        NOTIFIED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return false, // Poller will reschedule via finish_poll
                        Err(_) => continue,    // Retry
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
        let schedule_count = Arc::new(AtomicU32::new(0));

        // Thread 1: poller
        let ws1 = ws.clone();
        let sc1 = schedule_count.clone();
        let h1 = thread::spawn(move || {
            ws1.begin_poll();
            // Simulate some work
            let needs_reschedule = ws1.finish_poll();
            if needs_reschedule {
                sc1.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Thread 2: waker
        let ws2 = ws.clone();
        let sc2 = schedule_count.clone();
        let h2 = thread::spawn(move || {
            let should_schedule = ws2.notify();
            if should_schedule {
                sc2.fetch_add(1, Ordering::Relaxed);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // Exactly one schedule should happen (either waker or poller, not both)
        let count = schedule_count.load(Ordering::Relaxed);
        assert!(count <= 1, "double schedule detected: count={count}");
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

        let ws2 = ws.clone();
        let sc2 = schedule_count.clone();
        let h2 = thread::spawn(move || {
            if ws2.notify() {
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

struct LoomLocalQueue {
    inner: Arc<Mutex<VecDeque<u32>>>,
}

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
        let parker = Arc::new(LoomParker::new());
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
        let p2 = parker.clone();
        thread::spawn(move || {
            {
                let mut q = q2.lock().unwrap();
                q.push_back(42);
            }
            p2.unpark();
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
