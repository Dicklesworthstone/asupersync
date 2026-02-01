//! Worker thread logic.

use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::scheduler::global_queue::GlobalQueue;
use crate::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use crate::runtime::scheduler::stealing;
use crate::runtime::RuntimeState;
use crate::time::TimerDriverHandle;
use crate::trace::{TraceBufferHandle, TraceEvent};
use crate::tracing_compat::trace;
use crate::types::{Outcome, TaskId, Time};
use crate::util::DetRng;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Identifier for a scheduler worker.
pub type WorkerId = usize;

/// A worker thread that executes tasks.
#[derive(Debug)]
pub struct Worker {
    /// Unique worker ID.
    pub id: WorkerId,
    /// Local task queue for this worker.
    pub local: LocalQueue,
    /// Stealers for other workers' queues.
    pub stealers: Vec<Stealer>,
    /// Global queue shared across workers.
    pub global: Arc<GlobalQueue>,
    /// Shared runtime state.
    pub state: Arc<Mutex<RuntimeState>>, // RuntimeState is usually guarded
    /// Parking mechanism for idle workers.
    pub parker: Parker,
    /// Deterministic RNG for stealing decisions.
    pub rng: DetRng,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// I/O driver handle (optional).
    pub io_driver: Option<IoDriverHandle>,
    /// Trace buffer for I/O events.
    pub trace: TraceBufferHandle,
    /// Timer driver for timestamps (optional).
    pub timer_driver: Option<TimerDriverHandle>,
    /// Tokens seen for I/O trace emission.
    seen_io_tokens: HashSet<u64>,
}

impl Worker {
    /// Creates a new worker with the provided queues and state.
    pub fn new(
        id: WorkerId,
        stealers: Vec<Stealer>,
        global: Arc<GlobalQueue>,
        state: Arc<Mutex<RuntimeState>>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let (io_driver, trace, timer_driver) = {
            let guard = state.lock().expect("runtime state lock poisoned");
            (
                guard.io_driver_handle(),
                guard.trace_handle(),
                guard.timer_driver_handle(),
            )
        };

        Self {
            id,
            local: LocalQueue::new(),
            stealers,
            global,
            state,
            parker: Parker::new(),
            rng: DetRng::new(id as u64 + 1), // Simple seed
            shutdown,
            io_driver,
            trace,
            timer_driver,
            seen_io_tokens: HashSet::new(),
        }
    }

    /// Runs the worker scheduling loop.
    pub fn run_loop(&mut self) {
        const SPIN_LIMIT: u32 = 64;
        const YIELD_LIMIT: u32 = 16;

        while !self.shutdown.load(Ordering::Relaxed) {
            // 1. Try local queue (LIFO)
            if let Some(task) = self.local.pop() {
                self.execute(task);
                continue;
            }

            // 2. Try global queue
            if let Some(task) = self.global.pop() {
                self.execute(task);
                continue;
            }

            // 3. Try stealing from random worker
            if let Some(task) = stealing::steal_task(&self.stealers, &mut self.rng) {
                self.execute(task);
                continue;
            }

            // 4. Drive I/O (Leader/Follower pattern)
            // If we can acquire the IO driver lock, we become the I/O leader.
            // The leader polls the reactor with a short timeout.
            if let Some(io) = &self.io_driver {
                if let Ok(mut driver) = io.try_lock() {
                    // Poll with a short timeout to check for I/O events without
                    // spinning too hot, but returning frequently to check for new tasks.
                    //
                    // Note: Ideally we would block indefinitely and be woken by `spawn`,
                    // but that requires integrating the Parker with the Reactor.
                    // For now, a short timeout (1ms) serves as a "busy-wait with sleep".
                    let now = self
                        .timer_driver
                        .as_ref()
                        .map_or(Time::ZERO, TimerDriverHandle::now);
                    let trace = &self.trace;
                    let seen = &mut self.seen_io_tokens;
                    let _ = driver.turn_with(Some(Duration::from_millis(1)), |event, interest| {
                        let token = event.token.0 as u64;
                        let interest_bits = interest.unwrap_or(event.ready).bits();
                        if seen.insert(token) {
                            let seq = trace.next_seq();
                            trace.push_event(TraceEvent::io_requested(
                                seq,
                                now,
                                token,
                                interest_bits,
                            ));
                        }
                        let seq = trace.next_seq();
                        trace.push_event(TraceEvent::io_ready(seq, now, token, event.ready.bits()));
                    });

                    // Loop back to check queues (tasks might have been woken by I/O)
                    continue;
                }
            }

            // 5. Backoff before parking
            // We spin/yield briefly to avoid the high latency of parking/unparking
            // if new work arrives immediately.
            let mut backoff = 0;

            loop {
                // Check queues again (abbreviated check)
                if !self.local.is_empty() || !self.global.is_empty() {
                    break;
                }

                if backoff < SPIN_LIMIT {
                    std::hint::spin_loop();
                    backoff += 1;
                } else if backoff < SPIN_LIMIT + YIELD_LIMIT {
                    std::thread::yield_now();
                    backoff += 1;
                } else {
                    self.parker.park();
                    break;
                }
            }
        }
    }

    fn execute(&self, task_id: TaskId) {
        trace!(task_id = ?task_id, worker_id = self.id, "executing task");

        let (mut stored, task_cx, wake_state) = {
            let mut state = self.state.lock().expect("runtime state lock poisoned");
            let Some(stored) = state.remove_stored_future(task_id) else {
                return;
            };
            let Some(record) = state.tasks.get_mut(task_id.arena_index()) else {
                return;
            };
            record.start_running();
            record.wake_state.begin_poll();
            let task_cx = record.cx.clone();
            let wake_state = Arc::clone(&record.wake_state);
            drop(state);
            (stored, task_cx, wake_state)
        };

        let waker = Waker::from(Arc::new(WorkStealingWaker {
            task_id,
            wake_state: Arc::clone(&wake_state),
            global: Arc::clone(&self.global),
            parker: self.parker.clone(),
        }));
        let mut cx = Context::from_waker(&waker);
        let _cx_guard = crate::cx::Cx::set_current(task_cx);

        match stored.poll(&mut cx) {
            Poll::Ready(()) => {
                let mut state = self.state.lock().expect("runtime state lock poisoned");
                if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
                    if !record.state.is_terminal() {
                        record.complete(Outcome::Ok(()));
                    }
                }

                let waiters = state.task_completed(task_id);
                for waiter in waiters {
                    state
                        .tasks
                        .get(waiter.arena_index())
                        .is_none_or(|record| record.wake_state.notify())
                        .then(|| self.global.push(waiter));
                }
                drop(state);
                wake_state.clear();
            }
            Poll::Pending => {
                let mut state = self.state.lock().expect("runtime state lock poisoned");
                state.store_spawned_task(task_id, stored);
                drop(state);
                if wake_state.finish_poll() {
                    self.global.push(task_id);
                    self.parker.unpark();
                }
            }
        }
    }
}

struct WorkStealingWaker {
    task_id: TaskId,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalQueue>,
    parker: Parker,
}

impl WorkStealingWaker {
    fn schedule(&self) {
        if self.wake_state.notify() {
            self.global.push(self.task_id);
            self.parker.unpark();
        }
    }
}

impl Wake for WorkStealingWaker {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

#[derive(Debug)]
struct ParkerInner {
    notified: AtomicBool,
    mutex: Mutex<()>,
    cvar: Condvar,
}

/// A mechanism for parking and unparking a worker.
#[derive(Debug, Clone)]
pub struct Parker {
    inner: Arc<ParkerInner>,
}

impl Parker {
    /// Creates a new parker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ParkerInner {
                notified: AtomicBool::new(false),
                mutex: Mutex::new(()),
                cvar: Condvar::new(),
            }),
        }
    }

    /// Parks the current thread until notified.
    pub fn park(&self) {
        if self.inner.notified.swap(false, Ordering::Acquire) {
            return;
        }

        let mut guard = self.inner.mutex.lock().unwrap();
        while !self.inner.notified.swap(false, Ordering::Acquire) {
            guard = self.inner.cvar.wait(guard).unwrap();
        }
        drop(guard);
    }

    /// Parks the current thread with a timeout.
    pub fn park_timeout(&self, duration: Duration) {
        if self.inner.notified.swap(false, Ordering::Acquire) {
            return;
        }

        let (guard, _timeout) = self
            .inner
            .cvar
            .wait_timeout_while(self.inner.mutex.lock().unwrap(), duration, |()| {
                !self.inner.notified.swap(false, Ordering::Acquire)
            })
            .unwrap();
        drop(guard);
    }

    /// Unparks a parked thread.
    pub fn unpark(&self) {
        self.inner.notified.store(true, Ordering::Release);
        let _guard = self.inner.mutex.lock().unwrap();
        self.inner.cvar.notify_one();
    }
}

impl Default for Parker {
    fn default() -> Self {
        Self::new()
    }
}
