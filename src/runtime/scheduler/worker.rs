//! Worker thread logic.

use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::scheduler::global_queue::GlobalQueue;
use crate::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use crate::runtime::scheduler::stealing;
use crate::runtime::RuntimeState;
use crate::tracing_compat::trace;
use crate::types::Outcome;
use crate::types::TaskId;
use crate::util::DetRng;
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
        let io_driver = state
            .lock()
            .expect("runtime state lock poisoned")
            .io_driver_handle();

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
                    let _ = driver.turn(Some(Duration::from_millis(1)));

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
            record.wake_state.clear();
            let task_cx = record.cx.clone();
            let wake_state = Arc::clone(&record.wake_state);
            drop(state);
            (stored, task_cx, wake_state)
        };

        let waker = Waker::from(Arc::new(WorkStealingWaker {
            task_id,
            wake_state,
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
            }
            Poll::Pending => {
                let mut state = self.state.lock().expect("runtime state lock poisoned");
                state.store_spawned_task(task_id, stored);
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

/// A mechanism for parking and unparking a worker.
#[derive(Debug, Clone)]
pub struct Parker {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl Parker {
    /// Creates a new parker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// Parks the current thread until notified.
    pub fn park(&self) {
        let (lock, cvar) = &*self.inner;
        let mut notified = lock.lock().unwrap();
        while !*notified {
            notified = cvar.wait(notified).unwrap();
        }
        *notified = false;
    }

    /// Parks the current thread with a timeout.
    pub fn park_timeout(&self, duration: Duration) {
        let (lock, cvar) = &*self.inner;
        let notified = lock.lock().unwrap();
        if !*notified {
            let _ = cvar.wait_timeout(notified, duration).unwrap();
        }
    }

    /// Unparks a parked thread.
    pub fn unpark(&self) {
        let (lock, cvar) = &*self.inner;
        {
            let mut notified = lock.lock().unwrap();
            *notified = true;
        }
        cvar.notify_one();
    }
}

impl Default for Parker {
    fn default() -> Self {
        Self::new()
    }
}
