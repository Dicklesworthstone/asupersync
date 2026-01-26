//! Multi-worker 3-lane scheduler with work stealing.
//!
//! This scheduler coordinates multiple worker threads while maintaining
//! strict priority ordering: cancel > timed > ready.

use crate::runtime::scheduler::global_injector::GlobalInjector;
use crate::runtime::scheduler::priority::Scheduler as PriorityScheduler;
use crate::runtime::scheduler::worker::Parker;
use crate::runtime::RuntimeState;
use crate::tracing_compat::trace;
use crate::types::{TaskId, Time};
use crate::util::DetRng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Identifier for a scheduler worker.
pub type WorkerId = usize;

/// A multi-worker scheduler with 3-lane priority support.
///
/// Each worker maintains a local `PriorityScheduler` for tasks spawned within
/// that worker. Cross-thread wakeups go through the shared `GlobalInjector`.
/// Workers strictly process cancel work before timed, and timed before ready.
#[derive(Debug)]
pub struct ThreeLaneScheduler {
    /// Global injection queue for cross-thread wakeups.
    global: Arc<GlobalInjector>,
    /// Worker handles for thread spawning.
    workers: Vec<ThreeLaneWorker>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Parkers for waking idle workers.
    parkers: Vec<Parker>,
}

impl ThreeLaneScheduler {
    /// Creates a new 3-lane scheduler with the given number of workers.
    pub fn new(worker_count: usize, state: &Arc<Mutex<RuntimeState>>) -> Self {
        let global = Arc::new(GlobalInjector::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(worker_count);
        let mut parkers = Vec::with_capacity(worker_count);
        let mut local_schedulers: Vec<Arc<Mutex<PriorityScheduler>>> =
            Vec::with_capacity(worker_count);

        // Create local schedulers first so we can share references for stealing
        for _ in 0..worker_count {
            local_schedulers.push(Arc::new(Mutex::new(PriorityScheduler::new())));
        }

        // Create workers with references to all other workers' schedulers
        for id in 0..worker_count {
            let parker = Parker::new();
            parkers.push(parker.clone());

            // Stealers: all other workers' local schedulers (excluding self)
            let stealers: Vec<_> = local_schedulers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, sched)| Arc::clone(sched))
                .collect();

            workers.push(ThreeLaneWorker {
                id,
                local: Arc::clone(&local_schedulers[id]),
                stealers,
                global: Arc::clone(&global),
                state: Arc::clone(state),
                parker,
                rng: DetRng::new(id as u64),
                shutdown: Arc::clone(&shutdown),
            });
        }

        Self {
            global,
            workers,
            shutdown,
            parkers,
        }
    }

    /// Injects a task into the cancel lane for cross-thread wakeup.
    pub fn inject_cancel(&self, task: TaskId, priority: u8) {
        self.global.inject_cancel(task, priority);
        self.wake_one();
    }

    /// Injects a task into the timed lane for cross-thread wakeup.
    pub fn inject_timed(&self, task: TaskId, deadline: Time) {
        self.global.inject_timed(task, deadline);
        self.wake_one();
    }

    /// Injects a task into the ready lane for cross-thread wakeup.
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        self.global.inject_ready(task, priority);
        self.wake_one();
    }

    /// Spawns a task (shorthand for inject_ready).
    pub fn spawn(&self, task: TaskId, priority: u8) {
        self.inject_ready(task, priority);
    }

    /// Wakes a task by injecting it into the ready lane.
    ///
    /// For cancel wakeups, use `inject_cancel` instead.
    pub fn wake(&self, task: TaskId, priority: u8) {
        self.inject_ready(task, priority);
    }

    /// Wakes one idle worker.
    fn wake_one(&self) {
        // Simple strategy: wake the first parker
        // TODO: Could be smarter (round-robin, least-loaded, etc.)
        if let Some(parker) = self.parkers.first() {
            parker.unpark();
        }
    }

    /// Wakes all idle workers.
    pub fn wake_all(&self) {
        for parker in &self.parkers {
            parker.unpark();
        }
    }

    /// Extract workers to run them in threads.
    pub fn take_workers(&mut self) -> Vec<ThreeLaneWorker> {
        std::mem::take(&mut self.workers)
    }

    /// Signals all workers to shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.wake_all();
    }

    /// Returns true if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

/// A worker thread for the 3-lane scheduler.
#[derive(Debug)]
pub struct ThreeLaneWorker {
    /// Unique worker ID.
    pub id: WorkerId,
    /// Local 3-lane scheduler for this worker.
    pub local: Arc<Mutex<PriorityScheduler>>,
    /// References to other workers' local schedulers for stealing.
    pub stealers: Vec<Arc<Mutex<PriorityScheduler>>>,
    /// Global injection queue.
    pub global: Arc<GlobalInjector>,
    /// Shared runtime state.
    pub state: Arc<Mutex<RuntimeState>>,
    /// Parking mechanism for idle workers.
    pub parker: Parker,
    /// Deterministic RNG for stealing decisions.
    pub rng: DetRng,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
}

impl ThreeLaneWorker {
    /// Runs the worker scheduling loop.
    ///
    /// The loop maintains strict priority ordering:
    /// 1. Cancel work (global then local)
    /// 2. Timed work (global then local)
    /// 3. Ready work (global then local)
    /// 4. Steal from other workers
    /// 5. Park
    pub fn run_loop(&mut self) {
        while !self.shutdown.load(Ordering::Relaxed) {
            // PHASE 1: Cancel work (highest priority, never starve)
            if let Some(task) = self.try_cancel_work() {
                self.execute(task);
                continue;
            }

            // PHASE 2: Timed work
            if let Some(task) = self.try_timed_work() {
                self.execute(task);
                continue;
            }

            // PHASE 3: Ready work
            if let Some(task) = self.try_ready_work() {
                self.execute(task);
                continue;
            }

            // PHASE 4: Steal from other workers
            if let Some(task) = self.try_steal() {
                self.execute(task);
                continue;
            }

            // PHASE 5: Park until woken
            self.parker.park();
        }
    }

    /// Tries to get cancel work from global or local queues.
    fn try_cancel_work(&mut self) -> Option<TaskId> {
        // Global cancel has priority (cross-thread cancellations)
        if let Some(pt) = self.global.pop_cancel() {
            return Some(pt.task);
        }

        // Local cancel
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_cancel_only_with_hint(rng_hint)
    }

    /// Tries to get timed work from global or local queues.
    fn try_timed_work(&mut self) -> Option<TaskId> {
        // Global timed
        if let Some(tt) = self.global.pop_timed() {
            // TODO: Check if deadline is due before executing
            // For now, we assume all injected timed tasks are ready to run
            return Some(tt.task);
        }

        // Local timed
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_timed_only_with_hint(rng_hint)
    }

    /// Tries to get ready work from global or local queues.
    fn try_ready_work(&mut self) -> Option<TaskId> {
        // Global ready
        if let Some(pt) = self.global.pop_ready() {
            return Some(pt.task);
        }

        // Local ready
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_ready_only_with_hint(rng_hint)
    }

    /// Tries to steal work from other workers.
    ///
    /// Only steals from ready lanes to preserve cancel/timed priority semantics.
    fn try_steal(&mut self) -> Option<TaskId> {
        if self.stealers.is_empty() {
            return None;
        }

        let len = self.stealers.len();
        let start = self.rng.next_usize(len);

        for i in 0..len {
            let idx = (start + i) % len;
            let stealer = &self.stealers[idx];

            // Try to lock without blocking (skip if contended)
            if let Ok(mut victim) = stealer.try_lock() {
                let stolen = victim.steal_ready_batch(4);
                if !stolen.is_empty() {
                    // Take the first task to execute
                    let (first_task, _) = stolen[0];

                    // Push remaining stolen tasks to our local queue
                    if stolen.len() > 1 {
                        let mut local = self.local.lock().expect("local scheduler lock poisoned");
                        for (task, priority) in stolen.into_iter().skip(1) {
                            local.schedule(task, priority);
                        }
                    }

                    return Some(first_task);
                }
            }
        }

        None
    }

    /// Schedules a task locally in the appropriate lane.
    pub fn schedule_local(&self, task: TaskId, priority: u8) {
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        local.schedule(task, priority);
    }

    /// Schedules a cancelled task locally.
    pub fn schedule_local_cancel(&self, task: TaskId, priority: u8) {
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        local.schedule_cancel(task, priority);
    }

    /// Schedules a timed task locally.
    pub fn schedule_local_timed(&self, task: TaskId, deadline: Time) {
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        local.schedule_timed(task, deadline);
    }

    #[allow(clippy::unused_self)]
    fn execute(&self, _task: TaskId) {
        trace!(task_id = ?_task, worker_id = self.id, "executing task");
        // Placeholder for execution logic.
        // In real implementation, this would:
        // 1. Get stored future from RuntimeState
        // 2. Create Waker pointing to this Scheduler/Worker
        // 3. Poll future
        // 4. Handle Ready/Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_three_lane_scheduler_creation() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let scheduler = ThreeLaneScheduler::new(2, &state);

        assert!(!scheduler.is_shutdown());
        assert_eq!(scheduler.workers.len(), 2);
    }

    #[test]
    fn test_three_lane_worker_shutdown() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        let workers = scheduler.take_workers();
        assert_eq!(workers.len(), 2);

        // Spawn threads for workers
        let handles: Vec<_> = workers
            .into_iter()
            .map(|mut worker| {
                std::thread::spawn(move || {
                    worker.run_loop();
                })
            })
            .collect();

        // Let them run briefly
        std::thread::sleep(Duration::from_millis(10));

        // Signal shutdown
        scheduler.shutdown();

        // Join threads
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_cancel_priority_over_ready() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject ready first, then cancel
        scheduler.inject_ready(TaskId::new_for_test(1, 1), 100);
        scheduler.inject_cancel(TaskId::new_for_test(1, 2), 50);

        // Worker should get cancel first
        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // Cancel should come first
        let task1 = worker.try_cancel_work();
        assert!(task1.is_some());
        assert_eq!(task1.unwrap(), TaskId::new_for_test(1, 2));

        // Ready should come after
        let task2 = worker.try_ready_work();
        assert!(task2.is_some());
        assert_eq!(task2.unwrap(), TaskId::new_for_test(1, 1));
    }

    #[test]
    fn test_stealing_only_from_ready_lane() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        // Add cancel and ready work to worker 0's local queue
        {
            let workers = &scheduler.workers;
            let mut local0 = workers[0].local.lock().unwrap();
            local0.schedule_cancel(TaskId::new_for_test(1, 1), 100);
            local0.schedule(TaskId::new_for_test(1, 2), 50);
            local0.schedule(TaskId::new_for_test(1, 3), 50);
        }

        // Worker 1 should only be able to steal ready work
        let mut workers = scheduler.take_workers().into_iter();
        let _ = workers.next().unwrap(); // Skip worker 0
        let mut worker1 = workers.next().unwrap();

        // Stealing should only get ready tasks
        let stolen = worker1.try_steal();
        assert!(stolen.is_some());

        // The stolen task should be from ready lane (2 or 3)
        let stolen_id = stolen.unwrap();
        assert!(
            stolen_id == TaskId::new_for_test(1, 2) || stolen_id == TaskId::new_for_test(1, 3),
            "Expected ready task, got cancel task"
        );
    }
}
