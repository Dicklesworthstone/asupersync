//! Work-stealing scheduler with 3-lane priority support.
//!
//! The scheduler uses three priority lanes:
//! 1. Cancel lane (highest) - tasks with pending cancellation
//! 2. Timed lane (EDF) - tasks with deadlines
//! 3. Ready lane (lowest) - all other ready tasks
//!
//! Multi-worker scheduling preserves this strict lane ordering while
//! supporting work-stealing for load balancing across workers.

pub mod global_injector;
pub mod global_queue;
pub mod local_queue;
pub mod priority;
pub mod stealing;
pub mod three_lane;
pub mod worker;

pub use global_injector::GlobalInjector;
pub use global_queue::GlobalQueue;
pub use local_queue::LocalQueue;
pub use priority::Scheduler as PriorityScheduler;
pub use three_lane::{ThreeLaneScheduler, ThreeLaneWorker};
pub use worker::{Parker, Worker};

use crate::types::TaskId;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Work-stealing scheduler coordinator.
#[derive(Debug)]
pub struct WorkStealingScheduler {
    // Workers are moved out when threads start, so this might become empty.
    // We keep them here for initialization.
    workers: Vec<Worker>,
    global: Arc<GlobalQueue>,
    shutdown: Arc<AtomicBool>,
    parkers: Vec<Parker>,
}

impl WorkStealingScheduler {
    /// Creates a new scheduler with the given number of workers.
    ///
    /// This also creates the workers and their local queues.
    pub fn new(
        worker_count: usize,
        state: &std::sync::Arc<std::sync::Mutex<crate::runtime::RuntimeState>>,
    ) -> Self {
        let global = Arc::new(GlobalQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(worker_count);
        let mut stealers = Vec::with_capacity(worker_count);
        let mut parkers = Vec::with_capacity(worker_count);

        // First pass: create workers and collect stealers
        // We can't create workers fully yet because they need all stealers.
        // We create local queues first?
        // LocalQueue::new() -> (LocalQueue, Stealer) ?
        // LocalQueue has .stealer().

        // We'll create workers then extract stealers?
        // No, Worker owns LocalQueue.
        // We'll create LocalQueues first.
        let local_queues: Vec<LocalQueue> = (0..worker_count).map(|_| LocalQueue::new()).collect();

        for q in &local_queues {
            stealers.push(q.stealer());
        }

        for (id, local) in local_queues.into_iter().enumerate() {
            let worker_stealers = stealers.clone(); // All stealers (including self? stealing from self is weird but ok)
                                                    // Ideally filter out self.
            let my_stealers: Vec<_> = worker_stealers
                .into_iter()
                // .filter(|s| ...) // Stealer doesn't have ID.
                .collect();

            let parker = Parker::new();
            parkers.push(parker.clone());

            workers.push(Worker {
                id,
                local,
                stealers: my_stealers,
                global: Arc::clone(&global),
                state: state.clone(),
                parker,
                rng: crate::util::DetRng::new(id as u64),
                shutdown: Arc::clone(&shutdown),
            });
        }

        Self {
            workers,
            global,
            shutdown,
            parkers,
        }
    }

    /// Spawns a task.
    ///
    /// If called from a worker thread, it should push to the local queue.
    /// Otherwise, it pushes to the global queue.
    ///
    /// For Phase 1 initial implementation, we always push to global queue
    /// to avoid TLS complexity for now.
    pub fn spawn(&self, task: TaskId) {
        self.global.push(task);
        // TODO: Wake a worker
    }

    /// Wakes a task.
    pub fn wake(&self, task: TaskId) {
        self.spawn(task);
    }

    /// Extract workers to run them in threads.
    pub fn take_workers(&mut self) -> Vec<Worker> {
        std::mem::take(&mut self.workers)
    }

    /// Signals all workers to shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        for parker in &self.parkers {
            parker.unpark();
        }
    }
}

// Preserve backward compatibility for Phase 0
pub use priority::Scheduler;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeState;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn test_worker_shutdown() {
        // Create state
        let state = Arc::new(Mutex::new(RuntimeState::new()));

        // Create scheduler with 2 workers
        let mut scheduler = WorkStealingScheduler::new(2, &state);

        // Take workers
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

        // Let them run briefly (they will park immediately as there is no work)
        std::thread::sleep(Duration::from_millis(10));

        // Signal shutdown
        scheduler.shutdown();

        // Join threads (this will hang if shutdown logic is broken)
        for handle in handles {
            handle.join().unwrap();
        }

        // If we reach here, shutdown worked!
    }
}
