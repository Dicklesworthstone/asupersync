//! Work-stealing scheduler with 3-lane priority support.
//!
//! The scheduler uses three priority lanes:
//! 1. Cancel lane (highest) - tasks with pending cancellation
//! 2. Timed lane (EDF) - tasks with deadlines
//! 3. Ready lane (lowest) - all other ready tasks
//!
//! Multi-worker scheduling preserves this strict lane ordering while
//! supporting work-stealing for load balancing across workers.

pub mod decision_contract;
pub mod global_injector;
pub mod global_queue;
pub mod intrusive;
pub mod intrusive_heap;
pub mod local_queue;
pub mod priority;
pub mod stealing;
pub mod three_lane;
pub mod worker;

pub use global_injector::GlobalInjector;
pub use global_queue::GlobalQueue;
pub use intrusive::{IntrusiveRing, IntrusiveStack, QUEUE_TAG_CANCEL, QUEUE_TAG_READY};
pub use intrusive_heap::IntrusivePriorityHeap;
pub use local_queue::LocalQueue;
pub use priority::{
    DispatchLane, ScheduleCertificate, Scheduler as PriorityScheduler, SchedulerMode,
};
pub use three_lane::{ThreeLaneScheduler, ThreeLaneWorker};
pub use worker::{Parker, Worker};

use crate::types::TaskId;

/// Work-stealing scheduler coordinator.
#[derive(Debug)]
pub struct WorkStealingScheduler {
    inner: ThreeLaneScheduler,
}

impl WorkStealingScheduler {
    /// Creates a new scheduler with the given number of workers.
    ///
    /// This also creates the workers and their local queues.
    pub fn new(
        worker_count: usize,
        state: &std::sync::Arc<crate::sync::ContendedMutex<crate::runtime::RuntimeState>>,
    ) -> Self {
        // A zero-worker scheduler cannot make progress; clamp to one worker
        // to preserve forward progress for direct users of this API.
        let worker_count = worker_count.max(1);
        Self {
            inner: ThreeLaneScheduler::new(worker_count, state),
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
        self.inner.spawn(task, 0);
    }

    /// Wakes a task.
    pub fn wake(&self, task: TaskId) {
        self.inner.wake(task, 0);
    }

    /// Extract workers to run them in threads.
    pub fn take_workers(&mut self) -> Vec<ThreeLaneWorker> {
        self.inner.take_workers()
    }

    /// Signals all workers to shutdown.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

// Preserve backward compatibility for Phase 0
pub use priority::Scheduler;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeState;
    use crate::sync::ContendedMutex;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_worker_shutdown() {
        // Create state
        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));

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

    #[test]
    fn test_zero_worker_count_is_clamped_to_one() {
        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let mut scheduler = WorkStealingScheduler::new(0, &state);
        let workers = scheduler.take_workers();
        assert_eq!(
            workers.len(),
            1,
            "scheduler must clamp zero workers to one for forward progress"
        );
    }
}
