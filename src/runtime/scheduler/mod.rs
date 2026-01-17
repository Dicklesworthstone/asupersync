//! Work-stealing scheduler.

pub mod global_queue;
pub mod local_queue;
pub mod priority;
pub mod stealing;
pub mod worker;

pub use global_queue::GlobalQueue;
pub use local_queue::LocalQueue;
pub use priority::Scheduler as PriorityScheduler;
pub use worker::{Parker, Worker};

use crate::types::TaskId;
use std::sync::Arc;

/// Work-stealing scheduler coordinator.
#[derive(Debug)]
pub struct WorkStealingScheduler {
    // Workers are moved out when threads start, so this might become empty.
    // We keep them here for initialization.
    workers: Vec<Worker>,
    global: Arc<GlobalQueue>,
}

impl WorkStealingScheduler {
    /// Creates a new scheduler with the given number of workers.
    ///
    /// This also creates the workers and their local queues.
    pub fn new(worker_count: usize, state: &std::sync::Arc<std::sync::Mutex<crate::runtime::RuntimeState>>) -> Self {
        let global = Arc::new(GlobalQueue::new());
        let mut workers = Vec::with_capacity(worker_count);
        let mut stealers = Vec::with_capacity(worker_count);

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
            let my_stealers: Vec<_> = worker_stealers.into_iter()
                // .filter(|s| ...) // Stealer doesn't have ID. 
                .collect();

            workers.push(Worker {
                id,
                local,
                stealers: my_stealers,
                global: Arc::clone(&global),
                state: state.clone(),
                parker: Parker::new(),
                rng: crate::util::DetRng::new(id as u64),
            });
        }

        Self {
            workers,
            global,
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
}

// Preserve backward compatibility for Phase 0
pub use priority::Scheduler;
