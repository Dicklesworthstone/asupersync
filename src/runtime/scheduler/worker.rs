//! Worker thread logic.

use crate::runtime::scheduler::global_queue::GlobalQueue;
use crate::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use crate::runtime::scheduler::stealing;
use crate::runtime::RuntimeState;
use crate::types::TaskId;
use crate::util::DetRng;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub type WorkerId = usize;

/// A worker thread that executes tasks.
#[derive(Debug)]
pub struct Worker {
    pub id: WorkerId,
    pub local: LocalQueue,
    pub stealers: Vec<Stealer>,
    pub global: Arc<GlobalQueue>,
    pub state: Arc<Mutex<RuntimeState>>, // RuntimeState is usually guarded
    pub parker: Parker,
    pub rng: DetRng,
}

impl Worker {
    pub fn new(
        id: WorkerId,
        stealers: Vec<Stealer>,
        global: Arc<GlobalQueue>,
        state: Arc<Mutex<RuntimeState>>,
    ) -> Self {
        Self {
            id,
            local: LocalQueue::new(),
            stealers,
            global,
            state,
            parker: Parker::new(),
            rng: DetRng::new(id as u64 + 1), // Simple seed
        }
    }

    pub fn run_loop(&mut self) {
        loop {
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

            // 4. Park until woken
            // TODO: exponential backoff before parking
            self.parker.park();
        }
    }

    fn execute(&mut self, _task: TaskId) {
        // Placeholder for execution logic.
        // In real implementation, this would:
        // 1. Get stored future from RuntimeState
        // 2. Create Waker pointing to this Scheduler/Worker
        // 3. Poll future
        // 4. Handle Ready/Pending
    }
}

/// A mechanism for parking and unparking a worker.
#[derive(Debug, Clone)]
pub struct Parker {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl Parker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub fn park(&self) {
        let (lock, cvar) = &*self.inner;
        let mut notified = lock.lock().unwrap();
        while !*notified {
            notified = cvar.wait(notified).unwrap();
        }
        *notified = false;
    }

    pub fn park_timeout(&self, duration: Duration) {
        let (lock, cvar) = &*self.inner;
        let mut notified = lock.lock().unwrap();
        if !*notified {
            let _ = cvar.wait_timeout(notified, duration).unwrap();
        }
    }

    pub fn unpark(&self) {
        let (lock, cvar) = &*self.inner;
        let mut notified = lock.lock().unwrap();
        *notified = true;
        cvar.notify_one();
    }
}

impl Default for Parker {
    fn default() -> Self {
        Self::new()
    }
}
