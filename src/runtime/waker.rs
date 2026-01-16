//! Waker implementation with deduplication.
//!
//! This module provides the waker infrastructure for async polling.
//! Wakers are used to notify the runtime when a task is ready to make progress.
//!
//! Note: This implementation uses safe Rust only (no unsafe).

use crate::types::TaskId;
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};

/// Shared state for the waker system.
#[derive(Debug, Default)]
pub struct WakerState {
    /// Tasks that have been woken.
    woken: Mutex<Vec<TaskId>>,
}

impl WakerState {
    /// Creates a new waker state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a waker for a specific task.
    #[must_use]
    pub fn waker_for(self: &Arc<Self>, task: TaskId) -> Waker {
        Waker::from(Arc::new(TaskWaker {
            state: Arc::clone(self),
            task,
        }))
    }

    /// Drains all woken tasks.
    pub fn drain_woken(&self) -> Vec<TaskId> {
        let mut woken = self.woken.lock().expect("lock poisoned");
        std::mem::take(&mut *woken)
    }

    /// Returns true if any tasks have been woken.
    #[must_use]
    pub fn has_woken(&self) -> bool {
        let woken = self.woken.lock().expect("lock poisoned");
        !woken.is_empty()
    }

    fn wake(&self, task: TaskId) {
        let mut woken = self.woken.lock().expect("lock poisoned");
        if !woken.contains(&task) {
            woken.push(task);
        }
    }
}

/// A waker for a specific task.
struct TaskWaker {
    state: Arc<WakerState>,
    task: TaskId,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.state.wake(self.task);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.state.wake(self.task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    #[test]
    fn wake_and_drain() {
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for(task(1));

        waker.wake_by_ref();

        let woken = state.drain_woken();
        assert_eq!(woken, vec![task(1)]);
        assert!(state.drain_woken().is_empty());
    }

    #[test]
    fn dedup_multiple_wakes() {
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for(task(1));

        waker.wake_by_ref();
        waker.wake_by_ref();
        waker.wake();

        let woken = state.drain_woken();
        assert_eq!(woken.len(), 1);
    }
}
