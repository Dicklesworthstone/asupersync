//! Waker implementation with deduplication.
//!
//! This module provides the waker infrastructure for async polling.
//! Wakers are used to notify the runtime when a task is ready to make progress.
//!
//! Note: This implementation uses safe Rust only (no unsafe).

use crate::tracing_compat::trace;
use crate::types::TaskId;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use std::task::{Wake, Waker};

/// Source attribution for wake events.
///
/// Tracks what caused a task to be woken, enabling causality analysis
/// in tracing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeSource {
    /// Woken by a timer expiry.
    Timer,
    /// Woken by an I/O readiness event.
    Io {
        /// The file descriptor (Unix) or socket (Windows) that became ready.
        fd: i32,
    },
    /// Woken explicitly by user code or another task.
    Explicit,
    /// Wake source not specified (legacy path).
    Unknown,
}

/// Shared state for the waker system.
#[derive(Debug, Default)]
pub struct WakerState {
    /// Tasks that have been woken (HashSet for O(1) dedup on the wake hot path).
    woken: Mutex<HashSet<TaskId>>,
}

impl WakerState {
    /// Creates a new waker state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a waker for a specific task with unknown wake source.
    #[must_use]
    pub fn waker_for(self: &Arc<Self>, task: TaskId) -> Waker {
        self.waker_for_source(task, WakeSource::Unknown)
    }

    /// Creates a waker for a specific task with an attributed wake source.
    ///
    /// The `source` is recorded when the waker fires, enabling causality
    /// analysis in tracing output.
    #[must_use]
    pub fn waker_for_source(self: &Arc<Self>, task: TaskId, source: WakeSource) -> Waker {
        Waker::from(Arc::new(TaskWaker {
            state: Arc::clone(self),
            task,
            source,
        }))
    }

    /// Drains all woken tasks.
    pub fn drain_woken(&self) -> Vec<TaskId> {
        let mut woken = self.woken.lock();
        woken.drain().collect()
    }

    /// Returns true if any tasks have been woken.
    #[must_use]
    pub fn has_woken(&self) -> bool {
        let woken = self.woken.lock();
        !woken.is_empty()
    }

    fn wake(&self, task: TaskId, source: WakeSource) {
        let mut woken = self.woken.lock();
        if woken.insert(task) {
            let _source_label = match source {
                WakeSource::Timer => "timer",
                WakeSource::Io { .. } => "io",
                WakeSource::Explicit => "explicit",
                WakeSource::Unknown => "unknown",
            };
            trace!(
                task_id = ?task,
                wake_source = _source_label,
                "task woken"
            );
        }
    }
}

/// A waker for a specific task.
struct TaskWaker {
    state: Arc<WakerState>,
    task: TaskId,
    source: WakeSource,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.state.wake(self.task, self.source);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.state.wake(self.task, self.source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    #[test]
    fn wake_and_drain() {
        init_test("wake_and_drain");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for(task(1));

        crate::test_section!("wake");
        waker.wake_by_ref();

        crate::test_section!("drain");
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(1)],
            "drain should return the woken task",
            vec![task(1)],
            woken
        );
        let empty = state.drain_woken().is_empty();
        crate::assert_with_log!(empty, "second drain should be empty", true, empty);
        crate::test_complete!("wake_and_drain");
    }

    #[test]
    fn dedup_multiple_wakes() {
        init_test("dedup_multiple_wakes");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for(task(1));

        crate::test_section!("wake");
        waker.wake_by_ref();
        waker.wake_by_ref();
        waker.wake();

        crate::test_section!("verify");
        let woken = state.drain_woken();
        crate::assert_with_log!(woken.len() == 1, "woken list should dedup", 1, woken.len());
        crate::test_complete!("dedup_multiple_wakes");
    }

    #[test]
    fn wake_after_drain_requeues_task() {
        init_test("wake_after_drain_requeues_task");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for(task(4));

        waker.wake_by_ref();
        let first = state.drain_woken();
        crate::assert_with_log!(
            first == vec![task(4)],
            "first wake should queue task",
            vec![task(4)],
            first
        );

        waker.wake_by_ref();
        let second = state.drain_woken();
        crate::assert_with_log!(
            second == vec![task(4)],
            "task should be re-queueable after drain",
            vec![task(4)],
            second
        );
        crate::test_complete!("wake_after_drain_requeues_task");
    }

    #[test]
    fn waker_for_source_timer() {
        init_test("waker_for_source_timer");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for_source(task(1), WakeSource::Timer);

        waker.wake_by_ref();
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(1)],
            "timer waker should wake task",
            vec![task(1)],
            woken
        );
        crate::test_complete!("waker_for_source_timer");
    }

    #[test]
    fn waker_for_source_io() {
        init_test("waker_for_source_io");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for_source(task(2), WakeSource::Io { fd: 7 });

        waker.wake();
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(2)],
            "io waker should wake task",
            vec![task(2)],
            woken
        );
        crate::test_complete!("waker_for_source_io");
    }

    #[test]
    fn waker_for_source_explicit() {
        init_test("waker_for_source_explicit");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for_source(task(3), WakeSource::Explicit);

        waker.wake_by_ref();
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(3)],
            "explicit waker should wake task",
            vec![task(3)],
            woken
        );
        crate::test_complete!("waker_for_source_explicit");
    }

    /// Invariant: has_woken returns false when empty, true after wake.
    #[test]
    fn has_woken_tracks_state() {
        init_test("has_woken_tracks_state");
        let state = Arc::new(WakerState::new());
        let has_none = !state.has_woken();
        crate::assert_with_log!(has_none, "no woken initially", true, has_none);

        let waker = state.waker_for(task(1));
        waker.wake_by_ref();
        crate::assert_with_log!(
            state.has_woken(),
            "has woken after wake",
            true,
            state.has_woken()
        );

        state.drain_woken();
        let drained = !state.has_woken();
        crate::assert_with_log!(drained, "no woken after drain", true, drained);
        crate::test_complete!("has_woken_tracks_state");
    }

    /// Invariant: multiple tasks wake independently.
    #[test]
    fn multi_task_waking() {
        init_test("multi_task_waking");
        let state = Arc::new(WakerState::new());

        let w1 = state.waker_for(task(10));
        let w2 = state.waker_for(task(20));
        let w3 = state.waker_for(task(30));

        w1.wake();
        w2.wake();
        w3.wake();

        let mut woken = state.drain_woken();
        woken.sort();
        crate::assert_with_log!(woken.len() == 3, "3 tasks woken", 3, woken.len());
        crate::assert_with_log!(
            woken.contains(&task(10)),
            "contains 10",
            true,
            woken.contains(&task(10))
        );
        crate::assert_with_log!(
            woken.contains(&task(20)),
            "contains 20",
            true,
            woken.contains(&task(20))
        );
        crate::assert_with_log!(
            woken.contains(&task(30)),
            "contains 30",
            true,
            woken.contains(&task(30))
        );
        crate::test_complete!("multi_task_waking");
    }

    #[test]
    fn wake_source_equality() {
        init_test("wake_source_equality");
        let timer = WakeSource::Timer;
        let io = WakeSource::Io { fd: 3 };
        let explicit = WakeSource::Explicit;
        let unknown = WakeSource::Unknown;

        crate::assert_with_log!(
            timer == WakeSource::Timer,
            "timer eq",
            true,
            timer == WakeSource::Timer
        );
        crate::assert_with_log!(timer != io, "timer != io", true, timer != io);
        crate::assert_with_log!(io != explicit, "io != explicit", true, io != explicit);
        crate::assert_with_log!(
            explicit != unknown,
            "explicit != unknown",
            true,
            explicit != unknown
        );
        crate::assert_with_log!(
            WakeSource::Io { fd: 3 } == WakeSource::Io { fd: 3 },
            "io fd eq",
            true,
            WakeSource::Io { fd: 3 } == WakeSource::Io { fd: 3 }
        );
        crate::assert_with_log!(
            WakeSource::Io { fd: 3 } != WakeSource::Io { fd: 5 },
            "io fd neq",
            true,
            WakeSource::Io { fd: 3 } != WakeSource::Io { fd: 5 }
        );
        crate::test_complete!("wake_source_equality");
    }
}
