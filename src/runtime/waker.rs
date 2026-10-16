//! Waker implementation with deduplication.
//!
//! This module provides the waker infrastructure for async polling.
//! Wakers are used to notify the runtime when a task is ready to make progress.
//!
//! Note: This implementation uses safe Rust only (no unsafe).

use crate::tracing_compat::trace;
use crate::types::TaskId;
use crate::util::{DetHashMap, DetHashSet};
use parking_lot::Mutex;
use std::sync::{Arc, Weak};
use std::task::{Wake, Waker};

#[cfg(feature = "waker-profiling")]
#[path = "waker_profiling.rs"]
mod waker_profiling;
#[cfg(feature = "waker-profiling")]
use waker_profiling::profile;

#[cfg(test)]
#[path = "waker_allocation_hotpaths_test.rs"]
mod waker_allocation_hotpaths_test;

/// Source attribution for wake events.
///
/// Tracks what caused a task to be woken, enabling causality analysis
/// in tracing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl WakeSource {
    #[inline]
    #[must_use]
    #[allow(dead_code)] // used by trace! macro when tracing feature is enabled
    const fn label(self) -> &'static str {
        match self {
            Self::Timer => "timer",
            Self::Io { .. } => "io",
            Self::Explicit => "explicit",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct WakerKey {
    task: TaskId,
    source: WakeSource,
}

const WAKER_CACHE_PRUNE_THRESHOLD: usize = 4096;

/// Shared state for the waker system.
#[derive(Debug, Default)]
pub struct WakerState {
    /// Tasks that have been woken.
    ///
    /// We keep O(1)-style hash-set dedup on the wake hot path, but use the
    /// deterministic build hasher to avoid ambient hash seeding and sort at
    /// drain time so the returned order is replay-stable.
    woken: Mutex<DetHashSet<TaskId>>,
    /// Weak cache of live task wakers keyed by task and wake source.
    ///
    /// Repeated `waker_for*` calls for an already-live waker can clone the
    /// existing allocation. Weak entries avoid extending waker lifetimes.
    waker_cache: Mutex<DetHashMap<WakerKey, Weak<TaskWaker>>>,
}

impl WakerState {
    /// Creates a new waker state.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a waker for a specific task with unknown wake source.
    #[inline]
    #[must_use]
    pub fn waker_for(self: &Arc<Self>, task: TaskId) -> Waker {
        self.waker_for_source(task, WakeSource::Unknown)
    }

    /// Creates a waker for a specific task with an attributed wake source.
    ///
    /// The `source` is recorded when the waker fires, enabling causality
    /// analysis in tracing output.
    #[inline]
    #[must_use]
    pub fn waker_for_source(self: &Arc<Self>, task: TaskId, source: WakeSource) -> Waker {
        let key = WakerKey { task, source };
        let mut cache = self.waker_cache.lock();
        if let Some(existing) = cache.get(&key).and_then(Weak::upgrade) {
            return Waker::from(existing);
        }

        #[cfg(feature = "waker-profiling")]
        profile!(waker_profiling::profile_waker_allocation);

        if cache.len() >= WAKER_CACHE_PRUNE_THRESHOLD {
            cache.retain(|_, waker| waker.strong_count() > 0);
        }

        let waker = Arc::new(TaskWaker {
            state: Arc::clone(self),
            task,
            source,
        });
        cache.insert(key, Arc::downgrade(&waker));

        Waker::from(waker)
    }

    /// Drains all woken tasks.
    #[inline]
    pub fn drain_woken(&self) -> Vec<TaskId> {
        #[cfg(feature = "waker-profiling")]
        profile!(waker_profiling::profile_drain_operation);

        let mut drained: Vec<_> = {
            #[cfg(feature = "waker-profiling")]
            profile!(waker_profiling::profile_lock_acquisition);
            let mut woken = self.woken.lock();
            woken.drain().collect()
        };
        drained.sort_unstable();
        drained
    }

    /// Returns true if any tasks have been woken.
    #[inline]
    #[must_use]
    pub fn has_woken(&self) -> bool {
        let woken = self.woken.lock();
        !woken.is_empty()
    }

    #[allow(unused_variables)] // source used by trace! macro when tracing is enabled
    #[inline]
    fn wake(&self, task: TaskId, source: WakeSource) {
        #[cfg(feature = "waker-profiling")]
        profile!(waker_profiling::profile_wake_operation);

        #[cfg(feature = "waker-profiling")]
        profile!(waker_profiling::profile_lock_acquisition);
        let mut woken = self.woken.lock();

        if woken.insert(task) {
            trace!(
                task_id = ?task,
                wake_source = source.label(),
                "task woken"
            );
        } else {
            #[cfg(feature = "waker-profiling")]
            profile!(waker_profiling::profile_dedup_hit);
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
    #[inline]
    fn wake(self: Arc<Self>) {
        self.state.wake(self.task, self.source);
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.state.wake(self.task, self.source);
    }
}

#[cfg(test)]
#[path = "waker_inline_tests.rs"]
mod tests;
