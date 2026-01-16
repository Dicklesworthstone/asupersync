//! The capability context type.
//!
//! `Cx` is the token that grants access to runtime capabilities:
//! - Querying identity (region ID, task ID)
//! - Checking cancellation status
//! - Yielding and sleeping
//! - Tracing

use crate::types::{Budget, RegionId, TaskId};
use std::sync::Arc;

/// Internal state for a capability context.
#[derive(Debug)]
pub(crate) struct CxInner {
    /// The region this context belongs to.
    pub region: RegionId,
    /// The task this context belongs to.
    pub task: TaskId,
    /// Current budget.
    pub budget: Budget,
    /// Whether cancellation has been requested.
    pub cancel_requested: bool,
    /// Current mask depth.
    pub mask_depth: u32,
}

/// The capability context for a task.
///
/// This type provides access to runtime capabilities. All effects flow
/// through `Cx`, ensuring explicit capability security.
#[derive(Debug, Clone)]
pub struct Cx {
    pub(crate) inner: Arc<std::sync::RwLock<CxInner>>,
}

impl Cx {
    /// Creates a new capability context (internal use).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn new(region: RegionId, task: TaskId, budget: Budget) -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(CxInner {
                region,
                task,
                budget,
                cancel_requested: false,
                mask_depth: 0,
            })),
        }
    }

    /// Returns the current region ID.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.inner.read().expect("lock poisoned").region
    }

    /// Returns the current task ID.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.inner.read().expect("lock poisoned").task
    }

    /// Returns the current budget.
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.inner.read().expect("lock poisoned").budget
    }

    /// Returns true if cancellation has been requested.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.inner.read().expect("lock poisoned").cancel_requested
    }

    /// Checks for cancellation and returns an error if cancelled.
    ///
    /// This is a checkpoint where cancellation can be observed.
    /// If the context is masked, cancellation is deferred.
    ///
    /// # Errors
    ///
    /// Returns an `Err` with kind `ErrorKind::Cancelled` if cancellation is pending and not masked.
    pub fn checkpoint(&self) -> Result<(), crate::error::Error> {
        let inner = self.inner.read().expect("lock poisoned");
        if inner.cancel_requested && inner.mask_depth == 0 {
            Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))
        } else {
            Ok(())
        }
    }

    /// Executes a closure with cancellation masked.
    ///
    /// While masked, `checkpoint()` will not return an error.
    /// This is used for critical sections that must not be interrupted.
    pub fn masked<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        {
            let mut inner = self.inner.write().expect("lock poisoned");
            inner.mask_depth += 1;
        }

        let result = f();

        {
            let mut inner = self.inner.write().expect("lock poisoned");
            inner.mask_depth = inner.mask_depth.saturating_sub(1);
        }

        result
    }

    /// Traces an event (placeholder implementation).
    pub fn trace(&self, message: &str) {
        // In the full implementation, this would write to the trace buffer
        let _ = message;
    }

    /// Sets the cancellation flag (internal use).
    #[allow(dead_code)]
    pub(crate) fn set_cancel_requested(&self, value: bool) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.cancel_requested = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn checkpoint_without_cancel() {
        let cx = test_cx();
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn checkpoint_with_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);
        assert!(cx.checkpoint().is_err());
    }

    #[test]
    fn masked_defers_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        cx.masked(|| {
            assert!(
                cx.checkpoint().is_ok(),
                "checkpoint should succeed when masked"
            );
        });

        assert!(
            cx.checkpoint().is_err(),
            "checkpoint should fail after unmasking"
        );
    }
}
