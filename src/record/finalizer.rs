//! Finalizer types for region cleanup.
//!
//! Finalizers are cleanup handlers that run when a region closes, after all
//! children have completed. They are executed in LIFO (last-in, first-out)
//! order to ensure proper resource release ordering.

use crate::types::Budget;
use std::future::Future;
use std::pin::Pin;

/// A finalizer that runs during region close.
///
/// Finalizers are stored in a stack and executed LIFO when a region transitions
/// to the Finalizing state. This ensures resources are released in the reverse
/// order they were acquired.
pub enum Finalizer {
    /// Synchronous finalizer (runs directly on scheduler thread).
    ///
    /// Use for lightweight cleanup that doesn't need to await.
    Sync(Box<dyn FnOnce() + Send>),

    /// Asynchronous finalizer (runs as masked task).
    ///
    /// Use for cleanup that needs to perform async operations.
    /// Runs under a cancel mask to prevent interruption.
    Async(Pin<Box<dyn Future<Output = ()> + Send>>),
}

impl std::fmt::Debug for Finalizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sync(_) => f.debug_tuple("Sync").field(&"<closure>").finish(),
            Self::Async(_) => f.debug_tuple("Async").field(&"<future>").finish(),
        }
    }
}

/// Default budget for finalizer execution.
///
/// Finalizers have bounded resources to prevent unbounded cleanup.
pub const FINALIZER_POLL_BUDGET: u32 = 100;

/// Default time budget for finalizers (5 seconds).
pub const FINALIZER_TIME_BUDGET_NANOS: u64 = 5_000_000_000;

/// Returns the default budget for finalizer execution.
#[must_use]
pub fn finalizer_budget() -> Budget {
    Budget::new().with_poll_quota(FINALIZER_POLL_BUDGET)
    // Time budget would be set relative to current time when executed
}

/// Policy for handling finalizers that exceed their budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FinalizerEscalation {
    /// Wait indefinitely for the finalizer to complete (strict correctness).
    Soft,

    /// After budget exceeded, log a warning and continue to next finalizer.
    #[default]
    BoundedLog,

    /// After budget exceeded, panic.
    BoundedPanic,
}

impl FinalizerEscalation {
    /// Returns true if this policy allows continuing after budget exhaustion.
    #[must_use]
    pub const fn allows_continuation(self) -> bool {
        matches!(self, Self::BoundedLog)
    }

    /// Returns true if this policy requires waiting indefinitely.
    #[must_use]
    pub const fn is_soft(self) -> bool {
        matches!(self, Self::Soft)
    }
}

/// A stack of finalizers with LIFO semantics.
///
/// Finalizers are pushed when registered (defer_async/defer_sync) and popped
/// during region finalization. The LIFO ordering ensures resources are released
/// in the reverse order they were acquired.
#[derive(Debug, Default)]
pub struct FinalizerStack {
    /// The stack of finalizers.
    finalizers: Vec<Finalizer>,
    /// Escalation policy for budget violations.
    escalation: FinalizerEscalation,
}

impl FinalizerStack {
    /// Creates a new empty finalizer stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new finalizer stack with the specified escalation policy.
    #[must_use]
    pub fn with_escalation(escalation: FinalizerEscalation) -> Self {
        Self {
            finalizers: Vec::new(),
            escalation,
        }
    }

    /// Returns the escalation policy.
    #[must_use]
    pub const fn escalation(&self) -> FinalizerEscalation {
        self.escalation
    }

    /// Pushes a finalizer onto the stack.
    pub fn push(&mut self, finalizer: Finalizer) {
        self.finalizers.push(finalizer);
    }

    /// Pops a finalizer from the stack (LIFO order).
    pub fn pop(&mut self) -> Option<Finalizer> {
        self.finalizers.pop()
    }

    /// Returns the number of pending finalizers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.finalizers.len()
    }

    /// Returns true if there are no pending finalizers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.finalizers.is_empty()
    }

    /// Pushes a synchronous finalizer.
    pub fn push_sync<F>(&mut self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.push(Finalizer::Sync(Box::new(f)));
    }

    /// Pushes an asynchronous finalizer.
    pub fn push_async<F>(&mut self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.push(Finalizer::Async(Box::pin(future)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalizer_stack_lifo_order() {
        let mut stack = FinalizerStack::new();
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        stack.push_sync(move || o1.lock().unwrap().push(1));
        stack.push_sync(move || o2.lock().unwrap().push(2));
        stack.push_sync(move || o3.lock().unwrap().push(3));

        // Pop and execute in LIFO order
        while let Some(finalizer) = stack.pop() {
            if let Finalizer::Sync(f) = finalizer {
                f();
            }
        }

        // Should be 3, 2, 1 (LIFO)
        assert_eq!(*order.lock().unwrap(), vec![3, 2, 1]);
    }

    #[test]
    fn finalizer_stack_empty() {
        let mut stack = FinalizerStack::new();
        assert!(stack.is_empty());
        assert_eq!(stack.len(), 0);
        assert!(stack.pop().is_none());
    }

    #[test]
    fn finalizer_escalation_policies() {
        assert!(FinalizerEscalation::Soft.is_soft());
        assert!(!FinalizerEscalation::BoundedLog.is_soft());
        assert!(!FinalizerEscalation::BoundedPanic.is_soft());

        assert!(FinalizerEscalation::BoundedLog.allows_continuation());
        assert!(!FinalizerEscalation::Soft.allows_continuation());
        assert!(!FinalizerEscalation::BoundedPanic.allows_continuation());
    }

    #[test]
    fn finalizer_budget_has_expected_values() {
        let budget = finalizer_budget();
        assert_eq!(budget.poll_quota, FINALIZER_POLL_BUDGET);
    }

    #[test]
    fn finalizer_debug_impl() {
        let sync_finalizer = Finalizer::Sync(Box::new(|| {}));
        let debug_str = format!("{sync_finalizer:?}");
        assert!(debug_str.contains("Sync"));

        let async_finalizer = Finalizer::Async(Box::pin(async {}));
        let debug_str = format!("{async_finalizer:?}");
        assert!(debug_str.contains("Async"));
    }
}
