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
#[inline]
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
    #[inline]
    #[must_use]
    pub const fn allows_continuation(self) -> bool {
        matches!(self, Self::BoundedLog)
    }

    /// Returns true if this policy requires waiting indefinitely.
    #[inline]
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
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new finalizer stack with the specified escalation policy.
    #[must_use]
    #[inline]
    pub fn with_escalation(escalation: FinalizerEscalation) -> Self {
        Self {
            finalizers: Vec::new(),
            escalation,
        }
    }

    /// Returns the escalation policy.
    #[must_use]
    #[inline]
    pub const fn escalation(&self) -> FinalizerEscalation {
        self.escalation
    }

    /// Pushes a finalizer onto the stack.
    #[inline]
    pub fn push(&mut self, finalizer: Finalizer) {
        self.finalizers.push(finalizer);
    }

    /// Pops a finalizer from the stack (LIFO order).
    #[inline]
    pub fn pop(&mut self) -> Option<Finalizer> {
        self.finalizers.pop()
    }

    /// Returns the number of pending finalizers.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.finalizers.len()
    }

    /// Returns true if there are no pending finalizers.
    #[must_use]
    #[inline]
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
    use parking_lot::Mutex;

    fn finalizer_policy_table() -> String {
        [
            FinalizerEscalation::Soft,
            FinalizerEscalation::BoundedLog,
            FinalizerEscalation::BoundedPanic,
        ]
        .into_iter()
        .map(|policy| {
            format!(
                "{policy:?}|soft={}|continue={}|polls={}|time_ns={}",
                policy.is_soft(),
                policy.allows_continuation(),
                FINALIZER_POLL_BUDGET,
                FINALIZER_TIME_BUDGET_NANOS
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }



    #[test]
    fn finalizer_stack_lifo_order() {
        init_test("finalizer_stack_lifo_order");
        let mut stack = FinalizerStack::new();
        let order = std::sync::Arc::new(Mutex::new(Vec::new()));
        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        stack.push_sync(move || o1.lock().push(1));
        stack.push_sync(move || o2.lock().push(2));
        stack.push_sync(move || o3.lock().push(3));

        // Pop and execute in LIFO order
        while let Some(finalizer) = stack.pop() {
            if let Finalizer::Sync(f) = finalizer {
                f();
            }
        }

        // Should be 3, 2, 1 (LIFO)
        let order = order.lock().clone();
        crate::assert_with_log!(order == vec![3, 2, 1], "order", vec![3, 2, 1], order);
        crate::test_complete!("finalizer_stack_lifo_order");
    }

    #[test]
    fn finalizer_stack_empty() {
        init_test("finalizer_stack_empty");
        let mut stack = FinalizerStack::new();
        let empty = stack.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let len = stack.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        let pop = stack.pop();
        crate::assert_with_log!(pop.is_none(), "pop none", true, pop.is_none());
        crate::test_complete!("finalizer_stack_empty");
    }

    #[test]
    fn finalizer_escalation_policies() {
        init_test("finalizer_escalation_policies");
        let soft = FinalizerEscalation::Soft.is_soft();
        crate::assert_with_log!(soft, "soft is soft", true, soft);
        let log_soft = FinalizerEscalation::BoundedLog.is_soft();
        crate::assert_with_log!(!log_soft, "log not soft", false, log_soft);
        let panic_soft = FinalizerEscalation::BoundedPanic.is_soft();
        crate::assert_with_log!(!panic_soft, "panic not soft", false, panic_soft);

        let log_cont = FinalizerEscalation::BoundedLog.allows_continuation();
        crate::assert_with_log!(log_cont, "log allows", true, log_cont);
        let soft_cont = FinalizerEscalation::Soft.allows_continuation();
        crate::assert_with_log!(!soft_cont, "soft no continue", false, soft_cont);
        let panic_cont = FinalizerEscalation::BoundedPanic.allows_continuation();
        crate::assert_with_log!(!panic_cont, "panic no continue", false, panic_cont);
        crate::test_complete!("finalizer_escalation_policies");
    }

    #[test]
    fn finalizer_budget_has_expected_values() {
        init_test("finalizer_budget_has_expected_values");
        let budget = finalizer_budget();
        crate::assert_with_log!(
            budget.poll_quota == FINALIZER_POLL_BUDGET,
            "poll_quota",
            FINALIZER_POLL_BUDGET,
            budget.poll_quota
        );
        crate::test_complete!("finalizer_budget_has_expected_values");
    }

    #[test]
    fn finalizer_debug_impl() {
        init_test("finalizer_debug_impl");
        let sync_finalizer = Finalizer::Sync(Box::new(|| {}));
        let debug_str = format!("{sync_finalizer:?}");
        let sync_debug_present = debug_str.contains("Sync");
        crate::assert_with_log!(sync_debug_present, "sync debug", true, sync_debug_present);

        let async_finalizer = Finalizer::Async(Box::pin(async {}));
        let debug_str = format!("{async_finalizer:?}");
        let async_debug_present = debug_str.contains("Async");
        crate::assert_with_log!(
            async_debug_present,
            "async debug",
            true,
            async_debug_present
        );
        crate::test_complete!("finalizer_debug_impl");
    }

    // =========================================================================
    // Wave 51 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn finalizer_escalation_debug_clone_copy_eq_default() {
        let e = FinalizerEscalation::BoundedLog;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("BoundedLog"), "{dbg}");
        let copied = e;
        let cloned = e;
        assert_eq!(copied, cloned);
        let def = FinalizerEscalation::default();
        assert_eq!(def, FinalizerEscalation::BoundedLog);
    }

    #[test]
    fn finalizer_stack_debug_default() {
        let stack = FinalizerStack::default();
        let dbg = format!("{stack:?}");
        assert!(dbg.contains("FinalizerStack"), "{dbg}");
        assert!(stack.is_empty());
    }

    #[test]
    fn finalizer_policy_table_snapshot() {
        insta::assert_snapshot!("finalizer_policy_table", finalizer_policy_table());
    }

    // =========================================================================
    // Golden artifact tests for finalizer outputs
    // =========================================================================

    /// Generate structured budget configuration output for golden testing
    fn budget_configuration_table() -> String {
        let budget = finalizer_budget();
        vec![
            format!("poll_quota={}", budget.poll_quota),
            format!("cost_quota={:?}", budget.cost_quota),
            format!("priority={}", budget.priority),
            format!("deadline={:?}", budget.deadline),
            format!("constants.poll_budget={}", FINALIZER_POLL_BUDGET),
            format!("constants.time_budget_ns={}", FINALIZER_TIME_BUDGET_NANOS),
        ].join("\n")
    }

    /// Generate debug representations of finalizers for golden testing
    fn finalizer_debug_representations() -> String {
        let sync_finalizer = Finalizer::Sync(Box::new(|| {}));
        let async_finalizer = Finalizer::Async(Box::pin(async {}));

        vec![
            format!("Sync: {:?}", sync_finalizer),
            format!("Async: {:?}", async_finalizer),
        ].join("\n")
    }

    /// Generate finalizer stack states for golden testing
    fn finalizer_stack_operations() -> String {
        let mut lines = Vec::new();

        // Empty stack
        let mut stack = FinalizerStack::new();
        lines.push(format!("empty_stack: len={}, is_empty={}, escalation={:?}",
            stack.len(), stack.is_empty(), stack.escalation()));

        // Stack with custom escalation
        let stack_panic = FinalizerStack::with_escalation(FinalizerEscalation::BoundedPanic);
        lines.push(format!("panic_stack: len={}, is_empty={}, escalation={:?}",
            stack_panic.len(), stack_panic.is_empty(), stack_panic.escalation()));

        // Add finalizers and show progression
        stack.push_sync(|| {});
        lines.push(format!("after_sync_push: len={}, is_empty={}", stack.len(), stack.is_empty()));

        stack.push_async(async {});
        lines.push(format!("after_async_push: len={}, is_empty={}", stack.len(), stack.is_empty()));

        stack.push_sync(|| {});
        lines.push(format!("after_second_sync: len={}, is_empty={}", stack.len(), stack.is_empty()));

        // Pop operations (don't execute, just show types)
        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!("after_first_pop: len={}, is_empty={}", stack.len(), stack.is_empty()));

        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!("after_second_pop: len={}, is_empty={}", stack.len(), stack.is_empty()));

        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!("after_third_pop: len={}, is_empty={}", stack.len(), stack.is_empty()));

        // Test pop from empty
        let empty_pop = stack.pop();
        lines.push(format!("empty_pop: {}", if empty_pop.is_none() { "None" } else { "Some" }));

        lines.join("\n")
    }

    /// Generate escalation policy behavior matrix for golden testing
    fn escalation_policy_matrix() -> String {
        let policies = [
            FinalizerEscalation::Soft,
            FinalizerEscalation::BoundedLog,
            FinalizerEscalation::BoundedPanic,
        ];

        let mut lines = Vec::new();
        lines.push("policy|is_soft|allows_continuation|default_match".to_string());

        for policy in policies {
            let is_default = policy == FinalizerEscalation::default();
            lines.push(format!("{:?}|{}|{}|{}",
                policy,
                policy.is_soft(),
                policy.allows_continuation(),
                is_default
            ));
        }

        lines.join("\n")
    }

    /// Generate finalizer stack debug output for golden testing
    fn finalizer_stack_debug_output() -> String {
        let mut lines = Vec::new();

        // Empty stack debug
        let empty_stack = FinalizerStack::new();
        lines.push(format!("empty: {:?}", empty_stack));

        // Stack with escalation debug
        let panic_stack = FinalizerStack::with_escalation(FinalizerEscalation::BoundedPanic);
        lines.push(format!("panic_escalation: {:?}", panic_stack));

        let soft_stack = FinalizerStack::with_escalation(FinalizerEscalation::Soft);
        lines.push(format!("soft_escalation: {:?}", soft_stack));

        lines.join("\n")
    }

    #[test]
    fn finalizer_budget_configuration() {
        insta::assert_snapshot!("budget_configuration", budget_configuration_table());
    }

    #[test]
    fn finalizer_debug_output() {
        insta::assert_snapshot!("debug_representations", finalizer_debug_representations());
    }

    #[test]
    fn finalizer_stack_state_transitions() {
        insta::assert_snapshot!("stack_operations", finalizer_stack_operations());
    }

    #[test]
    fn finalizer_escalation_behavior_matrix() {
        insta::assert_snapshot!("escalation_matrix", escalation_policy_matrix());
    }

    #[test]
    fn finalizer_stack_debug_variants() {
        insta::assert_snapshot!("stack_debug_output", finalizer_stack_debug_output());
    }
}
