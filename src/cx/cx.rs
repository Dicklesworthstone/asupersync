//! The capability context type.
//!
//! `Cx` is the token that grants access to runtime capabilities:
//! - Querying identity (region ID, task ID)
//! - Checking cancellation status
//! - Yielding and sleeping
//! - Tracing
//!
//! # Capability Model
//!
//! All effectful operations in Asupersync flow through explicit `Cx` tokens.
//! This design prevents ambient authority and enables:
//!
//! - **Effect interception**: Production vs lab runtime can interpret effects differently
//! - **Cancellation propagation**: Cx carries cancellation signals through the task tree
//! - **Budget enforcement**: Deadlines and poll quotas flow through Cx
//! - **Observability**: Tracing and spans are tied to task identity
//!
//! # Thread Safety
//!
//! `Cx` is `Send + Sync` due to its internal `Arc<RwLock>`. However, the semantic
//! contract is that a `Cx` is associated with a specific task and should not be
//! shared across task boundaries. The runtime manages Cx lifetime and ensures
//! each task receives its own context.
//!
//! # Wrapping Cx for Frameworks
//!
//! Framework authors (e.g., fastapi_rust) should wrap `Cx` rather than store it directly:
//!
//! ```ignore
//! // CORRECT: Wrap Cx reference, delegate capabilities
//! pub struct RequestContext<'a> {
//!     cx: &'a Cx,
//!     request: &'a Request,
//!     // framework-specific fields
//! }
//!
//! impl<'a> RequestContext<'a> {
//!     pub fn check_cancelled(&self) -> bool {
//!         self.cx.is_cancel_requested()
//!     }
//!
//!     pub fn budget(&self) -> Budget {
//!         self.cx.budget()
//!     }
//! }
//! ```
//!
//! This pattern ensures:
//! - Cx lifetime is tied to the request scope
//! - Framework can add domain-specific context
//! - All capabilities flow through the wrapped Cx

use crate::observability::{DiagnosticContext, LogCollector, LogEntry, SpanId};
use crate::runtime::io_driver::IoDriverHandle;
use crate::tracing_compat::{debug, info, trace};
use crate::types::{Budget, CxInner, RegionId, TaskId};
use std::cell::RefCell;
use std::sync::Arc;

/// The capability context for a task.
///
/// `Cx` provides access to runtime capabilities within Asupersync. All effectful
/// operations flow through `Cx`, ensuring explicit capability security with no
/// ambient authority.
///
/// # Overview
///
/// A `Cx` instance is provided to each task by the runtime. It grants access to:
///
/// - **Identity**: Query the current region and task IDs
/// - **Budget**: Check remaining time/poll quotas
/// - **Cancellation**: Observe and respond to cancellation requests
/// - **Tracing**: Emit trace events for observability
///
/// # Usage for External Crates
///
/// External crates like fastapi_rust can depend on Asupersync and use `Cx`:
///
/// ```ignore
/// use asupersync::Cx;
///
/// async fn handle_request(cx: &Cx) -> Result<Response, Error> {
///     // Check if the request should be cancelled
///     if cx.is_cancel_requested() {
///         return Err(Error::Cancelled);
///     }
///
///     // Check remaining budget (timeout)
///     let budget = cx.budget();
///     if budget.is_expired() {
///         return Err(Error::Timeout);
///     }
///
///     // Trace request handling
///     cx.trace("Processing request");
///
///     // Do work...
///     Ok(Response::new())
/// }
/// ```
///
/// # Cloning
///
/// `Cx` is cheaply clonable (it wraps an `Arc`). Clones share the same
/// underlying state, so cancellation signals and budget updates are visible
/// to all clones.
///
/// # Lifetime Considerations
///
/// While `Cx` can be cloned and moved, it semantically belongs to a specific
/// task within a specific region. The runtime ensures proper cleanup when
/// tasks complete.
#[derive(Debug, Clone)]
pub struct Cx {
    pub(crate) inner: Arc<std::sync::RwLock<CxInner>>,
    observability: Arc<std::sync::RwLock<ObservabilityState>>,
    io_driver: Option<IoDriverHandle>,
}

/// Internal observability state shared by `Cx` clones.
#[derive(Debug, Clone)]
pub struct ObservabilityState {
    collector: Option<LogCollector>,
    context: DiagnosticContext,
}

impl ObservabilityState {
    fn new(region: RegionId, task: TaskId) -> Self {
        let context = DiagnosticContext::new()
            .with_task_id(task)
            .with_region_id(region)
            .with_span_id(SpanId::new());
        Self {
            collector: None,
            context,
        }
    }

    fn derive_child(&self, region: RegionId, task: TaskId) -> Self {
        let mut context = self.context.clone().fork();
        context = context.with_task_id(task).with_region_id(region);
        Self {
            collector: self.collector.clone(),
            context,
        }
    }
}

/// Guard that restores the cancellation mask on drop.
struct MaskGuard<'a> {
    inner: &'a Arc<std::sync::RwLock<CxInner>>,
}

impl Drop for MaskGuard<'_> {
    fn drop(&mut self) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.mask_depth = inner.mask_depth.saturating_sub(1);
    }
}

thread_local! {
    static CURRENT_CX: RefCell<Option<Cx>> = const { RefCell::new(None) };
}

/// Guard that restores the previous Cx on drop.
pub(crate) struct CurrentCxGuard {
    prev: Option<Cx>,
}

impl Drop for CurrentCxGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        CURRENT_CX.with(|slot| {
            *slot.borrow_mut() = prev;
        });
    }
}

impl Cx {
    /// Creates a new capability context (internal use).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn new(region: RegionId, task: TaskId, budget: Budget) -> Self {
        Self::new_with_observability(region, task, budget, None, None)
    }

    /// Creates a new capability context from shared state (internal use).
    pub(crate) fn from_inner(inner: Arc<std::sync::RwLock<CxInner>>) -> Self {
        let (region, task) = {
            let guard = inner.read().expect("lock poisoned");
            (guard.region, guard.task)
        };
        Self {
            inner,
            observability: Arc::new(std::sync::RwLock::new(ObservabilityState::new(
                region, task,
            ))),
            io_driver: None,
        }
    }

    /// Creates a new capability context with optional observability state (internal use).
    pub(crate) fn new_with_observability(
        region: RegionId,
        task: TaskId,
        budget: Budget,
        observability: Option<ObservabilityState>,
        io_driver: Option<IoDriverHandle>,
    ) -> Self {
        let inner = Arc::new(std::sync::RwLock::new(CxInner::new(region, task, budget)));
        let observability_state =
            observability.unwrap_or_else(|| ObservabilityState::new(region, task));
        let observability = Arc::new(std::sync::RwLock::new(observability_state));

        debug!(
            task_id = ?task,
            region_id = ?region,
            budget_deadline = ?budget.deadline,
            budget_poll_quota = budget.poll_quota,
            budget_cost_quota = ?budget.cost_quota,
            budget_priority = budget.priority,
            budget_source = "cx_new",
            "budget initialized for context"
        );

        Self {
            inner,
            observability,
            io_driver,
        }
    }

    /// Creates a capability context for testing purposes.
    ///
    /// This constructor creates a Cx with default IDs and an infinite budget,
    /// suitable for unit and integration tests. The resulting context is fully
    /// functional but not connected to a real runtime.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::Cx;
    ///
    /// let cx = Cx::for_testing();
    /// assert!(!cx.is_cancel_requested());
    /// assert!(cx.checkpoint().is_ok());
    /// ```
    ///
    /// # Note
    ///
    /// This API is intended for testing only. Production code should receive
    /// Cx instances from the runtime, not construct them directly.
    #[must_use]
    pub fn for_testing() -> Self {
        Self::new(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
        )
    }

    /// Returns the current task context, if one is set.
    ///
    /// This is set by the runtime while polling a task.
    #[must_use]
    pub fn current() -> Option<Self> {
        CURRENT_CX.with(|slot| slot.borrow().clone())
    }

    /// Sets the current task context for the duration of the guard.
    pub(crate) fn set_current(cx: Option<Self>) -> CurrentCxGuard {
        let prev = CURRENT_CX.with(|slot| {
            let mut guard = slot.borrow_mut();
            let prev = guard.take();
            *guard = cx;
            prev
        });
        CurrentCxGuard { prev }
    }

    /// Returns a cloned handle to the I/O driver, if present.
    #[must_use]
    pub(crate) fn io_driver_handle(&self) -> Option<IoDriverHandle> {
        self.io_driver.clone()
    }

    /// Returns the current region ID.
    ///
    /// The region ID identifies the structured concurrency scope that owns this task.
    /// Useful for debugging and for associating task-specific data with region boundaries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// fn log_context(cx: &Cx) {
    ///     println!("Running in region: {:?}", cx.region_id());
    /// }
    /// ```
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.inner.read().expect("lock poisoned").region
    }

    /// Returns the current task ID.
    ///
    /// The task ID uniquely identifies this task within the runtime. Useful for
    /// debugging, tracing, and correlating log entries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// fn log_task(cx: &Cx) {
    ///     println!("Task {:?} starting work", cx.task_id());
    /// }
    /// ```
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.inner.read().expect("lock poisoned").task
    }

    /// Returns the current budget.
    ///
    /// The budget defines resource limits for this task:
    /// - `deadline`: Absolute time limit
    /// - `poll_quota`: Maximum number of polls
    /// - `cost_quota`: Abstract cost units
    /// - `priority`: Scheduling priority
    ///
    /// Frameworks can use the budget to implement request timeouts:
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn check_timeout(cx: &Cx) -> Result<(), TimeoutError> {
    ///     let budget = cx.budget();
    ///     if budget.is_expired() {
    ///         return Err(TimeoutError::DeadlineExceeded);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.inner.read().expect("lock poisoned").budget
    }

    /// Returns true if cancellation has been requested.
    ///
    /// This is a non-blocking check that queries whether a cancellation signal
    /// has been sent to this task. Unlike `checkpoint()`, this method does not
    /// return an error - it just reports the current state.
    ///
    /// Frameworks should check this periodically during long-running operations
    /// to enable graceful shutdown.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_items(cx: &Cx, items: Vec<Item>) -> Result<(), Error> {
    ///     for item in items {
    ///         // Check for cancellation between items
    ///         if cx.is_cancel_requested() {
    ///             return Err(Error::Cancelled);
    ///         }
    ///         process(item).await?;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.inner.read().expect("lock poisoned").cancel_requested
    }

    /// Checks for cancellation and returns an error if cancelled.
    ///
    /// This is a checkpoint where cancellation can be observed. It combines
    /// checking the cancellation flag with returning an error, making it
    /// convenient for use with the `?` operator.
    ///
    /// If the context is currently masked (via `masked()`), this method
    /// returns `Ok(())` even when cancellation is pending, deferring the
    /// cancellation until the mask is released.
    ///
    /// # Errors
    ///
    /// Returns an `Err` with kind `ErrorKind::Cancelled` if cancellation is
    /// pending and the context is not masked.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn do_work(cx: &Cx) -> Result<(), Error> {
    ///     // Use checkpoint with ? for concise cancellation handling
    ///     cx.checkpoint()?;
    ///
    ///     expensive_operation().await?;
    ///
    ///     cx.checkpoint()?;
    ///
    ///     another_operation().await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    #[allow(clippy::result_large_err)]
    pub fn checkpoint(&self) -> Result<(), crate::error::Error> {
        let (cancel_requested, mask_depth, task, region, budget, budget_baseline, cancel_reason) = {
            let inner = self.inner.read().expect("lock poisoned");
            (
                inner.cancel_requested,
                inner.mask_depth,
                inner.task,
                inner.region,
                inner.budget,
                inner.budget_baseline,
                inner.cancel_reason.clone(),
            )
        };

        let polls_used = if budget_baseline.poll_quota == u32::MAX {
            None
        } else {
            Some(budget_baseline.poll_quota.saturating_sub(budget.poll_quota))
        };
        let cost_used = match (budget_baseline.cost_quota, budget.cost_quota) {
            (Some(baseline), Some(remaining)) => Some(baseline.saturating_sub(remaining)),
            _ => None,
        };
        // Best-effort until a clock is threaded through Cx.
        let time_remaining = budget.deadline;

        let _ = (
            &task,
            &region,
            &budget,
            &budget_baseline,
            &cancel_reason,
            &polls_used,
            &cost_used,
            &time_remaining,
        );

        // Trace every checkpoint call at TRACE level for high-frequency observability
        trace!(
            task_id = ?task,
            region_id = ?region,
            polls_used = ?polls_used,
            polls_remaining = budget.poll_quota,
            time_remaining = ?time_remaining,
            time_remaining_source = "deadline",
            cost_used = ?cost_used,
            cost_remaining = ?budget.cost_quota,
            deadline = ?budget.deadline,
            cancel_requested,
            mask_depth,
            "checkpoint"
        );

        if cancel_requested {
            if mask_depth == 0 {
                // Determine which resource triggered cancellation for INFO logging
                let cancel_reason_ref = cancel_reason.as_ref();
                let exhausted_resource = cancel_reason_ref
                    .map_or_else(|| "unknown".to_string(), |r| format!("{:?}", r.kind));
                let _ = &exhausted_resource;

                info!(
                    task_id = ?task,
                    region_id = ?region,
                    exhausted_resource = %exhausted_resource,
                    cancel_reason = ?cancel_reason,
                    budget_deadline = ?budget.deadline,
                    budget_poll_quota = budget.poll_quota,
                    budget_cost_quota = ?budget.cost_quota,
                    "cancel observed at checkpoint - task cancelled"
                );

                trace!(
                    task_id = ?task,
                    region_id = ?region,
                    cancel_reason = ?cancel_reason,
                    cancel_kind = ?cancel_reason.as_ref().map(|r| r.kind),
                    mask_depth,
                    budget_deadline = ?budget.deadline,
                    budget_poll_quota = budget.poll_quota,
                    budget_cost_quota = ?budget.cost_quota,
                    budget_priority = budget.priority,
                    "cancel observed at checkpoint"
                );
                Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))
            } else {
                trace!(
                    task_id = ?task,
                    region_id = ?region,
                    cancel_reason = ?cancel_reason,
                    cancel_kind = ?cancel_reason.as_ref().map(|r| r.kind),
                    mask_depth,
                    "cancel observed but masked"
                );
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    /// Executes a closure with cancellation masked.
    ///
    /// While masked, `checkpoint()` will return `Ok(())` even if cancellation
    /// has been requested. This is used for critical sections that must not
    /// be interrupted, such as:
    ///
    /// - Completing a two-phase commit
    /// - Flushing buffered data
    /// - Releasing resources in a specific order
    ///
    /// Masking can be nested - each call to `masked()` increments a depth
    /// counter, and cancellation is only observable when depth returns to 0.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn commit_transaction(cx: &Cx, tx: Transaction) -> Result<(), Error> {
    ///     // Critical section: must complete even if cancelled
    ///     cx.masked(|| {
    ///         tx.prepare()?;
    ///         tx.commit()?;  // Cannot be interrupted here
    ///         Ok(())
    ///     })
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// Use masking sparingly. Long-masked sections defeat the purpose of
    /// responsive cancellation. Prefer short critical sections followed
    /// by a checkpoint.
    pub fn masked<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        {
            let mut inner = self.inner.write().expect("lock poisoned");
            inner.mask_depth += 1;
        }

        let _guard = MaskGuard { inner: &self.inner };
        f()
    }

    /// Traces an event for observability.
    ///
    /// Trace events are associated with the current task and region, enabling
    /// structured observability. In the lab runtime, traces are captured
    /// deterministically for replay and debugging.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_request(cx: &Cx, request: &Request) -> Response {
    ///     cx.trace("Request received");
    ///
    ///     let result = handle(request).await;
    ///
    ///     cx.trace("Request processed");
    ///
    ///     result
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// This is currently a placeholder. The full implementation will write
    /// to the trace buffer maintained by the runtime.
    pub fn trace(&self, message: &str) {
        self.log(LogEntry::trace(message));
    }

    /// Logs a structured entry to the attached collector, if present.
    pub fn log(&self, entry: LogEntry) {
        let obs = self.observability.read().expect("lock poisoned");
        let Some(collector) = obs.collector.clone() else {
            return;
        };
        drop(obs);
        let entry = entry.with_context(&self.diagnostic_context());
        collector.log(entry);
    }

    /// Returns a snapshot of the current diagnostic context.
    #[must_use]
    pub fn diagnostic_context(&self) -> DiagnosticContext {
        self.observability
            .read()
            .expect("lock poisoned")
            .context
            .clone()
    }

    /// Replaces the current diagnostic context.
    pub fn set_diagnostic_context(&self, ctx: DiagnosticContext) {
        let mut obs = self.observability.write().expect("lock poisoned");
        obs.context = ctx;
    }

    /// Attaches a log collector to this context.
    pub fn set_log_collector(&self, collector: LogCollector) {
        let mut obs = self.observability.write().expect("lock poisoned");
        obs.collector = Some(collector);
    }

    /// Returns the current log collector, if attached.
    #[must_use]
    pub fn log_collector(&self) -> Option<LogCollector> {
        self.observability
            .read()
            .expect("lock poisoned")
            .collector
            .clone()
    }

    /// Derives an observability state for a child task.
    pub(crate) fn child_observability(&self, region: RegionId, task: TaskId) -> ObservabilityState {
        let obs = self.observability.read().expect("lock poisoned");
        obs.derive_child(region, task)
    }

    /// Sets the cancellation flag (internal use).
    #[allow(dead_code)]
    pub(crate) fn set_cancel_internal(&self, value: bool) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.cancel_requested = value;
        if !value {
            inner.cancel_reason = None;
        }
    }

    /// Sets the cancellation flag for testing purposes.
    ///
    /// This method allows tests to simulate cancellation signals. It sets the
    /// `cancel_requested` flag, which will cause subsequent `checkpoint()` calls
    /// to return an error (unless masked).
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::Cx;
    ///
    /// let cx = Cx::for_testing();
    /// assert!(cx.checkpoint().is_ok());
    ///
    /// cx.set_cancel_requested(true);
    /// assert!(cx.checkpoint().is_err());
    /// ```
    ///
    /// # Note
    ///
    /// This API is intended for testing only. In production, cancellation signals
    /// are propagated by the runtime through the task tree.
    pub fn set_cancel_requested(&self, value: bool) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.cancel_requested = value;
        if !value {
            inner.cancel_reason = None;
        }
    }

    /// Creates a [`Scope`] bound to this context's region.
    ///
    /// The returned `Scope` can be used to spawn tasks, create child regions,
    /// and register finalizers. All spawned tasks will be owned by this
    /// context's region.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Using the scope! macro (recommended):
    /// scope!(cx, {
    ///     let handle = scope.spawn(|cx| async { 42 });
    ///     handle.await
    /// });
    ///
    /// // Manual scope creation:
    /// let scope = cx.scope();
    /// // Use scope for spawning...
    /// ```
    ///
    /// # Note
    ///
    /// In Phase 0, this creates a scope bound to the current region. In later
    /// phases, the `scope!` macro will create child regions with proper
    /// quiescence guarantees.
    #[must_use]
    pub fn scope(&self) -> crate::cx::Scope<'static> {
        let budget = self.budget();
        debug!(
            task_id = ?self.task_id(),
            region_id = ?self.region_id(),
            budget_deadline = ?budget.deadline,
            budget_poll_quota = budget.poll_quota,
            budget_cost_quota = ?budget.cost_quota,
            budget_priority = budget.priority,
            budget_source = "inherited",
            "scope budget inherited"
        );
        crate::cx::Scope::new(self.region_id(), budget)
    }

    /// Creates a [`Scope`] bound to this context's region with a custom budget.
    ///
    /// This is used by the `scope!` macro when a budget is specified:
    /// ```ignore
    /// scope!(cx, budget: Budget::deadline(Duration::from_secs(5)), {
    ///     // body
    /// })
    /// ```
    #[must_use]
    pub fn scope_with_budget(&self, budget: Budget) -> crate::cx::Scope<'static> {
        let parent_budget = self.budget();
        let deadline_tightened = match (parent_budget.deadline, budget.deadline) {
            (Some(parent), Some(child)) => child < parent,
            (None, Some(_)) => true,
            _ => false,
        };
        let poll_tightened = budget.poll_quota < parent_budget.poll_quota;
        let cost_tightened = match (parent_budget.cost_quota, budget.cost_quota) {
            (Some(parent), Some(child)) => child < parent,
            (None, Some(_)) => true,
            _ => false,
        };
        let priority_boosted = budget.priority > parent_budget.priority;
        let _ = (
            &deadline_tightened,
            &poll_tightened,
            &cost_tightened,
            &priority_boosted,
        );

        debug!(
            task_id = ?self.task_id(),
            region_id = ?self.region_id(),
            parent_deadline = ?parent_budget.deadline,
            parent_poll_quota = parent_budget.poll_quota,
            parent_cost_quota = ?parent_budget.cost_quota,
            parent_priority = parent_budget.priority,
            budget_deadline = ?budget.deadline,
            budget_poll_quota = budget.poll_quota,
            budget_cost_quota = ?budget.cost_quota,
            budget_priority = budget.priority,
            deadline_tightened,
            poll_tightened,
            cost_tightened,
            priority_boosted,
            budget_source = "explicit",
            "scope budget set"
        );
        crate::cx::Scope::new(self.region_id(), budget)
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

    #[test]
    fn masked_panic_safety() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let cx = test_cx();
        cx.set_cancel_requested(true);

        // Ensure initial state is cancelled (unmasked)
        assert!(cx.checkpoint().is_err());

        // Run a masked block that panics
        let cx_clone = cx.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            cx_clone.masked(|| {
                panic!("oops");
            });
        }));

        // After panic, mask depth should have been restored.
        // If it leaked, checkpoint() will return Ok(()) because it thinks it's still masked.
        assert!(
            cx.checkpoint().is_err(),
            "Cx remains masked after panic! mask_depth leaked."
        );
    }
}
