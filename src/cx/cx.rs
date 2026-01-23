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

use crate::combinator::select::SelectAll;
use crate::observability::{DiagnosticContext, LogCollector, LogEntry, SpanId};
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::task_handle::JoinError;
use crate::time::{timeout, TimeSource, WallClock};
use crate::tracing_compat::{debug, info, trace};
use crate::types::{Budget, CancelKind, CancelReason, CxInner, RegionId, TaskId, Time};
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Get the current wall clock time.
fn wall_clock_now() -> Time {
    static CLOCK: OnceLock<WallClock> = OnceLock::new();
    CLOCK.get_or_init(WallClock::new).now()
}

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

    /// Creates a test-only capability context with a specified budget.
    ///
    /// Similar to [`Self::for_testing()`] but allows specifying a custom budget
    /// for testing timeout behavior.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::{Cx, Budget, Time};
    ///
    /// // Create a context with a 30-second deadline
    /// let cx = Cx::for_testing_with_budget(
    ///     Budget::new().with_deadline(Time::from_secs(30))
    /// );
    /// ```
    ///
    /// # Note
    ///
    /// This API is intended for testing only. Production code should receive
    /// Cx instances from the runtime, not construct them directly.
    #[must_use]
    pub fn for_testing_with_budget(budget: Budget) -> Self {
        Self::new(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            budget,
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
    /// In addition to cancellation checking, this method records progress by
    /// updating the checkpoint state. This is useful for:
    /// - Detecting stuck/stalled tasks via `checkpoint_state()`
    /// - Work-stealing scheduler decisions
    /// - Observability and debugging
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
        // Record progress checkpoint
        {
            let mut inner = self.inner.write().expect("lock poisoned");
            inner.checkpoint_state.record();
        }
        // Check for cancellation
        self.check_cancel()
    }

    /// Checks for cancellation with a progress message.
    ///
    /// This is like [`checkpoint()`](Self::checkpoint) but also records a
    /// human-readable message describing the current progress. The message
    /// is stored in the checkpoint state and can be retrieved via
    /// [`checkpoint_state()`](Self::checkpoint_state).
    ///
    /// # Errors
    ///
    /// Returns an `Err` with kind `ErrorKind::Cancelled` if cancellation is
    /// pending and the context is not masked.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_batch(cx: &Cx, items: &[Item]) -> Result<(), Error> {
    ///     for (i, item) in items.iter().enumerate() {
    ///         cx.checkpoint_with(format!("Processing item {}/{}", i + 1, items.len()))?;
    ///         process(item).await?;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[allow(clippy::result_large_err)]
    pub fn checkpoint_with(&self, msg: impl Into<String>) -> Result<(), crate::error::Error> {
        // Record progress checkpoint with message
        {
            let mut inner = self.inner.write().expect("lock poisoned");
            inner.checkpoint_state.record_with_message(msg.into());
        }
        // Delegate to cancellation check logic (but don't double-record)
        self.check_cancel()
    }

    /// Returns a snapshot of the current checkpoint state.
    ///
    /// The checkpoint state tracks progress reporting checkpoints:
    /// - `last_checkpoint`: When the last checkpoint was recorded
    /// - `last_message`: The message from the last `checkpoint_with()` call
    /// - `checkpoint_count`: Total number of checkpoints
    ///
    /// This is useful for monitoring task progress and detecting stalled tasks.
    ///
    /// # Example
    ///
    /// ```ignore
    /// fn check_task_health(cx: &Cx) -> bool {
    ///     let state = cx.checkpoint_state();
    ///     if let Some(last) = state.last_checkpoint {
    ///         // Stalled if no checkpoint in 30 seconds
    ///         last.elapsed() < Duration::from_secs(30)
    ///     } else {
    ///         // Never checkpointed, could be stuck
    ///         false
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn checkpoint_state(&self) -> crate::types::CheckpointState {
        self.inner
            .read()
            .expect("lock poisoned")
            .checkpoint_state
            .clone()
    }

    /// Internal: checks cancellation without recording a checkpoint.
    #[allow(clippy::result_large_err)]
    fn check_cancel(&self) -> Result<(), crate::error::Error> {
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

    // ========================================================================
    // Cancel Attribution API
    // ========================================================================

    /// Cancels this context with a detailed reason.
    ///
    /// This is the preferred method for initiating cancellation, as it provides
    /// complete attribution information. The reason includes:
    /// - The kind of cancellation (e.g., User, Timeout, Deadline)
    /// - An optional message explaining the cancellation
    /// - Origin region and task information (automatically set)
    ///
    /// # Arguments
    ///
    /// * `kind` - The type of cancellation being initiated
    /// * `message` - An optional human-readable message explaining why
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    /// cx.cancel_with(CancelKind::User, Some("User pressed Ctrl+C"));
    /// assert!(cx.is_cancel_requested());
    ///
    /// if let Some(reason) = cx.cancel_reason() {
    ///     assert_eq!(reason.kind, CancelKind::User);
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// This method only sets the local cancellation flag. In a real runtime,
    /// cancellation propagates through the region tree via `cancel_request()`.
    pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {
        let mut inner = self.inner.write().expect("lock poisoned");
        let region = inner.region;
        let task = inner.task;

        let mut reason = CancelReason::new(kind).with_region(region).with_task(task);
        if let Some(msg) = message {
            reason = reason.with_message(msg);
        }

        inner.cancel_requested = true;
        inner.cancel_reason = Some(reason);

        debug!(
            task_id = ?task,
            region_id = ?region,
            cancel_kind = ?kind,
            cancel_message = message,
            "cancel initiated via cancel_with"
        );
    }

    /// Cancels without building a full attribution chain (performance-critical path).
    ///
    /// Use this when attribution isn't needed and minimizing allocations is important.
    /// The cancellation reason will have minimal attribution (kind + region only).
    ///
    /// # Performance
    ///
    /// This method avoids:
    /// - Message string allocation
    /// - Cause chain allocation
    /// - Timestamp lookup
    ///
    /// Use `cancel_with` when you need full attribution for debugging.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Fast cancellation - no allocation
    /// cx.cancel_fast(CancelKind::RaceLost);
    /// assert!(cx.is_cancel_requested());
    /// ```
    pub fn cancel_fast(&self, kind: CancelKind) {
        let mut inner = self.inner.write().expect("lock poisoned");
        let region = inner.region;

        // Minimal attribution: just kind and region
        let reason = CancelReason::new(kind).with_region(region);

        inner.cancel_requested = true;
        inner.cancel_reason = Some(reason);

        trace!(
            region_id = ?region,
            cancel_kind = ?kind,
            "cancel_fast initiated"
        );
    }

    /// Gets the cancellation reason if this context is cancelled.
    ///
    /// Returns `None` if the context is not cancelled, or `Some(reason)` if
    /// cancellation has been requested. The returned reason includes full
    /// attribution (kind, origin region, origin task, timestamp, cause chain).
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    /// assert!(cx.cancel_reason().is_none());
    ///
    /// cx.cancel_with(CancelKind::Timeout, Some("request timeout"));
    /// if let Some(reason) = cx.cancel_reason() {
    ///     assert_eq!(reason.kind, CancelKind::Timeout);
    ///     println!("Cancelled: {:?}", reason.kind);
    /// }
    /// ```
    #[must_use]
    pub fn cancel_reason(&self) -> Option<CancelReason> {
        let inner = self.inner.read().expect("lock poisoned");
        inner.cancel_reason.clone()
    }

    /// Iterates through the full cancellation cause chain.
    ///
    /// The first element is the immediate reason, followed by parent causes
    /// in order (immediate -> root). This is useful for understanding the
    /// full propagation path of a cancellation.
    ///
    /// Returns an empty iterator if the context is not cancelled.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::{CancelKind, CancelReason}};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Create a chained reason: ParentCancelled -> Deadline
    /// let root_cause = CancelReason::deadline();
    /// let chained = CancelReason::parent_cancelled().with_cause(root_cause);
    ///
    /// // Set it via internal method for testing
    /// cx.set_cancel_reason(chained);
    ///
    /// let chain: Vec<_> = cx.cancel_chain().collect();
    /// assert_eq!(chain.len(), 2);
    /// assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
    /// assert_eq!(chain[1].kind, CancelKind::Deadline);
    /// ```
    pub fn cancel_chain(&self) -> impl Iterator<Item = CancelReason> {
        let cancel_reason = self
            .inner
            .read()
            .expect("lock poisoned")
            .cancel_reason
            .clone();
        let chain: Vec<CancelReason> = cancel_reason
            .as_ref()
            .map(|r| r.chain().cloned().collect())
            .unwrap_or_default();
        chain.into_iter()
    }

    /// Gets the root cause of cancellation.
    ///
    /// This is the original trigger that initiated the cancellation, regardless
    /// of how many parent regions the cancellation propagated through. For example,
    /// if a grandchild task was cancelled due to a parent timeout, `root_cancel_cause()`
    /// returns the original Timeout reason, not the intermediate ParentCancelled reasons.
    ///
    /// Returns `None` if the context is not cancelled.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::{CancelKind, CancelReason}};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Simulate a deep cancellation chain
    /// let deadline = CancelReason::deadline();
    /// let parent1 = CancelReason::parent_cancelled().with_cause(deadline);
    /// let parent2 = CancelReason::parent_cancelled().with_cause(parent1);
    ///
    /// cx.set_cancel_reason(parent2);
    ///
    /// // Root cause is the original Deadline, not ParentCancelled
    /// if let Some(root) = cx.root_cancel_cause() {
    ///     assert_eq!(root.kind, CancelKind::Deadline);
    /// }
    /// ```
    #[must_use]
    pub fn root_cancel_cause(&self) -> Option<CancelReason> {
        let inner = self.inner.read().expect("lock poisoned");
        inner.cancel_reason.as_ref().map(|r| r.root_cause().clone())
    }

    /// Checks if cancellation was due to a specific kind.
    ///
    /// This checks the immediate reason only, not the cause chain. For example,
    /// if a task was cancelled with `ParentCancelled` due to an upstream timeout,
    /// `cancelled_by(CancelKind::ParentCancelled)` returns `true` but
    /// `cancelled_by(CancelKind::Timeout)` returns `false`.
    ///
    /// Use `any_cause_is()` to check the full cause chain.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    /// cx.cancel_with(CancelKind::User, Some("manual cancel"));
    ///
    /// assert!(cx.cancelled_by(CancelKind::User));
    /// assert!(!cx.cancelled_by(CancelKind::Timeout));
    /// ```
    #[must_use]
    pub fn cancelled_by(&self, kind: CancelKind) -> bool {
        let inner = self.inner.read().expect("lock poisoned");
        inner.cancel_reason.as_ref().is_some_and(|r| r.kind == kind)
    }

    /// Checks if any cause in the chain is a specific kind.
    ///
    /// This searches the entire cause chain, from the immediate reason to the
    /// root cause. This is useful for checking if a specific condition (like
    /// a timeout) anywhere in the hierarchy caused this cancellation.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::{CancelKind, CancelReason}};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Grandchild cancelled due to parent timeout
    /// let timeout = CancelReason::timeout();
    /// let parent_cancelled = CancelReason::parent_cancelled().with_cause(timeout);
    ///
    /// cx.set_cancel_reason(parent_cancelled);
    ///
    /// // Immediate reason is ParentCancelled, but timeout is in the chain
    /// assert!(cx.cancelled_by(CancelKind::ParentCancelled));
    /// assert!(!cx.cancelled_by(CancelKind::Timeout));  // immediate only
    /// assert!(cx.any_cause_is(CancelKind::Timeout));   // searches chain
    /// assert!(cx.any_cause_is(CancelKind::ParentCancelled));  // also in chain
    /// ```
    #[must_use]
    pub fn any_cause_is(&self, kind: CancelKind) -> bool {
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .cancel_reason
            .as_ref()
            .is_some_and(|r| r.any_cause_is(kind))
    }

    /// Sets the cancellation reason (for testing purposes).
    ///
    /// This method allows tests to set a specific cancellation reason, including
    /// complex cause chains. It sets both the `cancel_requested` flag and the
    /// `cancel_reason`.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::{CancelKind, CancelReason}};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Create a chained reason for testing
    /// let root = CancelReason::deadline();
    /// let chained = CancelReason::parent_cancelled().with_cause(root);
    ///
    /// cx.set_cancel_reason(chained);
    ///
    /// assert!(cx.is_cancel_requested());
    /// assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::ParentCancelled);
    /// ```
    pub fn set_cancel_reason(&self, reason: CancelReason) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.cancel_requested = true;
        inner.cancel_reason = Some(reason);
    }

    /// Races multiple futures, waiting for the first to complete.
    ///
    /// This method is used by the `race!` macro. It runs the provided futures
    /// concurrently (inline, not spawned) and returns the result of the first
    /// one to complete. Losers are dropped (cancelled).
    pub async fn race<T>(
        &self,
        futures: Vec<Pin<Box<dyn Future<Output = T> + Send>>>,
    ) -> Result<T, JoinError> {
        if futures.is_empty() {
            // No futures to race?
            // This case should be prevented by the macro, but if it happens,
            // we probably want to return an error or hang forever.
            // Hanging forever is consistent with `race()` identity (never).
            // However, returning an error is more practical.
            return Err(JoinError::Cancelled(CancelReason::race_loser()));
        }
        let (res, _) = SelectAll::new(futures).await;
        Ok(res)
    }

    /// Races multiple named futures.
    ///
    /// Similar to `race`, but accepts names for tracing purposes.
    pub async fn race_named<T>(
        &self,
        futures: Vec<(&'static str, Pin<Box<dyn Future<Output = T> + Send>>)>,
    ) -> Result<T, JoinError> {
        let futures: Vec<_> = futures.into_iter().map(|(_, f)| f).collect();
        self.race(futures).await
    }

    /// Races multiple futures with a timeout.
    ///
    /// If the timeout expires before any future completes, returns a cancellation error.
    pub async fn race_timeout<T>(
        &self,
        duration: Duration,
        futures: Vec<Pin<Box<dyn Future<Output = T> + Send>>>,
    ) -> Result<T, JoinError> {
        let race_fut = Box::pin(self.race(futures));
        match timeout(wall_clock_now(), duration, race_fut).await {
            Ok(res) => res,
            Err(_) => Err(JoinError::Cancelled(CancelReason::timeout())),
        }
    }

    /// Races multiple named futures with a timeout.
    pub async fn race_timeout_named<T>(
        &self,
        duration: Duration,
        futures: Vec<(&'static str, Pin<Box<dyn Future<Output = T> + Send>>)>,
    ) -> Result<T, JoinError> {
        let futures: Vec<_> = futures.into_iter().map(|(_, f)| f).collect();
        self.race_timeout(duration, futures).await
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

    // ========================================================================
    // Cancel Attribution API Tests
    // ========================================================================

    #[test]
    fn cancel_with_sets_reason() {
        let cx = test_cx();
        assert!(cx.cancel_reason().is_none());

        cx.cancel_with(CancelKind::User, Some("manual stop"));

        assert!(cx.is_cancel_requested());
        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::User);
        assert_eq!(reason.message, Some("manual stop"));
    }

    #[test]
    fn cancel_with_no_message() {
        let cx = test_cx();
        cx.cancel_with(CancelKind::Timeout, None);

        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::Timeout);
        assert!(reason.message.is_none());
    }

    #[test]
    fn cancel_reason_returns_none_when_not_cancelled() {
        let cx = test_cx();
        assert!(cx.cancel_reason().is_none());
    }

    #[test]
    fn cancel_chain_empty_when_not_cancelled() {
        let cx = test_cx();
        let chain: Vec<_> = cx.cancel_chain().collect();
        assert!(chain.is_empty());
    }

    #[test]
    fn cancel_chain_traverses_causes() {
        let cx = test_cx();

        // Build a chain: ParentCancelled -> ParentCancelled -> Deadline
        let deadline = CancelReason::deadline();
        let parent1 = CancelReason::parent_cancelled().with_cause(deadline);
        let parent2 = CancelReason::parent_cancelled().with_cause(parent1);

        cx.set_cancel_reason(parent2);

        let chain: Vec<_> = cx.cancel_chain().collect();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[1].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[2].kind, CancelKind::Deadline);
    }

    #[test]
    fn root_cancel_cause_returns_none_when_not_cancelled() {
        let cx = test_cx();
        assert!(cx.root_cancel_cause().is_none());
    }

    #[test]
    fn root_cancel_cause_finds_root() {
        let cx = test_cx();

        // Build: ParentCancelled -> Timeout
        let timeout = CancelReason::timeout();
        let parent = CancelReason::parent_cancelled().with_cause(timeout);

        cx.set_cancel_reason(parent);

        let root = cx.root_cancel_cause().expect("should have root");
        assert_eq!(root.kind, CancelKind::Timeout);
    }

    #[test]
    fn root_cancel_cause_with_no_chain() {
        let cx = test_cx();
        cx.cancel_with(CancelKind::Shutdown, None);

        let root = cx.root_cancel_cause().expect("should have root");
        assert_eq!(root.kind, CancelKind::Shutdown);
    }

    #[test]
    fn cancelled_by_checks_immediate_reason() {
        let cx = test_cx();

        // Build: ParentCancelled -> Deadline
        let deadline = CancelReason::deadline();
        let parent = CancelReason::parent_cancelled().with_cause(deadline);

        cx.set_cancel_reason(parent);

        // Immediate reason is ParentCancelled
        assert!(cx.cancelled_by(CancelKind::ParentCancelled));
        // Deadline is in chain but not immediate
        assert!(!cx.cancelled_by(CancelKind::Deadline));
    }

    #[test]
    fn cancelled_by_returns_false_when_not_cancelled() {
        let cx = test_cx();
        assert!(!cx.cancelled_by(CancelKind::User));
    }

    #[test]
    fn any_cause_is_searches_chain() {
        let cx = test_cx();

        // Build: ParentCancelled -> ParentCancelled -> Timeout
        let timeout = CancelReason::timeout();
        let parent1 = CancelReason::parent_cancelled().with_cause(timeout);
        let parent2 = CancelReason::parent_cancelled().with_cause(parent1);

        cx.set_cancel_reason(parent2);

        // All kinds in the chain return true
        assert!(cx.any_cause_is(CancelKind::ParentCancelled));
        assert!(cx.any_cause_is(CancelKind::Timeout));

        // Kinds not in chain return false
        assert!(!cx.any_cause_is(CancelKind::Deadline));
        assert!(!cx.any_cause_is(CancelKind::Shutdown));
    }

    #[test]
    fn any_cause_is_returns_false_when_not_cancelled() {
        let cx = test_cx();
        assert!(!cx.any_cause_is(CancelKind::Timeout));
    }

    #[test]
    fn set_cancel_reason_sets_flag_and_reason() {
        let cx = test_cx();
        assert!(!cx.is_cancel_requested());

        cx.set_cancel_reason(CancelReason::shutdown());

        assert!(cx.is_cancel_requested());
        assert_eq!(
            cx.cancel_reason().expect("should have reason").kind,
            CancelKind::Shutdown
        );
    }

    #[test]
    fn integration_realistic_usage() {
        // Simulate a realistic cancellation scenario:
        // 1. Root region times out
        // 2. Child task receives ParentCancelled
        // 3. Handler inspects the cause chain

        let cx = test_cx();

        // Simulate runtime setting a chained reason (timeout -> parent_cancelled)
        let timeout_reason = CancelReason::timeout().with_message("request timeout");
        let child_reason = CancelReason::parent_cancelled().with_cause(timeout_reason);

        cx.set_cancel_reason(child_reason);

        // Handler code checks various conditions
        assert!(cx.is_cancel_requested());

        // Immediate reason is ParentCancelled
        assert!(cx.cancelled_by(CancelKind::ParentCancelled));

        // But we want to know if a timeout caused it
        if cx.any_cause_is(CancelKind::Timeout) {
            // Log or metric: "Request cancelled due to timeout"
            let root = cx.root_cancel_cause().unwrap();
            assert_eq!(root.kind, CancelKind::Timeout);
            assert_eq!(root.message, Some("request timeout"));
        }

        // Full chain inspection
        let chain: Vec<_> = cx.cancel_chain().collect();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[1].kind, CancelKind::Timeout);
    }

    #[test]
    fn cancel_fast_sets_flag_and_reason() {
        let cx = test_cx();
        assert!(!cx.is_cancel_requested());
        assert!(cx.cancel_reason().is_none());

        cx.cancel_fast(CancelKind::Shutdown);

        assert!(cx.is_cancel_requested());
        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::Shutdown);
    }

    #[test]
    fn cancel_fast_no_cause_chain() {
        // cancel_fast is for the no-attribution path - it shouldn't create cause chains
        let cx = test_cx();

        cx.cancel_fast(CancelKind::Timeout);

        let reason = cx.cancel_reason().expect("should have reason");
        // No cause chain
        assert!(reason.cause.is_none());
        // No message
        assert!(reason.message.is_none());
        // Not truncated (nothing to truncate)
        assert!(!reason.truncated);
    }

    #[test]
    fn cancel_fast_sets_region() {
        let cx = test_cx();

        cx.cancel_fast(CancelKind::User);

        let reason = cx.cancel_reason().expect("should have reason");
        // Region should be set from the Cx
        let expected_region = RegionId::from_arena(ArenaIndex::new(0, 0));
        assert_eq!(reason.origin_region, expected_region);
    }

    #[test]
    fn cancel_fast_minimal_allocation() {
        // cancel_fast should create minimal CancelReason without extra allocations
        let cx = test_cx();

        cx.cancel_fast(CancelKind::Deadline);

        let reason = cx.cancel_reason().expect("should have reason");
        // Verify minimal structure: just kind, region, no message, no cause, no truncation
        assert_eq!(reason.kind, CancelKind::Deadline);
        assert!(reason.message.is_none());
        assert!(reason.cause.is_none());
        assert!(!reason.truncated);
        assert!(reason.truncated_at_depth.is_none());

        // Memory cost should be minimal (just the struct size, no boxed cause)
        let cost = reason.estimated_memory_cost();
        // Should be roughly just the size of CancelReason without any heap allocations for cause
        assert!(
            cost < 200,
            "cancel_fast should have minimal memory cost, got {cost}"
        );
    }

    // ========================================================================
    // Checkpoint Progress Reporting Tests
    // ========================================================================

    #[test]
    fn checkpoint_records_progress() {
        let cx = test_cx();

        // Initially no checkpoints
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_none());
        assert!(state.last_message.is_none());
        assert_eq!(state.checkpoint_count, 0);

        // Record first checkpoint
        assert!(cx.checkpoint().is_ok());
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_some());
        assert!(state.last_message.is_none());
        assert_eq!(state.checkpoint_count, 1);

        // Record second checkpoint
        assert!(cx.checkpoint().is_ok());
        let state = cx.checkpoint_state();
        assert_eq!(state.checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_with_records_message() {
        let cx = test_cx();

        // Record checkpoint with message
        assert!(cx.checkpoint_with("processing step 1").is_ok());
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_some());
        assert_eq!(state.last_message.as_deref(), Some("processing step 1"));
        assert_eq!(state.checkpoint_count, 1);

        // Second checkpoint overwrites message
        assert!(cx.checkpoint_with("processing step 2").is_ok());
        let state = cx.checkpoint_state();
        assert_eq!(state.last_message.as_deref(), Some("processing step 2"));
        assert_eq!(state.checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_clears_message() {
        let cx = test_cx();

        // Record checkpoint with message
        assert!(cx.checkpoint_with("step 1").is_ok());
        assert_eq!(
            cx.checkpoint_state().last_message.as_deref(),
            Some("step 1")
        );

        // Regular checkpoint clears the message
        assert!(cx.checkpoint().is_ok());
        assert!(cx.checkpoint_state().last_message.is_none());
    }

    #[test]
    fn checkpoint_with_checks_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        // checkpoint_with should return error on cancellation
        assert!(cx.checkpoint_with("should fail").is_err());

        // But checkpoint state should still be updated
        let state = cx.checkpoint_state();
        assert_eq!(state.checkpoint_count, 1);
        assert_eq!(state.last_message.as_deref(), Some("should fail"));
    }

    #[test]
    fn checkpoint_state_is_snapshot() {
        let cx = test_cx();

        // Get a snapshot
        let snapshot = cx.checkpoint_state();
        assert_eq!(snapshot.checkpoint_count, 0);

        // Record more checkpoints
        assert!(cx.checkpoint().is_ok());
        assert!(cx.checkpoint().is_ok());

        // Original snapshot should be unchanged
        assert_eq!(snapshot.checkpoint_count, 0);

        // New snapshot should reflect updates
        assert_eq!(cx.checkpoint_state().checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_with_accepts_string_types() {
        let cx = test_cx();

        // Test &str
        assert!(cx.checkpoint_with("literal").is_ok());

        // Test String
        assert!(cx.checkpoint_with(String::from("owned")).is_ok());

        // Test format!
        assert!(cx.checkpoint_with(format!("item {}", 42)).is_ok());

        assert_eq!(cx.checkpoint_state().checkpoint_count, 3);
    }
}
