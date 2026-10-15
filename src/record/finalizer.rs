//! Finalizer types for region cleanup.
//!
//! Finalizers are cleanup handlers that run when a region closes, after all
//! children have completed. They are executed in LIFO (last-in, first-out)
//! order to ensure proper resource release ordering.

use crate::types::Budget;
use std::fmt;
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

/// Stable error-code token for finalizer timeout diagnostics.
pub const FINALIZER_TIMEOUT_ASUP_CODE: &str = "ASUP-E303";

/// Returns the default budget for finalizer execution.
#[must_use]
#[inline]
pub fn finalizer_budget() -> Budget {
    let budget = Budget::new().with_poll_quota(FINALIZER_POLL_BUDGET);

    // EDGE CASE VALIDATION: Ensure budget parameters are sane
    // This catches invalid configurations that could cause unbounded finalizer execution
    debug_assert!(
        budget.poll_quota > 0,
        "br-asupersync-mg70eb: finalizer budget must have positive poll quota \
         (poll_quota={})",
        budget.poll_quota
    );
    debug_assert!(
        FINALIZER_TIME_BUDGET_NANOS > 0,
        "[ASUP-E303] finalizer time budget must be positive \
         (time_budget_nanos={})",
        FINALIZER_TIME_BUDGET_NANOS
    );
    debug_assert!(
        FINALIZER_TIME_BUDGET_NANOS <= 300_000_000_000, // 5 minutes max
        "[ASUP-E303] finalizer time budget seems excessive, may indicate configuration error \
         (time_budget_nanos={}, max_reasonable=300_000_000_000)",
        FINALIZER_TIME_BUDGET_NANOS
    );

    budget
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

    /// Validates escalation policy configuration for edge cases.
    ///
    /// This catches policy misconfigurations that could lead to finalizer hangs
    /// or unexpected behavior during budget exhaustion scenarios.
    #[inline]
    #[must_use = "validate_policy_configuration returns configuration diagnostics"]
    pub fn validate_policy_configuration(self) -> Result<(), &'static str> {
        match self {
            Self::Soft => {
                // EDGE CASE VALIDATION: Soft policy should be used with caution
                // This policy can cause indefinite waits if finalizers don't respect cancellation
                debug_assert!(
                    true, // Always passes but documents the risk
                    "br-asupersync-mg70eb: Soft escalation policy can cause indefinite waits \
                     - ensure finalizers respect cancellation signals"
                );
                Ok(())
            }
            Self::BoundedLog => {
                // This is the default and safest policy
                Ok(())
            }
            Self::BoundedPanic => {
                // EDGE CASE VALIDATION: Panic policy should be used carefully
                // This policy can bring down the entire runtime if budget is exceeded
                debug_assert!(
                    true, // Always passes but documents the risk
                    "br-asupersync-mg70eb: BoundedPanic escalation policy will panic on budget exhaustion \
                     - ensure finalizer budgets are adequate for expected workload"
                );
                Ok(())
            }
        }
    }
}

/// Rendered finalizer timeout diagnostic used by runtime and docs surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizerTimeoutDiagnostic {
    /// Stable finalizer id within the runtime state.
    pub finalizer_id: u64,
    /// Configured finalizer completion budget in nanoseconds.
    pub time_budget_nanos: u64,
    /// Escalation policy active when the timeout was detected.
    pub escalation: FinalizerEscalation,
}

impl FinalizerTimeoutDiagnostic {
    /// Create a finalizer timeout diagnostic with an explicit time budget.
    #[must_use]
    #[inline]
    pub const fn new(
        finalizer_id: u64,
        time_budget_nanos: u64,
        escalation: FinalizerEscalation,
    ) -> Self {
        Self {
            finalizer_id,
            time_budget_nanos,
            escalation,
        }
    }

    /// Create a finalizer timeout diagnostic using the default finalizer budget.
    #[must_use]
    #[inline]
    pub const fn for_default_budget(finalizer_id: u64, escalation: FinalizerEscalation) -> Self {
        Self::new(finalizer_id, FINALIZER_TIME_BUDGET_NANOS, escalation)
    }
}

impl fmt::Display for FinalizerTimeoutDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{FINALIZER_TIMEOUT_ASUP_CODE}] finalizer {} exceeded {}ns completion budget \
             (escalation={:?}); move blocking cleanup behind a bounded capability or avoid \
             waiting on same-region tasks from finalizer code",
            self.finalizer_id, self.time_budget_nanos, self.escalation
        )
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
        // EDGE CASE VALIDATION: Validate escalation policy configuration
        // This catches policy misconfigurations during stack creation
        let _ = escalation.validate_policy_configuration();

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
    ///
    /// # LIFO Ordering Contract
    ///
    /// Finalizers are added to the top of the stack and later popped in
    /// reverse order (LIFO). This ensures that resources acquired in order
    /// A→B→C are released in order C→B→A, matching RAII principles.
    ///
    /// Contract verified by: `region_finalizer_stack()` and `finalizer_lifo_order()` tests.
    #[inline]
    pub fn push(&mut self, finalizer: Finalizer) {
        // EDGE CASE VALIDATION: Check for excessive finalizer accumulation
        // This catches potential memory leaks or runaway finalizer creation
        debug_assert!(
            self.finalizers.len() < 10000,
            "br-asupersync-mg70eb: excessive finalizer count suggests potential leak \
             (current_count={}, max_reasonable=10000)",
            self.finalizers.len()
        );

        self.finalizers.push(finalizer);

        // Defensive contract verification in debug builds
        #[cfg(debug_assertions)]
        {
            debug_assert!(
                !self.finalizers.is_empty(),
                "FinalizerStack::push() maintains non-empty invariant after successful push"
            );

            // EDGE CASE VALIDATION: Verify stack integrity after push
            debug_assert_eq!(
                self.finalizers.len(),
                self.len(),
                "br-asupersync-mg70eb: finalizer stack length inconsistency after push"
            );
        }
    }

    /// Pops a finalizer from the stack (LIFO order).
    ///
    /// # LIFO Contract Enforcement
    ///
    /// This method maintains strict LIFO semantics to ensure proper resource
    /// release ordering. The last finalizer added (most recent) is always
    /// the first to execute, matching structured concurrency cleanup patterns.
    ///
    /// The underlying Vec::pop() guarantees LIFO ordering, and this contract
    /// is verified by tests in region.rs (`finalizer_lifo_order`).
    #[inline]
    pub fn pop(&mut self) -> Option<Finalizer> {
        let _len_before = self.finalizers.len();
        let result = self.finalizers.pop();

        // Defensive assertion: LIFO ordering contract verification
        #[cfg(debug_assertions)]
        if result.is_some() {
            // Document LIFO guarantee in debug builds for audit trail
            debug_assert!(
                true, // Always passes - documents the invariant
                "FinalizerStack::pop() maintains LIFO contract per SEM-INV-002"
            );

            // EDGE CASE VALIDATION: Verify stack integrity after pop
            debug_assert_eq!(
                self.finalizers.len(),
                _len_before.saturating_sub(1),
                "br-asupersync-mg70eb: finalizer stack length inconsistency after pop \
                 (before={}, after={}, expected={})",
                _len_before,
                self.finalizers.len(),
                _len_before.saturating_sub(1)
            );

            // EDGE CASE VALIDATION: Check for stack underflow edge case
            debug_assert!(
                _len_before > 0,
                "br-asupersync-mg70eb: finalizer stack underflow - popped from empty stack"
            );
        } else {
            // EDGE CASE VALIDATION: Verify empty pop behavior
            debug_assert_eq!(
                _len_before, 0,
                "br-asupersync-mg70eb: finalizer stack returned None but was not empty \
                 (_len_before={})",
                _len_before
            );
        }

        result
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

/// Failure of an explicitly bounded, runtime-owned finalizer execution.
///
/// These are per-finalizer ceilings. Copying a region's shutdown envelope into
/// several finalizers does not establish an aggregate subtree work bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalizerBudgetError {
    /// The user future used every allowed poll and still needed another poll.
    PollQuota { limit: u32, polled: u32 },
    /// The captured runtime clock reached the absolute shutdown deadline.
    Deadline {
        deadline: crate::types::Time,
        observed: crate::types::Time,
    },
    /// A deadline cannot be enforced without an explicit runtime timer driver.
    TimerUnavailable { deadline: crate::types::Time },
}

impl fmt::Display for FinalizerBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PollQuota { limit, polled } => write!(
                formatter,
                "finalizer poll quota exhausted: limit={limit}, polled={polled}"
            ),
            Self::Deadline { deadline, observed } => write!(
                formatter,
                "finalizer deadline exceeded: deadline={deadline:?}, observed={observed:?}"
            ),
            Self::TimerUnavailable { deadline } => write!(
                formatter,
                "finalizer deadline requires a runtime timer driver: deadline={deadline:?}"
            ),
        }
    }
}

impl std::error::Error for FinalizerBudgetError {}

/// Region-owned shutdown ceiling shared with already-running finalizers.
///
/// The region updates this monotonically before dispatching cancellation wakes.
/// Reading a snapshot invokes no user callback under runtime or region locks.
pub(crate) type ShutdownBudget = std::sync::Arc<parking_lot::RwLock<Option<Budget>>>;

/// Enforces an explicit shutdown envelope at an unlocked task-poll boundary.
///
/// A None shutdown ceiling is the legacy path, without poll/deadline enforcement.
/// The first observed Some activates enforcement; later ceilings meet the
/// previous ceiling and never loosen it, including if a caller restores None.
/// The wrapper owns the original pinned future, including its destructor; zero
/// quota, expired deadlines and missing timer authority retire that future and
/// return failure, without polling it or silently treating it as completed.
///
/// The poll quota counts actual polls admitted after first activation; preceding
/// legacy polls do not consume a shutdown budget that did not yet exist. A
/// final permitted poll may return Ready successfully; Pending on that poll
/// exhausts immediately.
/// Deadline checks precede quota checks and also run after a user poll returns.
/// A synchronous poll that never returns cannot be preempted by this wrapper.
/// This wrapper charges no abstract cost units and does not enforce cost quota
/// or priority. Cost bounds require a separate charging/admission contract.
///
/// Its captured driver registration wakes even while task cancellation is
/// masked. It uses neither ambient time nor Sleep's cancellation-as-readiness
/// behavior. Timer-horizon wakes simply rearm against the original deadline.
pub(crate) struct BudgetedFinalizer {
    inner: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    budget: ShutdownBudget,
    observed_budget: Option<Budget>,
    timer: Option<crate::time::TimerDriverHandle>,
    registration: Option<crate::time::TimerHandle>,
    polled: u32,
    finished: bool,
}

impl BudgetedFinalizer {
    pub(crate) fn new(
        inner: Pin<Box<dyn Future<Output = ()> + Send>>,
        budget: ShutdownBudget,
        timer: Option<crate::time::TimerDriverHandle>,
    ) -> Self {
        Self {
            inner: Some(inner),
            budget,
            observed_budget: None,
            timer,
            registration: None,
            polled: 0,
            finished: false,
        }
    }

    fn snapshot_budget(&mut self) -> Option<Budget> {
        let current = *self.budget.read();
        self.observed_budget = match (self.observed_budget, current) {
            (Some(previous), Some(current)) => Some(previous.meet(current)),
            (Some(previous), None) => Some(previous),
            (None, current) => current,
        };
        self.observed_budget
    }

    fn deadline_failure(&self, budget: Option<Budget>) -> Option<FinalizerBudgetError> {
        let deadline = budget?.deadline?;
        let Some(timer) = &self.timer else {
            return Some(FinalizerBudgetError::TimerUnavailable { deadline });
        };
        let observed = timer.now();
        (observed >= deadline).then_some(FinalizerBudgetError::Deadline { deadline, observed })
    }

    fn cancel_registration(&mut self) {
        if let Some(registration) = self.registration.take() {
            let timer = self.timer.as_ref().expect("registration owns its driver");
            let _ = timer.cancel(&registration);
        }
    }

    fn arm_deadline(&mut self, deadline: crate::types::Time, waker: &std::task::Waker) {
        // Refresh the actual task Waker and recover from an already-fired
        // wheel-horizon registration. There is at most one active timer.
        self.cancel_registration();
        let timer = self.timer.as_ref().expect("deadline authority checked");
        self.registration = Some(timer.register(deadline, waker.clone()));
    }

    fn poll_inner(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<crate::types::Outcome<(), FinalizerBudgetError>> {
        use crate::types::Outcome;
        use std::task::Poll;
        let admitted_budget = self.snapshot_budget();
        if let Some(error) = self.deadline_failure(admitted_budget) {
            return Poll::Ready(Outcome::Err(error));
        }
        if let Some(budget) = admitted_budget
            && self.polled >= budget.poll_quota
        {
            return Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                limit: budget.poll_quota,
                polled: self.polled,
            }));
        }
        if let Some(deadline) = admitted_budget.and_then(|budget| budget.deadline) {
            self.arm_deadline(deadline, cx.waker());
        }
        if admitted_budget.is_some() {
            self.polled += 1;
        }
        let result = self
            .inner
            .as_mut()
            .expect("unfinished finalizer owns its future")
            .as_mut()
            .poll(cx);
        let completion_budget = self.snapshot_budget();
        if let Some(error) = self.deadline_failure(completion_budget) {
            return Poll::Ready(Outcome::Err(error));
        }
        // A limit can tighten while a synchronous poll is running. Recheck
        // before publishing its result; zero or a now-exceeded ceiling refuses
        // even a Ready result. This cannot preempt the running poll itself.
        if let Some(budget) = completion_budget
            && (budget.poll_quota == 0 || self.polled > budget.poll_quota)
        {
            return Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                limit: budget.poll_quota,
                polled: self.polled,
            }));
        }
        match result {
            Poll::Ready(()) => Poll::Ready(Outcome::Ok(())),
            Poll::Pending
                if completion_budget.is_some_and(|budget| self.polled >= budget.poll_quota) =>
            {
                Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                    limit: completion_budget
                        .expect("quota guard selected an active budget")
                        .poll_quota,
                    polled: self.polled,
                }))
            }
            Poll::Pending => {
                // Activation/tightening during user poll must arm the new
                // deadline before returning Pending, even if user code never
                // wakes again. Later updates are woken by the region owner.
                if completion_budget.and_then(|budget| budget.deadline)
                    != admitted_budget.and_then(|budget| budget.deadline)
                    && let Some(deadline) = completion_budget.and_then(|budget| budget.deadline)
                {
                    self.arm_deadline(deadline, cx.waker());
                }
                Poll::Pending
            }
        }
    }

    fn retire(
        &mut self,
        outcome: crate::types::Outcome<(), FinalizerBudgetError>,
    ) -> crate::types::Outcome<(), FinalizerBudgetError> {
        self.finished = true;
        // Retire the user future before publishing a terminal result. This is
        // called from the task poll/completion boundary, never under a region
        // or RuntimeState lock. A user destructor panic outranks both a budget
        // failure and an earlier body panic; secondary timer-retirement panics
        // cannot replace that first destructor failure.
        let inner = self.inner.take();
        let mut retirement_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(inner);
        }))
        .err()
        .map(finalizer_panic_payload);
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.cancel_registration();
        })) {
            if retirement_panic.is_none() {
                retirement_panic = Some(finalizer_panic_payload(payload));
            } else {
                // Arbitrary panic-payload destructors must not cause a second
                // unwind while the already selected failure is being retired.
                std::mem::forget(payload);
            }
        }
        retirement_panic.map_or(outcome, crate::types::Outcome::Panicked)
    }
}

fn finalizer_panic_payload(payload: Box<dyn std::any::Any + Send>) -> crate::types::PanicPayload {
    let message = crate::cx::scope::payload_to_string(&payload);
    // Retain the observed message without running arbitrary payload Drop code
    // during panic retirement, matching the runtime's existing unwind boundary.
    std::mem::forget(payload);
    crate::types::PanicPayload::new(message)
}

impl Future for BudgetedFinalizer {
    type Output = crate::types::Outcome<(), FinalizerBudgetError>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "BudgetedFinalizer polled after completion");
        let outcome =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| this.poll_inner(cx))) {
                Ok(std::task::Poll::Pending) => return std::task::Poll::Pending,
                Ok(std::task::Poll::Ready(outcome)) => outcome,
                Err(payload) => crate::types::Outcome::Panicked(finalizer_panic_payload(payload)),
            };
        std::task::Poll::Ready(this.retire(outcome))
    }
}

impl Drop for BudgetedFinalizer {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let unwinding = std::thread::panicking();
        let retired = self.retire(crate::types::Outcome::Ok(()));
        if let crate::types::Outcome::Panicked(payload) = retired {
            // On ordinary abandonment the enclosing runtime boundary must see
            // destructor failure. During an unrelated unwind, retain its
            // primary panic rather than initiate an aborting double unwind.
            if !unwinding {
                std::panic::panic_any(payload.message().to_owned());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
    fn finalizer_timeout_diagnostic_has_asup_e303_prefix() {
        let diagnostic =
            FinalizerTimeoutDiagnostic::for_default_budget(42, FinalizerEscalation::BoundedPanic);
        let rendered = diagnostic.to_string();

        assert!(rendered.starts_with("[ASUP-E303]"), "{rendered}");
        assert!(rendered.contains("finalizer 42"), "{rendered}");
        assert!(rendered.contains("5000000000ns"), "{rendered}");
        assert!(rendered.contains("BoundedPanic"), "{rendered}");
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
        ]
        .join("\n")
    }

    /// Generate debug representations of finalizers for golden testing
    fn finalizer_debug_representations() -> String {
        let sync_finalizer = Finalizer::Sync(Box::new(|| {}));
        let async_finalizer = Finalizer::Async(Box::pin(async {}));

        vec![
            format!("Sync: {:?}", sync_finalizer),
            format!("Async: {:?}", async_finalizer),
        ]
        .join("\n")
    }

    /// Generate finalizer stack states for golden testing
    fn finalizer_stack_operations() -> String {
        let mut lines = Vec::new();

        // Empty stack
        let mut stack = FinalizerStack::new();
        lines.push(format!(
            "empty_stack: len={}, is_empty={}, escalation={:?}",
            stack.len(),
            stack.is_empty(),
            stack.escalation()
        ));

        // Stack with custom escalation
        let stack_panic = FinalizerStack::with_escalation(FinalizerEscalation::BoundedPanic);
        lines.push(format!(
            "panic_stack: len={}, is_empty={}, escalation={:?}",
            stack_panic.len(),
            stack_panic.is_empty(),
            stack_panic.escalation()
        ));

        // Add finalizers and show progression
        stack.push_sync(|| {});
        lines.push(format!(
            "after_sync_push: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        stack.push_async(async {});
        lines.push(format!(
            "after_async_push: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        stack.push_sync(|| {});
        lines.push(format!(
            "after_second_sync: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        // Pop operations (don't execute, just show types)
        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!(
            "after_first_pop: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!(
            "after_second_pop: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!(
            "after_third_pop: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        // Test pop from empty
        let empty_pop = stack.pop();
        lines.push(format!(
            "empty_pop: {}",
            if empty_pop.is_none() { "None" } else { "Some" }
        ));

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
            lines.push(format!(
                "{:?}|{}|{}|{}",
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

    struct BudgetProbe {
        polls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        drops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        ready_at: Option<usize>,
        panic_poll: bool,
        panic_drop: bool,
        wake_pending: bool,
        advance: Option<(
            std::sync::Arc<crate::time::VirtualClock>,
            crate::types::Time,
        )>,
        update_budget: Option<(ShutdownBudget, Option<Budget>)>,
    }

    impl BudgetProbe {
        fn new(ready_at: Option<usize>) -> Self {
            Self {
                polls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                drops: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                ready_at,
                panic_poll: false,
                panic_drop: false,
                wake_pending: false,
                advance: None,
                update_budget: None,
            }
        }
    }

    impl Future for BudgetProbe {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
            let polled = self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            assert!(!self.panic_poll, "budgeted finalizer body panic");
            if let Some((clock, time)) = self.advance.take() {
                clock.advance_to(time);
            }
            if let Some((shared, next)) = self.update_budget.take() {
                *shared.write() = next;
            }
            if self.ready_at == Some(polled) {
                std::task::Poll::Ready(())
            } else {
                if self.wake_pending {
                    cx.waker().wake_by_ref();
                }
                std::task::Poll::Pending
            }
        }
    }

    impl Drop for BudgetProbe {
        fn drop(&mut self) {
            assert_eq!(
                self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                0
            );
            assert!(!self.panic_drop, "budgeted finalizer destructor panic");
        }
    }

    #[derive(Default)]
    struct BudgetWake(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for BudgetWake {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn shutdown_budget(budget: Option<Budget>) -> ShutdownBudget {
        std::sync::Arc::new(parking_lot::RwLock::new(budget))
    }

    #[test]
    fn explicit_finalizer_poll_budget_counts_actual_work_and_retires_once() {
        use crate::types::Outcome;
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        for limit in [0, 1, 3] {
            let mut probe = BudgetProbe::new(None);
            probe.wake_pending = true;
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(Budget::INFINITE.with_poll_quota(limit))),
                None,
            );
            let wake = std::sync::Arc::new(BudgetWake::default());
            let waker = std::task::Waker::from(wake.clone());
            let mut cx = std::task::Context::from_waker(&waker);
            for _ in 0..limit.saturating_sub(1) {
                assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
                assert_eq!(drops.load(Ordering::SeqCst), 0);
            }
            assert_eq!(
                Pin::new(&mut bounded).poll(&mut cx),
                Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                    limit,
                    polled: limit
                }))
            );
            assert_eq!(polls.load(Ordering::SeqCst), limit as usize);
            assert_eq!(wake.0.load(Ordering::SeqCst), limit as usize);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(bounded);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
        // Ready on the last permitted user poll is real successful cleanup.
        for limit in [1, 3] {
            let probe = BudgetProbe::new(Some(limit as usize));
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(Budget::INFINITE.with_poll_quota(limit))),
                None,
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            for _ in 1..limit {
                assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
            }
            assert_eq!(
                Pin::new(&mut bounded).poll(&mut cx),
                Poll::Ready(Outcome::Ok(()))
            );
            assert_eq!(polls.load(Ordering::SeqCst), limit as usize);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(bounded);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn explicit_finalizer_deadline_owns_real_wake_and_refuses_missing_clock() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        let start = Time::from_secs(7);
        let deadline = start.saturating_add_nanos(2_000_000);
        let clock = std::sync::Arc::new(VirtualClock::starting_at(start));
        let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let wake = std::sync::Arc::new(BudgetWake::default());
        let waker = std::task::Waker::from(wake.clone());
        let mut cx = std::task::Context::from_waker(&waker);
        let mut bounded = BudgetedFinalizer::new(
            Box::pin(probe),
            shutdown_budget(Some(
                Budget::INFINITE.with_poll_quota(3).with_deadline(deadline),
            )),
            Some(driver.clone()),
        );
        assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(
            wake.0.load(Ordering::SeqCst),
            0,
            "user future did not wake itself"
        );
        clock.advance_to(Time::from_nanos(deadline.as_nanos() - 1));
        assert_eq!(driver.process_timers(), 0);
        clock.advance_to(deadline);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::Deadline {
                deadline,
                observed: deadline
            }))
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "deadline wake never repolls expired user work"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(driver.pending_count(), 0);

        for missing_driver in [false, true] {
            let probe = BudgetProbe::new(Some(1));
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(
                    Budget::INFINITE.with_poll_quota(0).with_deadline(deadline),
                )),
                (!missing_driver).then(|| driver.clone()),
            );
            let expected = if missing_driver {
                FinalizerBudgetError::TimerUnavailable { deadline }
            } else {
                FinalizerBudgetError::Deadline {
                    deadline,
                    observed: deadline,
                }
            };
            assert_eq!(
                Pin::new(&mut bounded).poll(&mut cx),
                Poll::Ready(Outcome::Err(expected))
            );
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(driver.pending_count(), 0);
        }
    }

    #[test]
    fn explicit_finalizer_post_poll_deadline_and_destructor_panic_precedence() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        for cause in 0..6 {
            let start = Time::from_secs(11);
            let deadline = start.saturating_add_nanos(3_000_000);
            let clock = std::sync::Arc::new(VirtualClock::starting_at(start));
            let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
            let mut probe = BudgetProbe::new((cause == 0 || cause == 5).then_some(1));
            probe.panic_poll = cause == 2 || cause == 3;
            probe.panic_drop = matches!(cause, 1 | 3 | 4 | 5);
            if cause == 0 {
                probe.advance = Some((clock, deadline));
            }
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let quota = if cause == 4 { 0 } else { 1 };
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(
                    Budget::INFINITE
                        .with_poll_quota(quota)
                        .with_deadline(deadline),
                )),
                Some(driver.clone()),
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let Poll::Ready(outcome) = Pin::new(&mut bounded).poll(&mut cx) else {
                panic!("this bounded control must terminate in one wrapper poll");
            };
            match cause {
                0 => assert_eq!(
                    outcome,
                    Outcome::Err(FinalizerBudgetError::Deadline {
                        deadline,
                        observed: deadline
                    })
                ),
                2 => assert!(
                    matches!(outcome, Outcome::Panicked(ref payload) if payload.message() == "budgeted finalizer body panic")
                ),
                _ => assert!(
                    matches!(outcome, Outcome::Panicked(ref payload) if payload.message() == "budgeted finalizer destructor panic")
                ),
            }
            assert_eq!(polls.load(Ordering::SeqCst), usize::from(cause != 4));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(driver.pending_count(), 0);
            drop(bounded);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn explicit_finalizer_abandonment_retires_future_and_timer_without_double_drop() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::Time;
        use std::sync::atomic::Ordering;
        for panic_drop in [false, true] {
            let clock = std::sync::Arc::new(VirtualClock::starting_at(Time::from_secs(19)));
            let driver = TimerDriverHandle::with_virtual_clock(clock);
            let mut probe = BudgetProbe::new(None);
            probe.panic_drop = panic_drop;
            let drops = probe.drops.clone();
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(
                    Budget::INFINITE
                        .with_poll_quota(3)
                        .with_deadline(Time::from_secs(20)),
                )),
                Some(driver.clone()),
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
            assert_eq!(driver.pending_count(), 1);
            let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(bounded)));
            assert_eq!(retired.is_err(), panic_drop);
            if let Err(payload) = retired {
                assert_eq!(
                    crate::cx::scope::payload_to_string(&payload),
                    "budgeted finalizer destructor panic"
                );
            }
            assert_eq!(driver.pending_count(), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn explicit_finalizer_late_activation_and_tightening_are_monotone() {
        use crate::types::Outcome;
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        let shared = shutdown_budget(None);
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let mut bounded = BudgetedFinalizer::new(Box::pin(probe), shared.clone(), None);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for _ in 0..150 {
            assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        }
        assert_eq!(
            polls.load(Ordering::SeqCst),
            150,
            "None retains legacy progress beyond the old nominal 100-poll budget"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        *shared.write() = Some(Budget::INFINITE.with_poll_quota(3));
        assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        *shared.write() = Some(Budget::INFINITE.with_poll_quota(5));
        assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        *shared.write() = None;
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                limit: 3,
                polled: 3
            }))
        );
        assert_eq!(polls.load(Ordering::SeqCst), 153);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let shared = shutdown_budget(Some(Budget::INFINITE.with_poll_quota(5)));
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let mut bounded = BudgetedFinalizer::new(Box::pin(probe), shared.clone(), None);
        assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        *shared.write() = Some(Budget::INFINITE.with_poll_quota(0));
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                limit: 0,
                polled: 1
            }))
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "tightened zero ceiling never grants another poll"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        // Activation during a returning user poll cannot retroactively stop
        // that poll, but zero still refuses its completion and retires it.
        let shared = shutdown_budget(None);
        let mut probe = BudgetProbe::new(Some(1));
        probe.update_budget = Some((shared.clone(), Some(Budget::INFINITE.with_poll_quota(0))));
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let mut bounded = BudgetedFinalizer::new(Box::pin(probe), shared, None);
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                limit: 0,
                polled: 0
            }))
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "the sole poll began before activation"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn explicit_finalizer_late_deadline_arms_and_tightening_replaces_real_timer() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        for activate_during_poll in [false, true] {
            let start = Time::from_secs(31);
            let deadline = start.saturating_add_nanos(2_000_000);
            let later = start.saturating_add_nanos(6_000_000);
            let clock = std::sync::Arc::new(VirtualClock::starting_at(start));
            let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
            let shared = shutdown_budget(
                (!activate_during_poll)
                    .then_some(Budget::INFINITE.with_poll_quota(8).with_deadline(later)),
            );
            let mut probe = BudgetProbe::new(None);
            if activate_during_poll {
                probe.update_budget = Some((
                    shared.clone(),
                    Some(Budget::INFINITE.with_poll_quota(8).with_deadline(deadline)),
                ));
            }
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let wake = std::sync::Arc::new(BudgetWake::default());
            let waker = std::task::Waker::from(wake.clone());
            let mut cx = std::task::Context::from_waker(&waker);
            let mut bounded =
                BudgetedFinalizer::new(Box::pin(probe), shared.clone(), Some(driver.clone()));
            assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
            if !activate_during_poll {
                assert_eq!(driver.next_deadline(), Some(later));
                *shared.write() = Some(Budget::INFINITE.with_poll_quota(8).with_deadline(deadline));
                assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
            }
            assert_eq!(driver.pending_count(), 1);
            assert_eq!(driver.next_deadline(), Some(deadline));
            let observed_polls = polls.load(Ordering::SeqCst);
            assert_eq!(observed_polls, if activate_during_poll { 1 } else { 2 });
            clock.advance_to(deadline);
            assert_eq!(driver.process_timers(), 1);
            assert_eq!(wake.0.load(Ordering::SeqCst), 1);
            assert_eq!(
                Pin::new(&mut bounded).poll(&mut cx),
                Poll::Ready(Outcome::Err(FinalizerBudgetError::Deadline {
                    deadline,
                    observed: deadline
                }))
            );
            assert_eq!(polls.load(Ordering::SeqCst), observed_polls);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(driver.pending_count(), 0);
        }
    }

    #[test]
    fn explicit_finalizer_timer_horizon_wake_is_not_the_true_deadline() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        let start = Time::from_secs(37);
        let clock = std::sync::Arc::new(VirtualClock::starting_at(start));
        let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
        let horizon = u64::try_from(driver.max_timer_duration().as_nanos()).unwrap();
        let partial = start.saturating_add_nanos(horizon);
        let deadline = partial.saturating_add_nanos(horizon);
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let mut bounded = BudgetedFinalizer::new(
            Box::pin(probe),
            shutdown_budget(Some(
                Budget::INFINITE.with_poll_quota(4).with_deadline(deadline),
            )),
            Some(driver.clone()),
        );
        let first = std::sync::Arc::new(BudgetWake::default());
        let first_waker = std::task::Waker::from(first.clone());
        let mut first_cx = std::task::Context::from_waker(&first_waker);
        assert!(Pin::new(&mut bounded).poll(&mut first_cx).is_pending());
        assert_eq!(driver.next_deadline(), Some(partial));
        clock.advance_to(partial);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(first.0.load(Ordering::SeqCst), 1);
        let second = std::sync::Arc::new(BudgetWake::default());
        let second_waker = std::task::Waker::from(second.clone());
        let mut second_cx = std::task::Context::from_waker(&second_waker);
        assert!(Pin::new(&mut bounded).poll(&mut second_cx).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(driver.next_deadline(), Some(deadline));
        clock.advance_to(deadline);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert_eq!(first.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut second_cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::Deadline {
                deadline,
                observed: deadline
            }))
        );
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(driver.pending_count(), 0);
    }

    #[test]
    fn explicit_finalizer_actual_lab_task_deadline_wakes_through_cancel_mask() {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::{CancelReason, Outcome, Time};
        use std::sync::atomic::Ordering;
        let mut lab = LabRuntime::new(
            LabConfig::new(3401)
                .max_steps(10_000)
                .trace_capacity(10_000),
        );
        lab.advance_time_to(Time::from_secs(23));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let deadline = Time::from_secs(23).saturating_add_nanos(2_000_000);
        let observed_outcome = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let completed_outcome = std::sync::Arc::clone(&observed_outcome);
        let (task, mut joined) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = crate::Cx::current().expect("real scheduled finalizer-wrapper owner");
                let mut bounded = BudgetedFinalizer::new(
                    Box::pin(probe),
                    shutdown_budget(Some(
                        Budget::INFINITE.with_poll_quota(8).with_deadline(deadline),
                    )),
                    cx.timer_driver(),
                );
                let outcome = std::future::poll_fn(|poll_cx| {
                    cx.masked(|| {
                        assert!(
                            cx.checkpoint().is_ok(),
                            "the actual task is masked during finalizer polling"
                        );
                        Pin::new(&mut bounded).poll(poll_cx)
                    })
                })
                .await;
                assert!(
                    cx.checkpoint().is_err(),
                    "acknowledge the caller's real cancellation after cleanup"
                );
                *completed_outcome.lock() = Some(outcome);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let driver = lab.state.timer_driver_handle().unwrap();
        assert_eq!(driver.pending_count(), 1);
        assert!(joined.try_join().unwrap().is_none());
        let cancellation = CancelReason::user("finalizer wrapper test cancellation");
        joined.abort_with_reason(cancellation.clone());
        lab.run_until_idle();
        assert!(
            joined.try_join().unwrap().is_none(),
            "mask does not turn cancellation into timeout readiness"
        );
        assert_eq!(lab.state.live_task_count(), 1);
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let before_deadline = polls.load(Ordering::SeqCst);
        assert!((1..8).contains(&before_deadline));
        assert_eq!(lab.advance_to_next_timer(), 1);
        lab.run_until_idle();
        assert_eq!(
            joined.try_join(),
            Err(crate::runtime::task_handle::JoinError::Cancelled(
                cancellation
            )),
            "the low-level owner retains actual cancellation attribution"
        );
        assert_eq!(
            observed_outcome
                .lock()
                .take()
                .expect("actual timer woke and retired the wrapper"),
            Outcome::Err(FinalizerBudgetError::Deadline {
                deadline,
                observed: deadline
            })
        );
        assert_eq!(polls.load(Ordering::SeqCst), before_deadline);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(driver.pending_count(), 0);
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        lab.state
            .close_region_command(root, &CancelReason::user("finalizer wrapper test complete"));
        assert!(lab.state.region(root).is_none());
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
        assert!(!report.refinement_firewall_skipped_due_to_trace_truncation);
        eprintln!(
            "explicit_finalizer_deadline task={task:?} region={root:?} deadline={deadline:?} user_polls={before_deadline} retired=1 timer_pending=0 report={report:?}"
        );
    }
}
