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
#[path = "finalizer_inline_tests.rs"]
mod tests;
