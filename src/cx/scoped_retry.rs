//! Retry strategies with a fully owned and drained subtree per attempt.
//!
//! Builds on scoped fallback ownership for the core design's sections 6 and 12
//! (asupersync-bi2462, asupersync-16rul), without changing legacy retry behavior.

use super::scoped_first_ok::{
    ScopedFirstOkAttempt, ScopedFirstOkClose, ScopedFirstOkError, ScopedFirstOkStop,
    ScopedFirstOkTask,
};
use super::{ChildRegionError, Cx, cap};
use crate::combinator::retry::{
    AdmittedRetryToken, RetryBudget, RetryPolicy, RetryPredicate, calculate_delay,
};
use crate::runtime::state::SpawnError;
use crate::time::Sleep;
use crate::types::{CancelReason, RegionId};
use crate::util::det_rng::DetRng;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

/// Why a scoped retry stopped admitting attempts.
///
/// Selection is independent of the actual task and cleanup receipts. A chosen
/// success remains selected if its cleanup fails or its owner is cancelled
/// during cleanup; always inspect the corresponding close receipt too.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedRetryStop {
    /// This attempt returned a typed success before owner cancellation won.
    Succeeded {
        /// One-based attempt number.
        attempt: u32,
    },
    /// Every allowed attempt returned a typed error and closed cleanly.
    Exhausted,
    /// The predicate declined to retry a typed error after its subtree closed.
    PredicateRejected {
        /// One-based attempt number whose error the predicate examined.
        attempt: u32,
    },
    /// The shared retry budget could not reserve another attempt after a clean
    /// typed failure and predicate acceptance. That failure remains in the report.
    BudgetExhausted {
        /// One-based number of the completed attempt that could not be retried.
        attempt: u32,
    },
    /// The explicit owner requested cancellation before a success was selected.
    /// The task receipt can still contain an acknowledged late value or error.
    Cancelled(CancelReason),
    /// Submission or strict private-region admission refused this attempt.
    NotAdmitted {
        /// One-based attempt number.
        attempt: u32,
    },
    /// The task did not join normally, for example because it panicked.
    TaskFailed {
        /// One-based attempt number; its receipt retains the actual join error.
        attempt: u32,
    },
    /// A typed failure's subtree failed cleanup or could not certify quiescence.
    /// The predicate was not consulted and no subsequent attempt was started.
    CleanupFailed {
        /// One-based attempt number.
        attempt: u32,
    },
}

/// What an attempt actually returned, separately from retry selection.
pub type ScopedRetryTask<T, E> = ScopedFirstOkTask<T, E>;

/// The actual close receipt for an attempt's entire private subtree.
pub type ScopedRetryClose = ScopedFirstOkClose;

/// Independent task and cleanup receipts for one submitted retry attempt.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedRetryAttempt<T, E> {
    /// One-based attempt number. Receipts remain in attempt order.
    pub attempt: u32,
    /// The real result, including typed errors from earlier attempts.
    pub task: ScopedRetryTask<T, E>,
    /// The private region, if admission minted one.
    pub region_id: Option<RegionId>,
    /// Whole-subtree close, including descendant and finalizer failures.
    /// `None` means that no private region was published. An error does not
    /// certify quiescence, even if the task returned a useful value.
    pub close: Option<Result<ScopedRetryClose, ChildRegionError>>,
}

/// Selection plus every attempted operation's actual task and cleanup receipts.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect both retry selection and every cleanup receipt"]
pub struct ScopedRetryReport<T, E> {
    /// The condition that stopped retrying.
    pub stop: ScopedRetryStop,
    /// Submitted attempts, including a refused submission. A cancellation
    /// during backoff does not create a receipt for an unsubmitted attempt.
    pub attempts: Vec<ScopedRetryAttempt<T, E>>,
    /// Sum of scheduled backoff durations, saturating on overflow. This
    /// includes a backoff interrupted by cancellation, excludes operation and
    /// cleanup time, and is not a measurement of elapsed time.
    pub total_delay: Duration,
    /// Strongest explicit owner cancellation observed when assembling this
    /// report, including a request that arrived during unconditional cleanup.
    /// This does not replace an already-selected success or its actual value.
    pub owner_cancellation: Option<CancelReason>,
}

/// Refusal before any attempt is submitted to the owner's runtime.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedRetryError {
    /// Backoff or shared-budget accounting requires an authorized timer that
    /// the explicit owner does not provide.
    TimerUnavailable,
    /// Jitter can affect a delayed retry but the owner's entropy is restricted.
    EntropyUnavailable,
    /// The explicit context has no usable spawn gateway.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedRetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimerUnavailable => {
                f.write_str("scoped retry backoff or budget requires an authorized timer driver")
            }
            Self::EntropyUnavailable => {
                f.write_str("scoped retry jitter requires entropy authority")
            }
            Self::Spawn(error) => write!(f, "scoped retry requires an owning runtime: {error}"),
        }
    }
}

impl std::error::Error for ScopedRetryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::TimerUnavailable | Self::EntropyUnavailable => None,
        }
    }
}

fn owner_cancel_reason<Caps>(owner: &Cx<Caps>) -> CancelReason {
    owner
        .cancel_reason()
        .unwrap_or_else(|| CancelReason::user("scoped retry owner cancelled"))
}

fn finished<Caps, T, E>(
    owner: &Cx<Caps>,
    stop: ScopedRetryStop,
    attempts: Vec<ScopedRetryAttempt<T, E>>,
    total_delay: Duration,
) -> ScopedRetryReport<T, E> {
    let mut owner_cancellation = match &stop {
        ScopedRetryStop::Cancelled(reason) => Some(reason.clone()),
        _ => None,
    };
    if owner.is_cancel_requested() {
        let reason = owner_cancel_reason(owner);
        if let Some(previous) = &mut owner_cancellation {
            previous.strengthen(&reason);
        } else {
            owner_cancellation = Some(reason);
        }
    }
    ScopedRetryReport {
        stop,
        attempts,
        total_delay,
        owner_cancellation,
    }
}

/// Recover the mutable factory only after its attempt's subtree has closed.
/// Keeping it in the owned task's output avoids shared mutable state and keeps
/// a factory invocation (including a synchronous panic) inside strict admission.
fn recover_factory<T, E, F>(
    attempt: u32,
    receipt: ScopedFirstOkAttempt<(T, F), (E, F)>,
) -> (ScopedRetryAttempt<T, E>, Option<F>) {
    let mut factory = None;
    let task = match receipt.task {
        ScopedFirstOkTask::NotStarted => ScopedRetryTask::NotStarted,
        ScopedFirstOkTask::SubmissionFailed(error) => ScopedRetryTask::SubmissionFailed(error),
        ScopedFirstOkTask::Joined(Ok(Ok((value, returned)))) => {
            factory = Some(returned);
            ScopedRetryTask::Joined(Ok(Ok(value)))
        }
        ScopedFirstOkTask::Joined(Ok(Err((error, returned)))) => {
            factory = Some(returned);
            ScopedRetryTask::Joined(Ok(Err(error)))
        }
        ScopedFirstOkTask::Joined(Err(error)) => ScopedRetryTask::Joined(Err(error)),
    };
    (
        ScopedRetryAttempt {
            attempt,
            task,
            region_id: receipt.region_id,
            close: receipt.close,
        },
        factory,
    )
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + cap::HasTime + cap::HasRandom + Send + Sync + 'static,
{
    /// Retries typed failures only after each attempt's entire subtree closes.
    ///
    /// The factory receives the actual admitted context and a one-based attempt
    /// number. Work spawned through that context belongs to the attempt's private
    /// region. After the body completes, the region is cancelled and drained,
    /// including descendants, pending admissions, obligations, and finalizers.
    /// Only a typed `Err` followed by clean subtree closure can reach the retry
    /// predicate. Cleanup failure, task panic, or admission refusal stops retrying.
    /// Success also waits for subtree cleanup, whose receipt remains independent.
    ///
    /// The `FnMut` factory moves into each admitted task and returns with its
    /// result, preserving its state across attempts without requiring `Clone` or
    /// `Sync`. Neither the factory nor retained `T` or `E` values may hold an
    /// obligation whose release is required to close their own attempt. Futures
    /// returned by the factory must own their state rather than borrow the factory.
    /// A factory panic is a task failure; a predicate panic propagates to the caller
    /// after the previous attempt has already closed.
    ///
    /// Backoff uses [`RetryPolicy`] and [`calculate_delay`], including exponential
    /// growth, the delay cap, and jitter. Like the existing retry state machine,
    /// a zero `max_attempts` is normalized to one. The first attempt has no delay.
    /// Subsequent delays start only after cleanup and predicate acceptance. Each
    /// jittered delay is seeded from this owner's entropy. Timers and entropy are
    /// never obtained from an ambient context or a wall-clock fallback. The loop
    /// yields at least every 64 retryable failures, even with immediate backoff.
    ///
    /// This first scoped API requires spawn, time, and random capability types.
    /// An immediate policy or a single attempt needs no installed timer or runtime
    /// entropy permission. A policy that can delay retries requires an authorized
    /// timer before its first attempt; jitter additionally requires runtime entropy
    /// permission. A zero initial delay or delay cap keeps every backoff immediate.
    /// The policy's attempt count bounds submissions. Use
    /// [`Cx::retry_scoped_with_budget`] to also share retry admission across calls.
    ///
    /// Cancellation observation is mask-agnostic and does not acknowledge the
    /// owner's request. No predicate or new attempt starts after cancellation is
    /// observed. Cancellation is checked again immediately after the predicate.
    /// A success selected before cleanup stays selected if the owner is cancelled
    /// while cleanup runs. `owner_cancellation` records the strongest owner reason
    /// seen at return; it does not claim that later strengthening was forwarded
    /// into an already-closing subtree. Acknowledged late task values are retained.
    ///
    /// The ownership and drop guarantees come from [`Cx::first_ok_scoped`]: strict
    /// private-region admission never invokes user code in a parent fallback, and
    /// dropping an active retry requests subtree close even before admission has
    /// published. The runtime remains the asynchronous cleanup owner. Backoff has
    /// no active attempt; dropping it removes the timer registration. Cooperative
    /// cleanup has no time bound and is never replaced by forced destruction.
    ///
    /// # Errors
    ///
    /// Missing required timer, entropy, or spawn authority refuses before user
    /// work. An already-cancelled owner starts no work and needs no authority.
    /// Later submission, admission, task, and cleanup failures remain in the
    /// report alongside earlier typed errors. Inspect close receipts even when
    /// `stop` says `Succeeded`.
    ///
    /// ```
    /// use asupersync::Cx;
    /// use asupersync::combinator::retry::{AlwaysRetry, RetryPolicy};
    /// use asupersync::cx::{ScopedRetryStop, ScopedRetryTask};
    ///
    /// async fn example(cx: &Cx) {
    ///     let mut calls = 0;
    ///     let report = cx.retry_scoped(RetryPolicy::immediate(3), AlwaysRetry,
    ///         move |_attempt_cx, attempt| {
    ///             calls += 1;
    ///             assert_eq!(calls, attempt);
    ///             async move {
    ///                 if attempt < 2 { Err("transient") } else { Ok(42_u32) }
    ///             }
    ///         }).await.expect("retry authority");
    ///     assert!(matches!(report.stop, ScopedRetryStop::Succeeded { attempt: 2 }));
    ///     assert!(matches!(report.attempts[0].task,
    ///         ScopedRetryTask::Joined(Ok(Err("transient")))));
    ///     assert!(matches!(report.attempts[1].task,
    ///         ScopedRetryTask::Joined(Ok(Ok(42)))));
    ///     assert!(report.attempts.iter().all(|attempt| {
    ///         let Some(Ok(close)) = &attempt.close else { return false };
    ///         close.descendant_panic.is_none()
    ///             && close.cleanup_outcome.as_ref().is_none_or(|outcome| outcome.is_ok())
    ///     }));
    /// }
    /// ```
    pub async fn retry_scoped<T, E, Pred, F, Fut>(
        &self,
        policy: RetryPolicy,
        predicate: Pred,
        factory: F,
    ) -> Result<ScopedRetryReport<T, E>, ScopedRetryError>
    where
        Pred: RetryPredicate<E> + Send,
        F: FnMut(Cx<Caps>, u32) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        self.retry_scoped_inner(policy, None, predicate, factory)
            .await
    }

    /// Retries owned attempts while sharing admission tokens with other callers.
    ///
    /// This has the same per-attempt ownership, predicate, jitter, cancellation,
    /// and receipt semantics as [`Cx::retry_scoped`]. The initial attempt is free.
    /// After a typed failure closes cleanly and the predicate accepts another
    /// attempt, one shared token is reserved before any backoff or fairness yield.
    /// If none is available, [`ScopedRetryStop::BudgetExhausted`] preserves the
    /// completed attempt's typed error without starting or scheduling another.
    ///
    /// A reservation is spent only when strict admission invokes the next user
    /// factory. Cancellation, drop, or admission refusal before that invocation
    /// returns it, including a request that publishes its region after the outer
    /// future was dropped. A pending runtime-owned request may return the token
    /// only when the runtime retires that request; dropping does not force cleanup.
    /// An invoked factory consumes its token even if it subsequently fails or panics.
    ///
    /// The budget requires an authorized explicit timer even with an immediate
    /// policy, so refill accounting never consults ambient time or a wall-clock
    /// fallback. Construct the bucket with a `now` from the same clock domain,
    /// then pass clones of one [`RetryBudget`] to every caller sharing the limit.
    /// The policy's attempt count still applies, and no token is reserved after
    /// its final permitted attempt or a declined predicate.
    ///
    /// # Errors
    ///
    /// Missing timer, required entropy, or spawn authority refuses before user
    /// work. An already-cancelled owner starts no work and needs no authority.
    /// Later failures remain in the report, exactly as with [`Cx::retry_scoped`].
    pub async fn retry_scoped_with_budget<T, E, Pred, F, Fut>(
        &self,
        policy: RetryPolicy,
        budget: RetryBudget,
        predicate: Pred,
        factory: F,
    ) -> Result<ScopedRetryReport<T, E>, ScopedRetryError>
    where
        Pred: RetryPredicate<E> + Send,
        F: FnMut(Cx<Caps>, u32) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        self.retry_scoped_inner(policy, Some(budget), predicate, factory)
            .await
    }

    async fn retry_scoped_inner<T, E, Pred, F, Fut>(
        &self,
        mut policy: RetryPolicy,
        budget: Option<RetryBudget>,
        predicate: Pred,
        factory: F,
    ) -> Result<ScopedRetryReport<T, E>, ScopedRetryError>
    where
        Pred: RetryPredicate<E> + Send,
        F: FnMut(Cx<Caps>, u32) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        let mut attempts = Vec::new();
        let mut total_delay = Duration::ZERO;
        if self.is_cancel_requested() {
            return Ok(finished(
                self,
                ScopedRetryStop::Cancelled(owner_cancel_reason(self)),
                attempts,
                total_delay,
            ));
        }
        policy.max_attempts = policy.max_attempts.max(1);
        let can_delay = policy.max_attempts > 1
            && !policy.initial_delay.is_zero()
            && !policy.max_delay.is_zero();
        let timer = if can_delay || budget.is_some() {
            Some(
                self.timer_driver()
                    .ok_or(ScopedRetryError::TimerUnavailable)?,
            )
        } else {
            None
        };
        let jittered = can_delay && policy.jitter > 0.0;
        if jittered && !self.runtime_mask.has(cap::CapMask::RANDOM) {
            return Err(ScopedRetryError::EntropyUnavailable);
        }
        if self.spawn_gateway_handle().is_none() {
            return Err(ScopedRetryError::Spawn(SpawnError::RuntimeUnavailable));
        }

        let mut factory = Some(factory);
        let mut reservation: Option<AdmittedRetryToken> = None;
        let mut attempt = 1_u32;
        loop {
            if self.is_cancel_requested() {
                return Ok(finished(
                    self,
                    ScopedRetryStop::Cancelled(owner_cancel_reason(self)),
                    attempts,
                    total_delay,
                ));
            }
            let mut attempt_factory = factory.take().expect("factory recovered after typed error");
            let token = reservation.take();
            let receipt = self
                .first_ok_scoped([move |body| async move {
                    if let Some(token) = token {
                        token.spend();
                    }
                    match attempt_factory(body, attempt).await {
                        Ok(value) => Ok((value, attempt_factory)),
                        Err(error) => Err((error, attempt_factory)),
                    }
                }])
                .await;
            let receipt = match receipt {
                Ok(receipt) => receipt,
                Err(ScopedFirstOkError::Spawn(error)) => {
                    attempts.push(ScopedRetryAttempt {
                        attempt,
                        task: ScopedRetryTask::SubmissionFailed(error),
                        region_id: None,
                        close: None,
                    });
                    return Ok(finished(
                        self,
                        ScopedRetryStop::NotAdmitted { attempt },
                        attempts,
                        total_delay,
                    ));
                }
            };
            if let Some(receipt) = receipt.attempts.into_iter().next() {
                let (receipt, returned_factory) = recover_factory(attempt, receipt);
                attempts.push(receipt);
                factory = returned_factory;
            }
            let stop = match receipt.stop {
                ScopedFirstOkStop::Succeeded { .. } => Some(ScopedRetryStop::Succeeded { attempt }),
                ScopedFirstOkStop::AllFailed => None,
                ScopedFirstOkStop::Cancelled(reason) => Some(ScopedRetryStop::Cancelled(reason)),
                ScopedFirstOkStop::NotAdmitted { .. } => {
                    Some(ScopedRetryStop::NotAdmitted { attempt })
                }
                ScopedFirstOkStop::TaskFailed { .. } => {
                    Some(ScopedRetryStop::TaskFailed { attempt })
                }
                ScopedFirstOkStop::CleanupFailed { .. } => {
                    Some(ScopedRetryStop::CleanupFailed { attempt })
                }
                ScopedFirstOkStop::Empty => unreachable!("one attempt factory was supplied"),
            };
            if let Some(stop) = stop {
                return Ok(finished(self, stop, attempts, total_delay));
            }
            if self.is_cancel_requested() {
                return Ok(finished(
                    self,
                    ScopedRetryStop::Cancelled(owner_cancel_reason(self)),
                    attempts,
                    total_delay,
                ));
            }
            if attempt == policy.max_attempts {
                return Ok(finished(
                    self,
                    ScopedRetryStop::Exhausted,
                    attempts,
                    total_delay,
                ));
            }
            let should_retry = match &attempts.last().expect("typed failure receipt").task {
                ScopedRetryTask::Joined(Ok(Err(error))) => predicate.should_retry(error, attempt),
                _ => unreachable!("only a clean typed error permits another attempt"),
            };
            // A user predicate may publish cancellation even when returning false.
            if self.is_cancel_requested() {
                return Ok(finished(
                    self,
                    ScopedRetryStop::Cancelled(owner_cancel_reason(self)),
                    attempts,
                    total_delay,
                ));
            }
            if !should_retry {
                return Ok(finished(
                    self,
                    ScopedRetryStop::PredicateRejected { attempt },
                    attempts,
                    total_delay,
                ));
            }
            if let Some(budget) = &budget {
                let now = timer
                    .as_ref()
                    .expect("shared budget passed timer preflight")
                    .now();
                let Some(token) = budget.reserve(now) else {
                    return Ok(finished(
                        self,
                        ScopedRetryStop::BudgetExhausted { attempt },
                        attempts,
                        total_delay,
                    ));
                };
                reservation = Some(token);
            }
            if attempt.is_multiple_of(64) {
                crate::runtime::yield_now().await;
                if self.is_cancel_requested() {
                    return Ok(finished(
                        self,
                        ScopedRetryStop::Cancelled(owner_cancel_reason(self)),
                        attempts,
                        total_delay,
                    ));
                }
            }
            let mut rng = jittered.then(|| DetRng::new(self.random_u64()));
            let delay = calculate_delay(&policy, attempt, rng.as_mut());
            // Entropy providers are callbacks too. Recheck before arming a timer.
            if self.is_cancel_requested() {
                return Ok(finished(
                    self,
                    ScopedRetryStop::Cancelled(owner_cancel_reason(self)),
                    attempts,
                    total_delay,
                ));
            }
            total_delay = total_delay.saturating_add(delay);
            if !delay.is_zero() {
                let timer = timer
                    .as_ref()
                    .expect("nonzero backoff passed timer preflight");
                let deadline = timer.now() + delay;
                let elapsed = {
                    let mut cancelled = std::pin::pin!(self.cancelled());
                    let mut sleep =
                        std::pin::pin!(Sleep::with_timer_driver(deadline, timer.clone()));
                    poll_fn(|task| {
                        if cancelled.as_mut().poll(task).is_ready() {
                            return Poll::Ready(false);
                        }
                        if timer.now() >= deadline {
                            return Poll::Ready(true);
                        }
                        if sleep.as_mut().poll_deadline(task).is_ready() {
                            // Coalesced timer wakes can precede the exact deadline.
                            sleep.as_mut().get_mut().reset(deadline);
                            task.waker().wake_by_ref();
                        }
                        Poll::Pending
                    })
                    .await
                };
                if !elapsed {
                    return Ok(finished(
                        self,
                        ScopedRetryStop::Cancelled(owner_cancel_reason(self)),
                        attempts,
                        total_delay,
                    ));
                }
            }
            attempt += 1;
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_retry_inline_tests.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_retry_native_tests.rs"]
mod native_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_retry_budget_tests.rs"]
mod budget_tests;
