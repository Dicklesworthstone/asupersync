//! Owned, bounded orchestration of the existing authenticated repair cursor.

use super::{SymbolRepairClient, SymbolRepairCursor, SymbolRepairError, SymbolRepairProgress};
use crate::combinator::timeout::TimedResult;
use crate::cx::Cx;
use crate::distributed::anti_entropy::catalog::CatalogError;
use crate::distributed::symbol_service::{RemoteSymbolError, RemoteSymbolTransport};
use crate::remote::RemoteComputationClientError;
use crate::runtime::SpawnError;
use crate::sync::Notify;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelReason, Outcome, Time};
use parking_lot::Mutex;
use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

mod membership;
pub use membership::{SymbolRepairMembership, SymbolRepairMembershipReport, SymbolRepairMembershipStop};

/// Explicit finite work policy for one repair service.
///
/// A round starts with a fresh catalog cut and runs at most the configured
/// attempts and steps. Its timeout initiates cancellation and waits for actual
/// task retirement. Native remote drain policy still governs unreachable peers;
/// neither a timeout nor stopping this worker proves remote quiescence.
#[derive(Debug, Clone, Copy)]
pub struct SymbolRepairWorkerConfig {
    round_timeout: Duration,
    max_steps_per_attempt: usize,
    max_attempts: usize,
    retry_delay: Duration,
    interval: Option<Duration>,
    initial_repair: bool,
}

impl SymbolRepairWorkerConfig {
    /// One initial round, no periodic rounds, and no automatic retries.
    #[must_use]
    pub fn new(round_timeout: Duration, max_steps_per_attempt: usize) -> Self {
        Self {
            round_timeout,
            max_steps_per_attempt,
            max_attempts: 1,
            retry_delay: Duration::from_millis(100),
            interval: None,
            initial_repair: true,
        }
    }

    /// Enable fixed-delay periodic repair. Missed intervals never accumulate.
    #[must_use]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = Some(interval);
        self
    }

    /// Whether first polling the worker schedules a round immediately.
    #[must_use]
    pub fn with_initial_repair(mut self, enabled: bool) -> Self {
        self.initial_repair = enabled;
        self
    }

    /// Retry failed metadata reads, transient value transport failures, or a
    /// changed catalog with a new cursor. Already verified immutable puts
    /// survive; no effect rollback is implied.
    #[must_use]
    pub fn with_retry_policy(mut self, max_attempts: usize, delay: Duration) -> Self {
        self.max_attempts = max_attempts;
        self.retry_delay = delay;
        self
    }

    fn validate(self) -> Result<(), SymbolRepairWorkerError> {
        if !finite(self.round_timeout)
            || self.max_steps_per_attempt == 0
            || self.max_attempts == 0
            || self
                .max_steps_per_attempt
                .checked_mul(self.max_attempts)
                .is_none()
            || (self.max_attempts > 1 && !finite(self.retry_delay))
            || self.interval.is_some_and(|interval| !finite(interval))
        {
            return Err(SymbolRepairWorkerError::Configuration);
        }
        Ok(())
    }
}

fn finite(duration: Duration) -> bool {
    !duration.is_zero() && duration.as_nanos() <= u128::from(u64::MAX)
}

fn after(now: Time, duration: Duration) -> Result<Time, SymbolRepairWorkerError> {
    let nanos =
        u64::try_from(duration.as_nanos()).map_err(|_| SymbolRepairWorkerError::ClockExhausted)?;
    now.as_nanos()
        .checked_add(nanos)
        .filter(|deadline| *deadline > now.as_nanos())
        .map(Time::from_nanos)
        .ok_or(SymbolRepairWorkerError::ClockExhausted)
}

/// A worker-level refusal; individual round failures remain in their reports.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SymbolRepairWorkerError {
    /// All configured counts and durations must admit finite positive work.
    #[error("invalid symbol repair worker policy")]
    Configuration,
    /// The source and original origin must match the provisioned symbol route.
    #[error("symbol repair worker transport authority differs from its client")]
    Authority,
    /// Periodic, retry and cancellation deadlines need the caller's timer.
    #[error("symbol repair worker requires a context timer driver")]
    TimerRequired,
    /// A future deadline is no longer representable on the supplied clock.
    #[error("symbol repair worker clock has no remaining interval")]
    ClockExhausted,
    /// No representable next round identity remains.
    #[error("symbol repair worker round sequence exhausted")]
    SequenceExhausted,
    /// The caller's existing remote capability refused service startup.
    #[error(transparent)]
    Repair(#[from] SymbolRepairError),
}

/// A finished round's actual operation failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SymbolRepairRoundError {
    /// The existing authenticated repair workflow refused or failed.
    #[error(transparent)]
    Repair(#[from] SymbolRepairError),
    /// The finite cursor-step allowance ended before convergence.
    #[error("symbol repair round exhausted its cursor-step allowance")]
    StepLimit,
    /// The owned round task could not be submitted.
    #[error(transparent)]
    Spawn(#[from] SpawnError),
    /// A retry deadline cannot be represented on the current clock.
    #[error("symbol repair retry clock has no remaining interval")]
    ClockExhausted,
}

/// Why ordinary round execution ended; separate from its retained outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymbolRepairRoundTrigger {
    /// The operation returned before its deadline and owner cancellation.
    Completed,
    /// The finite round deadline was reached, including during drain.
    Deadline,
    /// The service's owning task requested cancellation.
    ParentCancelled(CancelReason),
}

/// One bounded latest-round receipt. A failed round may have retained verified
/// batches; inspect `progress`, and never infer rollback from its outcome.
#[derive(Debug)]
pub struct SymbolRepairRoundReport {
    /// Monotone identity within this worker instance, starting at one.
    pub sequence: u64,
    /// Number of fresh cursors attempted, including a failed start request.
    pub attempts: usize,
    /// Number of cursor-step calls attempted across all attempts.
    pub steps: usize,
    /// Final progress of the latest successfully created cursor, including
    /// puts before a later error or cancellation. Earlier attempts' immutable
    /// effects remain retained but are not added to this cursor's counters.
    pub progress: Option<SymbolRepairProgress>,
    /// Deadline/cancellation cannot be mistaken for authorized round success.
    pub trigger: SymbolRepairRoundTrigger,
    /// Actual operation result, panic or cancellation after task retirement.
    pub outcome: Outcome<(), SymbolRepairRoundError>,
}

impl SymbolRepairRoundReport {
    /// Whether the authenticated source cut converged within this round.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.trigger == SymbolRepairRoundTrigger::Completed
            && matches!(self.outcome, Outcome::Ok(()))
            && self.progress.is_some_and(|progress| progress.complete)
    }
}

/// Lifecycle of the service, independent of the success of individual rounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymbolRepairWorkerStatus {
    /// Constructed, without any task or network work started.
    Prepared,
    /// Waiting for a trigger or the next fixed-delay interval.
    Waiting,
    /// One round is executing; at most one further trigger is retained.
    Repairing,
    /// Admission is sealed; an already running round still owns its work.
    Stopping,
    /// An explicit graceful stop completed.
    Stopped,
    /// Caller cancellation was observed and the current round retired.
    Cancelled,
    /// Worker setup, clock or sequence failure stopped the service.
    Failed,
    /// The worker/future was dropped; no synchronous drain is claimed.
    Dropped,
}

impl SymbolRepairWorkerStatus {
    /// Whether no further round can be admitted.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Stopped | Self::Cancelled | Self::Failed | Self::Dropped
        )
    }
}

/// Bounded observation: only the latest report is retained by the service.
/// Copies held by observers are their own storage, not an internal history.
#[derive(Debug, Clone)]
pub struct SymbolRepairWorkerSnapshot {
    /// Current service lifecycle.
    pub status: SymbolRepairWorkerStatus,
    /// One coalesced request is waiting; never an unbounded request queue.
    pub pending: bool,
    /// Rounds whose task submission has begun.
    pub rounds_started: u64,
    /// Rounds with a terminal report, successful or otherwise.
    pub rounds_finished: u64,
    /// Finished rounds whose `is_success()` predicate is true.
    pub successful_rounds: u64,
    /// Latest terminal report, independent of the service's lifecycle status.
    pub last_round: Option<Arc<SymbolRepairRoundReport>>,
}

struct State {
    snapshot: SymbolRepairWorkerSnapshot,
    stop: bool,
}

struct Shared {
    state: Mutex<State>,
    changed: Notify,
}

impl Shared {
    fn notify(&self) {
        // A hostile observation waker cannot strand already-completed teardown.
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.changed.notify_waiters();
        })) {
            // Release ordinary panic captures outside the state lock. Only a
            // payload whose own destructor panics cannot safely be dropped.
            if let Err(nested) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
            {
                std::mem::forget(nested);
            }
        }
    }
}

/// Admission outcome for a repair hint, never a completed-repair receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolRepairRequest {
    /// One future round was scheduled.
    Scheduled,
    /// An existing pending round already covers the hint.
    Coalesced,
    /// Stop or terminal ownership has sealed further requests.
    Closed,
}

/// Cloneable trigger and observation access.
///
/// This retains no Cx, transport or
/// runtime task. Dropping all handles does not detach the worker: its calling
/// task/region remains its owner. Use `stop` and await `run` for graceful drain.
#[derive(Clone)]
pub struct SymbolRepairWorkerHandle {
    shared: Arc<Shared>,
}

impl fmt::Debug for SymbolRepairWorkerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot().fmt(f)
    }
}

impl SymbolRepairWorkerHandle {
    /// Request repair after a local update or a partition-heal observation.
    /// Hints cannot change routes, origins, credentials or grants. No network
    /// work or user callbacks run while the admission lock is held.
    pub fn request(&self) -> SymbolRepairRequest {
        let result = {
            let mut state = self.shared.state.lock();
            if state.stop || state.snapshot.status.is_terminal() {
                return SymbolRepairRequest::Closed;
            }
            if state.snapshot.pending {
                SymbolRepairRequest::Coalesced
            } else {
                state.snapshot.pending = true;
                SymbolRepairRequest::Scheduled
            }
        };
        if result == SymbolRepairRequest::Scheduled {
            self.shared.notify();
        }
        result
    }

    /// Seal admission and discard its single pending hint. An active round
    /// finishes or reaches its finite cancellation deadline, then drains.
    pub fn stop(&self) {
        {
            let mut state = self.shared.state.lock();
            state.stop = true;
            state.snapshot.pending = false;
            if !state.snapshot.status.is_terminal() {
                state.snapshot.status = SymbolRepairWorkerStatus::Stopping;
            }
        }
        self.shared.notify();
    }

    /// Observe the latest bounded receipt without driving any work.
    #[must_use]
    pub fn snapshot(&self) -> SymbolRepairWorkerSnapshot {
        self.shared.state.lock().snapshot.clone()
    }

    /// Wait for a finished round newer than `after`, or terminal service state.
    /// Intermediate rounds may coalesce; inspect `rounds_finished` and the last
    /// report's sequence. The caller composes its own cancellation/deadline.
    pub async fn changed(&self, after: u64) -> SymbolRepairWorkerSnapshot {
        self.shared
            .changed
            .wait_until(|| {
                let state = self.shared.state.lock();
                state.snapshot.rounds_finished > after || state.snapshot.status.is_terminal()
            })
            .await;
        self.snapshot()
    }
}

/// Terminal service result plus its retained round history summary.
/// `Outcome::Ok` means graceful stop, not that every repair round succeeded.
#[derive(Debug)]
pub struct SymbolRepairWorkerReport {
    /// Graceful stop, owner cancellation, or a worker-level refusal.
    pub outcome: Outcome<(), SymbolRepairWorkerError>,
    /// Final bounded observation, including the latest actual round outcome.
    pub snapshot: SymbolRepairWorkerSnapshot,
}

/// Automatic one-source repair using existing authenticated metadata and value
/// transports.
///
/// Poll `run` inside an existing owned task, for example through
/// `Cx::spawn`. No hidden task, alternate transport, source election, or raw
/// SWIM authority is created. External membership observations may request a
/// repair, but all ordinary origin/source/grant checks still govern every call.
///
/// One round runs at a time, with one coalesced pending hint and one retained
/// report. Periodic repair is fixed-delay after the previous round; slow peers
/// cannot accumulate missed ticks. Explicit triggers do not bypass retry delay
/// or extend the active round's timeout. Source catalogs must still be explicitly
/// captured and published by their owners.
///
/// Owner cancellation reaches the actual round task and its parked native RPCs;
/// `run` waits for that task's retirement. Dropping the `run` future requests
/// cancellation via the existing scope timeout owner; runtime regions retain
/// admitted descendants. Drop is not a synchronous drain receipt. A custom
/// nonterminating RemoteRuntime or blocking poll can delay cleanup indefinitely.
pub struct SymbolRepairWorker {
    client: SymbolRepairClient,
    symbols: RemoteSymbolTransport,
    config: SymbolRepairWorkerConfig,
    shared: Arc<Shared>,
    finished: bool,
}

impl fmt::Debug for SymbolRepairWorker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolRepairWorker")
            .field("client", &self.client)
            .field("config", &self.config)
            .field("snapshot", &self.handle().snapshot())
            .finish_non_exhaustive()
    }
}

impl SymbolRepairWorker {
    /// Validate finite policy and matching transport authority without I/O.
    pub fn new(
        client: SymbolRepairClient,
        symbols: RemoteSymbolTransport,
        config: SymbolRepairWorkerConfig,
    ) -> Result<Self, SymbolRepairWorkerError> {
        config.validate()?;
        if symbols
            .repair_binding(
                &client.origin,
                client.source.as_str(),
                client.limits.max_batch_bytes,
            )
            .is_none()
        {
            return Err(SymbolRepairWorkerError::Authority);
        }
        Ok(Self {
            client,
            symbols,
            config,
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    snapshot: SymbolRepairWorkerSnapshot {
                        status: SymbolRepairWorkerStatus::Prepared,
                        pending: config.initial_repair,
                        rounds_started: 0,
                        rounds_finished: 0,
                        successful_rounds: 0,
                        last_round: None,
                    },
                    stop: false,
                }),
                changed: Notify::new(),
            }),
            finished: false,
        })
    }

    /// Obtain control access before handing this worker to its owning task.
    #[must_use]
    pub fn handle(&self) -> SymbolRepairWorkerHandle {
        SymbolRepairWorkerHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Drive until explicit stop, caller cancellation, or worker-level failure.
    /// Individual failed rounds remain observable and wait for the next trigger.
    pub async fn run(mut self, cx: &Cx) -> SymbolRepairWorkerReport {
        let outcome = self.run_inner(cx).await;
        {
            let mut state = self.shared.state.lock();
            state.stop = true;
            state.snapshot.pending = false;
            state.snapshot.status = match &outcome {
                Outcome::Ok(()) => SymbolRepairWorkerStatus::Stopped,
                Outcome::Cancelled(_) => SymbolRepairWorkerStatus::Cancelled,
                Outcome::Err(_) | Outcome::Panicked(_) => SymbolRepairWorkerStatus::Failed,
            };
        }
        self.finished = true;
        self.shared.notify();
        SymbolRepairWorkerReport {
            outcome,
            snapshot: self.handle().snapshot(),
        }
    }

    async fn run_inner(&self, cx: &Cx) -> Outcome<(), SymbolRepairWorkerError> {
        if cx.checkpoint().is_err() {
            return cancelled(cx);
        }
        if self.shared.state.lock().stop {
            return Outcome::Ok(());
        }
        if let Err(error) = self.client.check_owner(cx) {
            return Outcome::Err(error.into());
        }
        let Some(clock) = cx.timer_driver() else {
            return Outcome::Err(SymbolRepairWorkerError::TimerRequired);
        };
        let mut next = match self.next_period(&clock) {
            Ok(next) => next,
            Err(error) => return Outcome::Err(error),
        };
        loop {
            {
                let mut state = self.shared.state.lock();
                if !state.stop {
                    state.snapshot.status = SymbolRepairWorkerStatus::Waiting;
                }
            }
            match self.wait(cx, &clock, next).await {
                Wake::Stop => return Outcome::Ok(()),
                Wake::Cancelled => return cancelled(cx),
                Wake::Repair => {}
            }
            let sequence = {
                let mut state = self.shared.state.lock();
                // stop can race the trigger's wake; do not publish another task.
                if state.stop {
                    return Outcome::Ok(());
                }
                let Some(sequence) = state.snapshot.rounds_started.checked_add(1) else {
                    return Outcome::Err(SymbolRepairWorkerError::SequenceExhausted);
                };
                state.snapshot.rounds_started = sequence;
                state.snapshot.status = SymbolRepairWorkerStatus::Repairing;
                sequence
            };
            let deadline = match after(clock.now(), self.config.round_timeout) {
                Ok(deadline) => deadline,
                Err(error) => return Outcome::Err(error),
            };
            let progress = Arc::new(Mutex::new(RoundProgress::default()));
            let operation_progress = Arc::clone(&progress);
            let client = self.client.clone();
            let symbols = self.symbols.clone();
            let config = self.config;
            let operation_clock = clock.clone();
            let remaining =
                Duration::from_nanos(deadline.as_nanos().saturating_sub(clock.now().as_nanos()));
            let outcome = if remaining.is_zero() {
                Outcome::Cancelled(CancelReason::timeout())
            } else {
                // Scope::timeout samples its relative timer when first polled.
                // The absolute child budget also fixes the original ceiling
                // across preemption and propagates it to every nested RPC.
                match cx
                    .scope_with_budget(cx.budget().with_deadline(deadline))
                    .timeout(cx, remaining, move |body| async move {
                        execute_round(
                            &body,
                            &client,
                            &symbols,
                            config,
                            &operation_clock,
                            &operation_progress,
                        )
                        .await
                    })
                    .await
                {
                    Ok(TimedResult::Completed(outcome)) => outcome,
                    Ok(TimedResult::TimedOut(_)) => Outcome::Cancelled(CancelReason::timeout()),
                    Err(error) => Outcome::Err(SymbolRepairRoundError::Spawn(error)),
                }
            };
            let trigger = if cx.is_cancel_requested() {
                SymbolRepairRoundTrigger::ParentCancelled(reason(cx))
            } else if clock.now() >= deadline {
                SymbolRepairRoundTrigger::Deadline
            } else {
                SymbolRepairRoundTrigger::Completed
            };
            let observed = *progress.lock();
            let report = Arc::new(SymbolRepairRoundReport {
                sequence,
                attempts: observed.attempts,
                steps: observed.steps,
                progress: observed.progress,
                trigger,
                outcome,
            });
            let retired = {
                let mut state = self.shared.state.lock();
                state.snapshot.rounds_finished = sequence;
                if report.is_success() {
                    state.snapshot.successful_rounds += 1;
                }
                state.snapshot.last_round.replace(report)
            };
            // Error payload destruction must not run under the admission lock.
            drop(retired);
            self.shared.notify();
            if cx.is_cancel_requested() {
                return cancelled(cx);
            }
            if self.shared.state.lock().stop {
                return Outcome::Ok(());
            }
            next = match self.next_period(&clock) {
                Ok(next) => next,
                Err(error) => return Outcome::Err(error),
            };
        }
    }

    fn next_period(
        &self,
        clock: &TimerDriverHandle,
    ) -> Result<Option<Time>, SymbolRepairWorkerError> {
        self.config
            .interval
            .map(|interval| after(clock.now(), interval))
            .transpose()
    }

    async fn wait(&self, cx: &Cx, clock: &TimerDriverHandle, next: Option<Time>) -> Wake {
        let mut changed = std::pin::pin!(self.shared.changed.wait_until(|| {
            let state = self.shared.state.lock();
            state.stop || state.snapshot.pending
        }));
        let mut cancelled = std::pin::pin!(cx.cancelled());
        let mut timer =
            std::pin::pin!(next.map(|deadline| Sleep::with_timer_driver(deadline, clock.clone())));
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() {
                return Poll::Ready(Wake::Cancelled);
            }
            let _ = changed.as_mut().poll(task);
            {
                let mut state = self.shared.state.lock();
                if state.stop {
                    return Poll::Ready(Wake::Stop);
                }
                if state.snapshot.pending {
                    state.snapshot.pending = false;
                    return Poll::Ready(Wake::Repair);
                }
            }
            if timer
                .as_mut()
                .as_pin_mut()
                .is_some_and(|timer| timer.poll_deadline(task).is_ready())
            {
                return Poll::Ready(Wake::Repair);
            }
            Poll::Pending
        })
        .await
    }
}

impl Drop for SymbolRepairWorker {
    fn drop(&mut self) {
        if !self.finished {
            {
                let mut state = self.shared.state.lock();
                state.stop = true;
                state.snapshot.pending = false;
                state.snapshot.status = SymbolRepairWorkerStatus::Dropped;
            }
            self.shared.notify();
        }
    }
}

enum Wake {
    Repair,
    Stop,
    Cancelled,
}

fn reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason()
        .unwrap_or_else(CancelReason::parent_cancelled)
}

fn cancelled(cx: &Cx) -> Outcome<(), SymbolRepairWorkerError> {
    let _ = cx.checkpoint();
    Outcome::Cancelled(reason(cx))
}

#[derive(Default, Clone, Copy)]
struct RoundProgress {
    attempts: usize,
    steps: usize,
    progress: Option<SymbolRepairProgress>,
}

struct AttemptCursor {
    cursor: SymbolRepairCursor,
    observed: Arc<Mutex<RoundProgress>>,
}

impl Drop for AttemptCursor {
    fn drop(&mut self) {
        // The timeout owner joins the task before reading this observation.
        // Preserve puts made before a later await, cancellation or error.
        self.observed.lock().progress = Some(self.cursor.progress());
    }
}

async fn execute_round(
    cx: &Cx,
    client: &SymbolRepairClient,
    symbols: &RemoteSymbolTransport,
    config: SymbolRepairWorkerConfig,
    clock: &TimerDriverHandle,
    observed: &Arc<Mutex<RoundProgress>>,
) -> Result<(), SymbolRepairRoundError> {
    for attempt in 1..=config.max_attempts {
        {
            let mut progress = observed.lock();
            progress.attempts = attempt;
        }
        let result =
            execute_attempt(cx, client, symbols, config.max_steps_per_attempt, observed).await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) if attempt < config.max_attempts && retryable(&error) => {
                if cx.checkpoint().is_err() {
                    return Err(SymbolRepairError::Cancelled.into());
                }
                let deadline = after(clock.now(), config.retry_delay)
                    .map_err(|_| SymbolRepairRoundError::ClockExhausted)?;
                Sleep::with_timer_driver(deadline, clock.clone()).await;
                if cx.checkpoint().is_err() {
                    return Err(SymbolRepairError::Cancelled.into());
                }
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("positive validated attempt count returns its final result")
}

async fn execute_attempt(
    cx: &Cx,
    client: &SymbolRepairClient,
    symbols: &RemoteSymbolTransport,
    max_steps: usize,
    observed: &Arc<Mutex<RoundProgress>>,
) -> Result<(), SymbolRepairRoundError> {
    let cursor = client.start(cx).await?;
    let mut owned = AttemptCursor {
        cursor,
        observed: Arc::clone(observed),
    };
    observed.lock().progress = Some(owned.cursor.progress());
    if owned.cursor.progress().complete {
        return Ok(());
    }
    for _ in 0..max_steps {
        observed.lock().steps += 1; // validated max_steps * max_attempts cannot overflow
        let result = client.step(cx, symbols, &mut owned.cursor).await;
        observed.lock().progress = Some(owned.cursor.progress());
        if result?.complete {
            return Ok(());
        }
        crate::runtime::yield_now().await;
    }
    Err(SymbolRepairRoundError::StepLimit)
}

fn retryable(error: &SymbolRepairRoundError) -> bool {
    matches!(
        error,
        SymbolRepairRoundError::Repair(
            SymbolRepairError::Remote
                | SymbolRepairError::Catalog(CatalogError::SnapshotChanged)
                | SymbolRepairError::Fetch(
                    RemoteSymbolError::Admission
                        | RemoteSymbolError::Client(
                            RemoteComputationClientError::Connect { .. }
                                | RemoteComputationClientError::AttemptTimeout { .. }
                                | RemoteComputationClientError::AmbiguousExchange { .. }
                        )
                )
        )
    )
}

#[cfg(test)]
mod tests;
