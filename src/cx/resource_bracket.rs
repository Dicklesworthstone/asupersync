//! Runtime-owned acquire/use/drain/release, including externally-woken cleanup.
//!
//! [`Cx::spawn_bracket`] admits a controller before acquiring anything. Acquisition
//! and use execute in one child region; release runs on the controller only after
//! that region is quiescent. The resource is borrowed by use, not cloned or moved
//! away. A borrowing join can be dropped and resumed; dropping the handle requests
//! cancellation without trying to poll asynchronous cleanup from `Drop`.
//!
//! This is additive to `combinator::bracket`, whose synchronous drop contract is
//! unchanged. It is not a general finalizer-registration API or a durability
//! protocol. Runtime hard-abort/process exit can still prevent release. All polls,
//! callbacks and destructors must return, and child/finalizer/cleanup work must
//! make progress. A poll-count mask is not a wall-clock completion guarantee.

use super::{CancelWakerToken, ChildRegionError, ChildRegionSpec, Cx};
use crate::record::task::TaskOutcome;
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::types::{Budget, CancelReason, Outcome, PanicPayload, RegionId, TaskId};
use parking_lot::Mutex;
use std::any::Any;
use std::fmt;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

/// The use future may borrow the single resource, but its output must be owned.
pub type BracketUseFuture<'a, T, E> =
    Pin<Box<dyn Future<Output = Outcome<T, E>> + Send + 'a>>;

/// Explicit region and cancellation policy; parent budgets are never relaxed.
#[derive(Debug, Clone)]
pub struct BracketConfig {
    /// Region owning acquisition, use, and everything spawned through their Cx.
    pub region: ChildRegionSpec,
    /// Budget passed to the existing region cancellation/drain protocol.
    pub shutdown_budget: Budget,
    /// Maximum release polls run with cancellation masked. Later polls continue
    /// unmasked; exhaustion never silently drops an unfinished release future.
    /// With a nonzero allowance, release construction and retirement are also
    /// masked. This bounds masked polls, not callback duration or total cleanup.
    pub release_masked_polls: u32,
}

impl BracketConfig {
    /// Inherit the region envelope and require an explicit release-mask allowance.
    #[must_use]
    pub const fn new(release_masked_polls: u32) -> Self {
        Self {
            region: ChildRegionSpec::inherit(),
            shutdown_budget: Budget::INFINITE,
            release_masked_polls,
        }
    }
}

/// Actual phase result and, independently, a panic while retiring its future.
/// A returned value is not erased just because the future's destructor panicked.
#[derive(Debug)]
pub struct BracketPhase<T, E> {
    /// Factory/poll panic is `Panicked`; explicit user outcomes remain exact.
    pub outcome: Outcome<T, E>,
    /// A destructor panic after polling, including after a value was returned.
    pub retirement_panic: Option<PanicPayload>,
}

impl<T, E> BracketPhase<T, E> {
    /// True only for an ordinary successful return and successful retirement.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.outcome.is_ok() && self.retirement_panic.is_none()
    }
}

/// Separate evidence of use-subtree quiescence and its finalizer outcome.
#[derive(Debug, Clone)]
pub struct BracketRegionOutcome {
    /// Aggregate region outcome; ordinary close may record shutdown cancellation.
    pub outcome: TaskOutcome,
    /// Explicit finalizer/cleanup outcome, when present.
    pub cleanup_outcome: Option<TaskOutcome>,
}

/// Infrastructure refusal, never substituted for a user's typed phase error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BracketInfrastructureError {
    /// No body or acquisition was submitted.
    #[error("bracket region admission failed: {0}")]
    Region(#[source] ChildRegionError),
    /// Child region exists, but submission of its body failed.
    #[error("bracket body submission failed: {0:?}")]
    Spawn(SpawnError),
    /// Region cancellation could not be enqueued; task abort is still attempted.
    #[error("bracket region cancellation failed: {0}")]
    Cancellation(#[source] ChildRegionError),
}

/// Retained lifecycle evidence. Inspect all phases, not merely the join result.
#[derive(Debug)]
#[must_use = "inspect work, region closure, release, and any unreleased resource"]
pub struct BracketReport<R, T, E, C> {
    /// Child region, absent when admission failed.
    pub region: Option<RegionId>,
    /// Successful acquisition carries unit: its resource has a separate owner.
    pub acquisition: Option<BracketPhase<(), E>>,
    /// Use-phase outcome, including cancellation that skips its factory.
    /// None when acquisition failed or its future retirement panicked.
    pub usage: Option<BracketPhase<T, E>>,
    /// Actual use-task terminal, distinct from its captured application outcomes.
    pub body_task: Option<Result<(), JoinError>>,
    /// Actual region-close result. Err does NOT establish quiescence.
    pub close: Option<Result<BracketRegionOutcome, ChildRegionError>>,
    /// None when no resource was acquired or close failed. A release failure
    /// does not overwrite the original acquisition/use outcome.
    pub release: Option<BracketPhase<(), C>>,
    /// Resource withheld from release because subtree quiescence was not proved.
    /// The caller must retain it until independently establishing safe cleanup.
    /// Dropping this report drops this resource; no async release is fabricated.
    pub unreleased: Option<R>,
    /// Admission/submission/cancellation diagnostics (at most two entries).
    pub infrastructure: Vec<BracketInfrastructureError>,
    /// Controller cancellation observed before terminal report publication.
    pub cancellation: Option<CancelReason>,
    /// Filled from the actual controller TaskHandle when joining.
    pub controller_task: Result<(), JoinError>,
}

impl<R, T, E, C> BracketReport<R, T, E, C> {
    fn empty() -> Self {
        Self {
            region: None, acquisition: None, usage: None, body_task: None,
            close: None, release: None, unreleased: None, infrastructure: Vec::new(),
            cancellation: None, controller_task: Ok(()),
        }
    }

    /// Conservative whole-operation success, including both task joins and cleanup.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.acquisition.as_ref().is_some_and(BracketPhase::is_success)
            && self.usage.as_ref().is_some_and(BracketPhase::is_success)
            && self.release.as_ref().is_some_and(BracketPhase::is_success)
            && matches!(&self.body_task, Some(Ok(())))
            && matches!(&self.close, Some(Ok(close))
                if matches!(&close.outcome, Outcome::Ok(()) | Outcome::Cancelled(_))
                    && close.cleanup_outcome.as_ref().is_none_or(|outcome| outcome.is_ok()))
            && self.unreleased.is_none()
            && self.infrastructure.is_empty()
            && self.cancellation.is_none()
            && self.controller_task.is_ok()
    }
}

type ReportSlot<R, T, E, C> = Arc<Mutex<Option<BracketReport<R, T, E, C>>>>;

/// Owns cancellation of a real runtime task, not an inline acquire/use future.
#[must_use = "retain and join to observe completed asynchronous release"]
pub struct BracketHandle<R, T, E, C> {
    task: TaskHandle<()>,
    report: ReportSlot<R, T, E, C>,
}

impl<R, T, E, C> fmt::Debug for BracketHandle<R, T, E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BracketHandle").field("task", &self.task.task_id())
            .finish_non_exhaustive()
    }
}

impl<R, T, E, C> BracketHandle<R, T, E, C> {
    /// Registered controller identity once admission publishes it.
    #[must_use]
    pub fn task_id(&self) -> TaskId { self.task.task_id() }

    /// Request cancellation. The controller still joins/drains before release.
    pub fn abort(&self) { self.task.abort(); }

    /// Uninterruptibly join the controller; dropping this borrowing wait neither
    /// aborts the controller nor loses a report. Dropping the HANDLE requests stop.
    pub async fn join(&mut self) -> Result<BracketReport<R, T, E, C>, JoinError> {
        let terminal = poll_fn(|cx| self.task.poll_join(cx)).await;
        let report = self.report.lock().take();
        if let Some(mut report) = report {
            report.controller_task = terminal;
            return Ok(report);
        }
        match terminal {
            Err(error) => Err(error),
            Ok(()) => Err(JoinError::Panicked(PanicPayload::new("bracket omitted its report"))),
        }
    }
}

impl<R, T, E, C> Drop for BracketHandle<R, T, E, C> {
    fn drop(&mut self) { self.task.abort(); }
}

impl Cx {
    /// Submit acquire/use/drain/release with one resource owner and real wakeups.
    ///
    /// Acquisition and use run in the child task's actual Cx. Use borrows `R`,
    /// allowing non-Clone and non-Sync resources. Everything spawned through that
    /// Cx drains before release. Release receives the controller's Cx and owns R;
    /// it must finish any cleanup work it starts before returning. Work spawned
    /// through independently captured capabilities is outside this bracket.
    ///
    /// Cancelling before acquisition invokes no release. If acquisition returns
    /// a resource, even while cancelled or with a future-destructor panic, it is
    /// retained for release after drain. An acquire that fails/panics without
    /// returning a resource is responsible for its own partial acquisitions.
    /// Cleanup waits are asynchronous and masked only by the supplied allowance.
    /// Neither a poll budget nor Drop promises termination of arbitrary code.
    pub fn spawn_bracket<R, T, E, C, A, AF, U, F, FF>(
        &self, config: BracketConfig, acquire: A, use_resource: U, release: F,
    ) -> Result<BracketHandle<R, T, E, C>, SpawnError>
    where
        R: Send + 'static, T: Send + 'static, E: Send + 'static, C: Send + 'static,
        A: FnOnce(Cx) -> AF + Send + 'static,
        AF: Future<Output = Outcome<R, E>> + Send + 'static,
        U: for<'a> FnOnce(Cx, &'a mut R) -> BracketUseFuture<'a, T, E> + Send + 'static,
        F: FnOnce(Cx, R) -> FF + Send + 'static,
        FF: Future<Output = Outcome<(), C>> + Send + 'static,
    {
        let report = Arc::new(Mutex::new(None));
        let publication = Arc::clone(&report);
        let task = self.spawn(move |cx| async move {
            let result = drive(cx, config, acquire, use_resource, release).await;
            // Terminal bookkeeping does not send through the cancelled Cx.
            *publication.lock() = Some(result);
        })?;
        Ok(BracketHandle { task, report })
    }
}

fn panic_payload(payload: Box<dyn Any + Send>) -> PanicPayload {
    let message = if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string bracket panic".to_owned()
    };
    // An arbitrary payload destructor can panic again. Do not let it prevent
    // resource return, subtree drain, or release of a successfully acquired R.
    std::mem::forget(payload);
    PanicPayload::new(message)
}

fn under_mask<T>(mask: Option<&Cx>, action: impl FnOnce() -> T) -> T {
    match mask { Some(cx) => cx.masked(action), None => action() }
}

async fn evaluate<T, E, F, Fut>(
    factory: F, mask: Option<(&Cx, u32)>,
) -> BracketPhase<T, E>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Outcome<T, E>>,
{
    let callback_mask = mask.filter(|(_, limit)| *limit != 0).map(|(cx, _)| cx);
    let constructed = catch_unwind(AssertUnwindSafe(|| under_mask(callback_mask, factory)));
    let mut future = match constructed {
        Ok(future) => Box::pin(future),
        Err(payload) => return BracketPhase {
            outcome: Outcome::Panicked(panic_payload(payload)), retirement_panic: None,
        },
    };
    let mut masked_polls = 0;
    let outcome = poll_fn(|task_cx| {
        let poll_mask = mask.filter(|(_, limit)| masked_polls < *limit).map(|(cx, _)| cx);
        if poll_mask.is_some() { masked_polls += 1; }
        match catch_unwind(AssertUnwindSafe(|| {
            under_mask(poll_mask, || future.as_mut().poll(task_cx))
        })) {
            Ok(poll) => poll,
            Err(payload) => Poll::Ready(Outcome::Panicked(panic_payload(payload))),
        }
    }).await;
    let retirement_panic = catch_unwind(AssertUnwindSafe(|| {
        under_mask(callback_mask, || drop(future));
    })).err().map(panic_payload);
    BracketPhase { outcome, retirement_panic }
}

struct Work<R, T, E> {
    resource: Option<R>,
    acquisition: Option<BracketPhase<(), E>>,
    usage: Option<BracketPhase<T, E>>,
}

/// Returns the resource even if the runtime forcibly retires the body future.
/// It never invokes user cleanup, and no user destructor runs under the slot lock.
struct ResourceReturn<R, T, E> {
    value: Option<R>,
    work: Arc<Mutex<Work<R, T, E>>>,
}

impl<R, T, E> Drop for ResourceReturn<R, T, E> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            let old = self.work.lock().resource.replace(value);
            debug_assert!(old.is_none(), "one resource owner per bracket");
            drop(old);
        }
    }
}

async fn body<R, T, E, A, AF, U>(
    cx: Cx, work: Arc<Mutex<Work<R, T, E>>>, acquire: A, use_resource: U,
)
where
    A: FnOnce(Cx) -> AF,
    AF: Future<Output = Outcome<R, E>>,
    U: for<'a> FnOnce(Cx, &'a mut R) -> BracketUseFuture<'a, T, E>,
{
    if cx.checkpoint().is_err() {
        work.lock().acquisition = Some(BracketPhase {
            outcome: Outcome::Cancelled(cancel_reason(&cx)), retirement_panic: None,
        });
        return;
    }
    let BracketPhase { outcome, retirement_panic } = evaluate(|| acquire(cx.clone()), None).await;
    let clean_acquire = retirement_panic.is_none();
    let resource = match outcome {
        Outcome::Ok(resource) => resource,
        outcome => {
            let outcome = match outcome {
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => Outcome::Panicked(payload),
                Outcome::Ok(_) => unreachable!(),
            };
            work.lock().acquisition = Some(BracketPhase { outcome, retirement_panic });
            return;
        }
    };
    let mut resource = ResourceReturn { value: Some(resource), work: Arc::clone(&work) };
    work.lock().acquisition = Some(BracketPhase { outcome: Outcome::Ok(()), retirement_panic });
    if clean_acquire {
        let usage = if cx.checkpoint().is_err() {
            BracketPhase { outcome: Outcome::Cancelled(cancel_reason(&cx)), retirement_panic: None }
        } else {
            evaluate(|| use_resource(cx.clone(), resource.value.as_mut().expect("owned resource")), None).await
        };
        work.lock().usage = Some(usage);
    }
    drop(resource);
}

fn cancel_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason().unwrap_or_else(|| CancelReason::user("bracket cancelled"))
}

struct Cancellation<'a> { cx: &'a Cx, token: Option<CancelWakerToken> }
impl Drop for Cancellation<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { self.cx.clear_cancel_waker(token); }
    }
}

struct BodyTask { task: TaskHandle<()>, joined: bool }
impl Drop for BodyTask {
    fn drop(&mut self) { if !self.joined { self.task.abort(); } }
}

async fn drive<R, T, E, C, A, AF, U, F, FF>(
    cx: Cx, config: BracketConfig, acquire: A, use_resource: U, release: F,
) -> BracketReport<R, T, E, C>
where
    R: Send + 'static, T: Send + 'static, E: Send + 'static, C: Send + 'static,
    A: FnOnce(Cx) -> AF + Send + 'static,
    AF: Future<Output = Outcome<R, E>> + Send + 'static,
    U: for<'a> FnOnce(Cx, &'a mut R) -> BracketUseFuture<'a, T, E> + Send + 'static,
    F: FnOnce(Cx, R) -> FF + Send + 'static,
    FF: Future<Output = Outcome<(), C>> + Send + 'static,
{
    let mut report = BracketReport::empty();
    let region = match cx.open_child_region(config.region).await {
        Ok(region) => region,
        Err(error) => {
            report.infrastructure.push(BracketInfrastructureError::Region(error));
            return report;
        }
    };
    report.region = Some(region.region_id());
    let work = Arc::new(Mutex::new(Work { resource: None, acquisition: None, usage: None }));
    let mut cancellation = Cancellation { cx: &cx, token: None };
    if cx.checkpoint().is_err() {
        report.cancellation = Some(cancel_reason(&cx));
    } else {
        let publication = Arc::clone(&work);
        match region.cx().spawn(move |cx| body(cx, publication, acquire, use_resource)) {
            Err(error) => report.infrastructure.push(BracketInfrastructureError::Spawn(error)),
            Ok(task) => {
                let mut body = BodyTask { task, joined: false };
                let mut stop_sent = false;
                let terminal = poll_fn(|task_cx| {
                    cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token, task_cx.waker()));
                    if !stop_sent && cx.checkpoint().is_err() {
                        stop_sent = true;
                        let reason = cancel_reason(&cx);
                        report.cancellation = Some(reason.clone());
                        if let Err(error) = region.cancel_with_budget(reason, config.shutdown_budget) {
                            report.infrastructure.push(BracketInfrastructureError::Cancellation(error));
                            body.task.abort();
                        }
                    }
                    body.task.poll_join(task_cx)
                }).await;
                body.joined = true;
                report.body_task = Some(terminal);
            }
        }
    }
    let close = region.close_with_outcome().await;
    let (resource, acquisition, usage) = {
        let mut work = work.lock();
        (work.resource.take(), work.acquisition.take(), work.usage.take())
    };
    report.acquisition = acquisition;
    report.usage = usage;
    match close {
        Err(error) => {
            report.close = Some(Err(error));
            report.unreleased = resource;
        }
        Ok(close) => {
            report.close = Some(Ok(BracketRegionOutcome {
                outcome: close.outcome, cleanup_outcome: close.cleanup_outcome,
            }));
            if let Some(resource) = resource {
                // Acknowledge before masking; preserve an independently observed reason.
                if cx.checkpoint().is_err() { report.cancellation = Some(cancel_reason(&cx)); }
                report.release = Some(evaluate(
                    || release(cx.clone(), resource), Some((&cx, config.release_masked_polls)),
                ).await);
            }
        }
    }
    if cx.checkpoint().is_err() { report.cancellation = Some(cancel_reason(&cx)); }
    report
}

#[cfg(test)]
mod tests;

/// Bounded heterogeneous resources with typed access and asynchronous LIFO release.
pub mod stack;
