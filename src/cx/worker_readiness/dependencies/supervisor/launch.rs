//! An owned, deadline-limited transition from a bound topology to a running service.
//!
//! The startup deadline limits acceptance, not the time allowed for safe teardown.
//! A failed start joins the incumbent controller and closes its enclosing region.
//! No timer, controller, or initializer is created until `start` is polled.

use super::{InitializedBindError, InitializedChildBinding, InitializedTopologyLimits, SupervisorReadiness};
use super::super::{DependencyError, DependencyRegionOutcome, ReadyDependencies};
use super::super::super::Cancellation;
use crate::cx::{ChildRegion, ChildRegionError, ChildRegionSpec, Cx};
use crate::runtime::{JoinError, SpawnError};
use crate::supervision::{CompiledSupervisor, ManagedSupervisor, ManagedSupervisorHandle, ManagedSupervisorReport, SupervisionConfig};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{Budget, CancelReason, RegionId, Time};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// One startup allowance, independent of the eventual service lifetime.
#[derive(Debug, Clone)]
pub struct InitializedStartConfig {
    /// Measured from the first poll, including enclosing-region admission.
    /// Zero is immediately expired; unrepresentable absolute deadlines refuse.
    pub timeout: Duration,
    /// Enclosing ownership boundary; ordinary parent capability/budget meet applies.
    /// The startup deadline is NOT installed as this region's lifetime deadline.
    pub region: ChildRegionSpec,
    /// Budget for failure/explicit-stop cancellation, not an arbitrary-future bound.
    pub shutdown_budget: Budget,
}

impl InitializedStartConfig {
    /// Select a finite startup allowance without changing worker lifetime budgets.
    #[must_use]
    pub const fn new(timeout: Duration, shutdown_budget: Budget) -> Self {
        Self { timeout, region: ChildRegionSpec::inherit(), shutdown_budget }
    }
}

/// The first observed startup refusal. Application errors stay in `cleanup`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InitializedStartCause {
    /// A running-service startup requires at least one initialized worker.
    #[error("initialized service topology is empty")]
    EmptyTopology,
    /// An explicit timer capability is required; no wall-clock fallback is used.
    #[error("initialized startup requires a context timer driver")]
    NoTimer,
    /// The requested duration cannot form a representable absolute deadline.
    #[error("initialized startup deadline is not representable")]
    InvalidTimeout,
    /// Deadline won before acceptance, even if readiness arrived in that poll.
    #[error("initialized startup expired at {deadline:?}")]
    Deadline {
        /// Absolute effective deadline in the supplied context's clock.
        deadline: Time,
    },
    /// Caller cancellation was acknowledged, without erasing teardown evidence.
    #[error("initialized startup caller cancelled")]
    Cancelled(CancelReason),
    /// The enclosing region could not be admitted.
    #[error("initialized startup region: {0}")]
    Region(ChildRegionError),
    /// Immediate controller submission failed.
    #[error("initialized startup controller submission: {0:?}")]
    Spawn(SpawnError),
    /// A prerequisite cannot become ready; this is not its typed application error.
    #[error("initialized startup readiness: {0}")]
    Readiness(DependencyError),
    /// The real controller terminated before startup acceptance.
    #[error("initialized supervisor terminated before readiness acceptance")]
    ControllerTerminated,
}

impl InitializedStartCause {
    fn stop_reason(&self) -> CancelReason {
        match self {
            Self::Cancelled(reason) => reason.clone(),
            Self::Deadline { .. } => CancelReason::timeout(),
            _ => CancelReason::user("initialized supervisor startup failed"),
        }
    }
}

/// Controller outcome and enclosing-region closure, never just an admission receipt.
#[derive(Debug)]
#[must_use = "inspect the controller report and actual enclosing-region closure"]
pub struct InitializedExit<E> {
    /// Boundary enclosing the controller, all workers, and all their descendants.
    pub region: RegionId,
    /// None only when immediate controller submission failed.
    pub controller: Option<Result<ManagedSupervisorReport<E>, JoinError>>,
    /// Err does not establish quiescence, even if a controller report exists.
    pub close: Result<DependencyRegionOutcome, ChildRegionError>,
    /// Whether this owner requested a stop, not evidence that workers cooperated.
    pub stop_requested: bool,
    /// First region-cancellation enqueue failure. Controller abort was attempted.
    pub stop_error: Option<ChildRegionError>,
}

/// Failed startup retains both its first cause and independent cleanup evidence.
#[derive(Debug)]
#[must_use = "startup failure does not imply successful cleanup"]
pub struct InitializedStartError<E> {
    /// First observed startup refusal, not a global timestamp ordering.
    pub cause: InitializedStartCause,
    /// Caller cancellation, including one first observed during failed-start drain.
    pub cancellation: Option<CancelReason>,
    /// None means no enclosing region was admitted. Some always contains a close
    /// attempt; its result must be checked rather than inferred from this error.
    pub cleanup: Option<InitializedExit<E>>,
}

impl<E> fmt::Display for InitializedStartError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.cause, f)
    }
}

impl<E: fmt::Debug> std::error::Error for InitializedStartError<E> {}

/// The exact managed topology and its matching readiness views, inseparable at start.
/// This owner prevents accidentally starting one supervisor against another's view.
#[must_use = "start the prepared supervisor to execute its workers"]
pub struct InitializedSupervisor<E> {
    managed: ManagedSupervisor<E>,
    readiness: SupervisorReadiness,
}

impl<E> fmt::Debug for InitializedSupervisor<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitializedSupervisor").field("managed", &self.managed)
            .field("readiness", &self.readiness).finish()
    }
}

impl CompiledSupervisor {
    /// Prepare the existing initialized binding with an inseparable startup owner.
    /// Legacy `bind_initialized` and ordinary managed entry points remain unchanged.
    pub fn bind_initialized_owned<E: Send + 'static>(
        self, bindings: Vec<InitializedChildBinding<E>>, config: SupervisionConfig,
        limits: InitializedTopologyLimits,
    ) -> Result<InitializedSupervisor<E>, InitializedBindError> {
        let (managed, readiness) = self.bind_initialized(bindings, config, limits)?;
        Ok(InitializedSupervisor { managed, readiness })
    }
}

type CloseFuture = Pin<Box<dyn Future<Output = Result<DependencyRegionOutcome, ChildRegionError>> + Send>>;

/// Owns a started topology, its initial readiness vector and its teardown progress.
///
/// Borrowing `join`/`shutdown` waits may be dropped and resumed without losing a
/// controller report or restarting region close. Dropping the OWNER requests stop;
/// only the enclosing runtime region can establish eventual quiescence afterward.
#[must_use = "retain and join or shut down the running supervisor"]
pub struct RunningInitializedSupervisor<E> {
    region_id: RegionId,
    region: Option<ChildRegion>,
    controller: Option<ManagedSupervisorHandle<E>>,
    terminal: Option<Result<ManagedSupervisorReport<E>, JoinError>>,
    closing: Option<CloseFuture>,
    shutdown_budget: Budget,
    readiness: SupervisorReadiness,
    selected: Option<ReadyDependencies>,
    stop_requested: bool,
    stop_error: Option<ChildRegionError>,
    reported: bool,
}

impl<E> fmt::Debug for RunningInitializedSupervisor<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunningInitializedSupervisor").field("region", &self.region_id)
            .field("stop_requested", &self.stop_requested).field("reported", &self.reported)
            .finish_non_exhaustive()
    }
}

impl<E> RunningInitializedSupervisor<E> {
    /// The additional boundary owning this complete launched topology.
    #[must_use]
    pub const fn region_id(&self) -> RegionId { self.region_id }

    /// Current named observations, not a health lease or lifecycle owner.
    #[must_use]
    pub fn readiness(&self) -> &SupervisorReadiness { &self.readiness }

    /// The exact coherent vector accepted at startup. It may already be stale.
    #[must_use]
    pub fn initial_readiness(&self) -> &ReadyDependencies {
        self.selected.as_ref().expect("running handle only escapes after acceptance")
    }

    /// Request whole-topology cancellation. Repeated calls do not reopen it.
    /// The original caller-side error remains available in the final exit report.
    pub fn request_stop(&mut self) { self.stop(CancelReason::shutdown()); }

    fn stop(&mut self, reason: CancelReason) {
        if self.stop_requested || self.reported { return; }
        self.stop_requested = true;
        if let Some(region) = &self.region {
            if let Err(error) = region.cancel_with_budget(reason, self.shutdown_budget) {
                self.stop_error = Some(error);
                if let Some(controller) = &self.controller { controller.abort(); }
            }
        } else if let Some(controller) = &self.controller {
            controller.abort();
        }
    }

    fn poll_controller(&mut self, task: &mut Context<'_>) -> Poll<()> {
        if self.terminal.is_some() || self.controller.is_none() { return Poll::Ready(()); }
        let result = {
            // The managed handle retains its join receiver/report on Pending.
            let mut join = std::pin::pin!(self.controller.as_mut().expect("owned controller").join());
            join.as_mut().poll(task)
        };
        let result = std::task::ready!(result);
        self.terminal = Some(result);
        drop(self.controller.take());
        Poll::Ready(())
    }

    fn poll_exit(&mut self, task: &mut Context<'_>) -> Poll<Result<InitializedExit<E>, JoinError>> {
        if self.reported { return Poll::Ready(Err(JoinError::PolledAfterCompletion)); }
        std::task::ready!(self.poll_controller(task));
        if self.closing.is_none() {
            let region = self.region.take().expect("one close per owned boundary");
            self.closing = Some(Box::pin(async move {
                region.close_with_outcome().await.map(|closed| DependencyRegionOutcome {
                    outcome: closed.outcome, cleanup_outcome: closed.cleanup_outcome,
                })
            }));
        }
        let close = std::task::ready!(self.closing.as_mut().expect("retained close").as_mut().poll(task));
        self.reported = true;
        drop(self.closing.take());
        Poll::Ready(Ok(InitializedExit {
            region: self.region_id, controller: self.terminal.take(), close,
            stop_requested: self.stop_requested, stop_error: self.stop_error.take(),
        }))
    }

    /// Observe natural termination and close the whole boundary. This wait does
    /// not cancel live workers and has no startup deadline. It is resumable on drop.
    /// After the one owned report is consumed, further joins return PolledAfterCompletion.
    pub async fn join(&mut self) -> Result<InitializedExit<E>, JoinError> {
        poll_fn(|task| self.poll_exit(task)).await
    }

    /// Request stop, then join and drain. Dropping this borrowing wait leaves the
    /// stop in force and keeps any already-observed result/close future in this owner.
    pub async fn shutdown(&mut self) -> Result<InitializedExit<E>, JoinError> {
        self.request_stop();
        self.join().await
    }
}

impl<E> Drop for RunningInitializedSupervisor<E> {
    fn drop(&mut self) {
        self.request_stop();
        // The handle and ChildRegion drops are the existing cancellation/close
        // backstops, including when an in-progress borrowing close was abandoned.
    }
}

fn deadline(now: Time, timeout: Duration, parent: Option<Time>) -> Option<Time> {
    let nanos = u64::try_from(timeout.as_nanos()).ok()?;
    let requested = Time::from_nanos(now.as_nanos().checked_add(nanos)?);
    Some(parent.map_or(requested, |parent| parent.min(requested)))
}

struct StartupWatch<'a> {
    cancellation: Cancellation<'a>,
    observed_cancel: Option<CancelReason>,
    timer: TimerDriverHandle,
    sleep: Pin<Box<Sleep>>,
    deadline: Time,
}

impl StartupWatch<'_> {
    fn observe_cancel(&mut self, task: &Context<'_>) -> bool {
        let cx = self.cancellation.cx;
        self.cancellation.token = Some(cx.refresh_cancel_waker(self.cancellation.token, task.waker()));
        if self.observed_cancel.is_none() && cx.checkpoint().is_err() {
            self.observed_cancel = Some(cx.cancel_reason().unwrap_or_else(CancelReason::shutdown));
        }
        self.observed_cancel.is_some()
    }

    fn refusal(&mut self, task: &mut Context<'_>) -> Option<InitializedStartCause> {
        if self.observe_cancel(task) {
            return Some(InitializedStartCause::Cancelled(self.observed_cancel.as_ref().expect("observed").clone()));
        }
        if self.timer.now() >= self.deadline || self.sleep.as_mut().poll(task).is_ready() {
            return Some(InitializedStartCause::Deadline { deadline: self.deadline });
        }
        None
    }
}

impl<E: Send + 'static> InitializedSupervisor<E> {
    /// Observe preparation without starting work. Observation cannot cancel it.
    #[must_use]
    pub fn readiness(&self) -> &SupervisorReadiness { &self.readiness }

    /// Start exactly this topology and accept it only while all workers are ready.
    ///
    /// One absolute, explicitly bound timer covers boundary admission and all
    /// initialization/restarts. Parent deadlines may shorten it; startup does not
    /// install a service-lifetime deadline or grant missing timer authority.
    /// Cancellation/deadline takes precedence over readiness observed in the same
    /// poll. The actual controller is observed as well, so controller termination
    /// cannot leave a startup waiter parked behind retained readiness factories.
    ///
    /// A failed start requests stop, joins the controller and awaits enclosing
    /// region close before returning its error and all available typed results.
    /// Teardown may exceed the startup deadline: cancellation is cooperative,
    /// not a hard kill. A stalled Transient factory still needs the startup timer;
    /// this API does not invent permanent-retirement events for that controller.
    ///
    /// Dropping this future after admission requests cancellation/close through
    /// its retained owners; it does not synchronously drain. On success the caller
    /// must retain the returned owner and ultimately join/shut it down.
    pub async fn start(
        self, cx: &Cx, config: InitializedStartConfig,
    ) -> Result<RunningInitializedSupervisor<E>, InitializedStartError<E>> {
        let refusal = |cause| InitializedStartError { cause, cancellation: None, cleanup: None };
        if cx.checkpoint().is_err() {
            let reason = cx.cancel_reason().unwrap_or_else(CancelReason::shutdown);
            return Err(InitializedStartError {
                cause: InitializedStartCause::Cancelled(reason.clone()), cancellation: Some(reason), cleanup: None,
            });
        }
        if self.readiness.all().is_empty() { return Err(refusal(InitializedStartCause::EmptyTopology)); }
        let timer = cx.timer_driver().ok_or_else(|| refusal(InitializedStartCause::NoTimer))?;
        let limit = deadline(timer.now(), config.timeout, cx.budget().deadline)
            .ok_or_else(|| refusal(InitializedStartCause::InvalidTimeout))?;
        if timer.now() >= limit { return Err(refusal(InitializedStartCause::Deadline { deadline: limit })); }
        let mut watch = StartupWatch {
            cancellation: Cancellation { cx, token: None }, observed_cancel: None,
            sleep: Box::pin(Sleep::with_timer_driver(limit, timer.clone())), timer, deadline: limit,
        };
        let mut cause = None;
        // Once submitted, observe admission even if the deadline wins; a region
        // minted late must be closed, not discarded by returning an early timeout.
        let mut opening = std::pin::pin!(cx.open_child_region(config.region));
        let admitted = poll_fn(|task| {
            if cause.is_none() { cause = watch.refusal(task); }
            else { watch.observe_cancel(task); }
            opening.as_mut().poll(task)
        }).await;
        let region = match admitted {
            Ok(region) => region,
            Err(error) => return Err(InitializedStartError {
                cause: cause.unwrap_or(InitializedStartCause::Region(error)),
                cancellation: watch.observed_cancel, cleanup: None,
            }),
        };
        let Self { managed, readiness } = self;
        let mut running = RunningInitializedSupervisor {
            region_id: region.region_id(), region: Some(region), controller: None,
            terminal: None, closing: None, shutdown_budget: config.shutdown_budget,
            readiness, selected: None, stop_requested: false, stop_error: None, reported: false,
        };
        // Check after the admission poll too: callbacks or time advancement may
        // have consumed the remaining allowance while producing the region.
        if cause.is_none() {
            cause = poll_fn(|task| Poll::Ready(watch.refusal(task))).await;
        }
        if cause.is_none() {
            match managed.spawn(running.region.as_ref().expect("admitted region").cx()) {
                Ok(controller) => running.controller = Some(controller),
                Err(error) => cause = Some(InitializedStartCause::Spawn(error)),
            }
        } else {
            drop(managed);
        }
        if cause.is_none() {
            let readiness = running.readiness.clone();
            let mut ready = std::pin::pin!(readiness.all().wait_ready(cx));
            let accepted = poll_fn(|task| {
                if let Some(cause) = watch.refusal(task) { return Poll::Ready(Err(cause)); }
                if running.poll_controller(task).is_ready() {
                    return Poll::Ready(Err(InitializedStartCause::ControllerTerminated));
                }
                let selected = match ready.as_mut().poll(task) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(InitializedStartCause::Readiness(error))),
                    Poll::Ready(Ok(selected)) => selected,
                };
                if let Some(cause) = watch.refusal(task) { return Poll::Ready(Err(cause)); }
                Poll::Ready(Ok(selected))
            }).await;
            match accepted {
                Ok(selected) => { running.selected = Some(selected); return Ok(running); }
                Err(error) => cause = Some(error),
            }
        }
        let cause = cause.expect("startup either accepted or refused");
        running.stop(cause.stop_reason());
        let cleanup = poll_fn(|task| {
            watch.observe_cancel(task);
            running.poll_exit(task)
        }).await.expect("unreported startup owner");
        Err(InitializedStartError { cause, cancellation: watch.observed_cancel, cleanup: Some(cleanup) })
    }
}

#[cfg(test)]
mod tests;
