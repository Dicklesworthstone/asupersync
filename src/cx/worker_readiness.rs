//! Initialization-aware readiness for real managed worker generations.
//!
//! [`initialized_worker`] adapts the existing managed factory contract. Each
//! generation initializes its own state, then hands that state to its run
//! factory. Readiness is published only after successful initialization and run
//! construction, and is withdrawn on observed cancellation or body retirement.
//! The existing supervisor still owns restart, backoff and subtree drain.
//!
//! Readiness is an observation, NOT a lease, health probe, admission receipt or
//! quiescence barrier. A worker can fail immediately after an observation. The
//! initializer defines what ready means for the application. Neither dropping
//! an observer nor cancelling an observation stops the worker. Join/reap through
//! its existing owner for the authoritative terminal result and region closure.

use super::{CancelWakerToken, Cx};
use crate::supervision::{ManagedChildFactory, ManagedGeneration};
use crate::sync::Notify;
use crate::types::{CancelReason, Outcome, PanicPayload};
use parking_lot::Mutex;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

/// Latest observed generation phase, not a retained transition history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkerReadinessPhase {
    /// The factory has not been invoked by an admitted worker yet.
    NotStarted,
    /// Initialization or run-factory construction has not completed.
    Initializing,
    /// Initialization and run construction succeeded with no observed stop.
    Ready,
    /// Cancellation was observed; the body may still be doing cleanup.
    Stopping,
    /// The body was retired. Its descendants/finalizers may still be draining.
    Retired,
    /// No factory or active body remains. This is NOT region quiescence.
    Closed,
    /// The factory contract was violated by an overlapping or stale generation.
    InvalidGeneration,
}

/// Payload-free latest state of one initialized worker's factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerReadinessState {
    /// Full runtime identity of the last invoked generation, if any.
    pub generation: Option<ManagedGeneration>,
    /// Latest observed phase.
    pub phase: WorkerReadinessPhase,
}

/// A readiness wait refusal, separate from the worker's typed terminal error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WorkerReadinessError {
    /// Only the observation was cancelled; the worker was not stopped.
    #[error("worker readiness observation cancelled")]
    Cancelled,
    /// No current or future ready generation can be supplied by this factory.
    #[error("worker readiness factory closed")]
    Closed,
    /// An observation from a different factory cannot select this one's restart.
    #[error("worker readiness observation belongs to another factory")]
    ForeignObservation,
    /// Invalid identity, overlapping invocation or non-increasing generation.
    #[error("worker readiness observed an invalid managed generation")]
    InvalidGeneration,
}

struct State {
    snapshot: WorkerReadinessState,
    factory_alive: bool,
    active: bool,
}

struct Shared {
    state: Mutex<State>,
    changed: Notify,
}

// Observer callbacks must not change a successful initialization into a worker
// failure or unwind from a generation's Drop. Notify broadcasts before resuming
// a callback panic; never run it while holding the readiness-state mutex.
fn notify(shared: &Shared) {
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        shared.changed.notify_waiters();
    })) {
        std::mem::forget(payload);
    }
}

/// Cloneable observation capability. Stores no application resource or error.
#[derive(Clone)]
pub struct WorkerReadiness {
    shared: Arc<Shared>,
}

impl fmt::Debug for WorkerReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerReadiness")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

/// An observation bound to this exact factory and one actual ready generation.
/// Keeping it does not keep the worker running or the factory open.
#[derive(Clone)]
pub struct ReadyWorker {
    shared: Arc<Shared>,
    generation: ManagedGeneration,
}

impl fmt::Debug for ReadyWorker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadyWorker")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl ReadyWorker {
    /// Complete task/region/generation identity, not just a reused child name.
    #[must_use]
    pub const fn generation(&self) -> ManagedGeneration {
        self.generation
    }
}

impl WorkerReadiness {
    /// Inspect the latest state without consuming an event or waiting.
    #[must_use]
    pub fn state(&self) -> WorkerReadinessState {
        self.shared.state.lock().snapshot
    }

    /// Whether this exact observation is still the latest Ready generation.
    /// The answer may become false immediately afterward; it grants no lease.
    #[must_use]
    pub fn is_current(&self, observation: &ReadyWorker) -> bool {
        if !Arc::ptr_eq(&self.shared, &observation.shared) {
            return false;
        }
        let state = self.state();
        state.phase == WorkerReadinessPhase::Ready
            && state.generation == Some(observation.generation)
    }

    /// Wait for a currently Ready generation. Intermediate short-lived Ready
    /// states may be missed: this is a latest-state view, not an event history.
    /// Dropping/cancelling this borrowing wait unregisters it, not the worker.
    ///
    /// # Errors
    /// Returns observer cancellation, factory closure, or invalid generation use.
    pub async fn wait_ready(&self, cx: &Cx) -> Result<ReadyWorker, WorkerReadinessError> {
        self.wait(cx, None).await
    }

    /// Wait for a Ready replacement STRICTLY newer than this factory's previous
    /// observation. A reused name or an observation from another factory refuses.
    /// Retry backoff and stopped generations never satisfy the predicate.
    ///
    /// # Errors
    /// Refuses foreign observations and the same conditions as `wait_ready`.
    pub async fn wait_ready_after(
        &self,
        cx: &Cx,
        previous: &ReadyWorker,
    ) -> Result<ReadyWorker, WorkerReadinessError> {
        if !Arc::ptr_eq(&self.shared, &previous.shared) {
            return Err(WorkerReadinessError::ForeignObservation);
        }
        self.wait(cx, Some(previous.generation.number)).await
    }

    async fn wait(&self, cx: &Cx, after: Option<u64>) -> Result<ReadyWorker, WorkerReadinessError> {
        let mut cancellation = Cancellation { cx, token: None };
        let mut notified = self.shared.changed.notified();
        poll_fn(|task| {
            cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token, task.waker()));
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(WorkerReadinessError::Cancelled));
            }
            // Arm before reading state. A racing broadcast either wakes this
            // waiter or is reflected by the predicate. Bound re-arming work.
            if Pin::new(&mut notified).poll(task).is_ready() {
                notified = self.shared.changed.notified();
                if Pin::new(&mut notified).poll(task).is_ready() {
                    task.waker().wake_by_ref();
                }
            }
            let state = self.state();
            match state.phase {
                WorkerReadinessPhase::Closed => Poll::Ready(Err(WorkerReadinessError::Closed)),
                WorkerReadinessPhase::InvalidGeneration => {
                    Poll::Ready(Err(WorkerReadinessError::InvalidGeneration))
                }
                WorkerReadinessPhase::Ready => {
                    let generation = state.generation.expect("ready generation has an identity");
                    if after.is_none_or(|previous| generation.number > previous) {
                        Poll::Ready(Ok(ReadyWorker { shared: Arc::clone(&self.shared), generation }))
                    } else {
                        Poll::Pending
                    }
                }
                _ => Poll::Pending,
            }
        }).await
    }
}

struct FactoryOwner(Arc<Shared>);

impl FactoryOwner {
    fn begin(&self, cx: &Cx, generation: ManagedGeneration) -> Option<GenerationGuard> {
        let task = cx.task_id();
        let region = cx.region_id();
        let valid = {
            let mut state = self.0.state.lock();
            let valid = state.factory_alive && !state.active
                && state.snapshot.phase != WorkerReadinessPhase::InvalidGeneration
                && generation.number != 0
                && state.snapshot.generation.is_none_or(|old| generation.number > old.number)
                && generation.task == task && generation.region == region;
            if valid {
                state.active = true;
                state.snapshot = WorkerReadinessState {
                    generation: Some(generation), phase: WorkerReadinessPhase::Initializing,
                };
            } else {
                state.snapshot.phase = WorkerReadinessPhase::InvalidGeneration;
            }
            valid
        };
        notify(&self.0);
        valid.then(|| GenerationGuard { shared: Arc::clone(&self.0), generation })
    }
}

impl Drop for FactoryOwner {
    fn drop(&mut self) {
        {
            let mut state = self.0.state.lock();
            state.factory_alive = false;
            if !state.active && state.snapshot.phase != WorkerReadinessPhase::InvalidGeneration {
                state.snapshot.phase = WorkerReadinessPhase::Closed;
            }
        }
        notify(&self.0);
    }
}

struct GenerationGuard {
    shared: Arc<Shared>,
    generation: ManagedGeneration,
}

impl GenerationGuard {
    fn phase(&self, next: WorkerReadinessPhase) {
        let changed = {
            let mut state = self.shared.state.lock();
            if state.snapshot.generation != Some(self.generation)
                || state.snapshot.phase == WorkerReadinessPhase::InvalidGeneration
                || state.snapshot.phase == next
                || (next == WorkerReadinessPhase::Ready
                    && state.snapshot.phase != WorkerReadinessPhase::Initializing)
            {
                false
            } else {
                state.snapshot.phase = next;
                true
            }
        };
        if changed { notify(&self.shared); }
    }
}

impl Drop for GenerationGuard {
    fn drop(&mut self) {
        {
            let mut state = self.shared.state.lock();
            if state.snapshot.generation == Some(self.generation) {
                state.active = false;
                if state.snapshot.phase != WorkerReadinessPhase::InvalidGeneration {
                    state.snapshot.phase = if state.factory_alive {
                        WorkerReadinessPhase::Retired
                    } else {
                        WorkerReadinessPhase::Closed
                    };
                }
            }
        }
        notify(&self.shared);
    }
}

struct Cancellation<'a> {
    cx: &'a Cx,
    token: Option<CancelWakerToken>,
}

impl Drop for Cancellation<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { self.cx.clear_cancel_waker(token); }
    }
}

async fn observe<F: Future + Send>(cx: &Cx, guard: &GenerationGuard, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cancellation = Cancellation { cx, token: None };
    poll_fn(|task| {
        cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token, task.waker()));
        // Observation must not acknowledge cancellation on behalf of a blind
        // user future or change the managed wrapper's terminal classification.
        if cx.is_cancel_requested() { guard.phase(WorkerReadinessPhase::Stopping); }
        future.as_mut().poll(task)
    }).await
}

/// Build a retained initialization/run factory and its independent readiness view.
///
/// Pass the factory to `DynamicSupervisor::start_worker`, a managed binding, or
/// the existing supervisor mailbox. No task, region, timer or initializer is
/// started here. The real managed controller supplies each generation and owns
/// its restart/backoff/drain. Do not invoke the factory for overlapping workers.
///
/// A successful initializer returns one owned state (which need not be Clone or
/// Sync). Run construction consumes it BEFORE Ready is published. If cancellation
/// arrives during successful initialization, run STILL receives the state so it
/// can clean up, but Ready is not published. The run future owns normal/failed
/// cleanup and may use the runtime's resource scopes; this adapter does not add
/// asynchronous destructors or repair partially acquired resources after panic.
/// Initialization failure never invokes run. Typed outcomes and panics retain
/// the existing managed semantics. All callbacks/polls/destructors must return.
///
/// The view stores only the latest metadata, with no unbounded generation log.
/// Observer memory is proportional to live waits; readiness is not a health or
/// quiescence guarantee and successful initialization can be followed by failure.
#[must_use = "run the retained factory through a managed supervisor"]
pub fn initialized_worker<R, E, I, IF, U, UF>(
    initialize: I,
    run: U,
) -> (impl ManagedChildFactory<E>, WorkerReadiness)
where
    R: Send + 'static,
    E: Send + 'static,
    I: Fn(Cx, ManagedGeneration) -> IF + Send + Sync + 'static,
    IF: Future<Output = Outcome<R, E>> + Send + 'static,
    U: Fn(Cx, ManagedGeneration, R) -> UF + Send + Sync + 'static,
    UF: Future<Output = Outcome<(), E>> + Send + 'static,
{
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            snapshot: WorkerReadinessState { generation: None, phase: WorkerReadinessPhase::NotStarted },
            factory_alive: true, active: false,
        }),
        changed: Notify::new(),
    });
    let readiness = WorkerReadiness { shared: Arc::clone(&shared) };
    let owner = FactoryOwner(shared);
    let initialize = Arc::new(initialize);
    let run = Arc::new(run);
    let factory = move |cx: Cx, generation: ManagedGeneration| {
        let guard = owner.begin(&cx, generation);
        let initialize = Arc::clone(&initialize);
        let run = Arc::clone(&run);
        async move {
            let Some(guard) = guard else {
                return Outcome::Panicked(PanicPayload::new("invalid initialized worker generation"));
            };
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(cx.cancel_reason().unwrap_or_else(CancelReason::shutdown));
            }
            let state = match observe(&cx, &guard, initialize(cx.clone(), generation)).await {
                Outcome::Ok(state) => state,
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(panic) => return Outcome::Panicked(panic),
            };
            let running = run(cx.clone(), generation, state);
            if cx.is_cancel_requested() {
                guard.phase(WorkerReadinessPhase::Stopping);
            } else {
                guard.phase(WorkerReadinessPhase::Ready);
            }
            observe(&cx, &guard, running).await
        }
    };
    (factory, readiness)
}

#[cfg(test)]
mod tests;
