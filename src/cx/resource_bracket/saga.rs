//! Runtime-owned asynchronous forward steps and reverse compensation.
//!
//! [`Cx::spawn_saga`] retains the undo values of successful steps inside the
//! existing bracket controller. A step reserves registration and result storage
//! BEFORE invoking its forward action. The action's returned value becomes the
//! compensation's exclusive owner without an intervening cancellation checkpoint
//! or await. Typed keys borrow these heterogeneous values during subsequent work.
//!
//! Commit is decided only after the work task and its entire child region have
//! drained, including finalizers. Any failed, cancelled, panicked or abandoned
//! step makes rollback sticky, even if the body catches its error. A failed body,
//! cancelled task in the work region, retained descendant panic, finalizer
//! failure, or controller cancellation observed before the decision also requires
//! rollback. Each successful step is then compensated once
//! in reverse order; a compensation failure never skips the older entries.
//! Ordinary errors/cancellation in explicitly nested regions are not folded into
//! the runtime's parent close receipt; the body must propagate them as failure
//! when they should abort the saga. Nested task panics ARE retained separately.
//!
//! This is an in-memory saga, not an atomic transaction or durable/cross-node
//! obligation protocol. An action that never returns a successful undo value
//! remains responsible for its own partial effects. Cleanup callbacks must drain
//! any work they start. Cancellation masking does not reopen a Closing ancestor
//! for task, region, or obligation admission: a remote undo can still be refused,
//! and that error is retained. Runtime hard-abort/process exit and callbacks that
//! do not return remain outside the completion guarantee.
//!
//! The finite registration capacity and aggregate masked-poll allowance are
//! explicit bounds. They do not promise a hard cleanup timeout. After masking
//! expires, unfinished compensation remains owned and continues unmasked. Once
//! the controller decides to commit, later cancellation cannot retroactively
//! undo it; the decision and any later lifecycle cancellation are reported
//! independently. The synchronous [`crate::remote::Saga`] is unchanged.

use super::stack::{ResourceCleanupReport, ResourceKey, ResourceStack, ResourceStackError};
use super::{
    BracketConfig, BracketHandle, BracketPhase, BracketReport, BracketUseFuture, Cx, Outcome,
};
use crate::runtime::{JoinError, SpawnError};
use crate::types::{PanicPayload, TaskId};
use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

/// Body future borrowing a controller-owned saga scope.
pub type AsyncSagaFuture<'a, T, E> = BracketUseFuture<'a, T, E>;

/// Forward-step evidence, separate from its returned typed phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsyncSagaStepState {
    /// The forward wait has not completed, or was abandoned while pending.
    Pending,
    /// Both the forward outcome and future retirement succeeded.
    Succeeded,
    /// The outcome was not successful, or retiring its future panicked.
    Failed,
}

/// One admitted forward action, in invocation order.
#[derive(Debug)]
pub struct AsyncSagaStep {
    /// Matches the undo key and compensation report index on successful return.
    pub index: usize,
    /// Caller-supplied diagnostic name; not a remote idempotency key.
    pub description: String,
    /// Retained even when application code ignores a returned step error.
    pub state: AsyncSagaStepState,
}

/// Why the forward phase can no longer commit or admit another step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsyncSagaAbortReason {
    /// The action never completed its borrowing wait.
    IncompleteStep,
    /// Inspect the step's returned `BracketPhase` for its exact typed outcome.
    FailedStep,
    /// Refused before the next forward factory was invoked.
    Registration(ResourceStackError),
}

/// Sticky failure; catching a step's error does not clear this evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsyncSagaAbort {
    /// Failed or refused zero-based step index.
    pub step: usize,
    /// Registration or forward-phase reason.
    pub reason: AsyncSagaAbortReason,
}

/// Decision made after actual child quiescence, before retiring undo owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsyncSagaDecision {
    /// Forward work and its subtree succeeded; no compensation is invoked.
    Commit,
    /// Attempt every registered compensation, even when another one fails.
    Rollback,
}

/// Destruction of a committed step's undo value and unused compensation factory.
/// The two owners are retired under separate panic guards, newest first.
#[derive(Debug)]
pub struct AsyncSagaDisposal {
    /// Original step index.
    pub step: usize,
    /// Panic while dropping the now-unneeded undo value.
    pub undo_panic: Option<PanicPayload>,
    /// Independent panic while dropping the unused compensation's captures.
    pub compensation_panic: Option<PanicPayload>,
}

/// Final decision and all compensation/disposal evidence.
#[derive(Debug)]
pub struct AsyncSagaResolution<C> {
    /// Remains Commit even if cancellation arrives after the commit decision.
    pub decision: AsyncSagaDecision,
    /// Admitted steps in forward order, including any incomplete/failed step.
    pub steps: Vec<AsyncSagaStep>,
    /// Sticky step-level abort, independently of body/drain failures.
    pub abort: Option<AsyncSagaAbort>,
    /// Retained nested-region panic, which is separate from the ordinary close
    /// outcome. Catching a descendant's join error cannot erase this evidence.
    pub descendant_panic: Option<PanicPayload>,
    /// Every compensation's exact typed result, in LIFO order. None on Commit.
    pub compensations: Option<ResourceCleanupReport<C>>,
    /// Commit-only disposal results in LIFO order; empty on Rollback.
    pub disposals: Vec<AsyncSagaDisposal>,
}

impl<C> AsyncSagaResolution<C> {
    /// All required compensation or commit disposal completed without failure.
    /// Successful rollback does not mean the forward operation succeeded.
    #[must_use]
    pub fn cleanup_succeeded(&self) -> bool {
        match self.decision {
            AsyncSagaDecision::Commit => self
                .disposals
                .iter()
                .all(|entry| entry.undo_panic.is_none() && entry.compensation_panic.is_none()),
            AsyncSagaDecision::Rollback => self
                .compensations
                .as_ref()
                .is_some_and(ResourceCleanupReport::is_success),
        }
    }
}

/// Exclusive undo owner, exposed in `lifecycle.unreleased` if region close fails.
/// No asynchronous compensation is attempted by Drop.
#[derive(Debug)]
#[must_use = "retain until user quiescence permits asynchronous compensation"]
pub struct AsyncSaga<C> {
    stack: ResourceStack<C>,
    steps: Vec<AsyncSagaStep>,
    abort: Option<AsyncSagaAbort>,
    disposals: Vec<AsyncSagaDisposal>,
}

impl<C: Send + 'static> AsyncSaga<C> {
    fn new(capacity: usize) -> Self {
        Self {
            stack: ResourceStack::new(capacity),
            steps: Vec::new(),
            abort: None,
            disposals: Vec::new(),
        }
    }

    /// Admitted forward work; does not execute any callbacks.
    #[must_use]
    pub fn steps(&self) -> &[AsyncSagaStep] {
        &self.steps
    }

    /// Step-level refusal/failure, even when its returned error was ignored.
    #[must_use]
    pub fn abort_reason(&self) -> Option<AsyncSagaAbort> {
        self.abort
    }

    /// Recover a withheld saga ONLY after independently proving user quiescence.
    ///
    /// This is the recovery path when a failed runtime close leaves this owner
    /// in `lifecycle.unreleased`. No mask is added; the caller owns that policy.
    /// Dropping this borrowing wait retains the current compensation and prior
    /// results. Resuming it never re-invokes a terminal compensation.
    pub async fn compensate_after_quiescence(&mut self, cx: &Cx) -> &ResourceCleanupReport<C> {
        self.stack.close(cx).await
    }
}

/// Work-phase access. Cannot commit, close, extract, or replace the undo owner.
pub struct AsyncSagaScope<'a, C> {
    cx: Cx,
    saga: &'a mut AsyncSaga<C>,
}

impl<C> fmt::Debug for AsyncSagaScope<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncSagaScope")
            .field("steps", &self.saga.steps.len())
            .field("abort", &self.saga.abort)
            .finish_non_exhaustive()
    }
}

impl<C: Send + 'static> AsyncSagaScope<'_, C> {
    /// Execute a forward action and register its successful returned undo value.
    ///
    /// `Err` is a pre-effect registration refusal. `Ok(phase)` preserves the
    /// exact forward outcome and independent future-retirement panic; inspect
    /// BOTH. An `Outcome::Ok(key)` with a retirement panic still owns its undo
    /// value and forces rollback. A failed/panicked action that returns no undo
    /// value owns its own partial-effect cleanup.
    ///
    /// Registration, failure, cancellation and abandonment are sticky. Later
    /// calls return `ResourceStackError::Closed` without invoking a new factory.
    /// The forward Cx is the actual saga child's Cx, never an ambient context.
    pub async fn step<R, E, A, AF, F, FF>(
        &mut self,
        description: impl Into<String>,
        forward: A,
        compensate: F,
    ) -> Result<BracketPhase<ResourceKey<R>, E>, ResourceStackError>
    where
        R: Send + 'static,
        A: FnOnce(Cx) -> AF,
        AF: Future<Output = Outcome<R, E>>,
        F: FnOnce(Cx, R) -> FF + Send + 'static,
        FF: Future<Output = Outcome<(), C>> + Send + 'static,
    {
        if self.saga.abort.is_some() {
            return Err(ResourceStackError::Closed);
        }
        let index = self.saga.steps.len();
        let description = description.into();
        let reserve = self
            .saga
            .steps
            .try_reserve(1)
            .and_then(|()| self.saga.disposals.try_reserve(index + 1));
        if reserve.is_err() {
            let error = ResourceStackError::Allocation;
            self.saga.abort = Some(AsyncSagaAbort {
                step: index,
                reason: AsyncSagaAbortReason::Registration(error),
            });
            return Err(error);
        }
        let slot = match self.saga.stack.reserve() {
            Ok(slot) => slot,
            Err(error) => {
                self.saga.abort = Some(AsyncSagaAbort {
                    step: index,
                    reason: AsyncSagaAbortReason::Registration(error),
                });
                return Err(error);
            }
        };
        self.saga.steps.push(AsyncSagaStep {
            index,
            description,
            state: AsyncSagaStepState::Pending,
        });
        // Install the failure latch BEFORE entering the action. Dropping this
        // borrowing step future while Pending must never permit a later commit.
        self.saga.abort = Some(AsyncSagaAbort {
            step: index,
            reason: AsyncSagaAbortReason::IncompleteStep,
        });
        let phase = slot.acquire(&self.cx, forward, compensate).await;
        if phase.is_success() {
            self.saga.steps[index].state = AsyncSagaStepState::Succeeded;
            self.saga.abort = None;
        } else {
            self.saga.steps[index].state = AsyncSagaStepState::Failed;
            self.saga.abort = Some(AsyncSagaAbort {
                step: index,
                reason: AsyncSagaAbortReason::FailedStep,
            });
        }
        Ok(phase)
    }

    /// Borrow an earlier undo value through its unforgeable, saga-specific key.
    #[must_use]
    pub fn get<R: 'static>(&self, key: &ResourceKey<R>) -> Option<&R> {
        self.saga.stack.get(key)
    }

    /// Mutate an undo value; compensation receives the replacement if replaced.
    /// Explicitly extracted/interior resources remain the caller's responsibility.
    pub fn get_mut<R: 'static>(&mut self, key: &ResourceKey<R>) -> Option<&mut R> {
        self.saga.stack.get_mut(key)
    }

    /// Sticky abort status without invoking callbacks or altering the decision.
    #[must_use]
    pub fn abort_reason(&self) -> Option<AsyncSagaAbort> {
        self.saga.abort
    }
}

/// Original forward lifecycle and independently retained commit/rollback result.
#[derive(Debug)]
#[must_use = "inspect both lifecycle and resolution, including compensation errors"]
pub struct AsyncSagaReport<T, E, C> {
    /// Bracket-owned task, child/finalizer drain and cancellation evidence. A
    /// release `Err(())` summarizes a compensation/disposal failure whose exact
    /// result remains in `resolution`. Close failure retains the whole undo owner.
    pub lifecycle: BracketReport<AsyncSaga<C>, T, E, ()>,
    /// None if acquisition never ran or runtime close could not prove quiescence.
    pub resolution: Option<AsyncSagaResolution<C>>,
}

impl<T, E, C> AsyncSagaReport<T, E, C> {
    /// Whether commit was decided, independently of cancellation arriving later.
    #[must_use]
    pub fn committed(&self) -> bool {
        self.resolution
            .as_ref()
            .is_some_and(|resolution| resolution.decision == AsyncSagaDecision::Commit)
    }

    /// Commit plus successful lifecycle and disposal. Rollback is never success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.committed()
            && self.lifecycle.is_success()
            && self
                .resolution
                .as_ref()
                .is_some_and(AsyncSagaResolution::cleanup_succeeded)
    }
}

/// Runtime-owned controller. Dropping the handle requests cancellation; it never
/// tries to run an asynchronous compensation in Drop. Retain and join for proof.
#[must_use = "retain and join to observe the saga decision and compensation results"]
pub struct AsyncSagaHandle<T, E, C> {
    bracket: BracketHandle<AsyncSaga<C>, T, E, ()>,
    resolution: Arc<Mutex<Option<AsyncSagaResolution<C>>>>,
}

impl<T, E, C> fmt::Debug for AsyncSagaHandle<T, E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncSagaHandle")
            .field("bracket", &self.bracket)
            .finish_non_exhaustive()
    }
}

impl<T, E, C> AsyncSagaHandle<T, E, C> {
    /// Existing bracket controller task identity.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.bracket.task_id()
    }

    /// Request cooperative cancellation; existing undo work stays owned.
    pub fn abort(&self) {
        self.bracket.abort();
    }

    /// Join once, without aborting on cancellation of the caller's Cx. Dropping
    /// this borrowing wait preserves the controller and eventual report.
    pub async fn join(&mut self) -> Result<AsyncSagaReport<T, E, C>, JoinError> {
        let lifecycle = self.bracket.join().await?;
        let resolution = self.resolution.lock().take();
        Ok(AsyncSagaReport {
            lifecycle,
            resolution,
        })
    }
}

impl Cx {
    /// Submit an owned asynchronous saga with bounded undo registration.
    ///
    /// The body receives its child Cx and a restricted scope. Each `step` can
    /// return a different `Send` undo type; compensations share error type C.
    /// Successful keys borrow those values for subsequent steps. The final body
    /// result is owned and retained separately from every compensation result.
    ///
    /// Commit requires clean body/future retirement, successful child drain and
    /// finalizers, no sticky step failure, and no cancellation observed before
    /// the decision. Direct work-region cancellation and retained nested-region
    /// panics cause rollback even when the body returns Ok. Ordinary nested-region
    /// error/cancellation must be propagated by the body when it should abort the
    /// saga. No compensation runs until the work subtree is quiescent.
    ///
    /// `config.release_masked_polls` covers the ENTIRE rollback/disposal future;
    /// it never resets per step and is not a hard timeout. New admission under a
    /// Closing ancestor may fail despite masking. Keep/report those failures.
    /// Setup/submission refusal returns SpawnError before forward work. A returned
    /// handle does not prove region admission: later controller-admission refusal
    /// is observed through `handle.join()`, without starting forward effects.
    pub fn spawn_saga<T, E, C, U>(
        &self,
        config: BracketConfig,
        capacity: usize,
        work: U,
    ) -> Result<AsyncSagaHandle<T, E, C>, SpawnError>
    where
        T: Send + 'static,
        E: Send + 'static,
        C: Send + 'static,
        U: for<'a> FnOnce(Cx, AsyncSagaScope<'a, C>) -> AsyncSagaFuture<'a, T, E> + Send + 'static,
    {
        let resolution = Arc::new(Mutex::new(None));
        let publication = Arc::clone(&resolution);
        let bracket = self.spawn_bracket_with_exit(
            config,
            move |_| async move { Outcome::<_, E>::Ok(AsyncSaga::<C>::new(capacity)) },
            move |cx, saga| work(cx.clone(), AsyncSagaScope { cx, saga }),
            move |cx, mut saga, exit| async move {
                let decision = if exit.clean
                    && saga.abort.is_none()
                    && saga
                        .steps
                        .iter()
                        .all(|step| step.state == AsyncSagaStepState::Succeeded)
                {
                    AsyncSagaDecision::Commit
                } else {
                    AsyncSagaDecision::Rollback
                };
                match decision {
                    AsyncSagaDecision::Commit => {
                        let disposals = &mut saga.disposals;
                        saga.stack
                            .discard(|step, undo_panic, compensation_panic| {
                                disposals.push(AsyncSagaDisposal {
                                    step,
                                    undo_panic,
                                    compensation_panic,
                                });
                            })
                            .await;
                    }
                    AsyncSagaDecision::Rollback => {
                        saga.stack.close(&cx).await;
                    }
                }
                let AsyncSaga {
                    stack,
                    steps,
                    abort,
                    disposals,
                } = saga;
                let compensations = match decision {
                    AsyncSagaDecision::Commit => None,
                    AsyncSagaDecision::Rollback => Some(stack.into_cleanup_report()),
                };
                let result = AsyncSagaResolution {
                    decision,
                    steps,
                    abort,
                    descendant_panic: exit.descendant_panic,
                    compensations,
                    disposals,
                };
                let success = result.cleanup_succeeded();
                // No application callbacks, errors or destructors run under this
                // private publication lock, including replacement retirement.
                let old = publication.lock().replace(result);
                debug_assert!(old.is_none(), "one resolution per saga controller");
                drop(old);
                if success {
                    Outcome::Ok(())
                } else {
                    Outcome::Err(())
                }
            },
        )?;
        Ok(AsyncSagaHandle {
            bracket,
            resolution,
        })
    }
}

#[cfg(test)]
mod tests;
