//! Sequential fallback with a fully owned and drained subtree per attempt.
//!
//! Extends the scoped ownership boundary to the fallback chains described by
//! the core design, sections 6 and 12 (asupersync-bi2462, asupersync-16rul).

use super::child_region::RegionQuiescence;
use super::scoped_timeout::ScopedTimeoutClose;
use super::{ChildRegionError, Cx, cap};
use crate::runtime::spawn_mailbox::{BranchRegionSlot, SpawnGateway};
use crate::runtime::state::SpawnError;
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelReason, Outcome, RegionId};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

/// Why a scoped fallback chain stopped trying operations.
///
/// This describes selection, independently of each attempt's actual task and
/// cleanup receipts. In particular, a selected success does not certify that
/// its descendants or finalizers completed successfully.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedFirstOkStop {
    /// No factories were supplied. No runtime authority is needed.
    Empty,
    /// This attempt returned `Ok` before owner cancellation was observed.
    /// Later owner cancellation or cleanup failure does not erase selection;
    /// inspect the selected attempt's close receipt independently.
    Succeeded {
        /// Zero-based input position of the selected attempt.
        index: usize,
    },
    /// Every supplied factory returned a typed `Err`, and every attempt's
    /// subtree closed without a cleanup or descendant failure.
    AllFailed,
    /// The explicit owner requested cancellation before a success was selected.
    /// The complete reason and any acknowledged late task result are retained.
    Cancelled(CancelReason),
    /// Submission or strict private-region admission refused this attempt.
    /// The attempt receipt retains any available submission or join error.
    NotAdmitted {
        /// Zero-based input position of the refused attempt.
        index: usize,
    },
    /// This task failed to join normally, for example by cancellation or panic.
    /// Its exact join error is retained in the attempt receipt.
    TaskFailed {
        /// Zero-based input position of the failed task.
        index: usize,
    },
    /// A typed failure could have led to another attempt, but its subtree
    /// failed cleanup or could not certify quiescence. No fallback was started.
    CleanupFailed {
        /// Zero-based input position of the attempt whose cleanup failed.
        index: usize,
    },
}

/// What an attempt actually returned, independently of why selection stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedFirstOkTask<T, E> {
    /// The admitted wrapper refused the user factory before invoking it.
    NotStarted,
    /// Submission was refused before a task handle was returned.
    SubmissionFailed(SpawnError),
    /// The actual task result, including acknowledged late values and errors.
    /// A join error can also describe admission failure before factory invocation.
    Joined(Result<Result<T, E>, JoinError>),
}

/// The actual close receipt for an attempt's entire private subtree.
pub type ScopedFirstOkClose = ScopedTimeoutClose;

/// Independent task and whole-region cleanup receipts for one attempted input.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedFirstOkAttempt<T, E> {
    /// Zero-based input position. Receipts remain in input order.
    pub index: usize,
    /// The task's real result, without replacing it with the chain's stop reason.
    pub task: ScopedFirstOkTask<T, E>,
    /// The private region, if admission minted one.
    pub region_id: Option<RegionId>,
    /// Whole-subtree close, including descendant and finalizer failures.
    /// `None` means no private region was published. An error does not certify
    /// quiescence, even when the body itself returned a value.
    pub close: Option<Result<ScopedFirstOkClose, ChildRegionError>>,
}

/// Selection plus every attempted operation's task and cleanup receipts.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect both selection and every cleanup receipt"]
pub struct ScopedFirstOkReport<T, E> {
    /// The condition that stopped the sequential fallback chain.
    pub stop: ScopedFirstOkStop,
    /// Attempted inputs in input order, including a refused submission.
    /// Factories after the stopping attempt were never invoked.
    pub attempts: Vec<ScopedFirstOkAttempt<T, E>>,
}

/// Refusal before the chain can use its explicit owner's runtime.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedFirstOkError {
    /// The explicit context has no usable spawn gateway. Per-attempt submission
    /// failures instead remain in the report alongside any earlier typed errors.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedFirstOkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "scoped first_ok requires an owning runtime: {error}"),
        }
    }
}

impl std::error::Error for ScopedFirstOkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
        }
    }
}

enum BodyResult<T, E> {
    Value(Result<T, E>),
    NotStarted(Option<CancelReason>),
}

/// Installed before submission, including before an enqueue notifier can panic.
/// Late admission inherits a close request even without a returned task handle.
struct OwnedAttempt<T, E> {
    region: Arc<BranchRegionSlot>,
    handle: Option<TaskHandle<BodyResult<T, E>>>,
    armed: bool,
}

impl<T, E> OwnedAttempt<T, E> {
    fn request_stop(&self, reason: CancelReason) {
        // The body may be joining a child whose cleanup needs cancellation.
        // Request the entire subtree's close before waiting for either task.
        let _ = self.region.request_close(reason.clone());
        if let Some(handle) = &self.handle
            && !handle.terminal_published()
        {
            handle.abort_with_reason(reason);
        }
    }

    async fn quiesce(
        &mut self,
        gateway: &Arc<SpawnGateway>,
    ) -> (
        Option<RegionId>,
        Option<Result<ScopedFirstOkClose, ChildRegionError>>,
    ) {
        let receipt = if let Some(minted) = self.region.get() {
            let closed =
                RegionQuiescence::watch(minted.close_notify(), Some(Arc::clone(gateway))).await;
            let outcome = closed.and_then(|()| {
                minted
                    .close_outcome()
                    .map(|receipt| ScopedFirstOkClose {
                        outcome: receipt.outcome,
                        cleanup_outcome: receipt.cleanup_outcome,
                        descendant_panic: receipt.descendant_panic,
                    })
                    .ok_or(ChildRegionError::RuntimeUnavailable)
            });
            (Some(minted.region_id), Some(outcome))
        } else {
            (None, None)
        };
        self.armed = false;
        receipt
    }
}

impl<T, E> Drop for OwnedAttempt<T, E> {
    fn drop(&mut self) {
        if self.armed {
            self.request_stop(CancelReason::user("scoped first_ok dropped"));
        }
    }
}

fn owner_cancel_reason<Caps>(owner: &Cx<Caps>) -> CancelReason {
    owner
        .cancel_reason()
        .unwrap_or_else(|| CancelReason::user("scoped first_ok owner cancelled"))
}

fn cleanup_failed(close: Option<&Result<ScopedFirstOkClose, ChildRegionError>>) -> bool {
    match close {
        Some(Ok(receipt)) => {
            receipt.descendant_panic.is_some()
                || matches!(&receipt.outcome, Outcome::Err(_) | Outcome::Panicked(_))
                || receipt
                    .cleanup_outcome
                    .as_ref()
                    .is_some_and(|outcome| !outcome.is_ok())
        }
        Some(Err(_)) | None => true,
    }
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Tries factories in input order, closing and draining each attempt's
    /// entire private subtree before starting a fallback or returning success.
    ///
    /// Like [`super::Scope::first_ok`], this is sequential fallback: only a typed
    /// `Err` allows another attempt. Each factory receives its actual admitted
    /// context, preserving the owner's capability type. Work spawned through
    /// that context belongs to the attempt's private subtree. The body result
    /// requests subtree close, including after success, and this method waits
    /// for the body, descendants, pending admissions, obligations, and finalizers.
    /// Descendant or cleanup failure after a typed error prevents fallback.
    /// Input is consumed lazily: the next factory is pulled only after the
    /// current attempt drains. The chain yields after every 64 typed failures
    /// so even a ready, unbounded fallback generator cannot monopolize a worker.
    /// Once a stop is selected, unused factories are dropped after requesting
    /// subtree close and before waiting for cleanup. Factories retained for a
    /// possible fallback must not hold resources needed to close an earlier
    /// failed attempt.
    ///
    /// Cancellation observation is mask-agnostic, like [`Cx::cancelled`], and
    /// neither acknowledges the owner's request nor changes its mask. Owner
    /// cancellation wins a simultaneous task join while useful work is pending.
    /// A success already selected before cleanup stays selected if the owner is
    /// cancelled during cleanup; its real close receipt still records failures.
    /// After a typed error's cleanup, cancellation is checked again before any
    /// further attempt, including before reporting that all attempts failed.
    /// A task that acknowledges cancellation can return a late value or typed
    /// error; the receipt preserves it without changing a selected cancellation.
    ///
    /// Strict private-region admission refuses user work if no distinct region
    /// can be minted. Retained contexts, including nested race winners, cannot
    /// spawn outside the owned subtree. Explicitly captured authority for an
    /// unrelated region remains unrelated authority: use the supplied context
    /// for owned work. No timer capability or ambient context is required.
    ///
    /// Dropping the future requests close for the active subtree, including a
    /// region whose admission has not yet published. The runtime remains the
    /// asynchronous cleanup owner. Cooperative cleanup has no time bound and
    /// is never replaced by forced destruction. Retained `T` and `E` values must
    /// not hold obligations whose release is required to close their own region.
    ///
    /// # Errors
    ///
    /// A nonempty chain with an uncancelled owner requires its spawn gateway;
    /// missing authority returns [`ScopedFirstOkError`]. Per-attempt submission,
    /// admission, join, and cleanup failures remain in the report so earlier
    /// typed errors are not lost. Always inspect the close receipt independently
    /// of a selected success.
    ///
    /// ```
    /// use asupersync::{Cx, Outcome};
    /// use asupersync::cx::{ScopedFirstOkStop, ScopedFirstOkTask};
    ///
    /// async fn example(cx: &Cx) {
    ///     let factories = (0..3).map(|index| move |_attempt| async move {
    ///         if index == 1 { Ok(42_u32) } else { Err(index) }
    ///     });
    ///     let report = cx.first_ok_scoped(factories).await.expect("owning runtime");
    ///     assert!(matches!(report.stop, ScopedFirstOkStop::Succeeded { index: 1 }));
    ///     assert_eq!(report.attempts.len(), 2);
    ///     assert!(matches!(report.attempts[1].task, ScopedFirstOkTask::Joined(Ok(Ok(42)))));
    ///     let close = report.attempts[1].close.as_ref().expect("owned region")
    ///         .as_ref().expect("region quiesced");
    ///     assert!(matches!(close.outcome, Outcome::Ok(()) | Outcome::Cancelled(_)));
    ///     assert!(close.cleanup_outcome.as_ref().is_none_or(|outcome| outcome.is_ok()));
    ///     assert!(close.descendant_panic.is_none());
    /// }
    /// ```
    pub async fn first_ok_scoped<T, E, I, F, Fut>(
        &self,
        factories: I,
    ) -> Result<ScopedFirstOkReport<T, E>, ScopedFirstOkError>
    where
        I: IntoIterator<Item = F> + Send,
        I::IntoIter: Send,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        let mut attempts = Vec::new();
        if self.is_cancel_requested() {
            return Ok(ScopedFirstOkReport {
                stop: ScopedFirstOkStop::Cancelled(owner_cancel_reason(self)),
                attempts,
            });
        }
        let mut factories = Some(factories.into_iter());
        let Some(mut factory) = factories.as_mut().expect("input retained").next() else {
            return Ok(ScopedFirstOkReport {
                stop: ScopedFirstOkStop::Empty,
                attempts,
            });
        };
        let gateway = self
            .spawn_gateway_handle()
            .ok_or(ScopedFirstOkError::Spawn(SpawnError::RuntimeUnavailable))?;

        let mut index = 0_usize;
        loop {
            if self.is_cancel_requested() {
                return Ok(ScopedFirstOkReport {
                    stop: ScopedFirstOkStop::Cancelled(owner_cancel_reason(self)),
                    attempts,
                });
            }
            let region = Arc::new(BranchRegionSlot::owned(&gateway));
            let mut owned = OwnedAttempt {
                region: Arc::clone(&region),
                handle: None,
                armed: true,
            };
            let factory_region = Arc::clone(&region);
            let factory_owner = self.clone();
            let submitted = self.spawn_owned_branch(Arc::clone(&region), move |body| async move {
                // Ordinary races can admit their wrapper in the parent when
                // minting fails. Never run the user's factory on that path.
                if factory_region.get().is_none() {
                    return BodyResult::NotStarted(None);
                }
                if factory_owner.is_cancel_requested() {
                    return BodyResult::NotStarted(Some(owner_cancel_reason(&factory_owner)));
                }
                if factory_region.close_requested() || body.is_cancel_requested() {
                    return BodyResult::NotStarted(None);
                }
                BodyResult::Value(factory(body).await)
            });
            match submitted {
                Ok(handle) => owned.handle = Some(handle),
                Err(error) => {
                    owned.request_stop(CancelReason::user("scoped first_ok submission refused"));
                    drop(factories.take());
                    let (region_id, close) = owned.quiesce(&gateway).await;
                    attempts.push(ScopedFirstOkAttempt {
                        index,
                        task: ScopedFirstOkTask::SubmissionFailed(error),
                        region_id,
                        close,
                    });
                    return Ok(ScopedFirstOkReport {
                        stop: ScopedFirstOkStop::NotAdmitted { index },
                        attempts,
                    });
                }
            }

            let (mut stop, mut joined) = {
                let mut cancelled = std::pin::pin!(self.cancelled());
                poll_fn(|task| {
                    if cancelled.as_mut().poll(task).is_ready() {
                        return Poll::Ready((
                            Some(ScopedFirstOkStop::Cancelled(owner_cancel_reason(self))),
                            None,
                        ));
                    }
                    match owned
                        .handle
                        .as_mut()
                        .expect("attempt submitted")
                        .poll_join(task)
                    {
                        Poll::Ready(result) => Poll::Ready((None, Some(result))),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
            };
            let reason = match &stop {
                Some(ScopedFirstOkStop::Cancelled(reason)) => reason.clone(),
                _ => CancelReason::user("scoped first_ok attempt completed"),
            };
            owned.request_stop(reason);
            if stop.is_some() {
                // An unused factory can own the final sender or lease a child
                // needs to finish cleanup. Release the tail before even the
                // direct join when cancellation has already stopped selection.
                drop(factories.take());
            }
            if joined.is_none() {
                joined = Some(
                    poll_fn(|task| {
                        owned
                            .handle
                            .as_mut()
                            .expect("attempt submitted")
                            .poll_join(task)
                    })
                    .await,
                );
            }
            let task = match joined.expect("attempt joined") {
                Ok(BodyResult::Value(value)) => ScopedFirstOkTask::Joined(Ok(value)),
                Ok(BodyResult::NotStarted(reason)) => {
                    if stop.is_none() {
                        stop = Some(reason.map_or(
                            ScopedFirstOkStop::NotAdmitted { index },
                            ScopedFirstOkStop::Cancelled,
                        ));
                    }
                    ScopedFirstOkTask::NotStarted
                }
                Err(error) => ScopedFirstOkTask::Joined(Err(error)),
            };
            // Select before the unconditional close wait. Cancellation during
            // that wait cannot retroactively replace an already-selected value.
            if stop.is_none() {
                stop = match &task {
                    _ if region.get().is_none() => Some(ScopedFirstOkStop::NotAdmitted { index }),
                    ScopedFirstOkTask::Joined(Ok(Ok(_))) => {
                        Some(ScopedFirstOkStop::Succeeded { index })
                    }
                    ScopedFirstOkTask::Joined(Err(_)) => {
                        Some(ScopedFirstOkStop::TaskFailed { index })
                    }
                    _ => None,
                };
            }
            if stop.is_some() {
                drop(factories.take());
            }
            let (region_id, close) = owned.quiesce(&gateway).await;
            let failed_cleanup = cleanup_failed(close.as_ref());
            attempts.push(ScopedFirstOkAttempt {
                index,
                task,
                region_id,
                close,
            });
            if let Some(stop) = stop {
                return Ok(ScopedFirstOkReport { stop, attempts });
            }
            if failed_cleanup {
                return Ok(ScopedFirstOkReport {
                    stop: ScopedFirstOkStop::CleanupFailed { index },
                    attempts,
                });
            }
            if self.is_cancel_requested() {
                return Ok(ScopedFirstOkReport {
                    stop: ScopedFirstOkStop::Cancelled(owner_cancel_reason(self)),
                    attempts,
                });
            }
            index += 1;
            if index.is_multiple_of(64) {
                crate::runtime::yield_now().await;
                if self.is_cancel_requested() {
                    return Ok(ScopedFirstOkReport {
                        stop: ScopedFirstOkStop::Cancelled(owner_cancel_reason(self)),
                        attempts,
                    });
                }
            }
            factory = match factories.as_mut().expect("fallback input retained").next() {
                Some(next) => next,
                None => {
                    return Ok(ScopedFirstOkReport {
                        stop: ScopedFirstOkStop::AllFailed,
                        attempts,
                    });
                }
            };
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_first_ok_inline_tests.rs"]
mod tests;
