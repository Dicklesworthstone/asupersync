//! Cancellation-owning joins (br-asupersync-1sngsf, owner propagation).
//!
//! Raw joins remain uninterruptible observation. These explicit collectors also
//! own the cancellation request for all supplied handles, including before the
//! returned future's first poll. They do not create or adopt tasks/regions.

use super::{Cx, Scope};
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelReason, Policy};
use std::any::Any;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::pin;
use std::task::{Context, Poll};

impl<P: Policy> Scope<'_, P> {
    /// Take cancellation ownership of two handles and join both to retirement.
    ///
    /// Unlike [`Self::join`], a cancellation request on `cx` is forwarded to
    /// every unfinished participant before waiting for any participant's drain.
    /// A child may therefore wait for a sibling to observe cancellation during
    /// cleanup without deadlocking this collector. Child tasks must use their
    /// own spawn-supplied contexts for cancel-aware operations.
    ///
    /// The returned tuple contains each handle's actual result: acknowledged
    /// typed cleanup results and panics are not replaced by a synthetic owner
    /// cancellation. Terminal publication is preserved even when retirement is
    /// still pending. The outer task's own outcome policy remains unchanged.
    ///
    /// Requests are observed even while `cx` is masked, as with `Cx::cancelled`;
    /// acknowledgement still goes through `checkpoint` and respects masking.
    /// A non-cooperative child can still delay completion indefinitely.
    ///
    /// Ownership transfers immediately, not on first poll. Dropping the future
    /// requests cancellation of every unfinished participant; their original
    /// regions remain responsible for eventual drain. Neither this method nor
    /// its drop path spawns cleanup work or moves a task into this scope's region.
    /// The returned future owns a context clone and does not borrow the scope
    /// or `cx`. No `Clone` or `Unpin` bound is imposed on the results.
    pub fn join_owned<T1, T2>(
        &self,
        cx: &Cx,
        first: TaskHandle<T1>,
        second: TaskHandle<T2>,
    ) -> impl Future<Output = (Result<T1, JoinError>, Result<T2, JoinError>)> + use<P, T1, T2>
    {
        collect(Owned {
            owner: cx.clone(),
            tasks: Pair {
                first: Some(first),
                second: Some(second),
                first_result: None,
                second_result: None,
            },
        })
    }

    /// Take cancellation ownership of all handles and return input-order results.
    ///
    /// This is the dynamic-arity form of [`Self::join_owned`]. Owner
    /// cancellation reaches the entire unfinished suffix before any drain wait;
    /// dropping an unpolled or partly completed collector does the same.
    /// Completion is observed through persistent handle registrations, not
    /// temporary join futures whose drop would cancel or unregister siblings.
    ///
    /// Empty input returns an empty vector. Collection uses linear total handle
    /// polls for an already-ready input and yields after 64 completions per poll.
    /// Results remain in input order, even when children finish out of order.
    /// Cancellation does not erase completed values, application errors or
    /// panics; the actual `TaskHandle` outcomes and retirement barriers govern.
    pub fn join_all_owned<T>(
        &self,
        cx: &Cx,
        handles: Vec<TaskHandle<T>>,
    ) -> impl Future<Output = Vec<Result<T, JoinError>>> + use<P, T> {
        let mut owned = Owned {
            owner: cx.clone(),
            tasks: Many {
                results: Vec::new(),
                handles,
                next: 0,
            },
        };
        // Install cancellation ownership before a potentially panicking
        // reservation, so a capacity failure cannot detach the input tasks.
        owned.tasks.results.reserve(owned.tasks.handles.len());
        collect(owned)
    }
}

trait Collection {
    type Output;
    fn poll_results(&mut self, task: &mut Context<'_>) -> Poll<Self::Output>;
    fn cancel_unfinished(&self, reason: &CancelReason);
}

// This guard is an async function argument, so it is captured immediately even
// if collect's body never starts. Raw TaskHandle drop alone does not cancel.
struct Owned<C: Collection> {
    owner: Cx,
    tasks: C,
}

impl<C: Collection> Drop for Owned<C> {
    fn drop(&mut self) {
        let reason = self.owner.cancel_reason()
            .unwrap_or_else(|| CancelReason::user("owned join dropped"));
        self.tasks.cancel_unfinished(&reason);
    }
}

async fn collect<C: Collection>(mut owned: Owned<C>) -> C::Output {
    let owner = owned.owner.clone();
    let mut cancelled = pin!(owner.cancelled());
    let mut forwarded = false;
    poll_fn(|task| {
        // Ready information wins over a simultaneous request; do not abort a
        // task that has already published its value but is awaiting retirement.
        if let Poll::Ready(results) = owned.tasks.poll_results(task) {
            return Poll::Ready(results);
        }
        if !forwarded && cancelled.as_mut().poll(task).is_ready() {
            forwarded = true;
            let reason = owner.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("owned join owner cancelled"));
            let _ = owner.checkpoint();
            owned.tasks.cancel_unfinished(&reason);
            // One transition wake closes the case where abort synchronously
            // retires a participant. No self-wake loop while cleanup is parked.
            task.waker().wake_by_ref();
        }
        Poll::Pending
    }).await
}

// A custom waker can panic. Still publish cancellation to every sibling before
// propagating the first panic; during an existing unwind do not double-panic.
type WakePanic = Box<dyn Any + Send>;

fn cancel_one<T>(
    handle: &TaskHandle<T>,
    reason: &CancelReason,
    first_panic: &mut Option<WakePanic>,
) {
    if handle.terminal_published() {
        return;
    }
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
        handle.abort_with_reason(reason.clone());
    })) && first_panic.is_none() {
        *first_panic = Some(payload);
    }
}

fn finish_cancel(first_panic: Option<WakePanic>) {
    if !std::thread::panicking() && let Some(payload) = first_panic {
        resume_unwind(payload);
    }
}

struct Pair<T1, T2> {
    first: Option<TaskHandle<T1>>,
    second: Option<TaskHandle<T2>>,
    first_result: Option<Result<T1, JoinError>>,
    second_result: Option<Result<T2, JoinError>>,
}

impl<T1, T2> Collection for Pair<T1, T2> {
    type Output = (Result<T1, JoinError>, Result<T2, JoinError>);

    fn poll_results(&mut self, task: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(handle) = self.first.as_mut()
            && let Poll::Ready(result) = handle.poll_join(task)
        {
            self.first_result = Some(result);
            self.first = None;
        }
        if let Some(handle) = self.second.as_mut()
            && let Poll::Ready(result) = handle.poll_join(task)
        {
            self.second_result = Some(result);
            self.second = None;
        }
        if self.first.is_none() && self.second.is_none() {
            Poll::Ready((
                self.first_result.take().expect("first join result already returned"),
                self.second_result.take().expect("second join result already returned"),
            ))
        } else {
            Poll::Pending
        }
    }

    fn cancel_unfinished(&self, reason: &CancelReason) {
        let mut first_panic = None;
        if let Some(handle) = &self.first {
            cancel_one(handle, reason, &mut first_panic);
        }
        if let Some(handle) = &self.second {
            cancel_one(handle, reason, &mut first_panic);
        }
        finish_cancel(first_panic);
    }
}

struct Many<T> {
    handles: Vec<TaskHandle<T>>,
    next: usize,
    results: Vec<Result<T, JoinError>>,
}

impl<T> Collection for Many<T> {
    type Output = Vec<Result<T, JoinError>>;

    fn poll_results(&mut self, task: &mut Context<'_>) -> Poll<Self::Output> {
        for _ in 0..64 {
            let Some(handle) = self.handles.get_mut(self.next) else {
                return Poll::Ready(std::mem::take(&mut self.results));
            };
            match handle.poll_join(task) {
                Poll::Ready(result) => {
                    self.results.push(result);
                    self.next += 1;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.next == self.handles.len() {
            Poll::Ready(std::mem::take(&mut self.results))
        } else {
            task.waker().wake_by_ref();
            Poll::Pending
        }
    }

    fn cancel_unfinished(&self, reason: &CancelReason) {
        let mut first_panic = None;
        for handle in &self.handles[self.next..] {
            cancel_one(handle, reason, &mut first_panic);
        }
        finish_cancel(first_panic);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "owned_join/tests.rs"]
mod tests;
