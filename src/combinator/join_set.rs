//! Dynamic-arity structured fan-out: spawn N tasks into a region and collect
//! their results.
//!
//! [`JoinSet`] is the region-aware, cancel-correct analog of the
//! ecosystem-standard `JoinSet` type. Members are spawned through the v2
//! [`Cx::spawn_in`](crate::cx::Cx::spawn_in) path into the **owning scope's
//! region**, so the region's quiescence guarantee still applies: the region
//! cannot close while a member is live, and dropping the set is a
//! *cancellation request* to every still-running member (region close is the
//! quiescence backstop that guarantees no orphans).
//!
//! ```no_run
//! use asupersync::{main, prelude::*};
//!
//! #[main]
//! async fn main(cx: &Cx) {
//!     let mut set = JoinSet::in_cx(cx);
//!     for i in 0..10_u32 {
//!         set.spawn(cx, move |_| async move { Ok::<_, ()>(i) }).expect("spawn");
//!     }
//!     let total = set.join_all(cx).await.into_iter().fold(0, |sum, outcome| {
//!         sum + outcome.expect("member ok")
//!     });
//!     assert_eq!(total, 45);
//! }
//! ```
//!
//! The API covers the common server patterns: [`JoinSet::in_cx`] for the
//! current region, [`JoinSet::new`] for an explicit scope, [`JoinSet::spawn`]
//! and [`JoinSet::spawn_local`] for member admission, [`JoinSet::join_next`]
//! for completion-order collection, [`JoinSet::join_all`] for spawn-order
//! collection, [`JoinSet::cancel_all`] for explicit drain after cancellation,
//! [`JoinSet::summary`] for severity aggregation, and abort-on-drop for
//! best-effort cancellation requests.
//!
//! [`join_next`]: JoinSet

use std::future::Future;
use std::task::Poll;

use crate::cx::{Cx, Scope};
use crate::runtime::JoinError;
use crate::runtime::TaskHandle;
use crate::runtime::state::SpawnError;
use crate::types::policy::FailFast;
use crate::types::{Outcome, PanicPayload, Policy, Severity};

/// A dynamically-sized collection of tasks spawned into a single region, whose
/// results are collected as four-valued [`Outcome`]s.
///
/// Each member runs as a real region task: pending-spawn accounting applies and
/// region close waits for it. Dropping a non-empty set requests cancellation of
/// every member it still owns (see the module docs).
pub struct JoinSet<'scope, T, E, P>
where
    P: Policy,
{
    scope: Scope<'scope, P>,
    handles: Vec<TaskHandle<Result<T, E>>>,
    summary: JoinSummary,
}

impl<'scope, T, E, P> JoinSet<'scope, T, E, P>
where
    P: Policy,
    T: Send + 'static,
    E: Send + 'static,
{
    /// Creates an empty set whose members will be spawned into `scope`'s
    /// region. The set shares the caller's region (no extra quiescence point);
    /// use a child region (a follow-up `in_child_region` constructor) when
    /// isolation is wanted.
    #[must_use]
    pub fn new(scope: &'scope Scope<'scope, P>) -> Self {
        Self {
            scope: clone_scope(scope),
            handles: Vec::new(),
            summary: JoinSummary::default(),
        }
    }

    /// Spawns a member into the set's region.
    ///
    /// The factory receives its own child [`Cx`] with the parent's inherited
    /// capabilities, exactly as [`Cx::spawn_in`] provides.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] when `cx` carries no spawn
    /// gateway for the set's region (see [`Cx::spawn_in`]). Admission-time
    /// denials are not errors here; they resolve as
    /// [`Outcome::Cancelled`] when the member is later collected.
    pub fn spawn<F, Fut>(&mut self, cx: &Cx, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
    {
        let handle = cx.spawn_in(&self.scope, f)?;
        self.handles.push(handle);
        Ok(())
    }

    /// Spawns a `!Send` member into the set's region, pinned to the current
    /// worker thread.
    ///
    /// This mirrors [`Cx::spawn_local_in`]: it fails off-worker or without a
    /// local spawn lane instead of silently falling back to a migratable task.
    ///
    /// # Errors
    ///
    /// Returns the same [`SpawnError`] variants as [`Cx::spawn_local_in`].
    pub fn spawn_local<F, Fut>(&mut self, cx: &Cx, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce(Cx) -> Fut + 'static,
        Fut: Future<Output = Result<T, E>> + 'static,
    {
        let handle = cx.spawn_local_in(&self.scope, f)?;
        self.handles.push(handle);
        Ok(())
    }

    /// Number of members currently owned by the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Returns `true` when the set owns no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Waits for every member to complete and returns their outcomes in spawn
    /// order.
    ///
    /// Each member's terminal state maps to an [`Outcome`]: a returned value is
    /// [`Outcome::Ok`]/[`Outcome::Err`] (from the member's own `Result`), a
    /// cancelled member is [`Outcome::Cancelled`], and a panicked member is
    /// [`Outcome::Panicked`]. Consuming the set means the awaited members are no
    /// longer abort-on-drop targets.
    pub async fn join_all(mut self, cx: &Cx) -> Vec<Outcome<T, E>> {
        self.drain_all(cx).await
    }

    /// Waits for the next member to complete and returns its terminal outcome.
    ///
    /// Results are yielded in completion order. When multiple members are
    /// already complete in the same poll, the earliest spawned ready member is
    /// selected as the deterministic tie-break. Pending members are polled with
    /// their join future's drop-abort path defused, so scanning for readiness
    /// never cancels still-running work.
    pub async fn join_next(&mut self, cx: &Cx) -> Option<Outcome<T, E>> {
        std::future::poll_fn(|task_cx| {
            if self.handles.is_empty() {
                return Poll::Ready(None);
            }

            for index in 0..self.handles.len() {
                let joined = {
                    let handle = &mut self.handles[index];
                    let mut join = handle.join(cx);
                    match std::pin::Pin::new(&mut join).poll(task_cx) {
                        Poll::Ready(joined) => Some(joined),
                        Poll::Pending => {
                            join.defuse_drop_abort();
                            None
                        }
                    }
                };

                if let Some(joined) = joined {
                    let outcome = join_to_outcome(joined);
                    self.summary.record(&outcome);
                    self.handles.remove(index);
                    return Poll::Ready(Some(outcome));
                }
            }

            Poll::Pending
        })
        .await
    }

    /// Requests cancellation for every member and drains all terminal outcomes
    /// in spawn order.
    ///
    /// Cancellation is requested through each task handle, then every member is
    /// joined so the caller observes the final [`Outcome`] for each child. This
    /// is the explicit counterpart to drop's best-effort cancellation request:
    /// `cancel_all` waits for the handles it owns before returning.
    pub async fn cancel_all(mut self, cx: &Cx) -> Vec<Outcome<T, E>> {
        for handle in &self.handles {
            handle.abort();
        }
        self.drain_all(cx).await
    }

    /// Returns the terminal-outcome summary observed so far by
    /// [`join_next`](Self::join_next).
    ///
    /// `join_all` and `cancel_all` consume the set and return all outcomes
    /// directly, so callers can build their own aggregate from that complete
    /// vector when they choose the spawn-order APIs.
    #[must_use]
    pub fn summary(&self) -> JoinSummary {
        self.summary
    }

    async fn drain_all(&mut self, cx: &Cx) -> Vec<Outcome<T, E>> {
        let mut handles = std::mem::take(&mut self.handles);
        let mut outcomes = Vec::with_capacity(handles.len());
        for handle in &mut handles {
            let outcome = join_to_outcome(handle.join(cx).await);
            self.summary.record(&outcome);
            outcomes.push(outcome);
        }
        outcomes
    }
}

impl<T, E> JoinSet<'static, T, E, FailFast>
where
    T: Send + 'static,
    E: Send + 'static,
{
    /// Creates an empty set bound to `cx`'s current region.
    ///
    /// This is the shortest blessed constructor for ordinary capability
    /// holders: it snapshots `cx.scope()` internally, so the caller does not
    /// need to bind a temporary [`Scope`] just to create a set.
    #[must_use]
    pub fn in_cx(cx: &Cx) -> Self {
        Self {
            scope: cx.scope(),
            handles: Vec::new(),
            summary: JoinSummary::default(),
        }
    }
}

impl<T, E, P> Drop for JoinSet<'_, T, E, P>
where
    P: Policy,
{
    fn drop(&mut self) {
        // Drop is a cancellation *request* to any member that has not yet been
        // collected; region close remains the quiescence backstop that
        // guarantees no orphans. Already-finished handles treat this as a
        // no-op.
        for handle in &self.handles {
            handle.abort();
        }
    }
}

/// Folds a task-join result into the four-valued [`Outcome`] lattice.
fn join_to_outcome<T, E>(joined: Result<Result<T, E>, JoinError>) -> Outcome<T, E> {
    match joined {
        Ok(Ok(value)) => Outcome::Ok(value),
        Ok(Err(error)) => Outcome::Err(error),
        Err(JoinError::Cancelled(reason)) => Outcome::Cancelled(reason),
        Err(JoinError::Panicked(payload)) => Outcome::Panicked(payload),
        Err(JoinError::PolledAfterCompletion) => {
            Outcome::Panicked(PanicPayload::new("join handle polled after completion"))
        }
    }
}

fn clone_scope<'scope, P>(scope: &'scope Scope<'scope, P>) -> Scope<'scope, P>
where
    P: Policy,
{
    Scope::new_with_capability_budget(scope.region_id(), scope.budget(), scope.capability_budget())
        .with_pending_spawn_counter(scope.pending_spawn_counter_handle())
}

/// Severity aggregation for outcomes already observed from a [`JoinSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinSummary {
    completed: usize,
    worst: Severity,
}

impl Default for JoinSummary {
    fn default() -> Self {
        Self {
            completed: 0,
            worst: Severity::Ok,
        }
    }
}

impl JoinSummary {
    /// Number of terminal outcomes included in this summary.
    #[must_use]
    pub const fn completed(&self) -> usize {
        self.completed
    }

    /// Worst observed severity using the [`Outcome`] severity lattice.
    #[must_use]
    pub const fn worst(&self) -> Severity {
        self.worst
    }

    fn record<T, E>(&mut self, outcome: &Outcome<T, E>) {
        self.completed += 1;
        self.worst = self.worst.max(outcome.severity());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_to_outcome_maps_value_and_application_error() {
        let ok: Outcome<i32, &'static str> = join_to_outcome(Ok(Ok(7)));
        assert!(matches!(ok, Outcome::Ok(7)));

        let err: Outcome<i32, &'static str> = join_to_outcome(Ok(Err("boom")));
        assert!(matches!(err, Outcome::Err("boom")));
    }

    #[test]
    fn join_to_outcome_maps_poll_after_completion_to_panic() {
        let outcome: Outcome<i32, &'static str> =
            join_to_outcome(Err(JoinError::PolledAfterCompletion));

        match outcome {
            Outcome::Panicked(payload) => {
                assert_eq!(payload.message(), "join handle polled after completion");
            }
            other => panic!("expected panic outcome, got {other:?}"),
        }
    }

    #[test]
    fn join_summary_tracks_completed_and_worst_severity() {
        let mut summary = JoinSummary::default();

        summary.record(&Outcome::<(), ()>::Ok(()));
        summary.record(&Outcome::<(), ()>::Err(()));
        summary.record(&Outcome::<(), ()>::Cancelled(crate::CancelReason::user(
            "cancelled",
        )));

        assert_eq!(summary.completed(), 3);
        assert_eq!(summary.worst(), Severity::Cancelled);
    }
}
