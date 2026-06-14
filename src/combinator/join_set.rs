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
//! ```ignore
//! let mut set = JoinSet::new(&scope);
//! for i in 0..n {
//!     set.spawn(&cx, move |_cx| async move { Ok::<_, MyError>(work(i)) })?;
//! }
//! let outcomes = set.join_all(&cx).await; // Vec<Outcome<T, MyError>>, in spawn order
//! ```
//!
//! # Scope of this slice
//!
//! This first slice lands the most common server pattern — fan-out N members
//! and collect them — via [`JoinSet::new`], [`JoinSet::spawn`],
//! [`JoinSet::join_all`], [`JoinSet::cancel_all`],
//! [`JoinSet::len`]/[`JoinSet::is_empty`], and abort-on-drop. The streaming
//! [`join_next`]-as-they-complete API, `in_cx`/`in_child_region`
//! constructors, and the `JoinSummary` severity aggregation are tracked
//! follow-up slices on the same bead (asupersync-dx-core-api-v2-u1z5hn.5).
//!
//! [`join_next`]: JoinSet

use std::future::Future;

use crate::cx::{Cx, Scope};
use crate::runtime::JoinError;
use crate::runtime::TaskHandle;
use crate::runtime::state::SpawnError;
use crate::types::{Outcome, PanicPayload, Policy};

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
    scope: &'scope Scope<'scope, P>,
    handles: Vec<TaskHandle<Result<T, E>>>,
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
            scope,
            handles: Vec::new(),
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
        let handle = cx.spawn_in(self.scope, f)?;
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

    async fn drain_all(&mut self, cx: &Cx) -> Vec<Outcome<T, E>> {
        let mut handles = std::mem::take(&mut self.handles);
        let mut outcomes = Vec::with_capacity(handles.len());
        for handle in &mut handles {
            outcomes.push(join_to_outcome(handle.join(cx).await));
        }
        outcomes
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
}
