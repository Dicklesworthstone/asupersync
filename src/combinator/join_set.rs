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
//! and [`JoinSet::spawn_all`] for member admission, [`JoinSet::spawn_local`]
//! for thread-pinned members, [`JoinSet::join_next`]
//! for completion-order collection, [`JoinSet::join_all`] for spawn-order
//! collection, [`JoinSet::cancel_all`] for explicit drain after cancellation,
//! [`JoinSet::summary`] for severity aggregation, structured
//! `join_set.spawn` trace fields that record the set's region id (`join_set_id`),
//! `member_index`, `member_task_id`, `region`, `spawn_kind`, and `active_members`
//! (uniquely distinguishing member tasks even when sets share an owning region), and
//! abort-on-drop for best-effort cancellation requests.
//!
//! Child-region isolation is state-threaded through [`Scope::region`]:
//! construct [`JoinSet::new`] with the child scope inside the region body.
//! [`JoinSet::new`] and [`JoinSet::in_cx`] intentionally reuse an existing
//! region instead of allocating a hidden quiescence boundary.
//!
//! # There is no separate `TaskGroup`
//!
//! `JoinSet` **is** this runtime's task-group primitive, and no `TaskGroup`
//! type is planned (`br-asupersync-ufdab2`). If you came here looking for one,
//! stop looking: everything a task group is normally wanted for is already on
//! this type — region-owned members, completion-order [`JoinSet::join_next`],
//! spawn-order [`JoinSet::join_all`], drained [`JoinSet::cancel_all`],
//! [`JoinSet::summary`] severity aggregation, and abort-on-drop.
//!
//! A `TaskGroup` that merely renamed or aliased `JoinSet` would be a
//! compatibility shim, which this project does not add, and it would leave
//! agents choosing between two names for one concept.
//!
//! The one genuinely different design — a group that *owns* a child region by
//! construction, so that cancelling the group is a region cancel and leaving it
//! is a quiescence boundary — is deliberately **not** what `JoinSet` does.
//! `JoinSet` shares the caller's region. When you want the group itself to be a
//! structure boundary, compose it explicitly rather than reaching for a
//! different type:
//!
//! ```ignore
//! // The group IS the quiescence boundary: the child region cannot close
//! // until every member is done, and cancelling the region cancels them all.
//! scope
//!     .region(&mut state, &cx, FailFast, |child, state| async move {
//!         let mut set = JoinSet::new(&child);
//!         // ... set.spawn(...) ...
//!         set.join_all(&cx).await
//!     })
//!     .await
//! ```
//!
//! [`join_next`]: JoinSet

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use crate::cx::{Cx, Scope};
use crate::runtime::JoinError;
use crate::runtime::TaskHandle;
use crate::runtime::state::SpawnError;
use crate::types::policy::FailFast;
use crate::types::{CancelReason, Outcome, PanicPayload, Policy, Severity, TaskId};

mod collector;
mod owner;
use collector::CollectorWait;

#[cfg(test)]
mod candidate_tests;
#[cfg(test)]
mod waker_tests;

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
    /// Owned members keyed by spawn index, so spawn-order collection and the
    /// earliest-spawned tie-break are ordered walks and removal is O(log N).
    members: BTreeMap<u64, Member<T, E>>,
    /// Members that may have finished since [`JoinSet::join_next`] last
    /// polled them: never-polled members, plus members whose waker fired.
    /// `join_next` polls only these instead of every member
    /// (br-asupersync-issue65-criticisms-kpmoy5.1.5).
    ready: Arc<ReadyMembers>,
    summary: JoinSummary,
    set_id: u64,
    next_member_index: u64,
}

struct Member<T, E> {
    handle: TaskHandle<Result<T, E>>,
    /// This member's own waker, created on its first `join_next` poll.
    waker: Option<Waker>,
}

/// Candidate members plus the waker of the task waiting in `join_next`.
#[derive(Default)]
struct ReadyMembers {
    candidates: parking_lot::Mutex<BTreeSet<u64>>,
    // Arc clones under this mutex never invoke an executor's RawWaker clone.
    waiter: parking_lot::Mutex<Option<Arc<Waker>>>,
}

impl ReadyMembers {
    /// The lowest candidate at or after `from`.
    fn next_candidate(&self, from: u64) -> Option<u64> {
        self.candidates.lock().range(from..).next().copied()
    }
}

/// A member's waker: marks it a candidate and wakes the collecting task.
struct MemberWake {
    index: u64,
    ready: Arc<ReadyMembers>,
}

impl Wake for MemberWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.candidates.lock().insert(self.index);
        let waiter = self.ready.waiter.lock().clone();
        if let Some(waiter) = waiter {
            // Invoke and retire the Arc-owned executor waker only after unlock.
            waiter.wake_by_ref();
        }
    }
}

impl<'scope, T, E, P> JoinSet<'scope, T, E, P>
where
    P: Policy,
    T: Send + 'static,
    E: Send + 'static,
{
    /// Creates an empty set whose members will be spawned into `scope`'s
    /// region. The set shares the caller's region (no extra quiescence point);
    /// use [`Scope::region`] and construct the set from that child scope when
    /// isolation is wanted.
    #[must_use]
    pub fn new(scope: &'scope Scope<'scope, P>) -> Self {
        Self {
            scope: clone_scope(scope),
            members: BTreeMap::new(),
            ready: Arc::new(ReadyMembers::default()),
            summary: JoinSummary::default(),
            set_id: scope.region_id().as_u64(),
            next_member_index: 0,
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
        let handle = cx.spawn_in_cancellation_dominant(&self.scope, f)?;
        let (member_index, task_id) = self.insert_member(handle);
        self.trace_member_spawn(cx, member_index, task_id, "send");
        Ok(())
    }

    /// Spawns a bounded batch of members into the set's region.
    ///
    /// Factories are submitted in input order, with one gateway notification
    /// for a non-empty batch. Each member keeps its own task identity,
    /// admission result, cancellation state, and pending-spawn reservation.
    /// This does not change scheduler fairness or make admission atomic:
    /// workers can admit a prefix while later requests are being queued.
    ///
    /// The set takes ownership of every returned handle in input order, after
    /// any existing members. [`Self::join_all`] preserves that order, while
    /// [`Self::join_next`] retains its ordinary completion-order behavior.
    /// Each factory receives its own child [`Cx`]. As with [`Self::spawn`],
    /// cancellation remains the member's outer outcome even if its future
    /// returns a value after acknowledging cancellation during cleanup.
    ///
    /// An empty iterator succeeds without requiring runtime wiring. At most
    /// [`crate::cx::MAX_SPAWN_BATCH_SIZE`] factories may be submitted in one
    /// call; use several calls for larger inputs. The iterator is consumed only
    /// through the first excess member when checking that limit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::cx::SpawnBatchError`] if the batch is too large or the
    /// spawn gateway is unavailable. A setup error publishes no requests and
    /// leaves the set's existing members unchanged. Subsequent region or quota
    /// denials are per-member [`Outcome::Cancelled`] results, collected and
    /// drained through the same methods as individually spawned members.
    pub fn spawn_all<I, F, Fut>(
        &mut self,
        cx: &Cx,
        factories: I,
    ) -> Result<(), crate::cx::SpawnBatchError>
    where
        I: IntoIterator<Item = F>,
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
    {
        let handles = cx.spawn_batch_in_cancellation_dominant(&self.scope, factories)?;
        for handle in handles {
            let (member_index, task_id) = self.insert_member(handle);
            self.trace_member_spawn(cx, member_index, task_id, "send");
        }
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
        let handle = cx.spawn_local_in_cancellation_dominant(&self.scope, f)?;
        let (member_index, task_id) = self.insert_member(handle);
        self.trace_member_spawn(cx, member_index, task_id, "local");
        Ok(())
    }

    /// Takes ownership of a spawned member and returns its spawn index and task id.
    /// A new member is a `join_next` candidate until its first poll.
    fn insert_member(&mut self, handle: TaskHandle<Result<T, E>>) -> (u64, TaskId) {
        let member_index = self.next_member_index;
        let task_id = handle.task_id();
        self.members.insert(
            member_index,
            Member {
                handle,
                waker: None,
            },
        );
        self.ready.candidates.lock().insert(member_index);
        self.next_member_index = self.next_member_index.saturating_add(1);
        (member_index, task_id)
    }

    /// Removes a collected member and records its outcome.
    fn take_member(&mut self, member_index: u64, outcome: &Outcome<T, E>) {
        self.summary.record(outcome);
        self.members.remove(&member_index);
        self.ready.candidates.lock().remove(&member_index);
    }

    /// Number of members currently owned by the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Returns `true` when the set owns no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Collects one already-complete member without waiting.
    ///
    /// Results use the same deterministic tie-break as
    /// [`join_next`](Self::join_next): if several members are already ready,
    /// the earliest spawned ready member is returned first. Pending handles are
    /// left owned by the set and are not cancelled by the readiness scan.
    ///
    /// Pending members retain an internal completion waker even when no async
    /// join has been polled. Repeated calls therefore revisit only newly woken
    /// candidates, not every sleeping member. This does not subscribe the caller
    /// to notifications; use `join_next` to wait for an actual completion.
    pub fn try_join_next(&mut self) -> Option<Outcome<T, E>> {
        let mut from = 0;
        while let Some(member_index) = self.ready.next_candidate(from) {
            if let Some(outcome) = self.poll_candidate(member_index) {
                return Some(outcome);
            }
            let Some(next) = member_index.checked_add(1) else {
                break;
            };
            from = next;
        }

        None
    }

    /// Poll one candidate and arm its persistent member registration if pending.
    /// Both synchronous and asynchronous collection use this readiness boundary.
    fn poll_candidate(&mut self, member_index: u64) -> Option<Outcome<T, E>> {
        // Remove BEFORE polling: a completion or a permitted spurious wake
        // during poll_join puts the member back, and must not be erased afterward.
        self.ready.candidates.lock().remove(&member_index);
        let outcome = self.members.get_mut(&member_index).and_then(|member| {
            let Member { handle, waker } = member;
            let waker = waker.get_or_insert_with(|| {
                Waker::from(Arc::new(MemberWake {
                    index: member_index,
                    ready: Arc::clone(&self.ready),
                }))
            });
            match handle.poll_join(&mut Context::from_waker(waker)) {
                Poll::Ready(joined) => try_join_to_outcome(joined.map(Some)),
                Poll::Pending => None,
            }
        })?;
        self.take_member(member_index, &outcome);
        Some(outcome)
    }

    /// Waits for every member to complete and returns their outcomes in spawn
    /// order.
    ///
    /// Each member's terminal state maps to an [`Outcome`]: a returned value is
    /// [`Outcome::Ok`]/[`Outcome::Err`] (from the member's own `Result`), a
    /// cancelled member is [`Outcome::Cancelled`], and a panicked member is
    /// [`Outcome::Panicked`]. Completed members are no longer abort-on-drop
    /// targets after the drain finishes. Dropping this future before completion
    /// requests cancellation of every remaining member, including members whose
    /// join has not yet been polled; region close remains the drain backstop.
    pub async fn join_all(mut self, cx: &Cx) -> Vec<Outcome<T, E>> {
        self.drain_all(cx).await
    }

    /// Waits for the next member to complete and returns its terminal outcome.
    ///
    /// Results are yielded in completion order. When multiple members are
    /// already complete in the same poll, the earliest spawned ready member is
    /// selected as the deterministic tie-break. Pending members are polled
    /// through [`TaskHandle::poll_join`], which registers for wakeup without
    /// requesting cancellation, so scanning for readiness never cancels
    /// still-running work. Each call polls only members that may have finished
    /// since they were last polled (members never polled, and members whose
    /// wakeup fired), so collecting N members costs O(N log N) in total rather
    /// than a scan of every member per call.
    ///
    /// The `Cx` parameter is kept for symmetry with [`join_all`](Self::join_all)
    /// and [`cancel_all`](Self::cancel_all). Collection itself is
    /// uninterruptible, exactly like [`TaskHandle::join`]: observing a member's
    /// terminal outcome is what upholds the no-orphan accounting, so a
    /// cancelled caller still drains rather than abandoning members.
    pub async fn join_next(&mut self, _cx: &Cx) -> Option<Outcome<T, E>> {
        self.next_outcome().await
    }

    /// [`Self::join_next`] without the unused context, for owner collectors
    /// whose context may carry no runtime capabilities.
    async fn next_outcome(&mut self) -> Option<Outcome<T, E>> {
        if let Some(outcome) = self.try_join_next() {
            return Some(outcome);
        }

        // Only this borrowing wait owns the executor's subscription. Member
        // registrations remain installed when the wait completes or is dropped.
        let mut collector = CollectorWait::new(Arc::clone(&self.ready));
        std::future::poll_fn(|task_cx| {
            if self.members.is_empty() {
                return Poll::Ready(None);
            }
            collector.refresh(task_cx.waker());

            // Poll each candidate, in spawn order, through its handle's own
            // long-lived receiver with the member's own waker, so every pending
            // registration SURVIVES this poll (br-asupersync-tncxj9). Polling a
            // temporary `handle.join(cx)` future per member instead registered a
            // waiter and then retired it again as that future dropped, so the
            // scan ended with no waker registered on any member and nothing ever
            // re-polled this set. A member leaves the candidates before its poll,
            // and its waker puts it back when its result is published.
            let mut from = 0;
            while let Some(member_index) = self.ready.next_candidate(from) {
                if let Some(outcome) = self.poll_candidate(member_index) {
                    return Poll::Ready(Some(outcome));
                }
                let Some(next) = member_index.checked_add(1) else {
                    break;
                };
                from = next;
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
    pub async fn cancel_all(self, cx: &Cx) -> Vec<Outcome<T, E>> {
        self.cancel_all_with_reason(cx, CancelReason::user("abort"))
            .await
    }

    /// Requests cancellation for every member with `reason` and drains all
    /// terminal outcomes in spawn order.
    ///
    /// This is the explicit-reason form used by higher-level combinators that
    /// need cancellation attribution stronger than ordinary user aborts, such
    /// as `RaceLost` loser-drain verification.
    pub async fn cancel_all_with_reason(
        mut self,
        cx: &Cx,
        reason: CancelReason,
    ) -> Vec<Outcome<T, E>> {
        for member in self.members.values() {
            member.handle.abort_with_reason(reason.clone());
        }
        self.drain_all(cx).await
    }

    /// Returns the terminal-outcome summary observed so far by collection
    /// methods on this set (such as [`join_next`](Self::join_next),
    /// [`try_join_next`](Self::try_join_next), and owner collection APIs).
    ///
    /// `join_all` and `cancel_all` consume the set and return all outcomes
    /// directly, so callers can build their own aggregate from that complete
    /// vector when they choose the spawn-order APIs.
    #[must_use]
    pub fn summary(&self) -> JoinSummary {
        self.summary
    }

    async fn drain_all(&mut self, cx: &Cx) -> Vec<Outcome<T, E>> {
        // TaskHandle drop does not cancel its task. Retain every handle in
        // the cancellation-owning set across each await, so dropping this
        // drain cannot abandon the not-yet-joined suffix. Iterating in place
        // also preserves linear work for large spawn-order collections.
        let mut outcomes = Vec::with_capacity(self.members.len());
        for member in self.members.values_mut() {
            let outcome = join_to_outcome(member.handle.join(cx).await);
            self.summary.record(&outcome);
            outcomes.push(outcome);
        }
        self.members.clear();
        self.ready.candidates.lock().clear();
        outcomes
    }

    fn trace_member_spawn(
        &self,
        cx: &Cx,
        member_index: u64,
        member_task_id: TaskId,
        spawn_kind: &str,
    ) {
        let set_id = self.set_id.to_string();
        let member_index = member_index.to_string();
        let member_task_id = member_task_id.to_string();
        let region = self.scope.region_id().to_string();
        let active_members = self.members.len().to_string();
        cx.trace_with_fields(
            "join_set.spawn",
            &[
                ("join_set_id", set_id.as_str()),
                ("member_index", member_index.as_str()),
                ("member_task_id", member_task_id.as_str()),
                ("region", region.as_str()),
                ("spawn_kind", spawn_kind),
                ("active_members", active_members.as_str()),
            ],
        );
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
            members: BTreeMap::new(),
            ready: Arc::new(ReadyMembers::default()),
            summary: JoinSummary::default(),
            set_id: cx.region_id().as_u64(),
            next_member_index: 0,
        }
    }
}

impl<T, E, P> Drop for JoinSet<'_, T, E, P>
where
    P: Policy,
{
    fn drop(&mut self) {
        // Drop is a cancellation *request* to any member that has not yet
        // finished; region close remains the quiescence backstop. Explicit
        // TaskHandle::abort can strengthen a completed task's reason, so do
        // not use it on terminal members during implicit ownership cleanup.
        // This also protects completed prefixes retained by drain_all. A
        // member that published its result is terminal even before the
        // scheduler retires its record, which is when is_finished() turns true.
        for member in self.members.values() {
            if !member.handle.terminal_published() {
                member.handle.abort();
            }
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

fn try_join_to_outcome<T, E>(
    joined: Result<Option<Result<T, E>>, JoinError>,
) -> Option<Outcome<T, E>> {
    match joined {
        Ok(Some(result)) => Some(join_to_outcome(Ok(result))),
        Ok(None) => None,
        Err(error) => Some(join_to_outcome(Err(error))),
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
#[path = "join_set_inline_tests.rs"]
mod tests;
