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
//! [`JoinSet::summary`] for severity aggregation, structured
//! `join_set.spawn` trace fields that bind each member to its parent set, and
//! abort-on-drop for best-effort cancellation requests.
//!
//! Child-region isolation is state-threaded through [`Scope::region`]:
//! construct [`JoinSet::new`] with the child scope inside the region body.
//! [`JoinSet::new`] and [`JoinSet::in_cx`] intentionally reuse an existing
//! region instead of allocating a hidden quiescence boundary.
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
    set_id: u64,
    next_member_index: u64,
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
            handles: Vec::new(),
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
        let member_index = self.next_member_index;
        let handle = cx.spawn_in(&self.scope, f)?;
        self.handles.push(handle);
        self.next_member_index = self.next_member_index.saturating_add(1);
        self.trace_member_spawn(cx, member_index, "send");
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
        let member_index = self.next_member_index;
        let handle = cx.spawn_local_in(&self.scope, f)?;
        self.handles.push(handle);
        self.next_member_index = self.next_member_index.saturating_add(1);
        self.trace_member_spawn(cx, member_index, "local");
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

    /// Collects one already-complete member without waiting.
    ///
    /// Results use the same deterministic tie-break as
    /// [`join_next`](Self::join_next): if several members are already ready,
    /// the earliest spawned ready member is returned first. Pending handles are
    /// left owned by the set and are not cancelled by the readiness scan.
    pub fn try_join_next(&mut self) -> Option<Outcome<T, E>> {
        for index in 0..self.handles.len() {
            let outcome = try_join_to_outcome(self.handles[index].try_join());
            if let Some(outcome) = outcome {
                self.summary.record(&outcome);
                self.handles.remove(index);
                return Some(outcome);
            }
        }

        None
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
        if let Some(outcome) = self.try_join_next() {
            return Some(outcome);
        }

        std::future::poll_fn(|task_cx| {
            if let Some(outcome) = self.try_join_next() {
                return Poll::Ready(Some(outcome));
            }

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

    fn trace_member_spawn(&self, cx: &Cx, member_index: u64, spawn_kind: &str) {
        let set_id = self.set_id.to_string();
        let member_index = member_index.to_string();
        let region = self.scope.region_id().to_string();
        let active_members = self.handles.len().to_string();
        cx.trace_with_fields(
            "join_set.spawn",
            &[
                ("join_set_id", set_id.as_str()),
                ("member_index", member_index.as_str()),
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
            handles: Vec::new(),
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
mod tests {
    use super::*;
    use crate::channel::oneshot;
    use crate::cx::Cx;
    use crate::observability::{LogCollector, LogLevel};
    use crate::runtime::{RuntimeBuilder, yield_now};
    use crate::types::TaskId;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn run_in_runtime<F, Fut, T>(f: F) -> T
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("spawned root task has Cx");
            f(cx).await
        }))
    }

    fn manual_handle<T>(task_slot: u32) -> (oneshot::Sender<Result<T, JoinError>>, TaskHandle<T>) {
        let (tx, rx) = oneshot::channel::<Result<T, JoinError>>();
        let handle = TaskHandle::new(
            TaskId::new_for_test(task_slot, 0),
            rx,
            std::sync::Weak::new(),
        );
        (tx, handle)
    }

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

    #[test]
    fn join_set_id_is_deterministic_from_owning_region() {
        let scope =
            Scope::<FailFast>::new(crate::RegionId::new_for_test(7, 1), crate::Budget::INFINITE);
        let set = JoinSet::<(), (), FailFast>::new(&scope);

        assert_eq!(set.set_id, scope.region_id().as_u64());
        assert_eq!(set.next_member_index, 0);
    }

    #[test]
    fn join_set_spawn_trace_records_parent_set_fields() {
        let (entries, set_id, region) = run_in_runtime(|cx| async move {
            let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
            cx.set_log_collector(collector.clone());

            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            let set_id = set.set_id.to_string();
            let region = cx.region_id().to_string();

            set.spawn(&cx, |_| async move { Ok::<u32, ()>(1) })
                .expect("first member spawns");
            set.spawn(&cx, |_| async move { Ok::<u32, ()>(2) })
                .expect("second member spawns");

            let values = set
                .join_all(&cx)
                .await
                .into_iter()
                .map(|outcome| outcome.expect("member ok"))
                .collect::<Vec<_>>();
            assert_eq!(values, vec![1, 2]);

            (collector.peek(), set_id, region)
        });

        let spawn_entries = entries
            .iter()
            .filter(|entry| entry.message() == "join_set.spawn")
            .collect::<Vec<_>>();
        assert_eq!(spawn_entries.len(), 2);

        for (index, entry) in spawn_entries.iter().enumerate() {
            let member_index = index.to_string();
            let active_members = (index + 1).to_string();

            assert_eq!(entry.get_field("join_set_id"), Some(set_id.as_str()));
            assert_eq!(entry.get_field("region"), Some(region.as_str()));
            assert_eq!(entry.get_field("spawn_kind"), Some("send"));
            assert_eq!(entry.get_field("member_index"), Some(member_index.as_str()));
            assert_eq!(
                entry.get_field("active_members"),
                Some(active_members.as_str())
            );
        }
    }

    #[test]
    fn join_next_returns_none_for_empty_set() {
        let observed = run_in_runtime(|cx| async move {
            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            let next = set.join_next(&cx).await;
            let summary = set.summary();
            (next, summary.completed(), summary.worst())
        });

        assert_eq!(observed.0, None);
        assert_eq!(observed.1, 0);
        assert_eq!(observed.2, Severity::Ok);
    }

    #[test]
    fn try_join_next_returns_none_until_member_is_ready() {
        let scope =
            Scope::<FailFast>::new(crate::RegionId::new_for_test(8, 1), crate::Budget::INFINITE);
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let (_tx, handle) = manual_handle::<Result<u32, &'static str>>(1);

        set.handles.push(handle);

        assert!(set.try_join_next().is_none());
        assert_eq!(set.len(), 1);
        assert_eq!(set.summary().completed(), 0);
        assert_eq!(set.summary().worst(), Severity::Ok);
    }

    #[test]
    fn try_join_next_collects_earliest_spawned_ready_member() {
        let cx = Cx::for_testing();
        let scope =
            Scope::<FailFast>::new(crate::RegionId::new_for_test(9, 1), crate::Budget::INFINITE);
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let (_pending_tx, pending_handle) = manual_handle::<Result<u32, &'static str>>(1);
        let (ready_tx, ready_handle) = manual_handle::<Result<u32, &'static str>>(2);

        set.handles.push(pending_handle);
        set.handles.push(ready_handle);
        ready_tx
            .send(&cx, Ok(Ok(9)))
            .expect("ready member result sends");

        let outcome = set.try_join_next().expect("ready member collected");

        assert!(matches!(outcome, Outcome::Ok(9)));
        assert_eq!(set.len(), 1);
        assert_eq!(set.summary().completed(), 1);
        assert_eq!(set.summary().worst(), Severity::Ok);
        assert!(set.try_join_next().is_none());
    }

    #[test]
    fn try_join_next_maps_application_error() {
        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(
            crate::RegionId::new_for_test(10, 1),
            crate::Budget::INFINITE,
        );
        let mut set = JoinSet::<u32, &'static str, FailFast>::new(&scope);
        let (ready_tx, ready_handle) = manual_handle::<Result<u32, &'static str>>(1);

        set.handles.push(ready_handle);
        ready_tx
            .send(&cx, Ok(Err("boom")))
            .expect("ready member error sends");

        let outcome = set.try_join_next().expect("ready member collected");

        assert!(matches!(outcome, Outcome::Err("boom")));
        assert!(set.is_empty());
        assert_eq!(set.summary().completed(), 1);
        assert_eq!(set.summary().worst(), Severity::Err);
    }

    #[test]
    fn join_all_collects_members_in_spawn_order() {
        let (outcomes, next_member_index) = run_in_runtime(|cx| async move {
            let mut set = JoinSet::<u32, (), _>::in_cx(&cx);
            for value in [30_u32, 10, 20] {
                set.spawn(&cx, move |_| async move { Ok::<u32, ()>(value) })
                    .expect("join-set member spawns");
            }

            let next_member_index = set.next_member_index;
            (set.join_all(&cx).await, next_member_index)
        });

        assert_eq!(next_member_index, 3);
        assert_eq!(
            outcomes
                .into_iter()
                .map(|outcome| outcome.expect("member ok"))
                .collect::<Vec<_>>(),
            vec![30, 10, 20]
        );
    }

    #[test]
    fn cancel_all_drains_live_members_as_cancelled_outcomes() {
        let (outcomes, summary) = run_in_runtime(|cx| async move {
            let started = Arc::new(AtomicUsize::new(0));
            let mut set = JoinSet::<u32, crate::error::Error, _>::in_cx(&cx);

            for _ in 0..3 {
                let started = Arc::clone(&started);
                set.spawn(&cx, move |member_cx| async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    loop {
                        if let Err(error) = member_cx.checkpoint() {
                            return Err(error);
                        }
                        yield_now().await;
                    }
                })
                .expect("join-set member spawns");
            }

            for _ in 0..16 {
                if started.load(Ordering::SeqCst) == 3 {
                    break;
                }
                yield_now().await;
            }
            assert_eq!(
                started.load(Ordering::SeqCst),
                3,
                "all members must start before cancel_all is tested"
            );

            let outcomes = set.cancel_all(&cx).await;
            let mut summary = JoinSummary::default();
            for outcome in &outcomes {
                summary.record(outcome);
            }
            (outcomes, summary)
        });

        assert_eq!(outcomes.len(), 3);
        assert!(
            outcomes
                .iter()
                .all(|outcome| matches!(outcome, Outcome::Cancelled(_))),
            "cancel_all must drain every live member to a terminal Cancelled outcome: {outcomes:?}"
        );
        assert_eq!(summary.completed(), 3);
        assert_eq!(summary.worst(), Severity::Cancelled);
    }
}
