//! Explicit owner-cancellation collection; legacy observation-only joins stay intact.

use super::{Cx, JoinSet, Outcome, Policy, join_to_outcome};
use crate::types::CancelReason;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

mod fail_fast;

impl<T, E, P> JoinSet<'_, T, E, P>
where
    P: Policy,
    T: Send + 'static,
    E: Send + 'static,
{
    /// Collect the group in spawn order, forwarding owner cancellation before drain.
    ///
    /// Unlike [`Self::join_all`], this observes the explicit `cx` while members
    /// are parked. Its first cancellation request is sent to every unfinished
    /// member before awaiting their cleanup. Completed publications are never
    /// rewritten just because their retirement barrier is still pending.
    ///
    /// All admitted members still retire before this returns. Member outcomes
    /// retain the set's existing cancellation-dominant policy: a cancelled member
    /// is `Outcome::Cancelled`, and a member panic remains `Outcome::Panicked`.
    /// The owner checkpoint acknowledges its request where masking permits;
    /// observing a request and beginning child drain are mask-agnostic.
    ///
    /// Dropping this future, even before its first poll, keeps the set's normal
    /// abort-on-drop behavior. Region close is the asynchronous drain backstop;
    /// a non-cooperative member can still delay it. No region or task is created.
    ///
    /// The owner needs no runtime capabilities: a task's own context or a
    /// [`Cx::detached_cancel_context`] both work.
    pub async fn join_all_cancel_on_owner<Caps>(mut self, cx: &Cx<Caps>) -> Vec<Outcome<T, E>> {
        let mut cancelled = pin!(cx.cancelled());
        let mut forwarded = false;
        let mut outcomes = Vec::with_capacity(self.members.len());
        poll_fn(|task| {
            // Remove only retired members. Keeping the rest in self preserves
            // the set's cancellation ownership on every unwind/drop path.
            let mut consumed = 0;
            while consumed < 64 {
                let Some((&index, _)) = self.members.first_key_value() else {
                    return Poll::Ready(std::mem::take(&mut outcomes));
                };
                let joined = self
                    .members
                    .get_mut(&index)
                    .expect("first member remains owned")
                    .handle
                    .poll_join(task);
                let Poll::Ready(joined) = joined else {
                    break;
                };
                let outcome = join_to_outcome(joined);
                self.take_member(index, &outcome);
                outcomes.push(outcome);
                consumed += 1;
            }
            if self.members.is_empty() {
                return Poll::Ready(std::mem::take(&mut outcomes));
            }
            if !forwarded && cancelled.as_mut().poll(task).is_ready() {
                forwarded = true;
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("join set owner cancelled"));
                let _ = cx.checkpoint();
                self.cancel_unfinished_for_owner(&reason);
                task.waker().wake_by_ref();
            } else if consumed == 64 {
                task.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }

    /// Collect one member, forwarding owner cancellation when the wait would park.
    ///
    /// Ready outcomes retain the normal completion-order/earliest-spawned
    /// tie-break. If no member is ready and `cx` is cancelled, every unfinished
    /// member receives its reason before this waits for the next actual result.
    /// Returning one result does not certify whole-group drain: the remaining
    /// members stay in this set and must still be collected or closed by region.
    ///
    /// Dropping this borrowing future does not remove a member, abort the set,
    /// or lose an outcome. Cancellation already forwarded is not rolled back.
    /// The next call can use either collection API. This reuses the existing
    /// ready-member index and persistent member wakers, not a full repeated scan.
    pub async fn join_next_cancel_on_owner<Caps>(
        &mut self,
        cx: &Cx<Caps>,
    ) -> Option<Outcome<T, E>> {
        let completed = {
            let mut waiting = pin!(self.next_outcome());
            let mut cancelled = pin!(cx.cancelled());
            poll_fn(|task| {
                if let Poll::Ready(outcome) = waiting.as_mut().poll(task) {
                    return Poll::Ready(Some(outcome));
                }
                if cancelled.as_mut().poll(task).is_ready() {
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        match completed {
            Some(outcome) => outcome,
            None => {
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("join set owner cancelled"));
                let _ = cx.checkpoint();
                self.cancel_unfinished_for_owner(&reason);
                // The temporary borrowing wait has retired, but its member
                // registrations live on the handles and survive this boundary.
                self.next_outcome().await
            }
        }
    }

    fn cancel_unfinished_for_owner(&self, reason: &CancelReason) {
        let mut first_panic = None;
        for member in self.members.values() {
            if !member.handle.terminal_published()
                && let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    member.handle.abort_with_reason(reason.clone());
                }))
                && first_panic.is_none()
            {
                first_panic = Some(payload);
            }
        }
        // A hostile waker must not strand the unvisited suffix. Every request
        // has been attempted before the first panic is allowed to propagate.
        if !std::thread::panicking()
            && let Some(payload) = first_panic
        {
            std::panic::resume_unwind(payload);
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::channel::oneshot;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder, yield_now};
    use crate::types::{CancelKind, Severity};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    fn bounded(test: impl FnOnce() + Send + 'static) {
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
            let _ = send.send(result);
        });
        let result = receive
            .recv_timeout(Duration::from_secs(45))
            .expect("owner-aware JoinSet scenario must finish");
        worker.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn run<F, Fut>(workers: usize, test: F)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let builder = if workers == 1 {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::new().worker_threads(workers)
        };
        let runtime = builder.build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            test(Cx::current().expect("runtime task context")).await;
        }));
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    async fn park(cx: &Cx, started: oneshot::Sender<Cx>) {
        let mut started = Some(started);
        let mut wait = pin!(cx.cancelled());
        poll_fn(|task| match wait.as_mut().poll(task) {
            Poll::Ready(()) => Poll::Ready(()),
            Poll::Pending => {
                if let Some(started) = started.take() {
                    started.send_blocking(cx.clone()).unwrap();
                }
                Poll::Pending
            }
        })
        .await;
        assert!(cx.checkpoint().is_err());
    }

    #[test]
    fn owner_abort_waits_for_every_members_async_cleanup() {
        bounded(|| {
            for workers in [1, 2] {
                run(workers, |cx| async move {
                    let mut starts = Vec::new();
                    let mut parked = Vec::new();
                    let mut releases = Vec::new();
                    let mut waits = Vec::new();
                    for _ in 0..3 {
                        let (send, receive) = oneshot::channel();
                        starts.push(send);
                        parked.push(receive);
                        let (release, wait) = oneshot::channel();
                        releases.push(release);
                        waits.push(wait);
                    }
                    let cleaned = Arc::new(AtomicUsize::new(0));
                    let observed = Arc::clone(&cleaned);
                    let drain_cx = cx.clone();
                    let mut owner = cx
                        .spawn(move |owner| async move {
                            let mut set = JoinSet::<usize, (), _>::in_cx(&owner);
                            for (index, (started, mut release)) in
                                starts.into_iter().zip(waits).enumerate()
                            {
                                let drain_cx = drain_cx.clone();
                                let cleaned = Arc::clone(&observed);
                                set.spawn(&owner, move |child| async move {
                                    park(&child, started).await;
                                    release.recv(&drain_cx).await.unwrap();
                                    cleaned.fetch_add(1, Ordering::SeqCst);
                                    Ok(index)
                                })
                                .unwrap();
                            }
                            set.join_all_cancel_on_owner(&owner).await
                        })
                        .unwrap();
                    let mut children = Vec::new();
                    for receiver in &mut parked {
                        children.push(receiver.recv(&cx).await.unwrap());
                    }
                    owner.abort_with_reason(CancelReason::shutdown());
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while children.iter().any(|child| !child.is_cancel_requested()) {
                        assert!(
                            Instant::now() < deadline,
                            "every child must receive owner cancellation"
                        );
                        yield_now().await;
                    }
                    assert_eq!(cleaned.load(Ordering::SeqCst), 0);
                    assert!(
                        matches!(owner.try_join(), Ok(None)),
                        "owner must still be draining"
                    );
                    for sender in releases {
                        sender.send_blocking(()).unwrap();
                    }
                    let outcomes = owner.join(&cx).await.unwrap();
                    assert_eq!(outcomes.len(), 3);
                    assert!(outcomes.iter().all(|outcome| matches!(outcome,
                        Outcome::Cancelled(reason) if reason.kind == CancelKind::Shutdown)));
                    assert_eq!(cleaned.load(Ordering::SeqCst), 3);
                });
            }
        });
    }

    #[test]
    fn incremental_owner_cancel_keeps_uncollected_members_and_updates_summary() {
        bounded(|| {
            for workers in [1, 2] {
                run(workers, |cx| async move {
                    let owner = Cx::detached_cancel_context();
                    let mut set = JoinSet::<usize, (), _>::in_cx(&cx);
                    let mut children = Vec::new();
                    for index in 0..3 {
                        let (started, mut parked) = oneshot::channel();
                        set.spawn(&cx, move |child| async move {
                            park(&child, started).await;
                            Ok(index)
                        })
                        .unwrap();
                        children.push(parked.recv(&cx).await.unwrap());
                    }
                    owner.cancel_with(CancelKind::User, Some("stop incremental collection"));
                    assert!(matches!(set.join_next_cancel_on_owner(&owner).await,
                        Some(Outcome::Cancelled(reason)) if reason.kind == CancelKind::User));
                    assert_eq!(set.len(), 2);
                    assert_eq!(set.summary().completed(), 1);
                    assert_eq!(set.summary().worst(), Severity::Cancelled);
                    assert!(children.iter().all(Cx::is_cancel_requested));
                    let rest = set.join_all(&cx).await;
                    assert_eq!(rest.len(), 2);
                    assert!(rest.iter().all(|outcome| matches!(outcome,
                        Outcome::Cancelled(reason) if reason.kind == CancelKind::User)));
                    assert!(!cx.is_cancel_requested());
                });
            }
        });
    }

    #[test]
    fn dropping_incremental_wait_does_not_cancel_or_lose_a_member() {
        bounded(|| {
            for workers in [1, 2] {
                run(workers, |cx| async move {
                    let owner = Cx::detached_cancel_context();
                    let mut set = JoinSet::<usize, (), _>::in_cx(&cx);
                    let mut releases = Vec::new();
                    let mut children = Vec::new();
                    for index in 0..3 {
                        let (release, mut waiting) = oneshot::channel();
                        let (started, mut parked) = oneshot::channel();
                        set.spawn(&cx, move |child| async move {
                            let mut started = Some(started);
                            let mut waiting = pin!(waiting.recv(&child));
                            poll_fn(|task| match waiting.as_mut().poll(task) {
                                Poll::Ready(result) => Poll::Ready(result),
                                Poll::Pending => {
                                    if let Some(started) = started.take() {
                                        started.send_blocking(child.clone()).unwrap();
                                    }
                                    Poll::Pending
                                }
                            })
                            .await
                            .unwrap();
                            Ok(index)
                        })
                        .unwrap();
                        releases.push(release);
                        children.push(parked.recv(&cx).await.unwrap());
                    }
                    let mut next = Box::pin(set.join_next_cancel_on_owner(&owner));
                    poll_fn(|task| {
                        assert!(next.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    drop(next);
                    owner.cancel_with(CancelKind::User, Some("observer already dropped"));
                    assert_eq!(set.len(), 3);
                    assert!(children.iter().all(|child| !child.is_cancel_requested()));
                    for release in releases.into_iter().rev() {
                        release.send_blocking(()).unwrap();
                    }
                    let mut values = Vec::new();
                    while let Some(outcome) = set.join_next(&cx).await {
                        values.push(outcome.expect("member was not cancelled"));
                    }
                    values.sort_unstable();
                    assert_eq!(values, [0, 1, 2]);
                    assert_eq!(set.summary().completed(), 3);
                    assert_eq!(set.summary().worst(), Severity::Ok);
                });
            }
        });
    }

    #[test]
    fn owner_cancel_preserves_ready_values_and_application_errors_in_spawn_order() {
        bounded(|| {
            for workers in [1, 2] {
                run(workers, |cx| async move {
                    let owner = Cx::detached_cancel_context();
                    let mut set = JoinSet::<u8, &'static str, _>::in_cx(&cx);
                    set.spawn(&cx, |_| async { Ok(5) }).unwrap();
                    set.spawn(&cx, |_| async { Err("application error") })
                        .unwrap();
                    while set
                        .members
                        .values()
                        .any(|member| !member.handle.is_finished())
                    {
                        yield_now().await;
                    }
                    let (started, mut parked) = oneshot::channel();
                    set.spawn(&cx, move |child| async move {
                        park(&child, started).await;
                        Ok(9)
                    })
                    .unwrap();
                    parked.recv(&cx).await.unwrap();
                    owner.cancel_with(CancelKind::User, Some("preserve completed prefix"));
                    let outcomes = set.join_all_cancel_on_owner(&owner).await;
                    assert_eq!(outcomes.len(), 3);
                    assert!(matches!(outcomes[0], Outcome::Ok(5)));
                    assert!(matches!(outcomes[1], Outcome::Err("application error")));
                    assert!(matches!(&outcomes[2], Outcome::Cancelled(reason)
                        if reason.kind == CancelKind::User));
                });
            }
        });
    }

    #[test]
    fn local_members_remain_pinned_through_owner_cancel_and_cleanup() {
        bounded(|| {
            for workers in [1, 2] {
                run(workers, |cx| async move {
                    let owner = Cx::detached_cancel_context();
                    let mut set = JoinSet::<usize, (), _>::in_cx(&cx);
                    let cleaned = Arc::new(AtomicUsize::new(0));
                    for index in 0..2 {
                        let (started, mut parked) = oneshot::channel();
                        let marker = Rc::new(index);
                        let cleaned = Arc::clone(&cleaned);
                        set.spawn_local(&cx, move |child| async move {
                            let thread = std::thread::current().id();
                            park(&child, started).await;
                            yield_now().await;
                            assert_eq!(std::thread::current().id(), thread);
                            cleaned.fetch_add(1, Ordering::SeqCst);
                            Ok(*marker)
                        })
                        .unwrap();
                        parked.recv(&cx).await.unwrap();
                    }
                    owner.cancel_with(CancelKind::User, Some("local group stop"));
                    let outcomes = set.join_all_cancel_on_owner(&owner).await;
                    assert_eq!(outcomes.len(), 2);
                    assert!(outcomes.iter().all(|outcome| matches!(outcome,
                        Outcome::Cancelled(reason) if reason.kind == CancelKind::User)));
                    assert_eq!(cleaned.load(Ordering::SeqCst), 2);
                });
            }
        });
    }

    #[test]
    fn legacy_join_next_stays_observation_only_for_a_cancelled_caller() {
        bounded(|| {
            for workers in [1, 2] {
                run(workers, |cx| async move {
                    // Legacy join_next takes a full-capability context; it is
                    // cancelled here and must still not be forwarded.
                    let observer = Cx::for_testing();
                    let mut set = JoinSet::<(), (), _>::in_cx(&cx);
                    let (started, mut parked) = oneshot::channel();
                    set.spawn(&cx, move |child| async move {
                        park(&child, started).await;
                        Ok(())
                    })
                    .unwrap();
                    let child = parked.recv(&cx).await.unwrap();
                    observer.cancel_with(CancelKind::User, Some("legacy observer cancellation"));
                    let mut next = Box::pin(set.join_next(&observer));
                    poll_fn(|task| {
                        assert!(next.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    drop(next);
                    assert!(!child.is_cancel_requested());
                    let outcomes = set.cancel_all(&cx).await;
                    assert!(matches!(&outcomes[..], [Outcome::Cancelled(reason)]
                        if reason.kind == CancelKind::User));
                });
            }
        });
    }

    #[test]
    fn panic_after_owner_cancel_is_not_replaced_or_used_to_skip_siblings() {
        bounded(|| {
            for workers in [1, 2] {
                run(workers, |cx| async move {
                    let owner = Cx::detached_cancel_context();
                    let mut set = JoinSet::<(), (), _>::in_cx(&cx);
                    let (start_a, mut parked_a) = oneshot::channel();
                    let (start_b, mut parked_b) = oneshot::channel();
                    let cleaned = Arc::new(AtomicUsize::new(0));
                    let observed = Arc::clone(&cleaned);
                    set.spawn(&cx, move |child| async move {
                        park(&child, start_a).await;
                        panic!("owner-aware set member panic");
                    })
                    .unwrap();
                    set.spawn(&cx, move |child| async move {
                        park(&child, start_b).await;
                        yield_now().await;
                        observed.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap();
                    parked_a.recv(&cx).await.unwrap();
                    parked_b.recv(&cx).await.unwrap();
                    owner.cancel_with(CancelKind::User, Some("stop before panic"));
                    let outcomes = set.join_all_cancel_on_owner(&owner).await;
                    assert_eq!(outcomes.len(), 2);
                    assert!(matches!(&outcomes[0], Outcome::Panicked(payload)
                        if payload.message().contains("owner-aware set member panic")));
                    assert!(matches!(&outcomes[1], Outcome::Cancelled(reason)
                        if reason.kind == CancelKind::User));
                    assert_eq!(cleaned.load(Ordering::SeqCst), 1);
                });
            }
        });
    }
}
