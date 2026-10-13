//! Success selection over already-admitted region-owned task groups.
//!
//! Unlike a race, application errors do not win a quorum. Unlike a plain join,
//! enough successes or an impossible quorum starts cancellation immediately.
//! Publication still waits for every remaining member's retirement.

use super::{JoinSet, QuorumError};
use crate::cx::Cx;
use crate::types::{CancelReason, Outcome, Policy};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

enum Decision {
    Satisfied,
    Impossible,
    Invalid,
    Panicked,
    OwnerCancelled(CancelReason),
}

struct Selection<T, E> {
    required: usize,
    total: usize,
    successes: usize,
    // Keep user values/errors alive until ALL members have retired. A user
    // destructor must not be able to interrupt the drain of a sibling.
    outcomes: Vec<Outcome<T, E>>,
    spontaneous_cancel: Option<CancelReason>,
}

impl<T, E> Selection<T, E> {
    fn new(required: usize, total: usize) -> Self {
        Self {
            required,
            total,
            successes: 0,
            outcomes: Vec::with_capacity(total),
            spontaneous_cancel: None,
        }
    }

    fn record(&mut self, outcome: Outcome<T, E>) -> Option<Decision> {
        let panicked = matches!(&outcome, Outcome::Panicked(_));
        match &outcome {
            Outcome::Ok(_) => self.successes += 1,
            // Report the strongest spontaneous cancellation, not the first: a
            // member's own poll-quota stop must not hide a shutdown that
            // cancelled its siblings (as quorum and join_all, br-asupersync-1sngsf).
            // Induced loser cancellations never reach record(), so no kind is
            // excluded here.
            Outcome::Cancelled(reason) => match &mut self.spontaneous_cancel {
                Some(strongest) => {
                    strongest.strengthen(reason);
                }
                None => self.spontaneous_cancel = Some(reason.clone()),
            },
            _ => {}
        }
        self.outcomes.push(outcome);
        if panicked {
            Some(Decision::Panicked)
        } else if self.successes >= self.required {
            Some(Decision::Satisfied)
        } else if self.total - self.outcomes.len() < self.required - self.successes {
            Some(Decision::Impossible)
        } else {
            None
        }
    }

    fn finish(
        self,
        decision: Decision,
        owner_cancelled: Option<CancelReason>,
    ) -> Result<Vec<T>, QuorumError<E>> {
        let mut values = Vec::new();
        let mut errors = Vec::new();
        let mut panic = None;
        for outcome in self.outcomes {
            match outcome {
                Outcome::Ok(value) => values.push(value),
                Outcome::Err(error) => errors.push(error),
                Outcome::Panicked(payload) if panic.is_none() => panic = Some(payload),
                Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
            }
        }
        // A cleanup panic cannot be hidden by a selected success, invalid
        // parameters, an application error, or owner cancellation.
        if let Some(payload) = panic {
            return Err(QuorumError::Panicked(payload));
        }
        if let Some(reason) = owner_cancelled {
            return Err(QuorumError::Cancelled(reason));
        }
        match decision {
            Decision::Satisfied => {
                // Only the first M observed successes won. Late successes are
                // retained through drain, but never enlarge the selected quorum.
                values.truncate(self.required);
                Ok(values)
            }
            Decision::Invalid => Err(QuorumError::InvalidQuorum {
                required: self.required,
                total: self.total,
            }),
            Decision::OwnerCancelled(reason) => Err(QuorumError::Cancelled(reason)),
            Decision::Impossible => match self.spontaneous_cancel {
                Some(reason) => Err(QuorumError::Cancelled(reason)),
                None => Err(QuorumError::InsufficientSuccesses {
                    required: self.required,
                    total: self.total,
                    achieved: values.len(),
                    errors,
                }),
            },
            Decision::Panicked => unreachable!("selected panic retained through drain"),
        }
    }
}

fn owner_reason(cx: &Cx) -> CancelReason {
    let reason = cx
        .cancel_reason()
        .unwrap_or_else(|| CancelReason::user("task quorum owner cancelled"));
    // Observation is mask-agnostic; acknowledgement respects the owner's mask.
    let _ = cx.checkpoint();
    reason
}

impl<T, E, P> JoinSet<'_, T, E, P>
where
    T: Send + 'static,
    E: Send + 'static,
    P: Policy,
{
    /// Select `required` successful remaining members, cancel and drain the rest.
    ///
    /// This consumes an already-admitted group; it never spawns or retries work.
    /// Application errors and independently cancelled members count against the
    /// available quorum rather than winning a race. An impossible quorum starts
    /// sibling cancellation without waiting for a parked member to finish alone.
    /// Any member panic is fatal, including a panic during loser cleanup.
    ///
    /// Successful values are returned in observed completion order, exactly
    /// `required` of them. Candidates ready at the start of a scan are examined
    /// in spawn order. A pending scan resumes its forward sweep across polling
    /// quanta before revisiting backward wakes. Previously collected members
    /// are excluded from both the count and the result. Values and errors need
    /// not implement `Clone`.
    ///
    /// Selection examines at most 64 candidates per poll, including pending
    /// ones; a parked set does not self-spin. Loser collection also yields after
    /// 64 retired members. The initial cancellation fan-out still visits every
    /// unfinished member before awaiting any cleanup, and does not rewrite an
    /// already-published outcome while waiting for its retirement barrier.
    ///
    /// Every member retires before this returns. Unselected values/errors are
    /// retained until that point, so their destructors cannot interrupt sibling
    /// cleanup. This is a task-completion quorum, NOT agreement on returned data.
    ///
    /// The explicit owner is observed while waiting and throughout loser drain.
    /// Cancellation observed before final publication invalidates a proposed
    /// success, including when the caller was already cancelled at entry. If
    /// loser cancellation already began, those members retain that drain reason;
    /// the returned error records the owner's reason. A panic has precedence.
    ///
    /// `required == 0` or `required > self.len()` is invalid. Since this API
    /// consumes existing tasks, invalid input ALSO cancels and drains them; it
    /// is not permission to abandon admitted work. Without a panic, invalid
    /// parameters take precedence over a concurrent owner cancellation.
    ///
    /// A dropped future requests cancellation via `JoinSet::drop`; the original
    /// regions remain the asynchronous drain backstop. Remaining members receive
    /// that request before destructors of already-collected values or errors run.
    /// Non-cooperative work can still delay completion. There is no forced
    /// preemption or implicit timeout.
    ///
    /// # Errors
    ///
    /// Returns `InvalidQuorum`, `InsufficientSuccesses`, `Cancelled`, or
    /// `Panicked`. Cleanup-induced loser cancellations do not replace an
    /// insufficient-success error. A spontaneous member cancellation only
    /// selects `Cancelled` if the quorum becomes impossible.
    pub async fn join_quorum(
        self,
        cx: &Cx,
        required: usize,
    ) -> Result<Vec<T>, QuorumError<E>> {
        let total = self.len();
        let mut selection = Selection::new(required, total);
        // Local bindings drop in reverse declaration order. Move the member
        // owner out of the function argument AFTER the collected outcomes, so
        // dropping a parked quorum first requests every remaining cancellation.
        // A collected value/error may run arbitrary code (or panic) in Drop;
        // leaving the set in `self` would run that code before its abort loop.
        // The later consuming drain likewise owns the set after `selection`.
        let mut members = self;
        let mut cancelled = pin!(cx.cancelled());
        let mut remaining_candidates = Self::SELECTION_CANDIDATES_PER_POLL;
        let decision = if required == 0 || required > total {
            Decision::Invalid
        } else {
            loop {
                // Poll the SAME member wait and owner observer until one is
                // ready. Dropping a borrowing join wait does not cancel or lose
                // a member; its persistent registration lives on the handle.
                let next = {
                    let mut waiting = pin!(members.next_outcome_bounded(&mut remaining_candidates));
                    poll_fn(|task| {
                        if cancelled.as_mut().poll(task).is_ready() {
                            return Poll::Ready(Err(owner_reason(cx)));
                        }
                        waiting.as_mut().poll(task).map(Ok)
                    })
                    .await
                };
                match next {
                    Err(reason) => break Decision::OwnerCancelled(reason),
                    Ok(Some(outcome)) => {
                        if let Some(decision) = selection.record(outcome) {
                            break decision;
                        }
                    }
                    Ok(None) => break Decision::Impossible,
                }
            }
        };
        let reason = match &decision {
            Decision::Satisfied => CancelReason::race_loser(),
            Decision::OwnerCancelled(reason) => reason.clone(),
            Decision::Impossible | Decision::Invalid | Decision::Panicked => {
                CancelReason::fail_fast()
            }
        };
        let invalid = matches!(&decision, Decision::Invalid);
        let mut owner_cancelled = match &decision {
            Decision::OwnerCancelled(reason) => Some(reason.clone()),
            _ => None,
        };
        let mut drain = pin!(members.cancel_remaining_for_selection(reason));
        let remainder = poll_fn(|task| {
            // Never drop/recreate the drain when the owner aborts. Observe once,
            // then continue polling the same uninterruptible retirement barrier.
            if !invalid && owner_cancelled.is_none() && cancelled.as_mut().poll(task).is_ready() {
                owner_cancelled = Some(owner_reason(cx));
            }
            drain.as_mut().poll(task)
        })
        .await;
        // Deliberately do not call record: these are cleanup outcomes, not new
        // votes or spontaneous cancellations. They still participate in panic
        // precedence and are kept alive until the entire group is retired.
        selection.outcomes.extend(remainder);
        selection.finish(decision, owner_cancelled)
    }

    /// Return the first successful remaining member after all siblings retire.
    ///
    /// This is [`Self::join_quorum`] with `required = 1`, not first-completion
    /// racing: an early application error does not defeat a later success.
    /// An empty remaining set is invalid. Owner cancellation, cleanup, panic
    /// precedence and the no-retry boundary are identical to `join_quorum`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::join_quorum`].
    pub async fn join_first_ok(self, cx: &Cx) -> Result<T, QuorumError<E>> {
        let mut values = self.join_quorum(cx, 1).await?;
        Ok(values.pop().expect("one successful member selected"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PanicPayload;

    #[test]
    fn impossible_quorum_is_decided_before_parked_suffix() {
        let mut selection = Selection::<u8, &str>::new(3, 4);
        assert!(selection.record(Outcome::Err("first")).is_none());
        let decision = selection.record(Outcome::Err("second")).unwrap();
        assert!(matches!(decision, Decision::Impossible));
        selection.outcomes.extend([
            Outcome::Cancelled(CancelReason::fail_fast()),
            Outcome::Cancelled(CancelReason::fail_fast()),
        ]);
        assert!(matches!(selection.finish(decision, None),
            Err(QuorumError::InsufficientSuccesses { required: 3, total: 4, achieved: 0, errors })
            if errors == ["first", "second"]));
    }

    #[test]
    fn quorum_keeps_only_selected_successes_after_late_retirement() {
        let mut selection = Selection::<u8, &str>::new(2, 4);
        assert!(selection.record(Outcome::Err("retryable application failure")).is_none());
        assert!(selection.record(Outcome::Ok(8)).is_none());
        let decision = selection.record(Outcome::Ok(3)).unwrap();
        selection.outcomes.push(Outcome::Ok(99));
        assert_eq!(selection.finish(decision, None).unwrap(), [8, 3]);
    }

    #[test]
    fn cleanup_panic_overrides_success_owner_cancel_and_invalid_input() {
        for decision in [Decision::Satisfied, Decision::Invalid, Decision::Impossible] {
            let mut selection = Selection::<u8, &str>::new(1, 2);
            selection.outcomes.push(Outcome::Ok(7));
            selection.outcomes.push(Outcome::Panicked(PanicPayload::new("cleanup")));
            assert!(matches!(selection.finish(decision, Some(CancelReason::shutdown())),
                Err(QuorumError::Panicked(_))));
        }
    }

    #[test]
    fn spontaneous_cancellation_does_not_prevent_an_achievable_quorum() {
        let mut selection = Selection::<u8, &str>::new(1, 2);
        assert!(selection.record(Outcome::Cancelled(CancelReason::shutdown())).is_none());
        let decision = selection.record(Outcome::Ok(6)).unwrap();
        assert_eq!(selection.finish(decision, None).unwrap(), [6]);
    }

    /// Review r32-e8 of 915d1ff53 (M2): when member cancellations make the
    /// quorum impossible, the strongest reason is reported, not the first
    /// (br-asupersync-1sngsf). Cleanup cancellations of the losers do not vote.
    #[test]
    fn impossible_quorum_reports_the_strongest_spontaneous_cancellation() {
        let mut selection = Selection::<u8, &str>::new(2, 3);
        assert!(
            selection
                .record(Outcome::Cancelled(CancelReason::user("member's own stop")))
                .is_none()
        );
        let decision = selection
            .record(Outcome::Cancelled(CancelReason::shutdown()))
            .unwrap();
        assert!(matches!(decision, Decision::Impossible));
        selection
            .outcomes
            .push(Outcome::Cancelled(CancelReason::fail_fast()));
        let Err(QuorumError::Cancelled(reason)) = selection.finish(decision, None) else {
            panic!("an impossible quorum after member cancellations reports Cancelled");
        };
        assert_eq!(reason.kind(), CancelReason::shutdown().kind());
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod drop_order_tests {
    use super::*;
    use crate::channel::oneshot;
    use crate::observability::BlockReason;
    use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
    use crate::types::CancelKind;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;

    type Snapshot = Arc<Mutex<Option<Vec<(bool, Option<CancelReason>)>>>>;

    struct DropCheck {
        peers: Vec<Cx>,
        observed: Snapshot,
        panic_on_drop: bool,
    }

    struct Probe(Option<DropCheck>);

    impl Drop for Probe {
        fn drop(&mut self) {
            let Some(check) = self.0.take() else {
                return;
            };
            let snapshot = check
                .peers
                .iter()
                .map(|peer| (peer.is_cancel_requested(), peer.cancel_reason()))
                .collect();
            *check.observed.lock().unwrap() = Some(snapshot);
            assert!(!check.panic_on_drop, "quorum prefix destructor");
        }
    }

    #[derive(Clone, Copy)]
    enum Prefix {
        Value,
        Error,
        FirstOkError,
        OwnerValue,
        OwnerError,
        FailFastValue,
    }

    // A watchdog bounds a broken cancellation path; it is not the state
    // witness. Members publish only after a native wait actually parks.
    fn bounded(test: impl FnOnce() + Send + 'static) {
        let (send, receive) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _ = send.send(catch_unwind(AssertUnwindSafe(test)));
        });
        let result = receive
            .recv_timeout(Duration::from_secs(45))
            .expect("native collector destructor ordering exceeded watchdog");
        thread.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    // Keep the native admission, drop, and delayed-cleanup witness in one
    // sequence so the ordering under test is visible at the call site.
    #[allow(clippy::too_many_lines)]
    fn run_drop_order(workers: usize, prefix: Prefix, panic_on_drop: bool) {
        let builder = if workers == 1 {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::new().worker_threads(workers)
        };
        let runtime = builder.build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("native parent context");
            let mut set = JoinSet::<Probe, Probe, _>::in_cx(&cx);
            // Spawn-order collectors need the completed result first. Supply
            // its payload only after the later members have genuinely parked.
            let (prefix_send, mut prefix_receive) = oneshot::channel::<Result<Probe, Probe>>();
            let (published, mut prefix_id) = oneshot::channel();
            set.spawn(&cx, move |child| async move {
                let outcome = prefix_receive.recv(&child).await.unwrap();
                // Capture the admitted identity, never a provisional mailbox ID.
                published.send_blocking(child.task_id()).unwrap();
                outcome
            })
            .unwrap();
            let mut peers = Vec::new();
            let mut cleanup_witnesses = Vec::new();
            let mut releases = Vec::new();
            let mut completions = Vec::new();
            let cleaned = Arc::new(AtomicUsize::new(0));
            for _ in 0..2 {
                let (ready, mut started) = oneshot::channel();
                let (cleanup_ready, cleanup_witness) = oneshot::channel();
                let (release, mut gate) = oneshot::channel();
                let (done, completion) = oneshot::channel();
                let cleaned = Arc::clone(&cleaned);
                set.spawn(&cx, move |child| async move {
                    let mut ready = Some(ready);
                    let mut cancellation = pin!(child.cancelled());
                    poll_fn(|task| match cancellation.as_mut().poll(task) {
                        Poll::Ready(()) => Poll::Ready(()),
                        Poll::Pending => {
                            if let Some(ready) = ready.take() {
                                ready.send_blocking(child.clone()).unwrap();
                            }
                            Poll::Pending
                        }
                    })
                    .await;
                    assert!(child.checkpoint().is_err());
                    let reason = child.cancel_reason().expect("member cancellation");
                    let mut cleanup_ready = Some(cleanup_ready);
                    // Acknowledged cleanup must be allowed to park again.
                    // The caller releases this wait only AFTER dropping the
                    // collector and witnessing both acknowledgements.
                    poll_fn(|task| {
                        let result = gate.poll_recv_uninterruptible(task);
                        if result.is_pending()
                            && let Some(ready) = cleanup_ready.take()
                        {
                            ready.send_blocking(reason.clone()).unwrap();
                        }
                        result
                    })
                    .await
                    .unwrap();
                    cleaned.fetch_add(1, Ordering::SeqCst);
                    done.send_blocking(()).unwrap();
                    Ok(Probe(None))
                })
                .unwrap();
                peers.push(started.recv(&cx).await.unwrap());
                cleanup_witnesses.push(cleanup_witness);
                releases.push(release);
                completions.push(completion);
            }

            let observed: Snapshot = Arc::new(Mutex::new(None));
            let probe = Probe(Some(DropCheck {
                peers: peers.clone(),
                observed: Arc::clone(&observed),
                panic_on_drop,
            }));
            let outcome = match prefix {
                Prefix::Value | Prefix::OwnerValue | Prefix::FailFastValue => Ok(probe),
                Prefix::Error | Prefix::FirstOkError | Prefix::OwnerError => Err(probe),
            };
            assert!(prefix_send.send_blocking(outcome).is_ok());
            let prefix_id = prefix_id.recv(&cx).await.unwrap();
            // Diagnostics is not Send, so it is read inside the condition: a
            // condition's temporaries are dropped before the body's await.
            while !matches!(
                Runtime::current_handle()
                    .unwrap()
                    .diagnostics()
                    .unwrap()
                    .explain_task_blocked(prefix_id)
                    .block_reason,
                BlockReason::TaskNotFound
            ) {
                yield_now().await;
            }
            // Retirement opens the member's result barrier. The first poll
            // MUST collect its prefix before parking on the two live members.
            // For an error, a 2-of-3 quorum is still possible at this point.
            let mut collecting: std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> =
                match prefix {
                    Prefix::FirstOkError => Box::pin(async {
                        let _ = set.join_first_ok(&cx).await;
                    }),
                    Prefix::Value | Prefix::Error => Box::pin(async {
                        let _ = set.join_quorum(&cx, 2).await;
                    }),
                    Prefix::OwnerValue | Prefix::OwnerError => Box::pin(async {
                        let _ = set.join_all_cancel_on_owner(&cx).await;
                    }),
                    Prefix::FailFastValue => Box::pin(async {
                        let _ = set.try_join_all(&cx).await;
                    }),
                };
            poll_fn(|task| {
                assert!(collecting.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(observed.lock().unwrap().is_none());
            assert!(peers.iter().all(|peer| !peer.is_cancel_requested()));

            let dropped = catch_unwind(AssertUnwindSafe(|| drop(collecting)));
            for mut witness in cleanup_witnesses {
                let reason = witness.recv(&cx).await.unwrap();
                assert_eq!(reason.kind, CancelKind::User);
                assert_eq!(reason.message.as_deref(), Some("abort"));
            }
            assert_eq!(cleaned.load(Ordering::SeqCst), 0);
            for release in releases {
                release.send_blocking(()).unwrap();
            }
            for mut completion in completions {
                completion.recv(&cx).await.unwrap();
            }
            assert_eq!(cleaned.load(Ordering::SeqCst), 2);

            // Assert the planted failure only after releasing cleanup, so the
            // old-code control fails at this property rather than a watchdog.
            let snapshot = observed.lock().unwrap().take().expect("prefix dropped once");
            assert_eq!(snapshot.len(), 2);
            for (requested, reason) in snapshot {
                assert!(requested, "member was not cancelled before prefix destructor");
                let reason = reason.expect("drop cancellation has an exact reason");
                assert_eq!(reason.kind, CancelKind::User);
                assert_eq!(reason.message.as_deref(), Some("abort"));
            }
            assert_eq!(dropped.is_err(), panic_on_drop);
            if let Err(payload) = dropped {
                assert_eq!(payload.downcast_ref::<&str>(), Some(&"quorum prefix destructor"));
            }
        }));
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    #[test]
    fn native_quorum_drop_cancels_before_collected_value_destructors() {
        bounded(|| {
            for workers in [1, 2] {
                for panic_on_drop in [false, true] {
                    run_drop_order(workers, Prefix::Value, panic_on_drop);
                }
            }
        });
    }

    #[test]
    fn native_quorum_drop_cancels_before_collected_error_destructors() {
        bounded(|| {
            for workers in [1, 2] {
                for panic_on_drop in [false, true] {
                    run_drop_order(workers, Prefix::Error, panic_on_drop);
                }
            }
        });
    }

    #[test]
    fn native_first_ok_drop_cancels_before_collected_error_destructors() {
        bounded(|| {
            for workers in [1, 2] {
                for panic_on_drop in [false, true] {
                    run_drop_order(workers, Prefix::FirstOkError, panic_on_drop);
                }
            }
        });
    }

    #[test]
    fn native_owner_join_drop_cancels_before_collected_value_destructors() {
        bounded(|| {
            for workers in [1, 2] {
                for panic_on_drop in [false, true] {
                    run_drop_order(workers, Prefix::OwnerValue, panic_on_drop);
                }
            }
        });
    }

    #[test]
    fn native_owner_join_drop_cancels_before_collected_error_destructors() {
        bounded(|| {
            for workers in [1, 2] {
                for panic_on_drop in [false, true] {
                    run_drop_order(workers, Prefix::OwnerError, panic_on_drop);
                }
            }
        });
    }

    #[test]
    fn native_fail_fast_drop_cancels_before_collected_value_destructors() {
        bounded(|| {
            for workers in [1, 2] {
                for panic_on_drop in [false, true] {
                    run_drop_order(workers, Prefix::FailFastValue, panic_on_drop);
                }
            }
        });
    }
}
