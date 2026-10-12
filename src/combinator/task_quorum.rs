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
            Outcome::Cancelled(reason) if self.spontaneous_cancel.is_none() => {
                self.spontaneous_cancel = Some(reason.clone());
            }
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
    /// `required` of them. Already-ready members use `join_next`'s spawn-order
    /// tie-break. Previously collected members are excluded from both the count
    /// and the result. Values and errors need not implement `Clone`.
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
    /// regions remain the asynchronous drain backstop. Non-cooperative work can
    /// still delay completion. There is no forced preemption or implicit timeout.
    ///
    /// # Errors
    ///
    /// Returns `InvalidQuorum`, `InsufficientSuccesses`, `Cancelled`, or
    /// `Panicked`. Cleanup-induced loser cancellations do not replace an
    /// insufficient-success error. A spontaneous member cancellation only
    /// selects `Cancelled` if the quorum becomes impossible.
    pub async fn join_quorum(
        mut self,
        cx: &Cx,
        required: usize,
    ) -> Result<Vec<T>, QuorumError<E>> {
        let total = self.len();
        let mut selection = Selection::new(required, total);
        let mut cancelled = pin!(cx.cancelled());
        let mut completed_in_quantum = 0;
        let decision = if required == 0 || required > total {
            Decision::Invalid
        } else {
            loop {
                // Poll the SAME member wait and owner observer until one is
                // ready. Dropping a borrowing join wait does not cancel or lose
                // a member; its persistent registration lives on the handle.
                let next = {
                    let mut waiting = pin!(self.join_next(cx));
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
                completed_in_quantum += 1;
                if completed_in_quantum == 64 {
                    completed_in_quantum = 0;
                    crate::runtime::yield_now().await;
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
        let mut drain = pin!(self.cancel_all_with_reason(cx, reason));
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
}
