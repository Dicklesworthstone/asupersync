//! Context-aware branches for the existing region-owned race engine.
//!
//! A prebuilt future can retain its caller's `Cx`; cancelling the spawned
//! branch does not cancel that caller. Factories instead receive the actual
//! admitted child context, so a parked operation observes loser cancellation.

use super::{Cx, cap};
use crate::runtime::{JoinError, TaskHandle};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelReason, Time};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

/// One lazy branch receiving its runtime-admitted context, never the parent's.
///
/// Factories and their futures are owned, `Send`, and `'static`. A factory is
/// invoked at most once, after admission. Captured values are dropped without
/// invocation if the race is dropped or refused before that branch starts.
pub type RaceFactory<T> =
    Box<dyn FnOnce(Cx) -> Pin<Box<dyn Future<Output = T> + Send>> + Send>;

struct Admitted<T> {
    handles: Vec<TaskHandle<T>>,
}

impl<T> Admitted<T> {
    async fn refuse(&mut self, reason: CancelReason) -> JoinError {
        // Publish to all siblings before awaiting any one of them: cleanup
        // can depend on a second sibling first observing its cancellation.
        for handle in &self.handles {
            if !handle.is_finished() {
                handle.abort_with_reason(reason.clone());
            }
        }
        let mut refusal = JoinError::Cancelled(reason);
        for handle in &mut self.handles {
            // Do not let the already-cancelled parent short-circuit cleanup.
            // poll_join waits for actual terminal publication and retirement.
            if let Err(JoinError::Panicked(payload)) = poll_fn(|task| handle.poll_join(task)).await {
                if !matches!(refusal, JoinError::Panicked(_)) {
                    refusal = JoinError::Panicked(payload);
                }
            }
        }
        refusal
    }
}

impl<T> Drop for Admitted<T> {
    fn drop(&mut self) {
        for handle in &self.handles {
            if !handle.is_finished() {
                handle.abort();
            }
        }
    }
}

enum Timed<T> {
    Value(T),
    Expired,
}

// Published by the primary itself, not by its waiting owner. Otherwise an
// owner that is not scheduled promptly could start a backup after the primary
// has already completed. Retirement also publishes this on a factory/poll panic.
struct HedgePrimaryCompletion(Arc<AtomicBool>);

impl Drop for HedgePrimaryCompletion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn hedge_cancelled(cx: &Cx) -> JoinError {
    JoinError::Cancelled(
        cx.cancel_reason()
            .unwrap_or_else(|| CancelReason::user("hedge cancelled")),
    )
}

impl Cx<cap::All> {
    /// Start a primary and, after a delay, a backup with its own child context.
    ///
    /// The first terminal branch wins; an application error returned as `T` is
    /// still a value, not a request to retry. Selection, panic precedence and
    /// loser retirement use the same engine as [`Self::race_drained_with`].
    /// Both factories run inside admitted child tasks, including their synchronous
    /// construction code. Pass each factory's `Cx` to its cancel-aware operations.
    ///
    /// Two region-owned task slots are admitted up front. The backup task waits
    /// without invoking its factory until `delay` has elapsed since admission
    /// began. It checks whether the primary has finished before invoking the
    /// backup, even if the owner has not yet polled the race's result. Cancellation
    /// interrupts this wait: a fast primary does not wait out the hedge delay.
    ///
    /// A nonzero delay requires this context's timer capability. A zero delay
    /// makes the backup eligible immediately without requiring time authority. No
    /// ambient timer or detached work is created. Return waits for loser cleanup;
    /// dropping the outer future requests cancellation and leaves asynchronous
    /// draining to the owning region. Uncooperative work can prevent that drain.
    ///
    /// # Errors
    /// Missing timer authority refuses before either factory is invoked. Parent
    /// cancellation and admission failures retain the existing race semantics;
    /// a panic in either child takes precedence over a successful winner.
    pub async fn hedge_drained_with<T, P, PF, B, BF>(
        &self,
        delay: Duration,
        primary: P,
        backup: B,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
        P: FnOnce(Cx) -> PF + Send + 'static,
        PF: Future<Output = T> + Send + 'static,
        B: FnOnce(Cx) -> BF + Send + 'static,
        BF: Future<Output = T> + Send + 'static,
    {
        self.hedge_drained_impl(delay, None, primary, backup).await
    }

    /// Hedge under one overall deadline, then cancel and drain both branches.
    ///
    /// `delay` controls backup eligibility; `duration` starts on this future's
    /// first poll and covers admission plus both attempts. Starting the backup
    /// never resets that deadline. Neither factory starts after expiry is
    /// observed, and a value completed at or after the deadline is ineligible.
    /// The delayed backup checks the overall deadline again before invoking
    /// user code, even when the owner has not yet observed timer completion.
    ///
    /// Requires explicit timer authority even with a zero hedge delay, and
    /// reserves three region-owned tasks (primary, delayed backup, deadline).
    /// A timely winner may return after the deadline because loser cleanup is
    /// awaited. Timeout likewise waits for cleanup, preserving loser-panic
    /// precedence. This is not a wall-clock bound on uncooperative cleanup.
    ///
    /// # Errors
    /// Expiry returns `JoinError::Cancelled` with a timeout reason only after
    /// drain. A zero duration refuses without invoking either factory. Missing
    /// timer authority, cancellation and admission retain the existing refusal
    /// semantics. The non-timeout hedge and legacy Scope APIs are unchanged.
    pub async fn hedge_drained_with_timeout<T, P, PF, B, BF>(
        &self,
        delay: Duration,
        duration: Duration,
        primary: P,
        backup: B,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
        P: FnOnce(Cx) -> PF + Send + 'static,
        PF: Future<Output = T> + Send + 'static,
        B: FnOnce(Cx) -> BF + Send + 'static,
        BF: Future<Output = T> + Send + 'static,
    {
        self.hedge_drained_impl(delay, Some(duration), primary, backup)
            .await
    }

    async fn hedge_drained_impl<T, P, PF, B, BF>(
        &self,
        delay: Duration,
        timeout: Option<Duration>,
        primary: P,
        backup: B,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
        P: FnOnce(Cx) -> PF + Send + 'static,
        PF: Future<Output = T> + Send + 'static,
        B: FnOnce(Cx) -> BF + Send + 'static,
        BF: Future<Output = T> + Send + 'static,
    {
        if self.checkpoint().is_err() {
            return Err(hedge_cancelled(self));
        }
        let schedule = if delay.is_zero() && timeout.is_none() {
            None
        } else {
            let timer = self.timer_driver().ok_or_else(|| {
                JoinError::Cancelled(
                    CancelReason::resource_unavailable()
                        .with_message("delayed or timed hedge requires a timer"),
                )
            })?;
            let now = timer.now();
            Some((timer, now))
        };
        if timeout.is_some_and(|duration| duration.is_zero()) {
            return Err(JoinError::Cancelled(CancelReason::timeout()));
        }
        let limit = schedule.as_ref().and_then(|(timer, now)| {
            timeout.map(|duration| (timer.clone(), *now + duration))
        });
        let delayed = schedule.as_ref().and_then(|(timer, now)| {
            (!delay.is_zero()).then(|| {
                let deadline = *now + delay;
                let deadline = limit.as_ref().map_or(deadline, |(_, end)| deadline.min(*end));
                (timer.clone(), deadline)
            })
        });

        let primary_finished = Arc::new(AtomicBool::new(false));
        let completion = HedgePrimaryCompletion(Arc::clone(&primary_finished));
        let primary: RaceFactory<Result<T, JoinError>> = Box::new(move |child| {
            Box::pin(async move {
                let _completion = completion;
                if child.checkpoint().is_err() {
                    return Err(hedge_cancelled(&child));
                }
                Ok(primary(child).await)
            })
        });
        let backup_limit = limit.clone();
        let backup: RaceFactory<Result<T, JoinError>> = Box::new(move |child| {
            Box::pin(async move {
                if let Some((timer, deadline)) = delayed {
                    let elapsed = {
                        let mut sleep = std::pin::pin!(Sleep::with_timer_driver(deadline, timer));
                        let mut cancelled = std::pin::pin!(child.cancelled());
                        poll_fn(|task| {
                            // Cancellation wins a tie with the timer so a stopped
                            // hedge never starts fresh work just to drain it.
                            if cancelled.as_mut().poll(task).is_ready() {
                                Poll::Ready(false)
                            } else if sleep.as_mut().poll(task).is_ready() {
                                Poll::Ready(true)
                            } else {
                                Poll::Pending
                            }
                        })
                        .await
                    };
                    if !elapsed {
                        return Err(hedge_cancelled(&child));
                    }
                }
                if child.checkpoint().is_err() {
                    return Err(hedge_cancelled(&child));
                }
                if primary_finished.load(Ordering::Acquire) {
                    // Do not publish a synthetic result: it could beat the
                    // primary's retirement barrier and hide its real outcome.
                    child.cancelled().await;
                    return Err(hedge_cancelled(&child));
                }
                if backup_limit.as_ref().is_some_and(|(timer, end)| timer.now() >= *end) {
                    // Delay completion is not permission to start user code
                    // after the overall deadline. The common timed engine
                    // classifies this completion as expiry, then drains.
                    return Err(JoinError::Cancelled(CancelReason::timeout()));
                }
                Ok(backup(child).await)
            })
        });

        let factories = vec![primary, backup];
        match limit {
            Some((timer, deadline)) => {
                self.race_factories_until(timer, deadline, factories).await?
            }
            None => self.race_drained_with(factories).await?,
        }
    }

    /// Race child-context factories, cancelling and draining losing tasks.
    ///
    /// This is the context-aware counterpart of [`Self::race_drained`]. Pass
    /// the factory's `Cx` to its channel, lock and I/O operations. Capturing a
    /// separate parent context inside a factory still defeats child cancellation;
    /// this API cannot rewrite capabilities hidden in user code.
    ///
    /// Uses the existing [`super::Scope::race_all`] selection and drain engine,
    /// preserving winner selection and loser-panic precedence. Synchronous
    /// admission failure cancels every admitted sibling and awaits its actual
    /// terminal before returning. Dropping this future requests cancellation;
    /// the owning region remains the asynchronous cleanup boundary on drop.
    /// Noncooperative user code can prevent draining; no preemption is promised.
    ///
    /// # Errors
    /// Empty input or synchronous admission refusal returns `JoinError::Cancelled` with a
    /// resource-unavailable reason. Parent cancellation retains its cause.
    /// A panic observed while draining takes precedence over admission failure.
    pub async fn race_drained_with<T>(
        &self,
        factories: Vec<RaceFactory<T>>,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        if factories.is_empty() {
            return Err(JoinError::Cancelled(
                CancelReason::resource_unavailable().with_message("factory race requires a branch"),
            ));
        }
        let scope = self.scope();
        let mut admitted = Admitted { handles: Vec::with_capacity(factories.len()) };
        for factory in factories {
            if self.checkpoint().is_err() {
                let reason = self.cancel_reason().unwrap_or_else(|| CancelReason::user("race cancelled"));
                return Err(admitted.refuse(reason).await);
            }
            match self.spawn_in(&scope, factory) {
                Ok(handle) => admitted.handles.push(handle),
                Err(_) => {
                    let reason = CancelReason::resource_unavailable()
                        .with_message("factory race branch admission failed");
                    return Err(admitted.refuse(reason).await);
                }
            }
        }
        // Ownership passes directly to race_all's existing join/drain guards.
        let handles = std::mem::take(&mut admitted.handles);
        scope.race_all(self, handles).await.map(|(value, _)| value)
    }

    /// Named counterpart of [`Self::race_drained_with`]. Names retain the
    /// legacy named-race semantics: labels do not change selection or ownership.
    pub async fn race_drained_with_named<T>(
        &self,
        factories: Vec<(&str, RaceFactory<T>)>,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        self.race_drained_with(factories.into_iter().map(|(_, factory)| factory).collect()).await
    }

    /// Race factories with one deadline, including cancellation and loser drain.
    ///
    /// The deadline competes as one additional region-owned branch. Unlike the
    /// legacy prebuilt-future timeout method, timeout does not drop the race
    /// before cleanup: it wins, cancels the other branches, and drains them.
    /// Thus `duration` bounds winner eligibility, NOT total cleanup latency.
    /// An uncooperative loser can keep this future pending after that deadline.
    ///
    /// Requires the explicit context's timer driver (including its TIME mask)
    /// and one extra task slot. No ambient clock or fallback timer is created.
    /// Factories are not invoked once the deadline is observed expired, and a
    /// value completing at or after the deadline cannot become a timely winner.
    /// A result completed before the deadline may be returned after loser drain.
    ///
    /// # Errors
    /// Missing timer authority or empty input refuses before spawning. Expiry
    /// returns `JoinError::Cancelled(CancelReason::timeout())` after draining;
    /// the existing race engine still preserves a losing task's panic.
    pub async fn race_drained_with_timeout<T>(
        &self,
        duration: Duration,
        factories: Vec<RaceFactory<T>>,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        if self.checkpoint().is_err() {
            return Err(JoinError::Cancelled(
                self.cancel_reason().unwrap_or_else(|| CancelReason::user("race cancelled")),
            ));
        }
        let timer = self.timer_driver().ok_or_else(|| JoinError::Cancelled(
            CancelReason::resource_unavailable().with_message("factory race timeout requires a timer"),
        ))?;
        if factories.is_empty() {
            return Err(JoinError::Cancelled(
                CancelReason::resource_unavailable().with_message("factory race requires a branch"),
            ));
        }
        if duration.is_zero() {
            return Err(JoinError::Cancelled(CancelReason::timeout()));
        }
        let deadline = timer.now() + duration;
        self.race_factories_until(timer, deadline, factories).await
    }

    // Share the same absolute-deadline engine with hedging. Passing an already
    // computed deadline avoids restarting a timeout after backup admission.
    async fn race_factories_until<T>(
        &self,
        timer: TimerDriverHandle,
        deadline: Time,
        factories: Vec<RaceFactory<T>>,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        let mut timed: Vec<RaceFactory<Timed<T>>> = Vec::new();
        for factory in factories {
            let clock = timer.clone();
            timed.push(Box::new(move |child| Box::pin(async move {
                if clock.now() >= deadline {
                    return Timed::Expired;
                }
                let value = factory(child).await;
                if clock.now() >= deadline { Timed::Expired } else { Timed::Value(value) }
            })));
        }
        timed.push(Box::new(move |child| Box::pin(async move {
            // The timer is a loser too: do not wait out its deadline after a
            // user branch wins, or depend on Sleep's ambient cancellation.
            let mut sleep = std::pin::pin!(Sleep::with_timer_driver(deadline, timer));
            let mut cancelled = std::pin::pin!(child.cancelled());
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() || sleep.as_mut().poll(task).is_ready() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }).await;
            Timed::Expired
        })));
        match self.race_drained_with(timed).await? {
            Timed::Value(value) => Ok(value),
            Timed::Expired => Err(JoinError::Cancelled(CancelReason::timeout())),
        }
    }

    /// Named counterpart of [`Self::race_drained_with_timeout`], with the
    /// same extra task slot, explicit timer requirement, and post-timeout drain.
    pub async fn race_drained_with_timeout_named<T>(
        &self,
        duration: Duration,
        factories: Vec<(&str, RaceFactory<T>)>,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        self.race_drained_with_timeout(
            duration, factories.into_iter().map(|(_, factory)| factory).collect(),
        ).await
    }
}
