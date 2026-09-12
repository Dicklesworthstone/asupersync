//! Combinators for structured concurrency.
//!
//! This module provides the core combinators:
//!
//! - [`join`]: Run multiple operations in parallel, waiting for all
//! - [`race`]: Run multiple operations in parallel, first wins
//! - [`select`]: Wait for the first of two futures
//! - [`timeout`]: Add a deadline to an operation
//! - [`bracket`](mod@bracket): Acquire/use/release resource safety pattern
//! - [`mod@retry`]: Retry with exponential backoff
//! - [`quorum`]: M-of-N completion semantics for consensus patterns
//!   (executed by [`Scope::quorum`](crate::cx::Scope::quorum))
//! - [`mod@hedge`]: Latency hedging - start backup after delay, first wins
//! - [`first_ok`]: Try operations sequentially until one succeeds
//!   (executed by [`Scope::first_ok`](crate::cx::Scope::first_ok) or the
//!   inline [`first_ok!`](crate::first_ok) macro)
//! - [`pipeline`]: Chain transformations with staged processing
//! - [`map_reduce`]: Parallel map followed by monoid-based reduction
//! - [`circuit_breaker`]: Failure detection and prevention
//! - [`bulkhead`]: Resource isolation and concurrency limiting
//! - [`rate_limit`]: Throughput control with token bucket algorithm
//!
//! # Structured fan-out, join, and race
//!
//! <!-- core-api-doctest: join-set-race-join -->
//! ```
//! use asupersync::{CancelReason, Cx, Outcome, main};
//! use asupersync::combinator::{JoinSet, RaceWinner, join2_outcomes, race2_outcomes};
//!
//! #[main]
//! async fn main(cx: &Cx) {
//!     let mut set = JoinSet::in_cx(cx);
//!     set.spawn(cx, |_| async { Ok::<u8, &'static str>(2) })
//!         .expect("spawn successful member");
//!     set.spawn(cx, |_| async { Err::<u8, &'static str>("member failed") })
//!         .expect("spawn failing member");
//!     let members = set.join_all(cx).await;
//!     assert!(members[0].is_ok());
//!     assert!(members[1].is_err());
//!
//!     let (joined, preserved, _) = join2_outcomes(
//!         Outcome::<u8, &str>::Ok(3),
//!         Outcome::<u8, &str>::Err("join failed"),
//!     );
//!     assert!(matches!(joined, Outcome::Err("join failed")));
//!     assert_eq!(preserved, Some(3));
//!
//!     let (winner, which, loser) = race2_outcomes(
//!         RaceWinner::First,
//!         Outcome::<u8, &str>::Ok(5),
//!         Outcome::<u8, &str>::Cancelled(CancelReason::race_loser()),
//!     );
//!     assert!(matches!(winner, Outcome::Ok(5)));
//!     assert!(which.is_first());
//!     assert!(loser.is_cancelled());
//! }
//! ```

/// Counts child terminations independently of a bounded join sweep.
///
/// The executing combinators and the managed supervisor poll a bounded
/// quantum of child handles per coordinator poll, so a sweep over more
/// children spans several polls. A child that finishes at an index the
/// current sweep has already passed wakes the coordinator once, that wake
/// is coalesced with the sweep's own self-wake, and the sweep then ends
/// without revisiting the index; with no other child left to wake it, the
/// coordinator would park forever. Every child carries one of these guards
/// (moved into its future at spawn, so it fires on completion, on
/// cancellation before the first poll, and on unwind), and the coordinator
/// restarts its sweep whenever the tally is ahead of the joins it observed.
pub(crate) struct TerminationTally(pub(crate) std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl TerminationTally {
    /// Tracks only spawns that return an owned join handle. A synchronous
    /// rejection drops the captured guard before returning its error, but
    /// there is no join that could account for that apparent termination.
    pub(crate) fn track_spawn<T, E>(
        terminated: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
        spawn: impl FnOnce(Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let result = spawn(Self(std::sync::Arc::clone(terminated)));
        if result.is_err() {
            terminated.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
        result
    }
}

impl Drop for TerminationTally {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Release);
    }
}

/// Adaptive latency-hedging controllers.
pub mod adaptive_hedge;
#[cfg(test)]
pub mod adaptive_hedge_metamorphic;
pub mod bracket;
#[cfg(test)]
pub mod bracket_metamorphic;
pub mod bulkhead;
#[cfg(test)]
pub mod bulkhead_metamorphic;
pub mod circuit_breaker;
pub mod first_ok;
pub mod hedge;
pub mod join;
pub mod join_set;
pub mod laws;
pub mod map_reduce;
pub mod pipeline;
pub mod quorum;
pub mod race;
#[cfg(test)]
pub mod race_join_dist_metamorphic;
#[cfg(test)]
pub mod race_metamorphic;
pub mod rate_limit;
pub mod retry;
pub mod select;
pub mod timeout;
#[cfg(test)]
pub mod timeout_metamorphic;

pub use adaptive_hedge::PeakEwmaHedgeController;
pub use bracket::{BracketError, bracket, bracket_move, commit_section, try_commit_section};
pub use bulkhead::{
    Bulkhead, BulkheadError, BulkheadMetrics, BulkheadPermit, BulkheadPolicy,
    BulkheadPolicyBuilder, BulkheadRegistry, FullCallback,
};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerError, CircuitBreakerMetrics, CircuitBreakerPolicy,
    CircuitBreakerPolicyBuilder, FailurePredicate, Permit, SlidingWindowConfig, State,
    StateChangeCallback,
};
pub use first_ok::{
    FirstOk, FirstOkError, FirstOkFailure, FirstOkResult, FirstOkSuccess, first_ok_outcomes,
    first_ok_to_result,
};
pub use hedge::{
    AdaptiveHedgePolicy, Hedge, HedgeConfig, HedgeError, HedgeFuture, HedgeResult, HedgeWinner,
    hedge, hedge_outcomes, hedge_to_result,
};
pub use join::{
    Join, Join2Result, JoinAll, JoinAllError, JoinAllResult, JoinError, aggregate_outcomes,
    join_all_outcomes, join_all_to_result, join2_outcomes, join2_to_result, make_join_all_result,
};
pub use join_set::{JoinSet, JoinSummary};
pub use map_reduce::{
    MapReduce, MapReduceError, MapReduceExecution, MapReduceExecutionError, MapReduceLimits,
    MapReduceResult, MapReduceStopCause, execute_map_reduce, make_map_reduce_result,
    map_reduce_outcomes, map_reduce_to_result, reduce_successes,
};
pub use pipeline::{
    FailedStage, Pipeline, PipelineConfig, PipelineError, PipelineExecution,
    PipelineExecutionConfig, PipelineExecutionError, PipelineExecutionReport,
    PipelineExecutionSummary, PipelineResult, pipeline_n_outcomes, pipeline_to_result,
    pipeline_with_final, pipeline2_outcomes, pipeline3_outcomes, stage_outcome_to_result,
};
pub use quorum::{
    Quorum, QuorumError, QuorumFailure, QuorumResult, quorum_achieved, quorum_outcomes,
    quorum_still_possible, quorum_to_result,
};
pub use race::{
    Cancel, PollingOrder, Race, Race2, Race2Result, Race3, Race4, RaceAll, RaceAllError,
    RaceAllResult, RaceError, RaceResult, RaceWinner, make_race_all_result, race_all_outcomes,
    race_all_to_result, race2_outcomes, race2_to_result,
};
pub use rate_limit::{
    RateLimitAlgorithm, RateLimitError, RateLimitMetrics, RateLimitPolicy, RateLimitPolicyBuilder,
    RateLimiter, RateLimiterRegistry, SlidingWindowRateLimiter, WaitStrategy,
};
pub use retry::{
    AlwaysRetry, NeverRetry, Retry, RetryError, RetryFailure, RetryIf, RetryPolicy, RetryPredicate,
    RetryResult, RetryState, calculate_deadline as retry_deadline, calculate_delay,
    make_retry_result, retry, total_delay_budget,
};
pub use select::{
    Either, Select, SelectAll, SelectAllDrain, SelectAllDrainError, SelectAllDrainResult,
    SelectAllError, SelectError,
};
pub use timeout::{
    TimedError, TimedResult, Timeout, TimeoutConfig, TimeoutError, effective_deadline,
    make_timed_result,
};

#[cfg(test)]
mod termination_tally_tests {
    use super::TerminationTally;
    use crate::Cx;
    use crate::runtime::{JoinError, RuntimeBuilder, SpawnError};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn termination_tally_rejected_spawn_preserves_native_child_accounting() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native parent context");
            let terminated = Arc::new(AtomicUsize::new(0));
            let mut completed = TerminationTally::track_spawn(&terminated, |tally| {
                cx.spawn(move |_| async move {
                    let _tally = tally;
                    17
                })
            })
            .unwrap();
            assert_eq!(completed.join(&cx).await, Ok(17));
            assert_eq!(terminated.load(Ordering::Acquire), 1);

            let entered = Arc::new(AtomicUsize::new(0));
            let child_entered = Arc::clone(&entered);
            let pending = cx.pending_spawn_counter_handle().unwrap();
            let before = pending.count();
            let mut unpolled = TerminationTally::track_spawn(&terminated, |tally| {
                cx.spawn(move |child| async move {
                    let _tally = tally;
                    child_entered.fetch_add(1, Ordering::Release);
                    assert!(
                        child.checkpoint().is_err(),
                        "pre-poll abort must be visible in the child's cleanup poll"
                    );
                    let (_sender, mut receiver) = crate::channel::mpsc::channel::<()>(1);
                    assert_eq!(
                        receiver.recv(&child).await,
                        Err(crate::channel::mpsc::RecvError::Cancelled)
                    );
                })
            })
            .unwrap();
            assert_eq!(pending.count(), before + 1, "child is still queued");
            assert_eq!(entered.load(Ordering::Acquire), 0);

            let unavailable = Cx::for_testing();
            let scope = cx.scope();
            for scoped in [false, true] {
                // Explicit old-boundary control: the rejected spawn captures
                // the guard directly, without compensating its Drop. This
                // exercises the old accounting, not an old-commit binary.
                let uncompensated = Arc::new(AtomicUsize::new(0));
                let tally = TerminationTally(Arc::clone(&uncompensated));
                let factory = move |_| async move {
                    let _tally = tally;
                };
                let old_boundary = if scoped {
                    unavailable.spawn_in_cancellation_dominant(&scope, factory)
                } else {
                    unavailable.spawn(factory)
                };
                assert!(matches!(old_boundary, Err(SpawnError::RuntimeUnavailable)));
                assert_eq!(uncompensated.load(Ordering::Acquire), 1);

                let rejected_entered = Arc::clone(&entered);
                let rejected = TerminationTally::track_spawn(&terminated, |tally| {
                    let factory = move |_| async move {
                        let _tally = tally;
                        rejected_entered.fetch_add(1, Ordering::Release);
                    };
                    if scoped {
                        unavailable.spawn_in_cancellation_dominant(&scope, factory)
                    } else {
                        unavailable.spawn(factory)
                    }
                });
                assert!(matches!(rejected, Err(SpawnError::RuntimeUnavailable)));
                assert_eq!(
                    terminated.load(Ordering::Acquire),
                    1,
                    "rejection must not invent a termination or erase the completed child"
                );
                assert_eq!(pending.count(), before + 1);
                assert_eq!(entered.load(Ordering::Acquire), 0);
                eprintln!(
                    "old-boundary control (scoped={scoped}): rejected spawn counted 1 nonexistent child; corrected accounting retains only the 1 completed native child"
                );
            }

            unpolled.abort();
            assert!(matches!(
                unpolled.join(&cx).await,
                Err(JoinError::Cancelled(ref reason))
                    if reason.kind == crate::types::CancelKind::User
            ));
            assert_eq!(
                entered.load(Ordering::Acquire),
                1,
                "pre-poll abort delivers one cleanup poll while retaining task-level cancellation"
            );
            assert_eq!(terminated.load(Ordering::Acquire), 2);
            assert_eq!(pending.count(), before);
        }));
    }

    #[test]
    fn termination_tally_accepted_drop_before_spawn_returns_still_counts() {
        let terminated = Arc::new(AtomicUsize::new(0));
        let result: Result<(), ()> = TerminationTally::track_spawn(&terminated, |tally| {
            // A native child can terminate before its producer gets the
            // accepted handle. That termination must not be compensated.
            drop(tally);
            Ok(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(terminated.load(Ordering::Acquire), 1);
    }
}
