//! Combinators for structured concurrency.
//!
//! This module provides the core combinators:
//!
//! - [`join`]: Run multiple operations in parallel, waiting for all
//! - [`race`]: Run multiple operations in parallel, first wins
//! - [`select`]: Wait for the first of two futures
//! - [`timeout`]: Add a deadline to an operation
//! - [`bracket`]: Acquire/use/release resource safety pattern
//! - [`retry`]: Retry with exponential backoff
//! - [`quorum`]: M-of-N completion semantics for consensus patterns
//! - [`hedge`]: Latency hedging - start backup after delay, first wins
//! - [`first_ok`]: Try operations sequentially until one succeeds
//! - [`pipeline`]: Chain transformations with staged processing
//! - [`map_reduce`]: Parallel map followed by monoid-based reduction
//! - [`circuit_breaker`]: Failure detection and prevention
//! - [`bulkhead`]: Resource isolation and concurrency limiting

pub mod bracket;
pub mod bulkhead;
pub mod circuit_breaker;
pub mod first_ok;
pub mod hedge;
pub mod join;
pub mod map_reduce;
pub mod pipeline;
pub mod quorum;
pub mod race;
pub mod retry;
pub mod select;
pub mod timeout;

pub use bracket::{bracket, bracket_move, commit_section, try_commit_section};
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
    first_ok_outcomes, first_ok_to_result, FirstOk, FirstOkError, FirstOkFailure, FirstOkResult,
    FirstOkSuccess,
};
pub use hedge::{
    hedge_outcomes, hedge_to_result, Hedge, HedgeConfig, HedgeError, HedgeResult, HedgeWinner,
};
pub use join::{
    aggregate_outcomes, join2_outcomes, join2_to_result, join_all_outcomes, join_all_to_result,
    make_join_all_result, Join, Join2Result, JoinAll, JoinAllError, JoinAllResult, JoinError,
};
pub use map_reduce::{
    make_map_reduce_result, map_reduce_outcomes, map_reduce_to_result, reduce_successes, MapReduce,
    MapReduceError, MapReduceResult,
};
pub use pipeline::{
    pipeline2_outcomes, pipeline3_outcomes, pipeline_n_outcomes, pipeline_to_result,
    pipeline_with_final, stage_outcome_to_result, FailedStage, Pipeline, PipelineConfig,
    PipelineError, PipelineResult,
};
pub use quorum::{
    quorum_achieved, quorum_outcomes, quorum_still_possible, quorum_to_result, Quorum, QuorumError,
    QuorumFailure, QuorumResult,
};
pub use race::{
    make_race_all_result, race2_outcomes, race2_to_result, race_all_outcomes, race_all_to_result,
    Race, Race2Result, RaceAll, RaceAllError, RaceAllResult, RaceError, RaceResult, RaceWinner,
};
pub use retry::{
    calculate_deadline as retry_deadline, calculate_delay, make_retry_result, total_delay_budget,
    AlwaysRetry, NeverRetry, RetryError, RetryFailure, RetryIf, RetryPolicy, RetryPredicate,
    RetryResult, RetryState,
};
pub use select::{Either, Select};
pub use timeout::{
    effective_deadline, make_timed_result, TimedError, TimedResult, Timeout, TimeoutConfig,
    TimeoutError,
};
