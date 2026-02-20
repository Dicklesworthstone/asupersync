//! Combinators for structured concurrency.
//!
//! This module provides the core combinators:
//!
//! - [`join`]: Run multiple operations in parallel, waiting for all
//! - [`race`]: Run multiple operations in parallel, first wins
//! - [`select`]: Wait for the first of two futures
//! - [`timeout`]: Add a deadline to an operation
//! - [`bracket`](mod@bracket): Acquire/use/release resource safety pattern
//! - [`retry`]: Retry with exponential backoff
//! - [`quorum`]: M-of-N completion semantics for consensus patterns
//! - [`hedge`]: Latency hedging - start backup after delay, first wins
//! - [`first_ok`]: Try operations sequentially until one succeeds
//! - [`pipeline`]: Chain transformations with staged processing
//! - [`map_reduce`]: Parallel map followed by monoid-based reduction
//! - [`circuit_breaker`]: Failure detection and prevention
//! - [`bulkhead`]: Resource isolation and concurrency limiting
//! - [`rate_limit`]: Throughput control with token bucket algorithm

pub mod bracket;
pub mod bulkhead;
pub mod circuit_breaker;
pub mod first_ok;
pub mod hedge;
pub mod join;
pub mod laws;
pub mod map_reduce;
pub mod pipeline;
pub mod quorum;
pub mod race;
pub mod rate_limit;
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
    FirstOk, FirstOkError, FirstOkFailure, FirstOkResult, FirstOkSuccess, first_ok_outcomes,
    first_ok_to_result,
};
pub use hedge::{
    Hedge, HedgeConfig, HedgeError, HedgeFuture, HedgeResult, HedgeWinner, hedge, hedge_outcomes,
    hedge_to_result,
};
pub use join::{
    Join, Join2Result, JoinAll, JoinAllError, JoinAllResult, JoinError, aggregate_outcomes,
    join_all_outcomes, join_all_to_result, join2_outcomes, join2_to_result, make_join_all_result,
};
pub use map_reduce::{
    MapReduce, MapReduceError, MapReduceResult, make_map_reduce_result, map_reduce_outcomes,
    map_reduce_to_result, reduce_successes,
};
pub use pipeline::{
    FailedStage, Pipeline, PipelineConfig, PipelineError, PipelineResult, pipeline_n_outcomes,
    pipeline_to_result, pipeline_with_final, pipeline2_outcomes, pipeline3_outcomes,
    stage_outcome_to_result,
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
pub use select::{Either, Select, SelectAll, SelectAllDrain, SelectAllDrainResult};
pub use timeout::{
    TimedError, TimedResult, Timeout, TimeoutConfig, TimeoutError, effective_deadline,
    make_timed_result,
};
