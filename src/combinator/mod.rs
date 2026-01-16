//! Combinators for structured concurrency.
//!
//! This module provides the core combinators:
//!
//! - [`join`]: Run multiple operations in parallel, waiting for all
//! - [`race`]: Run multiple operations in parallel, first wins
//! - [`timeout`]: Add a deadline to an operation
//! - [`bracket`]: Acquire/use/release resource safety pattern

pub mod bracket;
pub mod join;
pub mod race;
pub mod timeout;

pub use bracket::{bracket, bracket_move, commit_section, try_commit_section, Bracket};
pub use join::{
    aggregate_outcomes, join2_outcomes, join2_to_result, join_all_outcomes, Join, Join2Result,
    JoinError,
};
pub use race::{
    race2_outcomes, race2_to_result, race_all_outcomes, race_all_to_result, Race, Race2Result,
    RaceAllResult, RaceError, RaceResult, RaceWinner,
};
pub use timeout::{
    effective_deadline, make_timed_result, TimedError, TimedResult, Timeout, TimeoutConfig,
    TimeoutError,
};
