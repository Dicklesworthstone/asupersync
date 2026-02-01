//! Cancel-correctness tests for combinators.
//!
//! These tests verify the CRITICAL invariant that race losers are fully
//! drained (not just dropped), and that obligations are properly resolved.
//!
//! Test modules:
//! - `loser_drain`: Synchronous drop-semantic tests for drain verification
//! - `obligation_cleanup`: Tests for obligation resolution on cancellation
//! - `async_loser_drain`: LabRuntime-based async tests with oracle verification

pub mod async_loser_drain;
pub mod loser_drain;
pub mod obligation_cleanup;
