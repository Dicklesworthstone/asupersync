#![allow(warnings)]
#![allow(clippy::all)]
//! Combinator E2E test modules.
//!
//! Test organization:
//! - `cancel_correctness/` - Critical loser drain and obligation safety tests
//! - `unit/` - Per-combinator unit tests
//! - `stress/` - High-load stress tests

pub mod cancel_correctness;
pub mod unit;
pub mod util;
