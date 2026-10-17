#![allow(clippy::all)]
//! Metamorphic tests for blocking pool task fairness.
//!
//! Tests fairness properties using metamorphic relations to verify that the blocking
//! pool maintains task ordering guarantees, fair thread utilization, and correct
//! priority handling under various transformations.

#[cfg(test)]
#[path = "metamorphic_inline_tests.rs"]
mod tests;
