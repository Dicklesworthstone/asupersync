//! Obligation invariant conformance testing infrastructure.
//!
//! This module provides comprehensive testing of all structured concurrency
//! obligation invariants to ensure correctness of the obligation system.

pub mod obligation_tracker;
pub mod invariant_harness;

// Re-export key types for easier access
pub use obligation_tracker::{
    ObligationTracker, ObligationMetadata, ResourceTracker, InvariantViolation,
    InvariantViolationType, ResourceHandle,
};
pub use invariant_harness::{
    ObligationInvariantHarness, ObligationInvariantTest, InvariantTestCategory,
    ObligationTestContext, InvariantTestResult, TestOutcome, InvariantTestConfig,
    TestMetrics, TestSuiteResult, StressTestResult,
};