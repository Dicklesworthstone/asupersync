//! Obligation invariant conformance testing infrastructure.
//!
//! This module provides comprehensive testing of all structured concurrency
//! obligation invariants to ensure correctness of the obligation system.

pub mod invariant_harness;
pub mod obligation_tracker;

// Re-export key types for easier access
pub use invariant_harness::{
    InvariantTestCategory, InvariantTestConfig, InvariantTestResult, ObligationInvariantHarness,
    ObligationInvariantTest, ObligationTestContext, StressTestResult, TestMetrics, TestOutcome,
    TestSuiteResult,
};
pub use obligation_tracker::{
    InvariantViolation, InvariantViolationType, ObligationMetadata, ObligationTracker,
    ResourceHandle, ResourceTracker,
};
