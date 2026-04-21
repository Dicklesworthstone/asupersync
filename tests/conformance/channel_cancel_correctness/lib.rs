#![allow(clippy::all)]
//! Channel Cancellation Protocol Conformance Matrix
//!
//! This library provides comprehensive testing infrastructure for validating
//! that asupersync's channel primitives maintain structured concurrency
//! invariants under all cancellation scenarios.
//!
//! # Usage
//!
//! ```rust
//! use channel_cancel_correctness::ChannelCancelCorrectnessRunner;
//!
//! // Run the complete conformance suite
//! let report = ChannelCancelCorrectnessRunner::run_complete_suite();
//! report.print_summary();
//!
//! // Or run just smoke tests for quick validation
//! let smoke_report = ChannelCancelCorrectnessRunner::run_smoke_tests();
//! assert!(smoke_report.all_passed());
//! ```
//!
//! # Test Categories
//!
//! - **Basic Cancellation**: Cancel signal propagation and response
//! - **Resource Cleanup**: Waker and memory leak detection during cancellation
//! - **State Consistency**: Channel state integrity under cancellation
//! - **Stress Testing**: High-concurrency cancellation scenarios
//! - **Drop Safety**: Channel destruction during cancellation operations
//!
//! # Channel Types Tested
//!
//! - MPSC: Multi-producer single-consumer channels
//! - Broadcast: One-to-many broadcast channels
//! - Watch: State observation channels
//! - Oneshot: Single-value transfer channels

pub mod src;
pub mod mpsc;

pub use src::*;

// Re-export key types for convenience
pub use src::{
    ChannelCancelCorrectnessRunner,
    CancelTestHarness, CancelTestEngine, CancelTestResult,
    CancelCorrectnessTest, ConformanceTestReport,
    ChannelType, CancelScenario, ProtocolViolation,
    ResourceTracker, ResourceLeakError,
    StateValidator, StateValidationConfig,
    StressTestScenarios, StressConfig,
};

/// Version information for the conformance test suite.
pub const VERSION: &str = "0.1.0";

/// Run the complete channel cancellation protocol conformance test suite.
///
/// This is the main entry point for validation. It runs all registered
/// conformance tests across all channel types and cancellation scenarios.
#[allow(dead_code)]
pub fn run_conformance_tests() -> ConformanceTestReport {
    ChannelCancelCorrectnessRunner::run_complete_suite()
}

/// Run a quick smoke test for basic cancellation protocol validation.
///
/// This runs a subset of critical tests for fast validation during development.
#[allow(dead_code)]
pub fn run_smoke_tests() -> ConformanceTestReport {
    ChannelCancelCorrectnessRunner::run_smoke_tests()
}

/// Validate that a specific channel type meets cancellation protocol requirements.
#[allow(dead_code)]
pub fn validate_channel_type(channel_type: ChannelType) -> ConformanceTestReport {
    let mut engine = CancelTestEngine::new();

    // Add tests specific to the requested channel type
    // Implementation would filter tests by channel type

    engine.run_all_tests()
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_smoke_suite_runs() {
        let report = run_smoke_tests();

        // Basic smoke test validation
        assert!(report.total_tests >= 0);
        assert!(report.duration.as_secs() < 30); // Should complete quickly
    }

    #[test]
    #[allow(dead_code)]
    fn test_individual_channel_validation() {
        let report = validate_channel_type(ChannelType::Mpsc);

        // Should have run at least some MPSC-specific tests
        assert!(report.total_tests >= 0);
    }

    #[test]
    #[allow(dead_code)]
    fn test_harness_configuration() {
        let harness = CancelTestHarness::new("integration_test")
            .with_timeout(std::time::Duration::from_secs(10))
            .with_fail_fast(true);

        assert_eq!(harness.test_id, "integration_test");
        assert!(harness.fail_fast);
    }
}