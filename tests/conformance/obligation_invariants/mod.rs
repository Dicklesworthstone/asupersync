//! Obligation invariant conformance test module.
//!
//! This module contains all tests for validating structured concurrency obligation invariants.

pub mod no_leak_tests;
pub mod region_quiescence;
pub mod src;

// Test implementations
pub mod cancel_propagation {
    //! Cancel propagation tests - to be implemented
    pub mod hierarchical_cancel {}
    pub mod cross_region_cancel {}
    pub mod partial_cancel_scenarios {}
    pub mod cancel_race_conditions {}
}

pub mod resource_cleanup {
    //! Resource cleanup tests - to be implemented
    pub mod waker_cleanup_tests {}
    pub mod memory_cleanup_tests {}
    pub mod handle_cleanup_tests {}
    pub mod cleanup_stress_tests {}
}

pub mod temporal_safety {
    //! Temporal safety tests - to be implemented
    pub mod scope_violation_tests {}
    pub mod parent_child_ordering {}
    pub mod use_after_close_tests {}
    pub mod lifetime_stress_tests {}
}

// Re-export main testing infrastructure
pub use src::{
    InvariantTestCategory, InvariantTestConfig, InvariantTestResult, InvariantViolationType,
    ObligationInvariantHarness, ObligationInvariantTest, ObligationTracker, ResourceHandle,
    TestOutcome, WakerHandle,
};

// Re-export specific test implementations
pub use no_leak_tests::obligation_lifecycle::{
    BasicObligationLifecycleTest, ConcurrentObligationTest, ErrorPathCleanupTest,
    NestedObligationTest,
};

pub use region_quiescence::basic_quiescence::{
    BasicRegionQuiescenceTest, ConcurrentRegionClosureTest, NestedRegionQuiescenceTest,
    RegionCloseWithActiveObligationsTest,
};
