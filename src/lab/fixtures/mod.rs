//! Lab test fixtures and E2e scenarios for deterministic testing.
//!
//! This module provides reusable test fixtures and comprehensive E2e test
//! scenarios that can be executed under the lab runtime for deterministic
//! and reproducible testing across different network conditions and regimes.

pub mod repair_roi_e2e;

pub use repair_roi_e2e::{
    E2eReport, ExpectedOutcome, PerformanceImpact, ProofArtifactRef, RegimeSummary,
    RepairDecisionLog, RepairRoiE2eHarness, RepairRoiE2eResult, RepairRoiE2eScenario,
    TransferConfig, TransferResult,
};
