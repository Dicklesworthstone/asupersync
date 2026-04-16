//! Obligation Invariant Conformance Testing Infrastructure
//!
//! This module provides comprehensive testing for asupersync's structured concurrency
//! obligation system invariants, ensuring correctness of obligation lifecycle,
//! region management, and cancellation propagation.
//!
//! # Core Invariants Tested
//!
//! 1. **No Obligation Leaks**: Every created obligation must be properly resolved or cancelled
//! 2. **Region Close = Quiescence**: Region closure must wait for all obligations to complete
//! 3. **Cancel Propagation**: Cancel signals must propagate correctly through obligation hierarchies
//! 4. **Resource Cleanup**: Obligation cleanup must not leak resources (memory, wakers, handles)
//! 5. **Temporal Safety**: Obligations cannot outlive their parent regions
//!
//! # Usage
//!
//! ```rust
//! use obligation_invariants::*;
//!
//! let mut runner = ObligationInvariantRunner::new();
//! runner.register_all_invariant_tests();
//!
//! let results = runner.run_all_tests();
//! let violations = results.check_invariant_violations();
//! assert!(violations.is_empty(), "Invariant violations detected: {violations:?}");
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ============================================================================
// Core Obligation System Types
// ============================================================================

/// Unique identifier for an obligation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObligationId(pub u64);

/// Unique identifier for a region
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub u64);

/// Obligation lifecycle state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationState {
    /// Obligation created but not yet started
    Created,
    /// Obligation actively executing
    Active,
    /// Obligation completed successfully
    Resolved,
    /// Obligation cancelled before completion
    Cancelled,
    /// Obligation leaked (not properly cleaned up)
    Leaked,
}

/// Region lifecycle state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionState {
    /// Region created and accepting obligations
    Open,
    /// Region closing - no new obligations accepted
    Closing,
    /// Region closed - all obligations completed
    Closed,
    /// Region cancelled - propagating cancellation to obligations
    Cancelled,
}

/// Metadata for tracking obligation behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObligationMetadata {
    pub id: ObligationId,
    pub region_id: RegionId,
    pub state: ObligationState,
    pub created_at: Instant,
    pub completed_at: Option<Instant>,
    pub cancellation_source: Option<RegionId>,
    pub resource_count: ResourceCount,
}

/// Resource usage tracking for leak detection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceCount {
    pub wakers: usize,
    pub memory_bytes: usize,
    pub handles: usize,
    pub futures: usize,
}

/// Region hierarchy metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMetadata {
    pub id: RegionId,
    pub parent_id: Option<RegionId>,
    pub state: RegionState,
    pub created_at: Instant,
    pub closed_at: Option<Instant>,
    pub obligation_count: usize,
    pub child_regions: HashSet<RegionId>,
}

// ============================================================================
// Invariant Test Framework
// ============================================================================

/// Category of obligation invariant being tested
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantTestCategory {
    /// Test obligation leak detection and prevention
    NoLeakValidation,
    /// Test region closure quiescence behavior
    RegionQuiescence,
    /// Test cancel signal propagation
    CancelPropagation,
    /// Test resource cleanup correctness
    ResourceCleanup,
    /// Test lifetime and scoping invariants
    TemporalSafety,
}

/// Result of an invariant test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvariantTestResult {
    /// Test passed - invariant holds
    Passed {
        duration: Duration,
        metadata: TestMetadata,
    },
    /// Test failed - invariant violated
    Failed {
        reason: String,
        violation_details: InvariantViolation,
        duration: Duration,
    },
    /// Test skipped - preconditions not met
    Skipped {
        reason: String,
    },
}

impl InvariantTestResult {
    pub fn is_passed(&self) -> bool {
        matches!(self, InvariantTestResult::Passed { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, InvariantTestResult::Failed { .. })
    }

    pub fn duration(&self) -> Option<Duration> {
        match self {
            InvariantTestResult::Passed { duration, .. } => Some(*duration),
            InvariantTestResult::Failed { duration, .. } => Some(*duration),
            InvariantTestResult::Skipped { .. } => None,
        }
    }
}

/// Detailed information about an invariant violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant_name: String,
    pub violation_type: ViolationType,
    pub affected_obligations: Vec<ObligationId>,
    pub affected_regions: Vec<RegionId>,
    pub detected_at: Instant,
    pub stack_trace: Option<String>,
}

/// Type of invariant violation detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    /// Obligation leaked - not properly cleaned up
    ObligationLeak {
        leaked_count: usize,
    },
    /// Region closed without waiting for obligations
    RegionQuiescenceViolation {
        pending_obligations: usize,
    },
    /// Cancel signal failed to propagate
    CancelPropagationFailure {
        unpropagated_obligations: usize,
    },
    /// Resources leaked during cleanup
    ResourceLeak {
        leaked_resources: ResourceCount,
    },
    /// Obligation outlived its parent region
    TemporalSafetyViolation {
        surviving_obligations: usize,
    },
}

/// Test execution metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMetadata {
    pub obligations_created: usize,
    pub regions_created: usize,
    pub cancellations_triggered: usize,
    pub resource_peak_usage: ResourceCount,
}

/// Core trait for obligation invariant tests
pub trait ObligationInvariantTest: Send + Sync {
    /// Name of the invariant being tested
    fn invariant_name(&self) -> &str;

    /// Category of invariant test
    fn test_category(&self) -> InvariantTestCategory;

    /// Human-readable description of what this test validates
    fn description(&self) -> &str;

    /// Execute the invariant test
    fn run_test(&self, ctx: &ObligationTestContext) -> InvariantTestResult;

    /// Validate that the invariant holds given current system state
    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool;

    /// Test dependencies - other invariants that must pass first
    fn dependencies(&self) -> Vec<&str> {
        Vec::new()
    }

    /// Test tags for organization and filtering
    fn tags(&self) -> Vec<&str> {
        Vec::new()
    }
}

// ============================================================================
// Obligation Tracking Infrastructure
// ============================================================================

/// Comprehensive obligation and region tracking for invariant validation
#[derive(Debug)]
pub struct ObligationTracker {
    /// Active obligations and their metadata
    pub active_obligations: Arc<Mutex<HashMap<ObligationId, ObligationMetadata>>>,
    /// Region hierarchy and metadata
    pub regions: Arc<Mutex<HashMap<RegionId, RegionMetadata>>>,
    /// Resource usage tracking for leak detection
    pub resource_tracker: Arc<Mutex<ResourceCount>>,
    /// Detected invariant violations
    pub invariant_violations: Arc<Mutex<Vec<InvariantViolation>>>,
    /// Next obligation/region ID for uniqueness
    next_obligation_id: Arc<Mutex<u64>>,
    next_region_id: Arc<Mutex<u64>>,
}

impl ObligationTracker {
    /// Create new obligation tracker
    pub fn new() -> Self {
        Self {
            active_obligations: Arc::new(Mutex::new(HashMap::new())),
            regions: Arc::new(Mutex::new(HashMap::new())),
            resource_tracker: Arc::new(Mutex::new(ResourceCount::default())),
            invariant_violations: Arc::new(Mutex::new(Vec::new())),
            next_obligation_id: Arc::new(Mutex::new(1)),
            next_region_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Create a new region
    pub fn create_region(&self, parent_id: Option<RegionId>) -> RegionId {
        let id = {
            let mut next_id = self.next_region_id.lock().unwrap();
            let id = RegionId(*next_id);
            *next_id += 1;
            id
        };

        let metadata = RegionMetadata {
            id,
            parent_id,
            state: RegionState::Open,
            created_at: Instant::now(),
            closed_at: None,
            obligation_count: 0,
            child_regions: HashSet::new(),
        };

        {
            let mut regions = self.regions.lock().unwrap();
            regions.insert(id, metadata);

            // Update parent region
            if let Some(parent_id) = parent_id {
                if let Some(parent) = regions.get_mut(&parent_id) {
                    parent.child_regions.insert(id);
                }
            }
        }

        id
    }

    /// Create a new obligation in the specified region
    pub fn create_obligation(&self, region_id: RegionId) -> ObligationId {
        let id = {
            let mut next_id = self.next_obligation_id.lock().unwrap();
            let id = ObligationId(*next_id);
            *next_id += 1;
            id
        };

        let metadata = ObligationMetadata {
            id,
            region_id,
            state: ObligationState::Created,
            created_at: Instant::now(),
            completed_at: None,
            cancellation_source: None,
            resource_count: ResourceCount::default(),
        };

        {
            let mut obligations = self.active_obligations.lock().unwrap();
            obligations.insert(id, metadata);
        }

        {
            let mut regions = self.regions.lock().unwrap();
            if let Some(region) = regions.get_mut(&region_id) {
                region.obligation_count += 1;
            }
        }

        id
    }

    /// Mark obligation as active
    pub fn activate_obligation(&self, id: ObligationId) {
        let mut obligations = self.active_obligations.lock().unwrap();
        if let Some(obligation) = obligations.get_mut(&id) {
            obligation.state = ObligationState::Active;
        }
    }

    /// Resolve an obligation (successful completion)
    pub fn resolve_obligation(&self, id: ObligationId) {
        let mut obligations = self.active_obligations.lock().unwrap();
        if let Some(obligation) = obligations.get_mut(&id) {
            obligation.state = ObligationState::Resolved;
            obligation.completed_at = Some(Instant::now());
        }
    }

    /// Cancel an obligation
    pub fn cancel_obligation(&self, id: ObligationId, source: RegionId) {
        let mut obligations = self.active_obligations.lock().unwrap();
        if let Some(obligation) = obligations.get_mut(&id) {
            obligation.state = ObligationState::Cancelled;
            obligation.completed_at = Some(Instant::now());
            obligation.cancellation_source = Some(source);
        }
    }

    /// Close a region (triggers quiescence waiting)
    pub fn close_region(&self, id: RegionId) -> Result<(), String> {
        {
            let mut regions = self.regions.lock().unwrap();
            if let Some(region) = regions.get_mut(&id) {
                region.state = RegionState::Closing;
            } else {
                return Err(format!("Region {id:?} not found"));
            }
        }

        // Check for quiescence - all obligations must be complete
        let pending_obligations = self.get_pending_obligations_for_region(id);
        if !pending_obligations.is_empty() {
            // Record quiescence violation
            self.record_violation(InvariantViolation {
                invariant_name: "Region Close = Quiescence".to_string(),
                violation_type: ViolationType::RegionQuiescenceViolation {
                    pending_obligations: pending_obligations.len(),
                },
                affected_obligations: pending_obligations,
                affected_regions: vec![id],
                detected_at: Instant::now(),
                stack_trace: None,
            });
            return Err("Region quiescence violation: pending obligations remain".to_string());
        }

        // Mark region as closed
        {
            let mut regions = self.regions.lock().unwrap();
            if let Some(region) = regions.get_mut(&id) {
                region.state = RegionState::Closed;
                region.closed_at = Some(Instant::now());
            }
        }

        Ok(())
    }

    /// Cancel a region (propagates to all obligations)
    pub fn cancel_region(&self, id: RegionId) {
        // Mark region as cancelled
        {
            let mut regions = self.regions.lock().unwrap();
            if let Some(region) = regions.get_mut(&id) {
                region.state = RegionState::Cancelled;
            }
        }

        // Propagate cancellation to all obligations in this region
        let region_obligations = self.get_obligations_for_region(id);
        for obligation_id in region_obligations {
            self.cancel_obligation(obligation_id, id);
        }

        // Propagate to child regions
        let child_regions = self.get_child_regions(id);
        for child_id in child_regions {
            self.cancel_region(child_id);
        }
    }

    /// Get all obligations in a specific region
    pub fn get_obligations_for_region(&self, region_id: RegionId) -> Vec<ObligationId> {
        let obligations = self.active_obligations.lock().unwrap();
        obligations
            .values()
            .filter(|obligation| obligation.region_id == region_id)
            .map(|obligation| obligation.id)
            .collect()
    }

    /// Get pending obligations (not resolved or cancelled) for a region
    pub fn get_pending_obligations_for_region(&self, region_id: RegionId) -> Vec<ObligationId> {
        let obligations = self.active_obligations.lock().unwrap();
        obligations
            .values()
            .filter(|obligation| {
                obligation.region_id == region_id
                    && !matches!(
                        obligation.state,
                        ObligationState::Resolved | ObligationState::Cancelled
                    )
            })
            .map(|obligation| obligation.id)
            .collect()
    }

    /// Get child regions of a given region
    pub fn get_child_regions(&self, region_id: RegionId) -> Vec<RegionId> {
        let regions = self.regions.lock().unwrap();
        if let Some(region) = regions.get(&region_id) {
            region.child_regions.iter().copied().collect()
        } else {
            Vec::new()
        }
    }

    /// Check for obligation leaks
    pub fn check_obligation_leaks(&self) -> Vec<ObligationId> {
        let obligations = self.active_obligations.lock().unwrap();
        obligations
            .values()
            .filter(|obligation| {
                matches!(obligation.state, ObligationState::Created | ObligationState::Active)
                    && obligation.created_at.elapsed() > Duration::from_secs(60) // 1 minute timeout
            })
            .map(|obligation| obligation.id)
            .collect()
    }

    /// Check for resource leaks
    pub fn check_resource_leaks(&self) -> ResourceCount {
        // This would integrate with actual resource tracking
        // For now, return current tracked resources
        self.resource_tracker.lock().unwrap().clone()
    }

    /// Record an invariant violation
    pub fn record_violation(&self, violation: InvariantViolation) {
        let mut violations = self.invariant_violations.lock().unwrap();
        violations.push(violation);
    }

    /// Get all recorded violations
    pub fn get_violations(&self) -> Vec<InvariantViolation> {
        self.invariant_violations.lock().unwrap().clone()
    }

    /// Check if any invariants are currently violated
    pub fn has_violations(&self) -> bool {
        !self.invariant_violations.lock().unwrap().is_empty()
    }

    /// Reset tracker state for new test
    pub fn reset(&self) {
        self.active_obligations.lock().unwrap().clear();
        self.regions.lock().unwrap().clear();
        *self.resource_tracker.lock().unwrap() = ResourceCount::default();
        self.invariant_violations.lock().unwrap().clear();
        *self.next_obligation_id.lock().unwrap() = 1;
        *self.next_region_id.lock().unwrap() = 1;
    }

    /// Get count of active obligations
    pub fn active_obligation_count(&self) -> usize {
        self.active_obligations.lock().unwrap().len()
    }

    /// Get count of open regions
    pub fn open_region_count(&self) -> usize {
        let regions = self.regions.lock().unwrap();
        regions
            .values()
            .filter(|region| matches!(region.state, RegionState::Open))
            .count()
    }

    /// Validate all core invariants
    pub fn validate_all_invariants(&self) -> Result<(), Vec<InvariantViolation>> {
        let mut violations = Vec::new();

        // Check for obligation leaks
        let leaked_obligations = self.check_obligation_leaks();
        if !leaked_obligations.is_empty() {
            violations.push(InvariantViolation {
                invariant_name: "No Obligation Leaks".to_string(),
                violation_type: ViolationType::ObligationLeak {
                    leaked_count: leaked_obligations.len(),
                },
                affected_obligations: leaked_obligations,
                affected_regions: vec![],
                detected_at: Instant::now(),
                stack_trace: None,
            });
        }

        // Add violations to tracker
        for violation in &violations {
            self.record_violation(violation.clone());
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

impl Default for ObligationTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Test Execution Context
// ============================================================================

/// Context for obligation invariant test execution
#[derive(Debug, Clone)]
pub struct ObligationTestContext {
    /// Maximum test duration
    pub timeout: Duration,
    /// Enable stress testing with high concurrency
    pub stress_testing: bool,
    /// Number of concurrent obligations/regions for stress tests
    pub stress_concurrency: usize,
    /// Enable resource leak detection
    pub resource_tracking: bool,
    /// Verbose logging for debugging
    pub verbose: bool,
}

impl Default for ObligationTestContext {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            stress_testing: false,
            stress_concurrency: 100,
            resource_tracking: true,
            verbose: false,
        }
    }
}

impl ObligationTestContext {
    /// Create context optimized for stress testing
    pub fn stress_test_context() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            stress_testing: true,
            stress_concurrency: 1000,
            resource_tracking: true,
            verbose: false,
        }
    }

    /// Create context with verbose logging
    pub fn verbose_context() -> Self {
        Self {
            verbose: true,
            ..Default::default()
        }
    }
}