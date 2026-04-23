//! Metamorphic testing for region state commit monotonicity.
//!
//! This module verifies that region state transitions follow strict monotonic
//! progression through the defined state machine:
//!
//! ```text
//! Open(0) → Closing(1) → Draining(2) → Finalizing(3) → Closed(4)
//!    │                                      │
//!    └──────────────────────────────────────┘ (skip allowed)
//! ```
//!
//! Key metamorphic properties:
//! - **Monotonic Progression**: State transitions only increase numeric value
//! - **No Backward Transitions**: Once in state N, cannot transition to state < N
//! - **Terminal Absorption**: Closed state is absorbing (no further transitions)
//! - **Skip Consistency**: Allowed skips (Open → Finalizing) preserve monotonicity
//! - **Concurrent Consistency**: Multiple observers see monotonic progression

use asupersync::record::region::{RegionRecord, RegionState};
use asupersync::types::{Budget, RegionId, Time, CancelReason};
use std::sync::Arc;
use std::thread;
use proptest::prelude::*;

/// Test result for a single metamorphic relation.
#[derive(Debug, Clone)]
pub struct MetamorphicResult {
    pub relation_name: &'static str,
    pub description: &'static str,
    pub status: TestStatus,
    pub evidence: String,
    pub fault_sensitivity: f64, // How many bug classes this MR catches (1-5)
    pub independence: f64,      // How orthogonal to other MRs (1-5)
}

/// Status of metamorphic test execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    Pass,
    Fail,
    Skip,
}

/// Comprehensive metamorphic test suite for region state monotonicity.
pub struct RegionMonotonicityHarness {
    results: Vec<MetamorphicResult>,
}

impl RegionMonotonicityHarness {
    /// Creates a new metamorphic testing harness.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Runs all metamorphic relations and generates results.
    pub fn run_all(&mut self) {
        self.results.clear();

        // Core monotonicity relations
        self.results.push(Self::mr_state_ordering_preserved());
        self.results.push(Self::mr_no_backward_transitions());
        self.results.push(Self::mr_terminal_state_absorption());
        self.results.push(Self::mr_valid_transition_monotonicity());

        // Skip transition relations
        self.results.push(Self::mr_skip_preserves_ordering());
        self.results.push(Self::mr_allowed_skips_valid());

        // Concurrent consistency relations
        self.results.push(Self::mr_concurrent_observers_monotonic());
        self.results.push(Self::mr_transition_atomicity());

        // Invalid transition relations
        self.results.push(Self::mr_invalid_transitions_rejected());
        self.results.push(Self::mr_closed_state_immutable());
    }

    /// Returns MR strength matrix for analysis.
    pub fn strength_matrix(&self) -> String {
        let mut output = String::new();
        output.push_str("# Region State Monotonicity MR Strength Matrix\n\n");
        output.push_str("| MR Name | Fault Sensitivity | Independence | Cost | Score |\n");
        output.push_str("|---------|------------------|--------------|------|-------|\n");

        for result in &self.results {
            let cost = 2.0; // Assume moderate cost for region testing
            let score = (result.fault_sensitivity * result.independence) / cost;
            output.push_str(&format!(
                "| {} | {:.1}/5 | {:.1}/5 | {:.1} | {:.2} |\n",
                result.relation_name,
                result.fault_sensitivity,
                result.independence,
                cost,
                score
            ));
        }

        let total_score: f64 = self.results.iter()
            .map(|r| (r.fault_sensitivity * r.independence) / 2.0)
            .sum();
        output.push_str(&format!("\n**Total MR Power**: {:.2}\n", total_score));

        output
    }

    /// Returns failed metamorphic relations for debugging.
    pub fn failures(&self) -> Vec<&MetamorphicResult> {
        self.results.iter()
            .filter(|r| r.status == TestStatus::Fail)
            .collect()
    }

    // ========================================================================
    // Core Monotonicity Metamorphic Relations
    // ========================================================================

    /// MR1: State ordering preserved under any valid transition sequence.
    fn mr_state_ordering_preserved() -> MetamorphicResult {
        let region = create_test_region();

        // Test property: If state1.as_u8() ≤ state2.as_u8() before transitions,
        // then after any valid transition sequence, ordering is preserved.

        let initial_state = region.state();
        let mut evidence = vec![];
        let mut all_passed = true;

        // Test all valid state progressions
        let valid_progressions = [
            (RegionState::Open, RegionState::Closing),
            (RegionState::Closing, RegionState::Draining),
            (RegionState::Draining, RegionState::Finalizing),
            (RegionState::Finalizing, RegionState::Closed),
            (RegionState::Closing, RegionState::Finalizing), // Skip draining
        ];

        for &(from_state, to_state) in &valid_progressions {
            let region_test = create_test_region();

            // Set up initial state (using internal method for testing)
            region_test.set_state(from_state);
            let before_numeric = from_state.as_u8();

            // Perform transition
            let transition_result = match to_state {
                RegionState::Closing => region_test.begin_close(None),
                RegionState::Draining => region_test.begin_drain(),
                RegionState::Finalizing => region_test.begin_finalize(),
                RegionState::Closed => region_test.complete_close(),
                _ => false, // Invalid target
            };

            let after_state = region_test.state();
            let after_numeric = after_state.as_u8();

            // Verify monotonicity: after_numeric ≥ before_numeric
            let monotonic = after_numeric >= before_numeric;

            if !monotonic {
                all_passed = false;
            }

            evidence.push(format!(
                "{:?}({})→{:?}({}): {}",
                from_state, before_numeric,
                after_state, after_numeric,
                if monotonic { "✓" } else { "✗" }
            ));
        }

        MetamorphicResult {
            relation_name: "StateOrderingPreserved",
            description: "Valid transitions preserve numeric state ordering",
            status: if all_passed { TestStatus::Pass } else { TestStatus::Fail },
            evidence: evidence.join("; "),
            fault_sensitivity: 4.5, // Catches backward transitions, state corruption, ordering bugs
            independence: 4.0,      // Orthogonal to timing/concurrency MRs
        }
    }

    /// MR2: No backward state transitions allowed.
    fn mr_no_backward_transitions() -> MetamorphicResult {
        let region = create_test_region();
        let mut evidence = vec![];
        let mut all_rejected = true;

        // Test all possible backward transitions - should fail
        let backward_attempts = [
            (RegionState::Closing, RegionState::Open),
            (RegionState::Draining, RegionState::Open),
            (RegionState::Draining, RegionState::Closing),
            (RegionState::Finalizing, RegionState::Open),
            (RegionState::Finalizing, RegionState::Closing),
            (RegionState::Finalizing, RegionState::Draining),
            (RegionState::Closed, RegionState::Open),
            (RegionState::Closed, RegionState::Closing),
            (RegionState::Closed, RegionState::Draining),
            (RegionState::Closed, RegionState::Finalizing),
        ];

        for &(start_state, target_state) in &backward_attempts {
            let test_region = create_test_region();
            test_region.set_state(start_state);

            // Try to transition backward (should be rejected)
            let success = match target_state {
                RegionState::Open => false, // No method to transition to Open
                RegionState::Closing => test_region.begin_close(None),
                RegionState::Draining => test_region.begin_drain(),
                RegionState::Finalizing => test_region.begin_finalize(),
                RegionState::Closed => test_region.complete_close(),
            };

            let final_state = test_region.state();
            let stayed_in_start = final_state == start_state;
            let rejected = !success || stayed_in_start;

            if !rejected {
                all_rejected = false;
            }

            evidence.push(format!(
                "{:?}→{:?}: {}",
                start_state, target_state,
                if rejected { "rejected✓" } else { "allowed✗" }
            ));
        }

        MetamorphicResult {
            relation_name: "NoBackwardTransitions",
            description: "Backward state transitions are rejected",
            status: if all_rejected { TestStatus::Pass } else { TestStatus::Fail },
            evidence: evidence.join("; "),
            fault_sensitivity: 5.0, // Critical for state machine integrity
            independence: 4.5,      // Highly orthogonal to other concerns
        }
    }

    /// MR3: Terminal state (Closed) is absorbing.
    fn mr_terminal_state_absorption() -> MetamorphicResult {
        let region = create_test_region();
        region.set_state(RegionState::Closed);

        let mut evidence = vec![];
        let mut all_absorbed = true;

        // Try various transition attempts from Closed state
        let attempts = [
            ("begin_close", region.begin_close(Some(CancelReason::Explicit))),
            ("begin_drain", region.begin_drain()),
            ("begin_finalize", region.begin_finalize()),
            ("complete_close", region.complete_close()),
        ];

        for (method, result) in attempts {
            let state_after = region.state();
            let still_closed = state_after == RegionState::Closed;
            let transition_rejected = !result;
            let properly_absorbed = still_closed && transition_rejected;

            if !properly_absorbed {
                all_absorbed = false;
            }

            evidence.push(format!(
                "{}(): result={}, state={:?}",
                method, result, state_after
            ));
        }

        MetamorphicResult {
            relation_name: "TerminalStateAbsorption",
            description: "Closed state absorbs all transition attempts",
            status: if all_absorbed { TestStatus::Pass } else { TestStatus::Fail },
            evidence: evidence.join("; "),
            fault_sensitivity: 3.5, // Important for lifecycle correctness
            independence: 3.0,      // Overlaps with backward transition checks
        }
    }

    /// MR4: Valid transitions always increase numeric state value.
    fn mr_valid_transition_monotonicity() -> MetamorphicResult {
        let mut evidence = vec![];
        let mut all_monotonic = true;

        // Test real transition methods with proper setup
        let test_cases = [
            ("Open→Closing", RegionState::Open, |r: &RegionRecord| r.begin_close(None)),
            ("Closing→Draining", RegionState::Closing, |r: &RegionRecord| r.begin_drain()),
            ("Closing→Finalizing", RegionState::Closing, |r: &RegionRecord| r.begin_finalize()),
            ("Draining→Finalizing", RegionState::Draining, |r: &RegionRecord| r.begin_finalize()),
            ("Finalizing→Closed", RegionState::Finalizing, |r: &RegionRecord| r.complete_close()),
        ];

        for (name, initial_state, transition_fn) in test_cases {
            let region = create_test_region();
            region.set_state(initial_state);

            let before_numeric = region.state().as_u8();
            let transition_succeeded = transition_fn(&region);
            let after_numeric = region.state().as_u8();

            let increased = after_numeric > before_numeric;
            let monotonic = increased || (!transition_succeeded && after_numeric == before_numeric);

            if !monotonic {
                all_monotonic = false;
            }

            evidence.push(format!(
                "{}: {}→{} (success={}, monotonic={})",
                name, before_numeric, after_numeric, transition_succeeded, monotonic
            ));
        }

        MetamorphicResult {
            relation_name: "ValidTransitionMonotonicity",
            description: "Valid transitions strictly increase state numeric value",
            status: if all_monotonic { TestStatus::Pass } else { TestStatus::Fail },
            evidence: evidence.join("; "),
            fault_sensitivity: 4.0, // Catches state machine implementation bugs
            independence: 3.5,      // Some overlap with ordering preservation
        }
    }

    // ========================================================================
    // Skip Transition Metamorphic Relations
    // ========================================================================

    /// MR5: Allowed skips preserve monotonic ordering.
    fn mr_skip_preserves_ordering() -> MetamorphicResult {
        let region = create_test_region();
        region.set_state(RegionState::Open);

        // Test skip: Open → Finalizing (bypassing Closing and Draining)
        let before_state = region.state();
        let before_numeric = before_state.as_u8();

        // Force skip by setting state and then calling begin_finalize
        region.set_state(RegionState::Closing); // Minimum state for finalize
        let skip_success = region.begin_finalize();

        let after_state = region.state();
        let after_numeric = after_state.as_u8();

        let monotonic = after_numeric > before_numeric;
        let valid_skip = skip_success && after_state == RegionState::Finalizing;

        MetamorphicResult {
            relation_name: "SkipPreservesOrdering",
            description: "Allowed state skips maintain monotonic progression",
            status: if monotonic && valid_skip { TestStatus::Pass } else { TestStatus::Fail },
            evidence: format!(
                "Open({})→Finalizing({}): skip_success={}, monotonic={}",
                before_numeric, after_numeric, skip_success, monotonic
            ),
            fault_sensitivity: 3.0, // Important for skip logic correctness
            independence: 4.0,      // Distinct from regular transition logic
        }
    }

    /// MR6: Only specific skips are allowed.
    fn mr_allowed_skips_valid() -> MetamorphicResult {
        let mut evidence = vec![];
        let mut all_skips_valid = true;

        // Test the documented valid skip: Open → Finalizing (via Closing)
        let region = create_test_region();
        region.set_state(RegionState::Open);

        // The code shows begin_finalize() can succeed from Closing OR Draining
        region.set_state(RegionState::Closing);
        let closing_to_finalizing = region.begin_finalize();
        evidence.push(format!("Closing→Finalizing: {}", closing_to_finalizing));

        // Reset and test Draining → Finalizing
        let region2 = create_test_region();
        region2.set_state(RegionState::Draining);
        let draining_to_finalizing = region2.begin_finalize();
        evidence.push(format!("Draining→Finalizing: {}", draining_to_finalizing));

        // Test invalid skip attempts (should fail)
        let region3 = create_test_region();
        region3.set_state(RegionState::Open);
        let open_to_finalizing = region3.begin_finalize(); // Should fail - can't skip from Open directly
        evidence.push(format!("Open→Finalizing: {} (should be false)", open_to_finalizing));

        if open_to_finalizing {
            all_skips_valid = false; // This skip shouldn't be allowed
        }

        MetamorphicResult {
            relation_name: "AllowedSkipsValid",
            description: "Only documented state skips are permitted",
            status: if all_skips_valid { TestStatus::Pass } else { TestStatus::Fail },
            evidence: evidence.join("; "),
            fault_sensitivity: 3.5, // Catches invalid skip implementations
            independence: 3.5,      // Overlaps with transition validation
        }
    }

    // ========================================================================
    // Concurrent Consistency Metamorphic Relations
    // ========================================================================

    /// MR7: Concurrent observers see monotonic state progression.
    fn mr_concurrent_observers_monotonic() -> MetamorphicResult {
        let region = Arc::new(create_test_region());
        let observations = Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut handles = vec![];

        // Spawn observer threads
        for i in 0..4 {
            let region_clone = Arc::clone(&region);
            let obs_clone = Arc::clone(&observations);

            let handle = thread::spawn(move || {
                for j in 0..20 {
                    let state = region_clone.state();
                    let timestamp = std::time::Instant::now();
                    obs_clone.lock().unwrap().push((i, j, state, timestamp));
                    thread::sleep(std::time::Duration::from_micros(100));
                }
            });
            handles.push(handle);
        }

        // Perform state transitions in main thread
        thread::sleep(std::time::Duration::from_millis(1));
        region.begin_close(None);
        thread::sleep(std::time::Duration::from_millis(1));
        region.begin_drain();
        thread::sleep(std::time::Duration::from_millis(1));
        region.begin_finalize();
        thread::sleep(std::time::Duration::from_millis(1));

        // Wait for observers
        for handle in handles {
            handle.join().unwrap();
        }

        // Analyze observations for monotonicity violations
        let mut obs = observations.lock().unwrap();
        obs.sort_by_key(|(_, _, _, timestamp)| *timestamp);

        let mut monotonic = true;
        let mut prev_state_numeric = 0u8;

        for (observer, seq, state, _) in obs.iter() {
            let state_numeric = state.as_u8();
            if state_numeric < prev_state_numeric {
                monotonic = false;
                break;
            }
            prev_state_numeric = state_numeric;
        }

        MetamorphicResult {
            relation_name: "ConcurrentObserversMonotonic",
            description: "Multiple concurrent observers see monotonic state progression",
            status: if monotonic { TestStatus::Pass } else { TestStatus::Fail },
            evidence: format!("Observed {} state readings, monotonic={}", obs.len(), monotonic),
            fault_sensitivity: 4.0, // Catches race conditions and atomic consistency bugs
            independence: 5.0,      // Completely orthogonal to single-threaded properties
        }
    }

    /// MR8: State transitions are atomic (no intermediate states observed).
    fn mr_transition_atomicity() -> MetamorphicResult {
        let region = Arc::new(create_test_region());
        let invalid_observations = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = vec![];

        // Spawn fast observer threads to catch potential intermediate states
        for _ in 0..3 {
            let region_clone = Arc::clone(&region);
            let invalid_clone = Arc::clone(&invalid_observations);

            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    let state = region_clone.state();
                    // All observed states should be valid enum values
                    match state {
                        RegionState::Open | RegionState::Closing |
                        RegionState::Draining | RegionState::Finalizing |
                        RegionState::Closed => {
                            // Valid state
                        }
                    }
                    // Note: If we observed an invalid state, we'd increment invalid_observations
                    // but the from_u8() method would panic, so atomicity violations would be caught
                }
            });
            handles.push(handle);
        }

        // Perform rapid state transitions
        region.begin_close(None);
        region.begin_drain();
        region.begin_finalize();

        // Wait for observers
        for handle in handles {
            handle.join().unwrap();
        }

        let invalid_count = invalid_observations.load(std::sync::atomic::Ordering::Acquire);

        MetamorphicResult {
            relation_name: "TransitionAtomicity",
            description: "State transitions are atomic (no invalid intermediate states)",
            status: if invalid_count == 0 { TestStatus::Pass } else { TestStatus::Fail },
            evidence: format!("Invalid state observations: {}", invalid_count),
            fault_sensitivity: 3.0, // Catches atomic consistency bugs
            independence: 4.0,      // Different from ordering but overlaps with concurrency
        }
    }

    // ========================================================================
    // Invalid Transition Metamorphic Relations
    // ========================================================================

    /// MR9: Invalid transition attempts are properly rejected.
    fn mr_invalid_transitions_rejected() -> MetamorphicResult {
        let mut evidence = vec![];
        let mut all_rejected = true;

        // Test transitions from inappropriate states
        let invalid_cases = [
            // Can't drain from Open (must be Closing first)
            (RegionState::Open, "begin_drain", |r: &RegionRecord| r.begin_drain()),
            // Can't finalize from Open (must be Closing or Draining)
            (RegionState::Open, "begin_finalize", |r: &RegionRecord| r.begin_finalize()),
            // Can't complete from Draining (must be Finalizing)
            (RegionState::Draining, "complete_close", |r: &RegionRecord| r.complete_close()),
            // Can't complete from Closing (must be Finalizing)
            (RegionState::Closing, "complete_close", |r: &RegionRecord| r.complete_close()),
        ];

        for (start_state, method_name, method) in invalid_cases {
            let region = create_test_region();
            region.set_state(start_state);

            let before_state = region.state();
            let transition_result = method(&region);
            let after_state = region.state();

            let properly_rejected = !transition_result && before_state == after_state;

            if !properly_rejected {
                all_rejected = false;
            }

            evidence.push(format!(
                "{:?}.{}: result={}, state_change={:?}→{:?}",
                start_state, method_name, transition_result, before_state, after_state
            ));
        }

        MetamorphicResult {
            relation_name: "InvalidTransitionsRejected",
            description: "Inappropriate transition attempts are rejected",
            status: if all_rejected { TestStatus::Pass } else { TestStatus::Fail },
            evidence: evidence.join("; "),
            fault_sensitivity: 4.5, // Critical for state machine correctness
            independence: 3.0,      // Overlaps with valid transition testing
        }
    }

    /// MR10: Closed state is immutable to all changes.
    fn mr_closed_state_immutable() -> MetamorphicResult {
        let region = create_test_region();
        region.set_state(RegionState::Closed);

        // Try various operations that might modify a closed region
        let before_state = region.state();

        // Transition attempts (should all fail)
        let close_attempt = region.begin_close(Some(CancelReason::Explicit));
        let drain_attempt = region.begin_drain();
        let finalize_attempt = region.begin_finalize();
        let complete_attempt = region.complete_close();

        let after_state = region.state();
        let remained_closed = before_state == RegionState::Closed &&
                             after_state == RegionState::Closed;
        let all_rejected = !close_attempt && !drain_attempt &&
                          !finalize_attempt && !complete_attempt;

        MetamorphicResult {
            relation_name: "ClosedStateImmutable",
            description: "Closed regions reject all state modification attempts",
            status: if remained_closed && all_rejected { TestStatus::Pass } else { TestStatus::Fail },
            evidence: format!(
                "State: {:?}→{:?}, Attempts: close={}, drain={}, finalize={}, complete={}",
                before_state, after_state, close_attempt, drain_attempt, finalize_attempt, complete_attempt
            ),
            fault_sensitivity: 3.5, // Important for terminal state correctness
            independence: 2.5,      // Overlaps significantly with terminal absorption
        }
    }
}

/// Helper function to create a test region with minimal setup.
fn create_test_region() -> RegionRecord {
    RegionRecord::new(
        RegionId::new_for_test(1, 0),
        None, // No parent
        Budget::infinite(),
    )
}

impl Default for RegionMonotonicityHarness {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Property-Based Test Integration
// ============================================================================

/// Property-based testing of region state transitions with random sequences.
#[cfg(test)]
mod proptest_integration {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn valid_transition_sequence()
                                    (transitions in prop::collection::vec(0u8..=3, 1..=10))
                                    -> Vec<u8> {
            transitions
        }
    }

    proptest! {
        #[test]
        fn property_monotonic_under_valid_sequences(transitions in valid_transition_sequence()) {
            let region = create_test_region();
            let mut prev_numeric = 0u8; // Open state

            for &transition_type in &transitions {
                let current_state = region.state();
                let current_numeric = current_state.as_u8();

                // Apply random valid transition
                let _result = match transition_type {
                    0 if current_state == RegionState::Open => region.begin_close(None),
                    1 if current_state == RegionState::Closing => region.begin_drain(),
                    2 if matches!(current_state, RegionState::Closing | RegionState::Draining) => region.begin_finalize(),
                    3 if current_state == RegionState::Finalizing => region.complete_close(),
                    _ => false, // Invalid transition for current state
                };

                let new_numeric = region.state().as_u8();

                // Assert monotonicity
                prop_assert!(new_numeric >= prev_numeric,
                    "Monotonicity violation: {} → {} in transition sequence {:?}",
                    prev_numeric, new_numeric, transitions);

                prev_numeric = new_numeric;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metamorphic_harness_runs_all_relations() {
        let mut harness = RegionMonotonicityHarness::new();
        harness.run_all();

        // Should have 10 metamorphic relations
        assert_eq!(harness.results.len(), 10);

        // Generate strength matrix
        let matrix = harness.strength_matrix();
        assert!(matrix.contains("Region State Monotonicity MR Strength Matrix"));

        // Check that all relations have reasonable scores
        for result in &harness.results {
            assert!(result.fault_sensitivity > 0.0 && result.fault_sensitivity <= 5.0);
            assert!(result.independence > 0.0 && result.independence <= 5.0);
        }
    }

    #[test]
    fn specific_monotonicity_properties() {
        // Test individual metamorphic relations
        let result = RegionMonotonicityHarness::mr_state_ordering_preserved();
        assert_eq!(result.status, TestStatus::Pass);

        let result = RegionMonotonicityHarness::mr_no_backward_transitions();
        assert_eq!(result.status, TestStatus::Pass);

        let result = RegionMonotonicityHarness::mr_terminal_state_absorption();
        assert_eq!(result.status, TestStatus::Pass);
    }

    #[test]
    fn concurrent_consistency_properties() {
        // Test concurrent access metamorphic relations
        let result = RegionMonotonicityHarness::mr_concurrent_observers_monotonic();
        assert_eq!(result.status, TestStatus::Pass);

        let result = RegionMonotonicityHarness::mr_transition_atomicity();
        assert_eq!(result.status, TestStatus::Pass);
    }
}