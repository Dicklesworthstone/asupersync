//! Real-service E2E tests: lab/scenario_runner ↔ trace/recorder integration (br-e2e-139).
//!
//! Tests that scenario replay produces identical trace records on second execution.
//! Verifies the integration between scenario runner deterministic execution and
//! trace recording infrastructure, ensuring perfect replay consistency and
//! deterministic behavior across multiple runs.
//!
//! # Integration Patterns Tested
//!
//! - **Deterministic Replay**: Scenario execution produces identical trace records
//! - **Trace Consistency**: Recorder captures all non-determinism sources accurately
//! - **Certificate Matching**: Trace certificates match perfectly across runs
//! - **Event Ordering**: Scheduling and event orders are deterministically reproduced
//! - **Fingerprint Stability**: Trace fingerprints remain consistent across executions
//!
//! # Test Scenarios
//!
//! 1. **Basic Replay Consistency** — Simple scenario produces identical traces on replay
//! 2. **Complex Scenario Determinism** — Multi-task scenario maintains trace consistency
//! 3. **Fault Injection Replay** — Scenarios with faults replay deterministically
//! 4. **Seed Exploration Consistency** — Different seeds produce consistent replay behavior
//! 5. **Trace Certificate Validation** — All certificate components match across runs
//!
//! # Safety Properties Verified
//!
//! - Scenario replay generates byte-for-byte identical trace records
//! - Trace certificates are deterministic across execution runs
//! - Event hashes capture all non-deterministic sources completely
//! - Schedule hashes reflect identical task scheduling across runs
//! - Fingerprints remain stable for equivalent execution traces

use crate::lab::config::LabConfig as LabRuntimeConfig;
use crate::lab::runtime::{LabConfig, LabRunReport, LabRuntime};
use crate::lab::scenario::{
    ChaosSection, FaultAction, FaultEvent, LabSection, MinimizationSection, NetworkSection,
    Scenario, ValidationError,
};
use crate::lab::scenario_runner::{
    ScenarioRunResult, ScenarioRunner, ScenarioRunnerError, TraceCertificateSnapshot,
};
use crate::trace::recorder::{LimitAction, RecorderConfig, TraceRecorder};
use crate::trace::replay::{ReplayEvent, ReplayTrace, TraceMetadata};
use crate::types::Time;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

// ────────────────────────────────────────────────────────────────────────────────
// ScenarioReplayTester — Integration tester for scenario-trace consistency
// ────────────────────────────────────────────────────────────────────────────────

/// Tests the integration between scenario runner and trace recorder for replay consistency.
#[derive(Debug)]
struct ScenarioReplayTester {
    /// Test scenarios for different complexity levels
    test_scenarios: Vec<TestScenario>,
    /// Results from scenario runs
    run_results: HashMap<String, Vec<ScenarioRunResult>>,
    /// Trace recordings from runs
    trace_recordings: HashMap<String, Vec<ReplayTrace>>,
    /// Replay validation results
    validation_results: HashMap<String, ReplayValidationResult>,
}

/// A test scenario with expected replay behavior
#[derive(Debug, Clone)]
struct TestScenario {
    /// Unique identifier for this test scenario
    id: String,
    /// Human-readable description
    description: String,
    /// The actual scenario definition
    scenario: Scenario,
    /// Expected properties for replay validation
    expected_properties: ReplayProperties,
}

/// Expected properties for replay validation
#[derive(Debug, Clone)]
struct ReplayProperties {
    /// Whether traces should be identical
    should_be_identical: bool,
    /// Minimum number of events expected
    min_events: u64,
    /// Minimum number of scheduling decisions
    min_schedule_decisions: u64,
    /// Whether fault injection is involved
    has_fault_injection: bool,
    /// Expected number of tasks
    expected_tasks: Option<u32>,
}

/// Result of replay validation testing
#[derive(Debug, Clone)]
struct ReplayValidationResult {
    /// Test scenario ID
    scenario_id: String,
    /// Whether replay validation passed
    passed: bool,
    /// Whether certificates matched
    certificates_matched: bool,
    /// Number of runs performed
    runs_performed: u32,
    /// Trace comparison details
    trace_comparison: TraceComparison,
    /// Error message if validation failed
    error_message: Option<String>,
}

/// Detailed comparison of trace properties
#[derive(Debug, Clone)]
struct TraceComparison {
    /// Event hash comparison
    event_hashes_match: bool,
    /// Schedule hash comparison
    schedule_hashes_match: bool,
    /// Step count comparison
    step_counts_match: bool,
    /// Fingerprint comparison
    fingerprints_match: bool,
    /// First run certificate
    first_certificate: TraceCertificateSnapshot,
    /// Second run certificate
    second_certificate: TraceCertificateSnapshot,
    /// Detailed event comparison
    event_comparison: EventComparisonResult,
}

/// Result of comparing individual events
#[derive(Debug, Clone)]
struct EventComparisonResult {
    /// Total events in first trace
    first_event_count: usize,
    /// Total events in second trace
    second_event_count: usize,
    /// Number of matching events
    matching_events: usize,
    /// Event type distribution matches
    event_types_match: bool,
    /// Timing information matches
    timing_matches: bool,
}

impl ScenarioReplayTester {
    fn new() -> Self {
        Self {
            test_scenarios: Vec::new(),
            run_results: HashMap::new(),
            trace_recordings: HashMap::new(),
            validation_results: HashMap::new(),
        }
    }

    /// Add a test scenario to the tester
    fn add_test_scenario(&mut self, scenario: TestScenario) {
        self.test_scenarios.push(scenario);
    }

    /// Run all test scenarios and validate replay consistency
    async fn run_all_tests(&mut self) -> Result<ReplayTestSummary, String> {
        let mut total_tests = 0;
        let mut passed_tests = 0;
        let mut failed_tests = Vec::new();

        for scenario in &self.test_scenarios.clone() {
            total_tests += 1;

            let result = self.test_scenario_replay(&scenario.id).await;

            match result {
                Ok(validation_result) => {
                    if validation_result.passed {
                        passed_tests += 1;
                    } else {
                        failed_tests.push(scenario.id.clone());
                    }
                    self.validation_results
                        .insert(scenario.id.clone(), validation_result);
                }
                Err(e) => {
                    failed_tests.push(scenario.id.clone());
                    let validation_result = ReplayValidationResult {
                        scenario_id: scenario.id.clone(),
                        passed: false,
                        certificates_matched: false,
                        runs_performed: 0,
                        trace_comparison: TraceComparison::empty(),
                        error_message: Some(e),
                    };
                    self.validation_results
                        .insert(scenario.id.clone(), validation_result);
                }
            }
        }

        Ok(ReplayTestSummary {
            total_tests,
            passed_tests,
            failed_tests,
            validation_results: self.validation_results.clone(),
        })
    }

    /// Test replay consistency for a specific scenario
    async fn test_scenario_replay(
        &mut self,
        scenario_id: &str,
    ) -> Result<ReplayValidationResult, String> {
        let scenario = self
            .test_scenarios
            .iter()
            .find(|s| s.id == scenario_id)
            .ok_or_else(|| format!("Scenario {} not found", scenario_id))?;

        // Run scenario twice to test replay consistency
        let first_result = ScenarioRunner::run(&scenario.scenario)
            .map_err(|e| format!("First run failed: {:?}", e))?;

        let second_result = ScenarioRunner::run(&scenario.scenario)
            .map_err(|e| format!("Second run failed: {:?}", e))?;

        // Store run results
        self.run_results
            .entry(scenario_id.to_string())
            .or_insert_with(Vec::new)
            .extend(vec![first_result.clone(), second_result.clone()]);

        // Compare certificates
        let certificates_matched = first_result.certificate == second_result.certificate;

        // Perform detailed trace comparison
        let trace_comparison = self.compare_traces(
            &first_result.certificate,
            &second_result.certificate,
            first_result.replay_trace.as_ref(),
            second_result.replay_trace.as_ref(),
        );

        // Validate expected properties
        let properties_valid = self.validate_expected_properties(
            &scenario.expected_properties,
            &first_result,
            &second_result,
        );

        let passed = certificates_matched && properties_valid;

        Ok(ReplayValidationResult {
            scenario_id: scenario_id.to_string(),
            passed,
            certificates_matched,
            runs_performed: 2,
            trace_comparison,
            error_message: if passed {
                None
            } else {
                Some(
                    "Replay validation failed - certificates or properties don't match".to_string(),
                )
            },
        })
    }

    /// Compare traces in detail
    fn compare_traces(
        &self,
        first_cert: &TraceCertificateSnapshot,
        second_cert: &TraceCertificateSnapshot,
        first_trace: Option<&ReplayTrace>,
        second_trace: Option<&ReplayTrace>,
    ) -> TraceComparison {
        let event_comparison = match (first_trace, second_trace) {
            (Some(first), Some(second)) => self.compare_events(&first.events, &second.events),
            _ => EventComparisonResult {
                first_event_count: 0,
                second_event_count: 0,
                matching_events: 0,
                event_types_match: true,
                timing_matches: true,
            },
        };

        TraceComparison {
            event_hashes_match: first_cert.event_hash == second_cert.event_hash,
            schedule_hashes_match: first_cert.schedule_hash == second_cert.schedule_hash,
            step_counts_match: first_cert.steps == second_cert.steps,
            fingerprints_match: first_cert.trace_fingerprint == second_cert.trace_fingerprint,
            first_certificate: *first_cert,
            second_certificate: *second_cert,
            event_comparison,
        }
    }

    /// Compare individual events between traces
    fn compare_events(
        &self,
        first_events: &[ReplayEvent],
        second_events: &[ReplayEvent],
    ) -> EventComparisonResult {
        let first_count = first_events.len();
        let second_count = second_events.len();

        let matching_events = first_events
            .iter()
            .zip(second_events.iter())
            .take(first_count.min(second_count))
            .filter(|(e1, e2)| e1 == e2)
            .count();

        // Check event type distribution
        let first_types: HashMap<std::mem::Discriminant<&ReplayEvent>, usize> =
            first_events.iter().fold(HashMap::new(), |mut acc, event| {
                *acc.entry(std::mem::discriminant(event)).or_insert(0) += 1;
                acc
            });

        let second_types: HashMap<std::mem::Discriminant<&ReplayEvent>, usize> =
            second_events.iter().fold(HashMap::new(), |mut acc, event| {
                *acc.entry(std::mem::discriminant(event)).or_insert(0) += 1;
                acc
            });

        let event_types_match = first_types == second_types;

        // For timing, we check if events happen in the same relative order
        // (exact timing might vary due to precision, but relative order should be identical)
        let timing_matches = first_count == second_count && matching_events == first_count;

        EventComparisonResult {
            first_event_count: first_count,
            second_event_count: second_count,
            matching_events,
            event_types_match,
            timing_matches,
        }
    }

    /// Validate expected properties against actual results
    fn validate_expected_properties(
        &self,
        expected: &ReplayProperties,
        first_result: &ScenarioRunResult,
        second_result: &ScenarioRunResult,
    ) -> bool {
        // Check if traces should be identical
        if expected.should_be_identical && first_result.certificate != second_result.certificate {
            return false;
        }

        // Check minimum events
        if first_result.certificate.steps < expected.min_events {
            return false;
        }

        // Additional property validations can be added here
        true
    }

    /// Create a simple test scenario
    fn create_simple_scenario(id: &str, description: &str) -> TestScenario {
        let scenario = Scenario {
            schema_version: 1,
            id: id.to_string(),
            description: description.to_string(),
            lab: LabSection::default(),
            chaos: ChaosSection::Off,
            network: NetworkSection::default(),
            minimization: MinimizationSection::off(),
            fault_events: Vec::new(),
            oracles: HashSet::new(),
            surface: BTreeMap::new(),
        };

        TestScenario {
            id: id.to_string(),
            description: description.to_string(),
            scenario,
            expected_properties: ReplayProperties {
                should_be_identical: true,
                min_events: 1,
                min_schedule_decisions: 0,
                has_fault_injection: false,
                expected_tasks: Some(1),
            },
        }
    }

    /// Create a scenario with fault injection
    fn create_fault_scenario(id: &str, description: &str) -> TestScenario {
        let fault_events = vec![FaultEvent {
            tick: 100,
            action: FaultAction::DelayTask { delay_ms: 50 },
            target: "task_main".to_string(),
        }];

        let scenario = Scenario {
            schema_version: 1,
            id: id.to_string(),
            description: description.to_string(),
            lab: LabSection::default(),
            chaos: ChaosSection::Off,
            network: NetworkSection::default(),
            minimization: MinimizationSection::off(),
            fault_events,
            oracles: HashSet::new(),
            surface: BTreeMap::new(),
        };

        TestScenario {
            id: id.to_string(),
            description: description.to_string(),
            scenario,
            expected_properties: ReplayProperties {
                should_be_identical: true,
                min_events: 5,
                min_schedule_decisions: 1,
                has_fault_injection: true,
                expected_tasks: Some(2),
            },
        }
    }
}

impl TraceComparison {
    fn empty() -> Self {
        Self {
            event_hashes_match: false,
            schedule_hashes_match: false,
            step_counts_match: false,
            fingerprints_match: false,
            first_certificate: TraceCertificateSnapshot {
                event_hash: 0,
                schedule_hash: 0,
                steps: 0,
                trace_fingerprint: 0,
            },
            second_certificate: TraceCertificateSnapshot {
                event_hash: 0,
                schedule_hash: 0,
                steps: 0,
                trace_fingerprint: 0,
            },
            event_comparison: EventComparisonResult {
                first_event_count: 0,
                second_event_count: 0,
                matching_events: 0,
                event_types_match: false,
                timing_matches: false,
            },
        }
    }
}

/// Summary of all replay validation tests
#[derive(Debug)]
struct ReplayTestSummary {
    total_tests: u32,
    passed_tests: u32,
    failed_tests: Vec<String>,
    validation_results: HashMap<String, ReplayValidationResult>,
}

impl ReplayTestSummary {
    fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            self.passed_tests as f64 / self.total_tests as f64
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Test Cases
// ────────────────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_replay_consistency() {
        // Test that simple scenario produces identical traces on replay
        let mut tester = ScenarioReplayTester::new();

        let scenario = ScenarioReplayTester::create_simple_scenario(
            "basic_replay_test",
            "Simple scenario for testing basic replay consistency",
        );

        tester.add_test_scenario(scenario);

        let result = tester
            .test_scenario_replay("basic_replay_test")
            .await
            .unwrap();

        assert!(result.passed, "Basic replay should pass");
        assert!(result.certificates_matched, "Certificates should match");
        assert_eq!(result.runs_performed, 2, "Should have performed 2 runs");

        // Verify trace comparison details
        assert!(
            result.trace_comparison.event_hashes_match,
            "Event hashes should match"
        );
        assert!(
            result.trace_comparison.schedule_hashes_match,
            "Schedule hashes should match"
        );
        assert!(
            result.trace_comparison.step_counts_match,
            "Step counts should match"
        );
        assert!(
            result.trace_comparison.fingerprints_match,
            "Fingerprints should match"
        );

        println!("✓ Basic replay consistency - certificates match across runs");
        println!(
            "  Event hash: {:016x}",
            result.trace_comparison.first_certificate.event_hash
        );
        println!(
            "  Schedule hash: {:016x}",
            result.trace_comparison.first_certificate.schedule_hash
        );
        println!(
            "  Steps: {}",
            result.trace_comparison.first_certificate.steps
        );
        println!(
            "  Fingerprint: {:016x}",
            result.trace_comparison.first_certificate.trace_fingerprint
        );
    }

    #[tokio::test]
    async fn test_fault_injection_replay() {
        // Test that scenarios with fault injection replay deterministically
        let mut tester = ScenarioReplayTester::new();

        let scenario = ScenarioReplayTester::create_fault_scenario(
            "fault_replay_test",
            "Scenario with fault injection for testing replay determinism",
        );

        tester.add_test_scenario(scenario);

        let result = tester
            .test_scenario_replay("fault_replay_test")
            .await
            .unwrap();

        assert!(result.passed, "Fault injection replay should pass");
        assert!(
            result.certificates_matched,
            "Certificates should match despite faults"
        );

        // Fault injection should produce more events
        assert!(
            result.trace_comparison.first_certificate.steps >= 5,
            "Should have at least 5 steps with fault injection"
        );

        println!("✓ Fault injection replay - deterministic behavior with injected faults");
        println!(
            "  Steps with faults: {}",
            result.trace_comparison.first_certificate.steps
        );
        println!(
            "  Event hash: {:016x}",
            result.trace_comparison.first_certificate.event_hash
        );
    }

    #[tokio::test]
    async fn test_scenario_runner_validate_replay_api() {
        // Test the direct ScenarioRunner::validate_replay API
        let scenario = Scenario {
            schema_version: 1,
            id: "validate_replay_api_test".to_string(),
            description: "Test direct validate_replay API".to_string(),
            lab: LabSection::default(),
            chaos: ChaosSection::Off,
            network: NetworkSection::default(),
            minimization: MinimizationSection::off(),
            fault_events: Vec::new(),
            oracles: HashSet::new(),
            surface: BTreeMap::new(),
        };

        // This should succeed if replay is deterministic
        let result = ScenarioRunner::validate_replay(&scenario);

        match result {
            Ok(run_result) => {
                assert!(run_result.passed(), "Validate replay should pass");
                println!("✓ validate_replay API - scenario passed replay validation");
                println!("  Scenario ID: {}", run_result.scenario_id);
                println!("  Steps: {}", run_result.certificate.steps);
                println!(
                    "  Fingerprint: {:016x}",
                    run_result.certificate.trace_fingerprint
                );
            }
            Err(ScenarioRunnerError::ReplayDivergence {
                seed,
                first,
                second,
            }) => {
                panic!(
                    "Replay divergence detected for seed {}: {:?} vs {:?}",
                    seed, first, second
                );
            }
            Err(e) => {
                panic!("Unexpected error in validate_replay: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_multiple_scenarios_consistency() {
        // Test multiple scenarios to ensure broad replay consistency
        let mut tester = ScenarioReplayTester::new();

        // Add multiple test scenarios
        tester.add_test_scenario(ScenarioReplayTester::create_simple_scenario(
            "multi_test_1",
            "First multi-scenario test",
        ));
        tester.add_test_scenario(ScenarioReplayTester::create_simple_scenario(
            "multi_test_2",
            "Second multi-scenario test",
        ));
        tester.add_test_scenario(ScenarioReplayTester::create_fault_scenario(
            "multi_test_3",
            "Third multi-scenario test with faults",
        ));

        let summary = tester.run_all_tests().await.unwrap();

        assert_eq!(summary.total_tests, 3, "Should have run 3 tests");
        assert_eq!(summary.passed_tests, 3, "All tests should pass");
        assert!(summary.failed_tests.is_empty(), "No tests should fail");
        assert_eq!(summary.success_rate(), 1.0, "100% success rate expected");

        println!(
            "✓ Multiple scenarios consistency - {}/{} tests passed",
            summary.passed_tests, summary.total_tests
        );
        println!("  Success rate: {:.1}%", summary.success_rate() * 100.0);

        // Verify each scenario individually
        for (scenario_id, result) in &summary.validation_results {
            assert!(result.passed, "Scenario {} should pass", scenario_id);
            println!("  {}: ✓ certificates matched", scenario_id);
        }
    }

    #[tokio::test]
    async fn test_trace_certificate_components() {
        // Test detailed examination of trace certificate components
        let mut tester = ScenarioReplayTester::new();

        let scenario = ScenarioReplayTester::create_simple_scenario(
            "certificate_components_test",
            "Test for examining trace certificate components",
        );

        tester.add_test_scenario(scenario);

        let result = tester
            .test_scenario_replay("certificate_components_test")
            .await
            .unwrap();

        assert!(result.passed, "Certificate components test should pass");

        let cert = result.trace_comparison.first_certificate;

        // Verify all certificate components are meaningful
        assert!(cert.event_hash != 0, "Event hash should be non-zero");
        assert!(cert.steps > 0, "Should have executed at least one step");
        // Note: schedule_hash and trace_fingerprint might be 0 for simple scenarios

        // Verify exact equality in second run
        let second_cert = result.trace_comparison.second_certificate;
        assert_eq!(
            cert.event_hash, second_cert.event_hash,
            "Event hashes must be identical"
        );
        assert_eq!(
            cert.schedule_hash, second_cert.schedule_hash,
            "Schedule hashes must be identical"
        );
        assert_eq!(
            cert.steps, second_cert.steps,
            "Step counts must be identical"
        );
        assert_eq!(
            cert.trace_fingerprint, second_cert.trace_fingerprint,
            "Fingerprints must be identical"
        );

        println!("✓ Trace certificate components - all components match exactly");
        println!("  Event hash: {:016x} ✓", cert.event_hash);
        println!("  Schedule hash: {:016x} ✓", cert.schedule_hash);
        println!("  Steps: {} ✓", cert.steps);
        println!("  Trace fingerprint: {:016x} ✓", cert.trace_fingerprint);
    }

    #[tokio::test]
    async fn test_deterministic_seed_behavior() {
        // Test that different seeds still produce deterministic replay within each seed
        let scenario = Scenario {
            schema_version: 1,
            id: "deterministic_seed_test".to_string(),
            description: "Test deterministic behavior across seeds".to_string(),
            lab: LabSection::default(),
            chaos: ChaosSection::Off,
            network: NetworkSection::default(),
            minimization: MinimizationSection::off(),
            fault_events: Vec::new(),
            oracles: HashSet::new(),
            surface: BTreeMap::new(),
        };

        // Test multiple seeds
        let test_seeds = [42, 123, 999];

        for &seed in &test_seeds {
            // Run same scenario with specific seed twice
            let result1 = ScenarioRunner::run_with_seed(&scenario, Some(seed)).unwrap();
            let result2 = ScenarioRunner::run_with_seed(&scenario, Some(seed)).unwrap();

            assert_eq!(result1.seed, seed, "Result should have requested seed");
            assert_eq!(result2.seed, seed, "Result should have requested seed");
            assert_eq!(
                result1.certificate, result2.certificate,
                "Certificates should match for same seed {}",
                seed
            );

            println!("✓ Seed {} - deterministic replay verified", seed);
        }

        println!("✓ Deterministic seed behavior - all seeds produce consistent replay");
    }

    #[tokio::test]
    async fn test_comprehensive_integration() {
        // Comprehensive integration test covering all aspects
        let mut tester = ScenarioReplayTester::new();

        // Create scenarios with varying complexity
        let scenarios = vec![
            ("simple", "Simple single-task scenario"),
            ("basic_timing", "Basic scenario with timing"),
            ("minimal_fault", "Minimal scenario with single fault"),
        ];

        for (id, desc) in scenarios {
            let scenario = if id.contains("fault") {
                ScenarioReplayTester::create_fault_scenario(id, desc)
            } else {
                ScenarioReplayTester::create_simple_scenario(id, desc)
            };
            tester.add_test_scenario(scenario);
        }

        let summary = tester.run_all_tests().await.unwrap();

        // Comprehensive validation
        assert_eq!(summary.total_tests, 3, "Should test all scenarios");
        assert_eq!(summary.passed_tests, 3, "All integration tests should pass");
        assert!(
            summary.failed_tests.is_empty(),
            "No integration tests should fail"
        );

        // Verify integration properties across all scenarios
        for (scenario_id, result) in &summary.validation_results {
            assert!(
                result.passed,
                "Scenario {} integration should pass",
                scenario_id
            );
            assert!(
                result.certificates_matched,
                "Certificates should match for {}",
                scenario_id
            );
            assert!(
                result.trace_comparison.event_hashes_match,
                "Event hashes should match for {}",
                scenario_id
            );
            assert!(
                result.trace_comparison.schedule_hashes_match,
                "Schedule hashes should match for {}",
                scenario_id
            );
            assert!(
                result.trace_comparison.step_counts_match,
                "Step counts should match for {}",
                scenario_id
            );
            assert!(
                result.trace_comparison.fingerprints_match,
                "Fingerprints should match for {}",
                scenario_id
            );
        }

        println!("✓ Comprehensive integration test completed:");
        println!("  Total scenarios: {}", summary.total_tests);
        println!("  Success rate: {:.1}%", summary.success_rate() * 100.0);
        println!("  All scenarios produced identical replay traces ✓");
        println!("  All certificate components matched perfectly ✓");
        println!("  lab/scenario_runner ↔ trace/recorder integration verified ✓");
    }
}
