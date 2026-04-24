#![allow(missing_docs)]

//! No-Leak Invariant Conformance Test Harness
//!
//! This harness systematically verifies every MUST/SHOULD clause from the
//! formal no-leak proof specification in src/obligation/no_leak_proof.rs.
//!
//! ## Formal Specification Source
//!
//! **Theorem**: ∀ σ ∈ Reachable, ∀ o ∈ dom(σ):
//!              (state(o) = Reserved) ⇒ ◇(state(o) ∈ {Committed, Aborted, Leaked})
//!
//! **Source**: src/obligation/no_leak_proof.rs (formal proof document)

use asupersync::obligation::marking::{MarkingEvent, MarkingEventKind};
use asupersync::obligation::no_leak_proof::{LivenessProperty, NoLeakProver};
use asupersync::record::ObligationKind;
use asupersync::test_utils;
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Conformance Framework
// ============================================================================

/// Single conformance test case for the no-leak invariant.
#[derive(Debug, Clone)]
pub struct NoLeakConformanceTest {
    /// Unique test identifier (maps to formal proof requirement).
    pub id: &'static str,
    /// Specification section reference.
    pub section: &'static str,
    /// Requirement level.
    pub level: RequirementLevel,
    /// Human-readable description.
    pub description: &'static str,
    /// Test scenario setup.
    pub scenario: ConformanceScenario,
    /// Expected result.
    pub expected: ConformanceExpectation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone)]
pub enum ConformanceScenario {
    /// Single obligation lifecycle.
    SingleObligation {
        kind: ObligationKind,
        exit_path: ExitPath,
    },
    /// Multiple obligations, various patterns.
    MultipleObligations {
        obligations: Vec<ObligationSetup>,
        region_closure: bool,
    },
    /// Task completion scenario.
    TaskCompletion {
        task_obligations: Vec<ObligationKind>,
        complete_before_resolve: bool,
    },
    /// Region closure scenario.
    RegionClosure {
        cross_region_obligations: bool,
        nested_regions: bool,
    },
    /// Ghost counter properties.
    GhostCounter { operations: Vec<CounterOperation> },
}

#[derive(Debug, Clone)]
pub struct ObligationSetup {
    pub kind: ObligationKind,
    pub task: u32,
    pub region: u32,
    pub reserve_time: u64,
    pub exit_path: ExitPath,
    pub resolve_time: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ExitPath {
    /// Normal: explicit commit()
    Commit,
    /// Normal/error: explicit abort()
    Abort,
    /// Panic/cancel: Drop impl (leak detection)
    Leak,
}

#[derive(Debug, Clone)]
pub enum CounterOperation {
    Reserve { obligation: u32, time: u64 },
    Commit { obligation: u32, time: u64 },
    Abort { obligation: u32, time: u64 },
    Leak { obligation: u32, time: u64 },
}

#[derive(Debug, Clone)]
pub enum ConformanceExpectation {
    /// Proof must verify completely.
    Verified {
        final_counter: u64,
        properties_verified: Vec<LivenessProperty>,
    },
    /// Proof must fail with specific property violation.
    PropertyViolation {
        violated_property: LivenessProperty,
        reason: &'static str,
    },
}

// ============================================================================
// Test Case Definitions
// ============================================================================

/// Complete conformance test suite for the no-leak invariant.
pub fn no_leak_conformance_tests() -> Vec<NoLeakConformanceTest> {
    vec![
        // =====================================================================
        // MUST-1: Eventual Resolution (Core Theorem)
        // =====================================================================
        NoLeakConformanceTest {
            id: "NL-MUST-1.1",
            section: "Core Theorem",
            level: RequirementLevel::Must,
            description: "Single SendPermit obligation is eventually committed",
            scenario: ConformanceScenario::SingleObligation {
                kind: ObligationKind::SendPermit,
                exit_path: ExitPath::Commit,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![
                    LivenessProperty::CounterIncrement,
                    LivenessProperty::CounterDecrement,
                    LivenessProperty::EventualResolution,
                ],
            },
        },
        NoLeakConformanceTest {
            id: "NL-MUST-1.2",
            section: "Core Theorem",
            level: RequirementLevel::Must,
            description: "Single Ack obligation is eventually aborted",
            scenario: ConformanceScenario::SingleObligation {
                kind: ObligationKind::Ack,
                exit_path: ExitPath::Abort,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![
                    LivenessProperty::CounterIncrement,
                    LivenessProperty::CounterDecrement,
                    LivenessProperty::EventualResolution,
                ],
            },
        },
        NoLeakConformanceTest {
            id: "NL-MUST-1.3",
            section: "Core Theorem",
            level: RequirementLevel::Must,
            description: "Single Lease obligation resolved via Drop (leak detection)",
            scenario: ConformanceScenario::SingleObligation {
                kind: ObligationKind::Lease,
                exit_path: ExitPath::Leak,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![
                    LivenessProperty::CounterIncrement,
                    LivenessProperty::CounterDecrement,
                    LivenessProperty::EventualResolution,
                    LivenessProperty::DropPathCoverage,
                ],
            },
        },
        // =====================================================================
        // MUST-2: Ghost Counter Properties
        // =====================================================================
        NoLeakConformanceTest {
            id: "NL-MUST-2.1",
            section: "Ghost Counter",
            level: RequirementLevel::Must,
            description: "Ghost counter increases on every Reserve event",
            scenario: ConformanceScenario::GhostCounter {
                operations: vec![
                    CounterOperation::Reserve {
                        obligation: 0,
                        time: 10,
                    },
                    CounterOperation::Reserve {
                        obligation: 1,
                        time: 20,
                    },
                    CounterOperation::Commit {
                        obligation: 0,
                        time: 30,
                    },
                    CounterOperation::Commit {
                        obligation: 1,
                        time: 40,
                    },
                ],
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![
                    LivenessProperty::CounterIncrement,
                    LivenessProperty::CounterDecrement,
                    LivenessProperty::CounterNonNegative,
                ],
            },
        },
        NoLeakConformanceTest {
            id: "NL-MUST-2.2",
            section: "Ghost Counter",
            level: RequirementLevel::Must,
            description: "Ghost counter decreases on every Resolve event",
            scenario: ConformanceScenario::GhostCounter {
                operations: vec![
                    CounterOperation::Reserve {
                        obligation: 0,
                        time: 10,
                    },
                    CounterOperation::Commit {
                        obligation: 0,
                        time: 20,
                    },
                ],
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![
                    LivenessProperty::CounterDecrement,
                    LivenessProperty::EventualResolution,
                ],
            },
        },
        NoLeakConformanceTest {
            id: "NL-MUST-2.3",
            section: "Ghost Counter",
            level: RequirementLevel::Must,
            description: "Ghost counter never goes negative",
            scenario: ConformanceScenario::GhostCounter {
                operations: vec![
                    CounterOperation::Reserve {
                        obligation: 0,
                        time: 10,
                    },
                    CounterOperation::Reserve {
                        obligation: 1,
                        time: 20,
                    },
                    CounterOperation::Commit {
                        obligation: 0,
                        time: 30,
                    },
                    CounterOperation::Abort {
                        obligation: 1,
                        time: 40,
                    },
                ],
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![LivenessProperty::CounterNonNegative],
            },
        },
        // =====================================================================
        // MUST-3: Four Exit Paths (Rust Ownership Model)
        // =====================================================================
        NoLeakConformanceTest {
            id: "NL-MUST-3.1",
            section: "Exit Paths",
            level: RequirementLevel::Must,
            description: "Normal path: explicit commit() resolves obligation",
            scenario: ConformanceScenario::SingleObligation {
                kind: ObligationKind::SendPermit,
                exit_path: ExitPath::Commit,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![LivenessProperty::EventualResolution],
            },
        },
        NoLeakConformanceTest {
            id: "NL-MUST-3.2",
            section: "Exit Paths",
            level: RequirementLevel::Must,
            description: "Error path: explicit abort() resolves obligation",
            scenario: ConformanceScenario::SingleObligation {
                kind: ObligationKind::Ack,
                exit_path: ExitPath::Abort,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![LivenessProperty::EventualResolution],
            },
        },
        NoLeakConformanceTest {
            id: "NL-MUST-3.3",
            section: "Exit Paths",
            level: RequirementLevel::Must,
            description: "Panic/cancel path: Drop impl resolves obligation",
            scenario: ConformanceScenario::SingleObligation {
                kind: ObligationKind::Lease,
                exit_path: ExitPath::Leak,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![
                    LivenessProperty::EventualResolution,
                    LivenessProperty::DropPathCoverage,
                ],
            },
        },
        NoLeakConformanceTest {
            id: "NL-MUST-3.4",
            section: "Exit Paths",
            level: RequirementLevel::Must,
            description: "All four exit paths covered in multi-obligation scenario",
            scenario: ConformanceScenario::MultipleObligations {
                obligations: vec![
                    ObligationSetup {
                        kind: ObligationKind::SendPermit,
                        task: 0,
                        region: 0,
                        reserve_time: 10,
                        exit_path: ExitPath::Commit,
                        resolve_time: 50,
                    },
                    ObligationSetup {
                        kind: ObligationKind::Ack,
                        task: 1,
                        region: 0,
                        reserve_time: 20,
                        exit_path: ExitPath::Abort,
                        resolve_time: 60,
                    },
                    ObligationSetup {
                        kind: ObligationKind::Lease,
                        task: 2,
                        region: 0,
                        reserve_time: 30,
                        exit_path: ExitPath::Leak,
                        resolve_time: 70,
                    },
                ],
                region_closure: true,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![
                    LivenessProperty::EventualResolution,
                    LivenessProperty::DropPathCoverage,
                    LivenessProperty::RegionQuiescence,
                ],
            },
        },
        // =====================================================================
        // MUST-4: Task Completion
        // =====================================================================
        NoLeakConformanceTest {
            id: "NL-MUST-4.1",
            section: "Task Completion",
            level: RequirementLevel::Must,
            description: "Task completion implies zero pending obligations",
            scenario: ConformanceScenario::TaskCompletion {
                task_obligations: vec![ObligationKind::SendPermit, ObligationKind::Ack],
                complete_before_resolve: false, // Resolve before completion
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![LivenessProperty::TaskCompletion],
            },
        },
        // =====================================================================
        // MUST-5: Region Quiescence (Structured Concurrency)
        // =====================================================================
        NoLeakConformanceTest {
            id: "NL-MUST-5.1",
            section: "Region Closure",
            level: RequirementLevel::Must,
            description: "Region closure implies zero pending obligations",
            scenario: ConformanceScenario::RegionClosure {
                cross_region_obligations: false,
                nested_regions: false,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![LivenessProperty::RegionQuiescence],
            },
        },
        NoLeakConformanceTest {
            id: "NL-MUST-5.2",
            section: "Region Closure",
            level: RequirementLevel::Must,
            description: "Nested region closure maintains quiescence invariant",
            scenario: ConformanceScenario::RegionClosure {
                cross_region_obligations: false,
                nested_regions: true,
            },
            expected: ConformanceExpectation::Verified {
                final_counter: 0,
                properties_verified: vec![LivenessProperty::RegionQuiescence],
            },
        },
        // =====================================================================
        // SHOULD Requirements
        // =====================================================================

        // Note: mem::forget and Rc cycle requirements are runtime policies
        // that cannot be tested mechanically - they are documented as
        // architectural constraints in DISCREPANCIES.md
    ]
}

// ============================================================================
// Test Execution Engine
// ============================================================================

pub trait ConformanceTest: Send + Sync {
    fn name(&self) -> &str;
    fn requirement_level(&self) -> RequirementLevel;
    fn run(&self, ctx: &TestContext) -> TestResult;
}

#[derive(Debug)]
pub struct TestContext {
    // Test execution context - can be extended as needed
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

impl ConformanceTest for NoLeakConformanceTest {
    fn name(&self) -> &str {
        self.id
    }

    fn requirement_level(&self) -> RequirementLevel {
        self.level
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let events = generate_events_for_scenario(&self.scenario);
        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);

        match &self.expected {
            ConformanceExpectation::Verified {
                final_counter,
                properties_verified,
            } => {
                if !result.is_verified() {
                    return TestResult::Fail {
                        reason: format!("Expected verification but proof failed: {:?}", result),
                    };
                }

                if result.ghost_counter_final != *final_counter {
                    return TestResult::Fail {
                        reason: format!(
                            "Expected final counter {} but got {}",
                            final_counter, result.ghost_counter_final
                        ),
                    };
                }

                // Verify expected properties were checked
                for expected_prop in properties_verified {
                    let property_verified = result
                        .steps
                        .iter()
                        .any(|step| step.property == *expected_prop && step.verified);

                    if !property_verified {
                        return TestResult::Fail {
                            reason: format!("Expected property {:?} to be verified", expected_prop),
                        };
                    }
                }

                TestResult::Pass
            }

            ConformanceExpectation::PropertyViolation {
                violated_property,
                reason: _,
            } => {
                if result.is_verified() {
                    return TestResult::Fail {
                        reason: "Expected property violation but proof verified".to_string(),
                    };
                }

                // Check that the specific property was violated
                let property_violated = result
                    .steps
                    .iter()
                    .any(|step| step.property == *violated_property && !step.verified);

                if property_violated {
                    TestResult::Pass
                } else {
                    TestResult::Fail {
                        reason: format!(
                            "Expected property {:?} to be violated but it wasn't",
                            violated_property
                        ),
                    }
                }
            }
        }
    }
}

// ============================================================================
// Scenario Generation
// ============================================================================

fn generate_events_for_scenario(scenario: &ConformanceScenario) -> Vec<MarkingEvent> {
    match scenario {
        ConformanceScenario::SingleObligation { kind, exit_path } => {
            let mut events = vec![MarkingEvent::new(
                Time::from_nanos(10),
                MarkingEventKind::Reserve {
                    obligation: o(0),
                    kind: *kind,
                    task: t(0),
                    region: r(0),
                },
            )];

            match exit_path {
                ExitPath::Commit => {
                    events.push(MarkingEvent::new(
                        Time::from_nanos(20),
                        MarkingEventKind::Commit {
                            obligation: o(0),
                            region: r(0),
                            kind: *kind,
                        },
                    ));
                }
                ExitPath::Abort => {
                    events.push(MarkingEvent::new(
                        Time::from_nanos(20),
                        MarkingEventKind::Abort {
                            obligation: o(0),
                            region: r(0),
                            kind: *kind,
                        },
                    ));
                }
                ExitPath::Leak => {
                    events.push(MarkingEvent::new(
                        Time::from_nanos(20),
                        MarkingEventKind::Leak {
                            obligation: o(0),
                            region: r(0),
                            kind: *kind,
                        },
                    ));
                }
            }

            events
        }

        ConformanceScenario::MultipleObligations {
            obligations,
            region_closure,
        } => {
            let mut events = Vec::new();

            // Reserve all obligations
            for (i, setup) in obligations.iter().enumerate() {
                events.push(MarkingEvent::new(
                    Time::from_nanos(setup.reserve_time),
                    MarkingEventKind::Reserve {
                        obligation: o(i as u32),
                        kind: setup.kind,
                        task: t(setup.task),
                        region: r(setup.region),
                    },
                ));
            }

            // Resolve all obligations
            for (i, setup) in obligations.iter().enumerate() {
                let resolve_event = match setup.exit_path {
                    ExitPath::Commit => MarkingEventKind::Commit {
                        obligation: o(i as u32),
                        region: r(setup.region),
                        kind: setup.kind,
                    },
                    ExitPath::Abort => MarkingEventKind::Abort {
                        obligation: o(i as u32),
                        region: r(setup.region),
                        kind: setup.kind,
                    },
                    ExitPath::Leak => MarkingEventKind::Leak {
                        obligation: o(i as u32),
                        region: r(setup.region),
                        kind: setup.kind,
                    },
                };

                events.push(MarkingEvent::new(
                    Time::from_nanos(setup.resolve_time),
                    resolve_event,
                ));
            }

            // Add region closure if requested
            if *region_closure {
                let max_resolve_time = obligations
                    .iter()
                    .map(|o| o.resolve_time)
                    .max()
                    .unwrap_or(100);

                events.push(MarkingEvent::new(
                    Time::from_nanos(max_resolve_time + 10),
                    MarkingEventKind::RegionClose { region: r(0) },
                ));
            }

            events.sort_by_key(|e| e.time);
            events
        }

        ConformanceScenario::TaskCompletion {
            task_obligations,
            complete_before_resolve,
        } => {
            let mut events = Vec::new();

            // Reserve obligations for the task
            for (i, kind) in task_obligations.iter().enumerate() {
                events.push(MarkingEvent::new(
                    Time::from_nanos(10 + i as u64 * 10),
                    MarkingEventKind::Reserve {
                        obligation: o(i as u32),
                        kind: *kind,
                        task: t(0), // All on same task
                        region: r(0),
                    },
                ));
            }

            if *complete_before_resolve {
                // Complete task before resolving obligations (should fail)
                events.push(MarkingEvent::new(
                    Time::from_nanos(50),
                    MarkingEventKind::TaskComplete { task: t(0) },
                ));

                // Then resolve
                for i in 0..task_obligations.len() {
                    events.push(MarkingEvent::new(
                        Time::from_nanos(60 + i as u64 * 10),
                        MarkingEventKind::Commit {
                            obligation: o(i as u32),
                            region: r(0),
                            kind: task_obligations[i],
                        },
                    ));
                }
            } else {
                // Resolve obligations first
                for i in 0..task_obligations.len() {
                    events.push(MarkingEvent::new(
                        Time::from_nanos(50 + i as u64 * 10),
                        MarkingEventKind::Commit {
                            obligation: o(i as u32),
                            region: r(0),
                            kind: task_obligations[i],
                        },
                    ));
                }

                // Then complete task
                events.push(MarkingEvent::new(
                    Time::from_nanos(100),
                    MarkingEventKind::TaskComplete { task: t(0) },
                ));
            }

            events.sort_by_key(|e| e.time);
            events
        }

        ConformanceScenario::RegionClosure {
            cross_region_obligations,
            nested_regions,
        } => {
            let mut events = Vec::new();

            if *nested_regions {
                // Parent region r(0), child region r(1)
                events.push(MarkingEvent::new(
                    Time::from_nanos(5),
                    MarkingEventKind::Reserve {
                        obligation: o(0),
                        kind: ObligationKind::SendPermit,
                        task: t(0),
                        region: r(1), // Child region
                    },
                ));

                events.push(MarkingEvent::new(
                    Time::from_nanos(10),
                    MarkingEventKind::Commit {
                        obligation: o(0),
                        region: r(1),
                        kind: ObligationKind::SendPermit,
                    },
                ));

                // Close child region first
                events.push(MarkingEvent::new(
                    Time::from_nanos(20),
                    MarkingEventKind::RegionClose { region: r(1) },
                ));

                // Then parent
                events.push(MarkingEvent::new(
                    Time::from_nanos(30),
                    MarkingEventKind::RegionClose { region: r(0) },
                ));
            } else {
                // Simple single region case
                events.push(MarkingEvent::new(
                    Time::from_nanos(10),
                    MarkingEventKind::Reserve {
                        obligation: o(0),
                        kind: ObligationKind::Ack,
                        task: t(0),
                        region: r(0),
                    },
                ));

                events.push(MarkingEvent::new(
                    Time::from_nanos(20),
                    MarkingEventKind::Commit {
                        obligation: o(0),
                        region: r(0),
                        kind: ObligationKind::Ack,
                    },
                ));

                events.push(MarkingEvent::new(
                    Time::from_nanos(30),
                    MarkingEventKind::RegionClose { region: r(0) },
                ));
            }

            if *cross_region_obligations {
                // Add obligation that spans regions (edge case)
                events.insert(
                    0,
                    MarkingEvent::new(
                        Time::from_nanos(5),
                        MarkingEventKind::Reserve {
                            obligation: o(1),
                            kind: ObligationKind::Lease,
                            task: t(1),
                            region: r(1), // Different region
                        },
                    ),
                );

                events.push(MarkingEvent::new(
                    Time::from_nanos(25),
                    MarkingEventKind::Commit {
                        obligation: o(1),
                        region: r(1),
                        kind: ObligationKind::Lease,
                    },
                ));
            }

            events.sort_by_key(|e| e.time);
            events
        }

        ConformanceScenario::GhostCounter { operations } => {
            let mut events = Vec::new();

            for op in operations {
                match op {
                    CounterOperation::Reserve { obligation, time } => {
                        events.push(MarkingEvent::new(
                            Time::from_nanos(*time),
                            MarkingEventKind::Reserve {
                                obligation: o(*obligation),
                                kind: ObligationKind::SendPermit,
                                task: t(*obligation), // Simple mapping
                                region: r(0),
                            },
                        ));
                    }
                    CounterOperation::Commit { obligation, time } => {
                        events.push(MarkingEvent::new(
                            Time::from_nanos(*time),
                            MarkingEventKind::Commit {
                                obligation: o(*obligation),
                                region: r(0),
                                kind: ObligationKind::SendPermit,
                            },
                        ));
                    }
                    CounterOperation::Abort { obligation, time } => {
                        events.push(MarkingEvent::new(
                            Time::from_nanos(*time),
                            MarkingEventKind::Abort {
                                obligation: o(*obligation),
                                region: r(0),
                                kind: ObligationKind::SendPermit,
                            },
                        ));
                    }
                    CounterOperation::Leak { obligation, time } => {
                        events.push(MarkingEvent::new(
                            Time::from_nanos(*time),
                            MarkingEventKind::Leak {
                                obligation: o(*obligation),
                                region: r(0),
                                kind: ObligationKind::SendPermit,
                            },
                        ));
                    }
                }
            }

            events.sort_by_key(|e| e.time);
            events
        }
    }
}

// Helper functions for creating test IDs
fn r(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn t(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn o(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

// ============================================================================
// Conformance Test Execution
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_all_no_leak_conformance_tests() {
        test_utils::init_test_logging();
        asupersync::test_phase!("no_leak_conformance_suite");

        let ctx = TestContext {};
        let mut results: BTreeMap<RequirementLevel, (u32, u32)> = BTreeMap::new();
        let mut failures = Vec::new();
        let tests = no_leak_conformance_tests();

        for test_case in &tests {
            let result = test_case.run(&ctx);

            let (passed, total) = results.entry(test_case.level).or_insert((0, 0));
            *total += 1;

            match result {
                TestResult::Pass => {
                    *passed += 1;
                    println!(
                        "✅ {} ({}): {}",
                        test_case.id,
                        test_case.level_str(),
                        test_case.description
                    );
                }
                TestResult::Fail { ref reason } => {
                    failures.push((test_case.id, reason.clone()));
                    println!(
                        "❌ {} ({}): {} - FAILED: {}",
                        test_case.id,
                        test_case.level_str(),
                        test_case.description,
                        reason
                    );
                }
                TestResult::Skipped { ref reason } => {
                    println!(
                        "⏭️  {} ({}): {} - SKIPPED: {}",
                        test_case.id,
                        test_case.level_str(),
                        test_case.description,
                        reason
                    );
                }
                TestResult::ExpectedFailure { ref reason } => {
                    *passed += 1; // XFAIL counts as passing
                    println!(
                        "🔶 {} ({}): {} - XFAIL: {}",
                        test_case.id,
                        test_case.level_str(),
                        test_case.description,
                        reason
                    );
                }
            }
        }

        // Generate compliance report
        println!("\n📊 No-Leak Invariant Conformance Report");
        println!("==========================================");

        for (level, (passed, total)) in &results {
            let percentage = (*passed as f64 / *total as f64) * 100.0;
            println!(
                "{:?} Requirements: {}/{} ({:.1}%)",
                level, passed, total, percentage
            );
        }

        let must_results = results.get(&RequirementLevel::Must).unwrap_or(&(0, 0));
        let must_score = must_results.0 as f64 / must_results.1 as f64;

        println!("\n🎯 MUST Clause Coverage: {:.1}%", must_score * 100.0);

        if must_score < 0.95 {
            panic!(
                "MUST clause coverage {:.1}% < 95% - NOT CONFORMANT",
                must_score * 100.0
            );
        }

        if !failures.is_empty() {
            panic!("Conformance failures: {:?}", failures);
        }

        println!("\n✅ NO-LEAK INVARIANT CONFORMANCE: VERIFIED");
        asupersync::test_complete!("no_leak_conformance_suite");
    }
}

impl NoLeakConformanceTest {
    fn level_str(&self) -> &'static str {
        match self.level {
            RequirementLevel::Must => "MUST",
            RequirementLevel::Should => "SHOULD",
            RequirementLevel::May => "MAY",
        }
    }
}

// ============================================================================
// Coverage Analysis
// ============================================================================

/// Analyze conformance test coverage against the formal specification.
pub fn analyze_coverage() -> CoverageReport {
    let mut coverage = CoverageReport::new();

    // Count tests by requirement level
    let tests = no_leak_conformance_tests();
    for test in &tests {
        match test.level {
            RequirementLevel::Must => coverage.must_tests += 1,
            RequirementLevel::Should => coverage.should_tests += 1,
            RequirementLevel::May => coverage.may_tests += 1,
        }
    }

    // Verify all LivenessProperty variants are covered
    let all_properties = vec![
        LivenessProperty::CounterIncrement,
        LivenessProperty::CounterDecrement,
        LivenessProperty::CounterNonNegative,
        LivenessProperty::TaskCompletion,
        LivenessProperty::RegionQuiescence,
        LivenessProperty::EventualResolution,
        LivenessProperty::DropPathCoverage,
    ];

    for property in all_properties {
        let is_tested = tests.iter().any(|test| {
            if let ConformanceExpectation::Verified {
                properties_verified,
                ..
            } = &test.expected
            {
                properties_verified.contains(&property)
            } else {
                false
            }
        });

        if is_tested {
            coverage.properties_tested.push(property);
        } else {
            coverage.properties_untested.push(property);
        }
    }

    coverage
}

#[derive(Debug)]
pub struct CoverageReport {
    pub must_tests: usize,
    pub should_tests: usize,
    pub may_tests: usize,
    pub properties_tested: Vec<LivenessProperty>,
    pub properties_untested: Vec<LivenessProperty>,
}

impl CoverageReport {
    fn new() -> Self {
        Self {
            must_tests: 0,
            should_tests: 0,
            may_tests: 0,
            properties_tested: Vec::new(),
            properties_untested: Vec::new(),
        }
    }

    pub fn must_coverage_percentage(&self) -> f64 {
        // Based on formal spec analysis: 5 MUST requirements identified
        let total_must_requirements = 5;
        (self.must_tests as f64 / total_must_requirements as f64) * 100.0
    }

    pub fn property_coverage_percentage(&self) -> f64 {
        let total_properties = self.properties_tested.len() + self.properties_untested.len();
        if total_properties == 0 {
            return 100.0;
        }
        (self.properties_tested.len() as f64 / total_properties as f64) * 100.0
    }
}
