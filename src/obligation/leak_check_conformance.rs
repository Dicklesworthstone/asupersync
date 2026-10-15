//! Conformance test harness for static leak checker.
//!
//! This module verifies that the LeakChecker implementation satisfies
//! the requirements for obligation safety analysis:
//!
//! 1. **Leak Detection**: All unmatched obligations are detected
//! 2. **Control Flow**: Branch merging preserves leak information
//! 3. **Soundness**: No false negatives (missed real leaks)
//! 4. **Precision**: Minimal false positives on valid code
//! 5. **Completeness**: All obligation kinds are properly tracked

use super::{Body, BodyBuilder, DiagnosticCode, Instruction, LeakChecker, ObligationVar};
use crate::record::ObligationKind;

/// Conformance test result for a specific leak analysis requirement.
#[derive(Debug, Clone)]
pub struct LeakCheckConformanceResult {
    /// Stable requirement identifier covered by this result.
    pub requirement_id: &'static str,
    /// Human-readable requirement summary.
    pub description: &'static str,
    /// Criticality level for the requirement.
    pub level: RequirementLevel,
    /// Execution status for the requirement check.
    pub status: TestStatus,
    /// Evidence or failure details captured by the check.
    pub evidence: String,
    /// Confidence score for the result, from 0.0 to 1.0.
    pub confidence: f64,
}

/// Requirement criticality level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    /// MUST satisfy - violation invalidates the analysis.
    Must,
    /// SHOULD satisfy - violation is a quality issue.
    Should,
    /// MAY satisfy - nice to have.
    May,
}

/// Test execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    /// Requirement check passed.
    Pass,
    /// Requirement check failed.
    Fail,
    /// Requirement check was skipped.
    Skip,
    /// Requirement check is an expected failure for a known limitation.
    XFail,
}

/// Complete conformance matrix for leak checker implementation.
pub struct LeakCheckConformanceHarness {
    tests: Vec<LeakCheckConformanceTest>,
    results: Vec<LeakCheckConformanceResult>,
}

/// Individual conformance test.
pub struct LeakCheckConformanceTest {
    /// Stable requirement identifier covered by this test.
    pub id: &'static str,
    /// Human-readable requirement summary.
    pub description: &'static str,
    /// Criticality level for the requirement.
    pub level: RequirementLevel,
    /// Test function that evaluates the requirement.
    pub test_fn: fn() -> LeakCheckConformanceResult,
}

impl LeakCheckConformanceHarness {
    /// Creates a new conformance harness with all leak analysis requirements.
    pub fn new() -> Self {
        let tests = vec![
            LeakCheckConformanceTest {
                id: "LEAK-001",
                description: "Unmatched reserve without commit/abort is detected",
                level: RequirementLevel::Must,
                test_fn: test_unmatched_reserve_detection,
            },
            LeakCheckConformanceTest {
                id: "LEAK-002",
                description: "Matched reserve+commit pair is clean",
                level: RequirementLevel::Must,
                test_fn: test_matched_reserve_commit_clean,
            },
            LeakCheckConformanceTest {
                id: "LEAK-003",
                description: "Matched reserve+abort pair is clean",
                level: RequirementLevel::Must,
                test_fn: test_matched_reserve_abort_clean,
            },
            LeakCheckConformanceTest {
                id: "LEAK-004",
                description: "Branch merge preserves leak information",
                level: RequirementLevel::Must,
                test_fn: test_branch_merge_preserves_leaks,
            },
            LeakCheckConformanceTest {
                id: "LEAK-005",
                description: "All obligation kinds are trackable",
                level: RequirementLevel::Must,
                test_fn: test_all_obligation_kinds_trackable,
            },
            LeakCheckConformanceTest {
                id: "LEAK-006",
                description: "Double-commit is detected as invalid",
                level: RequirementLevel::Must,
                test_fn: test_double_commit_detection,
            },
            LeakCheckConformanceTest {
                id: "LEAK-007",
                description: "Use-before-reserve is detected",
                level: RequirementLevel::Must,
                test_fn: test_use_before_reserve_detection,
            },
            LeakCheckConformanceTest {
                id: "LEAK-008",
                description: "Sequential independent obligations are handled correctly",
                level: RequirementLevel::Should,
                test_fn: test_nested_obligation_scopes,
            },
            LeakCheckConformanceTest {
                id: "LEAK-009",
                description: "Overwriting a live obligation is detected",
                level: RequirementLevel::Should,
                test_fn: test_loop_with_leak_detection,
            },
            LeakCheckConformanceTest {
                id: "LEAK-010",
                description: "Valid conditional obligations are clean",
                level: RequirementLevel::Should,
                test_fn: test_conditional_obligations_valid,
            },
        ];

        Self {
            tests,
            results: Vec::new(),
        }
    }

    /// Runs all conformance tests and generates a compliance report.
    pub fn run_all(&mut self) {
        self.results.clear();

        for test in &self.tests {
            let result = (test.test_fn)();
            self.results.push(LeakCheckConformanceResult {
                requirement_id: test.id,
                description: test.description,
                level: test.level,
                status: result.status,
                evidence: result.evidence,
                confidence: result.confidence,
            });
        }
    }

    /// Generates compliance matrix showing requirement coverage.
    pub fn compliance_matrix(&self) -> String {
        let mut output = String::new();
        output.push_str("# Static Leak Checker Conformance Matrix\n\n");
        output.push_str("| Req ID | Level | Status | Description | Evidence |\n");
        output.push_str("|--------|-------|--------|-------------|----------|\n");

        let mut must_total = 0;
        let mut must_pass = 0;
        let mut should_total = 0;
        let mut should_pass = 0;

        for result in &self.results {
            let status_str = match result.status {
                TestStatus::Pass => "✅ PASS",
                TestStatus::Fail => "❌ FAIL",
                TestStatus::Skip => "⏸️ SKIP",
                TestStatus::XFail => "⚠️ XFAIL",
            };

            let level_str = match result.level {
                RequirementLevel::Must => {
                    must_total += 1;
                    if result.status == TestStatus::Pass {
                        must_pass += 1;
                    }
                    "MUST"
                }
                RequirementLevel::Should => {
                    should_total += 1;
                    if result.status == TestStatus::Pass {
                        should_pass += 1;
                    }
                    "SHOULD"
                }
                RequirementLevel::May => "MAY",
            };

            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                result.requirement_id,
                level_str,
                status_str,
                result.description,
                result.evidence.chars().take(50).collect::<String>()
            ));
        }

        output.push_str("\n## Compliance Summary\n\n");

        let must_score = if must_total > 0 {
            (must_pass as f64 / must_total as f64) * 100.0
        } else {
            100.0
        };
        let should_score = if should_total > 0 {
            (should_pass as f64 / should_total as f64) * 100.0
        } else {
            100.0
        };

        output.push_str(&format!(
            "**MUST Requirements**: {}/{} ({:.1}%)\n",
            must_pass, must_total, must_score
        ));
        output.push_str(&format!(
            "**SHOULD Requirements**: {}/{} ({:.1}%)\n",
            should_pass, should_total, should_score
        ));

        if must_score >= 95.0 {
            output.push_str(
                "\n✅ **CONFORMANT**: Implementation satisfies leak analysis requirements\n",
            );
        } else {
            output.push_str(
                "\n❌ **NON-CONFORMANT**: Critical leak analysis requirements not satisfied\n",
            );
        }

        output
    }

    /// Returns failed requirements for debugging.
    pub fn failed_requirements(&self) -> Vec<&LeakCheckConformanceResult> {
        self.results
            .iter()
            .filter(|r| r.status == TestStatus::Fail)
            .collect()
    }

    /// Returns all conformance results collected by the last run.
    pub fn results(&self) -> &[LeakCheckConformanceResult] {
        &self.results
    }
}

// ============================================================================
// Leak Analysis Conformance Tests
// ============================================================================

/// LEAK-001: Verify unmatched reserve without commit/abort is detected.
fn test_unmatched_reserve_detection() -> LeakCheckConformanceResult {
    let body = Body::new(
        "unmatched_reserve",
        vec![
            Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::SendPermit,
            },
            // Missing commit or abort - this should be detected as a leak.
        ],
    );

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let has_leak = !result.is_clean();
    let leak_count = result.leaks().len();
    let correct_diagnostic = result
        .leaks()
        .iter()
        .any(|diag| diag.code == DiagnosticCode::LeakExitDefinite);

    if has_leak && leak_count == 1 && correct_diagnostic {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-001",
            description: "Unmatched reserve detection",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: format!("Detected {} leak with correct diagnostic code", leak_count),
            confidence: 1.0,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-001",
            description: "Unmatched reserve detection",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: has_leak={}, count={}, correct_diag={}",
                has_leak, leak_count, correct_diagnostic
            ),
            confidence: 1.0,
        }
    }
}

/// LEAK-002: Verify matched reserve+commit pair is clean.
fn test_matched_reserve_commit_clean() -> LeakCheckConformanceResult {
    let body = Body::new(
        "matched_reserve_commit",
        vec![
            Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::SendPermit,
            },
            Instruction::Commit {
                var: ObligationVar(0),
            },
        ],
    );

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let is_clean = result.is_clean();
    let leak_count = result.leaks().len();

    if is_clean && leak_count == 0 {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-002",
            description: "Matched reserve+commit is clean",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: "Clean analysis with 0 leaks".to_string(),
            confidence: 1.0,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-002",
            description: "Matched reserve+commit is clean",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: is_clean={}, leak_count={}",
                is_clean, leak_count
            ),
            confidence: 1.0,
        }
    }
}

/// LEAK-003: Verify matched reserve+abort pair is clean.
fn test_matched_reserve_abort_clean() -> LeakCheckConformanceResult {
    let body = Body::new(
        "matched_reserve_abort",
        vec![
            Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::Ack,
            },
            Instruction::Abort {
                var: ObligationVar(0),
            },
        ],
    );

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let is_clean = result.is_clean();
    let leak_count = result.leaks().len();

    if is_clean && leak_count == 0 {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-003",
            description: "Matched reserve+abort is clean",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: "Clean analysis with 0 leaks".to_string(),
            confidence: 1.0,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-003",
            description: "Matched reserve+abort is clean",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: is_clean={}, leak_count={}",
                is_clean, leak_count
            ),
            confidence: 1.0,
        }
    }
}

/// LEAK-004: Verify branch merge preserves leak information.
fn test_branch_merge_preserves_leaks() -> LeakCheckConformanceResult {
    let mut builder = BodyBuilder::new("branch_merge_test");

    // Create a conditional where one branch leaks
    builder.branch(|branch| {
        // Branch 1: clean path.
        branch.arm(|arm| {
            arm.reserve(ObligationVar(0), ObligationKind::SendPermit);
            arm.commit(ObligationVar(0));
        });

        // Branch 2: leaky path.
        branch.arm(|arm| {
            arm.reserve(ObligationVar(1), ObligationKind::Ack);
            // Missing commit/abort - should leak.
        });
    });

    let body = builder.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let has_leak = !result.is_clean();
    let leak_count = result.leaks().len();

    if has_leak && leak_count >= 1 {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-004",
            description: "Branch merge preserves leaks",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: format!("Detected {} leaks from merged branches", leak_count),
            confidence: 0.95,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-004",
            description: "Branch merge preserves leaks",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: Expected leaks from branch merge, got {} leaks",
                leak_count
            ),
            confidence: 0.95,
        }
    }
}

/// LEAK-005: Verify all obligation kinds are trackable.
fn test_all_obligation_kinds_trackable() -> LeakCheckConformanceResult {
    let obligation_kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
        ObligationKind::SemaphorePermit,
    ];

    let mut all_trackable = true;
    let mut evidence_parts = Vec::new();

    for (i, &kind) in obligation_kinds.iter().enumerate() {
        let body = Body::new(
            format!("test_{kind:?}"),
            vec![
                Instruction::Reserve {
                    var: ObligationVar(i as u32),
                    kind,
                },
                // Intentional leak to test detection.
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);

        let detected_leak = !result.is_clean();
        if !detected_leak {
            all_trackable = false;
            evidence_parts.push(format!("{:?}: NOT_TRACKED", kind));
        } else {
            evidence_parts.push(format!("{:?}: tracked", kind));
        }
    }

    if all_trackable {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-005",
            description: "All obligation kinds trackable",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: evidence_parts.join(", "),
            confidence: 1.0,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-005",
            description: "All obligation kinds trackable",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!("VIOLATION: {}", evidence_parts.join(", ")),
            confidence: 1.0,
        }
    }
}

/// LEAK-006: Verify double-commit is detected as invalid.
fn test_double_commit_detection() -> LeakCheckConformanceResult {
    let body = Body::new(
        "double_commit",
        vec![
            Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::SendPermit,
            },
            Instruction::Commit {
                var: ObligationVar(0),
            },
            Instruction::Commit {
                var: ObligationVar(0),
            }, // Double commit.
        ],
    );

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let has_error = !result.is_clean();
    let has_double_commit_error = result
        .double_resolves()
        .iter()
        .any(|diag| diag.code == DiagnosticCode::DoubleResolve);

    if has_error && has_double_commit_error {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-006",
            description: "Double-commit detection",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: "Detected double-commit violation".to_string(),
            confidence: 1.0,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-006",
            description: "Double-commit detection",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: has_error={}, has_double_commit_error={}",
                has_error, has_double_commit_error
            ),
            confidence: 1.0,
        }
    }
}

/// LEAK-007: Verify use-before-reserve is detected.
fn test_use_before_reserve_detection() -> LeakCheckConformanceResult {
    let body = Body::new(
        "use_before_reserve",
        vec![
            Instruction::Commit {
                var: ObligationVar(0),
            }, // Use before reserve.
            Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::SendPermit,
            },
        ],
    );

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let has_error = !result.is_clean();
    let has_use_before_reserve = result
        .diagnostics
        .iter()
        .any(|diag| diag.code == DiagnosticCode::ResolveUnheld);

    if has_error && has_use_before_reserve {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-007",
            description: "Use-before-reserve detection",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: "Detected use-before-reserve violation".to_string(),
            confidence: 1.0,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-007",
            description: "Use-before-reserve detection",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: has_error={}, has_use_before_reserve={}",
                has_error, has_use_before_reserve
            ),
            confidence: 1.0,
        }
    }
}

/// LEAK-008: Test nested obligation scopes are handled correctly.
fn test_nested_obligation_scopes() -> LeakCheckConformanceResult {
    let mut builder = BodyBuilder::new("sequential_independent_obligations");

    let outer = builder.reserve(ObligationKind::Lease);
    let inner = builder.reserve(ObligationKind::SendPermit);

    builder.commit(inner);
    builder.commit(outer);

    let body = builder.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let is_clean = result.is_clean();

    if is_clean {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-008",
            description: "Sequential independent obligations",
            level: RequirementLevel::Should,
            status: TestStatus::Pass,
            evidence:
                "Clean analysis with two independent obligations resolved out of reservation order"
                    .to_string(),
            confidence: 0.95,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-008",
            description: "Sequential independent obligations",
            level: RequirementLevel::Should,
            status: TestStatus::Fail,
            evidence: "VIOLATION: independently resolved obligations were flagged".to_string(),
            confidence: 0.95,
        }
    }
}

/// LEAK-009: Test loop with leak is detected.
fn test_loop_with_leak_detection() -> LeakCheckConformanceResult {
    let body = Body::new(
        "overwrite_live_obligation",
        vec![
            Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::SendPermit,
            },
            Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::Ack,
            },
        ],
    );

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let has_overwrite = result
        .diagnostics
        .iter()
        .any(|diag| diag.code == DiagnosticCode::OverwriteActive);

    if has_overwrite {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-009",
            description: "Live obligation overwrite detection",
            level: RequirementLevel::Should,
            status: TestStatus::Pass,
            evidence: "Detected overwrite of a still-live obligation variable".to_string(),
            confidence: 0.95,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-009",
            description: "Live obligation overwrite detection",
            level: RequirementLevel::Should,
            status: TestStatus::Fail,
            evidence: "VIOLATION: live overwrite was not diagnosed".to_string(),
            confidence: 0.95,
        }
    }
}

/// LEAK-010: Test valid conditional obligations are clean.
fn test_conditional_obligations_valid() -> LeakCheckConformanceResult {
    let mut builder = BodyBuilder::new("conditional_valid");

    builder.branch(|branch| {
        // Both branches properly handle obligations.
        branch.arm(|arm| {
            arm.reserve(ObligationVar(0), ObligationKind::SendPermit);
            arm.commit(ObligationVar(0));
        });

        branch.arm(|arm| {
            arm.reserve(ObligationVar(1), ObligationKind::Ack);
            arm.abort(ObligationVar(1));
        });
    });

    let body = builder.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);

    let is_clean = result.is_clean();

    if is_clean {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-010",
            description: "Valid conditional obligations",
            level: RequirementLevel::Should,
            status: TestStatus::Pass,
            evidence: "Clean analysis with valid conditional paths".to_string(),
            confidence: 0.95,
        }
    } else {
        LeakCheckConformanceResult {
            requirement_id: "LEAK-010",
            description: "Valid conditional obligations",
            level: RequirementLevel::Should,
            status: TestStatus::Fail,
            evidence: "VIOLATION: valid conditional code flagged as leaky".to_string(),
            confidence: 0.95,
        }
    }
}

impl Default for LeakCheckConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn conformance_harness_runs_all_tests() {
        let mut harness = LeakCheckConformanceHarness::new();
        harness.run_all();

        // Should have results for all test cases
        assert_eq!(harness.results.len(), 10);

        // Generate matrix (should not panic)
        let matrix = harness.compliance_matrix();
        assert!(matrix.contains("Static Leak Checker Conformance Matrix"));

        // Should categorize by requirement level
        let must_count = harness
            .results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must)
            .count();
        assert!(must_count >= 7); // We have several MUST requirements
    }

    #[test]
    fn individual_leak_test_runs() {
        // Verify each test function can run independently
        let result = test_unmatched_reserve_detection();
        assert!(result.requirement_id == "LEAK-001");

        let result = test_matched_reserve_commit_clean();
        assert!(result.requirement_id == "LEAK-002");

        // Should all have confidence > 0
        assert!(result.confidence > 0.0);
    }
}
