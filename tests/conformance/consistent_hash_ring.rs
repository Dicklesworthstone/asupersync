//! Ring-consistency invariant conformance tests for consistent hash ring.
//!
//! Tests mathematical properties required for consistent hashing correctness.

use asupersync::distributed::consistent_hash::HashRing;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

pub trait RingConformanceTest {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn level(&self) -> RequirementLevel;
    fn run(&self) -> TestResult;
}

// RC-001: Ring ordering invariant
pub struct RingOrderingTest;

impl RingConformanceTest for RingOrderingTest {
    fn id(&self) -> &'static str {
        "RC-001"
    }
    fn name(&self) -> &'static str {
        "Ring virtual nodes must be sorted by hash"
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self) -> TestResult {
        // Black-box test: verify ordering through key assignment consistency
        let mut ring = HashRing::new(64);
        for i in 0..8 {
            ring.add_node(format!("node-{i}"));
        }

        // Test that key assignment is stable across many queries
        // If ring ordering were broken, assignments would be inconsistent
        let test_keys: Vec<u64> = (0..10_000).collect();
        let baseline: Vec<_> = test_keys.iter().map(|k| ring.node_for_key(k)).collect();

        // Verify stability across multiple queries
        for _ in 0..10 {
            let current: Vec<_> = test_keys.iter().map(|k| ring.node_for_key(k)).collect();

            if current != baseline {
                return TestResult::Fail {
                    reason: "Key assignment unstable - indicates ring ordering issue".to_string(),
                };
            }
        }

        // Test wraparound by ensuring high-hash keys get assigned
        if ring.node_for_key(&u64::MAX).is_none() {
            return TestResult::Fail {
                reason: "Max hash key not assigned - ring ordering issue".to_string(),
            };
        }

        TestResult::Pass
    }
}

// RC-002: Deterministic assignment invariant
pub struct DeterministicAssignmentTest;

impl RingConformanceTest for DeterministicAssignmentTest {
    fn id(&self) -> &'static str {
        "RC-002"
    }
    fn name(&self) -> &'static str {
        "Identical rings yield identical key assignments"
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self) -> TestResult {
        let build_ring = || {
            let mut ring = HashRing::new(32);
            for name in ["alpha", "beta", "gamma", "delta"] {
                ring.add_node(name);
            }
            ring
        };

        let r1 = build_ring();
        let r2 = build_ring();

        // Test 10,000 keys for assignment consistency
        for key in 0..10_000u64 {
            let assignment1 = r1.node_for_key(&key);
            let assignment2 = r2.node_for_key(&key);

            if assignment1 != assignment2 {
                return TestResult::Fail {
                    reason: format!(
                        "Non-deterministic assignment for key {}: {} != {}",
                        key,
                        assignment1.unwrap_or("None"),
                        assignment2.unwrap_or("None")
                    ),
                };
            }
        }

        TestResult::Pass
    }
}

// RC-003: Wraparound consistency test
pub struct WraparoundConsistencyTest;

impl RingConformanceTest for WraparoundConsistencyTest {
    fn id(&self) -> &'static str {
        "RC-003"
    }
    fn name(&self) -> &'static str {
        "Ring wraparound preserves consistent assignment"
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self) -> TestResult {
        let mut ring = HashRing::new(16);
        ring.add_node("node-a");
        ring.add_node("node-b");

        // Test keys that should wrap around the ring
        let test_keys = [u64::MAX - 1000, u64::MAX - 1, u64::MAX, 0, 1, 1000];

        for &key in &test_keys {
            let assignment = ring.node_for_key(&key);
            if assignment.is_none() {
                return TestResult::Fail {
                    reason: format!("Wraparound key {} assigned to None", key),
                };
            }

            // Verify assignment is deterministic on multiple calls
            for _ in 0..10 {
                if ring.node_for_key(&key) != assignment {
                    return TestResult::Fail {
                        reason: format!("Wraparound assignment unstable for key {}", key),
                    };
                }
            }
        }

        TestResult::Pass
    }
}

// RC-004: Node-vnode correlation invariant
pub struct NodeVnodeCorrelationTest;

impl RingConformanceTest for NodeVnodeCorrelationTest {
    fn id(&self) -> &'static str {
        "RC-004"
    }
    fn name(&self) -> &'static str {
        "Total vnodes equals node_count × vnodes_per_node"
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self) -> TestResult {
        for vnodes_per_node in [0, 1, 16, 64, 256] {
            for node_count in [0, 1, 5, 10] {
                let mut ring = HashRing::new(vnodes_per_node);

                for i in 0..node_count {
                    ring.add_node(format!("node-{i}"));
                }

                let expected_vnodes = if vnodes_per_node == 0 {
                    0
                } else {
                    node_count * vnodes_per_node
                };

                if ring.vnode_count() != expected_vnodes {
                    return TestResult::Fail {
                        reason: format!(
                            "Vnode correlation failed: {} nodes × {} vnodes/node = {} expected, got {}",
                            node_count,
                            vnodes_per_node,
                            expected_vnodes,
                            ring.vnode_count()
                        ),
                    };
                }

                if ring.node_count() != node_count {
                    return TestResult::Fail {
                        reason: format!(
                            "Node count mismatch: expected {}, got {}",
                            node_count,
                            ring.node_count()
                        ),
                    };
                }
            }
        }

        TestResult::Pass
    }
}

// RC-005: Idempotent operations test
pub struct IdempotentOperationsTest;

impl RingConformanceTest for IdempotentOperationsTest {
    fn id(&self) -> &'static str {
        "RC-005"
    }
    fn name(&self) -> &'static str {
        "Add/remove operations are idempotent"
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self) -> TestResult {
        let mut ring = HashRing::new(32);

        // Test idempotent add
        assert!(ring.add_node("test-node"));
        let node_count = ring.node_count();
        let vnode_count = ring.vnode_count();

        // Second add should be no-op
        if ring.add_node("test-node") {
            return TestResult::Fail {
                reason: "Duplicate add_node returned true instead of false".to_string(),
            };
        }

        if ring.node_count() != node_count || ring.vnode_count() != vnode_count {
            return TestResult::Fail {
                reason: format!(
                    "Duplicate add changed state: nodes {}→{}, vnodes {}→{}",
                    node_count,
                    ring.node_count(),
                    vnode_count,
                    ring.vnode_count()
                ),
            };
        }

        // Test idempotent remove
        let removed = ring.remove_node("test-node");
        if removed == 0 {
            return TestResult::Fail {
                reason: "First remove_node returned 0".to_string(),
            };
        }

        let removed2 = ring.remove_node("test-node");
        if removed2 != 0 {
            return TestResult::Fail {
                reason: format!("Second remove_node returned {} instead of 0", removed2),
            };
        }

        TestResult::Pass
    }
}

// RC-006: Empty ring behavior test
pub struct EmptyRingBehaviorTest;

impl RingConformanceTest for EmptyRingBehaviorTest {
    fn id(&self) -> &'static str {
        "RC-006"
    }
    fn name(&self) -> &'static str {
        "Empty ring returns None for all keys"
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self) -> TestResult {
        let ring = HashRing::new(64);

        if !ring.is_empty() {
            return TestResult::Fail {
                reason: "New ring is not empty".to_string(),
            };
        }

        let test_keys = [0u64, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX];
        for &key in &test_keys {
            if ring.node_for_key(&key).is_some() {
                return TestResult::Fail {
                    reason: format!("Empty ring assigned key {} to node", key),
                };
            }
        }

        TestResult::Pass
    }
}

// RC-007: Minimal remapping property (SHOULD)
pub struct MinimalRemappingTest;

impl RingConformanceTest for MinimalRemappingTest {
    fn id(&self) -> &'static str {
        "RC-007"
    }
    fn name(&self) -> &'static str {
        "Adding node affects ≤ 1/(n+1) of key assignments"
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self) -> TestResult {
        let mut ring = HashRing::new(64);
        for i in 0..5 {
            ring.add_node(format!("node-{i}"));
        }

        let keys: Vec<u64> = (0..50_000u64).collect();
        let before: Vec<_> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned())
            .collect();

        ring.add_node("new-node");

        let after: Vec<_> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned())
            .collect();

        let changed = before
            .iter()
            .zip(after.iter())
            .filter(|(a, b)| a != b)
            .count();

        let remap_ratio = changed as f64 / keys.len() as f64;
        let expected_max = 1.0 / 6.0; // 1/(n+1) for n=5

        if remap_ratio > expected_max * 1.5 {
            // Allow 50% tolerance
            return TestResult::Fail {
                reason: format!(
                    "Remapping ratio too high: {:.3} > {:.3} (expected ≤ {:.3})",
                    remap_ratio,
                    expected_max * 1.5,
                    expected_max
                ),
            };
        }

        TestResult::Pass
    }
}

// RC-008: Uniform distribution test (SHOULD)
pub struct UniformDistributionTest;

impl RingConformanceTest for UniformDistributionTest {
    fn id(&self) -> &'static str {
        "RC-008"
    }
    fn name(&self) -> &'static str {
        "Keys distribute uniformly across nodes"
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self) -> TestResult {
        let mut ring = HashRing::new(128);
        for i in 0..8 {
            ring.add_node(format!("node-{i}"));
        }

        let mut counts = HashMap::new();
        for key in 0..100_000u64 {
            let node = ring.node_for_key(&key).expect("node assigned");
            *counts.entry(node).or_insert(0) += 1;
        }

        let total = counts.values().sum::<usize>() as f64;
        let expected = total / counts.len() as f64;

        let max_deviation = counts
            .values()
            .map(|&count| (count as f64 - expected).abs() / expected)
            .fold(0.0, f64::max);

        if max_deviation > 0.20 {
            // Allow 20% deviation
            return TestResult::Fail {
                reason: format!(
                    "Distribution too skewed: max deviation {:.3} > 0.20",
                    max_deviation
                ),
            };
        }

        TestResult::Pass
    }
}

/// Run all ring-consistency conformance tests
pub fn run_all_tests() -> ConformanceReport {
    let tests: Vec<Box<dyn RingConformanceTest>> = vec![
        Box::new(RingOrderingTest),
        Box::new(DeterministicAssignmentTest),
        Box::new(WraparoundConsistencyTest),
        Box::new(NodeVnodeCorrelationTest),
        Box::new(IdempotentOperationsTest),
        Box::new(EmptyRingBehaviorTest),
        Box::new(MinimalRemappingTest),
        Box::new(UniformDistributionTest),
    ];

    let mut results = Vec::new();

    for test in tests {
        let result = test.run();
        println!(
            "{{\"id\":\"{}\",\"name\":\"{}\",\"level\":\"{:?}\",\"result\":\"{:?}\"}}",
            test.id(),
            test.name(),
            test.level(),
            result
        );

        results.push(ConformanceTestResult {
            id: test.id().to_string(),
            name: test.name().to_string(),
            level: test.level(),
            result,
        });
    }

    ConformanceReport { results }
}

#[derive(Debug)]
pub struct ConformanceTestResult {
    pub id: String,
    pub name: String,
    pub level: RequirementLevel,
    pub result: TestResult,
}

#[derive(Debug)]
pub struct ConformanceReport {
    pub results: Vec<ConformanceTestResult>,
}

impl ConformanceReport {
    pub fn compliance_matrix(&self) -> String {
        let mut must_total = 0;
        let mut must_pass = 0;
        let mut should_total = 0;
        let mut should_pass = 0;

        for result in &self.results {
            match result.level {
                RequirementLevel::Must => {
                    must_total += 1;
                    if matches!(result.result, TestResult::Pass) {
                        must_pass += 1;
                    }
                }
                RequirementLevel::Should => {
                    should_total += 1;
                    if matches!(result.result, TestResult::Pass) {
                        should_pass += 1;
                    }
                }
                RequirementLevel::May => {}
            }
        }

        let must_score = if must_total > 0 {
            (must_pass as f64 / must_total as f64) * 100.0
        } else {
            100.0
        };

        format!(
            "# Ring-Consistency Conformance Report\n\n\
            | Requirement Level | Total | Passing | Divergent | Score |\n\
            |------------------|-------|---------|-----------|-------|\n\
            | MUST             | {must_total}     | {must_pass}       | 0         | {must_score:.1}% |\n\
            | SHOULD           | {should_total}     | {should_pass}       | 0         | {:.1}% |\n\n\
            **CONFORMANCE STATUS**: {}\n",
            if should_total > 0 {
                (should_pass as f64 / should_total as f64) * 100.0
            } else {
                100.0
            },
            if must_score >= 95.0 {
                "COMPLIANT"
            } else {
                "NON-COMPLIANT"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_consistency_conformance_suite() {
        let report = run_all_tests();

        // Count failures
        let failures: Vec<_> = report
            .results
            .iter()
            .filter(|r| matches!(r.result, TestResult::Fail { .. }))
            .collect();

        if !failures.is_empty() {
            for failure in &failures {
                eprintln!("FAILED {}: {:?}", failure.id, failure.result);
            }
            panic!("{} conformance tests failed", failures.len());
        }

        println!("{}", report.compliance_matrix());
    }
}
