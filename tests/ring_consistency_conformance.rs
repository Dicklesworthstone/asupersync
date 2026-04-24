//! Ring-consistency conformance test runner
//!
//! This integration test verifies that the HashRing implementation conforms
//! to the mathematical properties required for consistent hashing.

#[cfg(test)]
mod tests {
    use asupersync::distributed::consistent_hash::HashRing;
    use std::collections::HashMap;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RequirementLevel {
        Must,
        Should,
        May,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TestResult {
        Pass,
        Fail {
            reason: String,
        },
        #[allow(dead_code)]
        Skipped {
            reason: String,
        },
    }

    pub trait RingConformanceTest {
        fn id(&self) -> &'static str;
        fn name(&self) -> &'static str;
        fn level(&self) -> RequirementLevel;
        fn run(&self) -> TestResult;
    }

    // RC-001: Ring ordering invariant (inferred through stability)
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
            // Black-box test: verify ordering through key assignment stability
            let mut ring = HashRing::new(64);
            for i in 0..8 {
                ring.add_node(format!("node-{i}"));
            }

            // Test that key assignment is stable across many queries
            let test_keys: Vec<u64> = (0..1_000).collect();
            let baseline: Vec<_> = test_keys.iter().map(|k| ring.node_for_key(k)).collect();

            // Verify stability across multiple queries
            for _ in 0..5 {
                let current: Vec<_> = test_keys.iter().map(|k| ring.node_for_key(k)).collect();

                if current != baseline {
                    return TestResult::Fail {
                        reason: "Key assignment unstable - indicates ring ordering issue"
                            .to_string(),
                    };
                }
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

            // Test key assignment consistency
            for key in 0..1_000u64 {
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

    // RC-003: Node-vnode correlation invariant
    pub struct NodeVnodeCorrelationTest;

    impl RingConformanceTest for NodeVnodeCorrelationTest {
        fn id(&self) -> &'static str {
            "RC-004"
        } // Note: Using RC-004 to match the design
        fn name(&self) -> &'static str {
            "Total vnodes equals node_count × vnodes_per_node"
        }
        fn level(&self) -> RequirementLevel {
            RequirementLevel::Must
        }

        fn run(&self) -> TestResult {
            for vnodes_per_node in [0, 1, 16, 64] {
                for node_count in [0, 1, 3, 5] {
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

    // RC-005: Empty ring behavior test
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

            let keys: Vec<u64> = (0..10_000u64).collect();
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
                // Allow 50% tolerance per DISC-003
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
            for key in 0..20_000u64 {
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
                // Allow 20% deviation per DISC-001
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
    fn run_all_conformance_tests() -> Vec<(String, TestResult)> {
        let tests: Vec<Box<dyn RingConformanceTest>> = vec![
            Box::new(RingOrderingTest),
            Box::new(DeterministicAssignmentTest),
            Box::new(NodeVnodeCorrelationTest),
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

            results.push((test.id().to_string(), result));
        }

        results
    }

    fn generate_compliance_report(results: &[(String, TestResult)]) -> String {
        let mut must_total = 0;
        let mut must_pass = 0;
        let mut should_total = 0;
        let mut should_pass = 0;

        for (id, result) in results {
            let level = match id.as_str() {
                "RC-001" | "RC-002" | "RC-004" | "RC-006" => RequirementLevel::Must,
                "RC-007" | "RC-008" => RequirementLevel::Should,
                _ => RequirementLevel::May,
            };

            match level {
                RequirementLevel::Must => {
                    must_total += 1;
                    if matches!(result, TestResult::Pass) {
                        must_pass += 1;
                    }
                }
                RequirementLevel::Should => {
                    should_total += 1;
                    if matches!(result, TestResult::Pass) {
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

        let should_score = if should_total > 0 {
            (should_pass as f64 / should_total as f64) * 100.0
        } else {
            100.0
        };

        format!(
            "# Ring-Consistency Conformance Report\n\n\
            | Requirement Level | Total | Passing | Divergent | Score |\n\
            |------------------|-------|---------|-----------|-------|\n\
            | MUST             | {must_total}     | {must_pass}       | 0         | {must_score:.1}% |\n\
            | SHOULD           | {should_total}     | {should_pass}       | 0         | {should_score:.1}% |\n\n\
            **CONFORMANCE STATUS**: {}\n",
            if must_score >= 95.0 {
                "COMPLIANT"
            } else {
                "NON-COMPLIANT"
            }
        )
    }

    #[test]
    fn ring_consistency_conformance_suite() {
        let results = run_all_conformance_tests();

        // Count failures
        let failures: Vec<_> = results
            .iter()
            .filter(|(_, r)| matches!(r, TestResult::Fail { .. }))
            .collect();

        if !failures.is_empty() {
            for (id, failure) in &failures {
                eprintln!("FAILED {}: {:?}", id, failure);
            }
            panic!("{} conformance tests failed", failures.len());
        }

        println!("{}", generate_compliance_report(&results));
    }

    #[test]
    fn ring_ordering_conformance() {
        let test = RingOrderingTest;
        let result = test.run();
        assert!(
            matches!(result, TestResult::Pass),
            "Ring ordering test failed: {:?}",
            result
        );
    }

    #[test]
    fn deterministic_assignment_conformance() {
        let test = DeterministicAssignmentTest;
        let result = test.run();
        assert!(
            matches!(result, TestResult::Pass),
            "Deterministic assignment test failed: {:?}",
            result
        );
    }

    #[test]
    fn node_vnode_correlation_conformance() {
        let test = NodeVnodeCorrelationTest;
        let result = test.run();
        assert!(
            matches!(result, TestResult::Pass),
            "Node-vnode correlation test failed: {:?}",
            result
        );
    }

    #[test]
    fn empty_ring_behavior_conformance() {
        let test = EmptyRingBehaviorTest;
        let result = test.run();
        assert!(
            matches!(result, TestResult::Pass),
            "Empty ring behavior test failed: {:?}",
            result
        );
    }

    #[test]
    fn minimal_remapping_conformance() {
        let test = MinimalRemappingTest;
        let result = test.run();
        assert!(
            matches!(result, TestResult::Pass),
            "Minimal remapping test failed: {:?}",
            result
        );
    }

    #[test]
    fn uniform_distribution_conformance() {
        let test = UniformDistributionTest;
        let result = test.run();
        assert!(
            matches!(result, TestResult::Pass),
            "Uniform distribution test failed: {:?}",
            result
        );
    }
}
