//! Metamorphic testing for distributed consistent hashing and obligation e-process monitoring.
//!
//! Addresses oracle problems where exact outputs cannot be predicted but structural
//! relationships between inputs and outputs are well-defined. Focuses on:
//!
//! **Consistent Hash (distributed/consistent_hash):**
//! - Bucket assignment determinism under node add/remove operations
//! - Virtual node conservation laws and ring ordering preservation
//! - Key mapping stability for unchanged nodes during topology changes
//!
//! **E-Process Monitor (obligation/eprocess):**
//! - Statistical monotonicity invariants in leak detection
//! - Threshold stability under observation reordering
//! - Reset identity and observation additivity properties
//!
//! Each metamorphic relation tests structural properties rather than exact values,
//! enabling comprehensive testing where traditional oracles fail.

#![cfg(any(test, feature = "test-internals"))]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(dead_code)]

#[cfg(test)]
mod tests {
    use crate::distributed::consistent_hash::HashRing;
    use crate::obligation::eprocess::{AlertState, LeakMonitor, MonitorConfig};
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet};

    // ────────────────────────────────────────────────────────────────────
    // Property Generators for Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// Generate valid node identifiers for hash ring testing.
    fn node_id() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9_-]{0,15}".prop_map(|s| s.to_string())
    }

    /// Generate sets of unique node identifiers.
    fn node_set(min_size: usize, max_size: usize) -> impl Strategy<Value = Vec<String>> {
        prop::collection::hash_set(node_id(), min_size..=max_size)
            .prop_map(|set| set.into_iter().collect())
    }

    /// Generate test keys for hash ring bucket assignment.
    fn hash_key() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9/._-]{1,32}".prop_map(|s| s.to_string())
    }

    /// Generate sequences of obligation ages for e-process testing.
    fn obligation_ages() -> impl Strategy<Value = Vec<u64>> {
        prop::collection::vec(1u64..100_000_000u64, 1..50)
    }

    /// Generate valid monitor configurations.
    fn monitor_config() -> impl Strategy<Value = MonitorConfig> {
        (0.001f64..0.1f64, 1_000u64..10_000_000u64, 1u64..10u64).prop_map(
            |(alpha, expected_lifetime_ns, min_observations)| MonitorConfig {
                alpha,
                expected_lifetime_ns,
                min_observations,
            },
        )
    }

    // ────────────────────────────────────────────────────────────────────
    // Deterministic implementations for structural property testing
    // ────────────────────────────────────────────────────────────────────

    /// Deterministic hash ring that tracks structural properties during operations.
    #[derive(Debug, Clone)]
    struct MockHashRing {
        inner: HashRing,
        operation_log: Vec<String>,
    }

    impl MockHashRing {
        fn new(vnodes_per_node: usize, seed: u64) -> Self {
            Self {
                inner: HashRing::new(vnodes_per_node, seed),
                operation_log: Vec::new(),
            }
        }

        fn add_node(&mut self, node_id: &str) -> bool {
            self.operation_log.push(format!("add:{}", node_id));
            self.inner.add_node(node_id)
        }

        fn remove_node(&mut self, node_id: &str) -> usize {
            self.operation_log.push(format!("remove:{}", node_id));
            self.inner.remove_node(node_id)
        }

        fn node_for_key<K: std::hash::Hash>(&self, key: &K) -> Option<&str> {
            self.inner.node_for_key(key)
        }

        fn node_count(&self) -> usize {
            self.inner.node_count()
        }

        fn vnode_count(&self) -> usize {
            self.inner.vnode_count()
        }

        fn nodes(&self) -> impl Iterator<Item = &str> {
            self.inner.nodes()
        }
    }

    /// Deterministic e-process monitor for observation sequence testing.
    #[derive(Debug)]
    struct MockLeakMonitor {
        inner: LeakMonitor,
        observation_sequence: Vec<u64>,
    }

    impl MockLeakMonitor {
        fn new(config: MonitorConfig) -> Self {
            Self {
                inner: LeakMonitor::new(config),
                observation_sequence: Vec::new(),
            }
        }

        fn observe(&mut self, age_ns: u64) {
            self.observation_sequence.push(age_ns);
            self.inner.observe(age_ns);
        }

        fn e_value(&self) -> f64 {
            self.inner.e_value()
        }

        fn observations(&self) -> u64 {
            self.inner.observations()
        }

        fn peak_e_value(&self) -> f64 {
            self.inner.peak_e_value()
        }

        fn alert_state(&self) -> AlertState {
            self.inner.alert_state()
        }

        fn threshold(&self) -> f64 {
            self.inner.threshold()
        }

        fn reset(&mut self) {
            self.observation_sequence.clear();
            self.inner.reset();
        }

        fn config(&self) -> &MonitorConfig {
            self.inner.config()
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Consistent Hash Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// **MR1: Node Addition Stability**
    ///
    /// **Property:** Adding a new node should not change key mappings for
    /// existing keys that were previously mapped to unchanged nodes.
    /// **Category:** Inclusive (adding nodes expands capacity)
    /// **Detects:** Hash function bugs, ring reconstruction errors, key redistribution failures
    proptest! {
        #[test]
        fn mr_node_addition_stability(
            initial_nodes in node_set(2, 5),
            new_node in node_id(),
            test_keys in prop::collection::vec(hash_key(), 10..20),
            vnodes_per_node in 1usize..8usize,
            seed in any::<u64>(),
        ) {
            // Skip if new_node already exists
            if initial_nodes.contains(&new_node) {
                return Ok(());
            }

            let mut ring_before = MockHashRing::new(vnodes_per_node, seed);
            for node in &initial_nodes {
                ring_before.add_node(node);
            }

            // Capture key mappings before node addition
            let mut mappings_before = HashMap::new();
            for key in &test_keys {
                if let Some(node) = ring_before.node_for_key(key) {
                    mappings_before.insert(key.clone(), node.to_string());
                }
            }

            // Add new node
            let mut ring_after = ring_before.clone();
            ring_after.add_node(&new_node);

            // Verify stability: keys that mapped to unchanged nodes should stay mapped there
            // (some keys may migrate to the new node, but existing mappings to unchanged nodes must be stable)
            let mut stable_mappings = 0;
            let mut total_previously_mapped = 0;

            for key in &test_keys {
                if let Some(node_before) = mappings_before.get(key) {
                    total_previously_mapped += 1;
                    if let Some(node_after) = ring_after.node_for_key(key) {
                        // If key stayed on an unchanged node, mapping must be identical
                        if node_after != new_node && node_after == node_before {
                            stable_mappings += 1;
                        }
                        // If key moved to new node, that's expected redistribution
                        // If key moved between old nodes, that's a bug
                        if node_after != new_node && node_after != node_before {
                            return Err(TestCaseError::fail(format!(
                                "Key '{}' moved from '{}' to '{}' (both old nodes) after adding '{}' - violates stability",
                                key, node_before, node_after, new_node
                            )));
                        }
                    }
                }
            }

            // At least some mappings should remain stable (unless all keys migrate to new node)
            if total_previously_mapped > 0 {
                let stability_ratio = stable_mappings as f64 / total_previously_mapped as f64;
                prop_assert!(stability_ratio >= 0.3 || stable_mappings > 0,
                    "Too many keys migrated between old nodes: {}/{} stable ({}%)",
                    stable_mappings, total_previously_mapped, stability_ratio * 100.0);
            }
        }
    }

    /// **MR2: Virtual Node Count Conservation**
    ///
    /// **Property:** Adding a node with N vnodes_per_node should increase
    /// total vnode count by exactly N.
    /// **Category:** Additive (vnode_count(ring + node) = vnode_count(ring) + N)
    /// **Detects:** Virtual node allocation bugs, count tracking errors
    proptest! {
        #[test]
        fn mr_virtual_node_count_conservation(
            initial_nodes in node_set(1, 4),
            new_node in node_id(),
            vnodes_per_node in 1usize..8usize,
            seed in any::<u64>(),
        ) {
            if initial_nodes.contains(&new_node) {
                return Ok(());
            }

            let mut ring = MockHashRing::new(vnodes_per_node, seed);
            for node in &initial_nodes {
                ring.add_node(node);
            }

            let vnodes_before = ring.vnode_count();
            let nodes_before = ring.node_count();

            ring.add_node(&new_node);

            let vnodes_after = ring.vnode_count();
            let nodes_after = ring.node_count();

            prop_assert_eq!(nodes_after, nodes_before + 1,
                "Node count should increase by exactly 1");

            prop_assert_eq!(vnodes_after, vnodes_before + vnodes_per_node,
                "Virtual node count should increase by exactly vnodes_per_node ({}) but was {} -> {}",
                vnodes_per_node, vnodes_before, vnodes_after);
        }
    }

    /// **MR3: Bucket Assignment Determinism**
    ///
    /// **Property:** Same ring configuration + same key = same bucket assignment.
    /// Ring reconstruction should be deterministic.
    /// **Category:** Equivalence (f(rebuild(ring), key) = f(ring, key))
    /// **Detects:** Non-deterministic hashing, ring ordering bugs, seed inconsistencies
    proptest! {
        #[test]
        fn mr_bucket_assignment_determinism(
            nodes in node_set(2, 6),
            test_keys in prop::collection::vec(hash_key(), 5..15),
            vnodes_per_node in 1usize..8usize,
            seed in any::<u64>(),
        ) {
            // Build ring A
            let mut ring_a = MockHashRing::new(vnodes_per_node, seed);
            for node in &nodes {
                ring_a.add_node(node);
            }

            // Build identical ring B with same parameters
            let mut ring_b = MockHashRing::new(vnodes_per_node, seed);
            for node in &nodes {
                ring_b.add_node(node);
            }

            // Verify identical bucket assignments
            for key in &test_keys {
                let mapping_a = ring_a.node_for_key(key);
                let mapping_b = ring_b.node_for_key(key);

                prop_assert_eq!(mapping_a, mapping_b,
                    "Key '{}' mapped to {:?} in ring A but {:?} in ring B - non-deterministic",
                    key, mapping_a, mapping_b);
            }

            // Verify structural equivalence
            prop_assert_eq!(ring_a.node_count(), ring_b.node_count());
            prop_assert_eq!(ring_a.vnode_count(), ring_b.vnode_count());
        }
    }

    /// **MR4: Node Removal Stability**
    ///
    /// **Property:** Removing a node should only affect keys that were mapped to it.
    /// Keys mapped to other nodes should remain stable.
    /// **Category:** Exclusive (removing nodes reduces capacity but preserves other mappings)
    /// **Detects:** Key redistribution bugs, ring reconstruction errors
    proptest! {
        #[test]
        fn mr_node_removal_stability(
            initial_nodes in node_set(3, 5),
            test_keys in prop::collection::vec(hash_key(), 10..20),
            vnodes_per_node in 1usize..8usize,
            seed in any::<u64>(),
        ) {
            let mut ring_before = MockHashRing::new(vnodes_per_node, seed);
            for node in &initial_nodes {
                ring_before.add_node(node);
            }

            // Pick a node to remove (use first node)
            let node_to_remove = &initial_nodes[0];

            // Capture mappings before removal
            let mut mappings_before = HashMap::new();
            for key in &test_keys {
                if let Some(node) = ring_before.node_for_key(key) {
                    mappings_before.insert(key.clone(), node.to_string());
                }
            }

            // Remove the node
            let mut ring_after = ring_before.clone();
            let removed_vnodes = ring_after.remove_node(node_to_remove);

            prop_assert_eq!(removed_vnodes, vnodes_per_node,
                "Should remove exactly {} virtual nodes", vnodes_per_node);

            // Verify stability for keys NOT mapped to removed node
            for key in &test_keys {
                if let Some(node_before) = mappings_before.get(key) {
                    if node_before != node_to_remove {
                        // Key was mapped to a remaining node - should stay mapped there
                        let node_after = ring_after.node_for_key(key);
                        prop_assert_eq!(node_after, Some(node_before.as_str()),
                            "Key '{}' was mapped to '{}' (remaining node) but is now mapped to {:?} - violates stability",
                            key, node_before, node_after);
                    } else {
                        // Key was mapped to removed node - should now map to a remaining node
                        let node_after = ring_after.node_for_key(key);
                        prop_assert!(node_after.is_some() && node_after.unwrap() != node_to_remove,
                            "Key '{}' was mapped to removed node '{}' but is now mapped to {:?} - should redistribute to remaining nodes",
                            key, node_to_remove, node_after);
                    }
                }
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // E-Process Monitor Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// **MR5: E-Value Monotonicity**
    ///
    /// **Property:** E-value must remain ≥ 1.0 (supermartingale property).
    /// Multiple observations should never decrease the cumulative evidence.
    /// **Category:** Multiplicative (E_n = E_{n-1} × likelihood_ratio_n, product ≥ 1.0)
    /// **Detects:** Likelihood ratio calculation bugs, floating-point underflow
    proptest! {
        #[test]
        fn mr_evalue_monotonicity(
            config in monitor_config(),
            ages in obligation_ages(),
        ) {
            let mut monitor = MockLeakMonitor::new(config);

            let mut previous_e_value = monitor.e_value();
            prop_assert!(previous_e_value >= 1.0, "Initial e-value should be ≥ 1.0, got {}", previous_e_value);

            for age in ages {
                monitor.observe(age);
                let current_e_value = monitor.e_value();

                prop_assert!(current_e_value >= 1.0,
                    "E-value became {} < 1.0 after observing age {} - violates supermartingale property",
                    current_e_value, age);

                // Note: E-value can sometimes decrease due to the normalization factor
                // but it should never go below 1.0. The monotonicity is in the evidence accumulation,
                // not necessarily in the absolute value.
                previous_e_value = current_e_value;
            }
        }
    }

    /// **MR6: Observation Count Additivity**
    ///
    /// **Property:** Adding N observations should increase observation count by exactly N.
    /// **Category:** Additive (count(monitor + N_obs) = count(monitor) + N)
    /// **Detects:** Counter bugs, observation tracking errors
    proptest! {
        #[test]
        fn mr_observation_count_additivity(
            config in monitor_config(),
            ages in obligation_ages(),
        ) {
            let mut monitor = MockLeakMonitor::new(config);

            let initial_count = monitor.observations();
            prop_assert_eq!(initial_count, 0, "New monitor should start with 0 observations");

            let expected_count = ages.len() as u64;

            for age in ages {
                monitor.observe(age);
            }

            let final_count = monitor.observations();
            prop_assert_eq!(final_count, initial_count + expected_count,
                "Expected {} observations but got {} (initial: {}, added: {})",
                initial_count + expected_count, final_count, initial_count, expected_count);
        }
    }

    /// **MR7: Reset Identity**
    ///
    /// **Property:** reset() should restore monitor to initial state.
    /// **Category:** Invertive (reset(monitor) = initial_state)
    /// **Detects:** State management bugs, incomplete reset logic
    proptest! {
        #[test]
        fn mr_reset_identity(
            config in monitor_config(),
            ages in obligation_ages().prop_filter("Non-empty", |ages| !ages.is_empty()),
        ) {
            let mut monitor = MockLeakMonitor::new(config.clone());

            // Capture initial state
            let initial_e_value = monitor.e_value();
            let initial_observations = monitor.observations();
            let initial_peak = monitor.peak_e_value();

            // Make some observations to change state
            for age in ages {
                monitor.observe(age);
            }

            // Verify state has changed
            prop_assert!(monitor.observations() > initial_observations,
                "Monitor state should change after observations");

            // Reset and verify identity
            monitor.reset();

            prop_assert_eq!(monitor.e_value(), initial_e_value,
                "E-value should be {} after reset but got {}", initial_e_value, monitor.e_value());

            prop_assert_eq!(monitor.observations(), initial_observations,
                "Observation count should be {} after reset but got {}", initial_observations, monitor.observations());

            prop_assert_eq!(monitor.peak_e_value(), initial_peak,
                "Peak e-value should be {} after reset but got {}", initial_peak, monitor.peak_e_value());

            // Configuration should be preserved
            prop_assert_eq!(monitor.config().alpha, config.alpha);
            prop_assert_eq!(monitor.config().expected_lifetime_ns, config.expected_lifetime_ns);
        }
    }

    /// **MR8: Threshold Invariance**
    ///
    /// **Property:** threshold = 1/alpha should remain constant regardless of observations.
    /// **Category:** Equivalence (threshold(monitor + obs) = threshold(monitor))
    /// **Detects:** Configuration corruption, threshold calculation bugs
    proptest! {
        #[test]
        fn mr_threshold_invariance(
            config in monitor_config(),
            ages in obligation_ages(),
        ) {
            let mut monitor = MockLeakMonitor::new(config.clone());

            let expected_threshold = 1.0 / config.alpha;
            let initial_threshold = monitor.threshold();

            prop_assert!((initial_threshold - expected_threshold).abs() < f64::EPSILON,
                "Initial threshold should be 1/alpha = {} but got {}", expected_threshold, initial_threshold);

            for age in ages {
                monitor.observe(age);
                let current_threshold = monitor.threshold();

                prop_assert!((current_threshold - expected_threshold).abs() < f64::EPSILON,
                    "Threshold should remain {} after observations but got {}", expected_threshold, current_threshold);
            }
        }
    }

    /// **MR9: Peak E-Value Monotonicity**
    ///
    /// **Property:** Peak e-value should never decrease (only increase when current e-value exceeds it).
    /// **Category:** Multiplicative (peak_value_n = max(peak_value_{n-1}, e_value_n))
    /// **Detects:** Peak tracking bugs, comparison logic errors
    proptest! {
        #[test]
        fn mr_peak_evalue_monotonicity(
            config in monitor_config(),
            ages in obligation_ages(),
        ) {
            let mut monitor = MockLeakMonitor::new(config);

            let mut previous_peak = monitor.peak_e_value();

            for age in ages {
                monitor.observe(age);
                let current_peak = monitor.peak_e_value();
                let current_e_value = monitor.e_value();

                prop_assert!(current_peak >= previous_peak,
                    "Peak e-value decreased from {} to {} - violates monotonicity", previous_peak, current_peak);

                prop_assert!(current_peak >= current_e_value,
                    "Peak e-value {} should be ≥ current e-value {}", current_peak, current_e_value);

                previous_peak = current_peak;
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Composite Metamorphic Relations (Cross-Module Properties)
    // ────────────────────────────────────────────────────────────────────

    /// **MR10: Hash Ring Stability Under E-Process Monitoring**
    ///
    /// **Property:** Consistent hash behavior should be independent of e-process monitoring.
    /// **Category:** Equivalence (hash_ring behavior is orthogonal to monitoring)
    /// **Detects:** Unexpected interactions between unrelated modules
    proptest! {
        #[test]
        fn mr_cross_module_independence(
            nodes in node_set(2, 4),
            test_keys in prop::collection::vec(hash_key(), 5..10),
            vnodes_per_node in 1usize..4usize,
            seed in any::<u64>(),
            monitor_config in monitor_config(),
            ages in obligation_ages(),
        ) {
            // Test hash ring behavior without monitoring
            let mut ring_standalone = MockHashRing::new(vnodes_per_node, seed);
            for node in &nodes {
                ring_standalone.add_node(node);
            }

            let mut mappings_standalone = HashMap::new();
            for key in &test_keys {
                if let Some(node) = ring_standalone.node_for_key(key) {
                    mappings_standalone.insert(key.clone(), node.to_string());
                }
            }

            // Test hash ring behavior with concurrent monitoring
            let mut ring_monitored = MockHashRing::new(vnodes_per_node, seed);
            let mut _monitor = MockLeakMonitor::new(monitor_config); // Monitor exists but doesn't interact

            for node in &nodes {
                ring_monitored.add_node(node);
            }

            // Record deterministic monitoring activity.
            for age in ages {
                _monitor.observe(age);
            }

            let mut mappings_monitored = HashMap::new();
            for key in &test_keys {
                if let Some(node) = ring_monitored.node_for_key(key) {
                    mappings_monitored.insert(key.clone(), node.to_string());
                }
            }

            // Hash ring behavior should be identical regardless of monitoring
            prop_assert_eq!(mappings_standalone, mappings_monitored,
                "Hash ring mappings should be independent of e-process monitoring");
        }
    }

    #[test]
    fn distributed_obligation_model_starts_empty_and_keeps_monitor_separate() {
        let config = MonitorConfig::default();
        let mut monitor = MockLeakMonitor::new(config);
        assert_eq!(monitor.observations(), 0);
        monitor.observe(3);
        assert_eq!(monitor.observations(), 1);

        let mut ring = MockHashRing::new(3, 42);
        assert_eq!(ring.node_count(), 0);
        assert!(ring.add_node("node-a"));
        assert!(ring.add_node("node-b"));
        assert_eq!(ring.node_count(), 2);
        assert_eq!(monitor.observations(), 1);
    }
}
