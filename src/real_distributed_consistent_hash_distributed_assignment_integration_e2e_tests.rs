//! BR-E2E-89: Real Distributed Consistent Hash ↔ Distributed Assignment Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the distributed
//! consistent hashing and distributed assignment subsystems. The tests verify that
//! hash-ring rebalance assigns keys with O(K/N) movement and that the assignment
//! table reaches eventual consistency.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `distributed::consistent_hash` - Consistent hashing with hash ring management and rebalancing
//! - `distributed::assignment` - Distributed assignment table with eventual consistency guarantees
//!
//! # Key Scenarios
//!
//! - Hash ring rebalancing with minimal key movement (O(K/N) complexity)
//! - Assignment table eventual consistency under concurrent updates
//! - Key migration coordination between ring topology and assignment state
//! - Consistency convergence timing and correctness verification
//! - Load distribution fairness across nodes

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    distributed::{
        consistent_hash::{
            ConsistentHashRing, HashRingConfig, HashRingStats, NodeId, VirtualNode,
            RingPosition, RebalanceEvent, KeyMovement,
        },
        assignment::{
            AssignmentTable, AssignmentConfig, AssignmentEntry, AssignmentUpdate,
            ConsistencyLevel, EventualConsistency, AssignmentStats,
        },
        DistributedKey, DistributedValue, NodeWeight, TopologyChange,
    },
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex},
    time::{Duration, Sleep, Instant},
    types::{Budget, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};
use std::{
    collections::{HashMap, HashSet, BTreeMap},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

/// Tracks hash ring rebalancing efficiency and assignment consistency events
#[derive(Debug, Clone)]
struct ConsistencyEfficiencyTracker {
    /// Total keys managed by the system
    total_keys: Arc<AtomicU64>,
    /// Keys moved during rebalancing operations
    keys_moved: Arc<AtomicU64>,
    /// Number of nodes in the system
    active_nodes: Arc<AtomicUsize>,
    /// Rebalance operations completed
    rebalance_operations: Arc<AtomicU64>,
    /// Assignment table update events
    assignment_updates: Arc<AtomicU64>,
    /// Consistency convergence events
    consistency_convergences: Arc<AtomicU64>,
    /// Load distribution violations detected
    load_imbalances: Arc<AtomicU64>,
    /// Timeline of rebalancing efficiency metrics
    efficiency_timeline: Arc<Mutex<Vec<(Instant, f64, usize, usize)>>>,
}

impl ConsistencyEfficiencyTracker {
    fn new() -> Self {
        Self {
            total_keys: Arc::new(AtomicU64::new(0)),
            keys_moved: Arc::new(AtomicU64::new(0)),
            active_nodes: Arc::new(AtomicUsize::new(0)),
            rebalance_operations: Arc::new(AtomicU64::new(0)),
            assignment_updates: Arc::new(AtomicU64::new(0)),
            consistency_convergences: Arc::new(AtomicU64::new(0)),
            load_imbalances: Arc::new(AtomicU64::new(0)),
            efficiency_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn set_total_keys(&self, count: u64) {
        self.total_keys.store(count, Ordering::Relaxed);
    }

    fn set_active_nodes(&self, count: usize) {
        self.active_nodes.store(count, Ordering::Relaxed);
    }

    fn record_keys_moved(&self, count: u64) -> u64 {
        self.keys_moved.fetch_add(count, Ordering::Relaxed)
    }

    fn record_rebalance_operation(&self) -> u64 {
        self.rebalance_operations.fetch_add(1, Ordering::Relaxed)
    }

    fn record_assignment_update(&self) -> u64 {
        self.assignment_updates.fetch_add(1, Ordering::Relaxed)
    }

    fn record_consistency_convergence(&self) -> u64 {
        self.consistency_convergences.fetch_add(1, Ordering::Relaxed)
    }

    fn record_load_imbalance(&self) -> u64 {
        self.load_imbalances.fetch_add(1, Ordering::Relaxed)
    }

    async fn record_efficiency_metric(
        &self,
        cx: &Cx,
        movement_ratio: f64,
        moved_keys: usize,
        total_keys: usize,
    ) {
        let mut timeline = self.efficiency_timeline.lock(cx).await;
        timeline.push((Instant::now(), movement_ratio, moved_keys, total_keys));
    }

    fn verify_movement_efficiency(&self) -> bool {
        let total_keys = self.total_keys.load(Ordering::Relaxed);
        let keys_moved = self.keys_moved.load(Ordering::Relaxed);
        let active_nodes = self.active_nodes.load(Ordering::Relaxed);

        if total_keys == 0 || active_nodes == 0 {
            return false;
        }

        // Verify O(K/N) movement efficiency
        let expected_max_movement = total_keys / active_nodes as u64;
        let actual_movement = keys_moved;

        // Allow some tolerance for practical implementations
        let efficiency_tolerance = 2.0;
        actual_movement <= (expected_max_movement as f64 * efficiency_tolerance) as u64
    }

    fn verify_eventual_consistency(&self) -> bool {
        let updates = self.assignment_updates.load(Ordering::Relaxed);
        let convergences = self.consistency_convergences.load(Ordering::Relaxed);

        // Should achieve convergence after updates
        updates > 0 && convergences > 0
    }

    fn verify_load_balance(&self) -> bool {
        let imbalances = self.load_imbalances.load(Ordering::Relaxed);
        let rebalances = self.rebalance_operations.load(Ordering::Relaxed);

        // Should have minimal load imbalances relative to rebalances
        rebalances > 0 && imbalances <= rebalances
    }
}

/// Mock distributed key generator for testing hash ring assignment
struct DistributedKeyGenerator {
    /// Key prefix for generated keys
    prefix: String,
    /// Current key counter
    counter: Arc<AtomicU64>,
    /// Random number generator for key variations
    rng: Arc<Mutex<DetRng>>,
}

impl DistributedKeyGenerator {
    fn new(prefix: String, seed: RngSeed) -> Self {
        Self {
            prefix,
            counter: Arc::new(AtomicU64::new(0)),
            rng: Arc::new(Mutex::new(DetRng::from_seed(seed))),
        }
    }

    async fn generate_key(&self, cx: &Cx) -> DistributedKey {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut rng = self.rng.lock(cx).await;
        let suffix = rng.gen_range(1000..=9999);

        DistributedKey::from_string(format!("{}_{:06}_{}", self.prefix, id, suffix))
    }

    async fn generate_keys(&self, cx: &Cx, count: usize) -> Vec<DistributedKey> {
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            keys.push(self.generate_key(cx).await);
        }
        keys
    }

    fn get_generated_count(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

/// Simulates a distributed node with consistent hash integration
struct MockDistributedNode {
    /// Node identifier
    node_id: NodeId,
    /// Node weight for load balancing
    weight: NodeWeight,
    /// Assigned keys managed by this node
    assigned_keys: Arc<Mutex<HashSet<DistributedKey>>>,
    /// Local assignment table replica
    assignment_table: AssignmentTable,
    /// Efficiency tracking
    efficiency_tracker: ConsistencyEfficiencyTracker,
}

impl MockDistributedNode {
    async fn new(
        cx: &Cx,
        node_id: NodeId,
        weight: NodeWeight,
        assignment_config: AssignmentConfig,
        efficiency_tracker: ConsistencyEfficiencyTracker,
    ) -> Outcome<Self> {
        Ok(Self {
            node_id,
            weight,
            assigned_keys: Arc::new(Mutex::new(HashSet::new())),
            assignment_table: AssignmentTable::new(assignment_config).await?,
            efficiency_tracker,
        })
    }

    async fn assign_key(&self, cx: &Cx, key: DistributedKey) -> Outcome<()> {
        let mut assigned_keys = self.assigned_keys.lock(cx).await;
        assigned_keys.insert(key.clone());

        // Update local assignment table
        let assignment_entry = AssignmentEntry {
            key: key.clone(),
            assigned_node: self.node_id.clone(),
            version: 1,
            timestamp: Instant::now(),
        };

        self.assignment_table.update(cx, assignment_entry).await?;
        self.efficiency_tracker.record_assignment_update();

        Ok(())
    }

    async fn remove_key(&self, cx: &Cx, key: &DistributedKey) -> Outcome<()> {
        let mut assigned_keys = self.assigned_keys.lock(cx).await;
        assigned_keys.remove(key);

        self.assignment_table.remove(cx, key).await?;
        self.efficiency_tracker.record_assignment_update();

        Ok(())
    }

    async fn get_assigned_keys(&self, cx: &Cx) -> HashSet<DistributedKey> {
        let assigned_keys = self.assigned_keys.lock(cx).await;
        assigned_keys.clone()
    }

    async fn synchronize_assignment_table(&self, cx: &Cx, other_table: &AssignmentTable) -> Outcome<()> {
        let updates = other_table.get_all_assignments(cx).await?;

        for assignment in updates {
            self.assignment_table.update(cx, assignment).await?;
        }

        // Check for consistency convergence
        if self.assignment_table.is_consistent(cx).await? {
            self.efficiency_tracker.record_consistency_convergence();
        }

        Ok(())
    }

    fn get_load(&self) -> usize {
        // Simplified load metric
        self.assigned_keys.try_lock().map_or(0, |keys| keys.len())
    }

    fn get_node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn get_weight(&self) -> NodeWeight {
        self.weight
    }
}

/// Comprehensive integration test for hash ring and assignment table coordination
#[tokio::test]
async fn test_consistent_hash_assignment_rebalance_efficiency() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("consistent_hash_assignment_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let efficiency_tracker = ConsistencyEfficiencyTracker::new();

                    // Configure hash ring with multiple virtual nodes per physical node
                    let ring_config = HashRingConfig {
                        virtual_nodes_per_node: 150, // Good balance for distribution
                        hash_function: "sha256".to_string(),
                        replication_factor: 3,
                        enable_weighted_distribution: true,
                    };

                    let mut hash_ring = ConsistentHashRing::new(ring_config);

                    // Configure assignment table
                    let assignment_config = AssignmentConfig {
                        consistency_level: ConsistencyLevel::EventualConsistency,
                        replication_factor: 3,
                        convergence_timeout: Duration::from_secs(30),
                        max_pending_updates: 10000,
                    };

                    // Create initial set of nodes
                    let initial_node_ids = vec![
                        NodeId::from_string("node_001".to_string()),
                        NodeId::from_string("node_002".to_string()),
                        NodeId::from_string("node_003".to_string()),
                        NodeId::from_string("node_004".to_string()),
                    ];

                    let mut nodes = Vec::new();
                    for (i, node_id) in initial_node_ids.iter().enumerate() {
                        // Vary node weights for realistic testing
                        let weight = NodeWeight::from_value(100 + (i * 50) as u32);

                        let node = MockDistributedNode::new(
                            cx,
                            node_id.clone(),
                            weight,
                            assignment_config.clone(),
                            efficiency_tracker.clone(),
                        ).await?;

                        hash_ring.add_node(node_id.clone(), weight)?;
                        nodes.push(node);
                    }

                    efficiency_tracker.set_active_nodes(initial_node_ids.len());

                    // Phase 1: Generate and distribute initial keys
                    let key_generator = DistributedKeyGenerator::new(
                        "test_key".to_string(),
                        RngSeed::new(12345),
                    );

                    let initial_key_count = 10000;
                    let initial_keys = key_generator.generate_keys(cx, initial_key_count).await;
                    efficiency_tracker.set_total_keys(initial_keys.len() as u64);

                    // Distribute keys according to hash ring
                    let mut key_to_node: HashMap<DistributedKey, NodeId> = HashMap::new();

                    for key in &initial_keys {
                        let assigned_node_id = hash_ring.get_node(key)?;
                        key_to_node.insert(key.clone(), assigned_node_id.clone());

                        // Find the corresponding node and assign the key
                        if let Some(node) = nodes.iter().find(|n| n.get_node_id() == assigned_node_id) {
                            node.assign_key(cx, key.clone()).await?;
                        }
                    }

                    // Verify initial distribution balance
                    let initial_loads: Vec<usize> = nodes.iter().map(|n| n.get_load()).collect();
                    let max_load = initial_loads.iter().max().unwrap_or(&0);
                    let min_load = initial_loads.iter().min().unwrap_or(&0);
                    let load_variance = max_load - min_load;

                    println!(
                        "Initial distribution: loads = {:?}, variance = {}",
                        initial_loads, load_variance
                    );

                    // Reasonable load balance for initial distribution
                    assert!(
                        load_variance <= initial_key_count / initial_node_ids.len() + 500,
                        "Initial load should be reasonably balanced"
                    );

                    // Phase 2: Add new nodes and trigger rebalancing
                    let new_node_ids = vec![
                        NodeId::from_string("node_005".to_string()),
                        NodeId::from_string("node_006".to_string()),
                    ];

                    let initial_assignment_snapshot = key_to_node.clone();

                    for (i, new_node_id) in new_node_ids.iter().enumerate() {
                        let weight = NodeWeight::from_value(120 + (i * 30) as u32);

                        let new_node = MockDistributedNode::new(
                            cx,
                            new_node_id.clone(),
                            weight,
                            assignment_config.clone(),
                            efficiency_tracker.clone(),
                        ).await?;

                        // Add to hash ring - this triggers rebalancing
                        hash_ring.add_node(new_node_id.clone(), weight)?;
                        efficiency_tracker.record_rebalance_operation();
                        nodes.push(new_node);
                    }

                    efficiency_tracker.set_active_nodes(nodes.len());

                    // Phase 3: Simulate key migration based on new hash ring
                    let mut keys_moved = 0;
                    let mut new_assignments: HashMap<DistributedKey, NodeId> = HashMap::new();

                    for key in &initial_keys {
                        let new_assigned_node_id = hash_ring.get_node(key)?;
                        new_assignments.insert(key.clone(), new_assigned_node_id.clone());

                        let old_assigned_node_id = &initial_assignment_snapshot[key];

                        if new_assigned_node_id != *old_assigned_node_id {
                            keys_moved += 1;

                            // Remove from old node
                            if let Some(old_node) = nodes.iter().find(|n| n.get_node_id() == *old_assigned_node_id) {
                                old_node.remove_key(cx, key).await?;
                            }

                            // Add to new node
                            if let Some(new_node) = nodes.iter().find(|n| n.get_node_id() == new_assigned_node_id) {
                                new_node.assign_key(cx, key.clone()).await?;
                            }
                        }
                    }

                    efficiency_tracker.record_keys_moved(keys_moved);

                    // Calculate movement efficiency
                    let movement_ratio = keys_moved as f64 / initial_keys.len() as f64;
                    let theoretical_optimal = initial_keys.len() / nodes.len();

                    efficiency_tracker
                        .record_efficiency_metric(cx, movement_ratio, keys_moved, initial_keys.len())
                        .await;

                    println!(
                        "Rebalancing: moved {} keys out of {} ({}%), theoretical optimal ≈ {}",
                        keys_moved,
                        initial_keys.len(),
                        movement_ratio * 100.0,
                        theoretical_optimal
                    );

                    // Phase 4: Synchronize assignment tables across all nodes
                    for i in 0..nodes.len() {
                        for j in 0..nodes.len() {
                            if i != j {
                                nodes[i].synchronize_assignment_table(cx, &nodes[j].assignment_table).await?;
                            }
                        }
                    }

                    // Allow time for eventual consistency
                    Sleep::new(Duration::from_millis(100)).await;

                    // Phase 5: Verify final load balance
                    let final_loads: Vec<usize> = nodes.iter().map(|n| n.get_load()).collect();
                    let final_max_load = final_loads.iter().max().unwrap_or(&0);
                    let final_min_load = final_loads.iter().min().unwrap_or(&0);
                    let final_load_variance = final_max_load - final_min_load;

                    println!(
                        "Final distribution: loads = {:?}, variance = {}",
                        final_loads, final_load_variance
                    );

                    // Check for excessive load imbalances
                    let expected_avg_load = initial_keys.len() / nodes.len();
                    for (i, &load) in final_loads.iter().enumerate() {
                        let deviation = (load as i32 - expected_avg_load as i32).abs() as usize;
                        if deviation > expected_avg_load / 2 {
                            efficiency_tracker.record_load_imbalance();
                            println!("Node {} has load imbalance: {} vs expected {}", i, load, expected_avg_load);
                        }
                    }

                    // Phase 6: Test removal scenario
                    let node_to_remove = nodes[1].get_node_id(); // Remove second node
                    hash_ring.remove_node(&node_to_remove)?;
                    efficiency_tracker.record_rebalance_operation();

                    // Simulate key redistribution after node removal
                    let mut removal_keys_moved = 0;
                    let removed_node_keys = nodes[1].get_assigned_keys(cx).await;

                    for key in &removed_node_keys {
                        let new_assigned_node_id = hash_ring.get_node(key)?;

                        // Remove from the node being removed
                        nodes[1].remove_key(cx, key).await?;

                        // Add to new node
                        if let Some(new_node) = nodes.iter().find(|n| n.get_node_id() == new_assigned_node_id) {
                            new_node.assign_key(cx, key.clone()).await?;
                            removal_keys_moved += 1;
                        }
                    }

                    efficiency_tracker.record_keys_moved(removal_keys_moved);

                    println!(
                        "Node removal: redistributed {} keys from removed node",
                        removal_keys_moved
                    );

                    // Phase 7: Final verification
                    assert!(
                        efficiency_tracker.verify_movement_efficiency(),
                        "Hash ring rebalancing should achieve O(K/N) movement efficiency"
                    );

                    assert!(
                        efficiency_tracker.verify_eventual_consistency(),
                        "Assignment table should reach eventual consistency"
                    );

                    assert!(
                        efficiency_tracker.verify_load_balance(),
                        "Load should be reasonably balanced across nodes"
                    );

                    // Verify movement efficiency constraints
                    let total_keys = efficiency_tracker.total_keys.load(Ordering::Relaxed);
                    let total_moved = efficiency_tracker.keys_moved.load(Ordering::Relaxed);
                    let active_nodes = efficiency_tracker.active_nodes.load(Ordering::Relaxed);

                    let movement_efficiency = total_moved as f64 / total_keys as f64;
                    let theoretical_bound = 1.0 / active_nodes as f64;

                    println!(
                        "Movement efficiency: {:.3}% (theoretical bound ≈ {:.3}%)",
                        movement_efficiency * 100.0,
                        theoretical_bound * 100.0
                    );

                    // Allow some tolerance for practical implementation
                    assert!(
                        movement_efficiency <= theoretical_bound * 3.0,
                        "Movement should be within reasonable bounds of O(K/N)"
                    );

                    println!(
                        "Integration test completed: {} rebalances, {} moved keys, {} consistency convergences",
                        efficiency_tracker.rebalance_operations.load(Ordering::Relaxed),
                        efficiency_tracker.keys_moved.load(Ordering::Relaxed),
                        efficiency_tracker.consistency_convergences.load(Ordering::Relaxed)
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test assignment table consistency under concurrent hash ring changes
#[tokio::test]
async fn test_assignment_consistency_concurrent_ring_changes() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("concurrent_ring_changes").await?;

            scope
                .run(async move |cx| {
                    let efficiency_tracker = ConsistencyEfficiencyTracker::new();

                    let ring_config = HashRingConfig {
                        virtual_nodes_per_node: 100,
                        hash_function: "sha256".to_string(),
                        replication_factor: 2,
                        enable_weighted_distribution: false, // Uniform for simplicity
                    };

                    let mut hash_ring = ConsistentHashRing::new(ring_config);

                    let assignment_config = AssignmentConfig {
                        consistency_level: ConsistencyLevel::EventualConsistency,
                        replication_factor: 2,
                        convergence_timeout: Duration::from_secs(20),
                        max_pending_updates: 5000,
                    };

                    // Start with 3 nodes
                    let initial_nodes = vec![
                        NodeId::from_string("concurrent_node_1".to_string()),
                        NodeId::from_string("concurrent_node_2".to_string()),
                        NodeId::from_string("concurrent_node_3".to_string()),
                    ];

                    let mut nodes = Vec::new();
                    for node_id in &initial_nodes {
                        let weight = NodeWeight::from_value(100);
                        hash_ring.add_node(node_id.clone(), weight)?;

                        let node = MockDistributedNode::new(
                            cx,
                            node_id.clone(),
                            weight,
                            assignment_config.clone(),
                            efficiency_tracker.clone(),
                        ).await?;

                        nodes.push(node);
                    }

                    efficiency_tracker.set_active_nodes(initial_nodes.len());

                    // Generate keys and initial assignment
                    let key_generator = DistributedKeyGenerator::new(
                        "concurrent_test".to_string(),
                        RngSeed::new(54321),
                    );

                    let key_count = 1000;
                    let keys = key_generator.generate_keys(cx, key_count).await;
                    efficiency_tracker.set_total_keys(keys.len() as u64);

                    // Initial key distribution
                    for key in &keys {
                        let assigned_node_id = hash_ring.get_node(key)?;
                        if let Some(node) = nodes.iter().find(|n| n.get_node_id() == assigned_node_id) {
                            node.assign_key(cx, key.clone()).await?;
                        }
                    }

                    // Launch concurrent operations
                    let mut operation_handles = Vec::new();

                    // Concurrent node additions/removals
                    for i in 0..3 {
                        let mut local_hash_ring = hash_ring.clone();
                        let tracker = efficiency_tracker.clone();

                        let handle = cx.spawn(&format!("ring_change_{}", i), async move |cx| {
                            for j in 0..2 {
                                Sleep::new(Duration::from_millis(20 + (i * 10))).await;

                                // Add a temporary node
                                let temp_node_id = NodeId::from_string(format!("temp_node_{}_{}", i, j));
                                let weight = NodeWeight::from_value(100);

                                match local_hash_ring.add_node(temp_node_id.clone(), weight) {
                                    Ok(()) => {
                                        tracker.record_rebalance_operation();

                                        // Keep it briefly then remove
                                        Sleep::new(Duration::from_millis(10)).await;

                                        let _ = local_hash_ring.remove_node(&temp_node_id);
                                        tracker.record_rebalance_operation();
                                    }
                                    Err(_) => {
                                        // Concurrent modification - continue
                                    }
                                }
                            }
                            Ok(())
                        })?;

                        operation_handles.push(handle);
                    }

                    // Concurrent assignment table updates
                    for i in 0..2 {
                        let nodes_ref = &nodes;
                        let keys_ref = &keys;
                        let tracker = efficiency_tracker.clone();

                        let handle = cx.spawn(&format!("assignment_update_{}", i), async move |cx| {
                            for j in 0..5 {
                                Sleep::new(Duration::from_millis(15 + (j * 5))).await;

                                // Update some random assignments
                                let start_idx = (j * 50) % keys_ref.len();
                                let end_idx = std::cmp::min(start_idx + 20, keys_ref.len());

                                for k in start_idx..end_idx {
                                    let key = &keys_ref[k];
                                    let target_node = &nodes_ref[k % nodes_ref.len()];

                                    match target_node.assign_key(cx, key.clone()).await {
                                        Ok(()) => tracker.record_assignment_update(),
                                        Err(_) => {
                                            // Concurrent update conflict - continue
                                        }
                                    }
                                }
                            }
                            Ok(())
                        })?;

                        operation_handles.push(handle);
                    }

                    // Concurrent synchronization operations
                    let sync_handle = cx.spawn("sync_operations", async move |cx| {
                        for _ in 0..10 {
                            Sleep::new(Duration::from_millis(30)).await;

                            // Cross-synchronize assignment tables
                            for i in 0..nodes.len() {
                                for j in 0..nodes.len() {
                                    if i != j {
                                        let _ = nodes[i].synchronize_assignment_table(cx, &nodes[j].assignment_table).await;
                                    }
                                }
                            }
                        }
                        Ok(())
                    })?;

                    operation_handles.push(sync_handle);

                    // Wait for all concurrent operations to complete
                    for handle in operation_handles {
                        handle.join(cx).await??;
                    }

                    // Final synchronization and consistency check
                    Sleep::new(Duration::from_millis(50)).await;

                    for i in 0..nodes.len() {
                        for j in 0..nodes.len() {
                            if i != j {
                                nodes[i].synchronize_assignment_table(cx, &nodes[j].assignment_table).await?;
                            }
                        }
                    }

                    // Verify eventual consistency was achieved
                    assert!(
                        efficiency_tracker.verify_eventual_consistency(),
                        "Should achieve eventual consistency despite concurrent modifications"
                    );

                    let rebalance_operations = efficiency_tracker.rebalance_operations.load(Ordering::Relaxed);
                    let assignment_updates = efficiency_tracker.assignment_updates.load(Ordering::Relaxed);
                    let consistency_convergences = efficiency_tracker.consistency_convergences.load(Ordering::Relaxed);

                    assert!(
                        rebalance_operations > 0,
                        "Should have performed ring rebalancing operations"
                    );

                    assert!(
                        assignment_updates > 0,
                        "Should have performed assignment table updates"
                    );

                    println!(
                        "Concurrent test completed: {} rebalances, {} updates, {} convergences",
                        rebalance_operations, assignment_updates, consistency_convergences
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test load balancing fairness across different node weights
#[tokio::test]
async fn test_weighted_hash_ring_assignment_fairness() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("weighted_assignment_fairness").await?;

            scope
                .run(async move |cx| {
                    let efficiency_tracker = ConsistencyEfficiencyTracker::new();

                    let ring_config = HashRingConfig {
                        virtual_nodes_per_node: 200, // Higher for better weight distribution
                        hash_function: "sha256".to_string(),
                        replication_factor: 1,
                        enable_weighted_distribution: true,
                    };

                    let mut hash_ring = ConsistentHashRing::new(ring_config);

                    let assignment_config = AssignmentConfig {
                        consistency_level: ConsistencyLevel::EventualConsistency,
                        replication_factor: 1,
                        convergence_timeout: Duration::from_secs(15),
                        max_pending_updates: 2000,
                    };

                    // Create nodes with different weights
                    let weighted_nodes = vec![
                        (NodeId::from_string("light_node".to_string()), NodeWeight::from_value(50)),   // Light capacity
                        (NodeId::from_string("medium_node".to_string()), NodeWeight::from_value(100)), // Medium capacity
                        (NodeId::from_string("heavy_node".to_string()), NodeWeight::from_value(200)),  // High capacity
                        (NodeId::from_string("super_node".to_string()), NodeWeight::from_value(300)),  // Very high capacity
                    ];

                    let mut nodes = Vec::new();
                    let mut node_weights = HashMap::new();

                    for (node_id, weight) in &weighted_nodes {
                        hash_ring.add_node(node_id.clone(), *weight)?;
                        node_weights.insert(node_id.clone(), *weight);

                        let node = MockDistributedNode::new(
                            cx,
                            node_id.clone(),
                            *weight,
                            assignment_config.clone(),
                            efficiency_tracker.clone(),
                        ).await?;

                        nodes.push(node);
                    }

                    efficiency_tracker.set_active_nodes(weighted_nodes.len());

                    // Generate a substantial number of keys for statistical validity
                    let key_generator = DistributedKeyGenerator::new(
                        "weighted_test".to_string(),
                        RngSeed::new(98765),
                    );

                    let key_count = 5000; // Large enough for weight distribution testing
                    let keys = key_generator.generate_keys(cx, key_count).await;
                    efficiency_tracker.set_total_keys(keys.len() as u64);

                    // Distribute keys according to weighted hash ring
                    let mut node_load_counts: HashMap<NodeId, usize> = HashMap::new();

                    for key in &keys {
                        let assigned_node_id = hash_ring.get_node(key)?;

                        *node_load_counts.entry(assigned_node_id.clone()).or_insert(0) += 1;

                        if let Some(node) = nodes.iter().find(|n| n.get_node_id() == assigned_node_id) {
                            node.assign_key(cx, key.clone()).await?;
                        }
                    }

                    // Calculate total weight for proportional analysis
                    let total_weight: u32 = weighted_nodes.iter().map(|(_, w)| w.value()).sum();

                    // Verify load distribution matches weight proportions
                    for (node_id, weight) in &weighted_nodes {
                        let expected_proportion = weight.value() as f64 / total_weight as f64;
                        let expected_load = (expected_proportion * key_count as f64) as usize;

                        let actual_load = node_load_counts.get(node_id).unwrap_or(&0);
                        let load_deviation = (*actual_load as i32 - expected_load as i32).abs() as f64;
                        let relative_deviation = load_deviation / expected_load as f64;

                        println!(
                            "Node {} (weight {}): expected load ≈ {}, actual load = {}, deviation = {:.1}%",
                            node_id.value(),
                            weight.value(),
                            expected_load,
                            actual_load,
                            relative_deviation * 100.0
                        );

                        // Allow reasonable tolerance for statistical variation
                        assert!(
                            relative_deviation <= 0.25, // 25% tolerance
                            "Load distribution should respect node weights within tolerance: node {}, deviation {:.1}%",
                            node_id.value(),
                            relative_deviation * 100.0
                        );

                        // Check for severe imbalances
                        if relative_deviation > 0.15 {
                            efficiency_tracker.record_load_imbalance();
                        }
                    }

                    // Verify load balancing
                    assert!(
                        efficiency_tracker.verify_load_balance(),
                        "Weighted distribution should maintain reasonable load balance"
                    );

                    println!(
                        "Weighted distribution test completed with {} total keys across {} nodes",
                        key_count,
                        weighted_nodes.len()
                    );

                    Ok(())
                })
                .await
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistency_efficiency_tracker_creation() {
        let tracker = ConsistencyEfficiencyTracker::new();

        // Verify initial state
        assert_eq!(tracker.total_keys.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.keys_moved.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.active_nodes.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.rebalance_operations.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.assignment_updates.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.consistency_convergences.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.load_imbalances.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_consistency_efficiency_tracking() {
        let tracker = ConsistencyEfficiencyTracker::new();

        // Set up test scenario
        tracker.set_total_keys(1000);
        tracker.set_active_nodes(5);
        tracker.record_keys_moved(200);
        tracker.record_rebalance_operation();
        tracker.record_assignment_update();
        tracker.record_consistency_convergence();

        // Verify tracking
        assert_eq!(tracker.total_keys.load(Ordering::Relaxed), 1000);
        assert_eq!(tracker.keys_moved.load(Ordering::Relaxed), 200);
        assert_eq!(tracker.active_nodes.load(Ordering::Relaxed), 5);
        assert_eq!(tracker.rebalance_operations.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.assignment_updates.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.consistency_convergences.load(Ordering::Relaxed), 1);

        // Verify verification methods
        assert!(tracker.verify_movement_efficiency());
        assert!(tracker.verify_eventual_consistency());
        assert!(tracker.verify_load_balance());
    }

    #[test]
    fn test_movement_efficiency_verification_edge_cases() {
        let tracker = ConsistencyEfficiencyTracker::new();

        // No keys or nodes
        assert!(!tracker.verify_movement_efficiency());

        // Keys but no nodes
        tracker.set_total_keys(100);
        assert!(!tracker.verify_movement_efficiency());

        // Perfect efficiency (no movement needed)
        let tracker2 = ConsistencyEfficiencyTracker::new();
        tracker2.set_total_keys(1000);
        tracker2.set_active_nodes(5);
        tracker2.record_keys_moved(0);
        assert!(tracker2.verify_movement_efficiency());

        // Optimal efficiency (K/N movement)
        let tracker3 = ConsistencyEfficiencyTracker::new();
        tracker3.set_total_keys(1000);
        tracker3.set_active_nodes(5);
        tracker3.record_keys_moved(200); // 1000/5 = 200
        assert!(tracker3.verify_movement_efficiency());

        // Within tolerance (2x optimal)
        let tracker4 = ConsistencyEfficiencyTracker::new();
        tracker4.set_total_keys(1000);
        tracker4.set_active_nodes(5);
        tracker4.record_keys_moved(400); // 2 * (1000/5)
        assert!(tracker4.verify_movement_efficiency());

        // Beyond tolerance (3x optimal)
        let tracker5 = ConsistencyEfficiencyTracker::new();
        tracker5.set_total_keys(1000);
        tracker5.set_active_nodes(5);
        tracker5.record_keys_moved(600); // 3 * (1000/5)
        assert!(!tracker5.verify_movement_efficiency());
    }

    #[test]
    fn test_eventual_consistency_verification() {
        let tracker = ConsistencyEfficiencyTracker::new();

        // No activity
        assert!(!tracker.verify_eventual_consistency());

        // Updates but no convergence
        tracker.record_assignment_update();
        assert!(!tracker.verify_eventual_consistency());

        // Convergence without updates (unusual but acceptable)
        let tracker2 = ConsistencyEfficiencyTracker::new();
        tracker2.record_consistency_convergence();
        assert!(!tracker2.verify_eventual_consistency());

        // Proper eventual consistency
        let tracker3 = ConsistencyEfficiencyTracker::new();
        tracker3.record_assignment_update();
        tracker3.record_consistency_convergence();
        assert!(tracker3.verify_eventual_consistency());
    }

    #[test]
    fn test_load_balance_verification() {
        let tracker = ConsistencyEfficiencyTracker::new();

        // No operations
        assert!(!tracker.verify_load_balance());

        // Rebalances with acceptable imbalances
        tracker.record_rebalance_operation();
        tracker.record_rebalance_operation();
        tracker.record_load_imbalance();
        assert!(tracker.verify_load_balance()); // 1 imbalance <= 2 rebalances

        // Too many imbalances
        let tracker2 = ConsistencyEfficiencyTracker::new();
        tracker2.record_rebalance_operation();
        tracker2.record_load_imbalance();
        tracker2.record_load_imbalance();
        assert!(!tracker2.verify_load_balance()); // 2 imbalances > 1 rebalance
    }

    #[test]
    fn test_distributed_key_generator_creation() {
        let generator = DistributedKeyGenerator::new(
            "test_prefix".to_string(),
            RngSeed::new(12345),
        );

        assert_eq!(generator.prefix, "test_prefix");
        assert_eq!(generator.get_generated_count(), 0);
    }
}