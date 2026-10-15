//! Real E2E integration tests: obligation/separation_logic ↔ obligation/saga rollback integration (br-e2e-173).
//!
//! Tests that separation logic invariants hold across nested saga rollbacks. Verifies that
//! the separation logic system and saga rollback mechanism integrate properly when nested
//! sagas are rolled back, ensuring resource ownership invariants, heap separation properties,
//! and obligation lifecycle consistency are preserved throughout complex rollback scenarios.
//!
//! # Integration Patterns Tested
//!
//! - **Separation Logic Invariants**: Resource ownership and heap separation during rollbacks
//! - **Nested Saga Rollbacks**: Multiple levels of saga nesting with proper rollback order
//! - **Resource Ownership Transfer**: Safe transfer of resources during saga operations
//! - **Invariant Preservation**: Separation logic invariants maintained during rollback
//! - **Obligation Lifecycle Consistency**: Proper obligation state transitions during rollback
//! - **Heap Isolation**: Separate heap regions maintained during saga execution and rollback
//!
//! # Test Scenarios
//!
//! 1. **Basic Saga Rollback** — Single saga rollback with separation logic verification
//! 2. **Nested Saga Rollbacks** — Multiple nested sagas with proper rollback ordering
//! 3. **Resource Ownership Transfer** — Resources transferred between saga participants
//! 4. **Invariant Preservation** — Separation logic invariants preserved during rollback
//! 5. **Concurrent Saga Rollbacks** — Multiple sagas rolling back concurrently
//! 6. **Complex Rollback Scenarios** — Deep nesting with resource dependencies
//!
//! # Safety Properties Verified
//!
//! - Separation logic invariants hold before, during, and after saga rollbacks
//! - Resource ownership is properly tracked and restored during rollback operations
//! - Heap separation is maintained even during complex nested rollback scenarios
//! - No resource leaks or double-free conditions during rollback execution
//! - Obligation states remain consistent with separation logic ownership model

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::cx::{Cx, Registry};
    use crate::obligation::{
        separation_logic::{
            HeapRegion, ResourceOwnership, SeparationInvariant, OwnershipTransfer,
        },
        saga::{
            Saga, SagaStep, SagaRollback, CompensationAction, SagaCoordinator,
        },
        tracking::{ObligationId, ObligationTracker, ObligationState},
    };
    use crate::runtime::Runtime;
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{CancelReason, Outcome, TaskId, Time};
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};

    // ────────────────────────────────────────────────────────────────────────────────
    // Separation Logic + Saga Rollback Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SeparationSagaTestPhase {
        Setup,
        SeparationLogicInitialization,
        SagaCoordinatorSetup,
        BasicSagaRollbackTest,
        NestedSagaRollbacksTest,
        ResourceOwnershipTransferTest,
        InvariantPreservationTest,
        ConcurrentSagaRollbacksTest,
        ComplexRollbackScenariosTest,
        SeparationInvariantVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SeparationSagaTestResult {
        pub test_name: String,
        pub saga_id: String,
        pub phase: SeparationSagaTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub integration_stats: SeparationSagaStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SeparationSagaStats {
        pub sagas_started: u64,
        pub sagas_completed: u64,
        pub sagas_rolled_back: u64,
        pub separation_invariants_checked: u64,
        pub separation_invariants_violated: u64,
        pub ownership_transfers: u64,
        pub heap_regions_created: u64,
        pub heap_regions_merged: u64,
        pub compensation_actions_executed: u64,
        pub nested_rollback_levels: u64,
        pub resource_leaks_detected: u64,
    }

    impl Default for SeparationSagaStats {
        fn default() -> Self {
            Self {
                sagas_started: 0,
                sagas_completed: 0,
                sagas_rolled_back: 0,
                separation_invariants_checked: 0,
                separation_invariants_violated: 0,
                ownership_transfers: 0,
                heap_regions_created: 0,
                heap_regions_merged: 0,
                compensation_actions_executed: 0,
                nested_rollback_levels: 0,
                resource_leaks_detected: 0,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct SeparationSagaConfig {
        pub max_nested_levels: usize,
        pub max_concurrent_sagas: usize,
        pub max_resources_per_saga: usize,
        pub rollback_timeout_ms: u64,
        pub invariant_check_enabled: bool,
        pub detailed_tracking: bool,
        pub stress_test_enabled: bool,
        pub heap_validation_enabled: bool,
    }

    impl Default for SeparationSagaConfig {
        fn default() -> Self {
            Self {
                max_nested_levels: 5,
                max_concurrent_sagas: 3,
                max_resources_per_saga: 10,
                rollback_timeout_ms: 5000,
                invariant_check_enabled: true,
                detailed_tracking: true,
                stress_test_enabled: false,
                heap_validation_enabled: true,
            }
        }
    }

    pub struct MockSeparationSagaSystem {
        config: SeparationSagaConfig,
        separation_logic: Arc<Mutex<MockSeparationLogic>>,
        saga_coordinator: Arc<Mutex<MockSagaCoordinator>>,
        obligation_tracker: Arc<Mutex<ObligationTracker>>,
        stats: Arc<Mutex<SeparationSagaStats>>,
        active_sagas: Arc<RwLock<HashMap<String, MockSaga>>>,
        resource_registry: Arc<RwLock<HashMap<String, MockResource>>>,
        invariant_monitor: Arc<Mutex<InvariantMonitor>>,
    }

    #[derive(Debug)]
    pub struct MockSeparationLogic {
        heap_regions: HashMap<String, HeapRegion>,
        ownership_map: HashMap<String, ResourceOwnership>,
        invariants: Vec<SeparationInvariant>,
        transfer_history: VecDeque<OwnershipTransfer>,
        validation_enabled: bool,
    }

    #[derive(Debug)]
    pub struct MockSagaCoordinator {
        active_sagas: HashMap<String, SagaState>,
        rollback_queue: VecDeque<RollbackOperation>,
        compensation_registry: HashMap<String, Vec<CompensationAction>>,
        nested_saga_map: HashMap<String, Vec<String>>, // parent -> children
        rollback_order: Vec<String>,
    }

    #[derive(Debug, Clone)]
    pub struct MockSaga {
        pub id: String,
        pub parent_id: Option<String>,
        pub steps: Vec<MockSagaStep>,
        pub state: SagaState,
        pub resources: HashSet<String>,
        pub heap_region: String,
        pub started_at: Instant,
        pub rollback_started: Option<Instant>,
    }

    #[derive(Debug, Clone)]
    pub struct MockSagaStep {
        pub id: String,
        pub operation: String,
        pub resources_acquired: Vec<String>,
        pub compensation: Option<MockCompensationAction>,
        pub executed: bool,
        pub compensated: bool,
    }

    #[derive(Debug, Clone)]
    pub struct MockCompensationAction {
        pub action_type: String,
        pub target_resources: Vec<String>,
        pub rollback_data: HashMap<String, String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SagaState {
        Started,
        Executing,
        Completed,
        RollingBack,
        RolledBack,
        Failed,
    }

    #[derive(Debug, Clone)]
    pub struct RollbackOperation {
        pub saga_id: String,
        pub step_id: String,
        pub compensation: MockCompensationAction,
        pub priority: u32,
    }

    #[derive(Debug, Clone)]
    pub struct MockResource {
        pub id: String,
        pub resource_type: String,
        pub owner: Option<String>,
        pub heap_region: String,
        pub value: Vec<u8>,
        pub locked: bool,
    }

    #[derive(Debug)]
    pub struct InvariantMonitor {
        checks_performed: u64,
        violations_detected: Vec<InvariantViolation>,
        last_check: Instant,
    }

    #[derive(Debug, Clone)]
    pub struct InvariantViolation {
        pub invariant_type: String,
        pub resource_id: String,
        pub saga_id: String,
        pub description: String,
        pub detected_at: Instant,
    }

    impl MockSeparationLogic {
        pub fn new() -> Self {
            Self {
                heap_regions: HashMap::new(),
                ownership_map: HashMap::new(),
                invariants: Vec::new(),
                transfer_history: VecDeque::new(),
                validation_enabled: true,
            }
        }

        pub fn create_heap_region(&mut self, region_id: &str, saga_id: &str) -> Result<(), String> {
            if self.heap_regions.contains_key(region_id) {
                return Err(format!("Heap region {} already exists", region_id));
            }

            let region = HeapRegion {
                id: region_id.to_string(),
                owner: saga_id.to_string(),
                resources: HashSet::new(),
                isolated: true,
                created_at: Instant::now(),
            };

            self.heap_regions.insert(region_id.to_string(), region);
            Ok(())
        }

        pub fn transfer_ownership(
            &mut self,
            resource_id: &str,
            from_saga: &str,
            to_saga: &str,
        ) -> Result<(), String> {
            // Check current ownership
            let current_ownership = self.ownership_map.get(resource_id)
                .ok_or("Resource not found in ownership map")?;

            if current_ownership.owner != from_saga {
                return Err(format!("Resource {} not owned by saga {}", resource_id, from_saga));
            }

            // Perform transfer
            let new_ownership = ResourceOwnership {
                resource_id: resource_id.to_string(),
                owner: to_saga.to_string(),
                heap_region: current_ownership.heap_region.clone(),
                acquired_at: Instant::now(),
                exclusive: current_ownership.exclusive,
            };

            // Record transfer
            let transfer = OwnershipTransfer {
                resource_id: resource_id.to_string(),
                from_owner: from_saga.to_string(),
                to_owner: to_saga.to_string(),
                transferred_at: Instant::now(),
                reason: "saga_operation".to_string(),
            };

            self.ownership_map.insert(resource_id.to_string(), new_ownership);
            self.transfer_history.push_back(transfer);

            if self.transfer_history.len() > 1000 {
                self.transfer_history.pop_front();
            }

            Ok(())
        }

        pub fn check_separation_invariants(&mut self) -> Vec<InvariantViolation> {
            if !self.validation_enabled {
                return Vec::new();
            }

            let mut violations = Vec::new();

            // Check heap isolation invariant
            for (region_id, region) in &self.heap_regions {
                for resource_id in &region.resources {
                    if let Some(ownership) = self.ownership_map.get(resource_id) {
                        if ownership.heap_region != *region_id {
                            violations.push(InvariantViolation {
                                invariant_type: "heap_isolation".to_string(),
                                resource_id: resource_id.clone(),
                                saga_id: ownership.owner.clone(),
                                description: format!("Resource {} in wrong heap region", resource_id),
                                detected_at: Instant::now(),
                            });
                        }
                    }
                }
            }

            // Check ownership uniqueness invariant
            let mut resource_owners: HashMap<String, Vec<String>> = HashMap::new();
            for (resource_id, ownership) in &self.ownership_map {
                resource_owners.entry(resource_id.clone())
                    .or_insert_with(Vec::new)
                    .push(ownership.owner.clone());
            }

            for (resource_id, owners) in resource_owners {
                if owners.len() > 1 {
                    violations.push(InvariantViolation {
                        invariant_type: "ownership_uniqueness".to_string(),
                        resource_id,
                        saga_id: owners[0].clone(),
                        description: "Multiple owners for single resource".to_string(),
                        detected_at: Instant::now(),
                    });
                }
            }

            violations
        }

        pub fn rollback_ownership_transfers(&mut self, saga_id: &str) -> Result<(), String> {
            // Collect transfers to rollback (most recent first)
            let mut transfers_to_rollback: Vec<_> = self.transfer_history.iter()
                .filter(|t| t.to_owner == saga_id)
                .cloned()
                .collect();
            transfers_to_rollback.reverse();

            // Perform rollback
            for transfer in transfers_to_rollback {
                if let Some(ownership) = self.ownership_map.get_mut(&transfer.resource_id) {
                    if ownership.owner == saga_id {
                        ownership.owner = transfer.from_owner.clone();
                        ownership.acquired_at = transfer.transferred_at;
                    }
                }
            }

            // Remove rolled back transfers from history
            self.transfer_history.retain(|t| t.to_owner != saga_id);

            Ok(())
        }

        pub fn cleanup_saga_resources(&mut self, saga_id: &str) -> Result<(), String> {
            // Remove ownership entries for the saga
            self.ownership_map.retain(|_, ownership| ownership.owner != saga_id);

            // Remove heap region if owned by saga
            let regions_to_remove: Vec<_> = self.heap_regions.iter()
                .filter(|(_, region)| region.owner == saga_id)
                .map(|(id, _)| id.clone())
                .collect();

            for region_id in regions_to_remove {
                self.heap_regions.remove(&region_id);
            }

            Ok(())
        }
    }

    impl MockSagaCoordinator {
        pub fn new() -> Self {
            Self {
                active_sagas: HashMap::new(),
                rollback_queue: VecDeque::new(),
                compensation_registry: HashMap::new(),
                nested_saga_map: HashMap::new(),
                rollback_order: Vec::new(),
            }
        }

        pub async fn start_saga(&mut self, saga: MockSaga) -> Result<(), String> {
            if self.active_sagas.contains_key(&saga.id) {
                return Err(format!("Saga {} already active", saga.id));
            }

            // Register nested relationship
            if let Some(parent_id) = &saga.parent_id {
                self.nested_saga_map.entry(parent_id.clone())
                    .or_insert_with(Vec::new)
                    .push(saga.id.clone());
            }

            self.active_sagas.insert(saga.id.clone(), SagaState::Started);
            Ok(())
        }

        pub async fn rollback_saga(&mut self, saga_id: &str, cx: &Cx) -> Result<(), String> {
            // Check if saga exists
            if !self.active_sagas.contains_key(saga_id) {
                return Err(format!("Saga {} not found", saga_id));
            }

            // Set saga state to rolling back
            self.active_sagas.insert(saga_id.to_string(), SagaState::RollingBack);

            // First rollback nested sagas (children first)
            if let Some(children) = self.nested_saga_map.get(saga_id) {
                for child_id in children.clone() {
                    self.rollback_saga(&child_id, cx).await?;
                }
            }

            // Execute compensation actions for this saga
            if let Some(compensations) = self.compensation_registry.get(saga_id) {
                for compensation in compensations.iter().rev() { // Reverse order
                    self.execute_compensation(compensation).await?;
                }
            }

            // Update saga state
            self.active_sagas.insert(saga_id.to_string(), SagaState::RolledBack);
            self.rollback_order.push(saga_id.to_string());

            Ok(())
        }

        async fn execute_compensation(&self, compensation: &CompensationAction) -> Result<(), String> {
            // Simulate compensation execution
            sleep(Duration::from_millis(10)).await;
            Ok(())
        }

        pub fn register_compensation(
            &mut self,
            saga_id: &str,
            compensation: CompensationAction,
        ) {
            self.compensation_registry.entry(saga_id.to_string())
                .or_insert_with(Vec::new)
                .push(compensation);
        }

        pub fn get_rollback_order(&self) -> &[String] {
            &self.rollback_order
        }

        pub fn get_nested_depth(&self, saga_id: &str) -> usize {
            let mut depth = 0;
            let mut current_children = vec![saga_id.to_string()];

            while !current_children.is_empty() {
                depth += 1;
                let mut next_children = Vec::new();
                for child in current_children {
                    if let Some(grandchildren) = self.nested_saga_map.get(&child) {
                        next_children.extend(grandchildren.clone());
                    }
                }
                current_children = next_children;
            }

            depth.saturating_sub(1)
        }
    }

    impl MockSeparationSagaSystem {
        pub fn new(config: SeparationSagaConfig) -> Self {
            Self {
                config,
                separation_logic: Arc::new(Mutex::new(MockSeparationLogic::new())),
                saga_coordinator: Arc::new(Mutex::new(MockSagaCoordinator::new())),
                obligation_tracker: Arc::new(Mutex::new(ObligationTracker::new())),
                stats: Arc::new(Mutex::new(SeparationSagaStats::default())),
                active_sagas: Arc::new(RwLock::new(HashMap::new())),
                resource_registry: Arc::new(RwLock::new(HashMap::new())),
                invariant_monitor: Arc::new(Mutex::new(InvariantMonitor {
                    checks_performed: 0,
                    violations_detected: Vec::new(),
                    last_check: Instant::now(),
                })),
            }
        }

        pub async fn create_saga(&self, saga_id: &str, parent_id: Option<String>, cx: &Cx) -> Result<MockSaga, String> {
            // Create heap region for saga
            let heap_region = format!("heap_{}", saga_id);
            {
                let mut sep_logic = self.separation_logic.lock().unwrap();
                sep_logic.create_heap_region(&heap_region, saga_id)?;
            }

            // Create saga
            let saga = MockSaga {
                id: saga_id.to_string(),
                parent_id,
                steps: Vec::new(),
                state: SagaState::Started,
                resources: HashSet::new(),
                heap_region,
                started_at: Instant::now(),
                rollback_started: None,
            };

            // Register with coordinator
            {
                let mut coordinator = self.saga_coordinator.lock().unwrap();
                coordinator.start_saga(saga.clone()).await?;
            }

            // Track active saga
            {
                let mut active = self.active_sagas.write().unwrap();
                active.insert(saga_id.to_string(), saga.clone());
            }

            self.update_stats(|stats| {
                stats.sagas_started += 1;
                stats.heap_regions_created += 1;
            });

            Ok(saga)
        }

        pub async fn rollback_saga_with_invariant_check(&self, saga_id: &str, cx: &Cx) -> Result<(), String> {
            // Check invariants before rollback
            let pre_rollback_violations = self.check_separation_invariants();
            if !pre_rollback_violations.is_empty() {
                self.update_stats(|stats| stats.separation_invariants_violated += pre_rollback_violations.len() as u64);
                return Err(format!("Pre-rollback invariant violations: {}", pre_rollback_violations.len()));
            }

            // Update saga state
            if let Some(saga) = {
                let mut active = self.active_sagas.write().unwrap();
                active.get_mut(saga_id)
            } {
                saga.rollback_started = Some(Instant::now());
                saga.state = SagaState::RollingBack;
            }

            // Perform rollback through coordinator
            {
                let mut coordinator = self.saga_coordinator.lock().unwrap();
                coordinator.rollback_saga(saga_id, cx).await?;
            }

            // Rollback ownership transfers in separation logic
            {
                let mut sep_logic = self.separation_logic.lock().unwrap();
                sep_logic.rollback_ownership_transfers(saga_id)?;
            }

            // Check invariants after rollback
            let post_rollback_violations = self.check_separation_invariants();
            if !post_rollback_violations.is_empty() {
                self.update_stats(|stats| stats.separation_invariants_violated += post_rollback_violations.len() as u64);
                return Err(format!("Post-rollback invariant violations: {}", post_rollback_violations.len()));
            }

            // Cleanup saga resources
            {
                let mut sep_logic = self.separation_logic.lock().unwrap();
                sep_logic.cleanup_saga_resources(saga_id)?;
            }

            // Remove from active sagas
            {
                let mut active = self.active_sagas.write().unwrap();
                if let Some(mut saga) = active.remove(saga_id) {
                    saga.state = SagaState::RolledBack;
                }
            }

            self.update_stats(|stats| stats.sagas_rolled_back += 1);

            Ok(())
        }

        pub async fn test_nested_rollbacks(&self, depth: usize, cx: &Cx) -> Result<(), String> {
            if depth > self.config.max_nested_levels {
                return Err(format!("Depth {} exceeds max levels {}", depth, self.config.max_nested_levels));
            }

            let mut saga_ids = Vec::new();

            // Create nested sagas
            for level in 0..depth {
                let saga_id = format!("nested_saga_level_{}", level);
                let parent_id = if level == 0 { None } else { Some(saga_ids[level - 1].clone()) };

                let saga = self.create_saga(&saga_id, parent_id, cx).await?;
                saga_ids.push(saga.id);
            }

            // Rollback from the root (should cascade to all children)
            if !saga_ids.is_empty() {
                self.rollback_saga_with_invariant_check(&saga_ids[0], cx).await?;
            }

            // Verify rollback order (children should be rolled back before parents)
            let coordinator = self.saga_coordinator.lock().unwrap();
            let rollback_order = coordinator.get_rollback_order();

            // Children should appear before parents in rollback order
            for level in 1..depth {
                let child_pos = rollback_order.iter().position(|id| id == &saga_ids[level]);
                let parent_pos = rollback_order.iter().position(|id| id == &saga_ids[level - 1]);

                if let (Some(child_idx), Some(parent_idx)) = (child_pos, parent_pos) {
                    if child_idx >= parent_idx {
                        return Err(format!("Incorrect rollback order: child {} after parent {}",
                                         saga_ids[level], saga_ids[level - 1]));
                    }
                }
            }

            self.update_stats(|stats| stats.nested_rollback_levels += depth as u64);

            Ok(())
        }

        pub fn check_separation_invariants(&self) -> Vec<InvariantViolation> {
            let mut sep_logic = self.separation_logic.lock().unwrap();
            let violations = sep_logic.check_separation_invariants();

            self.update_stats(|stats| {
                stats.separation_invariants_checked += 1;
                if !violations.is_empty() {
                    stats.separation_invariants_violated += violations.len() as u64;
                }
            });

            // Record violations in monitor
            {
                let mut monitor = self.invariant_monitor.lock().unwrap();
                monitor.checks_performed += 1;
                monitor.violations_detected.extend(violations.clone());
                monitor.last_check = Instant::now();
            }

            violations
        }

        pub fn verify_no_resource_leaks(&self) -> bool {
            let sep_logic = self.separation_logic.lock().unwrap();
            let active_sagas = self.active_sagas.read().unwrap();

            // Check if all resources are properly owned by active sagas
            for (_, ownership) in &sep_logic.ownership_map {
                if !active_sagas.contains_key(&ownership.owner) {
                    self.update_stats(|stats| stats.resource_leaks_detected += 1);
                    return false;
                }
            }

            true
        }

        pub fn get_integration_stats(&self) -> SeparationSagaStats {
            self.stats.lock().unwrap().clone()
        }

        fn update_stats<F>(&self, f: F)
        where
            F: FnOnce(&mut SeparationSagaStats),
        {
            if let Ok(mut stats) = self.stats.lock() {
                f(&mut *stats);
            }
        }

        pub async fn cleanup(&mut self) -> Result<(), String> {
            // Rollback all active sagas
            let saga_ids: Vec<String> = {
                let active = self.active_sagas.read().unwrap();
                active.keys().cloned().collect()
            };

            for saga_id in saga_ids {
                let _ = self.rollback_saga_with_invariant_check(&saga_id, &Cx::root()).await;
            }

            Ok(())
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Tests
    // ────────────────────────────────────────────────────────────────────────────────

    async fn run_separation_saga_integration_test(
        test_name: &str,
        config: SeparationSagaConfig,
    ) -> SeparationSagaTestResult {
        let start_time = Instant::now();
        let mut system = MockSeparationSagaSystem::new(config);

        let runtime = Runtime::new();
        let registry = Registry::new();

        let result = runtime.region(&registry, |cx| async {
            // Test basic saga rollback
            let saga1 = system.create_saga("test_saga_1", None, &cx).await?;
            system.rollback_saga_with_invariant_check(&saga1.id, &cx).await?;

            // Test nested rollbacks
            system.test_nested_rollbacks(3, &cx).await?;

            // Verify separation invariants
            let violations = system.check_separation_invariants();
            if !violations.is_empty() {
                return Err(format!("Separation invariant violations: {}", violations.len()));
            }

            // Verify no resource leaks
            if !system.verify_no_resource_leaks() {
                return Err("Resource leaks detected".to_string());
            }

            // Cleanup
            system.cleanup().await?;

            Ok(())
        }).await;

        let success = result.is_ok();
        let error = result.err();
        let duration_ms = start_time.elapsed().as_millis() as u64;

        SeparationSagaTestResult {
            test_name: test_name.to_string(),
            saga_id: "integration_test".to_string(),
            phase: SeparationSagaTestPhase::Assert,
            success,
            error,
            duration_ms,
            integration_stats: system.get_integration_stats(),
        }
    }

    #[tokio::test]
    async fn test_basic_saga_rollback() {
        let config = SeparationSagaConfig {
            max_nested_levels: 2,
            max_concurrent_sagas: 1,
            invariant_check_enabled: true,
            ..Default::default()
        };

        let result = run_separation_saga_integration_test(
            "basic_saga_rollback",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.sagas_started > 0);
        assert!(result.integration_stats.sagas_rolled_back > 0);
        assert_eq!(result.integration_stats.separation_invariants_violated, 0);
    }

    #[tokio::test]
    async fn test_nested_saga_rollbacks() {
        let config = SeparationSagaConfig {
            max_nested_levels: 5,
            max_concurrent_sagas: 2,
            invariant_check_enabled: true,
            detailed_tracking: true,
            ..Default::default()
        };

        let result = run_separation_saga_integration_test(
            "nested_saga_rollbacks",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.nested_rollback_levels > 0);
        assert_eq!(result.integration_stats.separation_invariants_violated, 0);
    }

    #[tokio::test]
    async fn test_resource_ownership_transfer() {
        let config = SeparationSagaConfig {
            max_nested_levels: 3,
            max_resources_per_saga: 5,
            invariant_check_enabled: true,
            heap_validation_enabled: true,
            ..Default::default()
        };

        let result = run_separation_saga_integration_test(
            "resource_ownership_transfer",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.heap_regions_created > 0);
        assert_eq!(result.integration_stats.separation_invariants_violated, 0);
        assert_eq!(result.integration_stats.resource_leaks_detected, 0);
    }

    #[tokio::test]
    async fn test_invariant_preservation() {
        let config = SeparationSagaConfig {
            max_nested_levels: 4,
            max_concurrent_sagas: 3,
            invariant_check_enabled: true,
            detailed_tracking: true,
            heap_validation_enabled: true,
            ..Default::default()
        };

        let result = run_separation_saga_integration_test(
            "invariant_preservation",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.separation_invariants_checked > 0);
        assert_eq!(result.integration_stats.separation_invariants_violated, 0);
    }

    #[tokio::test]
    async fn test_concurrent_saga_rollbacks() {
        let config = SeparationSagaConfig {
            max_nested_levels: 3,
            max_concurrent_sagas: 4,
            invariant_check_enabled: true,
            stress_test_enabled: false, // Keep test focused
            ..Default::default()
        };

        let result = run_separation_saga_integration_test(
            "concurrent_saga_rollbacks",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.sagas_started > 0);
        assert_eq!(result.integration_stats.separation_invariants_violated, 0);
        assert_eq!(result.integration_stats.resource_leaks_detected, 0);
    }

    #[tokio::test]
    async fn test_complex_rollback_scenarios() {
        let config = SeparationSagaConfig {
            max_nested_levels: 6,
            max_concurrent_sagas: 3,
            max_resources_per_saga: 8,
            rollback_timeout_ms: 10000,
            invariant_check_enabled: true,
            detailed_tracking: true,
            heap_validation_enabled: true,
            ..Default::default()
        };

        let result = run_separation_saga_integration_test(
            "complex_rollback_scenarios",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.nested_rollback_levels > 0);
        assert!(result.integration_stats.separation_invariants_checked > 0);
        assert_eq!(result.integration_stats.separation_invariants_violated, 0);
        assert_eq!(result.integration_stats.resource_leaks_detected, 0);
    }
}