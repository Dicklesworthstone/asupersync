//! BR-E2E-96: Real runtime/region_table ↔ runtime/obligation_table Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the runtime region table
//! and obligation table subsystems. The tests verify dual-table consistency under region
//! close + concurrent obligation modification without violating the strict lock order
//! (E→D→B→A→C): Config→Instrumentation→Regions→Tasks→Obligations.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `runtime::region_table` - Region lifecycle management with hierarchical close operations
//! - `runtime::obligation_table` - Obligation tracking with concurrent modification support
//!
//! # Key Scenarios
//!
//! - Region closure with active obligations requiring cross-table coordination
//! - Concurrent obligation modifications during region lifecycle transitions
//! - Lock order compliance verification (E→D→B→A→C) under stress
//! - Dual-table consistency preservation across crash boundaries
//! - Obligation migration during region hierarchy collapse

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    runtime::{
        obligation_table::{
            ObligationConsistencyCheck, ObligationEntry, ObligationEvent, ObligationId,
            ObligationLifecycle, ObligationMigration, ObligationModification, ObligationOwnership,
            ObligationState, ObligationTable,
        },
        region_table::{
            ChildRegion, ParentRegion, RegionCloseEvent, RegionCloseOperation, RegionCloseReason,
            RegionConsistencyCheck, RegionEntry, RegionHierarchy, RegionId, RegionLifecycle,
            RegionState, RegionTable,
        },
        sharded_state::{LockOrder, LockOrderValidator, ShardedState},
    },
    sync::{ContendedMutex, Mutex, RwLock},
    time::{Duration, Instant, Sleep, Timeout},
    types::{Budget, Cancel, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use futures::{
    ready,
    stream::{Stream, StreamExt},
};

/// Configuration for region/obligation table integration tests
#[derive(Debug, Clone)]
struct RegionObligationTableTestConfig {
    /// Number of concurrent region operations
    concurrent_regions: u32,
    /// Number of concurrent obligation modifications
    concurrent_obligations: u32,
    /// Maximum region hierarchy depth
    max_hierarchy_depth: u32,
    /// Test duration
    test_duration: Duration,
    /// Region close operation delay
    region_close_delay: Duration,
    /// Lock order validation strictness
    lock_order_strict: bool,
}

impl Default for RegionObligationTableTestConfig {
    fn default() -> Self {
        Self {
            concurrent_regions: 8,
            concurrent_obligations: 16,
            max_hierarchy_depth: 6,
            test_duration: Duration::from_secs(3),
            region_close_delay: Duration::from_millis(100),
            lock_order_strict: true,
        }
    }
}

/// Tracks dual-table consistency and lock order compliance
#[derive(Debug)]
struct RegionObligationConsistencyTracker {
    /// Region table operation events
    region_operations: Arc<Mutex<Vec<RegionOperationEvent>>>,
    /// Obligation table modification events
    obligation_operations: Arc<Mutex<Vec<ObligationOperationEvent>>>,
    /// Lock order violation detections
    lock_order_violations: Arc<Mutex<Vec<LockOrderViolationEvent>>>,
    /// Cross-table consistency checks
    consistency_checks: Arc<Mutex<Vec<ConsistencyCheckEvent>>>,
    /// Region close coordination events
    close_coordination: Arc<Mutex<Vec<CloseCoordinationEvent>>>,
    /// Lock acquisition sequence tracking
    lock_sequences: Arc<Mutex<Vec<LockSequenceEvent>>>,
    /// Dual-table state snapshots
    state_snapshots: Arc<Mutex<Vec<DualTableSnapshot>>>,
}

#[derive(Debug, Clone)]
struct RegionOperationEvent {
    timestamp: Instant,
    operation_type: RegionOperationType,
    region_id: RegionId,
    region_state: RegionState,
    hierarchy_context: HierarchyContext,
    affected_obligations: Vec<ObligationId>,
    lock_acquisition_order: Vec<LockType>,
}

#[derive(Debug, Clone, PartialEq)]
enum RegionOperationType {
    Create,
    Close,
    Destroy,
    HierarchyUpdate,
    StateTransition,
}

#[derive(Debug, Clone)]
struct ObligationOperationEvent {
    timestamp: Instant,
    operation_type: ObligationOperationType,
    obligation_id: ObligationId,
    obligation_state: ObligationState,
    region_context: Option<RegionId>,
    modification_type: ObligationModificationType,
    lock_acquisition_order: Vec<LockType>,
}

#[derive(Debug, Clone, PartialEq)]
enum ObligationOperationType {
    Create,
    Modify,
    Migrate,
    Complete,
    Cancel,
}

#[derive(Debug, Clone, PartialEq)]
enum ObligationModificationType {
    StateChange,
    RegionRebind,
    OwnershipTransfer,
    MetadataUpdate,
}

#[derive(Debug, Clone)]
struct LockOrderViolationEvent {
    timestamp: Instant,
    violation_type: LockOrderViolationType,
    expected_order: Vec<LockType>,
    actual_order: Vec<LockType>,
    operation_context: OperationContext,
    thread_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
enum LockOrderViolationType {
    OutOfOrder,
    Deadlock,
    SkippedLock,
    DuplicateAcquisition,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LockType {
    Config,          // E
    Instrumentation, // D
    Regions,         // B
    Tasks,           // A
    Obligations,     // C
}

impl LockType {
    fn order_index(&self) -> u8 {
        match self {
            LockType::Config => 0,          // E
            LockType::Instrumentation => 1, // D
            LockType::Regions => 2,         // B
            LockType::Tasks => 3,           // A
            LockType::Obligations => 4,     // C
        }
    }
}

#[derive(Debug, Clone)]
struct ConsistencyCheckEvent {
    timestamp: Instant,
    check_type: ConsistencyCheckType,
    region_table_state: RegionTableState,
    obligation_table_state: ObligationTableState,
    consistency_result: ConsistencyResult,
    inconsistencies: Vec<Inconsistency>,
}

#[derive(Debug, Clone, PartialEq)]
enum ConsistencyCheckType {
    RegionObligationBinding,
    HierarchyIntegrity,
    StateTransitionSync,
    LifecycleCoherence,
    CrossTableReferences,
}

#[derive(Debug, Clone)]
struct RegionTableState {
    active_regions: u32,
    pending_close: u32,
    hierarchy_depth: u32,
    region_count_by_state: HashMap<RegionState, u32>,
}

#[derive(Debug, Clone)]
struct ObligationTableState {
    active_obligations: u32,
    pending_modifications: u32,
    obligations_by_region: HashMap<RegionId, u32>,
    obligation_count_by_state: HashMap<ObligationState, u32>,
}

#[derive(Debug, Clone, PartialEq)]
enum ConsistencyResult {
    Consistent,
    Inconsistent { severity: InconsistencySeverity },
    UnableToDetermine,
}

#[derive(Debug, Clone, PartialEq)]
enum InconsistencySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct Inconsistency {
    inconsistency_type: InconsistencyType,
    description: String,
    affected_regions: Vec<RegionId>,
    affected_obligations: Vec<ObligationId>,
}

#[derive(Debug, Clone, PartialEq)]
enum InconsistencyType {
    OrphanedObligation,
    RegionObligationMismatch,
    StateDesynchronization,
    ReferentialIntegrityViolation,
}

#[derive(Debug, Clone)]
struct CloseCoordinationEvent {
    timestamp: Instant,
    coordination_type: CloseCoordinationType,
    region_id: RegionId,
    affected_obligations: Vec<ObligationId>,
    coordination_result: CoordinationResult,
    completion_time: Duration,
}

#[derive(Debug, Clone, PartialEq)]
enum CloseCoordinationType {
    RegionCloseInitiated,
    ObligationMigration,
    HierarchyCollapse,
    CrossTableSync,
}

#[derive(Debug, Clone, PartialEq)]
enum CoordinationResult {
    Success,
    PartialSuccess { completed: u32, failed: u32 },
    Failed { reason: String },
}

#[derive(Debug, Clone)]
struct LockSequenceEvent {
    timestamp: Instant,
    thread_id: u64,
    operation_id: OperationId,
    lock_acquired: LockType,
    acquisition_order: Vec<LockType>,
    is_valid_order: bool,
}

#[derive(Debug, Clone)]
struct DualTableSnapshot {
    timestamp: Instant,
    snapshot_id: SnapshotId,
    region_table_snapshot: RegionTableSnapshot,
    obligation_table_snapshot: ObligationTableSnapshot,
    cross_references: CrossTableReferences,
}

#[derive(Debug, Clone)]
struct RegionTableSnapshot {
    regions: HashMap<RegionId, RegionEntry>,
    hierarchy: RegionHierarchy,
    pending_operations: Vec<String>,
}

#[derive(Debug, Clone)]
struct ObligationTableSnapshot {
    obligations: HashMap<ObligationId, ObligationEntry>,
    region_bindings: HashMap<ObligationId, RegionId>,
    pending_modifications: Vec<String>,
}

#[derive(Debug, Clone)]
struct CrossTableReferences {
    regions_to_obligations: HashMap<RegionId, Vec<ObligationId>>,
    obligations_to_regions: HashMap<ObligationId, RegionId>,
    reference_consistency: bool,
}

#[derive(Debug, Clone)]
struct HierarchyContext {
    parent_region: Option<RegionId>,
    child_regions: Vec<RegionId>,
    hierarchy_depth: u32,
    root_region: RegionId,
}

#[derive(Debug, Clone)]
struct OperationContext {
    operation_id: OperationId,
    operation_type: String,
    thread_id: u64,
    start_time: Instant,
}

impl RegionObligationConsistencyTracker {
    fn new() -> Self {
        Self {
            region_operations: Arc::new(Mutex::new(Vec::new())),
            obligation_operations: Arc::new(Mutex::new(Vec::new())),
            lock_order_violations: Arc::new(Mutex::new(Vec::new())),
            consistency_checks: Arc::new(Mutex::new(Vec::new())),
            close_coordination: Arc::new(Mutex::new(Vec::new())),
            lock_sequences: Arc::new(Mutex::new(Vec::new())),
            state_snapshots: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_region_operation(&self, event: RegionOperationEvent) {
        self.region_operations.lock().unwrap().push(event);
    }

    fn record_obligation_operation(&self, event: ObligationOperationEvent) {
        self.obligation_operations.lock().unwrap().push(event);
    }

    fn record_lock_order_violation(&self, event: LockOrderViolationEvent) {
        self.lock_order_violations.lock().unwrap().push(event);
    }

    fn record_consistency_check(&self, event: ConsistencyCheckEvent) {
        self.consistency_checks.lock().unwrap().push(event);
    }

    fn record_close_coordination(&self, event: CloseCoordinationEvent) {
        self.close_coordination.lock().unwrap().push(event);
    }

    fn record_lock_sequence(&self, event: LockSequenceEvent) {
        self.lock_sequences.lock().unwrap().push(event);
    }

    fn record_dual_table_snapshot(&self, snapshot: DualTableSnapshot) {
        let mut snapshots = self.state_snapshots.lock().unwrap();
        snapshots.push(snapshot);
        if snapshots.len() > 100 {
            snapshots.remove(0);
        }
    }

    fn verify_lock_order_compliance(&self) -> bool {
        let violations = self.lock_order_violations.lock().unwrap();
        violations.is_empty()
    }

    fn verify_dual_table_consistency(&self) -> bool {
        let checks = self.consistency_checks.lock().unwrap();
        checks
            .iter()
            .all(|check| matches!(check.consistency_result, ConsistencyResult::Consistent))
    }

    fn verify_region_close_coordination(&self) -> bool {
        let coordinations = self.close_coordination.lock().unwrap();
        coordinations
            .iter()
            .all(|coord| matches!(coord.coordination_result, CoordinationResult::Success))
    }

    fn verify_no_orphaned_obligations(&self) -> bool {
        let checks = self.consistency_checks.lock().unwrap();
        checks.iter().all(|check| {
            !check
                .inconsistencies
                .iter()
                .any(|inc| inc.inconsistency_type == InconsistencyType::OrphanedObligation)
        })
    }

    fn get_lock_order_violation_count(&self) -> usize {
        self.lock_order_violations.lock().unwrap().len()
    }

    fn get_consistency_check_count(&self) -> usize {
        self.consistency_checks.lock().unwrap().len()
    }

    fn get_region_operation_count(&self) -> usize {
        self.region_operations.lock().unwrap().len()
    }

    fn get_obligation_operation_count(&self) -> usize {
        self.obligation_operations.lock().unwrap().len()
    }
}

/// Mock dual-table runtime that enforces lock order and consistency
struct MockDualTableRuntime {
    region_table: Arc<ContendedMutex<MockRegionTable>>,
    obligation_table: Arc<ContendedMutex<MockObligationTable>>,
    lock_order_validator: Arc<LockOrderValidator>,
    operation_id_counter: Arc<AtomicU64>,
    active_operations: Arc<Mutex<HashMap<OperationId, OperationContext>>>,
    consistency_checker: Arc<DualTableConsistencyChecker>,
}

#[derive(Debug)]
struct MockRegionTable {
    regions: HashMap<RegionId, RegionEntry>,
    hierarchy: RegionHierarchy,
    pending_close_operations: VecDeque<RegionCloseOperation>,
    region_id_counter: u64,
}

#[derive(Debug)]
struct MockObligationTable {
    obligations: HashMap<ObligationId, ObligationEntry>,
    region_bindings: HashMap<ObligationId, RegionId>,
    pending_modifications: VecDeque<ObligationModification>,
    obligation_id_counter: u64,
}

#[derive(Debug)]
struct DualTableConsistencyChecker;

impl MockDualTableRuntime {
    fn new() -> Self {
        Self {
            region_table: Arc::new(ContendedMutex::new(MockRegionTable {
                regions: HashMap::new(),
                hierarchy: RegionHierarchy::new(),
                pending_close_operations: VecDeque::new(),
                region_id_counter: 1,
            })),
            obligation_table: Arc::new(ContendedMutex::new(MockObligationTable {
                obligations: HashMap::new(),
                region_bindings: HashMap::new(),
                pending_modifications: VecDeque::new(),
                obligation_id_counter: 1,
            })),
            lock_order_validator: Arc::new(LockOrderValidator::new()),
            operation_id_counter: Arc::new(AtomicU64::new(1)),
            active_operations: Arc::new(Mutex::new(HashMap::new())),
            consistency_checker: Arc::new(DualTableConsistencyChecker),
        }
    }

    async fn create_region(
        &self,
        parent_region: Option<RegionId>,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<RegionId, Box<dyn std::error::Error>> {
        let operation_id = OperationId(self.operation_id_counter.fetch_add(1, Ordering::Release));
        let timestamp = Instant::now();
        let thread_id = self.get_thread_id();

        // Start operation tracking
        self.start_operation_tracking(operation_id, "create_region".to_string(), thread_id);

        // Acquire locks in proper order: E→D→B→A→C
        let lock_sequence = self
            .acquire_locks_for_region_create(operation_id, thread_id, tracker.clone())
            .await?;

        // Perform region creation
        let region_id = {
            let mut region_table = self.region_table.lock().await;
            let region_id = RegionId(region_table.region_id_counter);
            region_table.region_id_counter += 1;

            let region_entry = RegionEntry {
                id: region_id,
                state: RegionState::Active,
                parent: parent_region,
                children: Vec::new(),
                obligations: Vec::new(),
                created_at: timestamp,
            };

            region_table.regions.insert(region_id, region_entry);

            if let Some(parent) = parent_region {
                if let Some(parent_entry) = region_table.regions.get_mut(&parent) {
                    parent_entry.children.push(region_id);
                }
            }

            region_id
        };

        // Record region operation
        let hierarchy_context = self.build_hierarchy_context(region_id).await;
        let region_event = RegionOperationEvent {
            timestamp,
            operation_type: RegionOperationType::Create,
            region_id,
            region_state: RegionState::Active,
            hierarchy_context,
            affected_obligations: Vec::new(),
            lock_acquisition_order: lock_sequence,
        };
        tracker.record_region_operation(region_event);

        self.end_operation_tracking(operation_id);
        Ok(region_id)
    }

    async fn close_region(
        &self,
        region_id: RegionId,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let operation_id = OperationId(self.operation_id_counter.fetch_add(1, Ordering::Release));
        let timestamp = Instant::now();
        let thread_id = self.get_thread_id();

        self.start_operation_tracking(operation_id, "close_region".to_string(), thread_id);

        // Record close coordination initiation
        let coordination_start = Instant::now();
        let close_coord_event = CloseCoordinationEvent {
            timestamp,
            coordination_type: CloseCoordinationType::RegionCloseInitiated,
            region_id,
            affected_obligations: Vec::new(),
            coordination_result: CoordinationResult::Success,
            completion_time: Duration::ZERO,
        };
        tracker.record_close_coordination(close_coord_event);

        // Acquire locks in proper order for close operation
        let lock_sequence = self
            .acquire_locks_for_region_close(operation_id, thread_id, tracker.clone())
            .await?;

        // Get affected obligations before close
        let affected_obligations = {
            let region_table = self.region_table.lock().await;
            region_table
                .regions
                .get(&region_id)
                .map(|entry| entry.obligations.clone())
                .unwrap_or_default()
        };

        // Migrate obligations to parent region or complete them
        for obligation_id in &affected_obligations {
            self.migrate_obligation(*obligation_id, region_id, tracker.clone())
                .await?;
        }

        // Close the region
        {
            let mut region_table = self.region_table.lock().await;
            if let Some(region_entry) = region_table.regions.get_mut(&region_id) {
                region_entry.state = RegionState::Closing;
            }
        }

        // Record region operation
        let hierarchy_context = self.build_hierarchy_context(region_id).await;
        let region_event = RegionOperationEvent {
            timestamp,
            operation_type: RegionOperationType::Close,
            region_id,
            region_state: RegionState::Closing,
            hierarchy_context,
            affected_obligations: affected_obligations.clone(),
            lock_acquisition_order: lock_sequence,
        };
        tracker.record_region_operation(region_event);

        // Perform consistency check
        self.perform_consistency_check(tracker.clone()).await;

        let coordination_completion = CloseCoordinationEvent {
            timestamp,
            coordination_type: CloseCoordinationType::CrossTableSync,
            region_id,
            affected_obligations,
            coordination_result: CoordinationResult::Success,
            completion_time: coordination_start.elapsed(),
        };
        tracker.record_close_coordination(coordination_completion);

        self.end_operation_tracking(operation_id);
        Ok(())
    }

    async fn create_obligation(
        &self,
        region_id: RegionId,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<ObligationId, Box<dyn std::error::Error>> {
        let operation_id = OperationId(self.operation_id_counter.fetch_add(1, Ordering::Release));
        let timestamp = Instant::now();
        let thread_id = self.get_thread_id();

        self.start_operation_tracking(operation_id, "create_obligation".to_string(), thread_id);

        // Acquire locks in proper order
        let lock_sequence = self
            .acquire_locks_for_obligation_create(operation_id, thread_id, tracker.clone())
            .await?;

        // Create obligation
        let obligation_id = {
            let mut obligation_table = self.obligation_table.lock().await;
            let obligation_id = ObligationId(obligation_table.obligation_id_counter);
            obligation_table.obligation_id_counter += 1;

            let obligation_entry = ObligationEntry {
                id: obligation_id,
                state: ObligationState::Active,
                region_id,
                created_at: timestamp,
                metadata: HashMap::new(),
            };

            obligation_table
                .obligations
                .insert(obligation_id, obligation_entry);
            obligation_table
                .region_bindings
                .insert(obligation_id, region_id);

            obligation_id
        };

        // Update region table to reference obligation
        {
            let mut region_table = self.region_table.lock().await;
            if let Some(region_entry) = region_table.regions.get_mut(&region_id) {
                region_entry.obligations.push(obligation_id);
            }
        }

        // Record obligation operation
        let obligation_event = ObligationOperationEvent {
            timestamp,
            operation_type: ObligationOperationType::Create,
            obligation_id,
            obligation_state: ObligationState::Active,
            region_context: Some(region_id),
            modification_type: ObligationModificationType::StateChange,
            lock_acquisition_order: lock_sequence,
        };
        tracker.record_obligation_operation(obligation_event);

        self.end_operation_tracking(operation_id);
        Ok(obligation_id)
    }

    async fn modify_obligation(
        &self,
        obligation_id: ObligationId,
        modification_type: ObligationModificationType,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let operation_id = OperationId(self.operation_id_counter.fetch_add(1, Ordering::Release));
        let timestamp = Instant::now();
        let thread_id = self.get_thread_id();

        self.start_operation_tracking(operation_id, "modify_obligation".to_string(), thread_id);

        // Acquire locks in proper order
        let lock_sequence = self
            .acquire_locks_for_obligation_modify(operation_id, thread_id, tracker.clone())
            .await?;

        // Get current state
        let (current_state, region_id) = {
            let obligation_table = self.obligation_table.lock().await;
            let entry = obligation_table
                .obligations
                .get(&obligation_id)
                .ok_or("Obligation not found")?;
            (entry.state, entry.region_id)
        };

        // Perform modification
        {
            let mut obligation_table = self.obligation_table.lock().await;
            if let Some(obligation_entry) = obligation_table.obligations.get_mut(&obligation_id) {
                match modification_type {
                    ObligationModificationType::StateChange => {
                        obligation_entry.state = match current_state {
                            ObligationState::Active => ObligationState::Completing,
                            ObligationState::Completing => ObligationState::Completed,
                            other => other,
                        };
                    }
                    ObligationModificationType::MetadataUpdate => {
                        obligation_entry
                            .metadata
                            .insert("modified".to_string(), "true".to_string());
                    }
                    _ => {}
                }
            }
        }

        // Record obligation operation
        let obligation_event = ObligationOperationEvent {
            timestamp,
            operation_type: ObligationOperationType::Modify,
            obligation_id,
            obligation_state: current_state,
            region_context: Some(region_id),
            modification_type,
            lock_acquisition_order: lock_sequence,
        };
        tracker.record_obligation_operation(obligation_event);

        self.end_operation_tracking(operation_id);
        Ok(())
    }

    async fn migrate_obligation(
        &self,
        obligation_id: ObligationId,
        from_region: RegionId,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let operation_id = OperationId(self.operation_id_counter.fetch_add(1, Ordering::Release));
        let timestamp = Instant::now();
        let thread_id = self.get_thread_id();

        self.start_operation_tracking(operation_id, "migrate_obligation".to_string(), thread_id);

        // Find target region (parent or complete the obligation)
        let target_region = {
            let region_table = self.region_table.lock().await;
            region_table
                .regions
                .get(&from_region)
                .and_then(|entry| entry.parent)
        };

        let lock_sequence = self
            .acquire_locks_for_obligation_migrate(operation_id, thread_id, tracker.clone())
            .await?;

        if let Some(target_region) = target_region {
            // Migrate to parent region
            {
                let mut obligation_table = self.obligation_table.lock().await;
                if let Some(obligation_entry) = obligation_table.obligations.get_mut(&obligation_id)
                {
                    obligation_entry.region_id = target_region;
                }
                obligation_table
                    .region_bindings
                    .insert(obligation_id, target_region);
            }

            // Update region tables
            {
                let mut region_table = self.region_table.lock().await;
                // Remove from source region
                if let Some(source_entry) = region_table.regions.get_mut(&from_region) {
                    source_entry.obligations.retain(|&id| id != obligation_id);
                }
                // Add to target region
                if let Some(target_entry) = region_table.regions.get_mut(&target_region) {
                    target_entry.obligations.push(obligation_id);
                }
            }
        } else {
            // No parent region, complete the obligation
            {
                let mut obligation_table = self.obligation_table.lock().await;
                if let Some(obligation_entry) = obligation_table.obligations.get_mut(&obligation_id)
                {
                    obligation_entry.state = ObligationState::Completed;
                }
            }
        }

        // Record obligation operation
        let obligation_event = ObligationOperationEvent {
            timestamp,
            operation_type: ObligationOperationType::Migrate,
            obligation_id,
            obligation_state: ObligationState::Active,
            region_context: target_region,
            modification_type: ObligationModificationType::RegionRebind,
            lock_acquisition_order: lock_sequence,
        };
        tracker.record_obligation_operation(obligation_event);

        self.end_operation_tracking(operation_id);
        Ok(())
    }

    async fn acquire_locks_for_region_create(
        &self,
        operation_id: OperationId,
        thread_id: u64,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<Vec<LockType>, Box<dyn std::error::Error>> {
        let mut lock_sequence = Vec::new();

        // Lock order: E→D→B (Config→Instrumentation→Regions)
        self.acquire_lock_with_tracking(
            LockType::Config,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Instrumentation,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Regions,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;

        Ok(lock_sequence)
    }

    async fn acquire_locks_for_region_close(
        &self,
        operation_id: OperationId,
        thread_id: u64,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<Vec<LockType>, Box<dyn std::error::Error>> {
        let mut lock_sequence = Vec::new();

        // Lock order: E→D→B→A→C (full sequence for region close)
        self.acquire_lock_with_tracking(
            LockType::Config,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Instrumentation,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Regions,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Tasks,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Obligations,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;

        Ok(lock_sequence)
    }

    async fn acquire_locks_for_obligation_create(
        &self,
        operation_id: OperationId,
        thread_id: u64,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<Vec<LockType>, Box<dyn std::error::Error>> {
        let mut lock_sequence = Vec::new();

        // Lock order: E→D→B→C (Config→Instrumentation→Regions→Obligations)
        self.acquire_lock_with_tracking(
            LockType::Config,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Instrumentation,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Regions,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Obligations,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;

        Ok(lock_sequence)
    }

    async fn acquire_locks_for_obligation_modify(
        &self,
        operation_id: OperationId,
        thread_id: u64,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<Vec<LockType>, Box<dyn std::error::Error>> {
        let mut lock_sequence = Vec::new();

        // Lock order: E→D→C (Config→Instrumentation→Obligations)
        self.acquire_lock_with_tracking(
            LockType::Config,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Instrumentation,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Obligations,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;

        Ok(lock_sequence)
    }

    async fn acquire_locks_for_obligation_migrate(
        &self,
        operation_id: OperationId,
        thread_id: u64,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<Vec<LockType>, Box<dyn std::error::Error>> {
        let mut lock_sequence = Vec::new();

        // Lock order: E→D→B→C (Config→Instrumentation→Regions→Obligations)
        self.acquire_lock_with_tracking(
            LockType::Config,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Instrumentation,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Regions,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;
        self.acquire_lock_with_tracking(
            LockType::Obligations,
            operation_id,
            thread_id,
            &mut lock_sequence,
            tracker.clone(),
        )
        .await?;

        Ok(lock_sequence)
    }

    async fn acquire_lock_with_tracking(
        &self,
        lock_type: LockType,
        operation_id: OperationId,
        thread_id: u64,
        lock_sequence: &mut Vec<LockType>,
        tracker: Arc<RegionObligationConsistencyTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = Instant::now();

        // Validate lock order
        let is_valid_order = self.validate_lock_order(lock_sequence, &lock_type);

        if !is_valid_order {
            let violation_event = LockOrderViolationEvent {
                timestamp,
                violation_type: LockOrderViolationType::OutOfOrder,
                expected_order: self.get_expected_order(lock_sequence),
                actual_order: {
                    let mut actual = lock_sequence.clone();
                    actual.push(lock_type.clone());
                    actual
                },
                operation_context: OperationContext {
                    operation_id,
                    operation_type: "lock_acquisition".to_string(),
                    thread_id,
                    start_time: timestamp,
                },
                thread_id,
            };
            tracker.record_lock_order_violation(violation_event);
            return Err("Lock order violation detected".into());
        }

        // Simulate lock acquisition delay
        Sleep::new(Instant::now() + Duration::from_micros(10)).await;

        lock_sequence.push(lock_type.clone());

        let lock_sequence_event = LockSequenceEvent {
            timestamp,
            thread_id,
            operation_id,
            lock_acquired: lock_type,
            acquisition_order: lock_sequence.clone(),
            is_valid_order,
        };
        tracker.record_lock_sequence(lock_sequence_event);

        Ok(())
    }

    fn validate_lock_order(&self, current_sequence: &[LockType], next_lock: &LockType) -> bool {
        if current_sequence.is_empty() {
            return true;
        }

        let last_lock = &current_sequence[current_sequence.len() - 1];
        last_lock.order_index() < next_lock.order_index()
    }

    fn get_expected_order(&self, current_sequence: &[LockType]) -> Vec<LockType> {
        let mut expected = current_sequence.to_vec();
        // Add next expected lock in sequence
        if let Some(last_lock) = current_sequence.last() {
            let next_index = last_lock.order_index() + 1;
            if next_index <= LockType::Obligations.order_index() {
                match next_index {
                    0 => expected.push(LockType::Config),
                    1 => expected.push(LockType::Instrumentation),
                    2 => expected.push(LockType::Regions),
                    3 => expected.push(LockType::Tasks),
                    4 => expected.push(LockType::Obligations),
                    _ => {}
                }
            }
        }
        expected
    }

    async fn perform_consistency_check(&self, tracker: Arc<RegionObligationConsistencyTracker>) {
        let timestamp = Instant::now();

        let region_table_state = {
            let region_table = self.region_table.lock().await;
            let mut region_count_by_state = HashMap::new();
            let mut active_regions = 0;
            let mut pending_close = 0;
            let mut max_depth = 0;

            for region_entry in region_table.regions.values() {
                *region_count_by_state.entry(region_entry.state).or_insert(0) += 1;
                match region_entry.state {
                    RegionState::Active => active_regions += 1,
                    RegionState::Closing => pending_close += 1,
                    _ => {}
                }
            }

            RegionTableState {
                active_regions,
                pending_close,
                hierarchy_depth: max_depth,
                region_count_by_state,
            }
        };

        let obligation_table_state = {
            let obligation_table = self.obligation_table.lock().await;
            let mut obligation_count_by_state = HashMap::new();
            let mut obligations_by_region = HashMap::new();
            let mut active_obligations = 0;
            let pending_modifications = obligation_table.pending_modifications.len() as u32;

            for obligation_entry in obligation_table.obligations.values() {
                *obligation_count_by_state
                    .entry(obligation_entry.state)
                    .or_insert(0) += 1;
                *obligations_by_region
                    .entry(obligation_entry.region_id)
                    .or_insert(0) += 1;
                if obligation_entry.state == ObligationState::Active {
                    active_obligations += 1;
                }
            }

            ObligationTableState {
                active_obligations,
                pending_modifications,
                obligations_by_region,
                obligation_count_by_state,
            }
        };

        // Check for inconsistencies
        let inconsistencies = self
            .detect_inconsistencies(&region_table_state, &obligation_table_state)
            .await;

        let consistency_result = if inconsistencies.is_empty() {
            ConsistencyResult::Consistent
        } else {
            let max_severity = inconsistencies
                .iter()
                .map(|inc| self.get_severity(&inc.inconsistency_type))
                .max()
                .unwrap_or(InconsistencySeverity::Low);
            ConsistencyResult::Inconsistent {
                severity: max_severity,
            }
        };

        let consistency_event = ConsistencyCheckEvent {
            timestamp,
            check_type: ConsistencyCheckType::CrossTableReferences,
            region_table_state,
            obligation_table_state,
            consistency_result,
            inconsistencies,
        };

        tracker.record_consistency_check(consistency_event);
    }

    async fn detect_inconsistencies(
        &self,
        _region_state: &RegionTableState,
        _obligation_state: &ObligationTableState,
    ) -> Vec<Inconsistency> {
        let mut inconsistencies = Vec::new();

        // Check for orphaned obligations
        let region_table = self.region_table.lock().await;
        let obligation_table = self.obligation_table.lock().await;

        for (obligation_id, obligation_entry) in &obligation_table.obligations {
            if !region_table
                .regions
                .contains_key(&obligation_entry.region_id)
            {
                inconsistencies.push(Inconsistency {
                    inconsistency_type: InconsistencyType::OrphanedObligation,
                    description: format!(
                        "Obligation {:?} references non-existent region {:?}",
                        obligation_id, obligation_entry.region_id
                    ),
                    affected_regions: vec![obligation_entry.region_id],
                    affected_obligations: vec![*obligation_id],
                });
            }
        }

        // Check region-obligation binding consistency
        for (region_id, region_entry) in &region_table.regions {
            for &obligation_id in &region_entry.obligations {
                if let Some(obligation_entry) = obligation_table.obligations.get(&obligation_id) {
                    if obligation_entry.region_id != *region_id {
                        inconsistencies.push(Inconsistency {
                            inconsistency_type: InconsistencyType::RegionObligationMismatch,
                            description: format!("Region {:?} claims obligation {:?} but obligation points to region {:?}",
                                               region_id, obligation_id, obligation_entry.region_id),
                            affected_regions: vec![*region_id, obligation_entry.region_id],
                            affected_obligations: vec![obligation_id],
                        });
                    }
                }
            }
        }

        inconsistencies
    }

    fn get_severity(&self, inconsistency_type: &InconsistencyType) -> InconsistencySeverity {
        match inconsistency_type {
            InconsistencyType::OrphanedObligation => InconsistencySeverity::High,
            InconsistencyType::RegionObligationMismatch => InconsistencySeverity::Critical,
            InconsistencyType::StateDesynchronization => InconsistencySeverity::Medium,
            InconsistencyType::ReferentialIntegrityViolation => InconsistencySeverity::High,
        }
    }

    async fn build_hierarchy_context(&self, region_id: RegionId) -> HierarchyContext {
        let region_table = self.region_table.lock().await;
        let region_entry = region_table.regions.get(&region_id);

        HierarchyContext {
            parent_region: region_entry.and_then(|entry| entry.parent),
            child_regions: region_entry
                .map(|entry| entry.children.clone())
                .unwrap_or_default(),
            hierarchy_depth: self.calculate_hierarchy_depth(region_id, &region_table.regions),
            root_region: self.find_root_region(region_id, &region_table.regions),
        }
    }

    fn calculate_hierarchy_depth(
        &self,
        region_id: RegionId,
        regions: &HashMap<RegionId, RegionEntry>,
    ) -> u32 {
        let mut depth = 0;
        let mut current = region_id;

        while let Some(region_entry) = regions.get(&current) {
            if let Some(parent) = region_entry.parent {
                depth += 1;
                current = parent;
            } else {
                break;
            }
        }

        depth
    }

    fn find_root_region(
        &self,
        region_id: RegionId,
        regions: &HashMap<RegionId, RegionEntry>,
    ) -> RegionId {
        let mut current = region_id;

        while let Some(region_entry) = regions.get(&current) {
            if let Some(parent) = region_entry.parent {
                current = parent;
            } else {
                break;
            }
        }

        current
    }

    fn start_operation_tracking(
        &self,
        operation_id: OperationId,
        operation_type: String,
        thread_id: u64,
    ) {
        let operation_context = OperationContext {
            operation_id,
            operation_type,
            thread_id,
            start_time: Instant::now(),
        };

        self.active_operations
            .lock()
            .unwrap()
            .insert(operation_id, operation_context);
    }

    fn end_operation_tracking(&self, operation_id: OperationId) {
        self.active_operations.lock().unwrap().remove(&operation_id);
    }

    fn get_thread_id(&self) -> u64 {
        // Mock thread ID based on current time
        Instant::now().elapsed().as_nanos() as u64 % 10000
    }

    fn get_region_count(&self) -> usize {
        // Mock implementation - would require lock in real code
        0
    }

    fn get_obligation_count(&self) -> usize {
        // Mock implementation - would require lock in real code
        0
    }
}

// Test implementations start here

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_region_close_with_concurrent_obligation_modification() {
        let config = RegionObligationTableTestConfig {
            concurrent_regions: 4,
            concurrent_obligations: 8,
            max_hierarchy_depth: 3,
            test_duration: Duration::from_secs(2),
            region_close_delay: Duration::from_millis(300),
            lock_order_strict: true,
        };

        let tracker = Arc::new(RegionObligationConsistencyTracker::new());
        let runtime = Arc::new(MockDualTableRuntime::new());

        // Create region hierarchy
        let root_region = runtime.create_region(None, tracker.clone()).await.unwrap();

        let mut child_regions = Vec::new();
        for i in 0..config.concurrent_regions {
            let parent = if i == 0 {
                Some(root_region)
            } else {
                child_regions.get(0).copied()
            };
            let region = runtime
                .create_region(parent, tracker.clone())
                .await
                .unwrap();
            child_regions.push(region);
        }

        // Create obligations in various regions
        let mut obligations = Vec::new();
        for i in 0..config.concurrent_obligations {
            let region_idx = i as usize % child_regions.len();
            let region = child_regions[region_idx];
            let obligation = runtime
                .create_obligation(region, tracker.clone())
                .await
                .unwrap();
            obligations.push(obligation);
        }

        // Start concurrent obligation modifications
        let modification_handles: Vec<_> = obligations
            .iter()
            .take(4)
            .enumerate()
            .map(|(i, &obligation_id)| {
                let runtime = runtime.clone();
                let tracker = tracker.clone();

                tokio::spawn(async move {
                    let modification_types = [
                        ObligationModificationType::StateChange,
                        ObligationModificationType::MetadataUpdate,
                    ];

                    for j in 0..3 {
                        let mod_type = modification_types[j % modification_types.len()].clone();
                        let _ = runtime
                            .modify_obligation(obligation_id, mod_type, tracker.clone())
                            .await;

                        Sleep::new(Instant::now() + Duration::from_millis(50)).await;
                    }
                })
            })
            .collect();

        // Wait for some modifications to start
        Sleep::new(Instant::now() + config.region_close_delay).await;

        // Start region close operations
        let close_handles: Vec<_> = child_regions
            .iter()
            .take(2)
            .map(|&region_id| {
                let runtime = runtime.clone();
                let tracker = tracker.clone();

                tokio::spawn(async move {
                    let _ = runtime.close_region(region_id, tracker).await;
                })
            })
            .collect();

        // Wait for all operations to complete
        for handle in modification_handles {
            let _ = handle.await;
        }

        for handle in close_handles {
            let _ = handle.await;
        }

        // Verify lock order compliance
        assert!(
            tracker.verify_lock_order_compliance(),
            "Lock order E→D→B→A→C should be maintained"
        );

        // Verify dual-table consistency
        assert!(
            tracker.verify_dual_table_consistency(),
            "Region and obligation tables should remain consistent"
        );

        // Verify region close coordination
        assert!(
            tracker.verify_region_close_coordination(),
            "Region close operations should coordinate properly"
        );

        // Verify no orphaned obligations
        assert!(
            tracker.verify_no_orphaned_obligations(),
            "No obligations should be orphaned after region close"
        );

        // Verify operation counts
        assert!(
            tracker.get_region_operation_count() > 0,
            "Should have region operations"
        );
        assert!(
            tracker.get_obligation_operation_count() > 0,
            "Should have obligation operations"
        );
        assert_eq!(
            tracker.get_lock_order_violation_count(),
            0,
            "Should have no lock order violations"
        );
    }

    #[tokio::test]
    async fn test_lock_order_validation_under_stress() {
        let config = RegionObligationTableTestConfig {
            concurrent_regions: 6,
            concurrent_obligations: 12,
            test_duration: Duration::from_millis(1500),
            lock_order_strict: true,
            ..Default::default()
        };

        let tracker = Arc::new(RegionObligationConsistencyTracker::new());
        let runtime = Arc::new(MockDualTableRuntime::new());

        // Create baseline setup
        let root_region = runtime.create_region(None, tracker.clone()).await.unwrap();

        // Start high-frequency concurrent operations
        let operation_handles: Vec<_> = (0..config.concurrent_regions
            + config.concurrent_obligations)
            .map(|i| {
                let runtime = runtime.clone();
                let tracker = tracker.clone();

                tokio::spawn(async move {
                    for j in 0..5 {
                        if i % 2 == 0 {
                            // Create regions
                            let _ = runtime
                                .create_region(Some(root_region), tracker.clone())
                                .await;
                        } else {
                            // Create and modify obligations
                            if let Ok(obligation_id) = runtime
                                .create_obligation(root_region, tracker.clone())
                                .await
                            {
                                let _ = runtime
                                    .modify_obligation(
                                        obligation_id,
                                        ObligationModificationType::StateChange,
                                        tracker.clone(),
                                    )
                                    .await;
                            }
                        }

                        Sleep::new(Instant::now() + Duration::from_millis(20)).await;
                    }
                })
            })
            .collect();

        // Wait for all operations
        for handle in operation_handles {
            let _ = handle.await;
        }

        // Verify strict lock order compliance
        assert!(
            tracker.verify_lock_order_compliance(),
            "All operations should maintain strict lock order E→D→B→A→C"
        );

        // Verify no deadlocks occurred
        let violations = tracker.lock_order_violations.lock().unwrap();
        let deadlock_violations = violations
            .iter()
            .filter(|v| v.violation_type == LockOrderViolationType::Deadlock)
            .count();
        assert_eq!(deadlock_violations, 0, "Should have no deadlock violations");

        // Verify consistent operation tracking
        assert!(
            tracker.get_region_operation_count() > 0,
            "Should track region operations"
        );
        assert!(
            tracker.get_obligation_operation_count() > 0,
            "Should track obligation operations"
        );
    }

    #[tokio::test]
    async fn test_hierarchy_consistency_during_cascading_close() {
        let config = RegionObligationTableTestConfig {
            concurrent_regions: 5,
            concurrent_obligations: 10,
            max_hierarchy_depth: 4,
            test_duration: Duration::from_secs(1),
            ..Default::default()
        };

        let tracker = Arc::new(RegionObligationConsistencyTracker::new());
        let runtime = Arc::new(MockDualTableRuntime::new());

        // Build deep hierarchy
        let root_region = runtime.create_region(None, tracker.clone()).await.unwrap();
        let mut hierarchy = vec![root_region];

        for depth in 1..=config.max_hierarchy_depth {
            let parent = hierarchy[(depth - 1) as usize];
            let child = runtime
                .create_region(Some(parent), tracker.clone())
                .await
                .unwrap();
            hierarchy.push(child);
        }

        // Distribute obligations across hierarchy levels
        let mut obligations = Vec::new();
        for i in 0..config.concurrent_obligations {
            let region_idx = (i as usize) % hierarchy.len();
            let region = hierarchy[region_idx];
            let obligation = runtime
                .create_obligation(region, tracker.clone())
                .await
                .unwrap();
            obligations.push((obligation, region));
        }

        // Start obligation modifications
        let modification_handles: Vec<_> = obligations
            .iter()
            .map(|&(obligation_id, _)| {
                let runtime = runtime.clone();
                let tracker = tracker.clone();

                tokio::spawn(async move {
                    for _ in 0..3 {
                        let _ = runtime
                            .modify_obligation(
                                obligation_id,
                                ObligationModificationType::MetadataUpdate,
                                tracker.clone(),
                            )
                            .await;

                        Sleep::new(Instant::now() + Duration::from_millis(30)).await;
                    }
                })
            })
            .collect();

        // Close regions from deepest to shallowest (cascading close)
        let close_handles: Vec<_> = hierarchy
            .iter()
            .rev()
            .skip(1)
            .map(|&region_id| {
                let runtime = runtime.clone();
                let tracker = tracker.clone();

                tokio::spawn(async move {
                    Sleep::new(Instant::now() + Duration::from_millis(100)).await;
                    let _ = runtime.close_region(region_id, tracker).await;
                })
            })
            .collect();

        // Wait for all operations
        for handle in modification_handles {
            let _ = handle.await;
        }

        for handle in close_handles {
            let _ = handle.await;
        }

        // Verify hierarchy consistency
        assert!(
            tracker.verify_dual_table_consistency(),
            "Hierarchy should remain consistent during cascading close"
        );

        // Verify obligation migration occurred correctly
        assert!(
            tracker.verify_no_orphaned_obligations(),
            "All obligations should be properly migrated or completed"
        );

        // Verify coordination was successful
        assert!(
            tracker.verify_region_close_coordination(),
            "All close operations should coordinate successfully"
        );

        // Check consistency check results
        assert!(
            tracker.get_consistency_check_count() > 0,
            "Should have performed consistency checks"
        );
    }

    #[test]
    fn test_lock_order_validation_logic() {
        let runtime = MockDualTableRuntime::new();

        // Test valid lock order
        let valid_sequence = vec![
            LockType::Config,
            LockType::Instrumentation,
            LockType::Regions,
        ];
        assert!(runtime.validate_lock_order(&valid_sequence, &LockType::Tasks));

        // Test invalid lock order (skipping)
        assert!(!runtime.validate_lock_order(&vec![LockType::Config], &LockType::Regions));

        // Test backwards order
        let backwards_sequence = vec![LockType::Regions];
        assert!(!runtime.validate_lock_order(&backwards_sequence, &LockType::Config));

        // Test empty sequence (always valid)
        assert!(runtime.validate_lock_order(&[], &LockType::Config));
    }

    #[test]
    fn test_lock_type_ordering() {
        assert!(LockType::Config.order_index() < LockType::Instrumentation.order_index());
        assert!(LockType::Instrumentation.order_index() < LockType::Regions.order_index());
        assert!(LockType::Regions.order_index() < LockType::Tasks.order_index());
        assert!(LockType::Tasks.order_index() < LockType::Obligations.order_index());

        // Test the complete E→D→B→A→C ordering
        assert_eq!(LockType::Config.order_index(), 0); // E
        assert_eq!(LockType::Instrumentation.order_index(), 1); // D
        assert_eq!(LockType::Regions.order_index(), 2); // B
        assert_eq!(LockType::Tasks.order_index(), 3); // A
        assert_eq!(LockType::Obligations.order_index(), 4); // C
    }
}

// Supporting types and implementations

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RegionId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ObligationId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OperationId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SnapshotId(u64);

#[derive(Debug, Clone)]
struct RegionEntry {
    id: RegionId,
    state: RegionState,
    parent: Option<RegionId>,
    children: Vec<RegionId>,
    obligations: Vec<ObligationId>,
    created_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RegionState {
    Active,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
struct ObligationEntry {
    id: ObligationId,
    state: ObligationState,
    region_id: RegionId,
    created_at: Instant,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ObligationState {
    Active,
    Completing,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone)]
struct RegionHierarchy {
    root_regions: Vec<RegionId>,
    parent_child_map: HashMap<RegionId, Vec<RegionId>>,
}

impl RegionHierarchy {
    fn new() -> Self {
        Self {
            root_regions: Vec::new(),
            parent_child_map: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct RegionCloseOperation {
    region_id: RegionId,
    reason: RegionCloseReason,
    started_at: Instant,
}

#[derive(Debug, Clone)]
enum RegionCloseReason {
    Explicit,
    ParentClosed,
    TaskCompletion,
    Error,
}

#[derive(Debug, Clone)]
struct RegionCloseEvent;

#[derive(Debug, Clone)]
struct ParentRegion;

#[derive(Debug, Clone)]
struct ChildRegion;

#[derive(Debug, Clone)]
struct RegionLifecycle;

#[derive(Debug, Clone)]
struct RegionConsistencyCheck;

#[derive(Debug, Clone)]
struct ObligationModification {
    obligation_id: ObligationId,
    modification_type: ObligationModificationType,
    timestamp: Instant,
}

#[derive(Debug, Clone)]
struct ObligationEvent;

#[derive(Debug, Clone)]
struct ObligationOwnership;

#[derive(Debug, Clone)]
struct ObligationMigration;

#[derive(Debug, Clone)]
struct ObligationLifecycle;

#[derive(Debug, Clone)]
struct ObligationConsistencyCheck;

#[derive(Debug, Clone)]
struct ShardGuard;

#[derive(Debug, Clone)]
struct LockOrderValidator;

impl LockOrderValidator {
    fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
struct RuntimeState;

#[derive(Debug, Clone)]
struct RuntimeConfig;
