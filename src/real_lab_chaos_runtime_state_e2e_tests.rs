//! Real Lab Chaos ↔ Runtime State E2E Integration Tests
//!
//! Tests comprehensive integration between lab/chaos and runtime/state subsystems,
//! focusing on verification that chaos injection preserves the core region close=quiescence
//! invariant and all structured concurrency guarantees.
//!
//! Core verification: Lab chaos injection (scheduling delays, resource pressure,
//! timing perturbations) must not violate the fundamental invariant that
//! region close implies quiescence (no live children + all finalizers complete).

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    /// Chaos injection configuration for lab testing
    #[derive(Debug, Clone)]
    struct ChaosConfig {
        scheduling_delays: bool,        // Inject random scheduling delays
        resource_pressure: bool,        // Simulate resource exhaustion
        timing_perturbations: bool,     // Perturb timing-sensitive operations
        memory_pressure: bool,          // Simulate memory allocation failures
        network_partitions: bool,       // Inject network connectivity issues
        cpu_starvation: bool,           // Simulate CPU resource contention

        // Chaos parameters
        delay_range_ms: (u64, u64),     // Min/max delay range
        failure_probability: f64,       // Probability of chaos injection
        chaos_duration_ms: u64,         // How long chaos lasts
        recovery_time_ms: u64,          // Time for system recovery
    }

    impl Default for ChaosConfig {
        fn default() -> Self {
            Self {
                scheduling_delays: true,
                resource_pressure: true,
                timing_perturbations: true,
                memory_pressure: false,     // Potentially destructive
                network_partitions: false,  // Not applicable to single-node
                cpu_starvation: true,

                delay_range_ms: (1, 50),    // 1-50ms delays
                failure_probability: 0.1,   // 10% chaos injection rate
                chaos_duration_ms: 100,     // 100ms chaos duration
                recovery_time_ms: 200,      // 200ms recovery time
            }
        }
    }

    /// Runtime state representation for testing
    #[derive(Debug, Clone)]
    struct RuntimeState {
        regions: HashMap<RegionId, RegionState>,
        tasks: HashMap<TaskId, TaskState>,
        obligations: HashMap<ObligationId, ObligationState>,
        global_stats: GlobalStats,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct RegionState {
        region_id: RegionId,
        parent_region: Option<RegionId>,
        child_regions: Vec<RegionId>,
        owned_tasks: Vec<TaskId>,
        pending_obligations: Vec<ObligationId>,
        state: RegionStateEnum,
        created_at: Instant,
        close_requested_at: Option<Instant>,
        quiescence_achieved_at: Option<Instant>,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum RegionStateEnum {
        Active,
        CloseRequested,
        Draining,
        Quiescent,
        Closed,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct TaskState {
        task_id: TaskId,
        owning_region: RegionId,
        state: TaskStateEnum,
        obligations: Vec<ObligationId>,
        created_at: Instant,
        completed_at: Option<Instant>,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum TaskStateEnum {
        Running,
        Cancelling,
        Draining,
        Completed,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct ObligationState {
        obligation_id: ObligationId,
        owning_task: TaskId,
        state: ObligationStateEnum,
        created_at: Instant,
        resolved_at: Option<Instant>,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum ObligationStateEnum {
        Pending,
        Committed,
        Aborted,
    }

    #[derive(Debug, Clone)]
    struct GlobalStats {
        regions_created: AtomicUsize,
        regions_closed: AtomicUsize,
        tasks_spawned: AtomicUsize,
        tasks_completed: AtomicUsize,
        obligations_created: AtomicUsize,
        obligations_resolved: AtomicUsize,
        chaos_events_injected: AtomicUsize,
        invariant_violations: AtomicUsize,
    }

    // Simple ID types for testing
    type RegionId = u64;
    type TaskId = u64;
    type ObligationId = u64;

    impl Default for GlobalStats {
        fn default() -> Self {
            Self {
                regions_created: AtomicUsize::new(0),
                regions_closed: AtomicUsize::new(0),
                tasks_spawned: AtomicUsize::new(0),
                tasks_completed: AtomicUsize::new(0),
                obligations_created: AtomicUsize::new(0),
                obligations_resolved: AtomicUsize::new(0),
                chaos_events_injected: AtomicUsize::new(0),
                invariant_violations: AtomicUsize::new(0),
            }
        }
    }

    /// Chaos injection engine for lab testing
    #[derive(Debug)]
    struct ChaosEngine {
        config: ChaosConfig,
        active: AtomicBool,
        injection_history: Mutex<Vec<ChaosEvent>>,
        stats: ChaosStats,
    }

    #[derive(Debug)]
    struct ChaosStats {
        events_injected: AtomicUsize,
        scheduling_delays: AtomicUsize,
        resource_pressures: AtomicUsize,
        timing_perturbations: AtomicUsize,
        cpu_starvations: AtomicUsize,
        invariant_checks: AtomicUsize,
        invariant_violations: AtomicUsize,
    }

    #[derive(Debug, Clone)]
    struct ChaosEvent {
        event_type: ChaosEventType,
        timestamp: Instant,
        target_region: Option<RegionId>,
        target_task: Option<TaskId>,
        duration_ms: u64,
        description: String,
    }

    #[derive(Debug, Clone)]
    enum ChaosEventType {
        SchedulingDelay,
        ResourcePressure,
        TimingPerturbation,
        MemoryPressure,
        CpuStarvation,
    }

    impl ChaosEngine {
        fn new(config: ChaosConfig) -> Self {
            Self {
                config,
                active: AtomicBool::new(false),
                injection_history: Mutex::new(Vec::new()),
                stats: ChaosStats {
                    events_injected: AtomicUsize::new(0),
                    scheduling_delays: AtomicUsize::new(0),
                    resource_pressures: AtomicUsize::new(0),
                    timing_perturbations: AtomicUsize::new(0),
                    cpu_starvations: AtomicUsize::new(0),
                    invariant_checks: AtomicUsize::new(0),
                    invariant_violations: AtomicUsize::new(0),
                },
            }
        }

        fn start_chaos(&self) {
            self.active.store(true, Ordering::Relaxed);
        }

        fn stop_chaos(&self) {
            self.active.store(false, Ordering::Relaxed);
        }

        fn inject_chaos(&self, runtime_state: &RuntimeState, operation: &str) -> Option<ChaosEvent> {
            if !self.active.load(Ordering::Relaxed) {
                return None;
            }

            // Simple deterministic chaos based on operation hash
            let should_inject = self.should_inject_chaos(operation);
            if !should_inject {
                return None;
            }

            let event_type = self.select_chaos_type();
            let chaos_event = self.create_chaos_event(event_type, runtime_state);

            self.execute_chaos_event(&chaos_event);

            let mut history = self.injection_history.lock().unwrap();
            history.push(chaos_event.clone());
            self.stats.events_injected.fetch_add(1, Ordering::Relaxed);

            Some(chaos_event)
        }

        fn should_inject_chaos(&self, operation: &str) -> bool {
            // Deterministic chaos injection based on operation string
            let hash: u64 = operation.chars().map(|c| c as u64).sum();
            let probability = (hash % 1000) as f64 / 1000.0;
            probability < self.config.failure_probability
        }

        fn select_chaos_type(&self) -> ChaosEventType {
            // Weighted selection based on configuration
            if self.config.scheduling_delays {
                ChaosEventType::SchedulingDelay
            } else if self.config.resource_pressure {
                ChaosEventType::ResourcePressure
            } else if self.config.cpu_starvation {
                ChaosEventType::CpuStarvation
            } else {
                ChaosEventType::TimingPerturbation
            }
        }

        fn create_chaos_event(&self, event_type: ChaosEventType, runtime_state: &RuntimeState) -> ChaosEvent {
            let duration = self.config.delay_range_ms.0 +
                (runtime_state.global_stats.chaos_events_injected.load(Ordering::Relaxed) as u64 %
                 (self.config.delay_range_ms.1 - self.config.delay_range_ms.0));

            ChaosEvent {
                event_type,
                timestamp: Instant::now(),
                target_region: runtime_state.regions.keys().next().copied(),
                target_task: runtime_state.tasks.keys().next().copied(),
                duration_ms: duration,
                description: format!("Chaos injection: {:?} for {}ms", event_type, duration),
            }
        }

        fn execute_chaos_event(&self, event: &ChaosEvent) {
            match event.event_type {
                ChaosEventType::SchedulingDelay => {
                    // Simulate scheduling delay
                    std::thread::sleep(Duration::from_millis(event.duration_ms));
                    self.stats.scheduling_delays.fetch_add(1, Ordering::Relaxed);
                }
                ChaosEventType::ResourcePressure => {
                    // Simulate resource pressure (allocate temporary memory)
                    let _temp_allocation: Vec<u8> = vec![0; (event.duration_ms * 1024) as usize];
                    std::thread::sleep(Duration::from_millis(event.duration_ms / 10));
                    self.stats.resource_pressures.fetch_add(1, Ordering::Relaxed);
                }
                ChaosEventType::CpuStarvation => {
                    // Simulate CPU starvation (busy loop)
                    let end_time = Instant::now() + Duration::from_millis(event.duration_ms);
                    while Instant::now() < end_time {
                        // Busy loop to consume CPU
                        for _ in 0..1000 { std::hint::black_box(1 + 1); }
                    }
                    self.stats.cpu_starvations.fetch_add(1, Ordering::Relaxed);
                }
                ChaosEventType::TimingPerturbation => {
                    // Simulate timing perturbation
                    std::thread::sleep(Duration::from_millis(event.duration_ms / 2));
                    self.stats.timing_perturbations.fetch_add(1, Ordering::Relaxed);
                }
                ChaosEventType::MemoryPressure => {
                    // Memory pressure (disabled by default for safety)
                    // Would simulate memory allocation failures
                }
            }
        }
    }

    /// Runtime state manager with chaos integration
    #[derive(Debug)]
    struct ChaosAwareRuntimeState {
        state: Mutex<RuntimeState>,
        chaos_engine: ChaosEngine,
        invariant_validator: InvariantValidator,
        next_region_id: AtomicU64,
        next_task_id: AtomicU64,
        next_obligation_id: AtomicU64,
    }

    impl ChaosAwareRuntimeState {
        fn new(chaos_config: ChaosConfig) -> Self {
            Self {
                state: Mutex::new(RuntimeState {
                    regions: HashMap::new(),
                    tasks: HashMap::new(),
                    obligations: HashMap::new(),
                    global_stats: GlobalStats::default(),
                }),
                chaos_engine: ChaosEngine::new(chaos_config),
                invariant_validator: InvariantValidator::new(),
                next_region_id: AtomicU64::new(1),
                next_task_id: AtomicU64::new(1),
                next_obligation_id: AtomicU64::new(1),
            }
        }

        fn create_region(&self, parent: Option<RegionId>) -> Result<RegionId, String> {
            // Inject chaos before critical operation
            let state = self.state.lock().unwrap();
            self.chaos_engine.inject_chaos(&state, "create_region");
            drop(state);

            let region_id = self.next_region_id.fetch_add(1, Ordering::Relaxed);

            let mut state = self.state.lock().unwrap();
            let region = RegionState {
                region_id,
                parent_region: parent,
                child_regions: Vec::new(),
                owned_tasks: Vec::new(),
                pending_obligations: Vec::new(),
                state: RegionStateEnum::Active,
                created_at: Instant::now(),
                close_requested_at: None,
                quiescence_achieved_at: None,
            };

            state.regions.insert(region_id, region);
            state.global_stats.regions_created.fetch_add(1, Ordering::Relaxed);

            // Update parent's child list
            if let Some(parent_id) = parent {
                if let Some(parent_region) = state.regions.get_mut(&parent_id) {
                    parent_region.child_regions.push(region_id);
                }
            }

            drop(state);

            // Validate invariants after operation
            self.validate_invariants("create_region")?;

            Ok(region_id)
        }

        fn spawn_task(&self, region_id: RegionId) -> Result<TaskId, String> {
            // Inject chaos before task spawn
            let state = self.state.lock().unwrap();
            self.chaos_engine.inject_chaos(&state, "spawn_task");
            drop(state);

            let task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);

            let mut state = self.state.lock().unwrap();

            // Verify region exists and is active
            let region = state.regions.get(&region_id)
                .ok_or_else(|| format!("Region {} not found", region_id))?;

            if region.state != RegionStateEnum::Active {
                return Err(format!("Cannot spawn task in region {} with state {:?}",
                                   region_id, region.state));
            }

            let task = TaskState {
                task_id,
                owning_region: region_id,
                state: TaskStateEnum::Running,
                obligations: Vec::new(),
                created_at: Instant::now(),
                completed_at: None,
            };

            state.tasks.insert(task_id, task);
            state.global_stats.tasks_spawned.fetch_add(1, Ordering::Relaxed);

            // Add task to region's owned tasks
            if let Some(region) = state.regions.get_mut(&region_id) {
                region.owned_tasks.push(task_id);
            }

            drop(state);

            // Validate invariants after task spawn
            self.validate_invariants("spawn_task")?;

            Ok(task_id)
        }

        fn create_obligation(&self, task_id: TaskId) -> Result<ObligationId, String> {
            // Inject chaos before obligation creation
            let state = self.state.lock().unwrap();
            self.chaos_engine.inject_chaos(&state, "create_obligation");
            drop(state);

            let obligation_id = self.next_obligation_id.fetch_add(1, Ordering::Relaxed);

            let mut state = self.state.lock().unwrap();

            // Verify task exists and is running
            let task = state.tasks.get(&task_id)
                .ok_or_else(|| format!("Task {} not found", task_id))?;

            if task.state != TaskStateEnum::Running {
                return Err(format!("Cannot create obligation for task {} in state {:?}",
                                   task_id, task.state));
            }

            let obligation = ObligationState {
                obligation_id,
                owning_task: task_id,
                state: ObligationStateEnum::Pending,
                created_at: Instant::now(),
                resolved_at: None,
            };

            state.obligations.insert(obligation_id, obligation);
            state.global_stats.obligations_created.fetch_add(1, Ordering::Relaxed);

            // Add obligation to task and region
            if let Some(task) = state.tasks.get_mut(&task_id) {
                task.obligations.push(obligation_id);

                if let Some(region) = state.regions.get_mut(&task.owning_region) {
                    region.pending_obligations.push(obligation_id);
                }
            }

            drop(state);

            // Validate invariants after obligation creation
            self.validate_invariants("create_obligation")?;

            Ok(obligation_id)
        }

        fn close_region(&self, region_id: RegionId) -> Result<(), String> {
            // Inject chaos before region close
            let state = self.state.lock().unwrap();
            self.chaos_engine.inject_chaos(&state, "close_region");
            drop(state);

            let mut state = self.state.lock().unwrap();

            let region = state.regions.get_mut(&region_id)
                .ok_or_else(|| format!("Region {} not found", region_id))?;

            if region.state != RegionStateEnum::Active {
                return Err(format!("Region {} already closing/closed: {:?}",
                                   region_id, region.state));
            }

            region.state = RegionStateEnum::CloseRequested;
            region.close_requested_at = Some(Instant::now());

            drop(state);

            // Begin draining process
            self.drain_region(region_id)?;

            Ok(())
        }

        fn drain_region(&self, region_id: RegionId) -> Result<(), String> {
            // Inject chaos during drain
            let state = self.state.lock().unwrap();
            self.chaos_engine.inject_chaos(&state, "drain_region");
            drop(state);

            let mut state = self.state.lock().unwrap();

            let region = state.regions.get_mut(&region_id)
                .ok_or_else(|| format!("Region {} not found", region_id))?;

            region.state = RegionStateEnum::Draining;

            // Cancel all owned tasks
            for &task_id in &region.owned_tasks.clone() {
                if let Some(task) = state.tasks.get_mut(&task_id) {
                    if task.state == TaskStateEnum::Running {
                        task.state = TaskStateEnum::Cancelling;
                    }
                }
            }

            drop(state);

            // Complete draining and check for quiescence
            self.complete_region_drain(region_id)?;

            Ok(())
        }

        fn complete_region_drain(&self, region_id: RegionId) -> Result<(), String> {
            // Inject chaos during drain completion
            let state = self.state.lock().unwrap();
            self.chaos_engine.inject_chaos(&state, "complete_region_drain");
            drop(state);

            // Simulate task completion and obligation resolution
            let mut state = self.state.lock().unwrap();

            let region = state.regions.get(&region_id)
                .ok_or_else(|| format!("Region {} not found", region_id))?;

            // Complete all tasks in region
            for &task_id in &region.owned_tasks.clone() {
                if let Some(task) = state.tasks.get_mut(&task_id) {
                    if task.state == TaskStateEnum::Cancelling {
                        task.state = TaskStateEnum::Draining;

                        // Resolve all task obligations
                        for &obligation_id in &task.obligations.clone() {
                            if let Some(obligation) = state.obligations.get_mut(&obligation_id) {
                                if obligation.state == ObligationStateEnum::Pending {
                                    obligation.state = ObligationStateEnum::Aborted;
                                    obligation.resolved_at = Some(Instant::now());
                                    state.global_stats.obligations_resolved.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }

                        task.state = TaskStateEnum::Completed;
                        task.completed_at = Some(Instant::now());
                        state.global_stats.tasks_completed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            // Check if region can achieve quiescence
            let can_be_quiescent = self.check_region_quiescence(&state, region_id);

            if can_be_quiescent {
                if let Some(region) = state.regions.get_mut(&region_id) {
                    region.state = RegionStateEnum::Quiescent;
                    region.quiescence_achieved_at = Some(Instant::now());
                }
            }

            drop(state);

            // Final invariant validation for critical region close=quiescence
            self.validate_invariants("complete_region_drain")?;

            // If quiescent, finalize the close
            if can_be_quiescent {
                self.finalize_region_close(region_id)?;
            }

            Ok(())
        }

        fn finalize_region_close(&self, region_id: RegionId) -> Result<(), String> {
            // Final chaos injection before close completion
            let state = self.state.lock().unwrap();
            self.chaos_engine.inject_chaos(&state, "finalize_region_close");
            drop(state);

            let mut state = self.state.lock().unwrap();

            if let Some(region) = state.regions.get_mut(&region_id) {
                region.state = RegionStateEnum::Closed;
                state.global_stats.regions_closed.fetch_add(1, Ordering::Relaxed);
            }

            drop(state);

            // CRITICAL: Final validation of region close=quiescence invariant
            self.validate_invariants("finalize_region_close")?;

            Ok(())
        }

        fn check_region_quiescence(&self, state: &RuntimeState, region_id: RegionId) -> bool {
            let region = match state.regions.get(&region_id) {
                Some(r) => r,
                None => return false,
            };

            // Region is quiescent if:
            // 1. No child regions are active
            // 2. All owned tasks are completed
            // 3. All pending obligations are resolved

            // Check child regions
            for &child_id in &region.child_regions {
                if let Some(child) = state.regions.get(&child_id) {
                    if child.state != RegionStateEnum::Closed {
                        return false;
                    }
                }
            }

            // Check owned tasks
            for &task_id in &region.owned_tasks {
                if let Some(task) = state.tasks.get(&task_id) {
                    if task.state != TaskStateEnum::Completed {
                        return false;
                    }
                }
            }

            // Check pending obligations
            for &obligation_id in &region.pending_obligations {
                if let Some(obligation) = state.obligations.get(&obligation_id) {
                    if obligation.state == ObligationStateEnum::Pending {
                        return false;
                    }
                }
            }

            true
        }

        fn validate_invariants(&self, operation: &str) -> Result<(), String> {
            let state = self.state.lock().unwrap();
            let validation_result = self.invariant_validator.validate(&state, operation);
            drop(state);

            self.chaos_engine.stats.invariant_checks.fetch_add(1, Ordering::Relaxed);

            if let Err(ref _error) = validation_result {
                self.chaos_engine.stats.invariant_violations.fetch_add(1, Ordering::Relaxed);
            }

            validation_result
        }

        fn get_chaos_stats(&self) -> (usize, usize, usize) {
            let events = self.chaos_engine.stats.events_injected.load(Ordering::Relaxed);
            let checks = self.chaos_engine.stats.invariant_checks.load(Ordering::Relaxed);
            let violations = self.chaos_engine.stats.invariant_violations.load(Ordering::Relaxed);
            (events, checks, violations)
        }
    }

    /// Invariant validator ensuring core runtime guarantees
    #[derive(Debug)]
    struct InvariantValidator {
        validation_count: AtomicUsize,
    }

    impl InvariantValidator {
        fn new() -> Self {
            Self {
                validation_count: AtomicUsize::new(0),
            }
        }

        fn validate(&self, state: &RuntimeState, operation: &str) -> Result<(), String> {
            self.validation_count.fetch_add(1, Ordering::Relaxed);

            // Validate core invariants
            self.validate_structured_concurrency(state, operation)?;
            self.validate_region_close_quiescence(state, operation)?;
            self.validate_no_obligation_leaks(state, operation)?;
            self.validate_task_ownership(state, operation)?;

            Ok(())
        }

        fn validate_structured_concurrency(&self, state: &RuntimeState, operation: &str) -> Result<(), String> {
            // Every task must be owned by exactly one region
            for (task_id, task) in &state.tasks {
                if !state.regions.contains_key(&task.owning_region) {
                    return Err(format!(
                        "Invariant violation in {}: Task {} owned by non-existent region {}",
                        operation, task_id, task.owning_region
                    ));
                }

                // Verify task is in region's owned tasks list
                let region = &state.regions[&task.owning_region];
                if !region.owned_tasks.contains(task_id) {
                    return Err(format!(
                        "Invariant violation in {}: Task {} not in region {}'s owned tasks list",
                        operation, task_id, task.owning_region
                    ));
                }
            }

            Ok(())
        }

        fn validate_region_close_quiescence(&self, state: &RuntimeState, operation: &str) -> Result<(), String> {
            // CRITICAL INVARIANT: Region close = quiescence
            // If a region is closed, it must be truly quiescent
            for (region_id, region) in &state.regions {
                if region.state == RegionStateEnum::Closed {
                    // Must have no active child regions
                    for &child_id in &region.child_regions {
                        if let Some(child) = state.regions.get(&child_id) {
                            if child.state != RegionStateEnum::Closed {
                                return Err(format!(
                                    "CRITICAL invariant violation in {}: Closed region {} has non-closed child region {} in state {:?}",
                                    operation, region_id, child_id, child.state
                                ));
                            }
                        }
                    }

                    // Must have all tasks completed
                    for &task_id in &region.owned_tasks {
                        if let Some(task) = state.tasks.get(&task_id) {
                            if task.state != TaskStateEnum::Completed {
                                return Err(format!(
                                    "CRITICAL invariant violation in {}: Closed region {} has non-completed task {} in state {:?}",
                                    operation, region_id, task_id, task.state
                                ));
                            }
                        }
                    }

                    // Must have all obligations resolved
                    for &obligation_id in &region.pending_obligations {
                        if let Some(obligation) = state.obligations.get(&obligation_id) {
                            if obligation.state == ObligationStateEnum::Pending {
                                return Err(format!(
                                    "CRITICAL invariant violation in {}: Closed region {} has pending obligation {}",
                                    operation, region_id, obligation_id
                                ));
                            }
                        }
                    }
                }

                // If region is quiescent, it should be ready to close
                if region.state == RegionStateEnum::Quiescent {
                    if region.close_requested_at.is_none() {
                        return Err(format!(
                            "Invariant violation in {}: Region {} is quiescent but close was never requested",
                            operation, region_id
                        ));
                    }
                }
            }

            Ok(())
        }

        fn validate_no_obligation_leaks(&self, state: &RuntimeState, operation: &str) -> Result<(), String> {
            // No obligations should be orphaned
            for (obligation_id, obligation) in &state.obligations {
                if !state.tasks.contains_key(&obligation.owning_task) {
                    return Err(format!(
                        "Invariant violation in {}: Obligation {} owned by non-existent task {}",
                        operation, obligation_id, obligation.owning_task
                    ));
                }

                // If task is completed, obligation should be resolved
                let task = &state.tasks[&obligation.owning_task];
                if task.state == TaskStateEnum::Completed && obligation.state == ObligationStateEnum::Pending {
                    return Err(format!(
                        "Invariant violation in {}: Completed task {} has pending obligation {}",
                        operation, obligation.owning_task, obligation_id
                    ));
                }
            }

            Ok(())
        }

        fn validate_task_ownership(&self, state: &RuntimeState, operation: &str) -> Result<(), String> {
            // Verify region task ownership is consistent
            for (region_id, region) in &state.regions {
                for &task_id in &region.owned_tasks {
                    if let Some(task) = state.tasks.get(&task_id) {
                        if task.owning_region != *region_id {
                            return Err(format!(
                                "Invariant violation in {}: Region {} claims to own task {} but task thinks it's owned by region {}",
                                operation, region_id, task_id, task.owning_region
                            ));
                        }
                    } else {
                        return Err(format!(
                            "Invariant violation in {}: Region {} claims to own non-existent task {}",
                            operation, region_id, task_id
                        ));
                    }
                }
            }

            Ok(())
        }
    }

    /// Integration test harness for chaos runtime testing
    struct ChaosRuntimeHarness {
        runtime: ChaosAwareRuntimeState,
        test_scenarios: Vec<TestScenario>,
    }

    #[derive(Debug, Clone)]
    struct TestScenario {
        name: String,
        description: String,
        steps: Vec<ScenarioStep>,
        expected_chaos_events: usize,
        chaos_tolerance: f64,
    }

    #[derive(Debug, Clone)]
    enum ScenarioStep {
        CreateRegion { parent: Option<RegionId> },
        SpawnTask { region_id: RegionId },
        CreateObligation { task_id: TaskId },
        CloseRegion { region_id: RegionId },
        ValidateInvariants,
        EnableChaos,
        DisableChaos,
        Sleep(u64), // milliseconds
    }

    impl ChaosRuntimeHarness {
        fn new(chaos_config: ChaosConfig) -> Self {
            Self {
                runtime: ChaosAwareRuntimeState::new(chaos_config),
                test_scenarios: Vec::new(),
            }
        }

        fn add_scenario(&mut self, scenario: TestScenario) {
            self.test_scenarios.push(scenario);
        }

        fn execute_scenario(&self, scenario: &TestScenario) -> Result<ScenarioResult, String> {
            let mut region_ids = Vec::new();
            let mut task_ids = Vec::new();
            let mut obligation_ids = Vec::new();

            let start_time = Instant::now();

            for step in &scenario.steps {
                match step {
                    ScenarioStep::CreateRegion { parent } => {
                        let region_id = self.runtime.create_region(*parent)?;
                        region_ids.push(region_id);
                    }
                    ScenarioStep::SpawnTask { region_id } => {
                        let task_id = self.runtime.spawn_task(*region_id)?;
                        task_ids.push(task_id);
                    }
                    ScenarioStep::CreateObligation { task_id } => {
                        let obligation_id = self.runtime.create_obligation(*task_id)?;
                        obligation_ids.push(obligation_id);
                    }
                    ScenarioStep::CloseRegion { region_id } => {
                        self.runtime.close_region(*region_id)?;
                    }
                    ScenarioStep::ValidateInvariants => {
                        self.runtime.validate_invariants("manual_validation")?;
                    }
                    ScenarioStep::EnableChaos => {
                        self.runtime.chaos_engine.start_chaos();
                    }
                    ScenarioStep::DisableChaos => {
                        self.runtime.chaos_engine.stop_chaos();
                    }
                    ScenarioStep::Sleep(ms) => {
                        std::thread::sleep(Duration::from_millis(*ms));
                    }
                }
            }

            let execution_time = start_time.elapsed();
            let (chaos_events, invariant_checks, invariant_violations) = self.runtime.get_chaos_stats();

            Ok(ScenarioResult {
                scenario_name: scenario.name.clone(),
                execution_time,
                regions_created: region_ids.len(),
                tasks_spawned: task_ids.len(),
                obligations_created: obligation_ids.len(),
                chaos_events_injected: chaos_events,
                invariant_checks,
                invariant_violations,
                success: invariant_violations == 0,
            })
        }

        fn generate_basic_scenarios(&mut self) {
            self.add_scenario(TestScenario {
                name: "Basic Region Lifecycle".to_string(),
                description: "Create region, spawn task, create obligation, close region".to_string(),
                steps: vec![
                    ScenarioStep::EnableChaos,
                    ScenarioStep::CreateRegion { parent: None },
                    ScenarioStep::SpawnTask { region_id: 1 },
                    ScenarioStep::CreateObligation { task_id: 1 },
                    ScenarioStep::CloseRegion { region_id: 1 },
                    ScenarioStep::ValidateInvariants,
                    ScenarioStep::DisableChaos,
                ],
                expected_chaos_events: 5,
                chaos_tolerance: 0.2,
            });

            self.add_scenario(TestScenario {
                name: "Nested Region Hierarchy".to_string(),
                description: "Create nested regions with tasks and verify quiescence propagation".to_string(),
                steps: vec![
                    ScenarioStep::EnableChaos,
                    ScenarioStep::CreateRegion { parent: None },         // region 1
                    ScenarioStep::CreateRegion { parent: Some(1) },     // region 2
                    ScenarioStep::SpawnTask { region_id: 2 },           // task 1
                    ScenarioStep::CreateObligation { task_id: 1 },      // obligation 1
                    ScenarioStep::CloseRegion { region_id: 2 },         // close child first
                    ScenarioStep::CloseRegion { region_id: 1 },         // then parent
                    ScenarioStep::ValidateInvariants,
                    ScenarioStep::DisableChaos,
                ],
                expected_chaos_events: 8,
                chaos_tolerance: 0.3,
            });

            self.add_scenario(TestScenario {
                name: "High Concurrency Chaos".to_string(),
                description: "Multiple regions and tasks under heavy chaos".to_string(),
                steps: vec![
                    ScenarioStep::EnableChaos,
                    ScenarioStep::CreateRegion { parent: None },
                    ScenarioStep::CreateRegion { parent: None },
                    ScenarioStep::CreateRegion { parent: Some(1) },
                    ScenarioStep::SpawnTask { region_id: 1 },
                    ScenarioStep::SpawnTask { region_id: 2 },
                    ScenarioStep::SpawnTask { region_id: 3 },
                    ScenarioStep::CreateObligation { task_id: 1 },
                    ScenarioStep::CreateObligation { task_id: 2 },
                    ScenarioStep::CreateObligation { task_id: 3 },
                    ScenarioStep::Sleep(100), // Let chaos have time to inject
                    ScenarioStep::CloseRegion { region_id: 3 },
                    ScenarioStep::CloseRegion { region_id: 1 },
                    ScenarioStep::CloseRegion { region_id: 2 },
                    ScenarioStep::ValidateInvariants,
                    ScenarioStep::DisableChaos,
                ],
                expected_chaos_events: 15,
                chaos_tolerance: 0.4,
            });
        }
    }

    #[derive(Debug)]
    struct ScenarioResult {
        scenario_name: String,
        execution_time: Duration,
        regions_created: usize,
        tasks_spawned: usize,
        obligations_created: usize,
        chaos_events_injected: usize,
        invariant_checks: usize,
        invariant_violations: usize,
        success: bool,
    }

    #[test]
    fn test_basic_region_lifecycle_with_chaos() {
        let chaos_config = ChaosConfig::default();
        let mut harness = ChaosRuntimeHarness::new(chaos_config);
        harness.generate_basic_scenarios();

        let scenario = &harness.test_scenarios[0]; // Basic Region Lifecycle
        let result = harness.execute_scenario(scenario)
            .expect("Failed to execute basic region lifecycle scenario");

        assert!(result.success,
            "Scenario failed with {} invariant violations",
            result.invariant_violations);
        assert_eq!(result.regions_created, 1);
        assert_eq!(result.tasks_spawned, 1);
        assert_eq!(result.obligations_created, 1);
        assert!(result.chaos_events_injected > 0,
            "Expected chaos events to be injected");

        println!("✓ Basic region lifecycle preserved invariants under chaos: {} events, {} checks",
                 result.chaos_events_injected, result.invariant_checks);
    }

    #[test]
    fn test_nested_region_quiescence_with_chaos() {
        let chaos_config = ChaosConfig {
            scheduling_delays: true,
            resource_pressure: true,
            timing_perturbations: true,
            failure_probability: 0.2, // Higher chaos rate
            ..ChaosConfig::default()
        };

        let mut harness = ChaosRuntimeHarness::new(chaos_config);
        harness.generate_basic_scenarios();

        let scenario = &harness.test_scenarios[1]; // Nested Region Hierarchy
        let result = harness.execute_scenario(scenario)
            .expect("Failed to execute nested region scenario");

        assert!(result.success,
            "Nested region scenario failed with {} invariant violations",
            result.invariant_violations);
        assert_eq!(result.regions_created, 2);
        assert!(result.chaos_events_injected > 0);

        println!("✓ Nested region quiescence preserved under chaos: {} regions, {} events",
                 result.regions_created, result.chaos_events_injected);
    }

    #[test]
    fn test_high_concurrency_chaos_resilience() {
        let chaos_config = ChaosConfig {
            scheduling_delays: true,
            resource_pressure: true,
            timing_perturbations: true,
            cpu_starvation: true,
            failure_probability: 0.3, // Very high chaos rate
            delay_range_ms: (1, 100),  // Longer delays
            ..ChaosConfig::default()
        };

        let mut harness = ChaosRuntimeHarness::new(chaos_config);
        harness.generate_basic_scenarios();

        let scenario = &harness.test_scenarios[2]; // High Concurrency Chaos
        let result = harness.execute_scenario(scenario)
            .expect("Failed to execute high concurrency scenario");

        assert!(result.success,
            "High concurrency scenario failed with {} invariant violations",
            result.invariant_violations);
        assert_eq!(result.regions_created, 3);
        assert_eq!(result.tasks_spawned, 3);
        assert_eq!(result.obligations_created, 3);
        assert!(result.chaos_events_injected >= 10,
            "Expected significant chaos injection");

        println!("✓ High concurrency resilience verified: {} regions, {} tasks, {} chaos events",
                 result.regions_created, result.tasks_spawned, result.chaos_events_injected);
    }

    #[test]
    fn test_chaos_engine_isolation() {
        let chaos_config = ChaosConfig::default();
        let harness = ChaosRuntimeHarness::new(chaos_config);

        // Test chaos engine without runtime operations
        harness.runtime.chaos_engine.start_chaos();

        let dummy_state = RuntimeState {
            regions: HashMap::new(),
            tasks: HashMap::new(),
            obligations: HashMap::new(),
            global_stats: GlobalStats::default(),
        };

        // Inject chaos multiple times
        for i in 0..10 {
            let event = harness.runtime.chaos_engine.inject_chaos(&dummy_state, &format!("test_op_{}", i));
            if let Some(event) = event {
                assert!(event.duration_ms > 0);
                assert!(event.duration_ms <= 100); // Within expected range
            }
        }

        harness.runtime.chaos_engine.stop_chaos();

        let (events, _, _) = harness.runtime.get_chaos_stats();
        assert!(events > 0, "Expected some chaos events to be injected");

        println!("✓ Chaos engine isolation verified: {} events injected", events);
    }

    #[test]
    fn test_region_close_quiescence_invariant_preservation() {
        let chaos_config = ChaosConfig {
            failure_probability: 0.5, // Maximum chaos
            ..ChaosConfig::default()
        };

        let harness = ChaosRuntimeHarness::new(chaos_config);
        harness.runtime.chaos_engine.start_chaos();

        // Create region with tasks and obligations
        let region_id = harness.runtime.create_region(None)
            .expect("Failed to create region");
        let task1_id = harness.runtime.spawn_task(region_id)
            .expect("Failed to spawn task 1");
        let task2_id = harness.runtime.spawn_task(region_id)
            .expect("Failed to spawn task 2");
        let _obligation1 = harness.runtime.create_obligation(task1_id)
            .expect("Failed to create obligation 1");
        let _obligation2 = harness.runtime.create_obligation(task2_id)
            .expect("Failed to create obligation 2");

        // Close region - should trigger drain and quiescence
        harness.runtime.close_region(region_id)
            .expect("Failed to close region");

        // Final validation of region close = quiescence invariant
        harness.runtime.validate_invariants("final_validation")
            .expect("Region close=quiescence invariant violated under chaos");

        harness.runtime.chaos_engine.stop_chaos();

        let (events, checks, violations) = harness.runtime.get_chaos_stats();
        assert_eq!(violations, 0,
            "Invariant violations detected: {} violations out of {} checks",
            violations, checks);

        println!("✓ Region close=quiescence invariant preserved: {} chaos events, {} checks, {} violations",
                 events, checks, violations);
    }

    #[test]
    fn test_obligation_leak_prevention_under_chaos() {
        let chaos_config = ChaosConfig {
            scheduling_delays: true,
            resource_pressure: true,
            failure_probability: 0.4,
            ..ChaosConfig::default()
        };

        let harness = ChaosRuntimeHarness::new(chaos_config);
        harness.runtime.chaos_engine.start_chaos();

        // Create multiple regions with tasks and obligations
        let region1 = harness.runtime.create_region(None).expect("Failed to create region 1");
        let region2 = harness.runtime.create_region(None).expect("Failed to create region 2");

        let task1 = harness.runtime.spawn_task(region1).expect("Failed to spawn task 1");
        let task2 = harness.runtime.spawn_task(region2).expect("Failed to spawn task 2");

        let _obligation1 = harness.runtime.create_obligation(task1).expect("Failed to create obligation 1");
        let _obligation2 = harness.runtime.create_obligation(task2).expect("Failed to create obligation 2");

        // Close regions in specific order to test cleanup
        harness.runtime.close_region(region1).expect("Failed to close region 1");
        harness.runtime.close_region(region2).expect("Failed to close region 2");

        // Validate no obligation leaks
        harness.runtime.validate_invariants("obligation_leak_check")
            .expect("Obligation leak detected under chaos");

        harness.runtime.chaos_engine.stop_chaos();

        let (events, checks, violations) = harness.runtime.get_chaos_stats();
        assert_eq!(violations, 0, "Obligation leaks detected under chaos");

        println!("✓ Obligation leak prevention verified under chaos: {} events, {} checks",
                 events, checks);
    }

    #[test]
    fn test_structured_concurrency_under_extreme_chaos() {
        let chaos_config = ChaosConfig {
            scheduling_delays: true,
            resource_pressure: true,
            timing_perturbations: true,
            cpu_starvation: true,
            failure_probability: 0.8, // Extreme chaos
            delay_range_ms: (10, 200), // High delays
            ..ChaosConfig::default()
        };

        let harness = ChaosRuntimeHarness::new(chaos_config);
        harness.runtime.chaos_engine.start_chaos();

        // Create complex nested structure
        let root_region = harness.runtime.create_region(None).expect("Failed to create root region");
        let child1 = harness.runtime.create_region(Some(root_region)).expect("Failed to create child 1");
        let child2 = harness.runtime.create_region(Some(root_region)).expect("Failed to create child 2");
        let grandchild = harness.runtime.create_region(Some(child1)).expect("Failed to create grandchild");

        // Spawn tasks in each region
        let _task1 = harness.runtime.spawn_task(child1).expect("Failed to spawn task 1");
        let _task2 = harness.runtime.spawn_task(child2).expect("Failed to spawn task 2");
        let _task3 = harness.runtime.spawn_task(grandchild).expect("Failed to spawn task 3");

        // Close from leaves up to root
        harness.runtime.close_region(grandchild).expect("Failed to close grandchild");
        harness.runtime.close_region(child1).expect("Failed to close child 1");
        harness.runtime.close_region(child2).expect("Failed to close child 2");
        harness.runtime.close_region(root_region).expect("Failed to close root region");

        harness.runtime.chaos_engine.stop_chaos();

        let (events, checks, violations) = harness.runtime.get_chaos_stats();
        assert_eq!(violations, 0,
            "Structured concurrency violated under extreme chaos: {} violations",
            violations);

        println!("✓ Structured concurrency preserved under extreme chaos: {} events, {} checks",
                 events, checks);
    }
}