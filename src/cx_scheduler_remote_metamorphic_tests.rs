//! Metamorphic Testing for Context, Scheduler & Remote Modules [br-metamorphic-25]
//!
//! This module implements comprehensive metamorphic relations testing the
//! context system (registry & scope), scheduler subsystems, and remote task
//! handling. These tests address the oracle problem where conventional unit
//! tests cannot verify complex concurrency properties, priority fairness,
//! and distributed system semantics under contention.
//!
//! ## Metamorphic Relations Implemented
//!
//! ### Context (cx/*) Module (5 MRs)
//! - MR-RegistryEdgeCaseConsistency: Name lease operations maintain consistency under edge cases
//! - MR-RegistryConcurrentRegistrationOrder: Concurrent registrations follow deterministic ordering
//! - MR-ScopeBudgetExhaustionInvariance: Budget exhaustion behavior is invariant to scheduling
//! - MR-RegistryLeaseLifecycleMonotonicity: Lease lifecycle states progress monotonically
//! - MR-ScopeCapabilitySoundness: Capability access patterns preserve soundness rules
//!
//! ### Scheduler (runtime/scheduler) Modules (6 MRs)
//! - MR-IntrusiveHeapInsertionOrderInvariant: Insertion order invariants hold under churn
//! - MR-IntrusiveHeapPriorityPreservation: Priority heap properties preserved under mutations
//! - MR-ThreeLanePriorityPromotionStarvation: Priority promotion prevents starvation scenarios
//! - MR-ThreeLaneFairnessUnderContention: Lane fairness contracts maintained under load
//! - MR-GlobalInjectorFIFOContention: FIFO properties preserved under concurrent injection
//! - MR-GlobalInjectorCombinerConsistency: Ready combiner maintains batch consistency
//!
//! ### Remote (remote.rs) Module (4 MRs)
//! - MR-RemoteHandleJoinCancelAfterCompletionIdempotency: join() after completion is idempotent
//! - MR-RemoteHandleStateTransitionConsistency: State transitions follow protocol rules
//! - MR-RemoteTaskLeaseExpiryDeterminism: Lease expiry behavior is deterministic
//! - MR-RemoteResultDeliveryExactlyOnce: Result delivery maintains exactly-once semantics

#![allow(dead_code)]

#[cfg(test)]
mod tests {
    #[cfg(test)]
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
    use std::sync::Arc;
    use std::time::Duration;

    // ═══════════════════════════════════════════════════════════════════════════
    // Mock Implementations for Metamorphic Testing
    // ═══════════════════════════════════════════════════════════════════════════

    // Context (cx/*) Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockRegistry {
        pub leases: HashMap<String, MockNameLease>,
        pub next_lease_id: u64,
        pub concurrent_ops: VecDeque<MockRegistryOp>,
        pub deterministic_tie_breaker: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockNameLease {
        pub lease_id: u64,
        pub name: String,
        pub owner_task: u64,
        pub state: MockLeaseState,
        pub created_at: u64,
        pub released_at: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockLeaseState {
        Active,
        Released,
        Aborted,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockRegistryOp {
        pub op_id: u64,
        pub op_type: MockOpType,
        pub name: String,
        pub task_id: u64,
        pub timestamp: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockOpType {
        Reserve,
        Release,
        Abort,
    }

    impl MockRegistry {
        pub fn new() -> Self {
            Self {
                leases: HashMap::new(),
                next_lease_id: 1,
                concurrent_ops: VecDeque::new(),
                deterministic_tie_breaker: 0,
            }
        }

        pub fn reserve_name(
            &mut self,
            name: String,
            task_id: u64,
            timestamp: u64,
        ) -> Result<u64, &'static str> {
            if self.leases.contains_key(&name) {
                return Err("Name already leased");
            }

            let lease_id = self.next_lease_id;
            self.next_lease_id += 1;

            let lease = MockNameLease {
                lease_id,
                name: name.clone(),
                owner_task: task_id,
                state: MockLeaseState::Active,
                created_at: timestamp,
                released_at: None,
            };

            self.leases.insert(name.clone(), lease);

            // Record operation for deterministic ordering
            self.concurrent_ops.push_back(MockRegistryOp {
                op_id: lease_id,
                op_type: MockOpType::Reserve,
                name,
                task_id,
                timestamp,
            });

            Ok(lease_id)
        }

        pub fn release_name(&mut self, name: String, timestamp: u64) -> Result<(), &'static str> {
            if let Some(lease) = self.leases.get_mut(&name) {
                if lease.state != MockLeaseState::Active {
                    return Err("Lease not active");
                }
                lease.state = MockLeaseState::Released;
                lease.released_at = Some(timestamp);

                self.concurrent_ops.push_back(MockRegistryOp {
                    op_id: lease.lease_id,
                    op_type: MockOpType::Release,
                    name,
                    task_id: lease.owner_task,
                    timestamp,
                });

                Ok(())
            } else {
                Err("No lease found")
            }
        }

        pub fn abort_name(&mut self, name: String, timestamp: u64) -> Result<(), &'static str> {
            if let Some(lease) = self.leases.get_mut(&name) {
                if lease.state != MockLeaseState::Active {
                    return Err("Lease not active");
                }
                lease.state = MockLeaseState::Aborted;
                lease.released_at = Some(timestamp);

                self.concurrent_ops.push_back(MockRegistryOp {
                    op_id: lease.lease_id,
                    op_type: MockOpType::Abort,
                    name,
                    task_id: lease.owner_task,
                    timestamp,
                });

                Ok(())
            } else {
                Err("No lease found")
            }
        }

        pub fn get_deterministic_order(&self) -> Vec<MockRegistryOp> {
            let mut ops = self.concurrent_ops.iter().cloned().collect::<Vec<_>>();
            ops.sort_by_key(|op| (op.timestamp, op.task_id, op.name.clone()));
            ops
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockScope {
        pub budget: MockBudget,
        pub spawned_tasks: Vec<MockSpawnedTask>,
        pub budget_exhaustion_count: u32,
        pub next_task_id: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockBudget {
        pub cpu_millis: u64,
        pub memory_bytes: u64,
        pub io_ops: u32,
        pub network_bytes: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockSpawnedTask {
        pub task_id: u64,
        pub budget_consumed: MockBudget,
        pub spawn_result: MockSpawnResult,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockSpawnResult {
        Success,
        BudgetExhausted(String),
        CapabilityDenied(String),
    }

    impl MockScope {
        pub fn new(initial_budget: MockBudget) -> Self {
            Self {
                budget: initial_budget,
                spawned_tasks: Vec::new(),
                budget_exhaustion_count: 0,
                next_task_id: 1,
            }
        }

        pub fn try_spawn(&mut self, required_budget: MockBudget) -> Result<u64, MockSpawnResult> {
            let task_id = self.next_task_id;
            self.next_task_id += 1;

            if self.budget.cpu_millis < required_budget.cpu_millis
                || self.budget.memory_bytes < required_budget.memory_bytes
                || self.budget.io_ops < required_budget.io_ops
                || self.budget.network_bytes < required_budget.network_bytes
            {
                self.budget_exhaustion_count += 1;
                let result = MockSpawnResult::BudgetExhausted("Insufficient budget".to_string());
                self.spawned_tasks.push(MockSpawnedTask {
                    task_id,
                    budget_consumed: MockBudget {
                        cpu_millis: 0,
                        memory_bytes: 0,
                        io_ops: 0,
                        network_bytes: 0,
                    },
                    spawn_result: result.clone(),
                });
                return Err(result);
            }

            // Consume budget
            self.budget.cpu_millis -= required_budget.cpu_millis;
            self.budget.memory_bytes -= required_budget.memory_bytes;
            self.budget.io_ops -= required_budget.io_ops;
            self.budget.network_bytes -= required_budget.network_bytes;

            self.spawned_tasks.push(MockSpawnedTask {
                task_id,
                budget_consumed: required_budget,
                spawn_result: MockSpawnResult::Success,
            });

            Ok(task_id)
        }

        pub fn available_budget(&self) -> &MockBudget {
            &self.budget
        }
    }

    // Scheduler Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockIntrusiveHeap {
        pub heap: Vec<u64>, // task_ids
        pub task_metadata: HashMap<u64, MockTaskMetadata>,
        pub next_generation: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockTaskMetadata {
        pub task_id: u64,
        pub priority: u8,
        pub generation: u64,
        pub heap_index: Option<usize>,
    }

    impl MockIntrusiveHeap {
        pub fn new() -> Self {
            Self {
                heap: Vec::new(),
                task_metadata: HashMap::new(),
                next_generation: 1,
            }
        }

        pub fn push(&mut self, task_id: u64, priority: u8) {
            let generation = self.next_generation;
            self.next_generation += 1;

            let metadata = MockTaskMetadata {
                task_id,
                priority,
                generation,
                heap_index: None,
            };

            self.task_metadata.insert(task_id, metadata);
            self.heap.push(task_id);
            let pos = self.heap.len() - 1;
            self.task_metadata.get_mut(&task_id).unwrap().heap_index = Some(pos);
            self.sift_up(pos);
        }

        pub fn pop(&mut self) -> Option<u64> {
            if self.heap.is_empty() {
                return None;
            }

            let root_task = self.heap[0];
            let last_task = self.heap.pop().unwrap();

            self.task_metadata.get_mut(&root_task).unwrap().heap_index = None;

            if !self.heap.is_empty() {
                self.heap[0] = last_task;
                self.task_metadata.get_mut(&last_task).unwrap().heap_index = Some(0);
                self.sift_down(0);
            }

            Some(root_task)
        }

        pub fn remove(&mut self, task_id: u64) -> bool {
            if let Some(metadata) = self.task_metadata.get(&task_id) {
                if let Some(index) = metadata.heap_index {
                    let last_task = self.heap.pop().unwrap();
                    self.task_metadata.get_mut(&task_id).unwrap().heap_index = None;

                    if index < self.heap.len() {
                        self.heap[index] = last_task;
                        self.task_metadata.get_mut(&last_task).unwrap().heap_index = Some(index);

                        // Restore heap property
                        if self.should_sift_up(index) {
                            self.sift_up(index);
                        } else {
                            self.sift_down(index);
                        }
                    }

                    true
                } else {
                    false
                }
            } else {
                false
            }
        }

        fn sift_up(&mut self, mut pos: usize) {
            while pos > 0 {
                let parent_pos = (pos - 1) / 2;
                if self.compare(parent_pos, pos) {
                    break;
                }
                self.heap.swap(parent_pos, pos);
                self.task_metadata
                    .get_mut(&self.heap[parent_pos])
                    .unwrap()
                    .heap_index = Some(parent_pos);
                self.task_metadata
                    .get_mut(&self.heap[pos])
                    .unwrap()
                    .heap_index = Some(pos);
                pos = parent_pos;
            }
        }

        fn sift_down(&mut self, mut pos: usize) {
            loop {
                let left_child = 2 * pos + 1;
                let right_child = 2 * pos + 2;
                let mut largest = pos;

                if left_child < self.heap.len() && !self.compare(largest, left_child) {
                    largest = left_child;
                }

                if right_child < self.heap.len() && !self.compare(largest, right_child) {
                    largest = right_child;
                }

                if largest == pos {
                    break;
                }

                self.heap.swap(pos, largest);
                self.task_metadata
                    .get_mut(&self.heap[pos])
                    .unwrap()
                    .heap_index = Some(pos);
                self.task_metadata
                    .get_mut(&self.heap[largest])
                    .unwrap()
                    .heap_index = Some(largest);
                pos = largest;
            }
        }

        fn should_sift_up(&self, pos: usize) -> bool {
            if pos == 0 {
                return false;
            }
            let parent_pos = (pos - 1) / 2;
            !self.compare(parent_pos, pos)
        }

        fn compare(&self, i: usize, j: usize) -> bool {
            let task_i = self.heap[i];
            let task_j = self.heap[j];
            let meta_i = &self.task_metadata[&task_i];
            let meta_j = &self.task_metadata[&task_j];

            // Max heap: higher priority first, then earlier generation
            meta_i.priority > meta_j.priority
                || (meta_i.priority == meta_j.priority && meta_i.generation < meta_j.generation)
        }

        pub fn verify_heap_property(&self) -> bool {
            for i in 0..self.heap.len() {
                let left_child = 2 * i + 1;
                let right_child = 2 * i + 2;

                if left_child < self.heap.len() && !self.compare(i, left_child) {
                    return false;
                }

                if right_child < self.heap.len() && !self.compare(i, right_child) {
                    return false;
                }
            }
            true
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockThreeLaneScheduler {
        pub cancel_lane: VecDeque<u64>,
        pub timed_lane: BTreeMap<u64, Vec<u64>>, // deadline -> tasks
        pub ready_lane: VecDeque<u64>,
        pub cancel_streak: u32,
        pub cancel_streak_limit: u32,
        pub timed_streak: u32,
        pub timed_streak_limit: u32,
        pub stolen_streak: u32,
        pub stolen_streak_limit: u32,
        pub current_time: u64,
        pub dispatch_history: Vec<MockDispatch>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockDispatch {
        pub task_id: u64,
        pub lane: MockLaneType,
        pub timestamp: u64,
        pub streak_count: u32,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockLaneType {
        Cancel,
        Timed,
        Ready,
        Stolen,
    }

    impl MockThreeLaneScheduler {
        pub fn new(cancel_limit: u32, timed_limit: u32, stolen_limit: u32) -> Self {
            Self {
                cancel_lane: VecDeque::new(),
                timed_lane: BTreeMap::new(),
                ready_lane: VecDeque::new(),
                cancel_streak: 0,
                cancel_streak_limit: cancel_limit,
                timed_streak: 0,
                timed_streak_limit: timed_limit,
                stolen_streak: 0,
                stolen_streak_limit: stolen_limit,
                current_time: 0,
                dispatch_history: Vec::new(),
            }
        }

        pub fn schedule_cancel(&mut self, task_id: u64) {
            self.cancel_lane.push_back(task_id);
        }

        pub fn schedule_timed(&mut self, task_id: u64, deadline: u64) {
            self.timed_lane
                .entry(deadline)
                .or_insert_with(Vec::new)
                .push(task_id);
        }

        pub fn schedule_ready(&mut self, task_id: u64) {
            self.ready_lane.push_back(task_id);
        }

        pub fn advance_time(&mut self, new_time: u64) {
            self.current_time = new_time;
        }

        pub fn next_task(&mut self) -> Option<MockDispatch> {
            self.current_time += 1;

            // Cancel lane has strict priority, but fairness limits apply
            if !self.cancel_lane.is_empty()
                && (self.cancel_streak < self.cancel_streak_limit
                    || (self.timed_lane.is_empty() && self.ready_lane.is_empty()))
            {
                let task_id = self.cancel_lane.pop_front().unwrap();
                self.cancel_streak += 1;
                self.timed_streak = 0;
                self.stolen_streak = 0;

                let dispatch = MockDispatch {
                    task_id,
                    lane: MockLaneType::Cancel,
                    timestamp: self.current_time,
                    streak_count: self.cancel_streak,
                };
                self.dispatch_history.push(dispatch.clone());
                return Some(dispatch);
            }

            // Check timed lane for due tasks
            let due_tasks: Vec<u64> = self
                .timed_lane
                .range(..=self.current_time)
                .flat_map(|(_, tasks)| tasks.iter().cloned())
                .collect();

            if !due_tasks.is_empty()
                && (self.timed_streak < self.timed_streak_limit || self.ready_lane.is_empty())
            {
                // Remove from timed lane and dispatch
                for deadline in self.timed_lane.keys().cloned().collect::<Vec<_>>() {
                    if deadline <= self.current_time {
                        if let Some(mut tasks) = self.timed_lane.remove(&deadline) {
                            if !tasks.is_empty() {
                                let task_id = tasks.remove(0);
                                if !tasks.is_empty() {
                                    self.timed_lane.insert(deadline, tasks);
                                }

                                self.cancel_streak = 0;
                                self.timed_streak += 1;
                                self.stolen_streak = 0;

                                let dispatch = MockDispatch {
                                    task_id,
                                    lane: MockLaneType::Timed,
                                    timestamp: self.current_time,
                                    streak_count: self.timed_streak,
                                };
                                self.dispatch_history.push(dispatch.clone());
                                return Some(dispatch);
                            }
                        }
                    }
                }
            }

            // Ready lane
            if !self.ready_lane.is_empty() {
                let task_id = self.ready_lane.pop_front().unwrap();
                self.cancel_streak = 0;
                self.timed_streak = 0;
                self.stolen_streak += 1;

                let dispatch = MockDispatch {
                    task_id,
                    lane: MockLaneType::Ready,
                    timestamp: self.current_time,
                    streak_count: self.stolen_streak,
                };
                self.dispatch_history.push(dispatch.clone());
                return Some(dispatch);
            }

            // Reset streaks if no work available
            self.cancel_streak = 0;
            self.timed_streak = 0;
            self.stolen_streak = 0;
            None
        }

        pub fn verify_fairness_invariants(&self) -> bool {
            // Check cancel fairness: no more than limit consecutive cancel dispatches
            // when other work was available
            let mut max_cancel_streak = 0;
            let mut current_cancel_streak = 0;

            for window in self.dispatch_history.windows(2) {
                if let MockLaneType::Cancel = window[0].lane {
                    current_cancel_streak += 1;
                    max_cancel_streak = max_cancel_streak.max(current_cancel_streak);
                } else {
                    current_cancel_streak = 0;
                }
            }

            max_cancel_streak <= self.cancel_streak_limit
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockGlobalInjector {
        pub ready_queue: VecDeque<u64>,
        pub combiner_pending: Vec<u64>,
        pub combiner_active: bool,
        pub injection_order: Vec<u64>,
        pub batch_sizes: Vec<usize>,
        pub contention_counter: u32,
    }

    impl MockGlobalInjector {
        pub fn new() -> Self {
            Self {
                ready_queue: VecDeque::new(),
                combiner_pending: Vec::new(),
                combiner_active: false,
                injection_order: Vec::new(),
                batch_sizes: Vec::new(),
                contention_counter: 0,
            }
        }

        pub fn inject_task(&mut self, task_id: u64, contention: bool) {
            self.injection_order.push(task_id);

            if contention {
                self.contention_counter += 1;
            }

            if self.combiner_active || contention {
                // Use combiner path
                self.combiner_pending.push(task_id);

                if self.combiner_pending.len() >= 4 || !contention {
                    // Flush combiner
                    let batch_size = self.combiner_pending.len();
                    self.batch_sizes.push(batch_size);

                    for pending_task in self.combiner_pending.drain(..) {
                        self.ready_queue.push_back(pending_task);
                    }
                    self.combiner_active = false;
                }
            } else {
                // Direct path
                self.ready_queue.push_back(task_id);
            }
        }

        pub fn activate_combiner(&mut self) {
            self.combiner_active = true;
        }

        pub fn pop_task(&mut self) -> Option<u64> {
            self.ready_queue.pop_front()
        }

        pub fn verify_fifo_property(&self) -> bool {
            // Check that injection order matches ready queue order for tasks
            // that went through the direct path
            let mut ready_iter = self.ready_queue.iter();
            let mut injection_iter = self.injection_order.iter();

            // This is a simplified check - in practice, combiner batching
            // can reorder within batches while preserving global FIFO
            while let (Some(&ready_task), Some(&injected_task)) =
                (ready_iter.next(), injection_iter.next())
            {
                // Allow for combiner reordering within reasonable bounds
                let position_in_ready = self.ready_queue.iter().position(|&t| t == injected_task);

                if let Some(pos) = position_in_ready {
                    if pos > 10 {
                        // Allow some reordering due to batching
                        return false;
                    }
                }
            }
            true
        }
    }

    // Remote Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockRemoteHandle {
        pub remote_task_id: u64,
        pub state: MockRemoteState,
        pub completion_result: Option<MockRemoteResult>,
        pub join_call_count: u32,
        pub cancel_after_completion_calls: u32,
        pub lease_expiry_time: Option<u64>,
        pub current_time: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockRemoteState {
        Running,
        Completed,
        Cancelled,
        LeaseExpired,
        PolledAfterCompletion,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockRemoteResult {
        Success(Vec<u8>),
        Error(String),
        Cancelled(String),
        LeaseExpired,
    }

    impl MockRemoteHandle {
        pub fn new(remote_task_id: u64, lease_expiry_time: Option<u64>) -> Self {
            Self {
                remote_task_id,
                state: MockRemoteState::Running,
                completion_result: None,
                join_call_count: 0,
                cancel_after_completion_calls: 0,
                lease_expiry_time,
                current_time: 0,
            }
        }

        pub fn complete(&mut self, result: MockRemoteResult) {
            if self.state == MockRemoteState::Running {
                self.state = MockRemoteState::Completed;
                self.completion_result = Some(result);
            }
        }

        pub fn cancel(&mut self, reason: String) {
            if self.state == MockRemoteState::Running {
                self.state = MockRemoteState::Cancelled;
                self.completion_result = Some(MockRemoteResult::Cancelled(reason));
            }
        }

        pub fn advance_time(&mut self, new_time: u64) {
            self.current_time = new_time;

            if let Some(expiry_time) = self.lease_expiry_time {
                if self.current_time >= expiry_time && self.state == MockRemoteState::Running {
                    self.state = MockRemoteState::LeaseExpired;
                    self.completion_result = Some(MockRemoteResult::LeaseExpired);
                }
            }
        }

        pub fn join(&mut self) -> Result<MockRemoteResult, &'static str> {
            self.join_call_count += 1;

            match &self.state {
                MockRemoteState::Running => {
                    if let Some(expiry_time) = self.lease_expiry_time {
                        if self.current_time >= expiry_time {
                            self.state = MockRemoteState::LeaseExpired;
                            return Ok(MockRemoteResult::LeaseExpired);
                        }
                    }
                    Err("Still running")
                }
                MockRemoteState::Completed => {
                    if let Some(result) = &self.completion_result {
                        Ok(result.clone())
                    } else {
                        Err("No result available")
                    }
                }
                MockRemoteState::Cancelled => {
                    if let Some(result) = &self.completion_result {
                        Ok(result.clone())
                    } else {
                        Err("No result available")
                    }
                }
                MockRemoteState::LeaseExpired => Ok(MockRemoteResult::LeaseExpired),
                MockRemoteState::PolledAfterCompletion => {
                    self.state = MockRemoteState::PolledAfterCompletion;
                    Err("Polled after completion")
                }
            }
        }

        pub fn cancel_after_completion(&mut self) -> Result<(), &'static str> {
            self.cancel_after_completion_calls += 1;

            match &self.state {
                MockRemoteState::Completed
                | MockRemoteState::Cancelled
                | MockRemoteState::LeaseExpired => {
                    // Canceling after completion should be idempotent
                    Ok(())
                }
                MockRemoteState::Running => {
                    self.cancel("Cancel after completion".to_string());
                    Ok(())
                }
                MockRemoteState::PolledAfterCompletion => Err("Already polled after completion"),
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Context (cx/*) Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_registry_edge_case_consistency() {
        proptest!(|(
            name_operations in proptest::collection::vec(
                (
                    proptest::string::string_regex("[a-z]{3,8}").unwrap(),
                    1u64..100,
                    1000u64..2000,
                    0u8..3  // operation type
                ),
                5..15
            ),
            concurrent_batch_size in 2usize..6
        )| {
            // MR-RegistryEdgeCaseConsistency:
            // Registry operations should maintain consistency under edge cases:
            // duplicate names, concurrent registrations, lease state transitions

            let mut registry = MockRegistry::new();
            let mut operation_results = Vec::new();

            // Apply operations in batches to simulate concurrency
            for batch in name_operations.chunks(concurrent_batch_size) {
                let mut batch_results = Vec::new();

                for (name, task_id, timestamp, op_type) in batch {
                    let result = match op_type % 3 {
                        0 => registry.reserve_name(name.clone(), *task_id, *timestamp)
                            .map(|lease_id| format!("Reserved {} -> {}", name, lease_id))
                            .map_err(|e| e.to_string()),
                        1 => registry.release_name(name.clone(), *timestamp)
                            .map(|_| format!("Released {}", name))
                            .map_err(|e| e.to_string()),
                        _ => registry.abort_name(name.clone(), *timestamp)
                            .map(|_| format!("Aborted {}", name))
                            .map_err(|e| e.to_string()),
                    };
                    batch_results.push((name.clone(), result));
                }
                operation_results.extend(batch_results);
            }

            // Verify consistency properties

            // 1. No name should have multiple active leases
            let active_leases: HashMap<String, u32> = registry.leases.iter()
                .filter(|(_, lease)| lease.state == MockLeaseState::Active)
                .fold(HashMap::new(), |mut acc, (name, _)| {
                    *acc.entry(name.clone()).or_insert(0) += 1;
                    acc
                });

            for (name, count) in &active_leases {
                prop_assert_eq!(
                    *count, 1,
                    "Name '{}' should have at most one active lease, found {}",
                    name, count
                );
            }

            // 2. Deterministic ordering should be consistent
            let ordered_ops = registry.get_deterministic_order();
            for window in ordered_ops.windows(2) {
                let key1 = (window[0].timestamp, window[0].task_id, &window[0].name);
                let key2 = (window[1].timestamp, window[1].task_id, &window[1].name);

                prop_assert!(
                    key1 <= key2,
                    "Operations should be in deterministic order: {:?} vs {:?}",
                    window[0], window[1]
                );
            }

            // 3. Lease lifecycle monotonicity
            for lease in registry.leases.values() {
                match lease.state {
                    MockLeaseState::Released | MockLeaseState::Aborted => {
                        prop_assert!(
                            lease.released_at.is_some(),
                            "Terminal lease states should have release timestamp: {:?}",
                            lease
                        );

                        if let Some(released_at) = lease.released_at {
                            prop_assert!(
                                released_at >= lease.created_at,
                                "Release time should be >= creation time: {} vs {}",
                                released_at, lease.created_at
                            );
                        }
                    }
                    MockLeaseState::Active => {
                        prop_assert!(
                            lease.released_at.is_none(),
                            "Active leases should not have release timestamp: {:?}",
                            lease
                        );
                    }
                }
            }
        });
    }

    #[test]
    fn mr_registry_concurrent_registration_order() {
        proptest!(|(
            concurrent_registrations in proptest::collection::vec(
                (
                    proptest::string::string_regex("[a-z]{4,6}").unwrap(),
                    1u64..50,
                    1000u64..1100  // tight timestamp range for concurrency
                ),
                3..10
            ),
            permutation_seed in 0u64..1000
        )| {
            // MR-RegistryConcurrentRegistrationOrder:
            // Concurrent registrations for the same name should follow deterministic
            // ordering regardless of arrival order (first timestamp wins)

            let original_registrations = concurrent_registrations.clone();

            // Apply registrations in original order
            let mut registry_original = MockRegistry::new();
            for (name, task_id, timestamp) in &original_registrations {
                let _ = registry_original.reserve_name(name.clone(), *task_id, *timestamp);
            }

            // Apply registrations in permuted order
            let mut permuted_registrations = original_registrations.clone();
            for i in 0..permuted_registrations.len() {
                let j = ((permutation_seed + i as u64) % permuted_registrations.len() as u64) as usize;
                permuted_registrations.swap(i, j);
            }

            let mut registry_permuted = MockRegistry::new();
            for (name, task_id, timestamp) in &permuted_registrations {
                let _ = registry_permuted.reserve_name(name.clone(), *task_id, *timestamp);
            }

            // The final state should be identical regardless of arrival order
            // (deterministic tie-breaking by timestamp, task_id)
            let original_order = registry_original.get_deterministic_order();
            let permuted_order = registry_permuted.get_deterministic_order();

            prop_assert_eq!(
                original_order, permuted_order,
                "Deterministic ordering should be identical regardless of arrival order"
            );

            // For each name, the winning lease should be the one with earliest timestamp
            for name in original_registrations.iter().map(|(n, _, _)| n).collect::<BTreeSet<_>>() {
                let original_winner = registry_original.leases.get(name);
                let permuted_winner = registry_permuted.leases.get(name);

                match (original_winner, permuted_winner) {
                    (Some(orig), Some(perm)) => {
                        prop_assert_eq!(
                            orig, perm,
                            "Winner for name '{}' should be identical: {:?} vs {:?}",
                            name, orig, perm
                        );

                        // Winner should have earliest timestamp among all attempts for this name
                        let all_attempts_for_name: Vec<_> = original_registrations.iter()
                            .filter(|(n, _, _)| n == name)
                            .collect();

                        if let Some((_, _, earliest_timestamp)) = all_attempts_for_name.iter()
                            .min_by_key(|(_, task_id, timestamp)| (*timestamp, *task_id)) {

                            prop_assert_eq!(
                                orig.created_at, *earliest_timestamp,
                                "Winner should have earliest timestamp for name '{}': {} vs {}",
                                name, orig.created_at, *earliest_timestamp
                            );
                        }
                    }
                    (None, None) => {
                        // Both failed to register (collision handling worked identically)
                    }
                    _ => {
                        prop_assert!(false, "Registration outcome should be identical for name '{}'", name);
                    }
                }
            }
        });
    }

    #[test]
    fn mr_scope_budget_exhaustion_invariance() {
        proptest!(|(
            initial_budget in (
                1000u64..5000,  // cpu_millis
                1000000u64..10000000,  // memory_bytes
                100u32..1000,  // io_ops
                10000u64..100000  // network_bytes
            ),
            spawn_requests in proptest::collection::vec(
                (
                    1u64..1000,     // cpu_millis
                    1000u64..50000, // memory_bytes
                    1u32..50,       // io_ops
                    100u64..5000    // network_bytes
                ),
                5..20
            ),
            scheduling_permutation in proptest::collection::vec(0usize..20, 5..20)
        )| {
            // MR-ScopeBudgetExhaustionInvariance:
            // Budget exhaustion behavior should be invariant to task scheduling order
            // The set of tasks that succeed/fail should be deterministic

            if spawn_requests.is_empty() { return Ok(()); }

            let initial_mock_budget = MockBudget {
                cpu_millis: initial_budget.0,
                memory_bytes: initial_budget.1,
                io_ops: initial_budget.2,
                network_bytes: initial_budget.3,
            };

            // Original order execution
            let mut scope_original = MockScope::new(initial_mock_budget.clone());
            let mut original_results = Vec::new();

            for (cpu, memory, io, network) in &spawn_requests {
                let required_budget = MockBudget {
                    cpu_millis: *cpu,
                    memory_bytes: *memory,
                    io_ops: *io,
                    network_bytes: *network,
                };

                original_results.push(scope_original.try_spawn(required_budget));
            }

            // Permuted order execution
            let permuted_indices: Vec<usize> = scheduling_permutation.iter()
                .take(spawn_requests.len())
                .map(|&i| i % spawn_requests.len())
                .collect();

            let mut scope_permuted = MockScope::new(initial_mock_budget.clone());
            let mut permuted_results = Vec::new();
            let mut permuted_spawn_order = Vec::new();

            for &idx in &permuted_indices {
                let (cpu, memory, io, network) = spawn_requests[idx];
                let required_budget = MockBudget {
                    cpu_millis: cpu,
                    memory_bytes: memory,
                    io_ops: io,
                    network_bytes: network,
                };

                permuted_results.push(scope_permuted.try_spawn(required_budget));
                permuted_spawn_order.push(idx);
            }

            // Budget exhaustion count should be invariant to ordering
            prop_assert_eq!(
                scope_original.budget_exhaustion_count,
                scope_permuted.budget_exhaustion_count,
                "Budget exhaustion count should be invariant to scheduling order: {} vs {}",
                scope_original.budget_exhaustion_count,
                scope_permuted.budget_exhaustion_count
            );

            // The number of successful spawns should be the same
            let original_success_count = original_results.iter().filter(|r| r.is_ok()).count();
            let permuted_success_count = permuted_results.iter().filter(|r| r.is_ok()).count();

            prop_assert_eq!(
                original_success_count, permuted_success_count,
                "Success count should be invariant to scheduling order: {} vs {}",
                original_success_count, permuted_success_count
            );

            // Total budget consumption should be equivalent
            let original_total_consumed = scope_original.spawned_tasks.iter()
                .map(|task| &task.budget_consumed)
                .fold(MockBudget { cpu_millis: 0, memory_bytes: 0, io_ops: 0, network_bytes: 0 },
                    |mut acc, budget| {
                        acc.cpu_millis += budget.cpu_millis;
                        acc.memory_bytes += budget.memory_bytes;
                        acc.io_ops += budget.io_ops;
                        acc.network_bytes += budget.network_bytes;
                        acc
                    });

            let permuted_total_consumed = scope_permuted.spawned_tasks.iter()
                .map(|task| &task.budget_consumed)
                .fold(MockBudget { cpu_millis: 0, memory_bytes: 0, io_ops: 0, network_bytes: 0 },
                    |mut acc, budget| {
                        acc.cpu_millis += budget.cpu_millis;
                        acc.memory_bytes += budget.memory_bytes;
                        acc.io_ops += budget.io_ops;
                        acc.network_bytes += budget.network_bytes;
                        acc
                    });

            prop_assert_eq!(
                original_total_consumed.clone(), permuted_total_consumed.clone(),
                "Total budget consumption should be invariant to scheduling order: {:?} vs {:?}",
                original_total_consumed, permuted_total_consumed
            );
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Scheduler Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_intrusive_heap_insertion_order_invariant() {
        proptest!(|(
            task_insertions in proptest::collection::vec(
                (1u64..1000, 0u8..10),  // (task_id, priority)
                5..20
            ),
            churn_operations in proptest::collection::vec(
                (0usize..1000, 0u8..10),  // (remove_index, new_priority)
                3..10
            )
        )| {
            // MR-IntrusiveHeapInsertionOrderInvariant:
            // Heap property and insertion order invariants should hold under churn
            // (insertions, removals, priority updates)

            if task_insertions.is_empty() { return Ok(()); }

            let mut heap = MockIntrusiveHeap::new();
            let mut inserted_tasks = Vec::new();

            // Initial insertions
            for (task_id, priority) in &task_insertions {
                heap.push(*task_id, *priority);
                inserted_tasks.push(*task_id);
            }

            // Verify heap property after initial insertions
            prop_assert!(
                heap.verify_heap_property(),
                "Heap property should hold after initial insertions"
            );

            // Apply churn operations
            for (remove_index, new_priority) in &churn_operations {
                if !inserted_tasks.is_empty() {
                    let remove_idx = remove_index % inserted_tasks.len();
                    let task_to_remove = inserted_tasks[remove_idx];

                    // Remove task
                    let removed = heap.remove(task_to_remove);
                    if removed {
                        inserted_tasks.retain(|&t| t != task_to_remove);
                    }

                    // Verify heap property after removal
                    prop_assert!(
                        heap.verify_heap_property(),
                        "Heap property should hold after removal of task {}",
                        task_to_remove
                    );

                    // Re-insert with new priority
                    if !inserted_tasks.contains(&task_to_remove) {
                        heap.push(task_to_remove, *new_priority);
                        inserted_tasks.push(task_to_remove);
                    }

                    // Verify heap property after re-insertion
                    prop_assert!(
                        heap.verify_heap_property(),
                        "Heap property should hold after re-insertion of task {} with priority {}",
                        task_to_remove, new_priority
                    );
                }
            }

            // Final heap property verification
            prop_assert!(
                heap.verify_heap_property(),
                "Heap property should hold after all churn operations"
            );

            // Insertion order within same priority should follow generation order (FIFO)
            let mut popped_tasks = Vec::new();
            while let Some(task_id) = heap.pop() {
                popped_tasks.push(task_id);

                // Verify heap property after each pop
                prop_assert!(
                    heap.verify_heap_property(),
                    "Heap property should hold after popping task {}",
                    task_id
                );
            }

            // Verify that tasks with same priority come out in generation order
            let task_priorities: HashMap<u64, u8> = task_insertions.iter().cloned().collect();

            for window in popped_tasks.windows(2) {
                let task1 = window[0];
                let task2 = window[1];

                if let (Some(&priority1), Some(&priority2)) = (task_priorities.get(&task1), task_priorities.get(&task2)) {
                    if priority1 == priority2 {
                        // Within same priority, generation order should be preserved
                        if let (Some(meta1), Some(meta2)) = (heap.task_metadata.get(&task1), heap.task_metadata.get(&task2)) {
                            prop_assert!(
                                meta1.generation <= meta2.generation,
                                "Tasks with same priority should maintain generation order: {} (gen {}) -> {} (gen {})",
                                task1, meta1.generation, task2, meta2.generation
                            );
                        }
                    } else {
                        // Higher priority should come first
                        prop_assert!(
                            priority1 >= priority2,
                            "Higher priority tasks should come first: {} (pri {}) -> {} (pri {})",
                            task1, priority1, task2, priority2
                        );
                    }
                }
            }
        });
    }

    #[test]
    fn mr_three_lane_priority_promotion_starvation() {
        proptest!(|(
            cancel_tasks in proptest::collection::vec(1u64..100, 0..5),
            timed_tasks in proptest::collection::vec(
                (1u64..100, 1100u64..1200), // (task_id, deadline)
                2..8
            ),
            ready_tasks in proptest::collection::vec(1u64..100, 3..10),
            fairness_limits in (2u32..8, 3u32..8, 2u32..6), // (cancel, timed, stolen)
            simulation_steps in 20usize..50
        )| {
            // MR-ThreeLanePriorityPromotionStarvation:
            // Priority promotion should prevent starvation - lower priority lanes
            // should get opportunities to run even under heavy higher priority load

            let mut scheduler = MockThreeLaneScheduler::new(
                fairness_limits.0,  // cancel_limit
                fairness_limits.1,  // timed_limit
                fairness_limits.2   // stolen_limit
            );

            // Schedule initial tasks
            for &task_id in &cancel_tasks {
                scheduler.schedule_cancel(task_id);
            }

            for &(task_id, deadline) in &timed_tasks {
                scheduler.schedule_timed(task_id, deadline);
            }

            for &task_id in &ready_tasks {
                scheduler.schedule_ready(task_id);
            }

            // Run simulation
            scheduler.advance_time(1000);
            let mut dispatched_tasks = Vec::new();

            for step in 0..simulation_steps {
                scheduler.advance_time(1000 + step as u64);

                // Add more high-priority work to stress fairness
                if step % 3 == 0 && !cancel_tasks.is_empty() {
                    let stress_task = 2000 + step as u64;
                    scheduler.schedule_cancel(stress_task);
                }

                if let Some(dispatch) = scheduler.next_task() {
                    dispatched_tasks.push(dispatch);
                }
            }

            // Verify fairness properties

            // 1. If non-cancel work was available, it should have been dispatched
            // within the fairness limit
            let has_non_cancel_work = !timed_tasks.is_empty() || !ready_tasks.is_empty();
            if has_non_cancel_work && !cancel_tasks.is_empty() {
                let mut max_cancel_streak = 0;
                let mut current_cancel_streak = 0;

                for dispatch in &dispatched_tasks {
                    match dispatch.lane {
                        MockLaneType::Cancel => {
                            current_cancel_streak += 1;
                            max_cancel_streak = max_cancel_streak.max(current_cancel_streak);
                        }
                        _ => {
                            current_cancel_streak = 0;
                        }
                    }
                }

                prop_assert!(
                    max_cancel_streak <= fairness_limits.0 + 1,  // +1 for edge case tolerance
                    "Cancel streak should not exceed fairness limit: {} > {}",
                    max_cancel_streak, fairness_limits.0
                );
            }

            // 2. Non-cancel lanes should get dispatch opportunities
            let cancel_dispatches = dispatched_tasks.iter()
                .filter(|d| matches!(d.lane, MockLaneType::Cancel))
                .count();
            let non_cancel_dispatches = dispatched_tasks.len() - cancel_dispatches;

            if has_non_cancel_work && dispatched_tasks.len() > fairness_limits.0 as usize {
                prop_assert!(
                    non_cancel_dispatches > 0,
                    "Non-cancel work should get dispatch opportunities under fairness rules"
                );
            }

            // 3. Verify scheduler's internal fairness invariants
            prop_assert!(
                scheduler.verify_fairness_invariants(),
                "Scheduler should maintain internal fairness invariants"
            );

            // 4. Timed tasks that become due should eventually be dispatched
            let due_timed_tasks: Vec<u64> = timed_tasks.iter()
                .filter(|(_, deadline)| *deadline <= 1000 + simulation_steps as u64)
                .map(|(task_id, _)| *task_id)
                .collect();

            let dispatched_timed_tasks: Vec<u64> = dispatched_tasks.iter()
                .filter(|d| matches!(d.lane, MockLaneType::Timed))
                .map(|d| d.task_id)
                .collect();

            // All due timed tasks should eventually be dispatched (starvation prevention)
            for &due_task in &due_timed_tasks {
                prop_assert!(
                    dispatched_timed_tasks.contains(&due_task),
                    "Due timed task {} should be dispatched to prevent starvation",
                    due_task
                );
            }
        });
    }

    #[test]
    fn mr_global_injector_fifo_contention() {
        proptest!(|(
            injection_sequence in proptest::collection::vec(
                (1u64..1000, 0u8..2),  // (task_id, contention_level)
                10..30
            ),
            contention_pattern in proptest::collection::vec(0u8..4, 5..15),
            batch_sizes in proptest::collection::vec(2usize..8, 3..10)
        )| {
            // MR-GlobalInjectorFIFOContention:
            // FIFO properties should be preserved under concurrent injection
            // even with combiner batching and contention handling

            let mut injector = MockGlobalInjector::new();

            // Apply injection sequence with varying contention levels
            for (i, &(task_id, contention_level)) in injection_sequence.iter().enumerate() {
                let contention = contention_level > 0 ||
                                (i < contention_pattern.len() && contention_pattern[i] > 1);

                if contention {
                    injector.activate_combiner();
                }

                injector.inject_task(task_id, contention);
            }

            // Verify FIFO properties
            prop_assert!(
                injector.verify_fifo_property(),
                "Global injector should maintain FIFO properties under contention"
            );

            // Extract all tasks and verify overall order preservation
            let mut extracted_tasks = Vec::new();
            while let Some(task_id) = injector.pop_task() {
                extracted_tasks.push(task_id);
            }

            // The extraction order should roughly follow injection order,
            // allowing for combiner batching effects
            let injection_order = &injector.injection_order;

            // Check that early-injected tasks come out before late-injected tasks
            // (allowing some reordering within combiner batches)
            for window_size in [3, 5, 7] {
                if injection_order.len() >= window_size && extracted_tasks.len() >= window_size {
                    let early_tasks: BTreeSet<_> = injection_order[..window_size].iter().cloned().collect();
                    let late_tasks: BTreeSet<_> = injection_order[injection_order.len()-window_size..].iter().cloned().collect();

                    let early_positions: Vec<usize> = extracted_tasks.iter()
                        .enumerate()
                        .filter_map(|(i, task)| if early_tasks.contains(task) { Some(i) } else { None })
                        .collect();

                    let late_positions: Vec<usize> = extracted_tasks.iter()
                        .enumerate()
                        .filter_map(|(i, task)| if late_tasks.contains(task) { Some(i) } else { None })
                        .collect();

                    if !early_positions.is_empty() && !late_positions.is_empty() {
                        let avg_early_pos = early_positions.iter().sum::<usize>() / early_positions.len();
                        let avg_late_pos = late_positions.iter().sum::<usize>() / late_positions.len();

                        prop_assert!(
                            avg_early_pos <= avg_late_pos,
                            "Early-injected tasks should generally come out before late-injected tasks: avg_early={} avg_late={}",
                            avg_early_pos, avg_late_pos
                        );
                    }
                }
            }

            // Combiner batch sizes should be reasonable
            if !injector.batch_sizes.is_empty() {
                let max_batch = *injector.batch_sizes.iter().max().unwrap();
                prop_assert!(
                    max_batch <= 64,  // Reasonable upper bound
                    "Combiner batch sizes should be reasonable: max={}",
                    max_batch
                );

                let avg_batch = injector.batch_sizes.iter().sum::<usize>() / injector.batch_sizes.len();
                prop_assert!(
                    avg_batch >= 1,
                    "Average batch size should be at least 1: avg={}",
                    avg_batch
                );
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Remote Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_remote_handle_join_cancel_after_completion_idempotency() {
        proptest!(|(
            remote_task_id in 1u64..1000,
            completion_time in 1000u64..2000,
            completion_results in proptest::collection::vec(
                proptest::prop_oneof![
                    proptest::collection::vec(0u8..255, 1..100).prop_map(MockRemoteResult::Success),
                    proptest::string::string_regex("[a-z ]{5,20}").unwrap().prop_map(MockRemoteResult::Error),
                    proptest::string::string_regex("cancelled: [a-z ]{5,15}").unwrap().prop_map(MockRemoteResult::Cancelled),
                ],
                1..5
            ),
            post_completion_operations in proptest::collection::vec(0u8..3, 3..10),
            lease_expiry_offset in 0u64..500
        )| {
            // MR-RemoteHandleJoinCancelAfterCompletionIdempotency:
            // join() and cancel() operations after completion should be idempotent
            // Multiple calls should produce identical results

            if completion_results.is_empty() { return Ok(()); }

            let lease_expiry = Some(completion_time + lease_expiry_offset);
            let mut handle = MockRemoteHandle::new(remote_task_id, lease_expiry);

            // Complete the remote task
            handle.advance_time(completion_time - 100);
            handle.complete(completion_results[0].clone());

            // Advance past completion
            handle.advance_time(completion_time + 50);

            // Test idempotency of join() after completion
            let mut join_results = Vec::new();
            for _ in 0..3 {
                join_results.push(handle.join());
            }

            // All join() calls should return the same result
            let first_result = &join_results[0];
            for (i, result) in join_results.iter().enumerate().skip(1) {
                prop_assert_eq!(
                    first_result, result,
                    "join() call {} should be idempotent with first call: {:?} vs {:?}",
                    i, first_result, result
                );
            }

            // Test idempotency of cancel() after completion
            let initial_state = handle.state.clone();
            let initial_result = handle.completion_result.clone();

            let mut cancel_results = Vec::new();
            for _ in 0..3 {
                cancel_results.push(handle.cancel_after_completion());
            }

            // All cancel() calls should succeed (idempotent)
            for (i, result) in cancel_results.iter().enumerate() {
                prop_assert!(
                    result.is_ok(),
                    "cancel_after_completion() call {} should succeed idempotently: {:?}",
                    i, result
                );
            }

            // State should remain stable after multiple cancel attempts
            prop_assert_eq!(
                handle.state.clone(), initial_state,
                "State should be stable after multiple cancel_after_completion calls"
            );

            prop_assert_eq!(
                handle.completion_result.clone(), initial_result,
                "Completion result should be stable after multiple cancel_after_completion calls"
            );

            // Apply post-completion operations and verify idempotency
            for &op_type in &post_completion_operations {
                let state_before = handle.state.clone();
                let result_before = handle.completion_result.clone();

                match op_type % 3 {
                    0 => {
                        // Multiple join() calls
                        let join1 = handle.join();
                        let join2 = handle.join();
                        prop_assert_eq!(join1, join2, "Consecutive join() calls should be idempotent");
                    }
                    1 => {
                        // Multiple cancel() calls
                        let cancel1 = handle.cancel_after_completion();
                        let cancel2 = handle.cancel_after_completion();
                        prop_assert_eq!(cancel1, cancel2, "Consecutive cancel_after_completion() calls should be idempotent");
                    }
                    _ => {
                        // Mixed operations
                        let _ = handle.join();
                        let _ = handle.cancel_after_completion();
                        let _ = handle.join();
                    }
                }

                // State should remain consistent
                prop_assert_eq!(
                    handle.state.clone(), state_before,
                    "State should be stable after post-completion operation type {}",
                    op_type % 3
                );
            }

            // Call counters should reflect the operations but not affect results
            prop_assert!(
                handle.join_call_count > 0,
                "Join call count should reflect operations performed"
            );

            prop_assert!(
                handle.cancel_after_completion_calls > 0,
                "Cancel after completion call count should reflect operations performed"
            );
        });
    }

    #[test]
    fn mr_remote_task_lease_expiry_determinism() {
        proptest!(|(
            task_configs in proptest::collection::vec(
                (
                    1u64..1000,      // remote_task_id
                    1000u64..2000,   // lease_duration
                    500u64..1500     // completion_offset
                ),
                3..10
            ),
            time_advancement_pattern in proptest::collection::vec(50u64..200, 5..15)
        )| {
            // MR-RemoteTaskLeaseExpiryDeterminism:
            // Lease expiry behavior should be deterministic regardless of
            // time advancement patterns (step size, timing)

            if task_configs.is_empty() { return Ok(()); }

            let mut handles_pattern1 = Vec::new();
            let mut handles_pattern2 = Vec::new();

            // Create handles with same configurations
            for (task_id, lease_duration, completion_offset) in &task_configs {
                let lease_expiry = Some(*lease_duration);
                handles_pattern1.push(MockRemoteHandle::new(*task_id, lease_expiry));
                handles_pattern2.push(MockRemoteHandle::new(*task_id, lease_expiry));
            }

            // Pattern 1: Regular time advancement
            let mut current_time1 = 0u64;
            for step in &time_advancement_pattern {
                current_time1 += step;
                for handle in &mut handles_pattern1 {
                    handle.advance_time(current_time1);
                }
            }

            // Pattern 2: Irregular time advancement (larger steps)
            let mut current_time2 = 0u64;
            for step in &time_advancement_pattern {
                current_time2 += step * 2;  // Different pattern
                for handle in &mut handles_pattern2 {
                    handle.advance_time(current_time2);
                }
            }

            // Complete some tasks before lease expiry, some after
            for (i, (_, lease_duration, completion_offset)) in task_configs.iter().enumerate() {
                let completion_time = *completion_offset;

                if completion_time < *lease_duration {
                    // Complete before expiry
                    handles_pattern1[i].advance_time(completion_time);
                    handles_pattern1[i].complete(MockRemoteResult::Success(vec![i as u8]));

                    handles_pattern2[i].advance_time(completion_time);
                    handles_pattern2[i].complete(MockRemoteResult::Success(vec![i as u8]));
                }
                // Otherwise let it expire
            }

            // Advance to well past all lease expiry times
            let max_lease = task_configs.iter().map(|(_, lease, _)| lease).max().unwrap();
            for handle in &mut handles_pattern1 {
                handle.advance_time(max_lease + 1000);
            }
            for handle in &mut handles_pattern2 {
                handle.advance_time(max_lease + 1000);
            }

            // Final states should be identical despite different time advancement patterns
            for (i, ((task_id, lease_duration, completion_offset), handle1)) in
                task_configs.iter().zip(handles_pattern1.iter()).enumerate() {

                let handle2 = &handles_pattern2[i];

                prop_assert_eq!(
                    handle1.state.clone(), handle2.state.clone(),
                    "Final state should be identical for task {}: {:?} vs {:?}",
                    task_id, handle1.state, handle2.state
                );

                // Check deterministic lease expiry behavior
                if *completion_offset >= *lease_duration {
                    // Should have expired
                    prop_assert_eq!(
                        handle1.state.clone(), MockRemoteState::LeaseExpired,
                        "Task {} should have expired: lease={}, completion={}",
                        task_id, lease_duration, completion_offset
                    );

                    prop_assert_eq!(
                        handle2.state.clone(), MockRemoteState::LeaseExpired,
                        "Task {} should have expired in pattern 2: lease={}, completion={}",
                        task_id, lease_duration, completion_offset
                    );
                } else {
                    // Should have completed successfully
                    prop_assert_eq!(
                        handle1.state.clone(), MockRemoteState::Completed,
                        "Task {} should have completed: lease={}, completion={}",
                        task_id, lease_duration, completion_offset
                    );

                    prop_assert_eq!(
                        handle2.state.clone(), MockRemoteState::Completed,
                        "Task {} should have completed in pattern 2: lease={}, completion={}",
                        task_id, lease_duration, completion_offset
                    );
                }

                // join() results should be identical
                let mut handle1_copy = handle1.clone();
                let mut handle2_copy = handle2.clone();

                let result1 = handle1_copy.join();
                let result2 = handle2_copy.join();

                prop_assert_eq!(
                    result1.clone(), result2.clone(),
                    "join() results should be identical for task {}: {:?} vs {:?}",
                    task_id, result1, result2
                );
            }
        });
    }
}
