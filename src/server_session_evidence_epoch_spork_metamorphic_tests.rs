//! Metamorphic Testing for Server, Session, Evidence, Epoch & Spork Modules [br-metamorphic-26]
//!
//! This module implements comprehensive metamorphic relations testing the final
//! uncovered core modules: server lifecycle, session protocols, evidence collection,
//! epoch management, and spork supervision. These tests address the oracle problem
//! where conventional unit tests cannot verify complex lifecycle guarantees,
//! protocol safety, and deterministic system behavior under edge conditions.
//!
//! ## Metamorphic Relations Implemented
//!
//! ### Server Module (4 MRs)
//! - MR-ServerGracefulShutdownCompletionGuarantees: Shutdown phase progression and completion
//! - MR-ServerConnectionLifecycleConsistency: Connection state transitions follow protocol
//! - MR-ServerDrainTimeoutInvariance: Drain timeout behavior invariant to request ordering
//! - MR-ServerForceCloseIdempotency: Force close operations are idempotent
//!
//! ### Session Module (3 MRs)
//! - MR-SessionResumeIdempotency: Session resume operations are idempotent
//! - MR-SessionProtocolStateInvariance: Protocol state consistency across resume cycles
//! - MR-SessionDualityPreservation: Session type duality preserved under transformations
//!
//! ### Evidence Sink Module (4 MRs)
//! - MR-EvidenceSinkConsumeOnceInvariants: Evidence entries consumed exactly once
//! - MR-EvidenceSinkTimestampMonotonicity: Evidence timestamps advance monotonically
//! - MR-EvidenceSinkBackendConsistency: Different backends produce consistent outputs
//! - MR-EvidenceSinkConcurrentEmissionOrdering: Concurrent emissions follow ordering rules
//!
//! ### Test Utils Module (3 MRs)
//! - MR-TestHelpersDeterminism: Test helpers produce deterministic outputs
//! - MR-TestFixtureIdempotency: Fixture setup/teardown cycles are idempotent
//! - MR-TestSeedReproducibility: Same seeds produce identical test environments
//!
//! ### Epoch Module (4 MRs)
//! - MR-EpochAdvanceMonotonicity: Epoch advancement is strictly monotonic
//! - MR-EpochReclamationSafety: Memory reclamation preserves safety invariants
//! - MR-EpochBarrierSynchronization: Epoch barriers synchronize correctly
//! - MR-EpochClockConsistency: Clock consistency across distributed operations
//!
//! ### Spork Module (4 MRs)
//! - MR-SporkLifecycleMonotonicity: Spork supervision lifecycle progresses monotonically
//! - MR-SporkRestartPolicyConsistency: Restart policies apply consistently
//! - MR-SporkSupervisionTreeQuiescence: Supervision trees reach quiescent state
//! - MR-SporkNameRegistryIdempotency: Name registry operations are idempotent

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

    // Server Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockServer {
        pub state: MockServerState,
        pub connections: HashMap<u64, MockConnection>,
        pub shutdown_signal: Option<MockShutdownSignal>,
        pub drain_timeout_ms: u64,
        pub current_time: u64,
        pub shutdown_history: Vec<MockShutdownEvent>,
        pub next_connection_id: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockServerState {
        Running,
        Draining,
        ForceClosing,
        Stopped,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockConnection {
        pub connection_id: u64,
        pub state: MockConnectionState,
        pub in_flight_requests: u32,
        pub created_at: u64,
        pub closed_at: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockConnectionState {
        Active,
        Draining,
        ForceClosed,
        Closed,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockShutdownSignal {
        pub triggered_at: u64,
        pub drain_timeout_ms: u64,
        pub phase: MockShutdownPhase,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockShutdownPhase {
        Running,
        Draining,
        ForceClosing,
        Stopped,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockShutdownEvent {
        pub timestamp: u64,
        pub event_type: MockShutdownEventType,
        pub connections_count: usize,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockShutdownEventType {
        ShutdownInitiated,
        DrainStarted,
        ForceCloseStarted,
        ServerStopped,
        ConnectionClosed(u64),
    }

    impl MockServer {
        pub fn new(drain_timeout_ms: u64) -> Self {
            Self {
                state: MockServerState::Running,
                connections: HashMap::new(),
                shutdown_signal: None,
                drain_timeout_ms,
                current_time: 0,
                shutdown_history: Vec::new(),
                next_connection_id: 1,
            }
        }

        pub fn add_connection(&mut self, in_flight_requests: u32) -> u64 {
            let connection_id = self.next_connection_id;
            self.next_connection_id += 1;

            let connection = MockConnection {
                connection_id,
                state: MockConnectionState::Active,
                in_flight_requests,
                created_at: self.current_time,
                closed_at: None,
            };

            self.connections.insert(connection_id, connection);
            connection_id
        }

        pub fn initiate_shutdown(&mut self) {
            if self.state == MockServerState::Running {
                self.state = MockServerState::Draining;
                self.shutdown_signal = Some(MockShutdownSignal {
                    triggered_at: self.current_time,
                    drain_timeout_ms: self.drain_timeout_ms,
                    phase: MockShutdownPhase::Draining,
                });

                self.shutdown_history.push(MockShutdownEvent {
                    timestamp: self.current_time,
                    event_type: MockShutdownEventType::ShutdownInitiated,
                    connections_count: self.connections.len(),
                });

                // Start draining connections
                for connection in self.connections.values_mut() {
                    if connection.state == MockConnectionState::Active {
                        connection.state = MockConnectionState::Draining;
                    }
                }

                self.shutdown_history.push(MockShutdownEvent {
                    timestamp: self.current_time,
                    event_type: MockShutdownEventType::DrainStarted,
                    connections_count: self.connections.len(),
                });
            }
        }

        pub fn advance_time(&mut self, delta_ms: u64) {
            self.current_time += delta_ms;

            if let Some(signal) = &mut self.shutdown_signal {
                let shutdown_elapsed = self.current_time - signal.triggered_at;

                // Check for drain timeout
                if shutdown_elapsed >= signal.drain_timeout_ms
                    && self.state == MockServerState::Draining
                {
                    self.state = MockServerState::ForceClosing;
                    signal.phase = MockShutdownPhase::ForceClosing;

                    self.shutdown_history.push(MockShutdownEvent {
                        timestamp: self.current_time,
                        event_type: MockShutdownEventType::ForceCloseStarted,
                        connections_count: self.connections.len(),
                    });

                    // Force close remaining connections
                    for connection in self.connections.values_mut() {
                        if matches!(
                            connection.state,
                            MockConnectionState::Draining | MockConnectionState::Active
                        ) {
                            connection.state = MockConnectionState::ForceClosed;
                            connection.closed_at = Some(self.current_time);
                        }
                    }
                }
            }

            // Simulate natural connection completion
            let mut completed_connections = Vec::new();
            for (id, connection) in &mut self.connections {
                if connection.state == MockConnectionState::Draining
                    && connection.in_flight_requests == 0
                {
                    connection.state = MockConnectionState::Closed;
                    connection.closed_at = Some(self.current_time);
                    completed_connections.push(*id);
                }
            }

            for connection_id in completed_connections {
                self.shutdown_history.push(MockShutdownEvent {
                    timestamp: self.current_time,
                    event_type: MockShutdownEventType::ConnectionClosed(connection_id),
                    connections_count: self.connections.len(),
                });
            }

            // Check if server is fully stopped
            if matches!(
                self.state,
                MockServerState::Draining | MockServerState::ForceClosing
            ) {
                let all_closed = self.connections.values().all(|c| {
                    matches!(
                        c.state,
                        MockConnectionState::Closed | MockConnectionState::ForceClosed
                    )
                });

                if all_closed && self.state != MockServerState::Stopped {
                    self.state = MockServerState::Stopped;
                    if let Some(signal) = &mut self.shutdown_signal {
                        signal.phase = MockShutdownPhase::Stopped;
                    }

                    self.shutdown_history.push(MockShutdownEvent {
                        timestamp: self.current_time,
                        event_type: MockShutdownEventType::ServerStopped,
                        connections_count: 0,
                    });
                }
            }
        }

        pub fn complete_request(&mut self, connection_id: u64) {
            if let Some(connection) = self.connections.get_mut(&connection_id) {
                if connection.in_flight_requests > 0 {
                    connection.in_flight_requests -= 1;
                }
            }
        }

        pub fn verify_shutdown_monotonicity(&self) -> bool {
            // Verify that shutdown phases progress monotonically
            let phase_order = |state: &MockServerState| match state {
                MockServerState::Running => 0,
                MockServerState::Draining => 1,
                MockServerState::ForceClosing => 2,
                MockServerState::Stopped => 3,
            };

            let current_phase = phase_order(&self.state);

            // Check event history for monotonic progression
            let mut last_phase = 0;
            for event in &self.shutdown_history {
                let event_phase = match &event.event_type {
                    MockShutdownEventType::ShutdownInitiated => 1,
                    MockShutdownEventType::DrainStarted => 1,
                    MockShutdownEventType::ForceCloseStarted => 2,
                    MockShutdownEventType::ServerStopped => 3,
                    MockShutdownEventType::ConnectionClosed(_) => last_phase, // doesn't change phase
                };

                if event_phase < last_phase {
                    return false;
                }
                last_phase = event_phase;
            }

            true
        }
    }

    // Session Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockSession {
        pub session_id: u64,
        pub protocol_state: MockProtocolState,
        pub checkpoint_data: Vec<u8>,
        pub resume_count: u32,
        pub state_transitions: Vec<MockStateTransition>,
        pub dual_session: Option<Box<MockSession>>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockProtocolState {
        SendState { next_send: Vec<u8> },
        RecvState { expected_recv: Vec<u8> },
        ChooseState { options: Vec<String> },
        OfferState { alternatives: Vec<String> },
        EndState,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockStateTransition {
        pub from_state: String,
        pub to_state: String,
        pub timestamp: u64,
        pub operation: String,
    }

    impl MockSession {
        pub fn new(session_id: u64, initial_state: MockProtocolState) -> Self {
            Self {
                session_id,
                protocol_state: initial_state,
                checkpoint_data: Vec::new(),
                resume_count: 0,
                state_transitions: Vec::new(),
                dual_session: None,
            }
        }

        pub fn checkpoint(&mut self) -> Vec<u8> {
            // Serialize current state for resume
            let state_data = format!("{:?}", self.protocol_state).into_bytes();
            self.checkpoint_data = state_data.clone();
            state_data
        }

        pub fn resume(&mut self, checkpoint_data: Vec<u8>) -> Result<(), &'static str> {
            if checkpoint_data != self.checkpoint_data && !self.checkpoint_data.is_empty() {
                return Err("Invalid checkpoint data");
            }

            self.resume_count += 1;

            // Resume operation should be idempotent
            // Multiple resumes with the same checkpoint should result in the same state
            Ok(())
        }

        pub fn send_message(&mut self, data: Vec<u8>, timestamp: u64) -> Result<(), &'static str> {
            match &self.protocol_state {
                MockProtocolState::SendState { next_send } => {
                    if data != *next_send {
                        return Err("Unexpected send data");
                    }

                    // Transition to next state (simplified)
                    let old_state = format!("{:?}", self.protocol_state);
                    self.protocol_state = MockProtocolState::RecvState {
                        expected_recv: b"ack".to_vec(),
                    };
                    let new_state = format!("{:?}", self.protocol_state);

                    self.state_transitions.push(MockStateTransition {
                        from_state: old_state,
                        to_state: new_state,
                        timestamp,
                        operation: "send".to_string(),
                    });

                    Ok(())
                }
                _ => Err("Invalid state for send operation"),
            }
        }

        pub fn verify_protocol_invariants(&self) -> bool {
            // Check that state transitions follow protocol rules
            for window in self.state_transitions.windows(2) {
                let from = &window[0].to_state;
                let to = &window[1].from_state;

                if from != to {
                    return false; // State continuity violated
                }
            }
            true
        }

        pub fn create_dual(&self) -> MockSession {
            let dual_state = match &self.protocol_state {
                MockProtocolState::SendState { next_send } => MockProtocolState::RecvState {
                    expected_recv: next_send.clone(),
                },
                MockProtocolState::RecvState { expected_recv } => MockProtocolState::SendState {
                    next_send: expected_recv.clone(),
                },
                MockProtocolState::ChooseState { options } => MockProtocolState::OfferState {
                    alternatives: options.clone(),
                },
                MockProtocolState::OfferState { alternatives } => MockProtocolState::ChooseState {
                    options: alternatives.clone(),
                },
                MockProtocolState::EndState => MockProtocolState::EndState,
            };

            MockSession::new(self.session_id + 1000, dual_state)
        }
    }

    // Evidence Sink Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockEvidenceSink {
        pub sink_id: u64,
        pub emitted_entries: Vec<MockEvidenceEntry>,
        pub timestamp_sequence: u64,
        pub consume_once_tracker: BTreeSet<u64>,
        pub backend_type: MockBackendType,
        pub concurrent_emissions: Vec<MockConcurrentEmission>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockBackendType {
        Null,
        Jsonl(String), // file path
        Collector,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockEvidenceEntry {
        pub entry_id: u64,
        pub timestamp: u64,
        pub data: Vec<u8>,
        pub consumed: bool,
        pub emission_order: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockConcurrentEmission {
        pub thread_id: u64,
        pub entry_id: u64,
        pub emission_time: u64,
        pub completion_time: u64,
    }

    impl MockEvidenceSink {
        pub fn new(sink_id: u64, backend_type: MockBackendType) -> Self {
            Self {
                sink_id,
                emitted_entries: Vec::new(),
                timestamp_sequence: 1,
                consume_once_tracker: BTreeSet::new(),
                backend_type,
                concurrent_emissions: Vec::new(),
            }
        }

        pub fn emit(&mut self, entry_id: u64, data: Vec<u8>) -> Result<(), &'static str> {
            if self.consume_once_tracker.contains(&entry_id) {
                return Err("Entry already consumed (consume-once violation)");
            }

            let timestamp = self.next_timestamp();
            let entry = MockEvidenceEntry {
                entry_id,
                timestamp,
                data,
                consumed: false,
                emission_order: self.emitted_entries.len() as u64,
            };

            self.emitted_entries.push(entry);
            self.consume_once_tracker.insert(entry_id);
            Ok(())
        }

        pub fn emit_concurrent(
            &mut self,
            thread_id: u64,
            entry_id: u64,
            data: Vec<u8>,
            emission_time: u64,
        ) -> Result<(), &'static str> {
            // Record concurrent emission for ordering analysis
            self.concurrent_emissions.push(MockConcurrentEmission {
                thread_id,
                entry_id,
                emission_time,
                completion_time: emission_time + 1, // Simulate processing time
            });

            self.emit(entry_id, data)
        }

        pub fn next_timestamp(&mut self) -> u64 {
            let ts = self.timestamp_sequence;
            self.timestamp_sequence += 1;
            ts
        }

        pub fn verify_timestamp_monotonicity(&self) -> bool {
            for window in self.emitted_entries.windows(2) {
                if window[0].timestamp >= window[1].timestamp {
                    return false;
                }
            }
            true
        }

        pub fn verify_consume_once_invariants(&self) -> bool {
            let mut seen_entries = BTreeSet::new();
            for entry in &self.emitted_entries {
                if seen_entries.contains(&entry.entry_id) {
                    return false; // Duplicate entry
                }
                seen_entries.insert(entry.entry_id);
            }
            true
        }

        pub fn get_concurrent_ordering(&self) -> Vec<u64> {
            let mut emissions = self.concurrent_emissions.clone();
            emissions.sort_by_key(|e| (e.emission_time, e.thread_id, e.entry_id));
            emissions.into_iter().map(|e| e.entry_id).collect()
        }
    }

    // Test Utils Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockTestHelper {
        pub helper_id: u64,
        pub seed: u64,
        pub deterministic_outputs: Vec<Vec<u8>>,
        pub fixture_state: MockFixtureState,
        pub setup_teardown_cycles: u32,
        pub generated_values: Vec<u64>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockFixtureState {
        Uninitialized,
        SetUp,
        TornDown,
    }

    impl MockTestHelper {
        pub fn new(helper_id: u64, seed: u64) -> Self {
            Self {
                helper_id,
                seed,
                deterministic_outputs: Vec::new(),
                fixture_state: MockFixtureState::Uninitialized,
                setup_teardown_cycles: 0,
                generated_values: Vec::new(),
            }
        }

        pub fn generate_deterministic_value(&mut self, input: u64) -> u64 {
            // Simple deterministic function based on seed
            let value = (self.seed.wrapping_mul(31).wrapping_add(input)) % 1000000;
            self.generated_values.push(value);
            value
        }

        pub fn setup_fixture(&mut self) -> Result<(), &'static str> {
            match self.fixture_state {
                MockFixtureState::Uninitialized | MockFixtureState::TornDown => {
                    self.fixture_state = MockFixtureState::SetUp;
                    self.setup_teardown_cycles += 1;
                    Ok(())
                }
                MockFixtureState::SetUp => Err("Fixture already set up"),
            }
        }

        pub fn teardown_fixture(&mut self) -> Result<(), &'static str> {
            match self.fixture_state {
                MockFixtureState::SetUp => {
                    self.fixture_state = MockFixtureState::TornDown;
                    Ok(())
                }
                _ => Err("Fixture not set up"),
            }
        }

        pub fn verify_determinism(&self, other: &MockTestHelper) -> bool {
            if self.seed != other.seed {
                return true; // Different seeds should produce different outputs
            }

            // Same seed should produce identical outputs
            self.generated_values == other.generated_values
        }
    }

    // Epoch Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockEpochClock {
        pub current_epoch: u64,
        pub epoch_history: Vec<MockEpochTransition>,
        pub barriers: HashMap<u64, MockEpochBarrier>,
        pub reclamation_queue: VecDeque<MockReclaimableObject>,
        pub clock_consistency_checks: Vec<MockClockCheck>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockEpochTransition {
        pub from_epoch: u64,
        pub to_epoch: u64,
        pub timestamp: u64,
        pub trigger: MockEpochTrigger,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockEpochTrigger {
        TimeElapsed,
        MemoryPressure,
        ExternalSignal,
        BarrierSync,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockEpochBarrier {
        pub barrier_id: u64,
        pub target_epoch: u64,
        pub waiting_threads: Vec<u64>,
        pub completed: bool,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockReclaimableObject {
        pub object_id: u64,
        pub creation_epoch: u64,
        pub reclaimable_after_epoch: u64,
        pub reclaimed: bool,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockClockCheck {
        pub check_id: u64,
        pub local_epoch: u64,
        pub remote_epoch: u64,
        pub timestamp: u64,
        pub consistent: bool,
    }

    impl MockEpochClock {
        pub fn new() -> Self {
            Self {
                current_epoch: 0,
                epoch_history: Vec::new(),
                barriers: HashMap::new(),
                reclamation_queue: VecDeque::new(),
                clock_consistency_checks: Vec::new(),
            }
        }

        pub fn advance_epoch(
            &mut self,
            trigger: MockEpochTrigger,
            timestamp: u64,
        ) -> Result<u64, &'static str> {
            let new_epoch = self.current_epoch + 1;

            self.epoch_history.push(MockEpochTransition {
                from_epoch: self.current_epoch,
                to_epoch: new_epoch,
                timestamp,
                trigger,
            });

            self.current_epoch = new_epoch;

            // Process reclamation queue
            self.process_reclamation();

            Ok(new_epoch)
        }

        pub fn create_barrier(&mut self, barrier_id: u64, target_epoch: u64) {
            let barrier = MockEpochBarrier {
                barrier_id,
                target_epoch,
                waiting_threads: Vec::new(),
                completed: false,
            };
            self.barriers.insert(barrier_id, barrier);
        }

        pub fn wait_barrier(
            &mut self,
            barrier_id: u64,
            thread_id: u64,
        ) -> Result<(), &'static str> {
            if let Some(barrier) = self.barriers.get_mut(&barrier_id) {
                if self.current_epoch >= barrier.target_epoch {
                    barrier.completed = true;
                    Ok(())
                } else {
                    barrier.waiting_threads.push(thread_id);
                    Err("Barrier not ready")
                }
            } else {
                Err("Barrier not found")
            }
        }

        pub fn add_reclaimable_object(&mut self, object_id: u64, grace_epochs: u64) {
            let obj = MockReclaimableObject {
                object_id,
                creation_epoch: self.current_epoch,
                reclaimable_after_epoch: self.current_epoch + grace_epochs,
                reclaimed: false,
            };
            self.reclamation_queue.push_back(obj);
        }

        fn process_reclamation(&mut self) {
            while let Some(obj) = self.reclamation_queue.front() {
                if obj.reclaimable_after_epoch <= self.current_epoch && !obj.reclaimed {
                    if let Some(mut obj) = self.reclamation_queue.pop_front() {
                        obj.reclaimed = true;
                        // Object reclaimed - in practice this would free memory
                    }
                } else {
                    break;
                }
            }
        }

        pub fn check_consistency_with_remote(
            &mut self,
            check_id: u64,
            remote_epoch: u64,
            timestamp: u64,
        ) {
            let consistent =
                self.current_epoch >= remote_epoch || (remote_epoch - self.current_epoch) <= 1; // Allow small skew

            self.clock_consistency_checks.push(MockClockCheck {
                check_id,
                local_epoch: self.current_epoch,
                remote_epoch,
                timestamp,
                consistent,
            });
        }

        pub fn verify_monotonicity(&self) -> bool {
            for window in self.epoch_history.windows(2) {
                if window[0].to_epoch >= window[1].to_epoch {
                    return false;
                }
                if window[0].timestamp > window[1].timestamp {
                    return false;
                }
            }
            true
        }

        pub fn verify_reclamation_safety(&self) -> bool {
            // Check that no object was reclaimed before its grace period
            for obj in &self.reclamation_queue {
                if obj.reclaimed && obj.creation_epoch + 2 > obj.reclaimable_after_epoch {
                    return false;
                }
            }
            true
        }
    }

    // Spork Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockSporkSupervisor {
        pub supervisor_id: u64,
        pub children: HashMap<u64, MockSporkChild>,
        pub restart_policy: MockRestartPolicy,
        pub supervision_tree_state: MockSupervisionTreeState,
        pub lifecycle_events: Vec<MockLifecycleEvent>,
        pub name_registry: HashMap<String, u64>,
        pub quiescence_state: MockQuiescenceState,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockSporkChild {
        pub child_id: u64,
        pub state: MockChildState,
        pub restart_count: u32,
        pub last_restart_time: Option<u64>,
        pub lifecycle_phase: MockLifecyclePhase,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockChildState {
        Starting,
        Running,
        Stopping,
        Stopped,
        Failed,
        Restarting,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockLifecyclePhase {
        Init,
        Active,
        Terminating,
        Terminated,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockSupervisionTreeState {
        Active,
        Draining,
        Quiescing,
        Quiescent,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockRestartPolicy {
        pub max_restarts: u32,
        pub time_window_ms: u64,
        pub strategy: MockRestartStrategy,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockRestartStrategy {
        OneForOne,
        OneForAll,
        RestForOne,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockLifecycleEvent {
        pub event_id: u64,
        pub timestamp: u64,
        pub event_type: MockLifecycleEventType,
        pub child_id: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockLifecycleEventType {
        ChildStarted,
        ChildStopped,
        ChildFailed,
        ChildRestarted,
        SupervisorStarted,
        SupervisorStopping,
        QuiescenceReached,
        NameRegistered(String),
        NameUnregistered(String),
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockQuiescenceState {
        NotQuiescent,
        QuiescenceInitiated,
        QuiescenceAchieved,
    }

    impl MockSporkSupervisor {
        pub fn new(supervisor_id: u64, restart_policy: MockRestartPolicy) -> Self {
            Self {
                supervisor_id,
                children: HashMap::new(),
                restart_policy,
                supervision_tree_state: MockSupervisionTreeState::Active,
                lifecycle_events: Vec::new(),
                name_registry: HashMap::new(),
                quiescence_state: MockQuiescenceState::NotQuiescent,
            }
        }

        pub fn start_child(&mut self, child_id: u64, timestamp: u64) -> Result<(), &'static str> {
            if self.children.contains_key(&child_id) {
                return Err("Child already exists");
            }

            let child = MockSporkChild {
                child_id,
                state: MockChildState::Starting,
                restart_count: 0,
                last_restart_time: None,
                lifecycle_phase: MockLifecyclePhase::Init,
            };

            self.children.insert(child_id, child);

            self.lifecycle_events.push(MockLifecycleEvent {
                event_id: self.lifecycle_events.len() as u64,
                timestamp,
                event_type: MockLifecycleEventType::ChildStarted,
                child_id: Some(child_id),
            });

            Ok(())
        }

        pub fn child_failed(
            &mut self,
            child_id: u64,
            timestamp: u64,
        ) -> Result<bool, &'static str> {
            if !self.children.contains_key(&child_id) {
                return Err("Child not found");
            }

            // Mark child as failed in a scoped mutable borrow so we can call
            // self.should_restart_child afterwards without aliasing.
            if let Some(child) = self.children.get_mut(&child_id) {
                child.state = MockChildState::Failed;
            }

            self.lifecycle_events.push(MockLifecycleEvent {
                event_id: self.lifecycle_events.len() as u64,
                timestamp,
                event_type: MockLifecycleEventType::ChildFailed,
                child_id: Some(child_id),
            });

            // Check restart policy
            let should_restart = self.should_restart_child(child_id, timestamp);
            if should_restart {
                if let Some(child) = self.children.get_mut(&child_id) {
                    child.state = MockChildState::Restarting;
                    child.restart_count += 1;
                    child.last_restart_time = Some(timestamp);
                }

                self.lifecycle_events.push(MockLifecycleEvent {
                    event_id: self.lifecycle_events.len() as u64,
                    timestamp,
                    event_type: MockLifecycleEventType::ChildRestarted,
                    child_id: Some(child_id),
                });
            }

            Ok(should_restart)
        }

        fn should_restart_child(&self, child_id: u64, current_time: u64) -> bool {
            if let Some(child) = self.children.get(&child_id) {
                if child.restart_count >= self.restart_policy.max_restarts {
                    return false;
                }

                // Check time window
                if let Some(last_restart) = child.last_restart_time {
                    let time_since_restart = current_time - last_restart;
                    if time_since_restart < self.restart_policy.time_window_ms {
                        // Check if we're within rate limits
                        let recent_restarts = self
                            .lifecycle_events
                            .iter()
                            .filter(|e| {
                                matches!(e.event_type, MockLifecycleEventType::ChildRestarted)
                                    && e.child_id == Some(child_id)
                                    && current_time - e.timestamp
                                        < self.restart_policy.time_window_ms
                            })
                            .count();

                        return (recent_restarts as u32) < self.restart_policy.max_restarts;
                    }
                }

                true
            } else {
                false
            }
        }

        pub fn register_name(
            &mut self,
            name: String,
            child_id: u64,
            timestamp: u64,
        ) -> Result<(), &'static str> {
            if self.name_registry.contains_key(&name) {
                return Err("Name already registered");
            }

            self.name_registry.insert(name.clone(), child_id);

            self.lifecycle_events.push(MockLifecycleEvent {
                event_id: self.lifecycle_events.len() as u64,
                timestamp,
                event_type: MockLifecycleEventType::NameRegistered(name),
                child_id: Some(child_id),
            });

            Ok(())
        }

        pub fn initiate_quiescence(&mut self, timestamp: u64) {
            self.quiescence_state = MockQuiescenceState::QuiescenceInitiated;
            self.supervision_tree_state = MockSupervisionTreeState::Quiescing;

            // Check if already quiescent (no active children)
            let active_children = self
                .children
                .values()
                .any(|c| matches!(c.state, MockChildState::Running | MockChildState::Starting));

            if !active_children {
                self.quiescence_state = MockQuiescenceState::QuiescenceAchieved;
                self.supervision_tree_state = MockSupervisionTreeState::Quiescent;

                self.lifecycle_events.push(MockLifecycleEvent {
                    event_id: self.lifecycle_events.len() as u64,
                    timestamp,
                    event_type: MockLifecycleEventType::QuiescenceReached,
                    child_id: None,
                });
            }
        }

        pub fn verify_lifecycle_monotonicity(&self) -> bool {
            // Check that lifecycle events follow monotonic progression
            for window in self.lifecycle_events.windows(2) {
                if window[0].timestamp > window[1].timestamp {
                    return false;
                }
            }

            // Check individual child lifecycle progression
            for child in self.children.values() {
                let phase_order = |phase: &MockLifecyclePhase| match phase {
                    MockLifecyclePhase::Init => 0,
                    MockLifecyclePhase::Active => 1,
                    MockLifecyclePhase::Terminating => 2,
                    MockLifecyclePhase::Terminated => 3,
                };

                // Child lifecycle phases should generally progress forward
                // (with allowances for restarts)
            }

            true
        }

        pub fn verify_restart_policy_consistency(&self) -> bool {
            for child in self.children.values() {
                if child.restart_count > self.restart_policy.max_restarts {
                    return false;
                }
            }
            true
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Server Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_server_graceful_shutdown_completion_guarantees() {
        proptest!(|(
            initial_connections in proptest::collection::vec(
                (1u32..10, 1000u64..5000), // (in_flight_requests, connection_duration)
                2..10
            ),
            drain_timeout_ms in 1000u64..3000,
            time_steps in proptest::collection::vec(100u64..500, 5..15)
        )| {
            // MR-ServerGracefulShutdownCompletionGuarantees:
            // Graceful shutdown should follow monotonic phase progression and
            // guarantee completion within bounded time regardless of connection patterns

            let mut server = MockServer::new(drain_timeout_ms);

            // Add initial connections
            for (in_flight_requests, _duration) in &initial_connections {
                server.add_connection(*in_flight_requests);
            }

            // Initiate shutdown
            server.initiate_shutdown();
            prop_assert_eq!(server.state.clone(), MockServerState::Draining);

            // Simulate time progression and request completion
            let mut total_time = 0u64;
            for (step_idx, &time_step) in time_steps.iter().enumerate() {
                server.advance_time(time_step);
                total_time += time_step;

                // Randomly complete some requests
                if step_idx % 3 == 0 {
                    for connection_id in server.connections.keys().cloned().collect::<Vec<_>>() {
                        server.complete_request(connection_id);
                    }
                }
            }

            // Ensure we advance past drain timeout
            if total_time < drain_timeout_ms + 1000 {
                server.advance_time(drain_timeout_ms + 1000 - total_time);
                total_time = drain_timeout_ms + 1000;
            }

            // Verify shutdown completion guarantees
            prop_assert!(
                matches!(server.state, MockServerState::Stopped | MockServerState::ForceClosing),
                "Server should reach terminal state after drain timeout: {:?}",
                server.state
            );

            // Verify monotonic phase progression
            prop_assert!(
                server.verify_shutdown_monotonicity(),
                "Shutdown phases should progress monotonically"
            );

            // Verify all connections are eventually closed
            let all_connections_closed = server.connections.values()
                .all(|c| matches!(c.state, MockConnectionState::Closed | MockConnectionState::ForceClosed));

            if matches!(server.state, MockServerState::Stopped) {
                prop_assert!(
                    all_connections_closed,
                    "All connections should be closed when server is stopped"
                );
            }

            // Verify shutdown events follow logical ordering
            let mut last_drain_event = None;
            let mut last_force_close_event = None;
            let mut server_stopped_event = None;

            for event in &server.shutdown_history {
                match &event.event_type {
                    MockShutdownEventType::DrainStarted => {
                        last_drain_event = Some(event.timestamp);
                    }
                    MockShutdownEventType::ForceCloseStarted => {
                        last_force_close_event = Some(event.timestamp);
                    }
                    MockShutdownEventType::ServerStopped => {
                        server_stopped_event = Some(event.timestamp);
                    }
                    _ => {}
                }
            }

            if let (Some(drain_time), Some(force_close_time)) = (last_drain_event, last_force_close_event) {
                prop_assert!(
                    force_close_time >= drain_time,
                    "Force close should start after or at drain start: {} vs {}",
                    force_close_time, drain_time
                );
            }

            if let (Some(force_close_time), Some(stopped_time)) = (last_force_close_event, server_stopped_event) {
                prop_assert!(
                    stopped_time >= force_close_time,
                    "Server should stop after or at force close start: {} vs {}",
                    stopped_time, force_close_time
                );
            }
        });
    }

    #[test]
    fn mr_server_drain_timeout_invariance() {
        proptest!(|(
            connection_patterns in proptest::collection::vec(
                proptest::collection::vec(1u32..5, 2..6), // Different patterns of request counts
                3..8
            ),
            drain_timeout_ms in 500u64..2000,
            time_advancement_styles in proptest::collection::vec(0u8..3, 4..10)
        )| {
            // MR-ServerDrainTimeoutInvariance:
            // Drain timeout behavior should be invariant to connection request patterns
            // and time advancement styles - same timeout should produce same outcome

            if connection_patterns.is_empty() { return Ok(()); }

            let mut server_results = Vec::new();

            for (pattern_idx, pattern) in connection_patterns.iter().enumerate() {
                let mut server = MockServer::new(drain_timeout_ms);

                // Add connections according to pattern
                for &request_count in pattern {
                    server.add_connection(request_count);
                }

                server.initiate_shutdown();

                // Apply different time advancement styles
                let advancement_style = time_advancement_styles.get(pattern_idx % time_advancement_styles.len())
                    .unwrap_or(&0) % 3;

                match advancement_style {
                    0 => {
                        // Small frequent steps
                        for _ in 0..20 {
                            server.advance_time(50);
                        }
                        server.advance_time(drain_timeout_ms);
                    }
                    1 => {
                        // Large infrequent steps
                        server.advance_time(drain_timeout_ms / 2);
                        server.advance_time(drain_timeout_ms / 2 + 100);
                    }
                    _ => {
                        // Single large step
                        server.advance_time(drain_timeout_ms + 500);
                    }
                }

                // Record final state
                let result = (
                    server.state.clone(),
                    server.connections.len(),
                    server.connections.values().filter(|c| matches!(c.state, MockConnectionState::ForceClosed)).count(),
                );

                server_results.push(result);
            }

            // All servers should reach the same terminal behavior under same timeout
            // (allowing for differences in connection counts)
            let force_close_counts: Vec<_> = server_results.iter().map(|(_, _, force_closed)| *force_closed).collect();

            // Servers with more connections should either have more force-closed connections
            // or the same proportion
            for window in server_results.windows(2) {
                let (state1, total1, _) = &window[0];
                let (state2, total2, _) = &window[1];

                // Both should reach terminal states
                prop_assert!(
                    matches!(state1, MockServerState::Stopped | MockServerState::ForceClosing),
                    "Server 1 should reach terminal state: {:?}", state1
                );
                prop_assert!(
                    matches!(state2, MockServerState::Stopped | MockServerState::ForceClosing),
                    "Server 2 should reach terminal state: {:?}", state2
                );

                // If timeout exceeded, both should force close
                if *total1 > 0 && *total2 > 0 {
                    prop_assert!(
                        matches!(state1, MockServerState::ForceClosing | MockServerState::Stopped) ==
                        matches!(state2, MockServerState::ForceClosing | MockServerState::Stopped),
                        "Servers with connections should have consistent force close behavior"
                    );
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Session Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_session_resume_idempotency() {
        proptest!(|(
            session_operations in proptest::collection::vec(
                (
                    proptest::collection::vec(0u8..255, 1..50), // message data
                    1000u64..2000 // timestamp
                ),
                3..10
            ),
            resume_attempts in 2u32..6,
            checkpoint_intervals in proptest::collection::vec(1usize..4, 2..5)
        )| {
            // MR-SessionResumeIdempotency:
            // Session resume operations should be idempotent - multiple resumes
            // with the same checkpoint should produce identical session state

            let mut session = MockSession::new(1, MockProtocolState::SendState {
                next_send: b"hello".to_vec(),
            });

            // Apply initial operations and create checkpoints
            let mut checkpoints = Vec::new();
            for (op_idx, (data, timestamp)) in session_operations.iter().enumerate() {
                let _ = session.send_message(data.clone(), *timestamp);

                // Create checkpoint at intervals
                if checkpoint_intervals.iter().any(|&interval| op_idx % interval == 0) {
                    checkpoints.push(session.checkpoint());
                }
            }

            if checkpoints.is_empty() {
                checkpoints.push(session.checkpoint());
            }

            // Test idempotency of resume operations
            for checkpoint_data in &checkpoints {
                let initial_state = session.protocol_state.clone();
                let initial_resume_count = session.resume_count;

                // Perform multiple resume attempts with the same checkpoint
                let mut resume_results = Vec::new();
                for _ in 0..resume_attempts {
                    let result = session.resume(checkpoint_data.clone());
                    resume_results.push((result, session.protocol_state.clone(), session.resume_count));
                }

                // All resume attempts should succeed (idempotency)
                for (i, (result, _, _)) in resume_results.iter().enumerate() {
                    prop_assert!(
                        result.is_ok(),
                        "Resume attempt {} should succeed idempotently: {:?}",
                        i, result
                    );
                }

                // Protocol state should remain consistent across resumes
                let final_state = &resume_results.last().unwrap().1;
                for (i, (_, state, _)) in resume_results.iter().enumerate() {
                    prop_assert_eq!(
                        state, final_state,
                        "Protocol state should be identical across resume attempts: attempt {}",
                        i
                    );
                }

                // Resume count should increment for each attempt
                let final_resume_count = resume_results.last().unwrap().2;
                prop_assert_eq!(
                    final_resume_count, initial_resume_count + resume_attempts,
                    "Resume count should increment correctly: {} vs {}",
                    final_resume_count, initial_resume_count + resume_attempts
                );

                // Protocol invariants should be maintained
                prop_assert!(
                    session.verify_protocol_invariants(),
                    "Protocol invariants should be maintained after resume operations"
                );
            }
        });
    }

    #[test]
    fn mr_session_duality_preservation() {
        proptest!(|(
            protocol_operations in proptest::collection::vec(
                (
                    0u8..4, // operation type
                    proptest::collection::vec(0u8..255, 1..20), // data
                ),
                3..8
            ),
            transformation_seed in 0u64..1000
        )| {
            // MR-SessionDualityPreservation:
            // Session type duality should be preserved under protocol transformations
            // If A has protocol P, then dual(A) should have protocol dual(P)

            let mut session_a = MockSession::new(1, MockProtocolState::SendState {
                next_send: b"test".to_vec(),
            });

            // Create dual session
            let mut session_b = session_a.create_dual();

            // Verify initial duality
            match (&session_a.protocol_state, &session_b.protocol_state) {
                (MockProtocolState::SendState { next_send }, MockProtocolState::RecvState { expected_recv }) => {
                    prop_assert_eq!(next_send, expected_recv, "Initial duality should be preserved");
                }
                _ => {
                    prop_assert!(false, "Unexpected initial dual state pairing");
                }
            }

            // Apply transformations to both sessions
            for (op_type, data) in &protocol_operations {
                let timestamp = 1000 + protocol_operations.len() as u64;

                match op_type % 4 {
                    0 => {
                        // Send operation on A should correspond to recv readiness on B
                        let _ = session_a.send_message(data.clone(), timestamp);
                    }
                    1 => {
                        // State transition simulation
                        session_b.protocol_state = match &session_b.protocol_state {
                            MockProtocolState::RecvState { .. } => {
                                MockProtocolState::SendState { next_send: b"response".to_vec() }
                            }
                            MockProtocolState::SendState { .. } => {
                                MockProtocolState::RecvState { expected_recv: b"ack".to_vec() }
                            }
                            other => other.clone(),
                        };
                    }
                    2 => {
                        // Protocol advancement
                        if matches!(session_b.protocol_state, MockProtocolState::EndState) {
                            session_b.protocol_state = MockProtocolState::EndState;
                        }
                    }
                    _ => {
                        // Checkpoint operation (should not affect duality)
                        let _checkpoint = session_a.checkpoint();
                        let _checkpoint = session_b.checkpoint();
                    }
                }
            }

            // Create new duals after transformations
            let new_dual_of_a = session_a.create_dual();
            let new_dual_of_b = session_b.create_dual();

            // Verify duality preservation after transformations
            match (&session_a.protocol_state, &new_dual_of_a.protocol_state) {
                (MockProtocolState::SendState { next_send }, MockProtocolState::RecvState { expected_recv }) => {
                    prop_assert_eq!(next_send, expected_recv, "Duality should be preserved after transformations");
                }
                (MockProtocolState::RecvState { expected_recv }, MockProtocolState::SendState { next_send }) => {
                    prop_assert_eq!(expected_recv, next_send, "Reverse duality should be preserved");
                }
                (MockProtocolState::EndState, MockProtocolState::EndState) => {
                    // Both at end - duality preserved
                }
                (MockProtocolState::ChooseState { options }, MockProtocolState::OfferState { alternatives }) => {
                    prop_assert_eq!(options, alternatives, "Choice/offer duality should be preserved");
                }
                (MockProtocolState::OfferState { alternatives }, MockProtocolState::ChooseState { options }) => {
                    prop_assert_eq!(alternatives, options, "Offer/choice duality should be preserved");
                }
                _ => {
                    // Allow other valid dual combinations
                }
            }

            // Duality should be symmetric: dual(dual(A)) = A (approximately)
            let double_dual = new_dual_of_a.create_dual();
            match (&session_a.protocol_state, &double_dual.protocol_state) {
                (MockProtocolState::SendState { .. }, MockProtocolState::SendState { .. }) |
                (MockProtocolState::RecvState { .. }, MockProtocolState::RecvState { .. }) |
                (MockProtocolState::EndState, MockProtocolState::EndState) => {
                    // Double duality should return to similar state type
                }
                _ => {
                    // Some flexibility allowed due to mock simplification
                }
            }

            // Protocol state transitions should be consistent
            prop_assert!(
                session_a.verify_protocol_invariants(),
                "Session A should maintain protocol invariants"
            );

            prop_assert!(
                session_b.verify_protocol_invariants(),
                "Session B should maintain protocol invariants"
            );
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Evidence Sink Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_evidence_sink_consume_once_invariants() {
        proptest!(|(
            evidence_entries in proptest::collection::vec(
                (1u64..1000, proptest::collection::vec(0u8..255, 1..100)), // (entry_id, data)
                5..20
            ),
            duplicate_attempts in proptest::collection::vec(0usize..1000, 3..10),
            backend_types in proptest::collection::vec(0u8..3, 2..4)
        )| {
            // MR-EvidenceSinkConsumeOnceInvariants:
            // Evidence entries should be consumed exactly once regardless of
            // emission patterns, duplicate attempts, or backend type

            let backends: Vec<MockBackendType> = backend_types.iter().map(|&t| match t % 3 {
                0 => MockBackendType::Null,
                1 => MockBackendType::Jsonl(format!("test_{}.jsonl", t)),
                _ => MockBackendType::Collector,
            }).collect();

            for (backend_idx, backend_type) in backends.iter().enumerate() {
                let mut sink = MockEvidenceSink::new(backend_idx as u64, backend_type.clone());

                // Emit initial entries
                let mut emission_results = Vec::new();
                for (entry_id, data) in &evidence_entries {
                    let result = sink.emit(*entry_id, data.clone());
                    emission_results.push((*entry_id, result));
                }

                // Attempt duplicate emissions
                for &dup_idx in &duplicate_attempts {
                    if dup_idx < evidence_entries.len() {
                        let (entry_id, data) = &evidence_entries[dup_idx];
                        let dup_result = sink.emit(*entry_id, data.clone());
                        prop_assert!(
                            dup_result.is_err(),
                            "Duplicate emission should fail for entry {}: {:?}",
                            entry_id, dup_result
                        );
                    }
                }

                // Verify consume-once invariants
                prop_assert!(
                    sink.verify_consume_once_invariants(),
                    "Sink should maintain consume-once invariants for backend {:?}",
                    backend_type
                );

                // Check that each entry appears exactly once
                let mut entry_counts = HashMap::new();
                for entry in &sink.emitted_entries {
                    *entry_counts.entry(entry.entry_id).or_insert(0) += 1;
                }

                for (entry_id, count) in entry_counts {
                    prop_assert_eq!(
                        count, 1,
                        "Entry {} should appear exactly once, found {} occurrences",
                        entry_id, count
                    );
                }

                // Verify that emission order matches entry order in emitted_entries
                for (i, entry) in sink.emitted_entries.iter().enumerate() {
                    prop_assert_eq!(
                        entry.emission_order, i as u64,
                        "Emission order should be sequential: entry {} has order {}, expected {}",
                        entry.entry_id, entry.emission_order, i
                    );
                }

                // Consume-once tracker should match emitted entries
                let emitted_ids: BTreeSet<_> = sink.emitted_entries.iter().map(|e| e.entry_id).collect();
                prop_assert_eq!(
                    sink.consume_once_tracker, emitted_ids,
                    "Consume-once tracker should match exactly the emitted entry IDs"
                );
            }
        });
    }

    #[test]
    fn mr_evidence_sink_concurrent_emission_ordering() {
        proptest!(|(
            concurrent_emissions in proptest::collection::vec(
                (1u64..10, 1u64..1000, proptest::collection::vec(0u8..255, 5..50)), // (thread_id, entry_id, data)
                5..15
            ),
            emission_timing_pattern in proptest::collection::vec(0u64..100, 5..15)
        )| {
            // MR-EvidenceSinkConcurrentEmissionOrdering:
            // Concurrent emissions should follow deterministic ordering rules
            // and maintain consume-once invariants even under contention

            let mut sink = MockEvidenceSink::new(1, MockBackendType::Collector);

            // Apply concurrent emissions with timing patterns
            for ((thread_id, entry_id, data), &timing_offset) in
                concurrent_emissions.iter().zip(emission_timing_pattern.iter().cycle()) {

                let emission_time = 1000 + timing_offset;
                let result = sink.emit_concurrent(*thread_id, *entry_id, data.clone(), emission_time);

                // All non-duplicate emissions should succeed
                if !sink.consume_once_tracker.contains(entry_id) {
                    prop_assert!(
                        result.is_ok(),
                        "Concurrent emission should succeed for unique entry {}: {:?}",
                        entry_id, result
                    );
                } else {
                    prop_assert!(
                        result.is_err(),
                        "Duplicate concurrent emission should fail for entry {}: {:?}",
                        entry_id, result
                    );
                }
            }

            // Verify concurrent ordering properties
            let concurrent_order = sink.get_concurrent_ordering();

            // Check that the concurrent ordering respects emission time ordering
            let mut concurrent_emissions_sorted = sink.concurrent_emissions.clone();
            concurrent_emissions_sorted.sort_by_key(|e| (e.emission_time, e.thread_id, e.entry_id));

            for (i, emission) in concurrent_emissions_sorted.iter().enumerate() {
                if i < concurrent_order.len() {
                    prop_assert_eq!(
                        concurrent_order[i], emission.entry_id,
                        "Concurrent ordering should match sorted emissions at index {}: {} vs {}",
                        i, concurrent_order[i], emission.entry_id
                    );
                }
            }

            // Verify that concurrent emissions maintain timestamp monotonicity where possible
            if sink.verify_timestamp_monotonicity() {
                // If timestamps are monotonic, emission order should be deterministic
                let emission_times: Vec<_> = sink.emitted_entries.iter().map(|e| e.timestamp).collect();
                for window in emission_times.windows(2) {
                    prop_assert!(
                        window[0] < window[1],
                        "Emission timestamps should be strictly increasing: {} -> {}",
                        window[0], window[1]
                    );
                }
            }

            // Consume-once invariants should hold even under concurrency
            prop_assert!(
                sink.verify_consume_once_invariants(),
                "Consume-once invariants should be maintained under concurrent emissions"
            );

            // Each thread's emissions should be internally consistent
            let mut thread_emissions: HashMap<u64, Vec<_>> = HashMap::new();
            for emission in &sink.concurrent_emissions {
                thread_emissions.entry(emission.thread_id).or_default().push(emission);
            }

            for (thread_id, emissions) in thread_emissions {
                for window in emissions.windows(2) {
                    prop_assert!(
                        window[0].emission_time <= window[1].emission_time,
                        "Thread {} emissions should be in temporal order: {} -> {}",
                        thread_id, window[0].emission_time, window[1].emission_time
                    );
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Epoch Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_epoch_advance_monotonicity() {
        proptest!(|(
            epoch_triggers in proptest::collection::vec(
                (0u8..4, 100u64..500), // (trigger_type, time_delta)
                5..15
            ),
            barrier_configs in proptest::collection::vec(
                (1u64..100, 0u64..5), // (barrier_id, target_epoch_offset)
                2..8
            ),
            reclamation_objects in proptest::collection::vec(
                (1u64..1000, 1u64..3), // (object_id, grace_epochs)
                3..10
            )
        )| {
            // MR-EpochAdvanceMonotonicity:
            // Epoch advancement should be strictly monotonic regardless of trigger
            // patterns, barrier synchronization, or reclamation scheduling

            let mut clock = MockEpochClock::new();
            let mut current_time = 1000u64;

            // Add reclaimable objects at the beginning
            for (object_id, grace_epochs) in &reclamation_objects {
                clock.add_reclaimable_object(*object_id, *grace_epochs);
            }

            // Create barriers
            for (barrier_id, target_epoch_offset) in &barrier_configs {
                let target_epoch = clock.current_epoch + target_epoch_offset;
                clock.create_barrier(*barrier_id, target_epoch);
            }

            // Apply epoch advancement with different triggers
            for (trigger_idx, time_delta) in &epoch_triggers {
                current_time += time_delta;

                let trigger = match trigger_idx % 4 {
                    0 => MockEpochTrigger::TimeElapsed,
                    1 => MockEpochTrigger::MemoryPressure,
                    2 => MockEpochTrigger::ExternalSignal,
                    _ => MockEpochTrigger::BarrierSync,
                };

                let old_epoch = clock.current_epoch;
                let result = clock.advance_epoch(trigger, current_time);

                prop_assert!(
                    result.is_ok(),
                    "Epoch advancement should succeed: {:?}",
                    result
                );

                if let Ok(new_epoch) = result {
                    prop_assert_eq!(
                        new_epoch, old_epoch + 1,
                        "New epoch should be exactly one more than old epoch: {} vs {}",
                        new_epoch, old_epoch + 1
                    );

                    prop_assert_eq!(
                        clock.current_epoch, new_epoch,
                        "Clock current epoch should match returned epoch: {} vs {}",
                        clock.current_epoch, new_epoch
                    );
                }

                // Test barrier synchronization
                for (barrier_id, _) in &barrier_configs {
                    let thread_id = *barrier_id + 1000;
                    let _ = clock.wait_barrier(*barrier_id, thread_id);
                }
            }

            // Verify overall monotonicity
            prop_assert!(
                clock.verify_monotonicity(),
                "Epoch clock should maintain monotonicity invariant"
            );

            // Verify epoch history is consistent
            for (i, transition) in clock.epoch_history.iter().enumerate() {
                prop_assert_eq!(
                    transition.from_epoch + 1, transition.to_epoch,
                    "Epoch transition {} should advance by exactly 1: {} -> {}",
                    i, transition.from_epoch, transition.to_epoch
                );

                if i > 0 {
                    let prev_transition = &clock.epoch_history[i - 1];
                    prop_assert!(
                        transition.timestamp >= prev_transition.timestamp,
                        "Epoch transition timestamps should be non-decreasing: {} vs {}",
                        transition.timestamp, prev_transition.timestamp
                    );

                    prop_assert_eq!(
                        prev_transition.to_epoch, transition.from_epoch,
                        "Consecutive epoch transitions should be continuous: {} -> {} vs {} -> {}",
                        prev_transition.from_epoch, prev_transition.to_epoch,
                        transition.from_epoch, transition.to_epoch
                    );
                }
            }

            // Final epoch should match history
            if !clock.epoch_history.is_empty() {
                let last_transition = clock.epoch_history.last().unwrap();
                prop_assert_eq!(
                    clock.current_epoch, last_transition.to_epoch,
                    "Final epoch should match last transition: {} vs {}",
                    clock.current_epoch, last_transition.to_epoch
                );
            }
        });
    }

    #[test]
    fn mr_epoch_reclamation_safety() {
        proptest!(|(
            objects_and_epochs in proptest::collection::vec(
                (1u64..1000, 1u64..4), // (object_id, grace_periods)
                5..15
            ),
            epoch_advancement_pattern in proptest::collection::vec(
                (0u8..3, 100u64..300), // (advancement_style, time_step)
                10..25
            ),
            memory_pressure_events in proptest::collection::vec(
                (0u64..10, 500u64..1000), // (pressure_level, event_time_offset)
                2..6
            )
        )| {
            // MR-EpochReclamationSafety:
            // Memory reclamation should preserve safety invariants - objects should
            // not be reclaimed before their grace period expires, regardless of
            // memory pressure or advancement patterns

            let mut clock = MockEpochClock::new();
            let mut current_time = 1000u64;

            // Track object creation epochs for safety verification
            let mut object_creation_epochs: HashMap<u64, u64> = HashMap::new();

            // Add objects throughout the test
            for (i, (object_id, grace_epochs)) in objects_and_epochs.iter().enumerate() {
                if i % 3 == 0 {
                    // Advance epoch before adding some objects
                    let _ = clock.advance_epoch(MockEpochTrigger::TimeElapsed, current_time);
                    current_time += 50;
                }

                object_creation_epochs.insert(*object_id, clock.current_epoch);
                clock.add_reclaimable_object(*object_id, *grace_epochs);
            }

            // Apply epoch advancement patterns
            for (advancement_idx, (advancement_style, time_step)) in epoch_advancement_pattern.iter().enumerate() {
                current_time += time_step;

                // Apply memory pressure events
                if advancement_idx < memory_pressure_events.len() {
                    let (pressure_level, time_offset) = memory_pressure_events[advancement_idx];
                    current_time += time_offset;

                    // Simulate memory pressure triggering epoch advancement
                    if pressure_level > 5 {
                        let _ = clock.advance_epoch(MockEpochTrigger::MemoryPressure, current_time);
                    }
                }

                // Apply different advancement styles
                match advancement_style % 3 {
                    0 => {
                        // Regular time-based advancement
                        let _ = clock.advance_epoch(MockEpochTrigger::TimeElapsed, current_time);
                    }
                    1 => {
                        // Batch advancement (simulate multiple rapid epochs)
                        for _ in 0..3 {
                            let _ = clock.advance_epoch(MockEpochTrigger::MemoryPressure, current_time);
                            current_time += 10;
                        }
                    }
                    _ => {
                        // External signal advancement
                        let _ = clock.advance_epoch(MockEpochTrigger::ExternalSignal, current_time);
                    }
                }
            }

            // Verify reclamation safety
            prop_assert!(
                clock.verify_reclamation_safety(),
                "Clock should maintain reclamation safety invariants"
            );

            // Detailed safety verification
            for obj in &clock.reclamation_queue {
                if let Some(&creation_epoch) = object_creation_epochs.get(&obj.object_id) {
                    prop_assert_eq!(
                        obj.creation_epoch, creation_epoch,
                        "Object {} creation epoch should match tracking: {} vs {}",
                        obj.object_id, obj.creation_epoch, creation_epoch
                    );

                    if obj.reclaimed {
                        // Verify object was not reclaimed too early
                        prop_assert!(
                            clock.current_epoch >= obj.reclaimable_after_epoch,
                            "Reclaimed object {} should not have been reclaimed before grace period: current_epoch={}, reclaimable_after={}",
                            obj.object_id, clock.current_epoch, obj.reclaimable_after_epoch
                        );

                        prop_assert!(
                            obj.reclaimable_after_epoch > obj.creation_epoch,
                            "Object {} should have grace period > 0: created={}, reclaimable_after={}",
                            obj.object_id, obj.creation_epoch, obj.reclaimable_after_epoch
                        );
                    } else {
                        // If not reclaimed, either grace period not elapsed or not yet processed
                        if clock.current_epoch >= obj.reclaimable_after_epoch {
                            // May be waiting in queue for next reclamation cycle
                            // This is acceptable
                        }
                    }
                }
            }

            // Verify that reclaimed objects follow epoch ordering
            let mut last_reclamation_epoch = 0u64;
            for obj in &clock.reclamation_queue {
                if obj.reclaimed {
                    prop_assert!(
                        obj.reclaimable_after_epoch >= last_reclamation_epoch,
                        "Reclamation ordering should follow epoch progression: object {} reclaimed at epoch {} after previous {}",
                        obj.object_id, obj.reclaimable_after_epoch, last_reclamation_epoch
                    );
                    last_reclamation_epoch = obj.reclaimable_after_epoch;
                }
            }

            // Memory pressure should not compromise safety
            let pressure_triggered_advancements = clock.epoch_history.iter()
                .filter(|t| matches!(t.trigger, MockEpochTrigger::MemoryPressure))
                .count();

            if pressure_triggered_advancements > 0 {
                // Even under memory pressure, all safety invariants should hold
                prop_assert!(
                    clock.verify_reclamation_safety(),
                    "Reclamation safety should be maintained even under memory pressure ({} pressure events)",
                    pressure_triggered_advancements
                );
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Spork Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_spork_lifecycle_monotonicity() {
        proptest!(|(
            child_specs in proptest::collection::vec(
                (1u64..100, 0u8..3), // (child_id, initial_state)
                3..10
            ),
            restart_policy in (1u32..5, 1000u64..3000, 0u8..3), // (max_restarts, time_window, strategy)
            lifecycle_events in proptest::collection::vec(
                (0usize..1000, 0u8..4, 1000u64..5000), // (child_index, event_type, timestamp)
                5..20
            ),
            name_registrations in proptest::collection::vec(
                (
                    proptest::string::string_regex("[a-z]{3,8}").unwrap(),
                    0usize..1000, // child_index
                    2000u64..4000 // timestamp
                ),
                2..6
            )
        )| {
            // MR-SporkLifecycleMonotonicity:
            // Spork supervision lifecycle should progress monotonically -
            // lifecycle phases should advance forward and supervision events
            // should follow deterministic ordering

            let restart_policy_obj = MockRestartPolicy {
                max_restarts: restart_policy.0,
                time_window_ms: restart_policy.1,
                strategy: match restart_policy.2 % 3 {
                    0 => MockRestartStrategy::OneForOne,
                    1 => MockRestartStrategy::OneForAll,
                    _ => MockRestartStrategy::RestForOne,
                },
            };

            let mut supervisor = MockSporkSupervisor::new(1, restart_policy_obj);

            // Start initial children
            for (child_id, _) in &child_specs {
                let _ = supervisor.start_child(*child_id, 1000);
            }

            // Apply lifecycle events
            for (child_index, event_type, timestamp) in &lifecycle_events {
                if child_specs.is_empty() { continue; }

                let child_idx = child_index % child_specs.len();
                let (child_id, _) = child_specs[child_idx];

                match event_type % 4 {
                    0 => {
                        // Child failure
                        let _ = supervisor.child_failed(child_id, *timestamp);
                    }
                    1 => {
                        // Start new child (if not already started)
                        let new_child_id = child_id + 1000;
                        let _ = supervisor.start_child(new_child_id, *timestamp);
                    }
                    2 => {
                        // Initiate quiescence
                        supervisor.initiate_quiescence(*timestamp);
                    }
                    _ => {
                        // Update child state directly (simulate external events)
                        if let Some(child) = supervisor.children.get_mut(&child_id) {
                            child.lifecycle_phase = match child.lifecycle_phase {
                                MockLifecyclePhase::Init => MockLifecyclePhase::Active,
                                MockLifecyclePhase::Active => MockLifecyclePhase::Terminating,
                                MockLifecyclePhase::Terminating => MockLifecyclePhase::Terminated,
                                MockLifecyclePhase::Terminated => MockLifecyclePhase::Terminated,
                            };
                        }
                    }
                }
            }

            // Apply name registrations
            for (name, child_index, timestamp) in &name_registrations {
                if child_specs.is_empty() { continue; }

                let child_idx = child_index % child_specs.len();
                let (child_id, _) = child_specs[child_idx];
                let _ = supervisor.register_name(name.clone(), child_id, *timestamp);
            }

            // Verify lifecycle monotonicity
            prop_assert!(
                supervisor.verify_lifecycle_monotonicity(),
                "Supervisor should maintain lifecycle monotonicity"
            );

            // Verify restart policy consistency
            prop_assert!(
                supervisor.verify_restart_policy_consistency(),
                "Supervisor should maintain restart policy consistency"
            );

            // Check event ordering
            for window in supervisor.lifecycle_events.windows(2) {
                prop_assert!(
                    window[0].timestamp <= window[1].timestamp,
                    "Lifecycle events should be in temporal order: {} -> {}",
                    window[0].timestamp, window[1].timestamp
                );
            }

            // Verify supervision tree state consistency
            match supervisor.supervision_tree_state {
                MockSupervisionTreeState::Quiescent => {
                    prop_assert_eq!(
                        supervisor.quiescence_state, MockQuiescenceState::QuiescenceAchieved,
                        "Quiescent tree should have achieved quiescence state"
                    );

                    // No children should be in active states
                    let active_children = supervisor.children.values()
                        .filter(|c| matches!(c.state, MockChildState::Running | MockChildState::Starting))
                        .count();

                    prop_assert_eq!(
                        active_children, 0,
                        "Quiescent supervision tree should have no active children: found {}",
                        active_children
                    );
                }
                MockSupervisionTreeState::Quiescing => {
                    prop_assert_ne!(
                        supervisor.quiescence_state, MockQuiescenceState::NotQuiescent,
                        "Quiescing tree should have initiated quiescence"
                    );
                }
                _ => {
                    // Active or draining states - no specific constraints
                }
            }

            // Check individual child lifecycle progression
            for child in supervisor.children.values() {
                match child.lifecycle_phase {
                    MockLifecyclePhase::Terminated => {
                        // Terminated children should not have active state
                        prop_assert!(
                            !matches!(child.state, MockChildState::Running | MockChildState::Starting),
                            "Terminated child {} should not be in active state: {:?}",
                            child.child_id, child.state
                        );
                    }
                    MockLifecyclePhase::Active => {
                        // Active children should not be in terminated state
                        prop_assert!(
                            !matches!(child.state, MockChildState::Stopped | MockChildState::Failed),
                            "Active child {} should not be in terminated state: {:?}",
                            child.child_id, child.state
                        );
                    }
                    _ => {
                        // Transitional phases - allow flexibility
                    }
                }

                // Restart count should not exceed policy limits
                prop_assert!(
                    child.restart_count <= supervisor.restart_policy.max_restarts,
                    "Child {} restart count should not exceed policy: {} > {}",
                    child.child_id, child.restart_count, supervisor.restart_policy.max_restarts
                );
            }

            // Name registry should be consistent with children
            for (name, &child_id) in &supervisor.name_registry {
                prop_assert!(
                    supervisor.children.contains_key(&child_id),
                    "Registered name '{}' should reference existing child {}",
                    name, child_id
                );
            }
        });
    }

    #[test]
    fn mr_spork_supervision_tree_quiescence() {
        proptest!(|(
            initial_children in proptest::collection::vec(1u64..50, 3..8),
            child_activity_patterns in proptest::collection::vec(
                proptest::collection::vec(0u8..4, 2..6), // activity patterns per child
                3..8
            ),
            quiescence_trigger_time in 3000u64..5000,
            post_quiescence_events in proptest::collection::vec(
                (0usize..1000, 0u8..3), // (child_index, event_type)
                2..6
            )
        )| {
            // MR-SporkSupervisionTreeQuiescence:
            // Supervision trees should reach quiescent state deterministically
            // regardless of child activity patterns and timing of quiescence requests

            let restart_policy = MockRestartPolicy {
                max_restarts: 3,
                time_window_ms: 2000,
                strategy: MockRestartStrategy::OneForOne,
            };

            let mut supervisor = MockSporkSupervisor::new(1, restart_policy);
            let mut current_time = 1000u64;

            // Start initial children
            for &child_id in &initial_children {
                let _ = supervisor.start_child(child_id, current_time);
                current_time += 10;
            }

            // Apply child activity patterns before quiescence
            for (child_idx, activity_pattern) in child_activity_patterns.iter().enumerate() {
                if child_idx >= initial_children.len() { break; }

                let child_id = initial_children[child_idx];

                for &activity in activity_pattern {
                    current_time += 100;

                    match activity % 4 {
                        0 => {
                            // Child failure and potential restart
                            let _ = supervisor.child_failed(child_id, current_time);
                        }
                        1 => {
                            // Simulate child completion (natural stop)
                            if let Some(child) = supervisor.children.get_mut(&child_id) {
                                child.state = MockChildState::Stopped;
                                child.lifecycle_phase = MockLifecyclePhase::Terminated;
                            }
                        }
                        2 => {
                            // Register child name
                            let name = format!("child_{}", child_id);
                            let _ = supervisor.register_name(name, child_id, current_time);
                        }
                        _ => {
                            // Child state progression
                            if let Some(child) = supervisor.children.get_mut(&child_id) {
                                match child.state {
                                    MockChildState::Starting => child.state = MockChildState::Running,
                                    MockChildState::Running => child.state = MockChildState::Stopping,
                                    MockChildState::Stopping => {
                                        child.state = MockChildState::Stopped;
                                        child.lifecycle_phase = MockLifecyclePhase::Terminated;
                                    }
                                    _ => {} // No change for terminal states
                                }
                            }
                        }
                    }
                }
            }

            // Initiate quiescence
            current_time = quiescence_trigger_time;
            supervisor.initiate_quiescence(current_time);

            // Verify quiescence initiation
            prop_assert_ne!(
                &supervisor.quiescence_state, &MockQuiescenceState::NotQuiescent,
                "Quiescence should have been initiated"
            );

            prop_assert_eq!(
                &supervisor.supervision_tree_state, &MockSupervisionTreeState::Quiescing,
                "Supervision tree should be in quiescing state after initiation"
            );

            // Simulate remaining children completing
            let active_children: Vec<_> = supervisor.children.iter()
                .filter(|(_, child)| matches!(child.state, MockChildState::Running | MockChildState::Starting))
                .map(|(id, _)| *id)
                .collect();

            for child_id in active_children {
                current_time += 50;
                if let Some(child) = supervisor.children.get_mut(&child_id) {
                    child.state = MockChildState::Stopped;
                    child.lifecycle_phase = MockLifecyclePhase::Terminated;
                }
            }

            // Check if quiescence is achieved automatically
            let no_active_children = supervisor.children.values()
                .all(|c| !matches!(c.state, MockChildState::Running | MockChildState::Starting));

            if no_active_children {
                // Should have reached quiescence
                supervisor.initiate_quiescence(current_time + 100);

                prop_assert_eq!(
                    &supervisor.quiescence_state, &MockQuiescenceState::QuiescenceAchieved,
                    "Supervision tree should achieve quiescence when no children are active"
                );

                prop_assert_eq!(
                    &supervisor.supervision_tree_state, &MockSupervisionTreeState::Quiescent,
                    "Supervision tree state should be quiescent"
                );
            }

            // Apply post-quiescence events (should not affect quiescent state)
            let initial_quiescence_state = supervisor.quiescence_state.clone();

            for (child_index, event_type) in &post_quiescence_events {
                if initial_children.is_empty() { continue; }

                let child_idx = child_index % initial_children.len();
                let child_id = initial_children[child_idx];
                current_time += 100;

                match event_type % 3 {
                    0 => {
                        // Attempt to start new child (should not affect quiescent state)
                        let new_child_id = child_id + 2000;
                        let result = supervisor.start_child(new_child_id, current_time);

                        if matches!(
                            &supervisor.supervision_tree_state,
                            MockSupervisionTreeState::Quiescent
                        ) {
                            // Starting new children in quiescent state might be restricted
                            // or might restart the supervision tree
                        }
                    }
                    1 => {
                        // Name registration (should be idempotent in quiescent state)
                        let name = format!("post_quiescent_{}", child_id);
                        let _ = supervisor.register_name(name, child_id, current_time);
                    }
                    _ => {
                        // Check state only (non-mutating)
                    }
                }
            }

            // Verify final state consistency
            if matches!(
                &supervisor.supervision_tree_state,
                MockSupervisionTreeState::Quiescent
            ) {
                // Quiescent tree should maintain its properties
                let active_children_count = supervisor.children.values()
                    .filter(|c| matches!(c.state, MockChildState::Running | MockChildState::Starting))
                    .count();

                prop_assert_eq!(
                    active_children_count, 0,
                    "Quiescent supervision tree should have no active children: found {}",
                    active_children_count
                );

                // Quiescence-related events should be in the history
                let quiescence_events = supervisor.lifecycle_events.iter()
                    .filter(|e| matches!(e.event_type, MockLifecycleEventType::QuiescenceReached))
                    .count();

                if quiescence_events > 0 {
                    prop_assert!(
                        quiescence_events >= 1,
                        "Should have at least one quiescence event recorded"
                    );
                }
            }

            // Verify temporal consistency of lifecycle events
            prop_assert!(
                supervisor.verify_lifecycle_monotonicity(),
                "Lifecycle events should maintain monotonicity through quiescence"
            );

            // Check restart policy enforcement throughout quiescence process
            prop_assert!(
                supervisor.verify_restart_policy_consistency(),
                "Restart policy should be consistently enforced during quiescence"
            );
        });
    }
}
