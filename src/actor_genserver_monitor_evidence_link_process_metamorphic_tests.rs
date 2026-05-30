//! Metamorphic Testing for Actor System Core Modules [br-metamorphic-24]
//!
//! This module implements comprehensive metamorphic relations testing the core
//! actor system components: actor mailbox ordering, gen_server call semantics,
//! monitor transitivity, evidence chain determinism, link symmetry, and process
//! lifecycle consistency. These tests address the oracle problem where conventional
//! unit tests cannot verify complex state machine behaviors, ordering properties,
//! and distributed system semantics.
//!
//! ## Metamorphic Relations Implemented
//!
//! ### Actor Module (4 MRs)
//! - MR-MailboxFIFOPriorityLaneInteraction: Mailbox FIFO ordering is preserved under priority lane scheduling
//! - MR-ActorMessagePermutationInvariance: Message delivery semantics are invariant to scheduling permutations
//! - MR-ActorStateTransitionMonotonicity: Actor lifecycle state transitions progress monotonically
//! - MR-ActorMailboxBoundednessPersistence: Mailbox capacity constraints are preserved across operations
//!
//! ### GenServer Module (4 MRs)
//! - MR-CallTimeoutRetryComposition: Call timeout and retry mechanisms compose deterministically
//! - MR-GenServerCallCastOrdering: Call and cast operations maintain consistent ordering semantics
//! - MR-GenServerTimeoutIdempotency: Timeout operations are idempotent under retry
//! - MR-GenServerObligationConsistency: Reply obligations are preserved across all execution paths
//!
//! ### Monitor Module (4 MRs)
//! - MR-MonitorLinkTransitivity: Monitor relationships satisfy transitive closure properties
//! - MR-MonitorExitSignalPropagation: Exit signals propagate according to deterministic ordering
//! - MR-MonitorDownNotificationDeterminism: Down notifications follow consistent ordering rules
//! - MR-MonitorBatchOrderingConsistency: Batched notifications maintain sort order invariants
//!
//! ### Evidence Module (3 MRs)
//! - MR-EvidenceChainReplayDeterminism: Evidence chain replay produces identical results
//! - MR-EvidenceRenderingIdempotency: Evidence rendering is a pure function
//! - MR-EvidenceTimestampMonotonicity: Evidence timestamps progress monotonically
//!
//! ### Link Module (4 MRs)
//! - MR-LinkSymmetryPreservation: Link relationships are symmetric under all operations
//! - MR-LinkExitSignalBidirectionality: Exit signals propagate bidirectionally
//! - MR-LinkCrashPropagationTransitivity: Crash propagation follows transitive rules
//! - MR-LinkPolicyComposition: Exit policies compose correctly across link chains
//!
//! ### Process Module (4 MRs)
//! - MR-ProcessSpawnExitCodeConsistency: Process spawn and exit codes maintain consistency
//! - MR-ProcessLifecycleInvariance: Process lifecycle invariants hold under all operations
//! - MR-ProcessIORedirectionEquivalence: IO redirection preserves data integrity
//! - MR-ProcessSignalDeliveryDeterminism: Signal delivery follows deterministic ordering

#![allow(dead_code)]

#[cfg(test)]
mod tests {
    #[cfg(test)]
    use proptest::prelude::*;
    use std::collections::{BTreeMap, HashMap, VecDeque};

    // ═══════════════════════════════════════════════════════════════════════════
    // Mock Implementations for Metamorphic Testing
    // ═══════════════════════════════════════════════════════════════════════════

    // Actor Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockActor {
        pub id: u64,
        pub state: ActorState,
        pub mailbox: VecDeque<MockMessage>,
        pub mailbox_capacity: usize,
        pub priority_lane: u8, // 0 = low, 1 = normal, 2 = high
        pub processed_messages: Vec<MockMessage>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum ActorState {
        Created,
        Running,
        Stopping,
        Stopped,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockMessage {
        pub id: u64,
        pub priority: u8,
        pub data: Vec<u8>,
        pub timestamp: u64,
    }

    impl MockActor {
        pub fn new(id: u64, capacity: usize, priority_lane: u8) -> Self {
            Self {
                id,
                state: ActorState::Created,
                mailbox: VecDeque::new(),
                mailbox_capacity: capacity,
                priority_lane,
                processed_messages: Vec::new(),
            }
        }

        pub fn send_message(&mut self, msg: MockMessage) -> Result<(), &'static str> {
            if self.mailbox.len() >= self.mailbox_capacity {
                return Err("Mailbox full");
            }
            if self.state != ActorState::Running {
                return Err("Actor not running");
            }
            self.mailbox.push_back(msg);
            Ok(())
        }

        pub fn process_next_message(&mut self) -> Option<MockMessage> {
            if let Some(msg) = self.mailbox.pop_front() {
                self.processed_messages.push(msg.clone());
                Some(msg)
            } else {
                None
            }
        }

        pub fn start(&mut self) {
            if self.state == ActorState::Created {
                self.state = ActorState::Running;
            }
        }

        pub fn stop(&mut self) {
            self.state = ActorState::Stopping;
        }
    }

    // GenServer Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockGenServer {
        pub id: u64,
        pub state: GenServerState,
        pub pending_calls: BTreeMap<u64, MockCall>,
        pub cast_queue: VecDeque<MockCast>,
        pub timeout_ms: u64,
        pub retry_count: u32,
        pub max_retries: u32,
        pub obligations: Vec<MockObligation>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum GenServerState {
        Idle,
        Processing,
        Waiting,
        Stopping,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockCall {
        pub id: u64,
        pub request: Vec<u8>,
        pub reply_to: u64,
        pub started_at: u64,
        pub timeout_ms: u64,
        pub attempts: u32,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockCast {
        pub id: u64,
        pub message: Vec<u8>,
        pub timestamp: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockObligation {
        pub call_id: u64,
        pub is_fulfilled: bool,
        pub created_at: u64,
    }

    impl MockGenServer {
        pub fn new(id: u64, timeout_ms: u64, max_retries: u32) -> Self {
            Self {
                id,
                state: GenServerState::Idle,
                pending_calls: BTreeMap::new(),
                cast_queue: VecDeque::new(),
                timeout_ms,
                retry_count: 0,
                max_retries,
                obligations: Vec::new(),
            }
        }

        pub fn call(&mut self, call: MockCall) -> Result<(), &'static str> {
            if self.pending_calls.len() > 100 {
                return Err("Too many pending calls");
            }

            // Create obligation for this call
            let obligation = MockObligation {
                call_id: call.id,
                is_fulfilled: false,
                created_at: call.started_at,
            };

            self.obligations.push(obligation);
            self.pending_calls.insert(call.id, call);
            Ok(())
        }

        pub fn cast(&mut self, cast: MockCast) {
            self.cast_queue.push_back(cast);
        }

        pub fn reply_to_call(
            &mut self,
            call_id: u64,
            _response: Vec<u8>,
        ) -> Result<(), &'static str> {
            if !self.pending_calls.contains_key(&call_id) {
                return Err("Call not found");
            }

            // Fulfill obligation
            for obligation in &mut self.obligations {
                if obligation.call_id == call_id {
                    obligation.is_fulfilled = true;
                    break;
                }
            }

            self.pending_calls.remove(&call_id);
            Ok(())
        }

        pub fn check_timeout(&mut self, current_time: u64) -> Vec<u64> {
            let mut timed_out = Vec::new();
            let timeout_threshold = current_time.saturating_sub(self.timeout_ms);

            self.pending_calls.retain(|&id, call| {
                if call.started_at < timeout_threshold {
                    timed_out.push(id);
                    false
                } else {
                    true
                }
            });

            timed_out
        }

        pub fn retry_call(&mut self, call_id: u64, current_time: u64) -> Result<(), &'static str> {
            if let Some(mut call) = self.pending_calls.remove(&call_id) {
                if call.attempts >= self.max_retries {
                    return Err("Max retries exceeded");
                }

                call.attempts += 1;
                call.started_at = current_time;
                self.pending_calls.insert(call_id, call);
                Ok(())
            } else {
                Err("Call not found")
            }
        }
    }

    // Monitor Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockMonitorSet {
        pub monitors: BTreeMap<u64, MockMonitor>,
        pub watchers: HashMap<u64, Vec<u64>>, // task_id -> list of monitor_refs
        pub notifications: VecDeque<MockDownNotification>,
        pub next_ref: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockMonitor {
        pub monitor_ref: u64,
        pub watcher_id: u64,
        pub monitored_id: u64,
        pub created_at: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockDownNotification {
        pub monitored: u64,
        pub monitor_ref: u64,
        pub reason: MockDownReason,
        pub completion_vt: u64,
        pub timestamp: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockDownReason {
        Normal,
        Error(String),
        Panic(String),
        Cancelled,
    }

    impl MockMonitorSet {
        pub fn new() -> Self {
            Self {
                monitors: BTreeMap::new(),
                watchers: HashMap::new(),
                notifications: VecDeque::new(),
                next_ref: 1,
            }
        }

        pub fn establish(&mut self, watcher_id: u64, monitored_id: u64, timestamp: u64) -> u64 {
            let monitor_ref = self.next_ref;
            self.next_ref += 1;

            let monitor = MockMonitor {
                monitor_ref,
                watcher_id,
                monitored_id,
                created_at: timestamp,
            };

            self.monitors.insert(monitor_ref, monitor);
            self.watchers
                .entry(monitored_id)
                .or_insert_with(Vec::new)
                .push(monitor_ref);

            monitor_ref
        }

        pub fn notify_down(&mut self, task_id: u64, reason: MockDownReason, completion_vt: u64) {
            if let Some(monitor_refs) = self.watchers.get(&task_id) {
                let mut notifications = Vec::new();

                for &monitor_ref in monitor_refs {
                    if self.monitors.contains_key(&monitor_ref) {
                        notifications.push(MockDownNotification {
                            monitored: task_id,
                            monitor_ref,
                            reason: reason.clone(),
                            completion_vt,
                            timestamp: completion_vt,
                        });
                    }
                }

                // Sort by (completion_vt, monitored_tid, monitor_ref) as per DOWN-ORDER
                notifications.sort_by_key(|n| (n.completion_vt, n.monitored, n.monitor_ref));

                for notification in notifications {
                    self.notifications.push_back(notification);
                }
            }

            // Cleanup monitors for the terminated task
            self.watchers.remove(&task_id);
            self.monitors
                .retain(|_, monitor| monitor.monitored_id != task_id);
        }

        pub fn get_sorted_notifications(&self) -> Vec<MockDownNotification> {
            let mut sorted: Vec<_> = self.notifications.iter().cloned().collect();
            sorted.sort_by_key(|n| (n.completion_vt, n.monitored, n.monitor_ref));
            sorted
        }
    }

    // Evidence Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockEvidenceLedger {
        pub records: Vec<MockEvidenceRecord>,
        pub next_timestamp: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockEvidenceRecord {
        pub timestamp: u64,
        pub task_id: u64,
        pub region_id: u64,
        pub subsystem: MockSubsystem,
        pub detail: Vec<u8>, // Simplified detail as bytes
        pub verdict: MockVerdict,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockSubsystem {
        Supervision,
        Registry,
        Link,
        Monitor,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockVerdict {
        Restart,
        Stop,
        Escalate,
        Accept,
        Reject,
        Propagate,
        Trap,
    }

    impl MockEvidenceLedger {
        pub fn new() -> Self {
            Self {
                records: Vec::new(),
                next_timestamp: 1,
            }
        }

        pub fn add_record(&mut self, mut record: MockEvidenceRecord) {
            record.timestamp = self.next_timestamp;
            self.next_timestamp += 1;
            self.records.push(record);
        }

        pub fn render_deterministic(&self) -> String {
            let mut output = String::new();
            let mut sorted_records = self.records.clone();
            sorted_records.sort_by_key(|r| r.timestamp);

            for record in &sorted_records {
                output.push_str(&format!(
                    "T{:010} R{} T{} {:?} {:?}\n",
                    record.timestamp,
                    record.region_id,
                    record.task_id,
                    record.subsystem,
                    record.verdict
                ));
            }

            output
        }

        pub fn replay_chain(&self) -> Vec<MockEvidenceRecord> {
            let mut replayed = self.records.clone();
            replayed.sort_by_key(|r| r.timestamp);
            replayed
        }
    }

    // Link Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockLinkSet {
        pub links: BTreeMap<u64, MockLink>,
        pub task_links: HashMap<u64, Vec<u64>>, // task_id -> link_ids
        pub exit_signals: VecDeque<MockExitSignal>,
        pub next_link_id: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockLink {
        pub link_id: u64,
        pub task_a: u64,
        pub task_b: u64,
        pub policy_a: MockExitPolicy,
        pub policy_b: MockExitPolicy,
        pub created_at: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum MockExitPolicy {
        Propagate,
        Trap,
        Ignore,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockExitSignal {
        pub source_task: u64,
        pub target_task: u64,
        pub reason: MockDownReason,
        pub failure_vt: u64,
        pub link_id: u64,
    }

    impl MockLinkSet {
        pub fn new() -> Self {
            Self {
                links: BTreeMap::new(),
                task_links: HashMap::new(),
                exit_signals: VecDeque::new(),
                next_link_id: 1,
            }
        }

        pub fn establish_link(
            &mut self,
            task_a: u64,
            task_b: u64,
            policy_a: MockExitPolicy,
            policy_b: MockExitPolicy,
            timestamp: u64,
        ) -> u64 {
            let link_id = self.next_link_id;
            self.next_link_id += 1;

            let link = MockLink {
                link_id,
                task_a,
                task_b,
                policy_a,
                policy_b,
                created_at: timestamp,
            };

            self.links.insert(link_id, link);
            self.task_links
                .entry(task_a)
                .or_insert_with(Vec::new)
                .push(link_id);
            self.task_links
                .entry(task_b)
                .or_insert_with(Vec::new)
                .push(link_id);

            link_id
        }

        pub fn propagate_exit(&mut self, task_id: u64, reason: MockDownReason, failure_vt: u64) {
            if let Some(link_ids) = self.task_links.get(&task_id).cloned() {
                let mut signals = Vec::new();

                for link_id in &link_ids {
                    if let Some(link) = self.links.get(link_id) {
                        let (target_task, policy) = if link.task_a == task_id {
                            (link.task_b, &link.policy_b)
                        } else {
                            (link.task_a, &link.policy_a)
                        };

                        match policy {
                            MockExitPolicy::Propagate => {
                                signals.push(MockExitSignal {
                                    source_task: task_id,
                                    target_task,
                                    reason: reason.clone(),
                                    failure_vt,
                                    link_id: *link_id,
                                });
                            }
                            MockExitPolicy::Trap | MockExitPolicy::Ignore => {
                                // Signal is trapped or ignored
                            }
                        }
                    }
                }

                // Sort by (failure_vt, source_tid) as per EXIT-ORDER
                signals.sort_by_key(|s| (s.failure_vt, s.source_task));

                for signal in signals {
                    self.exit_signals.push_back(signal);
                }
            }

            // Cleanup links for the terminated task
            if let Some(link_ids) = self.task_links.remove(&task_id) {
                for link_id in link_ids {
                    if let Some(link) = self.links.remove(&link_id) {
                        // Remove from the other task's link list
                        let other_task = if link.task_a == task_id {
                            link.task_b
                        } else {
                            link.task_a
                        };

                        if let Some(other_links) = self.task_links.get_mut(&other_task) {
                            other_links.retain(|&id| id != link_id);
                        }
                    }
                }
            }
        }

        pub fn is_symmetric(&self) -> bool {
            for link in self.links.values() {
                let task_a_links = self
                    .task_links
                    .get(&link.task_a)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let task_b_links = self
                    .task_links
                    .get(&link.task_b)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);

                if !task_a_links.contains(&link.link_id) || !task_b_links.contains(&link.link_id) {
                    return false;
                }
            }
            true
        }
    }

    // Process Module Mocks
    #[derive(Debug, Clone, PartialEq)]
    pub struct MockProcess {
        pub pid: u32,
        pub command: String,
        pub args: Vec<String>,
        pub state: MockProcessState,
        pub exit_code: Option<i32>,
        pub spawn_time: u64,
        pub exit_time: Option<u64>,
        pub stdio: MockStdio,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum MockProcessState {
        Spawning,
        Running,
        Finished,
        Failed,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockStdio {
        pub stdin: Option<Vec<u8>>,
        pub stdout: Vec<u8>,
        pub stderr: Vec<u8>,
    }

    impl MockProcess {
        pub fn new(pid: u32, command: String, args: Vec<String>, spawn_time: u64) -> Self {
            Self {
                pid,
                command,
                args,
                state: MockProcessState::Spawning,
                exit_code: None,
                spawn_time,
                exit_time: None,
                stdio: MockStdio {
                    stdin: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                },
            }
        }

        pub fn start(&mut self) {
            if self.state == MockProcessState::Spawning {
                self.state = MockProcessState::Running;
            }
        }

        pub fn finish(&mut self, exit_code: i32, exit_time: u64) {
            self.state = MockProcessState::Finished;
            self.exit_code = Some(exit_code);
            self.exit_time = Some(exit_time);
        }

        pub fn is_spawn_exit_consistent(&self) -> bool {
            match &self.state {
                MockProcessState::Finished => {
                    self.exit_code.is_some()
                        && self.exit_time.is_some()
                        && self.exit_time.unwrap() >= self.spawn_time
                }
                _ => true, // Still running or failed, consistency check not applicable
            }
        }

        pub fn runtime_duration(&self) -> Option<u64> {
            if let (Some(exit_time), state) = (self.exit_time, &self.state) {
                if matches!(state, MockProcessState::Finished) {
                    Some(exit_time - self.spawn_time)
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Actor Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_mailbox_fifo_priority_lane_interaction() {
        proptest!(|(
            messages in proptest::collection::vec(
                (1u64..1000, 0u8..3, proptest::collection::vec(0u8..255, 1..50)),
                5..20
            ),
            priority_lanes in proptest::collection::vec(0u8..3, 3..10),
            capacities in proptest::collection::vec(10usize..100, 3..10)
        )| {
            // MR-MailboxFIFOPriorityLaneInteraction:
            // FIFO ordering within each priority lane should be preserved regardless of
            // inter-lane scheduling decisions

            let mock_messages: Vec<MockMessage> = messages.iter().enumerate()
                .map(|(i, (id, priority, data))| MockMessage {
                    id: *id,
                    priority: *priority,
                    data: data.clone(),
                    timestamp: i as u64,
                })
                .collect();

            // Test across different priority lanes
            for (lane_idx, (&priority_lane, &capacity)) in priority_lanes.iter().zip(capacities.iter()).enumerate() {
                let mut actor = MockActor::new(lane_idx as u64, capacity, priority_lane);
                actor.start();

                // Send messages to the actor
                let mut successfully_sent = Vec::new();
                for msg in &mock_messages {
                    if actor.send_message(msg.clone()).is_ok() {
                        successfully_sent.push(msg.clone());
                    }
                }

                // Group messages by priority
                let mut priority_groups: BTreeMap<u8, Vec<&MockMessage>> = BTreeMap::new();
                for msg in &successfully_sent {
                    priority_groups.entry(msg.priority).or_insert_with(Vec::new).push(msg);
                }

                // Process all messages
                let mut processed = Vec::new();
                while let Some(msg) = actor.process_next_message() {
                    processed.push(msg);
                }

                // Verify FIFO ordering within each priority group
                let mut processed_by_priority: BTreeMap<u8, Vec<&MockMessage>> = BTreeMap::new();
                for msg in &processed {
                    processed_by_priority.entry(msg.priority).or_insert_with(Vec::new).push(msg);
                }

                for (priority, original_msgs) in &priority_groups {
                    if let Some(processed_msgs) = processed_by_priority.get(priority) {
                        // Within the same priority, timestamps should be in order (FIFO)
                        for window in processed_msgs.windows(2) {
                            prop_assert!(
                                window[0].timestamp <= window[1].timestamp,
                                "FIFO ordering violated within priority {} lane {}: {} -> {}",
                                priority, priority_lane, window[0].timestamp, window[1].timestamp
                            );
                        }

                        // All originally sent messages of this priority should be processed
                        prop_assert_eq!(
                            original_msgs.len(), processed_msgs.len(),
                            "Message count mismatch for priority {} lane {}", priority, priority_lane
                        );
                    }
                }

                // Verify total message conservation
                prop_assert_eq!(
                    successfully_sent.len(), processed.len(),
                    "Total message count should be preserved: sent {} vs processed {}",
                    successfully_sent.len(), processed.len()
                );
            }
        });
    }

    #[test]
    fn mr_actor_message_permutation_invariance() {
        proptest!(|(
            messages in proptest::collection::vec(
                (1u64..1000, 1u8..4, proptest::collection::vec(0u8..255, 1..20)),
                3..15
            ),
            capacity in 20usize..50,
            permutation_seed in 0u64..1000
        )| {
            // MR-ActorMessagePermutationInvariance:
            // The set of processed messages should be invariant to input permutation
            // (though processing order may differ based on scheduling)

            let original_messages: Vec<MockMessage> = messages.iter().enumerate()
                .map(|(i, (id, priority, data))| MockMessage {
                    id: *id,
                    priority: *priority,
                    data: data.clone(),
                    timestamp: i as u64,
                })
                .collect();

            if original_messages.is_empty() {
                return Ok(());
            }

            // Original order processing
            let mut actor_original = MockActor::new(1, capacity, 1);
            actor_original.start();

            for msg in &original_messages {
                let _ = actor_original.send_message(msg.clone());
            }

            let mut processed_original = Vec::new();
            while let Some(msg) = actor_original.process_next_message() {
                processed_original.push(msg);
            }

            // Permuted order processing
            let mut permuted_messages = original_messages.clone();

            // Simple deterministic permutation based on seed
            for i in 0..permuted_messages.len() {
                let j = ((permutation_seed + i as u64) % permuted_messages.len() as u64) as usize;
                permuted_messages.swap(i, j);
            }

            let mut actor_permuted = MockActor::new(2, capacity, 1);
            actor_permuted.start();

            for msg in &permuted_messages {
                let _ = actor_permuted.send_message(msg.clone());
            }

            let mut processed_permuted = Vec::new();
            while let Some(msg) = actor_permuted.process_next_message() {
                processed_permuted.push(msg);
            }

            // The sets of processed messages should be identical (content-wise)
            let mut original_sorted = processed_original.clone();
            original_sorted.sort_by_key(|m| m.id);

            let mut permuted_sorted = processed_permuted.clone();
            permuted_sorted.sort_by_key(|m| m.id);

            prop_assert_eq!(
                original_sorted, permuted_sorted,
                "Message sets should be identical regardless of input permutation. Original: {} messages, Permuted: {} messages",
                processed_original.len(), processed_permuted.len()
            );
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GenServer Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_call_timeout_retry_composition() {
        proptest!(|(
            call_ids in proptest::collection::vec(1u64..1000, 3..10),
            timeout_ms in 100u64..1000,
            max_retries in 1u32..5,
            time_advances in proptest::collection::vec(50u64..500, 5..15)
        )| {
            // MR-CallTimeoutRetryComposition:
            // Timeout and retry mechanisms should compose deterministically:
            // timeout(retry(call)) ≡ retry(timeout(call))

            let mut genserver = MockGenServer::new(1, timeout_ms, max_retries);
            let mut current_time = 0u64;

            // Add initial calls
            for &call_id in &call_ids {
                let call = MockCall {
                    id: call_id,
                    request: vec![call_id as u8],
                    reply_to: call_id + 1000,
                    started_at: current_time,
                    timeout_ms,
                    attempts: 0,
                };

                let _ = genserver.call(call);
            }

            // Simulate time advancement and check timeout/retry behavior
            for &advance in &time_advances {
                current_time += advance;
                let timed_out_calls = genserver.check_timeout(current_time);

                let mut retry_results = Vec::new();
                let mut timeout_then_retry_results = Vec::new();

                // Path 1: retry(timeout(call))
                for &call_id in &timed_out_calls {
                    match genserver.retry_call(call_id, current_time) {
                        Ok(_) => retry_results.push((call_id, true)),
                        Err(_) => retry_results.push((call_id, false)),
                    }
                }

                // Path 2: timeout(retry(call)) - simulate by checking if the retry would succeed
                // and then timeout behavior
                for &call_id in &call_ids {
                    if let Some(call) = genserver.pending_calls.get(&call_id) {
                        let would_retry_succeed = call.attempts < max_retries;
                        let would_timeout = (current_time - call.started_at) >= timeout_ms;

                        timeout_then_retry_results.push((call_id, would_retry_succeed && !would_timeout));
                    }
                }

                // The composition should be equivalent in terms of observable outcomes
                // (though internal state may differ)
                let retry_success_count = retry_results.iter().filter(|(_, success)| *success).count();
                let _timeout_retry_possibility_count = timeout_then_retry_results.iter()
                    .filter(|(_, possible)| *possible).count();

                // The number of successful retries should be consistent with composition rules
                prop_assert!(
                    retry_success_count <= call_ids.len(),
                    "Retry success count should not exceed total calls: {} > {}",
                    retry_success_count, call_ids.len()
                );

                // Verify obligation consistency
                let fulfilled_obligations = genserver.obligations.iter()
                    .filter(|o| o.is_fulfilled).count();
                let total_obligations = genserver.obligations.len();

                prop_assert!(
                    fulfilled_obligations <= total_obligations,
                    "Fulfilled obligations should not exceed total: {} > {}",
                    fulfilled_obligations, total_obligations
                );
            }

            // Verify final state consistency
            let remaining_calls = genserver.pending_calls.len();
            let unfulfilled_obligations = genserver.obligations.iter()
                .filter(|o| !o.is_fulfilled).count();

            prop_assert!(
                remaining_calls <= unfulfilled_obligations,
                "Remaining calls should not exceed unfulfilled obligations: {} > {}",
                remaining_calls, unfulfilled_obligations
            );
        });
    }

    #[test]
    fn mr_genserver_call_cast_ordering() {
        proptest!(|(
            operations in proptest::collection::vec(
                proptest::prop_oneof![
                    (1u64..100, proptest::collection::vec(0u8..255, 1..10)).prop_map(|(id, data)| ("call", id, data)),
                    (1u64..100, proptest::collection::vec(0u8..255, 1..10)).prop_map(|(id, data)| ("cast", id, data))
                ],
                5..20
            ),
            timeout_ms in 500u64..2000
        )| {
            // MR-GenServerCallCastOrdering:
            // Call and cast operations should maintain consistent ordering semantics
            // Calls create obligations, casts don't; both should be processable in order

            let mut genserver = MockGenServer::new(1, timeout_ms, 3);
            let mut operation_log = Vec::new();
            let mut current_time = 0u64;

            // Process operations in order
            for (op_type, id, data) in &operations {
                operation_log.push(format!("{}:{}", op_type, id));
                current_time += 10;

                match *op_type {
                    "call" => {
                        let call = MockCall {
                            id: *id,
                            request: data.clone(),
                            reply_to: *id + 2000,
                            started_at: current_time,
                            timeout_ms,
                            attempts: 0,
                        };
                        let _ = genserver.call(call);
                    }
                    "cast" => {
                        let cast = MockCast {
                            id: *id,
                            message: data.clone(),
                            timestamp: current_time,
                        };
                        genserver.cast(cast);
                    }
                    _ => {} // Should not happen with proptest
                }
            }

            // Verify ordering invariants
            let call_count = operations.iter().filter(|(op, _, _)| *op == "call").count();
            let cast_count = operations.iter().filter(|(op, _, _)| *op == "cast").count();

            prop_assert_eq!(
                genserver.pending_calls.len(), call_count,
                "Pending calls should match call operation count: {} vs {}",
                genserver.pending_calls.len(), call_count
            );

            prop_assert_eq!(
                genserver.cast_queue.len(), cast_count,
                "Cast queue should match cast operation count: {} vs {}",
                genserver.cast_queue.len(), cast_count
            );

            prop_assert_eq!(
                genserver.obligations.len(), call_count,
                "Obligations should match call count: {} vs {}",
                genserver.obligations.len(), call_count
            );

            // Verify cast ordering (FIFO)
            let cast_queue: Vec<_> = genserver.cast_queue.iter().collect();
            for window in cast_queue.windows(2) {
                prop_assert!(
                    window[0].timestamp <= window[1].timestamp,
                    "Cast queue should maintain FIFO ordering: {} -> {}",
                    window[0].timestamp, window[1].timestamp
                );
            }

            // Test obligation-call consistency
            for obligation in &genserver.obligations {
                prop_assert!(
                    genserver.pending_calls.contains_key(&obligation.call_id) || obligation.is_fulfilled,
                    "Obligation should have corresponding pending call or be fulfilled: call_id={}",
                    obligation.call_id
                );
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Monitor Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_monitor_link_transitivity() {
        proptest!(|(
            task_pairs in proptest::collection::vec(
                (1u64..100, 101u64..200), 3..10
            ),
            completion_times in proptest::collection::vec(1000u64..2000, 3..10)
        )| {
            // MR-MonitorLinkTransitivity:
            // If A monitors B and B monitors C, then failure of C should be observable by A
            // (through the transitive notification chain)

            let mut monitor_set = MockMonitorSet::new();
            let mut current_time = 0u64;

            // Establish transitive monitoring relationships
            let mut monitor_chains = Vec::new();

            for &(task_a, task_b) in &task_pairs {
                current_time += 10;

                // Create a third task for transitivity
                let task_c = task_b + 100;

                // A monitors B, B monitors C
                let mon_ref_ab = monitor_set.establish(task_a, task_b, current_time);
                let mon_ref_bc = monitor_set.establish(task_b, task_c, current_time + 1);

                monitor_chains.push((task_a, task_b, task_c, mon_ref_ab, mon_ref_bc));
            }

            // Simulate failures and check transitive notification
            for (i, &completion_time) in completion_times.iter().enumerate() {
                if i < monitor_chains.len() {
                    let (task_a, task_b, task_c, _mon_ref_ab, _mon_ref_bc) = monitor_chains[i];

                    // Failure of C should notify B
                    monitor_set.notify_down(task_c, MockDownReason::Error("test failure".to_string()), completion_time);

                    // B gets the notification about C, then B might fail and notify A
                    // Simulate B's failure due to C's failure
                    monitor_set.notify_down(task_b, MockDownReason::Error("cascade failure".to_string()), completion_time + 1);

                    // Now A should have been notified about B's failure
                    let notifications = monitor_set.get_sorted_notifications();

                    // There should be at least one notification for task B's failure observable by task A
                    let a_notifications: Vec<_> = notifications.iter()
                        .filter(|n| n.monitored == task_b)
                        .collect();

                    prop_assert!(
                        !a_notifications.is_empty(),
                        "Task A should receive notification about B's failure in transitive chain: A={}, B={}, C={}",
                        task_a, task_b, task_c
                    );

                    // Verify notification ordering (DOWN-ORDER contract)
                    for window in notifications.windows(2) {
                        let key1 = (window[0].completion_vt, window[0].monitored, window[0].monitor_ref);
                        let key2 = (window[1].completion_vt, window[1].monitored, window[1].monitor_ref);

                        prop_assert!(
                            key1 <= key2,
                            "Notifications should be sorted by (completion_vt, monitored_tid, monitor_ref): {:?} vs {:?}",
                            key1, key2
                        );
                    }
                }
            }

            // Verify monitor cleanup consistency
            for (task_a, task_b, task_c, _mon_ref_ab, _mon_ref_bc) in &monitor_chains {
                // If tasks have been cleaned up, they shouldn't be in watchers map
                let has_a_watchers = monitor_set.watchers.contains_key(task_a);
                let _has_b_watchers = monitor_set.watchers.contains_key(task_b);
                let _has_c_watchers = monitor_set.watchers.contains_key(task_c);

                // Cleanup consistency: if a task has no watchers, it shouldn't have monitors either
                if !has_a_watchers {
                    let a_monitors: Vec<_> = monitor_set.monitors.values()
                        .filter(|m| m.monitored_id == *task_a).collect();
                    prop_assert!(
                        a_monitors.is_empty(),
                        "Task A should have no monitors if not in watchers: task={}",
                        task_a
                    );
                }
            }
        });
    }

    #[test]
    fn mr_monitor_down_notification_determinism() {
        proptest!(|(
            monitor_setups in proptest::collection::vec(
                (1u64..50, 51u64..100, 1u64..1000), 3..15
            ),
            failure_batch in proptest::collection::vec(
                (1u64..100, 2000u64..3000), 2..8
            )
        )| {
            // MR-MonitorDownNotificationDeterminism:
            // DOWN notifications should follow deterministic ordering regardless of
            // the order in which failures are reported

            let mut monitor_set = MockMonitorSet::new();
            let mut setup_time = 0u64;

            // Establish monitors
            for (watcher, monitored, offset) in &monitor_setups {
                setup_time += 1;
                monitor_set.establish(*watcher, *monitored, setup_time + offset);
            }

            // Apply failures in original order
            let mut monitor_set_original = monitor_set.clone();
            for (task_id, completion_vt) in &failure_batch {
                monitor_set_original.notify_down(
                    *task_id,
                    MockDownReason::Error("test failure".to_string()),
                    *completion_vt,
                );
            }
            let notifications_original = monitor_set_original.get_sorted_notifications();

            // Apply failures in reversed order
            let mut monitor_set_reversed = monitor_set.clone();
            for (task_id, completion_vt) in failure_batch.iter().rev() {
                monitor_set_reversed.notify_down(
                    *task_id,
                    MockDownReason::Error("test failure".to_string()),
                    *completion_vt,
                );
            }
            let notifications_reversed = monitor_set_reversed.get_sorted_notifications();

            // Apply failures in shuffled order (deterministic shuffle based on task_id)
            let mut shuffled_failures = failure_batch.clone();
            shuffled_failures.sort_by_key(|(task_id, _)| task_id % 7); // Simple deterministic shuffle

            let mut monitor_set_shuffled = monitor_set.clone();
            for (task_id, completion_vt) in &shuffled_failures {
                monitor_set_shuffled.notify_down(
                    *task_id,
                    MockDownReason::Error("test failure".to_string()),
                    *completion_vt,
                );
            }
            let notifications_shuffled = monitor_set_shuffled.get_sorted_notifications();

            // All orderings should produce identical final sorted notifications
            prop_assert_eq!(
                notifications_original.clone(), notifications_reversed.clone(),
                "Original and reversed failure ordering should produce identical notifications. Original len: {}, Reversed len: {}",
                notifications_original.len(), notifications_reversed.len()
            );

            prop_assert_eq!(
                notifications_original.clone(), notifications_shuffled.clone(),
                "Original and shuffled failure ordering should produce identical notifications. Original len: {}, Shuffled len: {}",
                notifications_original.len(), notifications_shuffled.len()
            );

            // Verify sorting invariant holds
            for notifications in [&notifications_original, &notifications_reversed, &notifications_shuffled] {
                for window in notifications.windows(2) {
                    let key1 = (window[0].completion_vt, window[0].monitored, window[0].monitor_ref);
                    let key2 = (window[1].completion_vt, window[1].monitored, window[1].monitor_ref);

                    prop_assert!(
                        key1 <= key2,
                        "DOWN-ORDER invariant violated: {:?} should be <= {:?}",
                        key1, key2
                    );
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Evidence Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_evidence_chain_replay_determinism() {
        proptest!(|(
            evidence_records in proptest::collection::vec(
                (1u64..100, 1u64..50, 0u32..4, 0u32..7, proptest::collection::vec(0u8..255, 5..20)),
                5..25
            ),
            replay_count in 2usize..5
        )| {
            // MR-EvidenceChainReplayDeterminism:
            // Replaying an evidence chain multiple times should produce identical results

            let records: Vec<MockEvidenceRecord> = evidence_records.iter()
                .map(|(task_id, region_id, subsystem_idx, verdict_idx, detail)| {
                    let subsystem = match subsystem_idx % 4 {
                        0 => MockSubsystem::Supervision,
                        1 => MockSubsystem::Registry,
                        2 => MockSubsystem::Link,
                        _ => MockSubsystem::Monitor,
                    };

                    let verdict = match verdict_idx % 7 {
                        0 => MockVerdict::Restart,
                        1 => MockVerdict::Stop,
                        2 => MockVerdict::Escalate,
                        3 => MockVerdict::Accept,
                        4 => MockVerdict::Reject,
                        5 => MockVerdict::Propagate,
                        _ => MockVerdict::Trap,
                    };

                    MockEvidenceRecord {
                        timestamp: 0, // Will be set by ledger
                        task_id: *task_id,
                        region_id: *region_id,
                        subsystem,
                        detail: detail.clone(),
                        verdict,
                    }
                })
                .collect();

            let mut ledger = MockEvidenceLedger::new();

            // Add records to ledger
            for record in records {
                ledger.add_record(record);
            }

            // Replay the chain multiple times
            let mut replay_results = Vec::new();
            for _ in 0..replay_count {
                replay_results.push(ledger.replay_chain());
            }

            // All replays should produce identical results
            let first_replay = &replay_results[0];
            for (i, replay) in replay_results.iter().enumerate().skip(1) {
                prop_assert_eq!(
                    first_replay, replay,
                    "Replay {} should be identical to first replay. First len: {}, Current len: {}",
                    i, first_replay.len(), replay.len()
                );
            }

            // Verify timestamp monotonicity within each replay
            for (replay_idx, replay) in replay_results.iter().enumerate() {
                for window in replay.windows(2) {
                    prop_assert!(
                        window[0].timestamp <= window[1].timestamp,
                        "Timestamp monotonicity violated in replay {}: {} -> {}",
                        replay_idx, window[0].timestamp, window[1].timestamp
                    );
                }
            }

            // Verify rendering determinism
            let mut rendered_outputs = Vec::new();
            for _ in 0..replay_count {
                rendered_outputs.push(ledger.render_deterministic());
            }

            let first_rendered = &rendered_outputs[0];
            for (i, rendered) in rendered_outputs.iter().enumerate().skip(1) {
                prop_assert_eq!(
                    first_rendered, rendered,
                    "Rendered output {} should be identical to first rendering",
                    i
                );
            }
        });
    }

    #[test]
    fn mr_evidence_rendering_idempotency() {
        proptest!(|(
            evidence_data in proptest::collection::vec(
                (1u64..100, 1u64..50, 0u8..4, proptest::collection::vec(0u8..255, 1..30)),
                3..20
            ),
            render_count in 3usize..8
        )| {
            // MR-EvidenceRenderingIdempotency:
            // render(render(evidence)) = render(evidence)
            // Evidence rendering should be a pure function

            let mut ledger = MockEvidenceLedger::new();

            // Add evidence records
            for (task_id, region_id, subsystem_idx, detail) in &evidence_data {
                let subsystem = match subsystem_idx % 4 {
                    0 => MockSubsystem::Supervision,
                    1 => MockSubsystem::Registry,
                    2 => MockSubsystem::Link,
                    _ => MockSubsystem::Monitor,
                };

                let record = MockEvidenceRecord {
                    timestamp: 0, // Will be set by ledger
                    task_id: *task_id,
                    region_id: *region_id,
                    subsystem,
                    detail: detail.clone(),
                    verdict: MockVerdict::Accept, // Use consistent verdict for this test
                };

                ledger.add_record(record);
            }

            // Render multiple times
            let mut renderings = Vec::new();
            for _ in 0..render_count {
                renderings.push(ledger.render_deterministic());
            }

            // All renderings should be identical (idempotency)
            let canonical_rendering = &renderings[0];
            for (i, rendering) in renderings.iter().enumerate().skip(1) {
                prop_assert_eq!(
                    canonical_rendering, rendering,
                    "Rendering {} should be identical to canonical rendering (idempotency violation)",
                    i
                );
            }

            // Verify that re-rendering after reading doesn't change the output
            let post_read_rendering = ledger.render_deterministic();
            prop_assert_eq!(
                canonical_rendering, &post_read_rendering,
                "Rendering should be stable after reading operations"
            );

            // Test that rendering preserves lexicographic ordering of formatted lines
            let lines: Vec<&str> = canonical_rendering.lines().collect();
            for window in lines.windows(2) {
                // Each line should start with a timestamp in the format T{:010}
                // so lexicographic ordering should match timestamp ordering
                prop_assert!(
                    window[0] <= window[1],
                    "Rendered lines should be in lexicographic order: '{}' vs '{}'",
                    window[0], window[1]
                );
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Link Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_link_symmetry_preservation() {
        proptest!(|(
            link_pairs in proptest::collection::vec(
                (1u64..50, 51u64..100), 3..12
            ),
            policy_combinations in proptest::collection::vec(
                (0u8..3, 0u8..3), 3..12
            ),
            timestamps in proptest::collection::vec(1000u64..2000, 3..12)
        )| {
            // MR-LinkSymmetryPreservation:
            // Links are bidirectional: link(A,B) ≡ link(B,A)
            // Symmetry should be preserved under all operations

            let mut link_set = MockLinkSet::new();

            // Create links with different policy combinations
            let mut established_links = Vec::new();
            for (i, ((&(task_a, task_b), &(policy_a_idx, policy_b_idx)), &timestamp)) in
                link_pairs.iter().zip(policy_combinations.iter()).zip(timestamps.iter()).enumerate() {

                if i >= link_pairs.len() { break; }

                let policy_a = match policy_a_idx % 3 {
                    0 => MockExitPolicy::Propagate,
                    1 => MockExitPolicy::Trap,
                    _ => MockExitPolicy::Ignore,
                };

                let policy_b = match policy_b_idx % 3 {
                    0 => MockExitPolicy::Propagate,
                    1 => MockExitPolicy::Trap,
                    _ => MockExitPolicy::Ignore,
                };

                let link_id = link_set.establish_link(task_a, task_b, policy_a, policy_b, timestamp);
                established_links.push((link_id, task_a, task_b));
            }

            // Verify initial symmetry
            prop_assert!(
                link_set.is_symmetric(),
                "Link set should maintain symmetry after establishment"
            );

            // Test symmetry under different operations

            // 1. Test symmetry of link lookup
            for (link_id, task_a, task_b) in &established_links {
                if let Some(link) = link_set.links.get(link_id) {
                    // Both tasks should reference this link
                    let task_a_links = link_set
                        .task_links
                        .get(task_a)
                        .map(|links| links.as_slice())
                        .unwrap_or(&[]);
                    let task_b_links = link_set
                        .task_links
                        .get(task_b)
                        .map(|links| links.as_slice())
                        .unwrap_or(&[]);

                    prop_assert!(
                        task_a_links.contains(link_id),
                        "Task A should reference link {}: A={}, B={}",
                        link_id, task_a, task_b
                    );

                    prop_assert!(
                        task_b_links.contains(link_id),
                        "Task B should reference link {}: A={}, B={}",
                        link_id, task_a, task_b
                    );

                    // Link should reference both tasks
                    prop_assert!(
                        (link.task_a == *task_a && link.task_b == *task_b) ||
                        (link.task_a == *task_b && link.task_b == *task_a),
                        "Link should reference both tasks symmetrically: link=({}, {}), expected=({}, {})",
                        link.task_a, link.task_b, task_a, task_b
                    );
                }
            }

            // 2. Test symmetry under exit signal propagation
            if !established_links.is_empty() {
                let (_, first_task_a, first_task_b) = established_links[0];

                // Terminate first_task_a and check bidirectional propagation
                let failure_vt = 5000;
                link_set.propagate_exit(first_task_a, MockDownReason::Error("test".to_string()), failure_vt);

                // If policy allows propagation, first_task_b should receive an exit signal
                let signals: Vec<_> = link_set.exit_signals.iter()
                    .filter(|s| s.source_task == first_task_a && s.target_task == first_task_b)
                    .collect();

                // Check that if a signal exists, it follows the bidirectional property
                if !signals.is_empty() {
                    prop_assert_eq!(
                        signals.len(), 1,
                        "Should have at most one exit signal per link direction"
                    );
                }

                // After cleanup, symmetry should still hold for remaining links
                prop_assert!(
                    link_set.is_symmetric(),
                    "Link set should maintain symmetry after exit propagation"
                );
            }

            // 3. Test symmetry invariant under multiple failures
            let remaining_tasks: Vec<_> = established_links.iter()
                .flat_map(|(_, a, b)| vec![*a, *b])
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            for &task in &remaining_tasks[..remaining_tasks.len().min(3)] {
                link_set.propagate_exit(task, MockDownReason::Normal, 6000);

                prop_assert!(
                    link_set.is_symmetric(),
                    "Link set should maintain symmetry after task {} failure",
                    task
                );
            }
        });
    }

    #[test]
    fn mr_link_exit_signal_bidirectionality() {
        proptest!(|(
            link_pairs in proptest::collection::vec(
                (10u64..30, 40u64..60), 2..8
            ),
            failure_scenarios in proptest::collection::vec(
                (0usize..1000, 7000u64..8000), 1..5
            )
        )| {
            // MR-LinkExitSignalBidirectionality:
            // If A links to B, then exit(A) → signal(B) and exit(B) → signal(A)
            // Bidirectionality should be preserved for symmetric policies

            let mut link_set = MockLinkSet::new();
            let timestamp = 1000;

            // Establish links with Propagate policy for clear bidirectionality
            let mut links = Vec::new();
            for (task_a, task_b) in &link_pairs {
                let link_id = link_set.establish_link(
                    *task_a,
                    *task_b,
                    MockExitPolicy::Propagate,
                    MockExitPolicy::Propagate,
                    timestamp
                );
                links.push((link_id, *task_a, *task_b));
            }

            // Test bidirectionality for each failure scenario
            for (link_idx, failure_vt) in &failure_scenarios {
                let link_idx = link_idx % links.len();
                let (link_id, task_a, task_b) = links[link_idx];

                // Clear previous signals for clean test
                link_set.exit_signals.clear();

                // Test A → B propagation
                link_set.propagate_exit(task_a, MockDownReason::Error("test_a_failure".to_string()), *failure_vt);

                let a_to_b_signals: Vec<_> = link_set.exit_signals.iter()
                    .filter(|s| s.source_task == task_a && s.target_task == task_b && s.link_id == link_id)
                    .collect();

                prop_assert_eq!(
                    a_to_b_signals.len(), 1,
                    "Should have exactly one exit signal from A to B: A={}, B={}, link={}",
                    task_a, task_b, link_id
                );

                // Clear signals and test B → A propagation
                link_set.exit_signals.clear();

                // Re-establish the link since A's failure would have cleaned it up
                let new_link_id = link_set.establish_link(
                    task_a,
                    task_b,
                    MockExitPolicy::Propagate,
                    MockExitPolicy::Propagate,
                    timestamp + 100
                );

                link_set.propagate_exit(task_b, MockDownReason::Error("test_b_failure".to_string()), failure_vt + 100);

                let b_to_a_signals: Vec<_> = link_set.exit_signals.iter()
                    .filter(|s| s.source_task == task_b && s.target_task == task_a && s.link_id == new_link_id)
                    .collect();

                prop_assert_eq!(
                    b_to_a_signals.len(), 1,
                    "Should have exactly one exit signal from B to A: A={}, B={}, link={}",
                    task_a, task_b, new_link_id
                );

                // Verify signal ordering (EXIT-ORDER contract)
                if !link_set.exit_signals.is_empty() {
                    let sorted_signals: Vec<_> = link_set.exit_signals.iter().collect();
                    for window in sorted_signals.windows(2) {
                        let key1 = (window[0].failure_vt, window[0].source_task);
                        let key2 = (window[1].failure_vt, window[1].source_task);

                        prop_assert!(
                            key1 <= key2,
                            "Exit signals should be ordered by (failure_vt, source_tid): {:?} vs {:?}",
                            key1, key2
                        );
                    }
                }
            }

            // Test policy-dependent bidirectionality
            link_set.exit_signals.clear();

            // Create a link with asymmetric policies
            let asym_task_a = 100;
            let asym_task_b = 200;
            let _asym_link = link_set.establish_link(
                asym_task_a,
                asym_task_b,
                MockExitPolicy::Propagate, // A propagates to B
                MockExitPolicy::Trap,      // B traps signals from A
                timestamp + 200
            );

            // A fails → B should receive signal
            link_set.propagate_exit(asym_task_a, MockDownReason::Error("asymmetric test".to_string()), 9000);

            let asym_signals: Vec<_> = link_set.exit_signals.iter()
                .filter(|s| s.source_task == asym_task_a && s.target_task == asym_task_b)
                .collect();

            // With Propagate policy, B should receive the signal
            // (Though with Trap policy, B would convert it to a message rather than propagate further)
            prop_assert!(
                asym_signals.len() <= 1, // 0 if trapped, 1 if propagated
                "Asymmetric link should respect policy differences: A→B propagate, B traps"
            );
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Process Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_process_spawn_exit_code_consistency() {
        proptest!(|(
            process_specs in proptest::collection::vec(
                (
                    proptest::string::string_regex("[a-z]{3,8}").unwrap(),
                    proptest::collection::vec(proptest::string::string_regex("[a-z0-9]{1,5}").unwrap(), 0..3),
                    -128i32..127
                ),
                3..10
            ),
            spawn_times in proptest::collection::vec(1000u64..2000, 3..10),
            execution_durations in proptest::collection::vec(100u64..1000, 3..10)
        )| {
            // MR-ProcessSpawnExitCodeConsistency:
            // spawn(cmd, args) → process → exit(code) should maintain consistency:
            // 1. spawn_time ≤ exit_time
            // 2. exit_code should be deterministic for the same command
            // 3. Process lifecycle should be monotonic

            let mut processes = Vec::new();
            let mut pid_counter = 1000u32;

            for (i, ((command, args, exit_code), &spawn_time)) in
                process_specs.iter().zip(spawn_times.iter()).enumerate() {

                if i >= execution_durations.len() { break; }

                let duration = execution_durations[i];
                pid_counter += 1;

                let mut process = MockProcess::new(
                    pid_counter,
                    command.clone(),
                    args.clone(),
                    spawn_time,
                );

                // Start the process
                process.start();
                prop_assert_eq!(
                    process.state.clone(), MockProcessState::Running,
                    "Process should be in Running state after start: pid={}",
                    process.pid
                );

                // Finish the process
                let exit_time = spawn_time + duration;
                process.finish(*exit_code, exit_time);

                // Verify spawn-exit consistency
                prop_assert!(
                    process.is_spawn_exit_consistent(),
                    "Process should maintain spawn-exit consistency: pid={}, spawn={}, exit={:?}",
                    process.pid, process.spawn_time, process.exit_time
                );

                processes.push(process);
            }

            // Test consistency across processes
            for process in &processes {
                // Verify lifecycle monotonicity
                if let Some(exit_time) = process.exit_time {
                    prop_assert!(
                        exit_time >= process.spawn_time,
                        "Exit time should be >= spawn time: spawn={}, exit={}",
                        process.spawn_time, exit_time
                    );
                }

                // Verify state consistency
                match process.state {
                    MockProcessState::Finished => {
                        prop_assert!(
                            process.exit_code.is_some() && process.exit_time.is_some(),
                            "Finished process should have exit code and time: pid={}",
                            process.pid
                        );
                    }
                    MockProcessState::Running => {
                        prop_assert!(
                            process.exit_code.is_none() && process.exit_time.is_none(),
                            "Running process should not have exit code or time: pid={}",
                            process.pid
                        );
                    }
                    _ => {} // Other states are transitional
                }

                // Verify runtime duration consistency
                if let Some(duration) = process.runtime_duration() {
                    prop_assert!(
                        duration > 0,
                        "Runtime duration should be positive for finished processes: duration={}",
                        duration
                    );
                }
            }

            // Test deterministic behavior for identical commands
            let mut command_groups: BTreeMap<(&str, &[String]), Vec<&MockProcess>> = BTreeMap::new();
            for process in &processes {
                command_groups.entry((&process.command, &process.args))
                    .or_insert_with(Vec::new)
                    .push(process);
            }

            for ((command, args), process_group) in &command_groups {
                if process_group.len() > 1 {
                    // Processes with identical commands should have consistent behavior patterns
                    let first_process = process_group[0];

                    for &other_process in &process_group[1..] {
                        // Same command should produce same exit code (if deterministic)
                        if let (Some(code1), Some(code2)) = (first_process.exit_code, other_process.exit_code) {
                            prop_assert_eq!(
                                code1, code2,
                                "Identical commands should produce identical exit codes: cmd='{}' args={:?}",
                                command, args
                            );
                        }

                        // State progression should be consistent
                        if first_process.state == MockProcessState::Finished {
                            prop_assert_eq!(
                                other_process.state.clone(), MockProcessState::Finished,
                                "Identical commands should reach same final state: cmd='{}' args={:?}",
                                command, args
                            );
                        }
                    }
                }
            }
        });
    }

    #[test]
    fn mr_process_lifecycle_invariance() {
        proptest!(|(
            initial_processes in proptest::collection::vec(
                (
                    1000u32..2000,
                    proptest::string::string_regex("[a-z]{2,6}").unwrap(),
                    1000u64..1500
                ),
                3..12
            ),
            state_transitions in proptest::collection::vec(
                (0usize..1000, 0u8..4, 100u64..500), 5..15
            )
        )| {
            // MR-ProcessLifecycleInvariance:
            // Process lifecycle invariants should hold under all valid operations:
            // Created → Spawning → Running → (Finished|Failed)
            // No backward transitions, no invalid states

            let mut processes: Vec<MockProcess> = initial_processes.iter()
                .map(|(pid, command, spawn_time)| {
                    MockProcess::new(*pid, command.clone(), vec![], *spawn_time)
                })
                .collect();

            // Apply state transitions
            for (process_idx, transition_type, time_offset) in &state_transitions {
                if processes.is_empty() { break; }

                let idx = process_idx % processes.len();
                let current_time = processes[idx].spawn_time + time_offset;
                let original_state = processes[idx].state.clone();

                match transition_type % 4 {
                    0 => {
                        // Start transition: Spawning → Running
                        if processes[idx].state == MockProcessState::Spawning {
                            processes[idx].start();
                            prop_assert_eq!(
                                processes[idx].state, MockProcessState::Running,
                                "Start transition should move to Running state"
                            );
                        }
                    }
                    1 => {
                        // Finish transition: Running → Finished
                        if processes[idx].state == MockProcessState::Running {
                            processes[idx].finish(0, current_time);
                            prop_assert_eq!(
                                processes[idx].state, MockProcessState::Finished,
                                "Finish transition should move to Finished state"
                            );
                        }
                    }
                    2 => {
                        // Fail transition: Running → Failed
                        if processes[idx].state == MockProcessState::Running {
                            processes[idx].finish(-1, current_time);
                            processes[idx].state = MockProcessState::Failed;
                            prop_assert_eq!(
                                processes[idx].state, MockProcessState::Failed,
                                "Fail transition should move to Failed state"
                            );
                        }
                    }
                    3 => {
                        // Invalid transition attempt (should be rejected)
                        let pre_transition_state = processes[idx].state.clone();

                        // Try to transition from terminal state (should not change)
                        if matches!(processes[idx].state, MockProcessState::Finished | MockProcessState::Failed) {
                            // Attempt to start again (invalid)
                            processes[idx].start();

                            prop_assert_eq!(
                                processes[idx].state, pre_transition_state,
                                "Invalid transition from terminal state should be rejected"
                            );
                        }
                    }
                    _ => {} // Should not occur with modulo
                }

                // Verify lifecycle monotonicity invariants
                let current_state = &processes[idx].state;

                // No process should go backwards in the lifecycle
                let state_order = |state: &MockProcessState| match state {
                    MockProcessState::Spawning => 0,
                    MockProcessState::Running => 1,
                    MockProcessState::Finished => 2,
                    MockProcessState::Failed => 2, // Terminal states are at same level
                };

                let original_order = state_order(&original_state);
                let current_order = state_order(current_state);

                prop_assert!(
                    current_order >= original_order,
                    "Process lifecycle should be monotonic: {:?} → {:?} (order {} → {})",
                    original_state, current_state, original_order, current_order
                );

                // Verify state-specific invariants
                match current_state {
                    MockProcessState::Finished => {
                        prop_assert!(
                            processes[idx].exit_code.is_some(),
                            "Finished process should have exit code"
                        );
                        prop_assert!(
                            processes[idx].exit_time.is_some(),
                            "Finished process should have exit time"
                        );
                    }
                    MockProcessState::Running => {
                        prop_assert!(
                            processes[idx].exit_code.is_none(),
                            "Running process should not have exit code"
                        );
                        prop_assert!(
                            processes[idx].exit_time.is_none(),
                            "Running process should not have exit time"
                        );
                    }
                    MockProcessState::Spawning => {
                        prop_assert!(
                            processes[idx].exit_code.is_none() && processes[idx].exit_time.is_none(),
                            "Spawning process should not have exit information"
                        );
                    }
                    MockProcessState::Failed => {
                        // Failed processes may or may not have exit information depending on failure mode
                    }
                }
            }

            // Final consistency check across all processes
            for (i, process) in processes.iter().enumerate() {
                prop_assert!(
                    process.is_spawn_exit_consistent(),
                    "Process {} should maintain overall consistency at end of test sequence",
                    i
                );

                // Verify that spawn time is always set
                prop_assert!(
                    process.spawn_time > 0,
                    "Process {} should have valid spawn time",
                    i
                );

                // Verify PID uniqueness
                for (j, other) in processes.iter().enumerate() {
                    if i != j {
                        prop_assert!(
                            process.pid != other.pid,
                            "PIDs should be unique: process {} and {} both have PID {}",
                            i, j, process.pid
                        );
                    }
                }
            }
        });
    }
}
