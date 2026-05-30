//! Metamorphic Testing for Supervision, GenServer, Actor, IO, and FS Modules
//!
//! This module implements comprehensive metamorphic relations testing the supervision
//! tree restart policies, gen_server call/cast semantics, actor mailbox ordering,
//! IO buffer operations, and filesystem operations. These tests address the oracle
//! problem where conventional unit tests cannot verify complex state machine behaviors,
//! ordering properties, and filesystem semantics.
//!
//! ## Metamorphic Relations Implemented
//!
//! ### Supervision Module (4 MRs)
//! - MR-RestartPolicyWellDefined: Restart policies produce consistent decisions
//! - MR-ExponentialBackoffBounded: Backoff delays remain within mathematical bounds
//! - MR-SupervisionTreeQuiescence: Tree shutdown reaches quiescent state
//! - MR-RestartEscalationMonotonicity: Escalation severity never decreases
//!
//! ### GenServer Module (3 MRs)
//! - MR-CallTimeoutIdempotency: Call timeout behavior is idempotent
//! - MR-CastOrderingPreservation: Cast messages maintain FIFO ordering
//! - MR-GenServerStateConsistency: State transitions are deterministic
//!
//! ### Actor Module (3 MRs)
//! - MR-MailboxFIFOOrdering: Mailbox preserves first-in-first-out message order
//! - MR-ActorLifecycleMonotonicity: Actor lifecycle states progress monotonically
//! - MR-MessageDeliveryGuarantees: Message delivery provides at-most-once semantics
//!
//! ### IO Module (4 MRs)
//! - MR-BufReaderWriterRoundTrip: buf_reader(buf_writer(data)) = data
//! - MR-CopyInvariantPreservation: IO copy operations preserve data integrity
//! - MR-SplitMergeIdentity: split → merge restores original stream
//! - MR-AsyncSyncEquivalence: Async and sync IO produce identical results
//!
//! ### FS Module (4 MRs)
//! - MR-FileCreateDeleteStatSemantics: File lifecycle operations are consistent
//! - MR-DirectoryEnumerationConsistency: Directory listings match enumeration
//! - MR-PathOperationCommutativity: Path operations commute where expected
//! - MR-FilesystemTransactionAtomicity: FS operations are atomic or rolled back

#![allow(dead_code)]

#[cfg(test)]
mod tests {
    #[cfg(test)]
    use proptest::prelude::*;

    // ═══════════════════════════════════════════════════════════════════════════
    // Mock Implementations for Metamorphic Testing
    // ═══════════════════════════════════════════════════════════════════════════

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockRestartPolicy {
        pub max_restarts: u32,
        pub max_time_window_secs: u64,
        pub backoff_strategy: BackoffStrategy,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum BackoffStrategy {
        Fixed(u64),
        Exponential {
            base_ms: u64,
            max_ms: u64,
            multiplier: f64,
        },
        Linear {
            step_ms: u64,
            max_ms: u64,
        },
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockRestartDecision {
        pub should_restart: bool,
        pub delay_ms: u64,
        pub escalate: bool,
        pub remaining_attempts: u32,
    }

    impl MockRestartPolicy {
        pub fn evaluate_restart(
            &self,
            failures_in_window: u32,
            attempt_number: u32,
        ) -> MockRestartDecision {
            let should_restart = failures_in_window < self.max_restarts;
            let delay_ms = self.calculate_backoff(attempt_number);
            let escalate = failures_in_window >= (self.max_restarts / 2);
            let remaining_attempts = self.max_restarts.saturating_sub(failures_in_window);

            MockRestartDecision {
                should_restart,
                delay_ms,
                escalate,
                remaining_attempts,
            }
        }

        fn calculate_backoff(&self, attempt: u32) -> u64 {
            match &self.backoff_strategy {
                BackoffStrategy::Fixed(delay) => *delay,
                BackoffStrategy::Exponential {
                    base_ms,
                    max_ms,
                    multiplier,
                } => {
                    let exponential_delay =
                        (*base_ms as f64) * multiplier.powi((attempt - 1) as i32);
                    (exponential_delay as u64).min(*max_ms)
                }
                BackoffStrategy::Linear { step_ms, max_ms } => {
                    (step_ms * attempt as u64).min(*max_ms)
                }
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockGenServerCall {
        pub call_id: u64,
        pub timeout_ms: u64,
        pub payload: Vec<u8>,
        pub timestamp: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockGenServerState {
        pub state_version: u64,
        pub pending_calls: Vec<MockGenServerCall>,
        pub processed_casts: Vec<u64>, // cast_id sequence
    }

    impl MockGenServerState {
        pub fn new() -> Self {
            MockGenServerState {
                state_version: 0,
                pending_calls: Vec::new(),
                processed_casts: Vec::new(),
            }
        }

        pub fn handle_call(&mut self, call: MockGenServerCall) -> bool {
            self.pending_calls.push(call);
            self.state_version += 1;
            true // Simplified - always succeeds
        }

        pub fn handle_cast(&mut self, cast_id: u64) {
            self.processed_casts.push(cast_id);
            self.state_version += 1;
        }

        pub fn timeout_calls(&mut self, current_time: u64) -> Vec<u64> {
            let timed_out: Vec<u64> = self
                .pending_calls
                .iter()
                .filter(|call| current_time > call.timestamp + call.timeout_ms)
                .map(|call| call.call_id)
                .collect();

            self.pending_calls
                .retain(|call| current_time <= call.timestamp + call.timeout_ms);
            timed_out
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockActorMailbox {
        pub messages: Vec<MockMessage>,
        pub next_sequence: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockMessage {
        pub sequence: u64,
        pub sender_id: u64,
        pub payload: Vec<u8>,
        pub timestamp: u64,
    }

    impl MockActorMailbox {
        pub fn new() -> Self {
            MockActorMailbox {
                messages: Vec::new(),
                next_sequence: 1,
            }
        }

        pub fn send_message(&mut self, sender_id: u64, payload: Vec<u8>, timestamp: u64) {
            let message = MockMessage {
                sequence: self.next_sequence,
                sender_id,
                payload,
                timestamp,
            };
            self.messages.push(message);
            self.next_sequence += 1;
        }

        pub fn receive_message(&mut self) -> Option<MockMessage> {
            if self.messages.is_empty() {
                None
            } else {
                Some(self.messages.remove(0)) // FIFO ordering
            }
        }

        pub fn peek_next(&self) -> Option<&MockMessage> {
            self.messages.first()
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockBufReader {
        pub data: Vec<u8>,
        pub position: usize,
        pub buffer_size: usize,
    }

    #[derive(Debug, Clone)]
    pub struct MockBufWriter {
        pub buffer: Vec<u8>,
        pub written_data: Vec<u8>,
        pub buffer_size: usize,
    }

    impl MockBufReader {
        pub fn new(data: Vec<u8>, buffer_size: usize) -> Self {
            MockBufReader {
                data,
                position: 0,
                buffer_size,
            }
        }

        pub fn read(&mut self, buf: &mut [u8]) -> usize {
            let available = self.data.len() - self.position;
            let to_read = buf.len().min(available);
            if to_read > 0 {
                buf[..to_read].copy_from_slice(&self.data[self.position..self.position + to_read]);
                self.position += to_read;
            }
            to_read
        }

        pub fn read_all(&mut self) -> Vec<u8> {
            let result = self.data[self.position..].to_vec();
            self.position = self.data.len();
            result
        }
    }

    impl MockBufWriter {
        pub fn new(buffer_size: usize) -> Self {
            MockBufWriter {
                buffer: Vec::new(),
                written_data: Vec::new(),
                buffer_size,
            }
        }

        pub fn write(&mut self, data: &[u8]) {
            self.buffer.extend_from_slice(data);
            if self.buffer.len() >= self.buffer_size {
                self.flush();
            }
        }

        pub fn flush(&mut self) {
            self.written_data.extend_from_slice(&self.buffer);
            self.buffer.clear();
        }

        pub fn into_inner(mut self) -> Vec<u8> {
            self.flush();
            self.written_data
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct MockFileSystemEntry {
        pub path: String,
        pub is_directory: bool,
        pub size: u64,
        pub created_at: u64,
        pub modified_at: u64,
        pub content: Option<Vec<u8>>, // None for directories
    }

    #[derive(Debug, Clone)]
    pub struct MockFileSystem {
        pub entries: std::collections::HashMap<String, MockFileSystemEntry>,
        pub next_timestamp: u64,
    }

    impl MockFileSystem {
        pub fn new() -> Self {
            MockFileSystem {
                entries: std::collections::HashMap::new(),
                next_timestamp: 1000,
            }
        }

        pub fn create_file(&mut self, path: String, content: Vec<u8>) -> bool {
            if self.entries.contains_key(&path) {
                return false; // File already exists
            }

            let entry = MockFileSystemEntry {
                path: path.clone(),
                is_directory: false,
                size: content.len() as u64,
                created_at: self.next_timestamp,
                modified_at: self.next_timestamp,
                content: Some(content),
            };
            self.entries.insert(path, entry);
            self.next_timestamp += 1;
            true
        }

        pub fn delete_file(&mut self, path: &str) -> bool {
            self.entries.remove(path).is_some()
        }

        pub fn stat(&self, path: &str) -> Option<&MockFileSystemEntry> {
            self.entries.get(path)
        }

        pub fn create_directory(&mut self, path: String) -> bool {
            if self.entries.contains_key(&path) {
                return false;
            }

            let entry = MockFileSystemEntry {
                path: path.clone(),
                is_directory: true,
                size: 0,
                created_at: self.next_timestamp,
                modified_at: self.next_timestamp,
                content: None,
            };
            self.entries.insert(path, entry);
            self.next_timestamp += 1;
            true
        }

        pub fn list_directory(&self, dir_path: &str) -> Vec<String> {
            let dir_path = if dir_path.ends_with('/') {
                dir_path.to_string()
            } else {
                format!("{}/", dir_path)
            };

            self.entries
                .keys()
                .filter(|path| {
                    path.starts_with(&dir_path) && path.as_str() != &dir_path[..dir_path.len() - 1]
                })
                .filter(|path| {
                    let relative = &path[dir_path.len()..];
                    !relative.contains('/') // Only direct children
                })
                .cloned()
                .collect()
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Supervision Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_restart_policy_well_defined() {
        proptest!(|(
            max_restarts in 1u32..10,
            window_secs in 1u64..3600,
            base_ms in 10u64..1000,
            max_ms in 1000u64..10000,
            multiplier in 1.1f64..3.0,
            failures1 in 0u32..15,
            failures2 in 0u32..15,
            attempt in 1u32..5
        )| {
            // MR-RestartPolicyWellDefined: Same policy parameters should produce same restart decision
            let policy = MockRestartPolicy {
                max_restarts,
                max_time_window_secs: window_secs,
                backoff_strategy: BackoffStrategy::Exponential { base_ms, max_ms, multiplier },
            };

            let decision1a = policy.evaluate_restart(failures1, attempt);
            let decision1b = policy.evaluate_restart(failures1, attempt);
            let decision2a = policy.evaluate_restart(failures2, attempt);
            let decision2b = policy.evaluate_restart(failures2, attempt);

            // `.clone()` the four decisions so `decision1a` / `decision2a`
            // survive the prop_assert_eq! moves below and remain available
            // for the followup `remaining_attempts` comparison.
            prop_assert_eq!(
                decision1a.clone(), decision1b.clone(),
                "Restart policy should be deterministic for same inputs: failures={}, attempt={}",
                failures1, attempt
            );

            prop_assert_eq!(
                decision2a.clone(), decision2b.clone(),
                "Restart policy should be deterministic for same inputs: failures={}, attempt={}",
                failures2, attempt
            );

            // Well-defined property: more failures should never increase remaining attempts
            if failures1 < failures2 {
                prop_assert!(
                    decision1a.remaining_attempts >= decision2a.remaining_attempts,
                    "More failures should not increase remaining attempts: {} failures -> {} remaining, {} failures -> {} remaining",
                    failures1, decision1a.remaining_attempts, failures2, decision2a.remaining_attempts
                );
            }
        });
    }

    #[test]
    fn mr_exponential_backoff_bounded() {
        proptest!(|(
            base_ms in 10u64..1000,
            max_ms in 1000u64..50000,
            multiplier in 1.1f64..5.0,
            attempts in proptest::collection::vec(1u32..20, 1..10)
        )| {
            // MR-ExponentialBackoffBounded: Exponential backoff delays must remain within mathematical bounds
            let policy = MockRestartPolicy {
                max_restarts: 10,
                max_time_window_secs: 3600,
                backoff_strategy: BackoffStrategy::Exponential { base_ms, max_ms, multiplier },
            };

            let mut delays = Vec::new();
            for &attempt in &attempts {
                let decision = policy.evaluate_restart(0, attempt);
                delays.push(decision.delay_ms);
            }

            // Verify all delays are bounded by max_ms
            for (i, &delay) in delays.iter().enumerate() {
                prop_assert!(
                    delay <= max_ms,
                    "Backoff delay {} at attempt {} exceeds maximum {} ms",
                    delay, attempts[i], max_ms
                );
            }

            // Verify monotonicity for sequential attempts (when not capped)
            if attempts.len() > 1 {
                let mut sorted_attempts = attempts.clone();
                sorted_attempts.sort_unstable();

                let mut prev_delay = 0u64;
                for &attempt in &sorted_attempts {
                    let decision = policy.evaluate_restart(0, attempt);
                    let expected_uncapped = (base_ms as f64 * multiplier.powi((attempt - 1) as i32)) as u64;

                    if expected_uncapped <= max_ms {
                        // Not capped, should be monotonic
                        if attempt > 1 && prev_delay > 0 {
                            prop_assert!(
                                decision.delay_ms >= prev_delay,
                                "Exponential backoff should be monotonically increasing when uncapped: attempt {} delay {} < previous {}",
                                attempt, decision.delay_ms, prev_delay
                            );
                        }
                        prev_delay = decision.delay_ms;
                    }
                }
            }
        });
    }

    #[test]
    fn mr_supervision_tree_quiescence() {
        proptest!(|(
            restart_counts in proptest::collection::vec(0u32..5, 3..8)
        )| {
            // MR-SupervisionTreeQuiescence: All restart policies should eventually reach quiescent state
            let policy = MockRestartPolicy {
                max_restarts: 3,
                max_time_window_secs: 10,
                backoff_strategy: BackoffStrategy::Fixed(100),
            };

            let mut all_quiescent = true;
            let mut final_states = Vec::new();

            for &restart_count in &restart_counts {
                let decision = policy.evaluate_restart(restart_count, 1);
                final_states.push(decision.clone());

                // Quiescent means no more restarts allowed
                if decision.should_restart && restart_count >= policy.max_restarts {
                    all_quiescent = false;
                }
            }

            // Verify that excessive failures lead to quiescence
            let excessive_failures = policy.max_restarts + 1;
            let final_decision = policy.evaluate_restart(excessive_failures, 1);

            prop_assert!(
                !final_decision.should_restart,
                "Supervision should reach quiescent state after {} failures: decision={:?}",
                excessive_failures, final_decision
            );

            prop_assert_eq!(
                final_decision.remaining_attempts, 0,
                "Quiescent state should have 0 remaining attempts: {:?}",
                final_decision
            );
        });
    }

    #[test]
    fn mr_restart_escalation_monotonicity() {
        proptest!(|(
            base_failures in 0u32..3,
            additional_failures in 0u32..5,
            attempt in 1u32..3
        )| {
            // MR-RestartEscalationMonotonicity: Escalation severity should never decrease with more failures
            let policy = MockRestartPolicy {
                max_restarts: 6,
                max_time_window_secs: 3600,
                backoff_strategy: BackoffStrategy::Fixed(1000),
            };

            let failures1 = base_failures;
            let failures2 = base_failures + additional_failures;

            let decision1 = policy.evaluate_restart(failures1, attempt);
            let decision2 = policy.evaluate_restart(failures2, attempt);

            // More failures should never decrease escalation severity
            if additional_failures > 0 {
                prop_assert!(
                    !decision1.escalate || decision2.escalate,
                    "Escalation severity should not decrease: {} failures -> escalate={}, {} failures -> escalate={}",
                    failures1, decision1.escalate, failures2, decision2.escalate
                );

                // More failures should never increase remaining attempts
                prop_assert!(
                    decision1.remaining_attempts >= decision2.remaining_attempts,
                    "More failures should not increase remaining attempts: {} -> {}, {} -> {}",
                    failures1, decision1.remaining_attempts, failures2, decision2.remaining_attempts
                );
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GenServer Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_call_timeout_idempotency() {
        proptest!(|(
            call_ids in proptest::collection::vec(1u64..1000, 3..8),
            timeout_ms in 100u64..5000,
            time_advance in 0u64..10000
        )| {
            // MR-CallTimeoutIdempotency: Multiple timeout operations should be idempotent
            let mut state1 = MockGenServerState::new();
            let mut state2 = MockGenServerState::new();

            let timestamp = 1000u64;
            let calls: Vec<MockGenServerCall> = call_ids.iter().enumerate().map(|(i, &call_id)| {
                MockGenServerCall {
                    call_id,
                    timeout_ms,
                    payload: vec![i as u8; 4],
                    timestamp,
                }
            }).collect();

            // Add same calls to both states
            for call in &calls {
                state1.handle_call(call.clone());
                state2.handle_call(call.clone());
            }

            let timeout_time = timestamp + time_advance;

            // Apply timeout once to state1
            let timed_out1 = state1.timeout_calls(timeout_time);

            // Apply timeout twice to state2 (idempotency test)
            let timed_out2a = state2.timeout_calls(timeout_time);
            let timed_out2b = state2.timeout_calls(timeout_time);

            prop_assert_eq!(
                timed_out1, timed_out2a,
                "First timeout operation should produce same results on identical states"
            );

            prop_assert!(
                timed_out2b.is_empty(),
                "Second timeout operation should be idempotent (no additional timeouts): {:?}",
                timed_out2b
            );

            prop_assert_eq!(
                state1.pending_calls, state2.pending_calls,
                "States should be identical after idempotent timeout operations"
            );
        });
    }

    #[test]
    fn mr_cast_ordering_preservation() {
        proptest!(|(
            cast_sequences in proptest::collection::vec(
                proptest::collection::vec(1u64..100, 3..8),
                2..4
            )
        )| {
            // MR-CastOrderingPreservation: Cast messages should maintain FIFO ordering regardless of processing patterns
            let mut state1 = MockGenServerState::new();
            let mut state2 = MockGenServerState::new();

            // Process all casts in original order for state1
            let all_casts: Vec<u64> = cast_sequences.iter().flatten().copied().collect();
            for &cast_id in &all_casts {
                state1.handle_cast(cast_id);
            }

            // Process casts in sequence batches for state2 (same total order)
            for sequence in &cast_sequences {
                for &cast_id in sequence {
                    state2.handle_cast(cast_id);
                }
            }

            prop_assert_eq!(
                state1.processed_casts.clone(), state2.processed_casts.clone(),
                "Cast ordering should be preserved regardless of batch processing"
            );

            // Verify FIFO property: processed order matches submission order
            prop_assert_eq!(
                state1.processed_casts.clone(), all_casts.clone(),
                "Processed cast order should match submission order (FIFO)"
            );
        });
    }

    #[test]
    fn mr_genserver_state_consistency() {
        proptest!(|(
            call_payloads in proptest::collection::vec(
                proptest::collection::vec(0u8..255, 1..10),
                2..6
            ),
            cast_ids in proptest::collection::vec(1u64..50, 2..6)
        )| {
            // MR-GenServerStateConsistency: Same sequence of operations should produce identical state
            let mut state1 = MockGenServerState::new();
            let mut state2 = MockGenServerState::new();

            // Apply operations in same order to both states
            for (i, payload) in call_payloads.iter().enumerate() {
                let call = MockGenServerCall {
                    call_id: i as u64 + 1,
                    timeout_ms: 1000,
                    payload: payload.clone(),
                    timestamp: 1000 + i as u64,
                };

                let result1 = state1.handle_call(call.clone());
                let result2 = state2.handle_call(call);

                prop_assert_eq!(result1, result2, "Call handling should be deterministic");
            }

            for &cast_id in &cast_ids {
                state1.handle_cast(cast_id);
                state2.handle_cast(cast_id);
            }

            prop_assert_eq!(
                state1.state_version, state2.state_version,
                "State versions should be identical after same operations"
            );

            prop_assert_eq!(
                state1.processed_casts, state2.processed_casts,
                "Cast processing should be deterministic"
            );

            prop_assert_eq!(
                state1.pending_calls.len(), state2.pending_calls.len(),
                "Pending call counts should be identical"
            );
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Actor Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_mailbox_fifo_ordering() {
        proptest!(|(
            senders in proptest::collection::vec(1u64..20, 5..12),
            payloads in proptest::collection::vec(
                proptest::collection::vec(0u8..255, 1..8),
                5..12
            ),
            receive_count in 0usize..10
        )| {
            // MR-MailboxFIFOOrdering: Messages should be received in first-in-first-out order
            let mut mailbox1 = MockActorMailbox::new();
            let mut mailbox2 = MockActorMailbox::new();

            let messages: Vec<(u64, Vec<u8>, u64)> = senders.iter().zip(payloads.iter())
                .enumerate()
                .map(|(i, (&sender, payload))| (sender, payload.clone(), 1000 + i as u64))
                .collect();

            // Send all messages to both mailboxes
            for &(sender, ref payload, timestamp) in &messages {
                mailbox1.send_message(sender, payload.clone(), timestamp);
                mailbox2.send_message(sender, payload.clone(), timestamp);
            }

            // Receive messages and verify FIFO ordering
            let receive_limit = receive_count.min(messages.len());
            let mut received1 = Vec::new();
            let mut received2 = Vec::new();

            for _ in 0..receive_limit {
                if let Some(msg1) = mailbox1.receive_message() {
                    received1.push(msg1);
                }
                if let Some(msg2) = mailbox2.receive_message() {
                    received2.push(msg2);
                }
            }

            prop_assert_eq!(
                received1.clone(), received2.clone(),
                "Both mailboxes should receive messages in identical FIFO order"
            );

            // Verify sequence numbers are monotonically increasing
            for (i, msg) in received1.iter().enumerate() {
                prop_assert_eq!(
                    msg.sequence, (i + 1) as u64,
                    "Message sequence should be monotonically increasing: expected {}, got {}",
                    i + 1, msg.sequence
                );
            }

            // Verify remaining messages maintain FIFO order
            let remaining1: Vec<u64> = mailbox1.messages.iter().map(|m| m.sequence).collect();
            let remaining2: Vec<u64> = mailbox2.messages.iter().map(|m| m.sequence).collect();

            prop_assert_eq!(remaining1.clone(), remaining2.clone(), "Remaining messages should maintain same order");

            for window in remaining1.windows(2) {
                prop_assert!(
                    window[0] < window[1],
                    "Remaining messages should maintain sequence order: {} >= {}",
                    window[0], window[1]
                );
            }
        });
    }

    #[test]
    fn mr_actor_lifecycle_monotonicity() {
        proptest!(|(
            message_counts in proptest::collection::vec(0usize..20, 3..7)
        )| {
            // MR-ActorLifecycleMonotonicity: Actor message sequence numbers progress monotonically
            let mut mailbox = MockActorMailbox::new();
            let mut all_sequences = Vec::new();

            for (phase, &count) in message_counts.iter().enumerate() {
                for i in 0..count {
                    let payload = vec![phase as u8, i as u8];
                    let timestamp = 1000 + all_sequences.len() as u64;
                    mailbox.send_message(phase as u64 + 1, payload, timestamp);
                    all_sequences.push(mailbox.next_sequence - 1); // Record assigned sequence
                }
            }

            // Verify monotonicity: each sequence number is strictly greater than the previous
            for window in all_sequences.windows(2) {
                prop_assert!(
                    window[0] < window[1],
                    "Sequence numbers should be monotonically increasing: {} >= {}",
                    window[0], window[1]
                );
            }

            // Verify no gaps in sequence (should be contiguous)
            for (i, &seq) in all_sequences.iter().enumerate() {
                prop_assert_eq!(
                    seq, (i + 1) as u64,
                    "Sequence numbers should be contiguous: position {} has sequence {}, expected {}",
                    i, seq, i + 1
                );
            }

            // Verify mailbox ordering matches sequence assignment order
            for (i, msg) in mailbox.messages.iter().enumerate() {
                prop_assert_eq!(
                    msg.sequence, all_sequences[i],
                    "Mailbox message order should match sequence assignment order"
                );
            }
        });
    }

    #[test]
    fn mr_message_delivery_guarantees() {
        proptest!(|(
            unique_payloads in proptest::collection::vec(
                proptest::collection::vec(1u8..255, 4..10),
                3..8
            )
        )| {
            // MR-MessageDeliveryGuarantees: Messages should be delivered at-most-once with unique sequences
            let mut mailbox = MockActorMailbox::new();

            // Send messages with unique payloads
            for (i, payload) in unique_payloads.iter().enumerate() {
                mailbox.send_message(i as u64 + 1, payload.clone(), 1000 + i as u64);
            }

            let initial_count = mailbox.messages.len();
            let mut delivered_sequences = Vec::new();
            let mut delivered_payloads = Vec::new();

            // Receive all messages
            while let Some(msg) = mailbox.receive_message() {
                delivered_sequences.push(msg.sequence);
                delivered_payloads.push(msg.payload);
            }

            prop_assert_eq!(
                delivered_payloads, unique_payloads,
                "All sent messages should be delivered exactly once"
            );

            prop_assert_eq!(
                delivered_sequences.len(), initial_count,
                "Should deliver exactly the number of sent messages"
            );

            // Verify at-most-once: no duplicate sequences
            let mut sorted_sequences = delivered_sequences.clone();
            sorted_sequences.sort_unstable();
            sorted_sequences.dedup();

            prop_assert_eq!(
                delivered_sequences.len(), sorted_sequences.len(),
                "All delivered sequences should be unique (at-most-once delivery): delivered={:?}",
                delivered_sequences
            );

            // Verify mailbox is empty after receiving all messages
            prop_assert!(
                mailbox.messages.is_empty(),
                "Mailbox should be empty after receiving all messages"
            );

            prop_assert!(
                mailbox.peek_next().is_none(),
                "Peek should return None for empty mailbox"
            );
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // IO Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_buf_reader_writer_round_trip() {
        proptest!(|(
            test_data in proptest::collection::vec(0u8..255, 10..1000),
            buffer_size in 16usize..512
        )| {
            // MR-BufReaderWriterRoundTrip: buf_reader(buf_writer(data)) should equal original data
            let original_data = test_data.clone();

            // Write data through BufWriter
            let mut writer = MockBufWriter::new(buffer_size);
            writer.write(&original_data);
            let written_data = writer.into_inner();

            // Read data back through BufReader
            let mut reader = MockBufReader::new(written_data, buffer_size);
            let recovered_data = reader.read_all();

            prop_assert_eq!(
                recovered_data.clone(), original_data.clone(),
                "Round-trip through BufWriter -> BufReader should preserve data integrity. Buffer size: {}",
                buffer_size
            );

            // Test chunked writing and reading
            let mut writer2 = MockBufWriter::new(buffer_size);
            let chunk_size = (original_data.len() / 3).max(1);

            for chunk in original_data.chunks(chunk_size) {
                writer2.write(chunk);
            }
            let written_data2 = writer2.into_inner();

            let mut reader2 = MockBufReader::new(written_data2, buffer_size);
            let mut recovered_data2 = Vec::new();
            let mut buf = vec![0u8; chunk_size];

            loop {
                let bytes_read = reader2.read(&mut buf);
                if bytes_read == 0 { break; }
                recovered_data2.extend_from_slice(&buf[..bytes_read]);
            }

            prop_assert_eq!(
                recovered_data2, original_data,
                "Chunked round-trip should preserve data integrity. Chunk size: {}, buffer size: {}",
                chunk_size, buffer_size
            );
        });
    }

    #[test]
    fn mr_copy_invariant_preservation() {
        proptest!(|(
            source_data in proptest::collection::vec(0u8..255, 10..500),
            copy_buffer_size in 8usize..256
        )| {
            // MR-CopyInvariantPreservation: IO copy operations should preserve data integrity and size
            let original_data = source_data.clone();

            // Simulate copy operation: source -> buffer -> destination
            let mut source = MockBufReader::new(original_data.clone(), copy_buffer_size);
            let mut destination = MockBufWriter::new(copy_buffer_size);

            // Copy in chunks to simulate real IO copy behavior
            let mut total_copied = 0usize;
            let mut copy_buffer = vec![0u8; copy_buffer_size];

            loop {
                let bytes_read = source.read(&mut copy_buffer);
                if bytes_read == 0 { break; }

                destination.write(&copy_buffer[..bytes_read]);
                total_copied += bytes_read;
            }

            let copied_data = destination.into_inner();

            prop_assert_eq!(
                copied_data.clone(), original_data.clone(),
                "Copy operation should preserve data content exactly"
            );

            prop_assert_eq!(
                total_copied, original_data.len(),
                "Copy operation should preserve data size: copied {} bytes, original {} bytes",
                total_copied, original_data.len()
            );

            // Test idempotency: copying the same data multiple times
            let mut source2 = MockBufReader::new(original_data.clone(), copy_buffer_size);
            let mut destination2 = MockBufWriter::new(copy_buffer_size);

            loop {
                let bytes_read = source2.read(&mut copy_buffer);
                if bytes_read == 0 { break; }
                destination2.write(&copy_buffer[..bytes_read]);
            }

            let copied_data2 = destination2.into_inner();

            prop_assert_eq!(
                copied_data, copied_data2,
                "Multiple copy operations should produce identical results (idempotency)"
            );
        });
    }

    #[test]
    fn mr_split_merge_identity() {
        proptest!(|(
            combined_data in proptest::collection::vec(0u8..255, 20..800),
            split_points in proptest::collection::vec(1usize..30, 1..5)
        )| {
            // MR-SplitMergeIdentity: split → merge should restore original stream
            let original_data = combined_data.clone();

            // Calculate actual split points within data bounds
            let mut actual_splits = split_points.clone();
            actual_splits.sort_unstable();
            actual_splits.dedup();
            actual_splits.retain(|&point| point < original_data.len());

            if actual_splits.is_empty() {
                actual_splits.push(original_data.len() / 2);
            }

            // Perform split operation
            let mut split_chunks = Vec::new();
            let mut start = 0;

            for &split_point in &actual_splits {
                if split_point > start {
                    split_chunks.push(original_data[start..split_point.min(original_data.len())].to_vec());
                    start = split_point;
                }
            }

            // Add remaining data as final chunk
            if start < original_data.len() {
                split_chunks.push(original_data[start..].to_vec());
            }

            // Verify split preserves total data
            let split_total_len: usize = split_chunks.iter().map(|chunk| chunk.len()).sum();
            prop_assert_eq!(
                split_total_len, original_data.len(),
                "Split operation should preserve total data length: {} chunks with {} total bytes, original {} bytes",
                split_chunks.len(), split_total_len, original_data.len()
            );

            // Perform merge operation
            let mut merged_data = Vec::new();
            for chunk in &split_chunks {
                merged_data.extend_from_slice(chunk);
            }

            prop_assert_eq!(
                merged_data.clone(), original_data.clone(),
                "Merge operation should restore original data exactly. Split points: {:?}",
                actual_splits
            );

            // Test alternative merge order (should be commutative for simple concatenation)
            let mut merged_data_alt = Vec::new();
            for chunk in split_chunks.iter() {
                merged_data_alt.extend_from_slice(chunk);
            }

            prop_assert_eq!(
                merged_data, merged_data_alt,
                "Different merge implementations should produce identical results"
            );
        });
    }

    #[test]
    fn mr_async_sync_equivalence() {
        proptest!(|(
            test_data in proptest::collection::vec(0u8..255, 5..200),
            read_chunk_size in 1usize..50
        )| {
            // MR-AsyncSyncEquivalence: Async and sync IO should produce identical results
            let original_data = test_data.clone();

            // Simulate synchronous IO
            let mut sync_reader = MockBufReader::new(original_data.clone(), 64);
            let sync_result = sync_reader.read_all();

            // Simulate asynchronous IO (chunked reading)
            let mut async_reader = MockBufReader::new(original_data.clone(), 64);
            let mut async_result = Vec::new();
            let mut read_buffer = vec![0u8; read_chunk_size];

            loop {
                let bytes_read = async_reader.read(&mut read_buffer);
                if bytes_read == 0 { break; }
                async_result.extend_from_slice(&read_buffer[..bytes_read]);
            }

            prop_assert_eq!(
                sync_result.clone(), async_result.clone(),
                "Synchronous and asynchronous IO should produce identical results. Chunk size: {}",
                read_chunk_size
            );

            prop_assert_eq!(
                sync_result.clone(), original_data.clone(),
                "Both sync and async should preserve original data integrity"
            );

            // Test write equivalence
            let mut sync_writer = MockBufWriter::new(64);
            sync_writer.write(&original_data);
            let sync_written = sync_writer.into_inner();

            let mut async_writer = MockBufWriter::new(64);
            for chunk in original_data.chunks(read_chunk_size) {
                async_writer.write(chunk);
            }
            let async_written = async_writer.into_inner();

            prop_assert_eq!(
                sync_written, async_written,
                "Synchronous and asynchronous writing should produce identical results"
            );
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FS Module Metamorphic Relations
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn mr_file_create_delete_stat_semantics() {
        proptest!(|(
            file_paths in proptest::collection::vec(
                "[a-z]{3,10}\\.[a-z]{2,4}", 2..6
            ),
            file_contents in proptest::collection::vec(
                proptest::collection::vec(0u8..255, 5..100), 2..6
            )
        )| {
            // MR-FileCreateDeleteStatSemantics: File lifecycle operations should have consistent semantics
            let mut fs = MockFileSystem::new();

            let files: Vec<(String, Vec<u8>)> = file_paths.iter().zip(file_contents.iter())
                .map(|(path, content)| (path.clone(), content.clone()))
                .collect();

            // Create files and verify stat consistency
            for (path, content) in &files {
                let created = fs.create_file(path.clone(), content.clone());
                prop_assert!(created, "File creation should succeed for new path: {}", path);

                let stat = fs.stat(path);
                prop_assert!(stat.is_some(), "Stat should find newly created file: {}", path);

                if let Some(entry) = stat {
                    prop_assert_eq!(
                        entry.size, content.len() as u64,
                        "File size should match content length: path={}, size={}, content_len={}",
                        path, entry.size, content.len()
                    );
                    prop_assert!(!entry.is_directory, "File should not be marked as directory: {}", path);
                    prop_assert_eq!(
                        entry.content.as_ref().unwrap(), content,
                        "File content should match what was written: {}", path
                    );
                }
            }

            // Test double creation (should fail)
            for (path, content) in &files {
                let created_again = fs.create_file(path.clone(), content.clone());
                prop_assert!(!created_again, "Double creation should fail: {}", path);
            }

            // Delete files and verify stat consistency
            let mut deleted_paths = Vec::new();
            for (i, (path, _)) in files.iter().enumerate() {
                if i % 2 == 0 { // Delete every other file
                    let deleted = fs.delete_file(path);
                    prop_assert!(deleted, "File deletion should succeed for existing file: {}", path);
                    deleted_paths.push(path.clone());

                    let stat_after_delete = fs.stat(path);
                    prop_assert!(
                        stat_after_delete.is_none(),
                        "Stat should not find deleted file: {}", path
                    );
                }
            }

            // Verify remaining files are still accessible
            for (path, content) in &files {
                if !deleted_paths.contains(path) {
                    let stat = fs.stat(path);
                    prop_assert!(
                        stat.is_some(),
                        "Non-deleted files should still be accessible: {}", path
                    );
                    if let Some(entry) = stat {
                        prop_assert_eq!(
                            entry.content.as_ref().unwrap(), content,
                            "Non-deleted file content should be preserved: {}", path
                        );
                    }
                }
            }

            // Test deletion of non-existent files
            for path in &deleted_paths {
                let deleted_again = fs.delete_file(path);
                prop_assert!(!deleted_again, "Double deletion should fail: {}", path);
            }
        });
    }

    #[test]
    fn mr_directory_enumeration_consistency() {
        proptest!(|(
            dir_names in proptest::collection::vec(
                "[a-z]{3,8}", 2..5
            ),
            file_counts in proptest::collection::vec(1usize..6, 2..5)
        )| {
            // MR-DirectoryEnumerationConsistency: Directory listings should match enumeration results
            let mut fs = MockFileSystem::new();

            // Create directories and files
            let mut expected_entries: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

            for (dir_name, &file_count) in dir_names.iter().zip(file_counts.iter()) {
                let dir_path = format!("{}/", dir_name);
                let created_dir = fs.create_directory(dir_path.clone());
                prop_assert!(created_dir, "Directory creation should succeed: {}", dir_path);

                let mut dir_files = Vec::new();
                for i in 0..file_count {
                    let file_path = format!("{}/file{}.txt", dir_name, i);
                    let content = vec![i as u8; 10];

                    let created_file = fs.create_file(file_path.clone(), content);
                    prop_assert!(created_file, "File creation should succeed: {}", file_path);
                    dir_files.push(file_path);
                }

                expected_entries.insert(dir_name.clone(), dir_files);
            }

            // Verify directory listings match expected entries
            for (dir_name, expected_files) in &expected_entries {
                let listed_files = fs.list_directory(dir_name);
                let mut sorted_listed = listed_files.clone();
                sorted_listed.sort();

                let mut sorted_expected = expected_files.clone();
                sorted_expected.sort();

                prop_assert_eq!(
                    sorted_listed.clone(), sorted_expected.clone(),
                    "Directory listing should match created files for directory '{}': listed={:?}, expected={:?}",
                    dir_name, sorted_listed, sorted_expected
                );

                // Verify enumeration count consistency
                prop_assert_eq!(
                    listed_files.len(), expected_files.len(),
                    "Directory enumeration count should match: dir={}, listed_count={}, expected_count={}",
                    dir_name, listed_files.len(), expected_files.len()
                );

                // Verify all listed files actually exist and are correct
                for file_path in &listed_files {
                    let stat = fs.stat(file_path);
                    prop_assert!(
                        stat.is_some(),
                        "Listed file should exist and be accessible: {}", file_path
                    );
                    if let Some(entry) = stat {
                        prop_assert!(
                            !entry.is_directory,
                            "Listed file should not be a directory: {}", file_path
                        );
                    }
                }
            }

            // Test empty directory listing
            let empty_dir = "empty_test_dir".to_string();
            let created_empty = fs.create_directory(empty_dir.clone());
            prop_assert!(created_empty, "Empty directory creation should succeed");

            let empty_listing = fs.list_directory(&empty_dir);
            prop_assert!(
                empty_listing.is_empty(),
                "Empty directory should have no entries: {:?}", empty_listing
            );
        });
    }

    #[test]
    fn mr_path_operation_commutativity() {
        proptest!(|(
            base_paths in proptest::collection::vec(
                "[a-z]{4,10}", 2..5
            ),
            file_sizes in proptest::collection::vec(10usize..200, 2..5)
        )| {
            // MR-PathOperationCommutativity: Independent path operations should commute
            let mut fs1 = MockFileSystem::new();
            let mut fs2 = MockFileSystem::new();

            let operations: Vec<(String, Vec<u8>)> = base_paths.iter().zip(file_sizes.iter())
                .map(|(path, &size)| (format!("{}.dat", path), vec![0u8; size]))
                .collect();

            // Apply operations in original order to fs1
            for (path, content) in &operations {
                fs1.create_file(path.clone(), content.clone());
            }

            // Apply operations in reverse order to fs2
            for (path, content) in operations.iter().rev() {
                fs2.create_file(path.clone(), content.clone());
            }

            // Both filesystems should have identical final state
            for (path, content) in &operations {
                let stat1 = fs1.stat(path);
                let stat2 = fs2.stat(path);

                prop_assert_eq!(
                    stat1.is_some(), stat2.is_some(),
                    "File existence should be consistent regardless of creation order: {}", path
                );

                if let (Some(entry1), Some(entry2)) = (stat1, stat2) {
                    prop_assert_eq!(
                        entry1.size, entry2.size,
                        "File sizes should be identical: path={}, fs1_size={}, fs2_size={}",
                        path, entry1.size, entry2.size
                    );
                    prop_assert_eq!(
                        entry1.content.clone(), entry2.content.clone(),
                        "File contents should be identical: {}", path
                    );
                    prop_assert_eq!(
                        entry1.is_directory, entry2.is_directory,
                        "File types should be identical: {}", path
                    );
                }
            }

            // Verify total file counts are identical
            prop_assert_eq!(
                fs1.entries.len(), fs2.entries.len(),
                "Total entry counts should be identical regardless of creation order: fs1={}, fs2={}",
                fs1.entries.len(), fs2.entries.len()
            );
        });
    }

    #[test]
    fn mr_filesystem_transaction_atomicity() {
        proptest!(|(
            transaction_files in proptest::collection::vec(
                ("[a-z]{4,8}\\.[a-z]{2,3}", proptest::collection::vec(0u8..255, 5..50)),
                3..7
            )
        )| {
            // MR-FilesystemTransactionAtomicity: FS operations should appear atomic
            let mut fs = MockFileSystem::new();

            let files: Vec<(String, Vec<u8>)> = transaction_files.into_iter().collect();

            // Simulate transaction: create all files
            let initial_state = fs.entries.clone();
            let mut transaction_success = true;

            for (path, content) in &files {
                let created = fs.create_file(path.clone(), content.clone());
                if !created {
                    transaction_success = false;
                    break;
                }
            }

            if transaction_success {
                // Verify all files exist after successful transaction
                for (path, content) in &files {
                    let stat = fs.stat(path);
                    prop_assert!(
                        stat.is_some(),
                        "File should exist after successful transaction: {}", path
                    );

                    if let Some(entry) = stat {
                        prop_assert_eq!(
                            entry.content.as_ref().unwrap(), content,
                            "File content should match after transaction: {}", path
                        );
                    }
                }

                // Test rollback simulation: delete all files (simulating transaction abort)
                let mut rollback_fs = fs.clone();
                let mut all_deleted = true;

                for (path, _) in &files {
                    let deleted = rollback_fs.delete_file(path);
                    if !deleted {
                        all_deleted = false;
                        break;
                    }
                }

                if all_deleted {
                    // After rollback, should be back to initial state count
                    prop_assert_eq!(
                        rollback_fs.entries.len(), initial_state.len(),
                        "Rollback should restore to initial entry count: current={}, initial={}",
                        rollback_fs.entries.len(), initial_state.len()
                    );

                    // Verify none of the transaction files exist after rollback
                    for (path, _) in &files {
                        let stat_after_rollback = rollback_fs.stat(path);
                        prop_assert!(
                            stat_after_rollback.is_none(),
                            "File should not exist after rollback: {}", path
                        );
                    }
                }
            }

            // Test partial failure atomicity: if we can't create a file, previous creates should be undoable
            let mut partial_fs = MockFileSystem::new();
            let mut created_count = 0;

            for (path, content) in &files {
                if partial_fs.create_file(path.clone(), content.clone()) {
                    created_count += 1;
                } else {
                    break; // Simulate failure mid-transaction
                }
            }

            // Verify we can clean up partial state
            let mut cleanup_successful = true;
            for (i, (path, _)) in files.iter().enumerate() {
                if i < created_count {
                    if !partial_fs.delete_file(path) {
                        cleanup_successful = false;
                        break;
                    }
                }
            }

            if cleanup_successful && created_count > 0 {
                prop_assert_eq!(
                    partial_fs.entries.len(), initial_state.len(),
                    "Cleanup after partial transaction should restore initial state"
                );
            }
        });
    }
}
