//! Metamorphic Testing Suite for Channel Send/Recv Operations
//!
//! This module implements metamorphic testing for asupersync channel operations
//! to validate ordering, conservation, and cancellation correctness where exact
//! scheduling outcomes are unpredictable (oracle problem).
//!
//! ## Metamorphic Relations Implemented
//!
//! 1. **FIFO Preservation** (Permutative) - Message ordering preserved within channel
//! 2. **Send-Recv Conservation** (Additive) - Message count conservation laws
//! 3. **Clone Behavior Identity** (Equivalence) - Channel clones have identical behavior
//! 4. **Channel Capacity Bounds** (Inclusive) - Capacity enforcement precision
//!
//! ## Oracle Problem
//!
//! Channel operations have non-deterministic timing due to:
//! - Async scheduling uncertainty
//! - Cancellation timing races
//! - Multi-producer contention
//!
//! Metamorphic testing validates invariant relationships between inputs/outputs
//! without needing to predict exact outcomes.

#[path = "metamorphic/channel_watch.rs"]
mod channel_watch;

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TestMessage {
    seq: u64,
    content: String,
    sender_id: u32,
}

impl TestMessage {
    fn new(seq: u64, content: impl Into<String>, sender_id: u32) -> Self {
        Self {
            seq,
            content: content.into(),
            sender_id,
        }
    }
}

#[derive(Debug, Clone)]
struct MRResult {
    relation_name: String,
    input_description: String,
    expected_property: String,
    actual_outcome: String,
    passed: bool,
    violation_details: Option<String>,
    messages_processed: u64,
    test_duration_ms: u64,
}

struct ChannelMetamorphicHarness {
    violation_count: Arc<AtomicUsize>,
}

impl ChannelMetamorphicHarness {
    /// Create new harness for metamorphic testing.
    fn new() -> Self {
        Self {
            violation_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Run all metamorphic relations for MPSC channels.
    pub async fn test_mpsc_metamorphic_relations(&self) -> Vec<MRResult> {
        let mut results = Vec::new();

        // MR1: FIFO Preservation
        results.extend(self.test_mpsc_fifo_preservation().await);

        // MR2: Send-Recv Conservation
        results.extend(self.test_mpsc_conservation().await);

        // MR3: Clone Behavior Identity
        results.extend(self.test_mpsc_clone_identity().await);

        // MR4: Channel Capacity Bounds
        results.extend(self.test_mpsc_capacity_bounds().await);

        results
    }

    /// MR1: FIFO Preservation (Permutative Relation)
    /// Property: send_sequence([a,b,c]) → recv_sequence() = [a,b,c]
    /// Catches: Message reordering, queue corruption, scheduling bugs
    async fn test_mpsc_fifo_preservation(&self) -> Vec<MRResult> {
        let mut results = Vec::new();
        let start_time = std::time::Instant::now();

        // Test case 1: Sequential send/recv with ordered messages
        let test_messages = vec![
            TestMessage::new(1, "first", 0),
            TestMessage::new(2, "second", 0),
            TestMessage::new(3, "third", 0),
            TestMessage::new(4, "fourth", 0),
            TestMessage::new(5, "fifth", 0),
        ];

        let (tx, mut rx) = mpsc::channel(test_messages.len());

        // Send messages in order
        let cx = Cx::for_testing();
        for msg in &test_messages {
            match tx.reserve(&cx).await {
                Ok(permit) => {
                    permit.send(msg.clone());
                }
                Err(e) => {
                    results.push(MRResult {
                        relation_name: "FIFO_Preservation".to_string(),
                        input_description: format!(
                            "Sequential send of {} messages",
                            test_messages.len()
                        ),
                        expected_property: "FIFO order preservation".to_string(),
                        actual_outcome: format!("Send failed: {:?}", e),
                        passed: false,
                        violation_details: Some(format!("Reserve failed: {:?}", e)),
                        messages_processed: 0,
                        test_duration_ms: start_time.elapsed().as_millis() as u64,
                    });
                    return results;
                }
            }
        }

        // Receive and verify order
        let mut received = Vec::new();
        let cx = Cx::for_testing();
        for _ in 0..test_messages.len() {
            match rx.recv(&cx).await {
                Ok(msg) => received.push(msg),
                Err(_) => break,
            }
        }

        // Verify FIFO ordering
        let fifo_preserved = received == test_messages;
        let violation_details = if !fifo_preserved {
            Some(format!(
                "FIFO violation: expected {:?}, got {:?}",
                test_messages.iter().map(|m| m.seq).collect::<Vec<_>>(),
                received.iter().map(|m| m.seq).collect::<Vec<_>>()
            ))
        } else {
            None
        };

        if !fifo_preserved {
            self.violation_count.fetch_add(1, Ordering::Relaxed);
        }

        results.push(MRResult {
            relation_name: "FIFO_Preservation".to_string(),
            input_description: format!("Sequential send/recv of {} messages", test_messages.len()),
            expected_property: "Messages received in same order as sent".to_string(),
            actual_outcome: format!(
                "Received {} messages in order: {}",
                received.len(),
                fifo_preserved
            ),
            passed: fifo_preserved,
            violation_details,
            messages_processed: received.len() as u64,
            test_duration_ms: start_time.elapsed().as_millis() as u64,
        });

        results
    }

    /// MR2: Send-Recv Conservation (Additive Relation)
    /// Property: count(successful_sends) = count(successful_receives) (modulo cancellation)
    /// Catches: Message loss, duplication, phantom receives
    async fn test_mpsc_conservation(&self) -> Vec<MRResult> {
        let mut results = Vec::new();
        let start_time = std::time::Instant::now();

        let message_count = 100;
        let (tx, mut rx) = mpsc::channel(message_count);
        let mut sent_count = 0;
        let mut recv_count = 0;

        // Send phase
        let cx = Cx::for_testing();
        for i in 0..message_count {
            let msg = TestMessage::new(i as u64, format!("msg_{}", i), 0);
            match tx.reserve(&cx).await {
                Ok(permit) => {
                    permit.send(msg);
                    sent_count += 1;
                }
                Err(_) => break, // Stop on any error
            }
        }

        // Receive phase - drain all available messages
        while let Ok(_) = rx.try_recv() {
            recv_count += 1;
        }

        // Verify conservation law
        let conservation_holds = sent_count == recv_count;
        let violation_details = if !conservation_holds {
            Some(format!(
                "Conservation violation: sent {}, received {}",
                sent_count, recv_count
            ))
        } else {
            None
        };

        if !conservation_holds {
            self.violation_count.fetch_add(1, Ordering::Relaxed);
        }

        results.push(MRResult {
            relation_name: "Send_Recv_Conservation".to_string(),
            input_description: format!("Send {} messages, drain all", message_count),
            expected_property: "count(sent) = count(received)".to_string(),
            actual_outcome: format!("sent: {}, received: {}", sent_count, recv_count),
            passed: conservation_holds,
            violation_details,
            messages_processed: recv_count as u64,
            test_duration_ms: start_time.elapsed().as_millis() as u64,
        });

        results
    }

    /// MR3: Clone Behavior Identity (Equivalence Relation)
    /// Property: behavior(original_channel) = behavior(cloned_channel)
    /// Catches: Shared state corruption, clone isolation failures
    async fn test_mpsc_clone_identity(&self) -> Vec<MRResult> {
        let mut results = Vec::new();
        let start_time = std::time::Instant::now();

        let (tx, mut rx) = mpsc::channel(10);
        let tx_clone = tx.clone();

        let test_msg = TestMessage::new(42, "clone_test", 1);

        // Send via original
        let cx = Cx::for_testing();
        let sent_via_original = if let Ok(permit) = tx.reserve(&cx).await {
            permit.send(test_msg.clone());
            true
        } else {
            false
        };

        // Send via clone
        let sent_via_clone = if let Ok(permit) = tx_clone.reserve(&cx).await {
            permit.send(test_msg.clone());
            true
        } else {
            false
        };

        // Receive both messages
        let mut received_count = 0;
        for _ in 0..2 {
            match rx.try_recv() {
                Ok(_) => received_count += 1,
                Err(_) => break,
            }
        }

        // Verify both sends worked and both receives succeeded
        let clone_identity_holds = sent_via_original && sent_via_clone && received_count == 2;

        let violation_details = if !clone_identity_holds {
            Some(format!(
                "Clone identity violation: original_send={}, clone_send={}, received_count={}",
                sent_via_original, sent_via_clone, received_count
            ))
        } else {
            None
        };

        if !clone_identity_holds {
            self.violation_count.fetch_add(1, Ordering::Relaxed);
        }

        results.push(MRResult {
            relation_name: "Clone_Behavior_Identity".to_string(),
            input_description: "Send via original and cloned sender".to_string(),
            expected_property: "Both senders should behave identically".to_string(),
            actual_outcome: format!(
                "original_sent: {}, clone_sent: {}, total_received: {}",
                sent_via_original, sent_via_clone, received_count
            ),
            passed: clone_identity_holds,
            violation_details,
            messages_processed: received_count as u64,
            test_duration_ms: start_time.elapsed().as_millis() as u64,
        });

        results
    }

    /// MR4: Channel Capacity Bounds (Inclusive Relation)
    /// Property: Bounded channel accepts exactly `capacity` messages before blocking
    /// Catches: Capacity miscounting, premature blocking
    async fn test_mpsc_capacity_bounds(&self) -> Vec<MRResult> {
        let mut results = Vec::new();
        let start_time = std::time::Instant::now();

        let capacity = 5;
        let (tx, _rx) = mpsc::channel::<TestMessage>(capacity);
        let mut successful_sends = 0;

        // Fill to capacity using try_reserve (non-blocking)
        for i in 0..capacity {
            let msg = TestMessage::new(i as u64, format!("capacity_test_{}", i), 2);
            match tx.try_reserve() {
                Ok(permit) => {
                    permit.send(msg);
                    successful_sends += 1;
                }
                Err(_) => break,
            }
        }

        // Next send should fail (channel full)
        let extra_msg = TestMessage::new(999, "should_fail", 2);
        let extra_send_blocked = match tx.try_reserve() {
            Ok(permit) => {
                permit.send(extra_msg);
                false // Should not succeed
            }
            Err(_) => true, // Expected to fail
        };

        // Verify capacity bounds
        let capacity_bounds_correct = successful_sends == capacity && extra_send_blocked;

        let violation_details = if !capacity_bounds_correct {
            Some(format!(
                "Capacity bounds violation: capacity={}, successful_sends={}, extra_blocked={}",
                capacity, successful_sends, extra_send_blocked
            ))
        } else {
            None
        };

        if !capacity_bounds_correct {
            self.violation_count.fetch_add(1, Ordering::Relaxed);
        }

        results.push(MRResult {
            relation_name: "Channel_Capacity_Bounds".to_string(),
            input_description: format!("Fill channel to capacity {} then try extra send", capacity),
            expected_property: "Channel accepts exactly capacity messages, blocks extra"
                .to_string(),
            actual_outcome: format!(
                "accepted: {}/{}, extra_blocked: {}",
                successful_sends, capacity, extra_send_blocked
            ),
            passed: capacity_bounds_correct,
            violation_details,
            messages_processed: successful_sends as u64,
            test_duration_ms: start_time.elapsed().as_millis() as u64,
        });

        results
    }

    /// Get total number of metamorphic relation violations detected.
    fn violation_count(&self) -> usize {
        self.violation_count.load(Ordering::Relaxed)
    }

    /// Generate summary report of all metamorphic test results.
    fn generate_summary_report(results: &[MRResult]) -> String {
        let total_tests = results.len();
        let passed_tests = results.iter().filter(|r| r.passed).count();
        let failed_tests = total_tests - passed_tests;
        let total_messages = results.iter().map(|r| r.messages_processed).sum::<u64>();
        let success_rate = if total_tests == 0 {
            100.0
        } else {
            (passed_tests as f64 / total_tests as f64) * 100.0
        };

        let mut report = String::new();
        report.push_str("=== METAMORPHIC TESTING SUMMARY REPORT ===\n\n");
        report.push_str(&format!("Total Tests: {}\n", total_tests));
        report.push_str(&format!("Passed: {}\n", passed_tests));
        report.push_str(&format!("Failed: {}\n", failed_tests));
        report.push_str(&format!("Success Rate: {:.2}%\n", success_rate));
        report.push_str(&format!("Messages Processed: {}\n\n", total_messages));

        report.push_str("=== DETAILED RESULTS ===\n");
        for result in results {
            report.push_str(&format!(
                "• {} [{}]\n",
                result.relation_name,
                if result.passed { "PASS" } else { "FAIL" }
            ));
            report.push_str(&format!("  Input: {}\n", result.input_description));
            report.push_str(&format!("  Property: {}\n", result.expected_property));
            report.push_str(&format!("  Outcome: {}\n", result.actual_outcome));

            if let Some(violation) = &result.violation_details {
                report.push_str(&format!("  Violation: {}\n", violation));
            }

            report.push_str(&format!(
                "  Duration: {}ms, Messages: {}\n\n",
                result.test_duration_ms, result.messages_processed
            ));
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metamorphic_relations_suite() {
        let rt = RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        rt.block_on(async {
            let harness = ChannelMetamorphicHarness::new();
            let results = harness.test_mpsc_metamorphic_relations().await;

            // Verify all tests executed
            assert!(!results.is_empty(), "No metamorphic tests executed");

            let report = ChannelMetamorphicHarness::generate_summary_report(&results);

            // Check for violations
            let violation_count = harness.violation_count();
            assert_eq!(
                violation_count, 0,
                "Metamorphic relations violated: {} failures detected\n{}",
                violation_count, report
            );

            // All tests should pass
            for result in &results {
                assert!(
                    result.passed,
                    "Metamorphic relation {} failed: {}",
                    result.relation_name,
                    result.violation_details.as_deref().unwrap_or("Unknown")
                );
            }
        });
    }

    #[test]
    fn test_fifo_preservation_specific() {
        let rt = RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        rt.block_on(async {
            let harness = ChannelMetamorphicHarness::new();
            let results = harness.test_mpsc_fifo_preservation().await;

            assert!(!results.is_empty(), "FIFO preservation test did not run");
            assert!(
                results[0].passed,
                "FIFO preservation violated: {:?}",
                results[0].violation_details
            );
        });
    }

    #[test]
    fn test_conservation_specific() {
        let rt = RuntimeBuilder::new()
            .build()
            .expect("Failed to build runtime");

        rt.block_on(async {
            let harness = ChannelMetamorphicHarness::new();
            let results = harness.test_mpsc_conservation().await;

            assert!(!results.is_empty(), "Conservation test did not run");
            assert!(
                results[0].passed,
                "Conservation law violated: {:?}",
                results[0].violation_details
            );
        });
    }
}
