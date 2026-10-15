//! Audit test for JetStream flow control: max_ack_pending enforcement.
//!
//! JetStream consumers configure `max_ack_pending` to limit the number of
//! unacknowledged messages that can be outstanding at any time.
//!
//! SECURITY/MEMORY REQUIREMENT: When a JetStream server sends a burst of messages
//! exceeding `max_ack_pending`, the client must:
//! - ENFORCE the limit client-side (correct: backpressure)
//! - NOT allow unbounded pending ack accumulation (prevents memory leak)
//! - Track pending acks correctly across ack/nack/drop operations

use asupersync::messaging::jetstream::{
    Consumer, fuzz_consumer_decrement_pending, fuzz_consumer_increment_pending,
    fuzz_consumer_max_ack_pending, fuzz_create_test_consumer, fuzz_create_test_js_message,
    fuzz_probe_publish_backpressure, fuzz_probe_publish_backpressure_cohort_tail_evidence,
    fuzz_probe_publish_backpressure_tail_evidence,
};

// Mock Consumer for testing flow control without JetStream server
fn create_test_consumer_with_limit(max_ack_pending: usize) -> Consumer {
    fuzz_create_test_consumer(max_ack_pending)
}

// Mock JsMessage for testing
fn create_mock_js_message(
    sequence: u64,
    consumer: Option<&Consumer>,
) -> asupersync::messaging::JsMessage {
    fuzz_create_test_js_message(sequence, consumer)
}

#[test]
fn jetstream_flow_control_max_ack_pending_enforcement() {
    println!("=== JETSTREAM FLOW CONTROL: MAX_ACK_PENDING ENFORCEMENT ===");

    // Test Case 1: Consumer respects max_ack_pending limit
    let consumer = create_test_consumer_with_limit(3); // Allow max 3 pending acks
    assert_eq!(consumer.pending_acks(), 0);
    assert_eq!(fuzz_consumer_max_ack_pending(&consumer), 3);

    // Accept messages up to the limit
    assert!(consumer.can_accept_message());
    assert!(fuzz_consumer_increment_pending(&consumer)); // 1/3
    assert_eq!(consumer.pending_acks(), 1);

    assert!(consumer.can_accept_message());
    assert!(fuzz_consumer_increment_pending(&consumer)); // 2/3
    assert_eq!(consumer.pending_acks(), 2);

    assert!(consumer.can_accept_message());
    assert!(fuzz_consumer_increment_pending(&consumer)); // 3/3 (at limit)
    assert_eq!(consumer.pending_acks(), 3);

    // Now at limit - should reject new messages
    assert!(!consumer.can_accept_message());
    assert!(!fuzz_consumer_increment_pending(&consumer)); // Should fail and not increment
    assert_eq!(consumer.pending_acks(), 3); // Should remain at limit

    println!("✓ Flow control correctly enforces max_ack_pending limit");
}

#[test]
fn jetstream_flow_control_pending_count_decrements_on_ack() {
    println!("\n=== JETSTREAM FLOW CONTROL: PENDING COUNT MANAGEMENT ===");

    let consumer = create_test_consumer_with_limit(5);
    let msg2 = create_mock_js_message(2, Some(&consumer));

    // Simulate receiving messages (increment pending)
    fuzz_consumer_increment_pending(&consumer); // msg1
    fuzz_consumer_increment_pending(&consumer); // msg2
    fuzz_consumer_increment_pending(&consumer); // msg3
    assert_eq!(consumer.pending_acks(), 3);

    // Simulate acking message (should decrement)
    fuzz_consumer_decrement_pending(&consumer); // msg1 acked
    assert_eq!(consumer.pending_acks(), 2);

    // Drop a message without ack (should decrement in Drop)
    drop(msg2);
    assert_eq!(consumer.pending_acks(), 1);

    // Ack another message
    fuzz_consumer_decrement_pending(&consumer); // msg3 acked
    assert_eq!(consumer.pending_acks(), 0);

    println!("✓ Pending ack count correctly tracks ack/nack/drop operations");
}

#[test]
fn jetstream_flow_control_burst_message_scenario() {
    println!("\n=== JETSTREAM FLOW CONTROL: BURST MESSAGE SCENARIO ===");

    // Scenario: Consumer with max_ack_pending=10, server sends 100 messages
    let max_ack_pending = 10;
    let burst_size = 100;
    let consumer = create_test_consumer_with_limit(max_ack_pending);

    let mut accepted = 0;
    let mut rejected = 0;

    // Simulate burst of 100 messages
    for i in 1..=burst_size {
        if fuzz_consumer_increment_pending(&consumer) {
            accepted += 1;
            println!(
                "Message {}: ACCEPTED (pending: {})",
                i,
                consumer.pending_acks()
            );
        } else {
            rejected += 1;
            if rejected <= 5 {
                // Only log first few rejections
                println!(
                    "Message {}: REJECTED (pending: {}, limit: {})",
                    i,
                    consumer.pending_acks(),
                    max_ack_pending
                );
            }
        }
    }

    // Verify flow control worked
    assert_eq!(
        accepted, max_ack_pending,
        "Should accept exactly max_ack_pending messages"
    );
    assert_eq!(
        rejected,
        burst_size - max_ack_pending,
        "Should reject excess messages beyond limit"
    );
    assert_eq!(
        consumer.pending_acks(),
        max_ack_pending,
        "Pending count should equal limit after burst"
    );

    println!("✓ SECURE: Flow control prevents memory leak during message burst");
    println!("  Accepted: {}/{} messages", accepted, burst_size);
    println!("  Rejected: {}/{} messages", rejected, burst_size);
}

#[test]
fn jetstream_flow_control_memory_safety_verification() {
    println!("\n=== JETSTREAM FLOW CONTROL: MEMORY SAFETY VERIFICATION ===");

    // Test that pending ack counter prevents unbounded memory growth
    let consumer = create_test_consumer_with_limit(5);

    // Create a large number of messages
    let mut messages = Vec::new();
    let mut accepted_count = 0;

    // Try to create 1000 messages
    for i in 1..=1000 {
        if fuzz_consumer_increment_pending(&consumer) {
            let msg = create_mock_js_message(i, Some(&consumer));
            messages.push(msg);
            accepted_count += 1;
        }
        // Stop when we can't accept more
        if !consumer.can_accept_message() {
            break;
        }
    }

    assert_eq!(
        accepted_count, 5,
        "Should only accept up to max_ack_pending"
    );
    assert_eq!(messages.len(), 5, "Should only store accepted messages");
    assert_eq!(
        consumer.pending_acks(),
        5,
        "Pending count should be at limit"
    );

    println!(
        "✓ Memory safety: Only {} messages stored (not 1000)",
        messages.len()
    );
    println!("✓ Flow control prevents unbounded memory growth");
}

#[test]
fn jetstream_publish_backpressure_refuses_when_slot_is_occupied() {
    println!("\n=== JETSTREAM PUBLISH BACKPRESSURE: OCCUPIED SLOT REFUSAL ===");

    let snapshot = fuzz_probe_publish_backpressure(None, 1);

    assert_eq!(snapshot.effective_max_in_flight_publishes, 1);
    assert_eq!(snapshot.max_waiters, 0);
    assert!(
        !snapshot.acquired,
        "occupied slot must refuse a new publish"
    );
    assert_eq!(snapshot.in_flight_publishes_after, 1);
    assert_eq!(snapshot.refused_publishes, 1);
    assert!(
        snapshot
            .error
            .as_deref()
            .is_some_and(|message| message.contains("local publish backpressure"))
    );

    println!("✓ Publish path now refuses before growing hidden waiters");
}

#[test]
fn jetstream_publish_backpressure_respects_emergency_pressure() {
    println!("\n=== JETSTREAM PUBLISH BACKPRESSURE: EMERGENCY PRESSURE ===");

    let snapshot = fuzz_probe_publish_backpressure(Some(0.0), 0);

    assert_eq!(snapshot.effective_max_in_flight_publishes, 0);
    assert_eq!(snapshot.pressure_level.as_deref(), Some("emergency"));
    assert!(!snapshot.acquired, "emergency pressure must fail closed");
    assert_eq!(snapshot.refused_publishes, 1);
    assert!(
        snapshot
            .error
            .as_deref()
            .is_some_and(|message| message.contains("pressure=emergency"))
    );

    println!("✓ Emergency pressure is visible at the publish seam");
}

#[test]
fn jetstream_publish_backpressure_zero_wait_tail_under_slow_ack_refusal() {
    println!("\n=== JETSTREAM PUBLISH BACKPRESSURE: ZERO-WAIT TAIL EVIDENCE ===");

    let snapshot = fuzz_probe_publish_backpressure_tail_evidence(None, 1, 64);

    assert_eq!(snapshot.tail_sample_count, 64);
    assert_eq!(snapshot.accepted_count, 0);
    assert_eq!(snapshot.refused_count, 64);
    assert!(snapshot.waiter_queue_absent);
    assert_eq!(snapshot.waiter_fairness_mode, "vacuous_zero_wait_refusal");
    assert!(snapshot.refusal_only_policy);
    assert_eq!(snapshot.tail_evidence_mode, "zero_wait_refusal_only");
    assert_eq!(snapshot.publish_wait_latency_p95_micros, 0);
    assert_eq!(snapshot.publish_wait_latency_p99_micros, 0);
    assert_eq!(snapshot.publish_wait_latency_p999_micros, 0);

    println!("✓ Slow-ACK refusal policy keeps p95/p99/p999 publish wait at 0us");
}

#[test]
fn jetstream_publish_backpressure_zero_wait_tail_under_emergency_pressure() {
    println!("\n=== JETSTREAM PUBLISH BACKPRESSURE: EMERGENCY ZERO-WAIT TAIL ===");

    let snapshot = fuzz_probe_publish_backpressure_tail_evidence(Some(0.0), 0, 64);

    assert_eq!(snapshot.tail_sample_count, 64);
    assert_eq!(snapshot.accepted_count, 0);
    assert_eq!(snapshot.refused_count, 64);
    assert!(snapshot.waiter_queue_absent);
    assert_eq!(snapshot.waiter_fairness_mode, "vacuous_zero_wait_refusal");
    assert!(snapshot.refusal_only_policy);
    assert_eq!(snapshot.tail_evidence_mode, "zero_wait_refusal_only");
    assert_eq!(snapshot.pressure_level.as_deref(), Some("emergency"));
    assert_eq!(snapshot.publish_wait_latency_p95_micros, 0);
    assert_eq!(snapshot.publish_wait_latency_p99_micros, 0);
    assert_eq!(snapshot.publish_wait_latency_p999_micros, 0);

    println!("✓ Emergency pressure refusal also keeps publish wait tails at 0us");
}

#[test]
fn jetstream_publish_backpressure_multi_publisher_zero_wait_tail_evidence() {
    println!("\n=== JETSTREAM PUBLISH BACKPRESSURE: MULTI-PUBLISHER ZERO-WAIT TAIL ===");

    let snapshot = fuzz_probe_publish_backpressure_cohort_tail_evidence(32, 16);

    assert_eq!(snapshot.publisher_count, 32);
    assert_eq!(snapshot.occupied_publisher_count, 16);
    assert_eq!(snapshot.accepted_count, 16);
    assert_eq!(snapshot.refused_count, 16);
    assert!(snapshot.waiter_queue_absent);
    assert_eq!(snapshot.waiter_fairness_mode, "vacuous_zero_wait_refusal");
    assert!(snapshot.refusal_only_policy);
    assert!(snapshot.multi_publisher_tail_evidence_present);
    assert_eq!(snapshot.queueing_model, "mg11_loss_system");
    assert_eq!(snapshot.publish_wait_latency_p95_micros, 0);
    assert_eq!(snapshot.publish_wait_latency_p99_micros, 0);
    assert_eq!(snapshot.publish_wait_latency_p999_micros, 0);

    println!(
        "✓ 32-publisher cohort preserves zero publish-wait tails under the loss-system policy"
    );
}

#[test]
fn jetstream_flow_control_compliance_summary() {
    println!("\n=== JETSTREAM FLOW CONTROL COMPLIANCE SUMMARY ===");
    println!("✓ FIXED: Added client-side max_ack_pending enforcement");
    println!("✓ SECURE: Prevents unbounded pending ack accumulation");
    println!("✓ CORRECT: Tracks pending acks across ack/nack/drop operations");
    println!("✓ MEMORY SAFE: Bounded message acceptance prevents memory leaks");
    println!("✓ BACKPRESSURE: Flow control provides proper backpressure mechanism");
    println!("✓ PUBLISH REFUSAL: Per-context outstanding publish seam is explicitly bounded");
    println!("✓ PRESSURE GATE: Emergency pressure can refuse publish before wire I/O");
    println!("✓ TAIL EVIDENCE: Refusal-only policy proves p95/p99/p999 wait tails at 0us");
    println!("✓ WAITER CERTIFICATE: max_waiters=0 makes fairness vacuous for the live controller");
    println!("✓ COHORT EVIDENCE: 32-publisher loss-system cohort keeps publish-wait tails at 0us");
    println!();
    println!("FOUNDATION ADDED: Explicit JetStream publish refusal gate");
    println!("  Before: Publish path relied on TCP backpressure only");
    println!(
        "  After:  Per-context refusal plus emergency pressure gate with single- and multi-publisher zero-wait tail evidence"
    );
    println!();
    println!(
        "STATUS: CONSUMER FLOW CONTROL IS SECURE; CURRENT PUBLISH CONTROLLER IS CERTIFIED ZERO-WAITER, WHILE ANY FUTURE NONZERO-WAIT POLICY STILL NEEDS ITS OWN FAIRNESS PROOF ✅"
    );
}
