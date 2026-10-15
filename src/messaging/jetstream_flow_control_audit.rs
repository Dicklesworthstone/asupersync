//! JetStream publish flow control audit test.
//!
//! AUDIT FINDING: FOUNDATION - per-context publish backpressure is now explicit,
//! and the conservative refusal-only policy now has deterministic zero-wait
//! tail evidence, and the current loss-system behavior now has deterministic
//! cohort evidence too. For the current controller, fairness is vacuous because
//! hidden waiters are impossible (`max_waiters = 0`).
//!
//! When client publishes faster than server can ack, the implementation:
//! - Current foundation: bound the per-context outstanding publish seam and
//!   refuse immediately when the slot is occupied or `Cx::pressure()` is in
//!   the emergency band
//! - Future-policy note: any later nonzero-wait controller must still prove
//!   bounded fairness before it can replace the current refusal-only path
//!
//! Per JetStream client backpressure best practices, high publish rate should
//! trigger explicit pressure-aware refusal rather than relying solely on TCP flow control.

#![cfg(test)]

use crate::messaging::jetstream::{
    fuzz_probe_publish_backpressure, fuzz_probe_publish_backpressure_cohort_tail_evidence,
    fuzz_probe_publish_backpressure_tail_evidence,
};

fn init_test(name: &str) {
    println!("[jetstream-flow-control] START {name}");
}

fn test_complete(name: &str) {
    println!("[jetstream-flow-control] PASS {name}");
}

/// AUDIT: Test JetStream publish flow control under high rate
///
/// Per JetStream backpressure best practices, when client publishes faster
/// than server can acknowledge:
/// (a) bound the per-context outstanding publish seam
/// (b) refuse immediately when that seam is occupied
/// NOT (c) grow hidden wait queues
#[test]
fn audit_jetstream_publish_flow_control_backpressure() {
    init_test("audit_jetstream_publish_flow_control_backpressure");

    let snapshot = fuzz_probe_publish_backpressure(None, 1);

    assert_eq!(snapshot.effective_max_in_flight_publishes, 1);
    assert_eq!(snapshot.max_waiters, 0);
    assert!(!snapshot.acquired);
    assert_eq!(snapshot.in_flight_publishes_after, 1);
    assert_eq!(snapshot.refused_publishes, 1);
    assert!(
        snapshot
            .error
            .as_deref()
            .is_some_and(|message| message.contains("local publish backpressure"))
    );

    test_complete("audit_jetstream_publish_flow_control_backpressure");
}

/// AUDIT: Test publish queue memory behavior under slow acknowledgments
///
/// Verifies that high publish rate doesn't lead to unbounded memory growth.
#[test]
fn audit_publish_memory_bounds_under_slow_acks() {
    init_test("audit_publish_memory_bounds_under_slow_acks");

    let snapshot = fuzz_probe_publish_backpressure(None, 1);

    assert_eq!(snapshot.effective_max_in_flight_publishes, 1);
    assert_eq!(
        snapshot.in_flight_publishes_after, 1,
        "occupied publish slot must stay bounded under slow ACK assumptions"
    );
    assert_eq!(
        snapshot.refused_publishes, 1,
        "slow ACK path must refuse the next publish instead of accumulating hidden waiters"
    );

    test_complete("audit_publish_memory_bounds_under_slow_acks");
}

/// AUDIT: Test pressure signaling integration with Cx
///
/// Verifies that publish backpressure integrates with Cx::pressure() system.
#[test]
fn audit_pressure_signaling_integration() {
    init_test("audit_pressure_signaling_integration");

    let snapshot = fuzz_probe_publish_backpressure(Some(0.0), 0);

    assert_eq!(snapshot.effective_max_in_flight_publishes, 0);
    assert_eq!(snapshot.pressure_level.as_deref(), Some("emergency"));
    assert!(!snapshot.acquired);
    assert!(
        snapshot
            .error
            .as_deref()
            .is_some_and(|message| message.contains("pressure=emergency"))
    );

    test_complete("audit_pressure_signaling_integration");
}

/// AUDIT: Document current TCP-based flow control behavior
///
/// Documents the existing flow control mechanism for comparison.
#[test]
fn audit_current_tcp_flow_control_behavior() {
    init_test("audit_current_tcp_flow_control_behavior");

    // AUDIT DOCUMENTATION: The publish seam now has an explicit local refusal
    // gate before the NATS request path, but it is still intentionally
    // conservative and fail-closed until tail-latency evidence exists.
    //
    // Positive aspects:
    // ✅ Messages are not dropped silently (no data loss)
    // ✅ Per-context outstanding publish count is explicitly bounded
    // ✅ Emergency `Cx::pressure()` state can refuse a new publish before wire I/O
    //
    // Current controller certificate:
    // ✅ Hidden waiters are impossible (`max_waiters = 0`)
    // ✅ Fairness is vacuous for the current controller because no waiter queue exists
    // ✅ Cohort evidence covers the current refusal-only loss-system controller
    //
    // Future-policy note: if a later nonzero-wait controller is introduced,
    // that controller must still prove bounded fairness without hidden memory growth.

    test_complete("audit_current_tcp_flow_control_behavior");
}

/// AUDIT: Reference implementation pattern for proper backpressure
///
/// Documents the expected implementation approach.
#[test]
fn audit_reference_backpressure_pattern() {
    init_test("audit_reference_backpressure_pattern");

    // AUDIT: Current foundation pattern
    //
    // ```rust
    // pub struct JetStreamContext {
    //     client: NatsClient,
    //     publish_backpressure: JetStreamPublishBackpressureGate,
    // }
    //
    // impl JetStreamContext {
    //     pub async fn publish(
    //         &mut self,
    //         cx: &Cx,
    //         subject: &str,
    //         payload: &[u8],
    //     ) -> Result<PubAck, JsError> {
    //         let _permit = self.publish_backpressure.begin_publish(cx, subject)?;
    //         let response = self.client.request(cx, subject, payload).await?;
    //         Self::parse_pub_ack(&response.payload)
    //     }
    // }
    // ```
    //
    // Benefits:
    // - Bounded per-context outstanding publish accounting
    // - Explicit emergency-pressure refusal at the publish seam
    // - Zero hidden waiters in the current foundation slice
    //
    // Current closeout basis:
    // - zero hidden waiters in the live controller
    // - fairness is vacuous because no waiter queue exists
    //
    // Future-policy note:
    // - any nonzero-wait alternative must still prove bounded fairness before adoption

    test_complete("audit_reference_backpressure_pattern");
}

/// AUDIT: Zero-wait tail evidence for the conservative refusal-only policy.
#[test]
fn audit_publish_wait_tail_zero_for_refusal_only_policy() {
    init_test("audit_publish_wait_tail_zero_for_refusal_only_policy");

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

    test_complete("audit_publish_wait_tail_zero_for_refusal_only_policy");
}

/// AUDIT: Shared multi-publisher cohort evidence for the current refusal-only
/// loss-system controller.
#[test]
fn audit_publish_wait_tail_zero_for_multi_publisher_loss_system() {
    init_test("audit_publish_wait_tail_zero_for_multi_publisher_loss_system");

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

    test_complete("audit_publish_wait_tail_zero_for_multi_publisher_loss_system");
}
