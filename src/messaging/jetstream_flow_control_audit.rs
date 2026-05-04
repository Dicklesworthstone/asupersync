//! JetStream publish flow control audit test.
//!
//! AUDIT FINDING: FOUNDATION - per-context publish backpressure is now explicit,
//! but tail-latency evidence is still missing so the operator surface remains
//! fail-closed.
//!
//! When client publishes faster than server can ack, the implementation:
//! - Current foundation: bound the per-context outstanding publish seam and
//!   refuse immediately when the slot is occupied or `Cx::pressure()` is in
//!   the emergency band
//! - Remaining gap: no p99/p999 publish-wait evidence yet
//!
//! Per JetStream client backpressure best practices, high publish rate should
//! trigger explicit pressure-aware refusal rather than relying solely on TCP flow control.

#![cfg(test)]

use crate::messaging::jetstream::fuzz_probe_publish_backpressure;

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
    // Remaining issues:
    // ❌ Wait-tail p99 evidence is still absent
    // ❌ Wait-tail p999 evidence is still absent
    // ❌ Zero-waiter refusal is the only foundation policy today
    //
    // Recommendation: keep fail-closed signoff until p99/p999 wait evidence lands.

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
    // Still missing for closeout:
    // - bounded waiter policy beyond zero-wait refusal
    // - publish wait latency p99 evidence
    // - publish wait latency p999 evidence

    test_complete("audit_reference_backpressure_pattern");
}
