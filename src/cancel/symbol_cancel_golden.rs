//! Golden artifacts test for symbol_cancel protocol lifecycle.
//!
//! This module captures the complete symbol cancellation protocol lifecycle
//! in golden files to ensure protocol stability and detect regressions across
//! token creation, cancellation message preparation, broadcasting, deduplication,
//! and cleanup coordination.

#[cfg(test)]
mod tests {
    use super::super::symbol_cancel::{
        CancelBroadcaster, CancelListener, CancelMessage, CleanupCoordinator, SymbolCancelToken,
    };
    use crate::types::symbol::ObjectId;
    use crate::types::{Budget, CancelKind, CancelReason, Time};
    use crate::util::DetRng;
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    /// Golden test capturing complete symbol cancellation protocol lifecycle.
    #[test]
    fn symbol_cancel_protocol_lifecycle_golden() {
        let golden_dir = Path::new("tests/golden/cancel");
        std::fs::create_dir_all(golden_dir).unwrap();

        // Use deterministic inputs for reproducible golden output
        let mut rng = DetRng::seed_from(42);
        let mut log = ProtocolLog::new();

        // Phase 1: Token Creation and Registration
        log.phase("token_creation");

        let obj1 = ObjectId::from_str("obj_12345678_90abcdef").unwrap();
        let obj2 = ObjectId::from_str("obj_87654321_fedcba09").unwrap();
        let budget = Budget::from_micros(500_000);

        let token1 = SymbolCancelToken::with_budget(obj1, budget, &mut rng);
        let token2 = SymbolCancelToken::new(obj2, &mut rng);

        log.record("token1_created", &format!("id={}, object_id={:?}, budget={:?}",
            token1.token_id(), obj1, budget));
        log.record("token2_created", &format!("id={}, object_id={:?}, budget=default",
            token2.token_id(), obj2));

        // Phase 2: Broadcaster Setup and Token Registration
        log.phase("broadcaster_setup");

        let mut broadcaster = CancelBroadcaster::new(DetRng::seed_from(100));
        broadcaster.register_token(token1.clone());
        broadcaster.register_token(token2.clone());

        log.record("broadcaster_state", &format!("active_tokens={}", broadcaster.active_token_count()));

        // Phase 3: Listener Registration and State Capture
        log.phase("listener_registration");

        let mut listener_events = Vec::new();
        let listener = TestListener::new(&mut listener_events);

        token1.add_listener(Box::new(listener));
        log.record("token1_listeners", &format!("count={}", token1.listener_count()));

        // Phase 4: Cancellation Initiation
        log.phase("cancellation_initiation");

        let cancel_time = Time::from_nanos(1_000_000_000); // 1 second epoch
        let reason = CancelReason::new(CancelKind::Timeout, "operation timeout".to_string());

        let cancel_msg1 = broadcaster.prepare_cancel(obj1, &reason, cancel_time);
        log.record("cancel_msg1", &format_cancel_message(&cancel_msg1));

        // Verify token was cancelled locally
        log.record("token1_state", &format!("cancelled={}, at={:?}, reason={:?}",
            token1.is_cancelled(), token1.cancelled_at(), token1.cancel_reason()));

        // Phase 5: Message Broadcasting and Deduplication
        log.phase("message_broadcasting");

        // Simulate receiving the same message (should be deduplicated)
        let forward_msg = broadcaster.receive_message(&cancel_msg1, cancel_time);
        log.record("msg_dedup_check", &format!("forward={:?}", forward_msg.is_some()));

        // Simulate receiving duplicate (should be rejected)
        let duplicate_msg = broadcaster.receive_message(&cancel_msg1, cancel_time);
        log.record("duplicate_rejected", &format!("forward={:?}", duplicate_msg.is_some()));

        // Phase 6: Cross-Broadcaster Communication
        log.phase("cross_broadcaster_comm");

        let mut broadcaster2 = CancelBroadcaster::new(DetRng::seed_from(200));
        let token3 = SymbolCancelToken::new(obj1, &mut rng); // Same object, different token
        broadcaster2.register_token(token3.clone());

        // Broadcaster2 receives cancellation from broadcaster1
        let received_msg = broadcaster2.receive_message(&cancel_msg1, cancel_time);
        log.record("cross_broadcaster_receive", &format!("forward={:?}, token3_cancelled={}",
            received_msg.is_some(), token3.is_cancelled()));

        // Phase 7: Child Token Hierarchical Cancellation
        log.phase("hierarchical_cancellation");

        let child_token = token2.create_child(obj2, &mut rng);
        log.record("child_created", &format!("parent_id={}, child_id={}",
            token2.token_id(), child_token.token_id()));

        // Cancel parent - should propagate to child
        let reason2 = CancelReason::new(CancelKind::ParentCancelled, "parent cancelled".to_string());
        token2.cancel(&reason2, cancel_time);

        log.record("hierarchical_result", &format!("parent_cancelled={}, child_cancelled={}",
            token2.is_cancelled(), child_token.is_cancelled()));

        // Phase 8: Cleanup Coordination
        log.phase("cleanup_coordination");

        let mut cleanup_coordinator = CleanupCoordinator::new();
        let cleanup_budget = Budget::from_micros(100_000);

        let cleanup_result = cleanup_coordinator.cleanup(obj1, Some(cleanup_budget));
        log.record("cleanup_obj1", &format!("result={:?}", cleanup_result));

        let cleanup_result2 = cleanup_coordinator.cleanup(obj2, None);
        log.record("cleanup_obj2", &format!("result={:?}", cleanup_result2));

        // Phase 9: Statistics and Final State
        log.phase("final_statistics");

        log.record("broadcaster1_stats", &format!("initiated={}, duplicates={}, forwarded={}",
            broadcaster.initiated_count(), broadcaster.duplicate_count(), broadcaster.forwarded_count()));
        log.record("broadcaster2_stats", &format!("initiated={}, duplicates={}, forwarded={}",
            broadcaster2.initiated_count(), broadcaster2.duplicate_count(), broadcaster2.forwarded_count()));
        log.record("listener_events", &format!("count={}", listener_events.len()));

        // Capture panic statistics
        log.record("panic_stats", &format!("token1_panics={}, token2_panics={}, child_panics={}",
            token1.listener_panic_count(), token2.listener_panic_count(), child_token.listener_panic_count()));

        // Write golden output
        let golden_output = log.to_string();
        let golden_path = golden_dir.join("protocol_lifecycle.golden");

        if std::env::var("UPDATE_GOLDENS").is_ok() {
            fs::write(&golden_path, &golden_output).unwrap();
            eprintln!("UPDATED golden: {}", golden_path.display());
        } else {
            let expected = fs::read_to_string(&golden_path)
                .unwrap_or_else(|_| panic!(
                    "Golden file not found: {}\nRun with UPDATE_GOLDENS=1 to create it",
                    golden_path.display()
                ));

            assert_eq!(golden_output, expected, "Protocol lifecycle golden mismatch");
        }
    }

    /// Test listener that captures cancellation events for verification.
    struct TestListener<'a> {
        events: &'a mut Vec<String>,
    }

    impl<'a> TestListener<'a> {
        fn new(events: &'a mut Vec<String>) -> Self {
            Self { events }
        }
    }

    impl<'a> CancelListener for TestListener<'a> {
        fn on_cancel(&self, reason: &CancelReason, at: Time) {
            self.events.push(format!("cancel: kind={:?}, msg={}, at={}ns",
                reason.kind(), reason.message(), at.as_nanos()));
        }
    }

    /// Structured logging for protocol lifecycle capture.
    struct ProtocolLog {
        entries: Vec<(String, String)>,
        current_phase: Option<String>,
    }

    impl ProtocolLog {
        fn new() -> Self {
            Self {
                entries: Vec::new(),
                current_phase: None,
            }
        }

        fn phase(&mut self, name: &str) {
            self.current_phase = Some(name.to_string());
            self.entries.push(("phase".to_string(), name.to_string()));
        }

        fn record(&mut self, key: &str, value: &str) {
            let prefixed_key = match &self.current_phase {
                Some(phase) => format!("{}::{}", phase, key),
                None => key.to_string(),
            };
            self.entries.push((prefixed_key, value.to_string()));
        }
    }

    impl ToString for ProtocolLog {
        fn to_string(&self) -> String {
            let mut output = String::new();
            for (key, value) in &self.entries {
                output.push_str(&format!("{}={}\n", key, value));
            }
            output
        }
    }

    fn format_cancel_message(msg: &CancelMessage) -> String {
        format!("token_id={}, object_id={:?}, kind={:?}, at={}ns, seq={}",
            msg.token_id(), msg.object_id(), msg.cancel_kind(),
            msg.initiated_at().as_nanos(), msg.sequence())
    }

    /// Test additional edge cases for comprehensive coverage.
    #[test]
    fn symbol_cancel_edge_cases_golden() {
        let golden_dir = Path::new("tests/golden/cancel");
        std::fs::create_dir_all(golden_dir).unwrap();

        let mut rng = DetRng::seed_from(99);
        let mut log = ProtocolLog::new();

        // Edge Case 1: Cancel non-existent object
        log.phase("nonexistent_object");

        let broadcaster = CancelBroadcaster::new(DetRng::seed_from(300));
        let nonexistent_obj = ObjectId::from_str("obj_00000000_00000000").unwrap();
        let reason = CancelReason::new(CancelKind::User, "test".to_string());
        let time = Time::from_nanos(2_000_000_000);

        let msg = broadcaster.prepare_cancel(nonexistent_obj, &reason, time);
        log.record("nonexistent_cancel", &format_cancel_message(&msg));

        // Edge Case 2: Multiple cancellations of same token
        log.phase("multiple_cancellations");

        let obj = ObjectId::from_str("obj_aaaaaaaa_bbbbbbbb").unwrap();
        let token = SymbolCancelToken::new(obj, &mut rng);

        let reason1 = CancelReason::new(CancelKind::Timeout, "first".to_string());
        let reason2 = CancelReason::new(CancelKind::User, "second".to_string());

        let result1 = token.cancel(&reason1, time);
        let result2 = token.cancel(&reason2, time);

        log.record("first_cancel", &format!("success={}", result1));
        log.record("second_cancel", &format!("success={}", result2));
        log.record("final_reason", &format!("{:?}", token.cancel_reason()));

        // Edge Case 3: Empty broadcaster statistics
        log.phase("empty_broadcaster");

        let empty_broadcaster = CancelBroadcaster::new(DetRng::seed_from(400));
        log.record("empty_stats", &format!("tokens={}, initiated={}, duplicates={}",
            empty_broadcaster.active_token_count(),
            empty_broadcaster.initiated_count(),
            empty_broadcaster.duplicate_count()));

        // Write edge cases golden
        let golden_output = log.to_string();
        let golden_path = golden_dir.join("edge_cases.golden");

        if std::env::var("UPDATE_GOLDENS").is_ok() {
            fs::write(&golden_path, &golden_output).unwrap();
            eprintln!("UPDATED golden: {}", golden_path.display());
        } else {
            let expected = fs::read_to_string(&golden_path)
                .unwrap_or_else(|_| panic!(
                    "Golden file not found: {}\nRun with UPDATE_GOLDENS=1 to create it",
                    golden_path.display()
                ));

            assert_eq!(golden_output, expected, "Edge cases golden mismatch");
        }
    }
}