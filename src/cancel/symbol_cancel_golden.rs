//! Golden artifacts test for symbol_cancel protocol lifecycle.
//!
//! This module captures the complete symbol cancellation protocol lifecycle
//! in golden strings to ensure protocol stability and detect regressions across
//! token creation, cancellation message preparation, broadcasting, deduplication,
//! and cleanup coordination.

#[cfg(test)]
mod tests {
    use super::super::symbol_cancel::{
        CancelBroadcaster, CancelMessage, CancelSink, CleanupCoordinator, CleanupHandler, PeerId,
        SymbolCancelToken,
    };
    use crate::cancel::CleanupResult;
    use crate::types::symbol::{ObjectId, Symbol};
    use crate::types::{Budget, CancelReason, Time};
    use crate::util::DetRng;
    use std::sync::{Arc, Mutex as StdMutex};

    const EXPECTED_PROTOCOL_LIFECYCLE: &str = "\
phase=token_creation
token_creation::token1_created=object_id=00000000000000000000000090abcdef, cleanup_budget=deadline_ns=Some(500000000),poll_quota=4294967295,priority=128
token_creation::token2_created=object_id=000000000000000000000000fedcba09, cleanup_budget=deadline_ns=None,poll_quota=4294967295,priority=128
phase=broadcaster_setup
broadcaster_setup::registered_tokens=2
phase=listener_registration
listener_registration::token1_listeners=registered=1
phase=cancellation_initiation
cancellation_initiation::cancel_msg1=object_id=00000000000000000000000090abcdef, kind=Timeout, at=1000000000ns, seq=0
cancellation_initiation::token1_state=cancelled=true, at_ns=Some(1000000000), reason_kind=Some(\"Timeout\")
phase=message_broadcasting
message_broadcasting::msg_dedup_check=forwarded=false
message_broadcasting::duplicate_rejected=forwarded=false
phase=cross_broadcaster_comm
cross_broadcaster_comm::cross_broadcaster_receive=forwarded=true, token3_cancelled=true, token3_reason=Some(\"Timeout\")
phase=hierarchical_cancellation
hierarchical_cancellation::child_created=parent_object_id=000000000000000000000000fedcba09, child_object_id=000000000000000000000000fedcba09
hierarchical_cancellation::hierarchical_result=parent_cancelled=true, child_cancelled=true, child_reason=Some(\"ParentCancelled\")
phase=cleanup_coordination
cleanup_coordination::cleanup_obj1=cleaned=2, bytes=8, within_budget=true, completed=true, handlers=1, errors=0
cleanup_coordination::cleanup_obj2=cleaned=0, bytes=0, within_budget=true, completed=false, handlers=0, errors=1
phase=final_statistics
final_statistics::broadcaster1_stats=initiated=1, duplicates=2, forwarded=0
final_statistics::broadcaster2_stats=initiated=0, duplicates=0, forwarded=1
final_statistics::listener_events=kind=Timeout, msg=Some(\"operation timeout\"), at=1000000000ns
final_statistics::panic_stats=token1=0, token2=0, child=0
";

    const EXPECTED_EDGE_CASES: &str = "\
phase=nonexistent_object
nonexistent_object::nonexistent_cancel=object_id=00000000000000000000000000000000, kind=User, at=2000000000ns, seq=0
phase=multiple_cancellations
multiple_cancellations::first_cancel=success=true
multiple_cancellations::second_cancel=success=false
multiple_cancellations::final_reason=Some(\"Timeout\")
phase=empty_broadcaster
empty_broadcaster::empty_stats=initiated=0, duplicates=0, forwarded=0, pending_retries=0
";

    struct NullSink;

    impl CancelSink for NullSink {
        fn send_to(
            &self,
            _peer: &PeerId,
            _msg: &CancelMessage,
        ) -> impl std::future::Future<Output = crate::error::Result<()>> + Send {
            std::future::ready(Ok(()))
        }

        fn broadcast(
            &self,
            _msg: &CancelMessage,
        ) -> impl std::future::Future<Output = crate::error::Result<usize>> + Send {
            std::future::ready(Ok(0))
        }
    }

    struct CountingCleanupHandler;

    impl CleanupHandler for CountingCleanupHandler {
        fn cleanup(
            &self,
            _object_id: ObjectId,
            symbols: Vec<Symbol>,
        ) -> crate::error::Result<usize> {
            Ok(symbols.len())
        }

        fn name(&self) -> &'static str {
            "counting"
        }
    }

    /// Golden test capturing complete symbol cancellation protocol lifecycle.
    #[test]
    fn symbol_cancel_protocol_lifecycle_golden() {
        let mut rng = DetRng::new(42);
        let mut log = ProtocolLog::new();

        log.phase("token_creation");

        let obj1 = ObjectId::new(0, 0x90ab_cdef);
        let obj2 = ObjectId::new(0, 0xfedc_ba09);
        let budget = Budget::with_deadline_ns(500_000_000);

        let token1 = SymbolCancelToken::with_budget(obj1, budget, &mut rng);
        let token2 = SymbolCancelToken::new(obj2, &mut rng);

        log.record(
            "token1_created",
            &format!(
                "object_id={}, cleanup_budget={}",
                format_object_id(obj1),
                format_budget(token1.cleanup_budget())
            ),
        );
        log.record(
            "token2_created",
            &format!(
                "object_id={}, cleanup_budget={}",
                format_object_id(obj2),
                format_budget(token2.cleanup_budget())
            ),
        );

        log.phase("broadcaster_setup");

        let broadcaster = CancelBroadcaster::new(NullSink);
        broadcaster.register_token(token1.clone());
        broadcaster.register_token(token2.clone());

        log.record("registered_tokens", "2");

        log.phase("listener_registration");

        let listener_events = Arc::new(StdMutex::new(Vec::new()));
        let listener_events_for_token = Arc::clone(&listener_events);

        token1.add_listener(move |reason: &CancelReason, at: Time| {
            listener_events_for_token
                .lock()
                .expect("listener event mutex")
                .push(format!(
                    "kind={:?}, msg={:?}, at={}ns",
                    reason.kind(),
                    reason.message(),
                    at.as_nanos()
                ));
        });
        log.record("token1_listeners", "registered=1");

        log.phase("cancellation_initiation");

        let cancel_time = Time::from_nanos(1_000_000_000);
        let reason = CancelReason::timeout()
            .with_message("operation timeout")
            .with_timestamp(cancel_time);

        let cancel_msg1 = broadcaster.prepare_cancel(obj1, &reason, cancel_time);
        log.record("cancel_msg1", &format_cancel_message(&cancel_msg1));
        log.record(
            "token1_state",
            &format!(
                "cancelled={}, at_ns={:?}, reason_kind={:?}",
                token1.is_cancelled(),
                token1.cancelled_at().map(Time::as_nanos),
                token1.reason().map(|stored| format!("{:?}", stored.kind()))
            ),
        );

        log.phase("message_broadcasting");

        let forward_msg = broadcaster.receive_message(&cancel_msg1, cancel_time);
        log.record(
            "msg_dedup_check",
            &format!("forwarded={}", forward_msg.is_some()),
        );

        let duplicate_msg = broadcaster.receive_message(&cancel_msg1, cancel_time);
        log.record(
            "duplicate_rejected",
            &format!("forwarded={}", duplicate_msg.is_some()),
        );

        log.phase("cross_broadcaster_comm");

        let broadcaster2 = CancelBroadcaster::new(NullSink);
        let token3 = SymbolCancelToken::new(obj1, &mut rng);
        broadcaster2.register_token(token3.clone());

        let received_msg = broadcaster2.receive_message(&cancel_msg1, cancel_time);
        log.record(
            "cross_broadcaster_receive",
            &format!(
                "forwarded={}, token3_cancelled={}, token3_reason={:?}",
                received_msg.is_some(),
                token3.is_cancelled(),
                token3.reason().map(|stored| format!("{:?}", stored.kind()))
            ),
        );

        log.phase("hierarchical_cancellation");

        let child_token = token2.child(&mut rng);
        log.record(
            "child_created",
            &format!(
                "parent_object_id={}, child_object_id={}",
                format_object_id(token2.object_id()),
                format_object_id(child_token.object_id())
            ),
        );

        let reason2 = CancelReason::parent_cancelled()
            .with_message("parent cancelled")
            .with_timestamp(cancel_time);
        token2.cancel(&reason2, cancel_time);

        log.record(
            "hierarchical_result",
            &format!(
                "parent_cancelled={}, child_cancelled={}, child_reason={:?}",
                token2.is_cancelled(),
                child_token.is_cancelled(),
                child_token
                    .reason()
                    .map(|stored| format!("{:?}", stored.kind()))
            ),
        );

        log.phase("cleanup_coordination");

        let cleanup_coordinator = CleanupCoordinator::new();
        let cleanup_budget = Budget::new().with_poll_quota(100);

        cleanup_coordinator.register_handler(obj1, CountingCleanupHandler);
        cleanup_coordinator.register_pending(
            obj1,
            Symbol::new_for_test(0x90ab_cdef, 0, 0, &[1, 2, 3, 4]),
            cancel_time,
        );
        cleanup_coordinator.register_pending(
            obj1,
            Symbol::new_for_test(0x90ab_cdef, 0, 1, &[5, 6, 7, 8]),
            cancel_time,
        );
        cleanup_coordinator.register_pending(
            obj2,
            Symbol::new_for_test(0xfedc_ba09, 0, 0, &[9, 10]),
            cancel_time,
        );

        let cleanup_result = cleanup_coordinator.cleanup(obj1, Some(cleanup_budget));
        log.record("cleanup_obj1", &format_cleanup_result(&cleanup_result));

        let cleanup_result2 = cleanup_coordinator.cleanup(obj2, None);
        log.record("cleanup_obj2", &format_cleanup_result(&cleanup_result2));

        log.phase("final_statistics");

        let broadcaster1_metrics = broadcaster.metrics();
        log.record(
            "broadcaster1_stats",
            &format!(
                "initiated={}, duplicates={}, forwarded={}",
                broadcaster1_metrics.initiated,
                broadcaster1_metrics.duplicates,
                broadcaster1_metrics.forwarded
            ),
        );
        let broadcaster2_metrics = broadcaster2.metrics();
        log.record(
            "broadcaster2_stats",
            &format!(
                "initiated={}, duplicates={}, forwarded={}",
                broadcaster2_metrics.initiated,
                broadcaster2_metrics.duplicates,
                broadcaster2_metrics.forwarded
            ),
        );
        log.record(
            "listener_events",
            &listener_events
                .lock()
                .expect("listener event mutex")
                .first()
                .cloned()
                .unwrap_or_else(|| "none".to_string()),
        );
        log.record(
            "panic_stats",
            &format!(
                "token1={}, token2={}, child={}",
                token1.listener_panic_count(),
                token2.listener_panic_count(),
                child_token.listener_panic_count()
            ),
        );

        assert_eq!(
            log.to_string(),
            EXPECTED_PROTOCOL_LIFECYCLE,
            "Protocol lifecycle golden mismatch"
        );
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

    impl std::fmt::Display for ProtocolLog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for (key, value) in &self.entries {
                writeln!(f, "{}={}", key, value)?;
            }
            Ok(())
        }
    }

    fn format_object_id(object_id: ObjectId) -> String {
        format!("{:016x}{:016x}", object_id.high(), object_id.low())
    }

    fn format_budget(budget: Budget) -> String {
        format!(
            "deadline_ns={:?},poll_quota={},priority={}",
            budget.deadline.map(Time::as_nanos),
            budget.poll_quota,
            budget.priority
        )
    }

    fn format_cancel_message(msg: &CancelMessage) -> String {
        format!(
            "object_id={}, kind={:?}, at={}ns, seq={}",
            format_object_id(msg.object_id()),
            msg.kind(),
            msg.initiated_at().as_nanos(),
            msg.sequence()
        )
    }

    fn format_cleanup_result(result: &CleanupResult) -> String {
        format!(
            "cleaned={}, bytes={}, within_budget={}, completed={}, handlers={}, errors={}",
            result.symbols_cleaned,
            result.bytes_freed,
            result.within_budget,
            result.completed,
            result.handlers_run.len(),
            result.handler_errors.len()
        )
    }

    /// Test additional edge cases for comprehensive coverage.
    #[test]
    fn symbol_cancel_edge_cases_golden() {
        let mut rng = DetRng::new(99);
        let mut log = ProtocolLog::new();

        log.phase("nonexistent_object");

        let broadcaster = CancelBroadcaster::new(NullSink);
        let nonexistent_obj = ObjectId::NIL;
        let reason = CancelReason::user("test");
        let time = Time::from_nanos(2_000_000_000);

        let msg = broadcaster.prepare_cancel(nonexistent_obj, &reason, time);
        log.record("nonexistent_cancel", &format_cancel_message(&msg));

        log.phase("multiple_cancellations");

        let obj = ObjectId::new(0xaaaa_aaaa, 0xbbbb_bbbb);
        let token = SymbolCancelToken::new(obj, &mut rng);

        let reason1 = CancelReason::user("first").with_timestamp(time);
        let reason2 = CancelReason::timeout()
            .with_message("second")
            .with_timestamp(time);

        let result1 = token.cancel(&reason1, time);
        let result2 = token.cancel(&reason2, time);

        log.record("first_cancel", &format!("success={}", result1));
        log.record("second_cancel", &format!("success={}", result2));
        log.record(
            "final_reason",
            &format!(
                "{:?}",
                token.reason().map(|stored| format!("{:?}", stored.kind()))
            ),
        );

        log.phase("empty_broadcaster");

        let empty_broadcaster = CancelBroadcaster::new(NullSink);
        let metrics = empty_broadcaster.metrics();
        log.record(
            "empty_stats",
            &format!(
                "initiated={}, duplicates={}, forwarded={}, pending_retries={}",
                metrics.initiated, metrics.duplicates, metrics.forwarded, metrics.pending_retries
            ),
        );

        assert_eq!(
            log.to_string(),
            EXPECTED_EDGE_CASES,
            "Edge cases golden mismatch"
        );
    }
}
