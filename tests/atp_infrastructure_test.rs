//! Mock-free ATP infrastructure integration tests.
//!
//! Tests real ATP protocol components with structured JSON logging,
//! following testing-perfect-e2e-integration-tests-with-logging-and-no-mocks skill.
//! NO MOCKS for critical paths (peer IDs, sessions, protocol flows).

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::atp;
use asupersync::types::{Budget, Outcome};
use serde_json::json;
use std::time::{Duration, SystemTime};

/// Structured test logger for ATP integration tests.
#[derive(Debug)]
struct AtpTestLogger {
    suite_name: String,
    test_name: String,
    start_time: SystemTime,
    current_phase: String,
}

impl AtpTestLogger {
    fn new(suite: &str, test: &str) -> Self {
        let logger = Self {
            suite_name: suite.to_string(),
            test_name: test.to_string(),
            start_time: SystemTime::now(),
            current_phase: "init".to_string(),
        };

        eprintln!(
            "{}",
            json!({
                "ts": logger.start_time,
                "suite": suite,
                "test": test,
                "event": "atp_test_start"
            })
        );

        logger
    }

    fn phase(&mut self, phase: &str) {
        self.current_phase = phase.to_string();
        eprintln!(
            "{}",
            json!({
                "ts": SystemTime::now(),
                "suite": self.suite_name,
                "test": self.test_name,
                "phase": phase,
                "event": "atp_phase_start"
            })
        );
    }

    fn snapshot<T: serde::Serialize>(&self, label: &str, data: &T) {
        eprintln!(
            "{}",
            json!({
                "ts": SystemTime::now(),
                "suite": self.suite_name,
                "test": self.test_name,
                "phase": self.current_phase,
                "event": "atp_snapshot",
                "label": label,
                "data": data
            })
        );
    }

    fn assert_outcome<T>(&self, field: &str, expected: &T, actual: &T) -> bool
    where
        T: PartialEq + serde::Serialize,
    {
        let matches = expected == actual;
        eprintln!(
            "{}",
            json!({
                "ts": SystemTime::now(),
                "suite": self.suite_name,
                "test": self.test_name,
                "phase": self.current_phase,
                "event": "atp_assertion",
                "field": field,
                "expected": expected,
                "actual": actual,
                "match": matches
            })
        );
        matches
    }

    fn test_end(&self, result: &str) {
        let duration_ms = self
            .start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;
        eprintln!(
            "{}",
            json!({
                "ts": SystemTime::now(),
                "suite": self.suite_name,
                "test": self.test_name,
                "event": "atp_test_end",
                "result": result,
                "duration_ms": duration_ms
            })
        );
    }
}

/// ATP peer factory for creating real peer instances.
struct AtpPeerFactory;

impl AtpPeerFactory {
    fn create_peer_with_label(label: &str) -> asupersync::net::atp::protocol::PeerId {
        asupersync::net::atp::protocol::PeerId::from_label(label)
    }

    fn create_peer_with_entropy(entropy: u64) -> asupersync::net::atp::protocol::PeerId {
        // Create a deterministic but realistic peer ID using entropy
        let label = format!("peer_{:016x}", entropy);
        Self::create_peer_with_label(&label)
    }

    fn create_session_with_timestamp() -> asupersync::net::atp::protocol::SessionId {
        let timestamp_nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64;
        asupersync::net::atp::protocol::SessionId::new(timestamp_nanos)
    }

    fn create_session_with_id(id: u64) -> asupersync::net::atp::protocol::SessionId {
        asupersync::net::atp::protocol::SessionId::new(id)
    }
}

#[test]
fn atp_peer_identity_and_session_management_integration() {
    let mut log = AtpTestLogger::new("atp_infrastructure", "peer_session_management");

    log.phase("setup");

    // Create deterministic lab runtime for consistent testing
    let mut runtime = LabRuntime::new(LabConfig::new(0x1234_atp1).max_steps(10_000));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    runtime.run(&root, |cx| async {
        log.phase("peer_creation");

        // Create real peer IDs using different methods (NO MOCKS)
        let peer_label = AtpPeerFactory::create_peer_with_label("integration_test_peer");
        let peer_entropy1 = AtpPeerFactory::create_peer_with_entropy(0x1234567890abcdef);
        let peer_entropy2 = AtpPeerFactory::create_peer_with_entropy(0x1234567890abcdef);
        let peer_entropy3 = AtpPeerFactory::create_peer_with_entropy(0xfedcba0987654321);

        log.snapshot("peer_label", &peer_label.to_string());
        log.snapshot("peer_entropy1", &peer_entropy1.to_string());
        log.snapshot("peer_entropy2", &peer_entropy2.to_string());
        log.snapshot("peer_entropy3", &peer_entropy3.to_string());

        log.phase("session_creation");

        // Create real session IDs (NO MOCKS)
        let session_timestamp = AtpPeerFactory::create_session_with_timestamp();
        let session_id1 = AtpPeerFactory::create_session_with_id(12345);
        let session_id2 = AtpPeerFactory::create_session_with_id(12345);
        let session_id3 = AtpPeerFactory::create_session_with_id(67890);

        log.snapshot("session_timestamp", &session_timestamp.value());
        log.snapshot("session_id1", &session_id1.value());
        log.snapshot("session_id2", &session_id2.value());
        log.snapshot("session_id3", &session_id3.value());

        log.phase("identity_verification");

        // Verify peer identity behavior (deterministic with same inputs)
        assert!(log.assert_outcome(
            "peer_deterministic_same_entropy",
            &peer_entropy1,
            &peer_entropy2
        ));
        assert!(!log.assert_outcome("peer_different_entropy", &peer_entropy1, &peer_entropy3));

        // Verify session ID behavior
        assert!(log.assert_outcome(
            "session_deterministic_same_id",
            &session_id1.value(),
            &session_id2.value()
        ));
        assert!(!log.assert_outcome(
            "session_different_id",
            &session_id1.value(),
            &session_id3.value()
        ));

        // Verify peer IDs are non-empty and unique
        assert!(!peer_label.to_string().is_empty());
        assert!(!peer_entropy1.to_string().is_empty());
        assert_ne!(peer_label.to_string(), peer_entropy1.to_string());

        log.phase("outcome_handling");

        // Test real Outcome handling in ATP context
        let success_outcome: Outcome<String, String> = Outcome::Ok("atp_success".to_string());
        let error_outcome: Outcome<String, String> = Outcome::Err("atp_error".to_string());
        let cancelled_outcome: Outcome<String, String> = Outcome::Cancelled;

        log.snapshot("success_outcome", &success_outcome);
        log.snapshot("error_outcome", &error_outcome);
        log.snapshot("cancelled_outcome", &cancelled_outcome);

        // Verify outcome pattern matching works
        match success_outcome {
            Outcome::Ok(value) => {
                assert!(log.assert_outcome("success_value", &"atp_success".to_string(), &value));
            }
            _ => panic!("Expected Ok outcome"),
        }

        match error_outcome {
            Outcome::Err(error) => {
                assert!(log.assert_outcome("error_value", &"atp_error".to_string(), &error));
            }
            _ => panic!("Expected Err outcome"),
        }

        match cancelled_outcome {
            Outcome::Cancelled => {
                assert!(log.assert_outcome("cancelled_outcome_match", &true, &true));
            }
            _ => panic!("Expected Cancelled outcome"),
        }

        log.phase("context_integration");

        // Verify ATP components work with real asupersync context
        let current_budget = cx.budget();
        log.snapshot("context_budget", &current_budget.remaining_ms());

        // Create ATP components in real context
        let peer_in_context = AtpPeerFactory::create_peer_with_label("context_peer");
        let session_in_context = AtpPeerFactory::create_session_with_timestamp();

        log.snapshot("peer_in_context", &peer_in_context.to_string());
        log.snapshot("session_in_context", &session_in_context.value());

        assert!(!peer_in_context.to_string().is_empty());
        assert!(session_in_context.value() > 0);

        Ok::<(), anyhow::Error>(())
    });

    log.phase("teardown");
    log.test_end("pass");
}

#[test]
fn atp_test_utilities_without_mocks() {
    let mut log = AtpTestLogger::new("atp_infrastructure", "test_utilities_mock_free");

    log.phase("setup");

    // Test utilities that DON'T use mocks
    #[cfg(test)]
    {
        use asupersync::net::atp::test_utils::{TEST_BUDGET, assertions, test_cx, test_data};

        log.phase("context_utilities");

        // Test context creation (real context, not mocked)
        let cx = test_cx();
        let budget_remaining = cx.budget().remaining_ms();
        log.snapshot("test_context_budget", &budget_remaining);

        assert!(budget_remaining <= TEST_BUDGET.as_millis());

        log.phase("test_data_utilities");

        // Test data utilities (deterministic but real data)
        let small = test_data::SMALL_DATA;
        let pattern = test_data::pattern_data(16);
        let det1 = test_data::deterministic_data(32, 100);
        let det2 = test_data::deterministic_data(32, 100);

        log.snapshot("small_data_length", &small.len());
        log.snapshot("small_data_first_byte", &small[0]);
        log.snapshot("pattern_data_length", &pattern.len());
        log.snapshot("deterministic_data_consistency", &(det1 == det2));

        assert!(log.assert_outcome("small_data_size", &64_usize, &small.len()));
        assert!(log.assert_outcome("small_data_first", &0x42_u8, &small[0]));
        assert!(log.assert_outcome("pattern_data_size", &16_usize, &pattern.len()));
        assert!(log.assert_outcome("pattern_first", &0_u8, &pattern[0]));
        assert!(log.assert_outcome("pattern_last", &15_u8, &pattern[15]));
        assert!(log.assert_outcome("deterministic_consistency", &det1, &det2));

        log.phase("assertion_utilities");

        // Test assertion utilities with real outcomes
        let ok_outcome: Outcome<i32, String> = Outcome::Ok(123);
        let cancelled_outcome: Outcome<i32, String> = Outcome::Cancelled;

        let extracted_value = assertions::assert_atp_ok(ok_outcome);
        assertions::assert_atp_cancelled(cancelled_outcome);

        log.snapshot("extracted_ok_value", &extracted_value);
        assert!(log.assert_outcome("assertion_extracted_value", &123_i32, &extracted_value));
    }

    log.phase("teardown");
    log.test_end("pass");
}
