//! Test utilities for ATP module development.
//!
//! Provides common fixtures, helpers, and assertions for testing ATP components
//! in a deterministic and cancellation-correct manner.

use crate::cx::Cx;
use crate::types::Budget;
use std::time::Duration;

/// Test-specific budget for ATP operations.
pub const TEST_BUDGET: Budget = Budget::from_millis(5000);

/// Default test timeout for ATP operations.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Creates a test context with appropriate budget and cancellation setup.
pub fn test_cx() -> Cx {
    let cx = Cx::root();
    cx.set_budget(TEST_BUDGET);
    cx
}

/// Test data patterns for ATP testing.
pub mod test_data {
    /// Small test data (64 bytes) for basic operations.
    pub const SMALL_DATA: &[u8] = &[0x42; 64];

    /// Medium test data (4KB) for chunk testing.
    pub const MEDIUM_DATA: &[u8] = &[0xAB; 4096];

    /// Pattern data with incrementing bytes for integrity testing.
    pub fn pattern_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    /// Random-like deterministic data for testing.
    pub fn deterministic_data(size: usize, seed: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(size);
        let mut state = seed;
        for _ in 0..size {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            data.push((state >> 16) as u8);
        }
        data
    }
}

/// Test assertions specific to ATP behavior.
pub mod assertions {
    use crate::types::Outcome;

    /// Assert that an ATP outcome is successful and extract the value.
    pub fn assert_atp_ok<T, E>(outcome: Outcome<T, E>) -> T
    where
        E: std::fmt::Debug,
    {
        match outcome {
            Outcome::Ok(value) => value,
            Outcome::Err(err) => panic!("Expected Ok, got Err: {:?}", err),
            Outcome::Cancelled => panic!("Expected Ok, got Cancelled"),
            Outcome::Panicked => panic!("Expected Ok, got Panicked"),
        }
    }

    /// Assert that an ATP outcome is cancelled.
    pub fn assert_atp_cancelled<T, E>(outcome: Outcome<T, E>)
    where
        T: std::fmt::Debug,
        E: std::fmt::Debug,
    {
        match outcome {
            Outcome::Cancelled => {}
            other => panic!("Expected Cancelled, got: {:?}", other),
        }
    }

    /// Assert that an ATP outcome is an error of expected type.
    pub fn assert_atp_err<T, E>(outcome: Outcome<T, E>) -> E
    where
        T: std::fmt::Debug,
    {
        match outcome {
            Outcome::Err(err) => err,
            Outcome::Ok(value) => panic!("Expected Err, got Ok: {:?}", value),
            Outcome::Cancelled => panic!("Expected Err, got Cancelled"),
            Outcome::Panicked => panic!("Expected Err, got Panicked"),
        }
    }
}

/// Mock types for testing ATP components without external dependencies.
pub mod mocks {
    use crate::net::atp::protocol::{PeerId, SessionId};

    /// Create a deterministic test peer ID.
    pub fn test_peer_id(suffix: u64) -> PeerId {
        PeerId::from_label(&format!("test_peer_{}", suffix))
    }

    /// Create a deterministic test session ID.
    pub fn test_session_id(suffix: u64) -> SessionId {
        SessionId::new(suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::assertions::*;
    use super::test_data::*;
    use super::*;
    use crate::types::Outcome;

    #[test]
    fn test_cx_creation() {
        let cx = test_cx();
        assert!(cx.budget().remaining_ms() <= TEST_BUDGET.as_millis());
    }

    #[test]
    fn test_pattern_data() {
        let data = pattern_data(256);
        assert_eq!(data.len(), 256);
        assert_eq!(data[0], 0);
        assert_eq!(data[255], 255);
        assert_eq!(data[128], 128);
    }

    #[test]
    fn test_deterministic_data() {
        let data1 = deterministic_data(100, 42);
        let data2 = deterministic_data(100, 42);
        let data3 = deterministic_data(100, 43);

        assert_eq!(data1, data2, "Same seed should produce same data");
        assert_ne!(data1, data3, "Different seed should produce different data");
        assert_eq!(data1.len(), 100);
    }

    #[test]
    fn test_assert_atp_ok() {
        let outcome: Outcome<i32, String> = Outcome::Ok(42);
        let value = assert_atp_ok(outcome);
        assert_eq!(value, 42);
    }

    #[test]
    #[should_panic(expected = "Expected Ok, got Cancelled")]
    fn test_assert_atp_ok_with_cancelled() {
        let outcome: Outcome<i32, String> = Outcome::Cancelled;
        assert_atp_ok(outcome);
    }

    #[test]
    fn test_assert_atp_cancelled() {
        let outcome: Outcome<i32, String> = Outcome::Cancelled;
        assert_atp_cancelled(outcome);
    }

    #[test]
    fn test_assert_atp_err() {
        let outcome: Outcome<i32, String> = Outcome::Err("test error".to_string());
        let err = assert_atp_err(outcome);
        assert_eq!(err, "test error");
    }

    #[test]
    fn test_mock_peer_ids() {
        let peer1 = mocks::test_peer_id(1);
        let peer2 = mocks::test_peer_id(2);
        let peer1_again = mocks::test_peer_id(1);

        assert_eq!(
            peer1, peer1_again,
            "Same suffix should produce same peer ID"
        );
        assert_ne!(
            peer1, peer2,
            "Different suffix should produce different peer ID"
        );
    }

    #[test]
    fn test_mock_session_ids() {
        let session1 = mocks::test_session_id(100);
        let session2 = mocks::test_session_id(200);
        let session1_again = mocks::test_session_id(100);

        assert_eq!(
            session1, session1_again,
            "Same suffix should produce same session ID"
        );
        assert_ne!(
            session1, session2,
            "Different suffix should produce different session ID"
        );
    }
}
