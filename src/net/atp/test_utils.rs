//! Test utilities for ATP module development.
//!
//! Provides common fixtures, helpers, and assertions for testing ATP components
//! in a deterministic and cancellation-correct manner.

use crate::cx::Cx;
use crate::types::{Budget, Time};
use std::time::Duration;

/// Test-specific budget for ATP operations.
pub const TEST_BUDGET_DEADLINE_MS: u64 = 5_000;

/// Test-specific budget for ATP operations.
pub const TEST_BUDGET: Budget =
    Budget::new().with_deadline(Time::from_millis(TEST_BUDGET_DEADLINE_MS));

/// Default test timeout for ATP operations.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Creates a test context with appropriate budget and cancellation setup.
///
/// The deadline is [`TEST_BUDGET_DEADLINE_MS`] after creation. [`TEST_BUDGET`]
/// holds that span as an absolute time on the process clock, so a context
/// built from it directly expires once the test process is five seconds old.
pub fn test_cx() -> Cx {
    let deadline = crate::time::wall_now() + Duration::from_millis(TEST_BUDGET_DEADLINE_MS);
    Cx::for_testing_with_budget(Budget::new().with_deadline(deadline))
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
            Outcome::Cancelled(_) => panic!("Expected Ok, got Cancelled"),
            Outcome::Panicked(_) => panic!("Expected Ok, got Panicked"),
        }
    }

    /// Assert that an ATP outcome is cancelled.
    pub fn assert_atp_cancelled<T, E>(outcome: Outcome<T, E>)
    where
        T: std::fmt::Debug,
        E: std::fmt::Debug,
    {
        match outcome {
            Outcome::Cancelled(_) => {}
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
            Outcome::Cancelled(_) => panic!("Expected Err, got Cancelled"),
            Outcome::Panicked(_) => panic!("Expected Err, got Panicked"),
        }
    }
}

/// Deterministic ATP fixtures for testing protocol components without external dependencies.
pub mod fixtures {
    use crate::net::atp::protocol::{
        AtpFeature, ClientHello, PeerId, SessionContextKind, SessionId, SessionNegotiator,
        SessionPolicy, SessionTraceId, TransferNonce,
    };

    /// Create a deterministic test peer ID.
    pub fn test_peer_id(suffix: u64) -> PeerId {
        PeerId::from_label(&format!("test_peer_{}", suffix))
    }

    /// Create a deterministic test session ID.
    pub fn test_session_id(suffix: u64) -> SessionId {
        let initiator = PeerId::from_label(&format!("fixture_initiator_{suffix}"));
        let responder = PeerId::from_label(&format!("fixture_responder_{suffix}"));
        let nonce = TransferNonce::from_seed(&format!("fixture_nonce_{suffix}"));
        let hello = ClientHello::new(
            initiator,
            responder,
            nonce,
            SessionContextKind::Direct,
            SessionTraceId::new(suffix),
        )
        .with_features(&[AtpFeature::EncryptionPolicy]);
        let mut policy = SessionPolicy::new(responder, suffix);
        let mut server = SessionNegotiator::server(responder);
        let (server_hello, _, _) = server
            .accept_client_hello(&hello, &mut policy)
            .expect("fixture ATP session negotiation should succeed");
        server_hello.session_id
    }
}

#[cfg(test)]
#[path = "test_utils_inline_tests.rs"]
mod tests;
