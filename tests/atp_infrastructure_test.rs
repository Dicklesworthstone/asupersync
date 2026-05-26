//! ATP infrastructure compilation and basic functionality test.
//!
//! This test ensures that the ATP modules compile correctly and basic
//! infrastructure works as expected. Serves as a foundational test for
//! ATP development.

use asupersync::net::atp;
use asupersync::cx::Cx;
use asupersync::types::{Budget, Outcome};

#[tokio::test]
async fn test_atp_module_compilation() {
    // This test primarily ensures that ATP modules compile and basic types work.
    // The fact that this test runs successfully means the ATP infrastructure
    // is at least minimally functional.

    let cx = Cx::root();
    cx.set_budget(Budget::from_millis(1000));

    // Test that we can create basic ATP types
    let peer_id = asupersync::net::atp::protocol::PeerId::from_label("test_peer");
    let session_id = asupersync::net::atp::protocol::SessionId::new(12345);

    // Basic sanity checks
    assert_ne!(peer_id.to_string(), "");
    assert_eq!(session_id.value(), 12345);

    // Test basic outcome handling
    let outcome: Outcome<u32, String> = Outcome::Ok(42);
    match outcome {
        Outcome::Ok(value) => assert_eq!(value, 42),
        _ => panic!("Expected Ok outcome"),
    }
}

#[cfg(test)]
mod atp_test_utils_tests {
    use super::*;

    #[test]
    fn test_atp_test_utilities_compilation() {
        // Ensure ATP test utilities compile and work
        #[cfg(test)]
        {
            use asupersync::net::atp::test_utils::{
                test_cx, test_data, assertions, mocks, TEST_BUDGET
            };

            // Test context creation
            let cx = test_cx();
            assert!(cx.budget().remaining_ms() <= TEST_BUDGET.as_millis());

            // Test data utilities
            let small = test_data::SMALL_DATA;
            assert_eq!(small.len(), 64);
            assert_eq!(small[0], 0x42);

            let pattern = test_data::pattern_data(16);
            assert_eq!(pattern.len(), 16);
            assert_eq!(pattern[0], 0);
            assert_eq!(pattern[15], 15);

            let det1 = test_data::deterministic_data(32, 100);
            let det2 = test_data::deterministic_data(32, 100);
            assert_eq!(det1, det2, "Deterministic data should be consistent");

            // Test assertion utilities
            let ok_outcome: Outcome<i32, String> = Outcome::Ok(123);
            let value = assertions::assert_atp_ok(ok_outcome);
            assert_eq!(value, 123);

            let cancelled_outcome: Outcome<i32, String> = Outcome::Cancelled;
            assertions::assert_atp_cancelled(cancelled_outcome);

            // Test mock utilities
            let peer1 = mocks::test_peer_id(1);
            let peer2 = mocks::test_peer_id(1);
            assert_eq!(peer1, peer2, "Mock peer IDs should be deterministic");

            let session1 = mocks::test_session_id(500);
            let session2 = mocks::test_session_id(500);
            assert_eq!(session1, session2, "Mock session IDs should be deterministic");
        }
    }
}