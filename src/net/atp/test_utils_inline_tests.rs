    use super::assertions::*;
    use super::test_data::*;
    use super::*;
    use crate::types::{CancelReason, Outcome};

    /// The budget runs from creation. An absolute deadline on the process
    /// clock expired for every context made after the test binary was five
    /// seconds old, failing ATP conformance cases on a loaded worker
    /// (br-asupersync-bi2462.147.74).
    #[test]
    fn test_cx_creation() {
        // Start the shared process clock and let it advance, so a deadline
        // fixed at five seconds cannot pass for one measured from creation.
        let _ = crate::time::wall_now();
        std::thread::sleep(Duration::from_millis(10));
        let before = crate::time::wall_now();
        let cx = test_cx();
        let after = crate::time::wall_now();
        let budget = Duration::from_millis(TEST_BUDGET_DEADLINE_MS);
        let deadline = cx.budget().deadline.expect("test budget has a deadline");
        assert!(
            deadline >= before + budget && deadline <= after + budget,
            "deadline {deadline:?} is not {budget:?} after {before:?}..{after:?}"
        );
        assert!(cx.checkpoint().is_ok());
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
        let outcome: Outcome<i32, String> = Outcome::cancelled(CancelReason::user("test"));
        assert_atp_ok(outcome);
    }

    #[test]
    fn test_assert_atp_cancelled() {
        let outcome: Outcome<i32, String> = Outcome::cancelled(CancelReason::user("test"));
        assert_atp_cancelled(outcome);
    }

    #[test]
    fn test_assert_atp_err() {
        let outcome: Outcome<i32, String> = Outcome::Err("test error".to_string());
        let err = assert_atp_err(outcome);
        assert_eq!(err, "test error");
    }

    #[test]
    fn test_fixture_peer_ids() {
        let peer1 = fixtures::test_peer_id(1);
        let peer2 = fixtures::test_peer_id(2);
        let peer1_again = fixtures::test_peer_id(1);

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
    fn test_fixture_session_ids() {
        let session1 = fixtures::test_session_id(100);
        let session2 = fixtures::test_session_id(200);
        let session1_again = fixtures::test_session_id(100);

        assert_eq!(
            session1, session1_again,
            "Same suffix should produce same session ID"
        );
        assert_ne!(
            session1, session2,
            "Different suffix should produce different session ID"
        );
    }
