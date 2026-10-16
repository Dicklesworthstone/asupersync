    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn new_creates_with_deadline() {
        init_test("new_creates_with_deadline");
        let deadline = Time::from_secs(10);
        let elapsed = Elapsed::new(deadline);
        crate::assert_with_log!(
            elapsed.deadline() == deadline,
            "deadline matches",
            deadline,
            elapsed.deadline()
        );
        crate::test_complete!("new_creates_with_deadline");
    }

    #[test]
    fn deadline_nanos() {
        init_test("deadline_nanos");
        let elapsed = Elapsed::new(Time::from_millis(500));
        crate::assert_with_log!(
            elapsed.deadline_nanos() == 500_000_000,
            "deadline nanos",
            500_000_000u64,
            elapsed.deadline_nanos()
        );
        crate::test_complete!("deadline_nanos");
    }

    #[test]
    fn const_accessors_work_in_const_contexts() {
        init_test("const_accessors_work_in_const_contexts");

        const ELAPSED: Elapsed = Elapsed::new(Time::from_secs(3));
        const DEADLINE: Time = ELAPSED.deadline();
        const DEADLINE_NANOS: u64 = ELAPSED.deadline_nanos();

        crate::assert_with_log!(
            DEADLINE == Time::from_secs(3),
            "const deadline",
            Time::from_secs(3),
            DEADLINE
        );
        crate::assert_with_log!(
            DEADLINE_NANOS == 3_000_000_000,
            "const deadline nanos",
            3_000_000_000u64,
            DEADLINE_NANOS
        );
        crate::test_complete!("const_accessors_work_in_const_contexts");
    }

    #[test]
    fn display_format() {
        init_test("display_format");
        let elapsed = Elapsed::new(Time::from_secs(5));
        let s = elapsed.to_string();
        crate::assert_with_log!(
            s.contains("elapsed"),
            "contains 'elapsed'",
            true,
            s.contains("elapsed")
        );
        crate::assert_with_log!(
            s.contains("5000000000"),
            "contains nanos",
            true,
            s.contains("5000000000")
        );
        crate::test_complete!("display_format");
    }

    #[test]
    fn default_is_zero() {
        init_test("default_is_zero");
        let elapsed = Elapsed::default();
        crate::assert_with_log!(
            elapsed.deadline() == Time::ZERO,
            "deadline zero",
            Time::ZERO,
            elapsed.deadline()
        );
        crate::test_complete!("default_is_zero");
    }

    #[test]
    fn clone_and_copy() {
        init_test("clone_and_copy");
        let e1 = Elapsed::new(Time::from_secs(1));
        let e2 = e1; // Copy
        let e3 = e1; // Also copy
        crate::assert_with_log!(e1 == e2, "e1 == e2", e2, e1);
        crate::assert_with_log!(e2 == e3, "e2 == e3", e3, e2);
        crate::test_complete!("clone_and_copy");
    }

    #[test]
    fn equality() {
        init_test("equality");
        let e1 = Elapsed::new(Time::from_secs(1));
        let e2 = Elapsed::new(Time::from_secs(1));
        let e3 = Elapsed::new(Time::from_secs(2));

        crate::assert_with_log!(e1 == e2, "e1 == e2", e2, e1);
        crate::assert_with_log!(e1 != e3, "e1 != e3", true, e1 != e3);
        crate::test_complete!("equality");
    }

    #[test]
    fn is_error() {
        init_test("is_error");
        let elapsed = Elapsed::new(Time::from_secs(1));
        // Verify it implements Error
        let _: &dyn std::error::Error = &elapsed;
        crate::test_complete!("is_error");
    }
