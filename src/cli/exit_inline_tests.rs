    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::collections::HashSet;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn exit_codes_are_distinct() {
        init_test("exit_codes_are_distinct");
        let codes = vec![
            ExitCode::SUCCESS,
            ExitCode::USER_ERROR,
            ExitCode::RUNTIME_ERROR,
            ExitCode::INTERNAL_ERROR,
            ExitCode::CANCELLED,
            ExitCode::PARTIAL_SUCCESS,
            ExitCode::TEST_FAILURE,
            ExitCode::ORACLE_VIOLATION,
            ExitCode::DETERMINISM_FAILURE,
            ExitCode::TRACE_MISMATCH,
        ];

        let unique: HashSet<_> = codes.iter().collect();
        let len = codes.len();
        let unique_len = unique.len();
        crate::assert_with_log!(len == unique_len, "unique codes", len, unique_len);
        crate::test_complete!("exit_codes_are_distinct");
    }

    #[test]
    fn exit_codes_in_valid_range() {
        init_test("exit_codes_in_valid_range");
        let codes = vec![
            ExitCode::SUCCESS,
            ExitCode::USER_ERROR,
            ExitCode::RUNTIME_ERROR,
            ExitCode::INTERNAL_ERROR,
            ExitCode::CANCELLED,
            ExitCode::PARTIAL_SUCCESS,
            ExitCode::TEST_FAILURE,
            ExitCode::ORACLE_VIOLATION,
            ExitCode::DETERMINISM_FAILURE,
            ExitCode::TRACE_MISMATCH,
        ];

        for code in codes {
            let in_range = (0..=125).contains(&code);
            crate::assert_with_log!(in_range, "code in range", "0..=125", code);
        }
        crate::test_complete!("exit_codes_in_valid_range");
    }

    #[test]
    fn exit_code_descriptions_not_empty() {
        init_test("exit_code_descriptions_not_empty");
        let codes = [0, 1, 2, 3, 4, 5, 10, 11, 12, 13];
        for code in codes {
            let desc = ExitCode::description(code);
            crate::assert_with_log!(!desc.is_empty(), "description not empty", "non-empty", desc);
            crate::assert_with_log!(
                desc != "unknown",
                "description not unknown",
                "not unknown",
                desc
            );
        }
        crate::test_complete!("exit_code_descriptions_not_empty");
    }

    #[test]
    fn unknown_code_description() {
        init_test("unknown_code_description");
        let desc = ExitCode::description(99);
        crate::assert_with_log!(desc == "unknown", "99 unknown", "unknown", desc);
        let desc = ExitCode::description(-1);
        crate::assert_with_log!(desc == "unknown", "-1 unknown", "unknown", desc);
        crate::test_complete!("unknown_code_description");
    }

    #[test]
    fn is_success_and_failure() {
        init_test("is_success_and_failure");
        let success0 = ExitCode::is_success(0);
        crate::assert_with_log!(success0, "success 0", true, success0);
        let success1 = ExitCode::is_success(1);
        crate::assert_with_log!(!success1, "success 1 false", false, success1);
        let failure0 = ExitCode::is_failure(0);
        crate::assert_with_log!(!failure0, "failure 0 false", false, failure0);
        let failure1 = ExitCode::is_failure(1);
        crate::assert_with_log!(failure1, "failure 1 true", true, failure1);
        crate::test_complete!("is_success_and_failure");
    }

    #[test]
    fn exit_code_validity_matches_documented_range() {
        init_test("exit_code_validity_matches_documented_range");
        crate::assert_with_log!(
            ExitCode::is_valid(0),
            "0 valid",
            true,
            ExitCode::is_valid(0)
        );
        crate::assert_with_log!(
            ExitCode::is_valid(125),
            "125 valid",
            true,
            ExitCode::is_valid(125)
        );
        crate::assert_with_log!(
            !ExitCode::is_valid(-1),
            "-1 invalid",
            false,
            ExitCode::is_valid(-1)
        );
        crate::assert_with_log!(
            !ExitCode::is_valid(126),
            "126 invalid",
            false,
            ExitCode::is_valid(126)
        );
        crate::test_complete!("exit_code_validity_matches_documented_range");
    }

    #[test]
    fn sanitize_invalid_exit_codes_to_internal_error() {
        init_test("sanitize_invalid_exit_codes_to_internal_error");
        let reserved = ExitCode::sanitize(126);
        crate::assert_with_log!(
            reserved == ExitCode::INTERNAL_ERROR,
            "126 sanitized",
            ExitCode::INTERNAL_ERROR,
            reserved
        );
        let negative = ExitCode::sanitize(-7);
        crate::assert_with_log!(
            negative == ExitCode::INTERNAL_ERROR,
            "-7 sanitized",
            ExitCode::INTERNAL_ERROR,
            negative
        );
        let valid = ExitCode::sanitize(ExitCode::TEST_FAILURE);
        crate::assert_with_log!(
            valid == ExitCode::TEST_FAILURE,
            "valid preserved",
            ExitCode::TEST_FAILURE,
            valid
        );
        crate::test_complete!("sanitize_invalid_exit_codes_to_internal_error");
    }
