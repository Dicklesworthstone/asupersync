//! Semantic exit codes for Asupersync CLI tools.
//!
//! Exit codes follow common conventions and are in the valid range (0-125).
//! Codes 126-255 are reserved by shells for special purposes.

/// Semantic exit codes for CLI tools.
///
/// These follow common conventions and provide machine-readable status.
/// All codes are in the valid range (0-125).
pub struct ExitCode;

impl ExitCode {
    /// Success - operation completed without errors.
    pub const SUCCESS: i32 = 0;

    /// User error - bad arguments, missing files, invalid input.
    pub const USER_ERROR: i32 = 1;

    /// Runtime error - test failed, invariant violated.
    pub const RUNTIME_ERROR: i32 = 2;

    /// Internal error - bug in the tool itself.
    pub const INTERNAL_ERROR: i32 = 3;

    /// Operation cancelled - by user signal or timeout.
    pub const CANCELLED: i32 = 4;

    /// Partial success - some items succeeded, some failed.
    pub const PARTIAL_SUCCESS: i32 = 5;

    // Application-specific codes (10-125)

    /// Test failure - one or more tests failed.
    pub const TEST_FAILURE: i32 = 10;

    /// Oracle violation detected during testing.
    pub const ORACLE_VIOLATION: i32 = 11;

    /// Determinism check failed - non-reproducible execution.
    pub const DETERMINISM_FAILURE: i32 = 12;

    /// Trace mismatch during replay.
    pub const TRACE_MISMATCH: i32 = 13;

    /// Get human-readable description of an exit code.
    #[must_use]
    pub const fn description(code: i32) -> &'static str {
        match code {
            0 => "success",
            1 => "user error (invalid input/arguments)",
            2 => "runtime error",
            3 => "internal error (bug)",
            4 => "cancelled",
            5 => "partial success",
            10 => "test failure",
            11 => "oracle violation",
            12 => "determinism failure",
            13 => "trace mismatch",
            _ => "unknown",
        }
    }

    /// Check if an exit code indicates success (code 0).
    #[must_use]
    pub const fn is_success(code: i32) -> bool {
        code == Self::SUCCESS
    }

    /// Check if an exit code indicates any kind of failure (non-zero).
    #[must_use]
    pub const fn is_failure(code: i32) -> bool {
        code != Self::SUCCESS
    }
}

#[cfg(test)]
mod tests {
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
}
