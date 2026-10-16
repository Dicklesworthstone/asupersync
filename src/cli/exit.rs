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

    /// Lowest valid process exit code that is not shell-reserved.
    pub const MIN_VALID: i32 = 0;

    /// Highest valid process exit code that is not shell-reserved.
    pub const MAX_VALID: i32 = 125;

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

    /// Check whether a code is safe to pass to `std::process::exit`.
    #[must_use]
    pub const fn is_valid(code: i32) -> bool {
        code >= Self::MIN_VALID && code <= Self::MAX_VALID
    }

    /// Sanitize arbitrary integers into the supported semantic exit-code range.
    ///
    /// Invalid or shell-reserved values are treated as internal tool bugs.
    #[must_use]
    pub const fn sanitize(code: i32) -> i32 {
        if Self::is_valid(code) {
            code
        } else {
            Self::INTERNAL_ERROR
        }
    }

    /// Check if an exit code indicates any kind of failure (non-zero).
    #[must_use]
    pub const fn is_failure(code: i32) -> bool {
        code != Self::SUCCESS
    }
}

#[cfg(test)]
#[path = "exit_inline_tests.rs"]
mod tests;
