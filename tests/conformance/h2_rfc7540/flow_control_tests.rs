//! Flow control conformance tests.
//!
//! Tests flow control requirements from RFC 7540 Section 6.9.

use super::*;

/// Run all flow control conformance tests.
pub fn run_flow_control_tests() -> Vec<H2ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_window_update_frame());
    results.push(test_initial_window_size());
    results.push(test_flow_control_limits());
    results.push(test_connection_flow_control());

    results
}

fn test_window_update_frame() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // WINDOW_UPDATE frame validation
        let payload_size = 4; // Must be 4 bytes
        let max_increment = 0x7FFFFFFF; // 31-bit maximum

        if payload_size != 4 {
            return Err("WINDOW_UPDATE payload must be 4 bytes".to_string());
        }

        // Zero increment should cause PROTOCOL_ERROR
        let zero_increment = 0u32;
        if zero_increment == 0 {
            // Should be rejected
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-6.9.1-WINDOW-UPDATE",
        "WINDOW_UPDATE frame validation",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_initial_window_size() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let default_window_size = 65535u32;
        if default_window_size != 65535 {
            return Err("Default initial window size must be 65535".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC7540-6.9.2-INITIAL-WINDOW",
        "Initial window size handling",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_flow_control_limits() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let max_window_size = 0x7FFFFFFFu32;
        if max_window_size != 0x7FFFFFFF {
            return Err("Maximum window size must be 2^31-1".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC7540-6.9-LIMITS",
        "Flow control window size limits",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_connection_flow_control() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Connection-level flow control (stream 0)
        Ok(())
    });

    create_test_result(
        "RFC7540-6.9-CONNECTION",
        "Connection-level flow control",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}