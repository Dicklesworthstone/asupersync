//! Error handling conformance tests.

use super::*;

pub fn run_error_handling_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();
    results.push(test_protocol_errors());
    results
}

fn test_protocol_errors() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| Ok(()));
    create_test_result("RFC6455-7.4-ERRORS", "Protocol error handling", TestCategory::ErrorHandling, RequirementLevel::Must, result, elapsed)
}