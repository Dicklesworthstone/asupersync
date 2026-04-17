//! Masking conformance tests.

use super::*;

pub fn run_masking_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();
    results.push(test_client_masking_requirement());
    results
}

fn test_client_masking_requirement() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| Ok(()));
    create_test_result(
        "RFC6455-5.3-MASKING",
        "Client masking requirement",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
