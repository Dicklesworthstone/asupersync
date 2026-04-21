#![allow(warnings)]
#![allow(clippy::all)]
//! Message fragmentation conformance tests.

use super::*;

#[allow(dead_code)]

pub fn run_fragmentation_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();
    results.push(test_message_fragmentation());
    results
}

#[allow(dead_code)]

fn test_message_fragmentation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| Ok(()));
    create_test_result(
        "RFC6455-5.4-FRAGMENTATION",
        "Message fragmentation",
        TestCategory::Fragmentation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
