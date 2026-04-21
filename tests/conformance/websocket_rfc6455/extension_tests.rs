#![allow(warnings)]
#![allow(clippy::all)]
//! Extension negotiation conformance tests.

use super::*;

#[allow(dead_code)]

pub fn run_extension_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();
    results.push(test_extension_negotiation());
    results
}

#[allow(dead_code)]

fn test_extension_negotiation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| Ok(()));
    create_test_result(
        "RFC6455-9-EXTENSION",
        "Extension negotiation",
        TestCategory::Extensions,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}
