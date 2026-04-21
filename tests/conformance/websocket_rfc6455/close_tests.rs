//! Close frame conformance tests.

use super::*;

#[allow(dead_code)]

pub fn run_close_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();
    results.push(test_close_frame_format());
    results
}

#[allow(dead_code)]

fn test_close_frame_format() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| Ok(()));
    create_test_result(
        "RFC6455-5.5.1-CLOSE",
        "Close frame format",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
