//! Demonstration of structured evidence logging for test analysis.
//!
//! This test shows how to use the EvidenceSink to capture structured JSON events
//! during test execution. Events are written to tests/_evidence/evidence_logging_demo.jsonl
//! for post-hoc analysis, flake detection, and regression tracking.

use asupersync::cx::Cx;
use asupersync::test_utils::{EvidenceSink, lab_with_evidence};
use std::time::Duration;

#[test]
fn evidence_logging_demo() {
    // Demonstrate basic evidence sink usage
    let mut evidence = EvidenceSink::for_test("evidence_logging_demo");

    // Log test phases
    evidence.phase("setup");
    evidence.event(
        "test_init",
        &[("framework", "asupersync"), ("version", "0.3.1")],
    );

    evidence.phase("execution");

    // Simulate some test operations with evidence logging
    for i in 0..3 {
        evidence.event(
            "iteration",
            &[("count", &i.to_string()), ("operation", "mock_work")],
        );

        // Simulate work
        std::thread::sleep(Duration::from_millis(10));
    }

    // Log runtime context information
    evidence.cx_id("test_cx_main");
    evidence.event("context_switch", &[("from", "setup"), ("to", "validation")]);

    evidence.phase("validation");
    evidence.event("assertion", &[("type", "equality"), ("result", "pass")]);

    evidence.phase("cleanup");
    evidence.event(
        "resource_cleanup",
        &[("type", "memory"), ("status", "complete")],
    );

    // Record final outcome
    evidence.outcome("passed");

    // Save evidence to file
    let evidence_file = evidence.save().expect("Failed to save evidence");

    // Verify the evidence file was created
    assert!(
        evidence_file.exists(),
        "Evidence file should be created at {:?}",
        evidence_file
    );

    // Read and verify the evidence contains expected events
    let evidence_content =
        std::fs::read_to_string(&evidence_file).expect("Should be able to read evidence file");

    // Check for key events in the JSON lines
    assert!(evidence_content.contains("phase_transition"));
    assert!(evidence_content.contains("evidence_logging_demo"));
    assert!(evidence_content.contains("outcome"));
    assert!(evidence_content.contains("passed"));

    println!("✓ Evidence logged to: {}", evidence_file.display());
}

#[test]
fn lab_runtime_evidence_integration() {
    // Demonstrate evidence logging with LabRuntime
    let (result, evidence) =
        lab_with_evidence("lab_runtime_evidence_integration", |_runtime, evidence| {
            evidence.phase("lab_execution");
            evidence.event(
                "runtime_start",
                &[("deterministic", "true"), ("virtual_time", "enabled")],
            );

            evidence.event("async_start", &[("task", "sleep_demo")]);

            // Use the LabRuntime for deterministic async execution
            let cx = Cx::for_testing();
            evidence.cx_id(&format!("cx_{:?}", cx.task_id()));

            evidence.event(
                "async_complete",
                &[("task", "sleep_demo"), ("duration_ms", "100")],
            );

            "lab_test_result"
        });

    // Save evidence
    let evidence_file = evidence.save().expect("Failed to save evidence");

    assert_eq!(result, "lab_test_result");
    assert!(evidence_file.exists());

    // Verify evidence contains lab runtime events
    let evidence_content =
        std::fs::read_to_string(&evidence_file).expect("Should be able to read evidence file");

    assert!(evidence_content.contains("lab_start"));
    assert!(evidence_content.contains("deterministic"));
    assert!(evidence_content.contains("async_start"));
    assert!(evidence_content.contains("cx_"));

    println!(
        "✓ Lab runtime evidence logged to: {}",
        evidence_file.display()
    );
}

#[test]
fn evidence_with_custom_context() {
    use asupersync::test_logging::TestContext;
    use asupersync::test_utils::DEFAULT_TEST_SEED;

    // Demonstrate evidence with custom test context
    let ctx = TestContext::new("evidence_with_custom_context", DEFAULT_TEST_SEED)
        .with_subsystem("evidence_demo");
    let mut evidence = EvidenceSink::with_context("evidence_with_custom_context", ctx);

    evidence.phase("custom_setup");
    evidence.event(
        "custom_config",
        &[
            ("seed", &DEFAULT_TEST_SEED.to_string()),
            ("subsystem", "evidence_demo"),
        ],
    );

    evidence.phase("custom_execution");

    // Simulate test-specific events
    evidence.event("data_validation", &[("rows", "100"), ("schema", "v1")]);
    evidence.event(
        "performance_check",
        &[("latency_ms", "5"), ("throughput", "1000")],
    );

    evidence.outcome("passed");

    let evidence_file = evidence.save().expect("Failed to save evidence");
    assert!(evidence_file.exists());

    let evidence_content =
        std::fs::read_to_string(&evidence_file).expect("Should be able to read evidence file");

    assert!(evidence_content.contains("custom_config"));
    assert!(evidence_content.contains("data_validation"));
    assert!(evidence_content.contains("performance_check"));

    println!(
        "✓ Custom context evidence logged to: {}",
        evidence_file.display()
    );
}
