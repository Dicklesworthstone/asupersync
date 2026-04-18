//! Integration test for Kafka RecordBatch v2 conformance.

#[test]
fn kafka_record_batch_v2_conformance_integration() {
    // Import the conformance test harness
    use conformance::KafkaConformanceHarness;

    let harness = KafkaConformanceHarness::new();

    // Run a subset of conformance tests to verify integration
    let results = harness.run_format_tests();

    // Verify we have some test results
    assert!(!results.is_empty(), "Should have conformance test results");

    // Log the results
    for result in &results {
        println!(
            "Test {}: {} - {}",
            result.test_id,
            if result.passed { "PASS" } else { "FAIL" },
            result.error_message.as_deref().unwrap_or("No error")
        );
    }

    // Ensure we don't have any unexpected failures
    let failed_count = results.iter().filter(|r| !r.passed).count();

    assert_eq!(
        failed_count, 0,
        "Found {} unexpected test failures in Kafka RecordBatch v2 conformance tests",
        failed_count
    );

    println!(
        "✓ All {} Kafka RecordBatch v2 conformance tests passed",
        results.len()
    );
}
