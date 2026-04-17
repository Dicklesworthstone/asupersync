//! Integration test for PostgreSQL logical replication conformance.

#[test]
fn postgres_logical_replication_conformance_integration() {
    // Import the conformance test harness
    use asupersync_conformance::postgres_logical_replication::PgLogicalReplicationHarness;

    let mut harness = PgLogicalReplicationHarness::new();

    // Run all conformance tests for pgoutput protocol
    let results = harness.run_all_tests();

    // Verify we have some test results
    assert!(!results.is_empty(), "Should have conformance test results");

    // Log the results
    for result in &results {
        println!(
            "Test {}: {} - {}",
            result.test_id,
            if result.verdict == asupersync_conformance::postgres_logical_replication::TestVerdict::Pass { "PASS" } else { "FAIL" },
            result.description
        );
    }

    // Ensure we don't have any unexpected failures
    let failed_count = results.iter()
        .filter(|r| r.verdict == asupersync_conformance::postgres_logical_replication::TestVerdict::Fail)
        .count();

    assert_eq!(
        failed_count, 0,
        "Found {} unexpected test failures in PostgreSQL logical replication conformance tests",
        failed_count
    );

    // Verify we have comprehensive coverage
    let mut categories = std::collections::HashSet::new();
    for result in &results {
        categories.insert(&result.category);
    }

    assert!(
        categories.len() >= 4,
        "Should have at least 4 test categories, found {}",
        categories.len()
    );

    println!("✓ All {} PostgreSQL logical replication conformance tests passed", results.len());
}

#[test]
fn postgres_logical_replication_message_types_coverage() {
    use asupersync_conformance::postgres_logical_replication::{PgLogicalReplicationHarness, TestCategory};

    let mut harness = PgLogicalReplicationHarness::new();
    let results = harness.run_all_tests();

    // Check that we test all major pgoutput message types
    let descriptions: Vec<String> = results.iter()
        .map(|r| r.description.clone())
        .collect();

    let message_types = vec!["BEGIN", "COMMIT", "RELATION", "INSERT", "UPDATE"];
    for msg_type in &message_types {
        let found = descriptions.iter()
            .any(|desc| desc.to_uppercase().contains(msg_type));

        assert!(
            found,
            "Should have tests for {} message type",
            msg_type
        );
    }

    // Verify transaction boundary coverage
    let boundary_tests = results.iter()
        .filter(|r| r.category == TestCategory::TransactionBoundaries)
        .count();

    assert!(
        boundary_tests >= 2,
        "Should have at least 2 transaction boundary tests, found {}",
        boundary_tests
    );

    // Verify tuple format coverage
    let tuple_tests = results.iter()
        .filter(|r| r.category == TestCategory::TupleFormat)
        .count();

    assert!(
        tuple_tests >= 1,
        "Should have at least 1 tuple format test, found {}",
        tuple_tests
    );
}

#[test]
fn postgres_logical_replication_error_handling_coverage() {
    use asupersync_conformance::postgres_logical_replication::{PgLogicalReplicationHarness, TestCategory};

    let mut harness = PgLogicalReplicationHarness::new();
    let results = harness.run_all_tests();

    // Verify error handling tests exist
    let error_tests = results.iter()
        .filter(|r| r.category == TestCategory::ErrorHandling)
        .count();

    assert!(
        error_tests >= 1,
        "Should have at least 1 error handling test, found {}",
        error_tests
    );

    // Check for malformed message testing
    let malformed_test = results.iter()
        .any(|r| r.description.to_lowercase().contains("malformed"));

    assert!(
        malformed_test,
        "Should test malformed message handling"
    );
}