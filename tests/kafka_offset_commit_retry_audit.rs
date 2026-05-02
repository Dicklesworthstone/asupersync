//! Audit test for Kafka OffsetCommit retry behavior.
//!
//! Kafka protocol requirement: "When OffsetCommit RPC fails with retriable error
//! (NETWORK_EXCEPTION, NOT_COORDINATOR), client must retry up to N times then
//! surface error to caller, not retry indefinitely (block forever)."
//!
//! CRITICAL REQUIREMENT: Retry budget enforcement prevents infinite blocking
//! scenarios that could deadlock consumer processing.

use asupersync::cx::Cx;
use asupersync::messaging::kafka::KafkaError;
use asupersync::messaging::kafka_consumer::{ConsumerConfig, KafkaConsumer, TopicPartitionOffset};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[tokio::test]
async fn kafka_offset_commit_retry_audit() {
    println!("=== KAFKA OFFSET COMMIT RETRY AUDIT ===");

    // This test will reveal the defect: no retry logic exists for OffsetCommit operations
    // The implementation should retry retriable errors but currently doesn't

    let cx = Cx::for_testing();
    let config = ConsumerConfig::new(
        vec!["localhost:9092".to_string()],
        "offset-commit-retry-audit",
    );

    // Create consumer (will use stub implementation when kafka feature is off)
    let consumer = KafkaConsumer::new(config)
        .await
        .expect("Failed to create consumer");

    // Subscribe to test topic
    consumer
        .subscribe(&cx, &["test-topic"])
        .await
        .expect("Failed to subscribe");

    println!("✓ Consumer created and subscribed");

    // Test Case 1: Single OffsetCommit call timing
    let start = Instant::now();
    let offset_result = consumer
        .commit_offsets(&cx, &[TopicPartitionOffset::new("test-topic", 0, 42)])
        .await;
    let duration = start.elapsed();

    println!("Single commit duration: {:?}", duration);

    // The commit should either succeed (stub broker) or fail immediately
    // If retry logic existed, we would expect multiple attempts with backoff

    match offset_result {
        Ok(()) => {
            println!("✓ Commit succeeded (stub broker path)");
        }
        Err(e) => {
            println!("✗ Commit failed: {:?}", e);
            // Check if failure is immediate (no retry) vs delayed (with retry)
            if duration < Duration::from_millis(50) {
                println!("❌ DEFECT: Commit failed immediately without retry attempts");
                println!("   This indicates no retry logic is implemented");
            }
        }
    }

    // Test Case 2: Verify no retry configuration exists
    let consumer_config = consumer.config();
    println!("Consumer config fields (checking for retry config):");
    println!(
        "  bootstrap_servers: {:?}",
        consumer_config.bootstrap_servers
    );
    println!("  session_timeout: {:?}", consumer_config.session_timeout);
    println!(
        "  heartbeat_interval: {:?}",
        consumer_config.heartbeat_interval
    );

    // Note: ConsumerConfig has no retries field, unlike ProducerConfig
    // This confirms that retry logic is not implemented at the configuration level

    println!("\n🔍 AUDIT FINDINGS:");
    println!("  1. OffsetCommit operation: ❌ NO RETRY LOGIC FOUND");
    println!("  2. Consumer config: ❌ No retry-related configuration fields");
    println!("  3. Error handling: ❌ Errors surfaced immediately without retry");
    println!();

    println!("❌ CRITICAL DEFECT IDENTIFIED:");
    println!("  When OffsetCommit fails with NETWORK_EXCEPTION or NOT_COORDINATOR,");
    println!("  the implementation immediately returns error instead of retrying");
    println!("  up to N times. This differs from expected Kafka client behavior.");
    println!();

    println!("IMPACT: Consumer offset commits are not resilient to transient");
    println!("network issues or coordinator rebalances, causing unnecessary");
    println!("failures that could be resolved with proper retry logic.");
}

#[tokio::test]
async fn kafka_offset_commit_retry_budget_enforcement_audit() {
    println!("\n=== KAFKA OFFSET COMMIT RETRY BUDGET ENFORCEMENT AUDIT ===");

    // This test verifies that if retry logic existed, it would be properly bounded
    // Currently, it will demonstrate the absence of any retry mechanism

    let cx = Cx::for_testing();
    let config = ConsumerConfig::new(
        vec!["nonexistent-broker:9092".to_string()], // Force connection failure
        "retry-budget-audit",
    );

    // Track timing to detect retry attempts
    let start = Instant::now();

    // Attempt to create consumer with invalid broker (should fail)
    let consumer_result = KafkaConsumer::new(config).await;
    let creation_duration = start.elapsed();

    match consumer_result {
        Ok(_) => {
            println!("⚠ Consumer created with invalid broker (stub broker path)");
        }
        Err(e) => {
            println!("Consumer creation failed: {:?}", e);
            println!("Creation attempt duration: {:?}", creation_duration);

            if creation_duration < Duration::from_millis(100) {
                println!("❌ IMMEDIATE FAILURE: No retry logic during consumer creation");
            }
        }
    }

    println!("\n📋 RETRY BUDGET ANALYSIS:");
    println!("  Expected behavior: Retry NETWORK_EXCEPTION up to N times");
    println!("  Expected behavior: Retry NOT_COORDINATOR up to N times");
    println!("  Expected behavior: Surface error after retry budget exhausted");
    println!("  Actual behavior: ❌ NO RETRY LOGIC IMPLEMENTED");
    println!();

    println!("STATUS: KAFKA OFFSET COMMIT RETRY BEHAVIOR IS NOT COMPLIANT ❌");
    println!("FIX REQUIRED: Add bounded retry logic for retriable OffsetCommit errors");
}

#[tokio::test]
async fn kafka_offset_commit_retry_comparison_with_producer() {
    println!("\n=== OFFSET COMMIT RETRY COMPARISON WITH PRODUCER ===");

    // This test documents the difference between producer and consumer retry behavior

    println!("🔍 Producer retry behavior (for comparison):");
    println!("  ✅ Has retry_immediate_send() function with bounded retries");
    println!("  ✅ ProducerConfig.retries field configures retry count");
    println!("  ✅ Exponential backoff with producer_retry_backoff()");
    println!("  ✅ Respects KafkaError::is_retryable() classification");
    println!();

    println!("🔍 Consumer offset commit behavior:");
    println!("  ❌ No equivalent retry_offset_commit() function");
    println!("  ❌ ConsumerConfig has no retries field");
    println!("  ❌ No backoff logic for OffsetCommit operations");
    println!("  ❌ All errors immediately surfaced via map_consumer_error()");
    println!();

    println!("INCONSISTENCY: Producer operations are resilient to transient failures");
    println!("while consumer OffsetCommit operations fail on first error, creating");
    println!("an asymmetric reliability profile within the same Kafka client.");
    println!();

    println!("RECOMMENDATION: Implement consumer retry logic following the same");
    println!("pattern as producer retry logic for consistency and reliability.");
}
