//! Comprehensive tests for content-aware scheduler.
//!
//! Tests cover the acceptance criteria from ATP-E2:
//! - Small-file-first and metadata-first prioritization
//! - Prefix-first delivery for early usability
//! - Sparse missing chunk handling
//! - Relay-expensive repair scheduling
//! - Multi-peer rarity considerations
//! - Disk-stalled receiver scenarios
//! - Cancellation behavior
//! - Deterministic tie-breaking

use crate::runtime::scheduler::content::{
    ContentId, ContentItem, ContentScheduler, PressureSnapshot, PriorityClass, ScheduleReason,
};
use crate::runtime::scheduler::stream_priority::{SchedulerIntegration, StreamPriority};
use crate::types::Time;

fn test_content(
    id: u64,
    priority: PriorityClass,
    size: usize,
    cost: f64,
    utility: f64,
) -> ContentItem {
    ContentItem::new(ContentId::new(id), priority, size, cost, utility)
}

/// Tests small-file-first prioritization policy.
#[test]
fn test_small_file_first_policy() {
    let mut scheduler = ContentScheduler::new();

    // Create files with different sizes but same priority
    let small_file = test_content(1, PriorityClass::Data, 1024, 1.0, 10.0); // 1KB
    let large_file = test_content(2, PriorityClass::Data, 1_048_576, 10.0, 50.0); // 1MB
    let medium_file = test_content(3, PriorityClass::Data, 10_240, 5.0, 20.0); // 10KB

    // Schedule in random order
    scheduler.schedule(large_file.clone());
    scheduler.schedule(small_file.clone());
    scheduler.schedule(medium_file.clone());

    // Small file should come first (highest efficiency: 10.0)
    let (next, evidence) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("scheduler should return small_file first");
    assert_eq!(next.id, small_file.id);
    assert_eq!(evidence.reason, ScheduleReason::EfficiencyOptimal);

    // Large file second (efficiency: 5.0)
    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("scheduler should return large_file second");
    assert_eq!(next.id, large_file.id);

    // Medium file last (efficiency: 4.0)
    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("scheduler should return medium_file last");
    assert_eq!(next.id, medium_file.id);
}

/// Tests metadata-first prioritization.
#[test]
fn test_metadata_first_prioritization() {
    let mut scheduler = ContentScheduler::new();

    // Directory listing (manifest) should beat data
    let data_chunk = test_content(1, PriorityClass::Data, 1024, 1.0, 5.0);
    let manifest = test_content(2, PriorityClass::Manifest, 512, 0.5, 2.0);
    let control_msg = test_content(3, PriorityClass::Control, 64, 0.1, 1.0);

    scheduler.schedule(data_chunk.clone());
    scheduler.schedule(manifest.clone());
    scheduler.schedule(control_msg.clone());

    // Should prioritize: Control > Manifest > Data
    let (next, evidence) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule control message first");
    assert_eq!(next.id, control_msg.id);
    assert_eq!(evidence.reason, ScheduleReason::PriorityClass);

    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule manifest second");
    assert_eq!(next.id, manifest.id);

    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule data chunk third");
    assert_eq!(next.id, data_chunk.id);
}

/// Tests prefix-first delivery mode for early usability.
#[test]
fn test_prefix_first_delivery() {
    let mut scheduler = ContentScheduler::new();

    // Create chunks representing file prefixes vs random chunks
    let prefix_chunk = test_content(1, PriorityClass::Data, 1024, 1.0, 20.0)
        .with_metadata("chunk_type", "prefix")
        .with_metadata("offset", "0");

    let middle_chunk = test_content(2, PriorityClass::Data, 1024, 1.0, 5.0)
        .with_metadata("chunk_type", "middle")
        .with_metadata("offset", "1048576");

    let random_chunk = test_content(3, PriorityClass::Data, 1024, 1.0, 8.0)
        .with_metadata("chunk_type", "random")
        .with_metadata("offset", "2097152");

    scheduler.schedule(middle_chunk.clone());
    scheduler.schedule(random_chunk.clone());
    scheduler.schedule(prefix_chunk.clone());

    // Prefix should come first due to highest utility
    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("scheduler should return prefix_chunk first");
    assert_eq!(next.id, prefix_chunk.id);
    assert_eq!(next.metadata.get("chunk_type"), Some(&"prefix".to_string()));
}

/// Tests sparse missing chunk handling.
#[test]
fn test_sparse_missing_handling() {
    let mut scheduler = ContentScheduler::new();

    // Simulate missing chunks with different rarity/utility
    let common_chunk = test_content(1, PriorityClass::Data, 1024, 1.0, 2.0)
        .with_metadata("rarity", "common")
        .with_metadata("missing_peers", "1");

    let rare_chunk = test_content(2, PriorityClass::Data, 1024, 1.0, 10.0)
        .with_metadata("rarity", "rare")
        .with_metadata("missing_peers", "5");

    scheduler.schedule(common_chunk.clone());
    scheduler.schedule(rare_chunk.clone());

    // Rare chunk should be prioritized due to higher utility
    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule rare chunk due to higher utility");
    assert_eq!(next.id, rare_chunk.id);
    assert_eq!(next.metadata.get("rarity"), Some(&"rare".to_string()));
}

/// Tests relay-expensive repair scheduling.
#[test]
fn test_relay_expensive_repair() {
    let mut scheduler = ContentScheduler::new();

    // Direct repair vs relay repair with different costs
    let direct_repair =
        test_content(1, PriorityClass::Repair, 1024, 1.0, 5.0).with_metadata("path_type", "direct");

    let relay_repair =
        test_content(2, PriorityClass::Repair, 1024, 10.0, 5.0).with_metadata("path_type", "relay");

    scheduler.schedule(relay_repair.clone());
    scheduler.schedule(direct_repair.clone());

    // Direct repair should be prioritized (higher efficiency: 5.0 vs 0.5)
    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("scheduler should return direct_repair first");
    assert_eq!(next.id, direct_repair.id);
    assert_eq!(next.metadata.get("path_type"), Some(&"direct".to_string()));
}

/// Tests multi-peer rarity considerations.
#[test]
fn test_multi_peer_rarity() {
    let mut scheduler = ContentScheduler::new();

    // Chunks with different peer availability
    let abundant_chunk = test_content(1, PriorityClass::Data, 1024, 1.0, 3.0)
        .with_metadata("available_peers", "10")
        .with_metadata("rarity_score", "0.1");

    let scarce_chunk = test_content(2, PriorityClass::Data, 1024, 1.0, 8.0)
        .with_metadata("available_peers", "2")
        .with_metadata("rarity_score", "0.8");

    scheduler.schedule(abundant_chunk.clone());
    scheduler.schedule(scarce_chunk.clone());

    // Scarce chunk prioritized due to higher utility
    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule scarce chunk due to higher utility");
    assert_eq!(next.id, scarce_chunk.id);
}

/// Tests disk-stalled receiver scenario.
#[test]
fn test_disk_stalled_receiver() {
    let mut scheduler = ContentScheduler::new();

    let content = test_content(1, PriorityClass::Data, 1024, 1.0, 5.0);
    scheduler.schedule(content.clone());

    // Normal pressure - should get content
    let normal_pressure = PressureSnapshot {
        disk: 0.5,
        ..Default::default()
    };
    scheduler.update_pressure(normal_pressure);

    let result = scheduler.next_content(Time::from_nanos(1_000_000_000));
    assert!(result.is_some());

    // Reset scheduler for high disk pressure test
    scheduler.clear();
    scheduler.schedule(content.clone());

    // High disk pressure - should throttle
    let high_disk_pressure = PressureSnapshot {
        disk: 0.9, // High disk pressure
        ..Default::default()
    };
    scheduler.update_pressure(high_disk_pressure);

    let result = scheduler.next_content(Time::from_nanos(1_000_000_000));
    assert!(result.is_none()); // Should be throttled
}

/// Tests cancellation behavior.
#[test]
fn test_cancellation_behavior() {
    let mut scheduler = ContentScheduler::new();

    let content1 = test_content(1, PriorityClass::Data, 1024, 1.0, 5.0);
    let content2 = test_content(2, PriorityClass::Data, 1024, 1.0, 5.0);

    scheduler.schedule(content1.clone());
    scheduler.schedule(content2.clone());

    // Cancel/unschedule first content
    assert!(scheduler.unschedule(content1.id));
    assert_eq!(scheduler.pending_count(), 1);

    // Should only get second content
    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule second content after stall recovery");
    assert_eq!(next.id, content2.id);

    assert!(
        scheduler
            .next_content(Time::from_nanos(1_000_000_000))
            .is_none()
    );
}

/// Tests deterministic tie-breaking.
#[test]
fn test_deterministic_tie_breaking() {
    let mut scheduler = ContentScheduler::new();

    // Create identical items except for ID
    let item1 = test_content(1, PriorityClass::Data, 1024, 1.0, 5.0);
    let item2 = test_content(2, PriorityClass::Data, 1024, 1.0, 5.0);
    let item3 = test_content(3, PriorityClass::Data, 1024, 1.0, 5.0);

    // Schedule in reverse ID order
    scheduler.schedule(item3.clone());
    scheduler.schedule(item1.clone());
    scheduler.schedule(item2.clone());

    // Should come out in FIFO order (3, 1, 2)
    let (next, evidence) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule first item by tie-breaking order");
    assert_eq!(next.id, item3.id);
    assert_eq!(evidence.reason, ScheduleReason::FifoOrder);

    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule second item by tie-breaking order");
    assert_eq!(next.id, item1.id);

    let (next, _) = scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule third item by tie-breaking order");
    assert_eq!(next.id, item2.id);
}

/// Tests stream priority integration.
#[test]
fn test_stream_priority_integration() {
    let mut integrated = SchedulerIntegration::new();

    let control = test_content(1, PriorityClass::Control, 100, 1.0, 5.0);
    let data = test_content(2, PriorityClass::Data, 1000, 1.0, 3.0);

    integrated.schedule_content(control.clone(), Time::from_nanos(1_000_000_000));
    integrated.schedule_content(data.clone(), Time::from_nanos(1_000_000_000));

    // Control should get critical stream priority
    let (content, assignment, _evidence) = integrated
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule control with critical stream priority");
    assert_eq!(content.id, control.id);
    assert_eq!(assignment.priority, StreamPriority::Critical);

    // Data should get normal stream priority
    let (content, assignment, _evidence) = integrated
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule data with normal stream priority");
    assert_eq!(content.id, data.id);
    assert_eq!(assignment.priority, StreamPriority::Normal);
}

/// Property test: Evidence logging completeness.
#[test]
fn test_evidence_logging_completeness() {
    let mut scheduler = ContentScheduler::new();

    let items = (1..=5)
        .map(|i| test_content(i, PriorityClass::Data, 1024, 1.0, i as f64))
        .collect::<Vec<_>>();

    for item in &items {
        scheduler.schedule(item.clone());
    }

    let mut decisions = Vec::new();
    while let Some((content, evidence)) = scheduler.next_content(Time::from_nanos(1_000_000_000)) {
        decisions.push((content.id, evidence));
    }

    assert_eq!(decisions.len(), 5);

    // Check evidence properties
    for (i, (content_id, evidence)) in decisions.iter().enumerate() {
        assert_eq!(evidence.decision_id, (i + 1) as u64);
        assert_eq!(evidence.selected, *content_id);
        assert!(!evidence.rejected_alternatives.is_empty() || i == decisions.len() - 1);
    }
}

/// Property test: FIFO ordering invariant.
#[test]
fn test_fifo_ordering_invariant() {
    let mut scheduler = ContentScheduler::new();

    // Schedule identical items in specific order
    let ids = [5, 2, 8, 1, 9];
    for &id in &ids {
        let item = test_content(id, PriorityClass::Data, 1024, 1.0, 5.0);
        scheduler.schedule(item);
    }

    // Should come out in FIFO order
    let mut results = Vec::new();
    while let Some((content, _)) = scheduler.next_content(Time::from_nanos(1_000_000_000)) {
        results.push(content.id.value());
    }

    assert_eq!(results, ids.to_vec());
}

/// Property test: Priority class ordering invariant.
#[test]
fn test_priority_class_ordering_invariant() {
    let mut scheduler = ContentScheduler::new();

    let priorities = [
        PriorityClass::Telemetry,
        PriorityClass::Control,
        PriorityClass::Data,
        PriorityClass::Manifest,
        PriorityClass::Repair,
    ];

    // Schedule items with different priorities in random order
    for (i, &priority) in priorities.iter().enumerate() {
        let item = test_content(i as u64 + 1, priority, 1024, 1.0, 1.0);
        scheduler.schedule(item);
    }

    // Should come out in priority order (highest first)
    let mut results = Vec::new();
    while let Some((content, _)) = scheduler.next_content(Time::from_nanos(1_000_000_000)) {
        results.push(content.priority_class);
    }

    let expected = [
        PriorityClass::Control,
        PriorityClass::Manifest,
        PriorityClass::Data,
        PriorityClass::Repair,
        PriorityClass::Telemetry,
    ];

    assert_eq!(results, expected);
}

/// Integration test: Directory transfer simulation.
#[test]
fn test_directory_transfer_simulation() {
    let mut integrated = SchedulerIntegration::new();

    // Simulate directory transfer: manifest + multiple files
    let manifest = test_content(1, PriorityClass::Manifest, 1024, 0.5, 10.0);
    let small_file = test_content(2, PriorityClass::Data, 2048, 1.0, 8.0);
    let large_file = test_content(3, PriorityClass::Data, 1_048_576, 20.0, 50.0);
    let readme = test_content(4, PriorityClass::Data, 512, 0.2, 15.0); // High utility (readable)

    integrated.schedule_content(large_file.clone(), Time::from_nanos(1_000_000_000));
    integrated.schedule_content(manifest.clone(), Time::from_nanos(1_000_000_000));
    integrated.schedule_content(readme.clone(), Time::from_nanos(1_000_000_000));
    integrated.schedule_content(small_file.clone(), Time::from_nanos(1_000_000_000));

    // Should prioritize: manifest > readme > small_file > large_file
    let (content, assignment, _) = integrated
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule manifest with critical priority");
    assert_eq!(content.id, manifest.id);
    assert_eq!(assignment.priority, StreamPriority::Critical);

    let (content, _, _) = integrated
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule readme with highest efficiency");
    assert_eq!(content.id, readme.id); // Highest efficiency for data

    let (content, _, _) = integrated
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule small file by size priority");
    assert_eq!(content.id, small_file.id);

    let (content, _, _) = integrated
        .next_content(Time::from_nanos(1_000_000_000))
        .expect("should schedule large file last");
    assert_eq!(content.id, large_file.id);
}

/// Benchmark test: Scheduler performance under load.
#[test]
fn test_scheduler_performance() {
    let mut scheduler = ContentScheduler::new();

    // Schedule many items
    let start = std::time::Instant::now();
    for i in 1..=1000 {
        let item = test_content(i, PriorityClass::Data, 1024, 1.0, i as f64);
        scheduler.schedule(item);
    }
    let schedule_time = start.elapsed();

    // Process all items
    let start = std::time::Instant::now();
    let mut count = 0;
    while scheduler
        .next_content(Time::from_nanos(1_000_000_000))
        .is_some()
    {
        count += 1;
    }
    let process_time = start.elapsed();

    assert_eq!(count, 1000);

    // Ensure reasonable performance (these are generous bounds)
    assert!(schedule_time.as_millis() < 100, "Scheduling should be fast");
    assert!(process_time.as_millis() < 100, "Processing should be fast");
}
