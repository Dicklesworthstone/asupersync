//! Golden snapshot tests for transport aggregator report format.
//!
//! Tests that the `MultipathAggregator::stats()` output format remains stable
//! for aggregation reporting and monitoring dashboards.

use asupersync::transport::aggregator::{
    AggregatorConfig, MultipathAggregator, PathCharacteristics, PathState,
};
use asupersync::types::Time;
use asupersync::types::symbol::Symbol;
use std::sync::atomic::Ordering;

/// Initialize test with a unique test name to prevent interference.
fn init_test(test_name: &str) {
    println!("=== Starting test: {} ===", test_name);
}

fn create_test_symbol(
    object_id: u64,
    source_block: u32,
    encoded_symbol: u32,
    size: usize,
) -> Symbol {
    let data = vec![42u8; size];
    Symbol::new_for_test(object_id, source_block as u8, encoded_symbol, &data)
}

fn format_aggregator_stats_report(
    stats: &asupersync::transport::aggregator::AggregatorStats,
) -> String {
    let mut report = String::new();

    report.push_str("=== Transport Aggregator Report ===\n");
    report.push_str(&format!("Total Processed: {}\n", stats.total_processed));

    report.push_str("\n--- Path Statistics ---\n");
    report.push_str(&format!("Path Count: {}\n", stats.paths.path_count));
    report.push_str(&format!("Usable Paths: {}\n", stats.paths.usable_count));
    report.push_str(&format!("Total Received: {}\n", stats.paths.total_received));
    report.push_str(&format!("Total Lost: {}\n", stats.paths.total_lost));
    report.push_str(&format!(
        "Total Duplicates: {}\n",
        stats.paths.total_duplicates
    ));
    report.push_str(&format!(
        "Aggregate Bandwidth (bps): {}\n",
        stats.paths.aggregate_bandwidth_bps
    ));

    report.push_str("\n--- Deduplication Statistics ---\n");
    report.push_str(&format!(
        "Objects Tracked: {}\n",
        stats.dedup.objects_tracked
    ));
    report.push_str(&format!(
        "Symbols Tracked: {}\n",
        stats.dedup.symbols_tracked
    ));
    report.push_str(&format!(
        "Duplicates Detected: {}\n",
        stats.dedup.duplicates_detected
    ));
    report.push_str(&format!("Unique Symbols: {}\n", stats.dedup.unique_symbols));

    report.push_str("\n--- Reordering Statistics ---\n");
    report.push_str(&format!(
        "Objects Tracked: {}\n",
        stats.reorder.objects_tracked
    ));
    report.push_str(&format!(
        "Symbols Buffered: {}\n",
        stats.reorder.symbols_buffered
    ));
    report.push_str(&format!(
        "In-Order Deliveries: {}\n",
        stats.reorder.in_order_deliveries
    ));
    report.push_str(&format!(
        "Reordered Deliveries: {}\n",
        stats.reorder.reordered_deliveries
    ));
    report.push_str(&format!(
        "Timeout Deliveries: {}\n",
        stats.reorder.timeout_deliveries
    ));

    report.push_str("=================================\n");
    report
}

#[test]
fn test_aggregator_stats_golden_snapshot_basic() {
    init_test("test_aggregator_stats_golden_snapshot_basic");

    let config = AggregatorConfig::default();
    let aggregator = MultipathAggregator::new(config);

    // Create a single path
    let path_id = aggregator.paths().create_path(
        "test-path".to_string(),
        "localhost:8080".to_string(),
        PathCharacteristics::default(),
    );

    // Process a few symbols
    for i in 0..5u32 {
        let symbol = create_test_symbol(1, 0, i, 100);
        aggregator.process(symbol, path_id, Time::from_secs(i as u64));
    }

    let stats = aggregator.stats();
    let report = format_aggregator_stats_report(&stats);

    insta::assert_snapshot!("aggregator_basic_stats", report);
}

#[test]
fn test_aggregator_stats_golden_snapshot_multipath() {
    init_test("test_aggregator_stats_golden_snapshot_multipath");

    let config = AggregatorConfig::default();
    let aggregator = MultipathAggregator::new(config);

    // Create multiple paths with different characteristics
    let primary_path = aggregator.paths().create_path(
        "primary-path".to_string(),
        "10.0.1.100:8080".to_string(),
        PathCharacteristics {
            latency_ms: 10,
            bandwidth_bps: 1_000_000,
            loss_rate: 0.001,
            jitter_ms: 2,
            is_primary: true,
            priority: 1,
        },
    );

    let backup_path = aggregator.paths().create_path(
        "backup-path".to_string(),
        "10.0.1.101:8080".to_string(),
        PathCharacteristics {
            latency_ms: 25,
            bandwidth_bps: 500_000,
            loss_rate: 0.005,
            jitter_ms: 5,
            is_primary: false,
            priority: 2,
        },
    );

    let fallback_path = aggregator.paths().create_path(
        "fallback-path".to_string(),
        "10.0.1.102:8080".to_string(),
        PathCharacteristics {
            latency_ms: 100,
            bandwidth_bps: 128_000,
            loss_rate: 0.02,
            jitter_ms: 20,
            is_primary: false,
            priority: 3,
        },
    );

    // Set symbol received counts for realistic stats
    if let Some(path) = aggregator.paths().get(primary_path) {
        path.symbols_received.store(150, Ordering::Relaxed);
    }
    if let Some(path) = aggregator.paths().get(backup_path) {
        path.symbols_received.store(75, Ordering::Relaxed);
    }
    if let Some(path) = aggregator.paths().get(fallback_path) {
        path.symbols_received.store(25, Ordering::Relaxed);
    }

    // Process symbols from different paths to create realistic stats
    for i in 0..10u32 {
        let symbol1 = create_test_symbol(1, 0, i * 3, 200);
        let symbol2 = create_test_symbol(1, 0, i * 3 + 1, 200);
        let symbol3 = create_test_symbol(2, 0, i, 150);

        aggregator.process(symbol1, primary_path, Time::from_secs(i as u64));
        aggregator.process(symbol2, backup_path, Time::from_secs((i + 1) as u64));
        aggregator.process(symbol3, fallback_path, Time::from_secs((i + 2) as u64));
    }

    // Process some duplicate symbols to trigger deduplication stats
    for i in 0..3u32 {
        let duplicate_symbol = create_test_symbol(1, 0, i, 200);
        aggregator.process(
            duplicate_symbol,
            backup_path,
            Time::from_secs((20 + i) as u64),
        );
    }

    let stats = aggregator.stats();
    let report = format_aggregator_stats_report(&stats);

    insta::assert_snapshot!("aggregator_multipath_stats", report);
}

#[test]
fn test_aggregator_stats_golden_snapshot_degraded_paths() {
    init_test("test_aggregator_stats_golden_snapshot_degraded_paths");

    let config = AggregatorConfig::default();
    let aggregator = MultipathAggregator::new(config);

    // Create paths in different states
    let active_path = aggregator.paths().create_path(
        "active".to_string(),
        "10.0.1.1:8080".to_string(),
        PathCharacteristics {
            latency_ms: 15,
            bandwidth_bps: 2_000_000,
            loss_rate: 0.0001,
            jitter_ms: 1,
            is_primary: true,
            priority: 1,
        },
    );

    let degraded_path = aggregator.paths().create_path(
        "degraded".to_string(),
        "10.0.1.2:8080".to_string(),
        PathCharacteristics {
            latency_ms: 150,
            bandwidth_bps: 256_000,
            loss_rate: 0.1,
            jitter_ms: 50,
            is_primary: false,
            priority: 2,
        },
    );

    let unavailable_path = aggregator.paths().create_path(
        "unavailable".to_string(),
        "10.0.1.3:8080".to_string(),
        PathCharacteristics {
            latency_ms: 500,
            bandwidth_bps: 56_000,
            loss_rate: 0.5,
            jitter_ms: 200,
            is_primary: false,
            priority: 3,
        },
    );

    // Set symbol counts and states
    if let Some(path) = aggregator.paths().get(active_path) {
        path.symbols_received.store(200, Ordering::Relaxed);
    }

    if let Some(path) = aggregator.paths().get(degraded_path) {
        path.symbols_received.store(50, Ordering::Relaxed);
        path.set_state(PathState::Degraded);
    }

    if let Some(path) = aggregator.paths().get(unavailable_path) {
        path.symbols_received.store(10, Ordering::Relaxed);
        path.set_state(PathState::Unavailable);
    }

    // Process symbols creating reordering scenarios
    let symbols = [
        (1, 0, 0),
        (1, 0, 2),
        (1, 0, 1), // Out of order for object 1
        (2, 0, 1),
        (2, 0, 0),
        (2, 0, 3), // Out of order for object 2
        (3, 0, 0),
        (3, 0, 1),
        (3, 0, 2), // In order for object 3
    ];

    for (i, (obj, sb, es)) in symbols.iter().enumerate() {
        let symbol = create_test_symbol(*obj, *sb, *es, 300);
        let path = if i % 3 == 0 {
            active_path
        } else if i % 3 == 1 {
            degraded_path
        } else {
            unavailable_path
        };
        aggregator.process(symbol, path, Time::from_secs(i as u64));
    }

    let stats = aggregator.stats();
    let report = format_aggregator_stats_report(&stats);

    insta::assert_snapshot!("aggregator_degraded_paths_stats", report);
}

#[test]
fn test_aggregator_stats_golden_snapshot_high_load() {
    init_test("test_aggregator_stats_golden_snapshot_high_load");

    let config = AggregatorConfig::default();
    let aggregator = MultipathAggregator::new(config);

    // Create a high-throughput path
    let high_throughput_path = aggregator.paths().create_path(
        "high-throughput".to_string(),
        "10.0.10.100:8080".to_string(),
        PathCharacteristics {
            latency_ms: 5,
            bandwidth_bps: 10_000_000, // 10 Mbps
            loss_rate: 0.0001,
            jitter_ms: 1,
            is_primary: true,
            priority: 1,
        },
    );

    if let Some(path) = aggregator.paths().get(high_throughput_path) {
        path.symbols_received.store(5000, Ordering::Relaxed);
    }

    // Process many symbols to simulate high load
    for obj_id in 1..=10u64 {
        for es in 0..50u32 {
            let symbol = create_test_symbol(obj_id, 0, es, 1024);
            aggregator.process(
                symbol,
                high_throughput_path,
                Time::from_millis((obj_id * 50 + es as u64) * 10),
            );
        }
    }

    let stats = aggregator.stats();
    let report = format_aggregator_stats_report(&stats);

    insta::assert_snapshot!("aggregator_high_load_stats", report);
}
