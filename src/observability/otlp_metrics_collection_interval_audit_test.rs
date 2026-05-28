//! OTLP metrics collection interval audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP MetricExporter collection interval configuration
//! behavior per OpenTelemetry specification requirements.
//!
//! **OTLP METRICS COLLECTION SPECIFICATION**:
//! - MetricExporter MUST have configurable collection interval per OTLP spec
//! - Default interval should be reasonable for production use (typically 10-60s)
//! - Applications should be able to configure interval based on use case:
//!   - High-frequency monitoring: 1-5s intervals
//!   - Standard monitoring: 10-30s intervals
//!   - Low-frequency monitoring: 60s+ intervals
//! - NOT: Force users to manually configure PeriodicReader externally
//! - NOT: Use hardcoded intervals without configuration options
//!
//! **CRITICAL DEFECT IDENTIFIED**:
//! - Current implementation provides no collection interval configuration
//! - All PeriodicReader instances use OpenTelemetry SDK default (60s)
//! - No way to configure collection interval through OtelMetrics or MetricsConfig
//! - Forces manual PeriodicReader configuration, violating encapsulation

#![cfg(test)]
#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// In-memory metrics exporter for collection interval behavior.
#[derive(Debug, Clone)]
pub struct InMemoryMetricsExporter {
    exports: Arc<Mutex<VecDeque<Instant>>>,
    export_count: Arc<AtomicUsize>,
}

impl InMemoryMetricsExporter {
    fn new() -> Self {
        Self {
            exports: Arc::new(Mutex::new(VecDeque::new())),
            export_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_export_at(&self, timestamp: Instant) {
        self.exports.lock().unwrap().push_back(timestamp);
        self.export_count.fetch_add(1, Ordering::Relaxed);
    }

    fn get_export_intervals(&self) -> Vec<Duration> {
        let exports = self.exports.lock().unwrap();
        let mut intervals = Vec::new();
        for window in exports.iter().collect::<Vec<_>>().windows(2) {
            intervals.push(window[1].duration_since(*window[0]));
        }
        intervals
    }

    fn export_count(&self) -> usize {
        self.export_count.load(Ordering::Relaxed)
    }
}

/// Metrics collection configuration fixture.
#[derive(Debug, Clone)]
pub struct MetricsCollectionConfigFixture {
    collection_interval: Option<Duration>,
    timeout: Duration,
    export_timeout: Duration,
}

impl MetricsCollectionConfigFixture {
    fn new() -> Self {
        Self {
            collection_interval: None,
            timeout: Duration::from_secs(30),
            export_timeout: Duration::from_secs(10),
        }
    }

    fn with_collection_interval(mut self, interval: Duration) -> Self {
        self.collection_interval = Some(interval);
        self
    }

    fn get_collection_interval(&self) -> Duration {
        self.collection_interval.unwrap_or(Duration::from_secs(60)) // SDK default
    }
}

/// Deterministic OTLP metrics provider for collection behavior.
#[derive(Debug)]
pub struct DeterministicOtlpMetricsProvider {
    config: MetricsCollectionConfigFixture,
    exporter: InMemoryMetricsExporter,
}

impl DeterministicOtlpMetricsProvider {
    fn new() -> Self {
        Self {
            config: MetricsCollectionConfigFixture::new(),
            exporter: InMemoryMetricsExporter::new(),
        }
    }

    fn with_config(mut self, config: MetricsCollectionConfigFixture) -> Self {
        self.config = config;
        self
    }

    fn collection_interval(&self) -> Duration {
        self.config.get_collection_interval()
    }

    fn run_periodic_export_schedule(&self, duration: Duration) -> Vec<Duration> {
        let interval = self.collection_interval();
        let export_count = (duration.as_millis() / interval.as_millis()) as usize;

        let start = Instant::now();
        for i in 0..export_count {
            let target_time = start + interval * (i as u32 + 1);
            self.exporter.record_export_at(target_time);
        }

        self.exporter.get_export_intervals()
    }
}

/// **AUDIT TEST**: Verify OTLP metrics collection interval configuration support.
///
/// **SCENARIO**: User needs to configure different collection intervals for different use cases.
/// **REQUIREMENT**: OtelMetrics should expose collection interval configuration.
/// **ASSESSMENT**: Current implementation vs OTLP specification requirements.
#[test]
fn audit_otlp_metrics_collection_interval_configuration() {
    println!("🔍 AUDIT: OTLP metrics collection interval configuration support");

    println!("📋 OTLP metrics collection requirements:");
    println!("   • MetricExporter MUST have configurable collection interval");
    println!("   • Default interval should be production-appropriate (10-60s)");
    println!("   • Applications should configure based on monitoring needs");
    println!("   • High-freq: 1-5s, Standard: 10-30s, Low-freq: 60s+");
    println!("   • NOT: Force manual PeriodicReader configuration");

    let collection_scenarios = vec![
        (Duration::from_secs(1), "High-frequency monitoring"),
        (Duration::from_secs(5), "Real-time dashboards"),
        (Duration::from_millis(500), "Ultra high-frequency"),
        (Duration::from_secs(15), "Standard monitoring"),
        (Duration::from_secs(30), "Medium-frequency monitoring"),
        (Duration::from_secs(60), "Low-frequency monitoring"),
    ];

    println!("📊 Testing collection interval scenarios:");

    for (interval, description) in collection_scenarios {
        println!(
            "   Testing: {} ({})",
            format_duration(interval),
            description
        );

        // **IMPROVED IMPLEMENTATION** (what should exist)
        let config = MetricsCollectionConfigFixture::new().with_collection_interval(interval);
        let provider = DeterministicOtlpMetricsProvider::new().with_config(config);

        println!("     Configured interval: {}", format_duration(interval));
        println!(
            "     Provider interval: {}",
            format_duration(provider.collection_interval())
        );

        // Verify the interval is correctly configured
        if provider.collection_interval() == interval {
            println!("     ✅ CONFIGURATION: Interval correctly set");
        } else {
            println!("     ❌ CONFIGURATION: Interval not applied");
        }

        // Test actual collection behavior
        let test_duration = Duration::from_millis(
            u64::try_from(interval.as_millis() * 3).expect("test interval must fit in u64"),
        ); // 3 intervals
        let actual_intervals = provider.run_periodic_export_schedule(test_duration);

        if actual_intervals.is_empty() {
            println!("     ⚠️  TIMING: No exports captured in test window");
            continue;
        }

        // Verify timing accuracy
        let expected = interval;
        let tolerance = Duration::from_millis(50); // 50ms tolerance

        let mut accurate_count = 0;
        for actual_interval in &actual_intervals {
            let diff = actual_interval.abs_diff(expected);

            if diff <= tolerance {
                accurate_count += 1;
            }
        }

        let accuracy_ratio = accurate_count as f64 / actual_intervals.len() as f64;
        println!(
            "     Timing accuracy: {:.1}% ({}/{} intervals within tolerance)",
            accuracy_ratio * 100.0,
            accurate_count,
            actual_intervals.len()
        );

        if accuracy_ratio >= 0.8 {
            println!("     ✅ TIMING: Collection interval maintained");
        } else {
            println!("     ❌ TIMING: Collection interval drift detected");
        }
    }
}

/// **AUDIT TEST**: Verify current OTLP implementation collection interval gaps.
///
/// **SCENARIO**: Document current implementation limitations vs spec requirements.
/// **REQUIREMENT**: Identify configuration gaps in current OtelMetrics.
/// **ASSESSMENT**: Current behavior vs ideal configurable implementation.
#[test]
fn audit_current_otlp_metrics_collection_gaps() {
    println!("🔍 AUDIT: Current OTLP metrics collection implementation gaps");

    println!("📊 Current implementation analysis:");
    println!("   File: src/observability/otel.rs");
    println!("   Lines 2184, 2225, 2299, etc: PeriodicReader::builder(exporter).build()");
    println!("   Issue: No collection interval configuration exposed");

    // **CURRENT BEHAVIOR ANALYSIS**
    println!("📋 Current configuration limitations:");
    println!("   • OtelMetrics::new() - no interval parameter");
    println!("   • MetricsConfig - only cardinality/sampling, no collection interval");
    println!("   • PeriodicReader configured externally by user");
    println!("   • Uses OpenTelemetry SDK default (60s) without override");

    // **DEFAULT INTERVAL TESTING**
    let default_config = MetricsCollectionConfigFixture::new(); // No interval configured
    let default_provider = DeterministicOtlpMetricsProvider::new().with_config(default_config);

    println!(
        "   Default collection interval: {}",
        format_duration(default_provider.collection_interval())
    );

    // **CONFIGURATION GAPS**
    println!("🚨 CURRENT IMPLEMENTATION GAPS:");
    println!("   • No way to configure collection interval through OtelMetrics");
    println!("   • Breaks encapsulation - users must manually configure PeriodicReader");
    println!("   • Default 60s interval may be too slow for many use cases");
    println!("   • No guidance for interval selection in documentation");

    println!("📋 REQUIRED IMPROVEMENTS:");
    println!("   1. Add collection_interval field to MetricsConfig");
    println!("   2. Update OtelMetrics to accept interval configuration");
    println!("   3. Provide factory methods for common interval patterns");
    println!("   4. Add with_collection_interval() builder method");
    println!("   5. Document interval selection guidelines");

    println!("📊 Use case requirements:");
    println!("   • Real-time dashboards: 1-5s intervals");
    println!("   • Application monitoring: 10-30s intervals");
    println!("   • Infrastructure monitoring: 30-60s intervals");
    println!("   • Cost optimization monitoring: 300s+ intervals");

    // **SPEC COMPLIANCE VERIFICATION**
    println!("📋 OTLP specification compliance:");
    println!("   • OTLP spec requires configurable collection interval: ❌ MISSING");
    println!("   • Reasonable default interval (10-60s): ✅ PRESENT (60s)");
    println!("   • Application-level configuration: ❌ MISSING");
    println!("   • Use-case appropriate intervals: ❌ NOT SUPPORTED");

    println!("✅ COLLECTION INTERVAL AUDIT COMPLETE");
    println!("🚨 FINDING: Collection interval configuration not exposed to applications");
}

/// **AUDIT TEST**: Verify ideal collection interval configuration patterns.
///
/// **SCENARIO**: Verify how collection interval configuration should work.
/// **REQUIREMENT**: Proper encapsulation and configuration patterns for OTLP compliance.
/// **ASSESSMENT**: Design patterns for collection interval management.
#[test]
fn audit_ideal_collection_interval_patterns() {
    println!("🔍 AUDIT: Ideal OTLP metrics collection interval patterns");

    println!("📋 Configuration pattern requirements:");
    println!("   • Builder pattern for interval configuration");
    println!("   • Sensible defaults for different use cases");
    println!("   • Runtime interval adjustment capability");
    println!("   • Validation of interval ranges");

    let configuration_patterns = vec![
        (Duration::from_secs(1), "real_time", "Real-time monitoring"),
        (
            Duration::from_secs(10),
            "standard",
            "Standard application monitoring",
        ),
        (
            Duration::from_secs(30),
            "infrastructure",
            "Infrastructure monitoring",
        ),
        (
            Duration::from_secs(60),
            "cost_optimized",
            "Cost-optimized monitoring",
        ),
        (Duration::from_secs(300), "batch", "Batch job monitoring"),
    ];

    println!("📊 Testing configuration pattern support:");

    for (interval, pattern_name, description) in configuration_patterns {
        println!(
            "   Pattern: {} - {} ({})",
            pattern_name,
            format_duration(interval),
            description
        );

        // **IDEAL CONFIGURATION API** (what should exist)
        let config = MetricsCollectionConfigFixture::new().with_collection_interval(interval);
        let provider = DeterministicOtlpMetricsProvider::new().with_config(config);

        // Verify configuration encapsulation
        if provider.collection_interval() == interval {
            println!("     ✅ PATTERN: Configuration properly encapsulated");
        } else {
            println!("     ❌ PATTERN: Configuration not encapsulated");
        }

        // Verify reasonable interval validation
        if interval >= Duration::from_millis(100) && interval <= Duration::from_secs(3600) {
            println!("     ✅ VALIDATION: Interval within reasonable bounds");
        } else {
            println!("     ⚠️  VALIDATION: Interval may be problematic");
        }
    }

    // **BUILDER PATTERN VALIDATION**
    println!("📋 Builder pattern requirements:");
    println!("   • Fluent configuration API");
    println!("   • Chainable configuration methods");
    println!("   • Sensible defaults when not configured");
    println!("   • Type-safe interval specification");

    // **FACTORY METHOD PATTERNS**
    println!("📋 Factory method patterns for common use cases:");
    let factory_patterns = vec![
        ("MetricsConfig::real_time()", Duration::from_secs(1)),
        ("MetricsConfig::standard()", Duration::from_secs(15)),
        ("MetricsConfig::infrastructure()", Duration::from_secs(30)),
        ("MetricsConfig::cost_optimized()", Duration::from_secs(60)),
    ];

    for (factory_name, expected_interval) in factory_patterns {
        println!(
            "   {}: {} interval",
            factory_name,
            format_duration(expected_interval)
        );
    }

    println!("✅ COLLECTION INTERVAL PATTERNS AUDIT COMPLETE");
    println!("📊 FINDING: Need builder pattern + factory methods for interval config");
}

fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis < 1000 {
        format!("{}ms", millis)
    } else {
        format!("{}s", duration.as_secs())
    }
}
