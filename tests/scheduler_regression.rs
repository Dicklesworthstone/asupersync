//! Scheduler performance regression tests.
//!
//! These tests establish baseline performance metrics and fail if
//! performance degrades beyond acceptable thresholds. Run with:
//!
//!   cargo test --test scheduler_regression --release -- --nocapture
//!
//! Note: these tests require --release for meaningful numbers.

use std::collections::BTreeMap;
use std::time::Instant;

use asupersync::runtime::scheduler::{GlobalQueue, LocalQueue, Parker, Scheduler};
use asupersync::types::{TaskId, Time};
use serde::Deserialize;

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

/// Throughput regression: schedule+pop 10K tasks must complete in < 50ms.
/// This is a generous threshold to avoid flaky failures on slow CI.
#[test]
fn regression_throughput_10k_schedule_pop() {
    let mut scheduler = Scheduler::new();
    let start = Instant::now();

    for i in 0..10_000u32 {
        scheduler.schedule(task(i), (i % 256) as u8);
    }
    let mut popped = 0u32;
    while scheduler.pop().is_some() {
        popped += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(popped, 10_000);
    assert!(
        elapsed.as_millis() < 50,
        "throughput regression: 10K schedule+pop took {}ms (threshold: 50ms)",
        elapsed.as_millis()
    );
}

/// Local queue regression: push+pop 100K items in < 100ms.
#[test]
fn regression_local_queue_100k() {
    let queue = LocalQueue::new_for_test(99_999);
    let start = Instant::now();

    for i in 0..100_000u32 {
        queue.push(task(i));
    }
    let mut popped = 0u32;
    while queue.pop().is_some() {
        popped += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(popped, 100_000);
    assert!(
        elapsed.as_millis() < 100,
        "local queue regression: 100K push+pop took {}ms (threshold: 100ms)",
        elapsed.as_millis()
    );
}

/// Global queue regression: push+pop 100K items in < 200ms.
#[test]
fn regression_global_queue_100k() {
    let queue = GlobalQueue::new();
    let start = Instant::now();

    for i in 0..100_000u32 {
        queue.push(task(i));
    }
    let mut popped = 0u32;
    while queue.pop().is_some() {
        popped += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(popped, 100_000);
    assert!(
        elapsed.as_millis() < 200,
        "global queue regression: 100K push+pop took {}ms (threshold: 200ms)",
        elapsed.as_millis()
    );
}

/// Parker regression: 1000 unpark+park cycles in < 100ms.
#[test]
fn regression_parker_cycle_1k() {
    let parker = Parker::new();
    let start = Instant::now();

    for _ in 0..1_000 {
        parker.unpark();
        parker.park();
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 100,
        "parker regression: 1K cycles took {}ms (threshold: 100ms)",
        elapsed.as_millis()
    );
}

/// Mixed-lane throughput: schedule 10K tasks across all 3 lanes + pop.
#[test]
fn regression_mixed_lane_10k() {
    let mut scheduler = Scheduler::new();
    let start = Instant::now();

    for i in 0..10_000u32 {
        match i % 3 {
            0 => scheduler.schedule(task(i), 0),
            1 => scheduler.schedule_timed(task(i), Time::from_nanos(u64::from(i) * 1000)),
            _ => scheduler.schedule_cancel(task(i), 0),
        }
    }
    let mut popped = 0u32;
    while scheduler.pop().is_some() {
        popped += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(popped, 10_000);
    assert!(
        elapsed.as_millis() < 100,
        "mixed-lane regression: 10K tasks took {}ms (threshold: 100ms)",
        elapsed.as_millis()
    );
}

#[derive(Debug, Deserialize)]
struct BaselineReport {
    generated_at: String,
    benchmarks: Vec<BaselineEntry>,
}

#[derive(Debug, Deserialize)]
struct BaselineEntry {
    name: String,
    mean_ns: f64,
    median_ns: f64,
    p95_ns: Option<f64>,
    p99_ns: Option<f64>,
    std_dev_ns: Option<f64>,
}

#[test]
fn baseline_report_format_parses() {
    let sample = r#"{
        "generated_at": "2026-02-03T19:00:00Z",
        "benchmarks": [
            {
                "name": "scheduler/priority_lane_ordering_100",
                "mean_ns": 1234.5,
                "median_ns": 1200.0,
                "p95_ns": 1500.0,
                "p99_ns": 1700.0,
                "std_dev_ns": 45.0
            }
        ]
    }"#;

    let report: BaselineReport = serde_json::from_str(sample).expect("parse baseline report");
    assert!(!report.generated_at.is_empty());
    assert_eq!(report.benchmarks.len(), 1);
    assert_eq!(
        report.benchmarks[0].name,
        "scheduler/priority_lane_ordering_100"
    );
    assert!(report.benchmarks[0].mean_ns > 0.0);
    assert!(report.benchmarks[0].median_ns > 0.0);

    let sample_nullable = r#"{
        "generated_at": "2026-02-03T19:00:00Z",
        "benchmarks": [
            {
                "name": "scheduler/priority_lane_ordering_100",
                "mean_ns": 1234.5,
                "median_ns": 1200.0,
                "p95_ns": null,
                "p99_ns": null,
                "std_dev_ns": null
            }
        ]
    }"#;

    let report: BaselineReport =
        serde_json::from_str(sample_nullable).expect("parse baseline report with nulls");
    assert_eq!(report.benchmarks.len(), 1);
    assert_eq!(report.benchmarks[0].p95_ns, None);
    assert_eq!(report.benchmarks[0].p99_ns, None);
    assert_eq!(report.benchmarks[0].std_dev_ns, None);
}

#[derive(Debug, Deserialize)]
struct SmokeReport {
    generated_at: String,
    command: String,
    seed: Option<String>,
    criterion_dir: String,
    baseline_path: String,
    latest_path: String,
    git_sha: Option<String>,
    config: SmokeConfig,
    env: BTreeMap<String, Option<String>>,
    system: SmokeSystem,
}

#[derive(Debug, Deserialize)]
struct SmokeConfig {
    criterion_dir: String,
    save_dir: Option<String>,
    compare_path: Option<String>,
    metric: String,
    max_regression_pct: f64,
}

#[derive(Debug, Deserialize)]
struct SmokeSystem {
    os: String,
    arch: String,
    platform: String,
}

#[test]
fn smoke_report_format_parses() {
    let sample = r#"{
        "generated_at": "2026-02-03T19:00:00Z",
        "command": "cargo bench --bench phase0_baseline",
        "seed": "3735928559",
        "criterion_dir": "target/criterion",
        "baseline_path": "baselines/baseline_20260203_190000.json",
        "latest_path": "baselines/baseline_latest.json",
        "git_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "config": {
            "criterion_dir": "target/criterion",
            "save_dir": "baselines",
            "compare_path": null,
            "metric": "median_ns",
            "max_regression_pct": 10.0
        },
        "env": {
            "CI": "true",
            "RUSTFLAGS": "-C force-frame-pointers=yes"
        },
        "system": {
            "os": "linux",
            "arch": "x86_64",
            "platform": "Linux-6.x-x86_64"
        }
    }"#;

    let report: SmokeReport = serde_json::from_str(sample).expect("parse smoke report");
    assert!(!report.generated_at.is_empty());
    assert!(!report.command.is_empty());
    assert_eq!(report.criterion_dir, "target/criterion");
    assert_eq!(
        report.baseline_path,
        "baselines/baseline_20260203_190000.json"
    );
    assert_eq!(report.latest_path, "baselines/baseline_latest.json");
    assert_eq!(report.system.os, "linux");
    assert_eq!(report.system.arch, "x86_64");
    assert!(!report.system.platform.is_empty());
    assert!(report.env.contains_key("CI"));
    assert!(report.env.contains_key("RUSTFLAGS"));
    assert_eq!(report.config.criterion_dir, "target/criterion");
    assert_eq!(report.config.save_dir.as_deref(), Some("baselines"));
    assert!(report.config.compare_path.is_none());
    assert_eq!(report.config.metric, "median_ns");
    assert!(
        (report.config.max_regression_pct - 10.0).abs() < f64::EPSILON,
        "max_regression_pct should be 10.0"
    );
    assert_eq!(report.seed.as_deref(), Some("3735928559"));
    assert_eq!(
        report.git_sha.as_deref(),
        Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    );
}
