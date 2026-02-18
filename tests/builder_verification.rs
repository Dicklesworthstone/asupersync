//! Builder Pattern Verification Suite
//!
//! Verifies the public API surface of runtime and lab builders:
//!   - RuntimeBuilder construction (001-006)
//!   - RuntimeBuilder presets (007-010)
//!   - DeadlineMonitoringBuilder (011-014)
//!   - LabConfig construction (015-020)
//!   - ChaosConfig (021-026)
//!   - LabRuntime lifecycle (027-032)
//!   - LabInjectionConfig (033-035)
//!
//! Bead: asupersync-f74u

#![allow(
    clippy::items_after_statements,
    clippy::redundant_clone,
    clippy::should_panic_without_expect,
    clippy::single_char_pattern
)]

#[macro_use]
mod common;

use common::init_test_logging;

use asupersync::lab::chaos::ChaosConfig;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::deadline_monitor::{AdaptiveDeadlineConfig, MonitorConfig};
use asupersync::runtime::{RegionLimits, RuntimeBuilder, SpawnError};
use asupersync::types::Time;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// =============================================================================
// RuntimeBuilder Construction (001-006)
// =============================================================================

/// BUILDER-VERIFY-001: Default RuntimeBuilder produces valid Runtime
///
/// RuntimeBuilder::new().build() should succeed with reasonable defaults.
#[test]
fn builder_verify_001_default_build() {
    init_test("builder_verify_001_default_build");

    let runtime = RuntimeBuilder::new()
        .build()
        .expect("default build should succeed");
    let config = runtime.config();

    assert!(config.worker_threads >= 1, "must have at least 1 worker");
    assert!(config.thread_stack_size > 0, "stack size must be positive");
    assert!(config.poll_budget >= 1, "poll budget must be positive");
    assert!(
        config.enable_parking,
        "parking should be enabled by default"
    );

    test_complete!("builder_verify_001_default_build");
}

/// BUILDER-VERIFY-002: Worker thread configuration
///
/// worker_threads, thread_stack_size, thread_name_prefix are respected.
#[test]
fn builder_verify_002_worker_config() {
    init_test("builder_verify_002_worker_config");

    let runtime = RuntimeBuilder::new()
        .worker_threads(4)
        .thread_stack_size(4 * 1024 * 1024)
        .thread_name_prefix("test-worker")
        .build()
        .expect("configured build should succeed");

    let config = runtime.config();
    assert_eq!(config.worker_threads, 4);
    assert_eq!(config.thread_stack_size, 4 * 1024 * 1024);
    assert_eq!(config.thread_name_prefix, "test-worker");

    test_complete!("builder_verify_002_worker_config");
}

/// BUILDER-VERIFY-003: Scheduler tuning parameters
///
/// steal_batch_size, poll_budget, global_queue_limit, enable_parking are configurable.
#[test]
fn builder_verify_003_scheduler_tuning() {
    init_test("builder_verify_003_scheduler_tuning");

    let runtime = RuntimeBuilder::new()
        .steal_batch_size(32)
        .poll_budget(64)
        .global_queue_limit(8192)
        .enable_parking(false)
        .build()
        .expect("build with tuning should succeed");

    let config = runtime.config();
    assert_eq!(config.steal_batch_size, 32);
    assert_eq!(config.poll_budget, 64);
    assert_eq!(config.global_queue_limit, 8192);
    assert!(!config.enable_parking);

    test_complete!("builder_verify_003_scheduler_tuning");
}

/// BUILDER-VERIFY-004: Blocking pool configuration
///
/// blocking_threads(min, max) sets the blocking thread pool bounds.
#[test]
fn builder_verify_004_blocking_pool() {
    init_test("builder_verify_004_blocking_pool");

    let runtime = RuntimeBuilder::new()
        .blocking_threads(2, 16)
        .build()
        .expect("build with blocking pool should succeed");

    let config = runtime.config();
    assert_eq!(config.blocking.min_threads, 2);
    assert_eq!(config.blocking.max_threads, 16);

    test_complete!("builder_verify_004_blocking_pool");
}

/// BUILDER-VERIFY-005: Thread lifecycle callbacks
///
/// on_thread_start and on_thread_stop callbacks are set without panicking.
#[test]
fn builder_verify_005_thread_callbacks() {
    init_test("builder_verify_005_thread_callbacks");

    let started = Arc::new(AtomicBool::new(false));
    let stopped = Arc::new(AtomicBool::new(false));

    let s = started.clone();
    let t = stopped.clone();

    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .on_thread_start(move || {
            s.store(true, Ordering::SeqCst);
        })
        .on_thread_stop(move || {
            t.store(true, Ordering::SeqCst);
        })
        .build()
        .expect("build with callbacks should succeed");

    // Verify callbacks are set (actual invocation depends on runtime scheduling)
    assert!(runtime.config().on_thread_start.is_some());
    assert!(runtime.config().on_thread_stop.is_some());

    test_complete!("builder_verify_005_thread_callbacks");
}

/// BUILDER-VERIFY-006: Config normalization of zero/empty values
///
/// Builder normalizes degenerate values to safe defaults.
#[test]
fn builder_verify_006_normalization() {
    init_test("builder_verify_006_normalization");

    // Zero workers → at least 1
    let runtime = RuntimeBuilder::new()
        .worker_threads(0)
        .thread_stack_size(0)
        .steal_batch_size(0)
        .poll_budget(0)
        .build()
        .expect("zero values should be normalized");

    let config = runtime.config();
    assert!(config.worker_threads >= 1, "normalized workers");
    assert!(config.thread_stack_size > 0, "normalized stack size");
    assert!(config.steal_batch_size >= 1, "normalized steal batch");
    assert!(config.poll_budget >= 1, "normalized poll budget");

    test_complete!("builder_verify_006_normalization");
}

/// BUILDER-VERIFY-006B: Root region admission limits
///
/// RuntimeBuilder applies root region limits and spawn returns an error when
/// admission is denied.
#[test]
fn builder_verify_006b_root_region_limits() {
    init_test("builder_verify_006b_root_region_limits");

    let limits = RegionLimits {
        max_tasks: Some(0),
        ..RegionLimits::unlimited()
    };

    let runtime = RuntimeBuilder::new()
        .root_region_limits(limits)
        .build()
        .expect("build with root limits should succeed");

    let result = runtime.handle().try_spawn(async { 1_u8 });
    assert!(matches!(result, Err(SpawnError::RegionAtCapacity { .. })));

    test_complete!("builder_verify_006b_root_region_limits");
}

// =============================================================================
// RuntimeBuilder Presets (007-010)
// =============================================================================

/// BUILDER-VERIFY-007: current_thread preset
///
/// Single-threaded runtime for Phase 0 compatibility.
#[test]
fn builder_verify_007_current_thread() {
    init_test("builder_verify_007_current_thread");

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("current_thread should build");

    assert_eq!(runtime.config().worker_threads, 1);

    test_complete!("builder_verify_007_current_thread");
}

/// BUILDER-VERIFY-008: multi_thread preset
///
/// Multi-threaded preset uses available parallelism.
#[test]
fn builder_verify_008_multi_thread() {
    init_test("builder_verify_008_multi_thread");

    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("multi_thread should build");

    assert!(runtime.config().worker_threads >= 1);

    test_complete!("builder_verify_008_multi_thread");
}

/// BUILDER-VERIFY-009: high_throughput preset
///
/// Optimized for throughput: 2x workers, larger batch size.
#[test]
fn builder_verify_009_high_throughput() {
    init_test("builder_verify_009_high_throughput");

    let runtime = RuntimeBuilder::high_throughput()
        .build()
        .expect("high_throughput should build");

    let config = runtime.config();
    // High throughput should have batch_size=32
    assert_eq!(config.steal_batch_size, 32);

    test_complete!("builder_verify_009_high_throughput");
}

/// BUILDER-VERIFY-010: low_latency preset
///
/// Optimized for latency: smaller batch and poll budget.
#[test]
fn builder_verify_010_low_latency() {
    init_test("builder_verify_010_low_latency");

    let runtime = RuntimeBuilder::low_latency()
        .build()
        .expect("low_latency should build");

    let config = runtime.config();
    assert_eq!(config.steal_batch_size, 4);
    assert_eq!(config.poll_budget, 32);

    test_complete!("builder_verify_010_low_latency");
}

// =============================================================================
// DeadlineMonitoringBuilder (011-014)
// =============================================================================

/// BUILDER-VERIFY-011: MonitorConfig defaults
///
/// Default MonitorConfig has reasonable values.
#[test]
fn builder_verify_011_monitor_config_defaults() {
    init_test("builder_verify_011_monitor_config_defaults");

    let config = MonitorConfig::default();
    assert_eq!(config.check_interval, Duration::from_secs(1));
    assert!((config.warning_threshold_fraction - 0.2).abs() < f64::EPSILON);
    assert_eq!(config.checkpoint_timeout, Duration::from_secs(30));
    assert!(config.enabled);

    test_complete!("builder_verify_011_monitor_config_defaults");
}

/// BUILDER-VERIFY-012: AdaptiveDeadlineConfig defaults
///
/// Adaptive deadlines are disabled by default.
#[test]
fn builder_verify_012_adaptive_config_defaults() {
    init_test("builder_verify_012_adaptive_config_defaults");

    let config = AdaptiveDeadlineConfig::default();
    assert!(!config.adaptive_enabled);
    assert!((config.warning_percentile - 0.90).abs() < f64::EPSILON);
    assert_eq!(config.min_samples, 10);
    assert_eq!(config.max_history, 1000);
    assert_eq!(config.fallback_threshold, Duration::from_secs(30));

    test_complete!("builder_verify_012_adaptive_config_defaults");
}

/// BUILDER-VERIFY-013: DeadlineMonitoringBuilder fluent API
///
/// Builder methods configure all monitoring fields.
#[test]
fn builder_verify_013_deadline_builder() {
    init_test("builder_verify_013_deadline_builder");

    let runtime = RuntimeBuilder::new()
        .deadline_monitoring(|dm| {
            dm.check_interval(Duration::from_millis(500))
                .warning_threshold_fraction(0.5)
                .checkpoint_timeout(Duration::from_secs(10))
                .enabled(true)
        })
        .build()
        .expect("build with deadline monitoring should succeed");

    let config = runtime.config();
    assert!(config.deadline_monitor.is_some());
    let mon = config.deadline_monitor.as_ref().unwrap();
    assert_eq!(mon.check_interval, Duration::from_millis(500));
    assert!((mon.warning_threshold_fraction - 0.5).abs() < f64::EPSILON);
    assert_eq!(mon.checkpoint_timeout, Duration::from_secs(10));
    assert!(mon.enabled);

    test_complete!("builder_verify_013_deadline_builder");
}

/// BUILDER-VERIFY-014: DeadlineMonitoringBuilder adaptive config
///
/// Adaptive deadline settings are forwarded correctly.
#[test]
fn builder_verify_014_adaptive_deadline_builder() {
    init_test("builder_verify_014_adaptive_deadline_builder");

    let runtime = RuntimeBuilder::new()
        .deadline_monitoring(|dm| {
            dm.adaptive_enabled(true)
                .adaptive_warning_percentile(0.95)
                .adaptive_min_samples(20)
                .adaptive_max_history(2000)
                .adaptive_fallback_threshold(Duration::from_secs(60))
        })
        .build()
        .expect("build with adaptive deadlines should succeed");

    let config = runtime.config();
    let mon = config.deadline_monitor.as_ref().unwrap();
    assert!(mon.adaptive.adaptive_enabled);
    assert!((mon.adaptive.warning_percentile - 0.95).abs() < f64::EPSILON);
    assert_eq!(mon.adaptive.min_samples, 20);
    assert_eq!(mon.adaptive.max_history, 2000);
    assert_eq!(mon.adaptive.fallback_threshold, Duration::from_secs(60));

    test_complete!("builder_verify_014_adaptive_deadline_builder");
}

// =============================================================================
// LabConfig Construction (015-020)
// =============================================================================

/// BUILDER-VERIFY-015: LabConfig basic construction
///
/// LabConfig::new(seed) sets the seed and reasonable defaults.
#[test]
fn builder_verify_015_lab_config_basic() {
    init_test("builder_verify_015_lab_config_basic");

    let config = LabConfig::new(42);
    assert_eq!(config.seed, 42);
    assert_eq!(config.entropy_seed, 42);
    assert_eq!(config.worker_count, 1);
    assert!(config.panic_on_obligation_leak);
    assert!(config.panic_on_futurelock);
    assert_eq!(config.trace_capacity, 4096);
    assert_eq!(config.futurelock_max_idle_steps, 10_000);
    assert_eq!(config.max_steps, Some(100_000));
    assert!(!config.has_chaos());
    assert!(!config.has_replay_recording());

    test_complete!("builder_verify_015_lab_config_basic");
}

/// BUILDER-VERIFY-016: LabConfig fluent builder
///
/// All LabConfig builder methods work correctly.
#[test]
fn builder_verify_016_lab_config_fluent() {
    init_test("builder_verify_016_lab_config_fluent");

    let config = LabConfig::new(100)
        .entropy_seed(200)
        .worker_count(4)
        .panic_on_leak(false)
        .panic_on_futurelock(false)
        .trace_capacity(8192)
        .futurelock_max_idle_steps(50_000)
        .max_steps(500_000);

    assert_eq!(config.seed, 100);
    assert_eq!(config.entropy_seed, 200);
    assert_eq!(config.worker_count, 4);
    assert!(!config.panic_on_obligation_leak);
    assert!(!config.panic_on_futurelock);
    assert_eq!(config.trace_capacity, 8192);
    assert_eq!(config.futurelock_max_idle_steps, 50_000);
    assert_eq!(config.max_steps, Some(500_000));

    test_complete!("builder_verify_016_lab_config_fluent");
}

/// BUILDER-VERIFY-017: LabConfig no_step_limit
///
/// no_step_limit() removes the max_steps cap.
#[test]
fn builder_verify_017_no_step_limit() {
    init_test("builder_verify_017_no_step_limit");

    let config = LabConfig::new(42).no_step_limit();
    assert!(config.max_steps.is_none());

    test_complete!("builder_verify_017_no_step_limit");
}

/// BUILDER-VERIFY-018: LabConfig::from_time()
///
/// Time-based seed produces varying configs.
#[test]
fn builder_verify_018_from_time() {
    init_test("builder_verify_018_from_time");

    let config1 = LabConfig::from_time();
    // Seed is derived from system time, so it should be nonzero
    assert_ne!(config1.seed, 0, "time-based seed should be nonzero");

    test_complete!("builder_verify_018_from_time");
}

/// BUILDER-VERIFY-019: LabConfig worker_count clamps zero to one
///
/// Zero worker count is normalized to 1.
#[test]
fn builder_verify_019_worker_clamp() {
    init_test("builder_verify_019_worker_clamp");

    let config = LabConfig::new(42).worker_count(0);
    assert_eq!(config.worker_count, 1, "zero workers should clamp to 1");

    test_complete!("builder_verify_019_worker_clamp");
}

/// BUILDER-VERIFY-020: LabConfig with replay recording
///
/// Replay recording can be enabled via the fluent API.
#[test]
fn builder_verify_020_replay_recording() {
    init_test("builder_verify_020_replay_recording");

    let config = LabConfig::new(42).with_default_replay_recording();
    assert!(config.has_replay_recording());

    test_complete!("builder_verify_020_replay_recording");
}

// =============================================================================
// ChaosConfig (021-026)
// =============================================================================

/// BUILDER-VERIFY-021: ChaosConfig::off()
///
/// Disabled chaos has all probabilities at zero.
#[test]
fn builder_verify_021_chaos_off() {
    init_test("builder_verify_021_chaos_off");

    let config = ChaosConfig::off();
    assert!(!config.is_enabled());

    let summary = config.summary();
    assert!(
        summary.contains("disabled") || summary.contains("off") || summary.contains("0"),
        "summary should indicate disabled: {summary}"
    );

    test_complete!("builder_verify_021_chaos_off");
}

/// BUILDER-VERIFY-022: ChaosConfig::light()
///
/// Light chaos preset: ~1% cancel, ~5% delay, ~2% I/O error.
#[test]
fn builder_verify_022_chaos_light() {
    init_test("builder_verify_022_chaos_light");

    let config = ChaosConfig::light();
    assert!(config.is_enabled());
    assert!(config.cancel_probability > 0.0);
    assert!(config.delay_probability > 0.0);
    assert!(config.io_error_probability > 0.0);

    test_complete!("builder_verify_022_chaos_light");
}

/// BUILDER-VERIFY-023: ChaosConfig::heavy()
///
/// Heavy chaos preset: more aggressive probabilities.
#[test]
fn builder_verify_023_chaos_heavy() {
    init_test("builder_verify_023_chaos_heavy");

    let config = ChaosConfig::heavy();
    assert!(config.is_enabled());
    // Heavy should be more aggressive than light
    let light = ChaosConfig::light();
    assert!(config.cancel_probability >= light.cancel_probability);
    assert!(config.delay_probability >= light.delay_probability);
    assert!(config.io_error_probability >= light.io_error_probability);

    test_complete!("builder_verify_023_chaos_heavy");
}

/// BUILDER-VERIFY-024: ChaosConfig custom probabilities
///
/// Individual probability setters validate range [0.0, 1.0].
#[test]
fn builder_verify_024_chaos_custom() {
    init_test("builder_verify_024_chaos_custom");

    let config = ChaosConfig::new(42)
        .with_cancel_probability(0.05)
        .with_delay_probability(0.1)
        .with_delay_range(Duration::from_micros(10)..Duration::from_millis(1))
        .with_io_error_probability(0.03)
        .with_wakeup_storm_probability(0.02)
        .with_wakeup_storm_count(1..10)
        .with_budget_exhaust_probability(0.01);

    assert!(config.is_enabled());
    assert!((config.cancel_probability - 0.05).abs() < f64::EPSILON);
    assert!((config.delay_probability - 0.1).abs() < f64::EPSILON);
    assert!((config.io_error_probability - 0.03).abs() < f64::EPSILON);
    assert!((config.wakeup_storm_probability - 0.02).abs() < f64::EPSILON);
    assert!((config.budget_exhaust_probability - 0.01).abs() < f64::EPSILON);

    test_complete!("builder_verify_024_chaos_custom");
}

/// BUILDER-VERIFY-025: ChaosConfig with LabConfig integration
///
/// LabConfig can be built with light/heavy chaos.
#[test]
fn builder_verify_025_chaos_lab_integration() {
    init_test("builder_verify_025_chaos_lab_integration");

    let config = LabConfig::new(42).with_light_chaos();
    assert!(config.has_chaos());

    let config = LabConfig::new(42).with_heavy_chaos();
    assert!(config.has_chaos());

    let custom = ChaosConfig::new(42).with_cancel_probability(0.5);
    let config = LabConfig::new(42).with_chaos(custom);
    assert!(config.has_chaos());

    test_complete!("builder_verify_025_chaos_lab_integration");
}

/// BUILDER-VERIFY-026: ChaosConfig probability validation
///
/// Probabilities outside [0.0, 1.0] should panic.
#[test]
#[should_panic]
fn builder_verify_026_chaos_invalid_probability() {
    let _ = ChaosConfig::new(42).with_cancel_probability(1.5);
}

// =============================================================================
// LabRuntime Lifecycle (027-032)
// =============================================================================

/// BUILDER-VERIFY-027: LabRuntime construction
///
/// LabRuntime::new(config) creates a valid runtime.
#[test]
fn builder_verify_027_lab_runtime_new() {
    init_test("builder_verify_027_lab_runtime_new");

    let config = LabConfig::new(0xDEAD_BEEF);
    let lab = LabRuntime::new(config);

    assert_eq!(lab.now(), Time::ZERO);
    assert_eq!(lab.steps(), 0);
    assert_eq!(lab.config().seed, 0xDEAD_BEEF);

    test_complete!("builder_verify_027_lab_runtime_new");
}

/// BUILDER-VERIFY-028: LabRuntime with_seed convenience
///
/// with_seed(n) is equivalent to new(LabConfig::new(n)).
#[test]
fn builder_verify_028_lab_with_seed() {
    init_test("builder_verify_028_lab_with_seed");

    let lab = LabRuntime::with_seed(42);
    assert_eq!(lab.config().seed, 42);
    assert_eq!(lab.now(), Time::ZERO);

    test_complete!("builder_verify_028_lab_with_seed");
}

/// BUILDER-VERIFY-029: LabRuntime time management
///
/// advance_time and advance_time_to move the virtual clock.
#[test]
fn builder_verify_029_lab_time() {
    init_test("builder_verify_029_lab_time");

    let mut lab = LabRuntime::new(LabConfig::new(42));
    assert_eq!(lab.now(), Time::ZERO);

    lab.advance_time(1_000_000); // 1ms in nanos
    assert_eq!(lab.now(), Time::from_nanos(1_000_000));

    let target = Time::from_secs(1);
    lab.advance_time_to(target);
    assert_eq!(lab.now(), target);

    test_complete!("builder_verify_029_lab_time");
}

/// BUILDER-VERIFY-030: LabRuntime trace buffer
///
/// Trace buffer is initialized with the configured capacity.
#[test]
fn builder_verify_030_lab_trace() {
    init_test("builder_verify_030_lab_trace");

    let config = LabConfig::new(42).trace_capacity(1024);
    let lab = LabRuntime::new(config);

    // trace() should be accessible without panic
    let _trace = lab.trace();

    test_complete!("builder_verify_030_lab_trace");
}

/// BUILDER-VERIFY-031: LabRuntime with chaos
///
/// Chaos-enabled LabRuntime tracks chaos stats.
#[test]
fn builder_verify_031_lab_with_chaos() {
    init_test("builder_verify_031_lab_with_chaos");

    let config = LabConfig::new(42).with_light_chaos();
    let lab = LabRuntime::new(config);

    assert!(lab.has_chaos());
    let stats = lab.chaos_stats();
    let _ = stats; // Just verify it's accessible

    test_complete!("builder_verify_031_lab_with_chaos");
}

/// BUILDER-VERIFY-032: LabRuntime with replay recording
///
/// Replay recording can be enabled and traces can be taken.
#[test]
fn builder_verify_032_lab_with_replay() {
    init_test("builder_verify_032_lab_with_replay");

    let config = LabConfig::new(42).with_default_replay_recording();
    let lab = LabRuntime::new(config);
    assert!(lab.has_replay_recording());

    // Recorder should be accessible
    let _recorder = lab.replay_recorder();

    test_complete!("builder_verify_032_lab_with_replay");
}

// =============================================================================
// LabInjectionConfig (033-035)
// =============================================================================

/// BUILDER-VERIFY-033: LabInjectionConfig construction
///
/// Injection config has a seed and configurable strategy.
#[test]
fn builder_verify_033_injection_config() {
    init_test("builder_verify_033_injection_config");

    use asupersync::lab::LabInjectionConfig;

    let config = LabInjectionConfig::new(42);
    assert_eq!(config.seed(), 42);

    test_complete!("builder_verify_033_injection_config");
}

/// BUILDER-VERIFY-034: LabInjectionConfig fluent API
///
/// Builder methods configure stop behavior and step limits.
#[test]
fn builder_verify_034_injection_fluent() {
    init_test("builder_verify_034_injection_fluent");

    use asupersync::lab::LabInjectionConfig;

    let config = LabInjectionConfig::new(42)
        .with_all_oracles()
        .stop_on_failure(true)
        .max_steps_per_run(50_000);

    assert_eq!(config.seed(), 42);

    test_complete!("builder_verify_034_injection_fluent");
}

/// BUILDER-VERIFY-035: LabInjectionRunner construction
///
/// Runner can be created from a config.
#[test]
fn builder_verify_035_injection_runner() {
    init_test("builder_verify_035_injection_runner");

    use asupersync::lab::{LabInjectionConfig, LabInjectionRunner};

    let config = LabInjectionConfig::new(42);
    let runner = LabInjectionRunner::new(config);
    assert_eq!(runner.config().seed(), 42);

    test_complete!("builder_verify_035_injection_runner");
}
