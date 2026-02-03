#![allow(dead_code)]
#![allow(unused_imports)]
//! Shared integration test utilities.
//!
//! Import with:
//! ```
//! mod common;
//! use common::*;
//! ```

pub mod coverage;

pub use coverage::{
    assert_coverage, assert_coverage_threshold, CoverageEntry, CoverageInfo, CoverageReport,
    InvariantTracker,
};

pub use asupersync::test_logging::{
    AggregatedReport, TestContext, TestHarness, TestReportAggregator, TestSummary,
};

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::timeout;
use asupersync::types::Time;
use proptest::prelude::ProptestConfig;
use proptest::test_runner::RngSeed;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Once;
use std::time::Duration;
use tracing_subscriber::fmt::format::FmtSpan;

static INIT_LOGGING: Once = Once::new();

/// Default seed used by test lab helpers.
pub const DEFAULT_TEST_SEED: u64 = 0xDEAD_BEEF;
/// Default seed for property tests when running under CI.
pub const DEFAULT_PROPTEST_SEED: u64 = 0x5EED_5EED;

const PROPTEST_SEED_ENV: &str = "ASUPERSYNC_PROPTEST_SEED";
const PROPTEST_MAX_SHRINK_ITERS_ENV: &str = "ASUPERSYNC_PROPTEST_MAX_SHRINK_ITERS";
const CONFORMANCE_ARTIFACTS_DIR_ENV: &str = "ASUPERSYNC_CONFORMANCE_ARTIFACTS_DIR";
const TOPOLOGY_ARTIFACTS_DIR_ENV: &str = "ASUPERSYNC_TOPOLOGY_ARTIFACTS_DIR";

/// Configuration for property tests with optional deterministic seed support.
#[derive(Debug, Clone)]
pub struct PropertyTestConfig {
    /// Fixed seed for reproducibility (overrides CI default when set).
    pub seed: Option<u64>,
    /// Number of successful cases required.
    pub cases: u32,
    /// Maximum shrink iterations.
    pub max_shrink_iters: u32,
}

impl PropertyTestConfig {
    /// Build a config with defaults for property tests.
    #[must_use]
    pub fn new(cases: u32) -> Self {
        Self {
            seed: read_proptest_seed(),
            cases,
            max_shrink_iters: read_max_shrink_iters()
                .unwrap_or_else(|| ProptestConfig::default().max_shrink_iters),
        }
    }

    /// Convert into a ProptestConfig, applying deterministic seed rules.
    #[must_use]
    pub fn to_proptest_config(&self) -> ProptestConfig {
        let mut config = ProptestConfig::with_cases(self.cases);

        // Honor existing PROPTEST_RNG_SEED, otherwise apply our own.
        if matches!(config.rng_seed, RngSeed::Random) {
            if let Some(seed) = self.seed {
                config.rng_seed = RngSeed::Fixed(seed);
            }
        }

        config.max_shrink_iters = self.max_shrink_iters;
        config
    }
}

/// Build a ProptestConfig with deterministic seed support for CI.
#[must_use]
pub fn test_proptest_config(cases: u32) -> ProptestConfig {
    PropertyTestConfig::new(cases).to_proptest_config()
}

fn read_proptest_seed() -> Option<u64> {
    if let Ok(value) = std::env::var(PROPTEST_SEED_ENV) {
        return value.parse::<u64>().ok();
    }

    // If CI is set and no explicit seed is provided, use a fixed seed.
    if std::env::var("CI").is_ok() {
        return Some(DEFAULT_PROPTEST_SEED);
    }

    None
}

fn read_max_shrink_iters() -> Option<u32> {
    std::env::var(PROPTEST_MAX_SHRINK_ITERS_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
}

/// Initialize test logging with trace-level output.
pub fn init_test_logging() {
    init_test_logging_with_level(tracing::Level::TRACE);
}

/// Initialize test logging with a custom level.
pub fn init_test_logging_with_level(level: tracing::Level) {
    INIT_LOGGING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_test_writer()
            .with_file(true)
            .with_line_number(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_span_events(FmtSpan::CLOSE)
            .with_ansi(false)
            .try_init();
    });
}

/// Create a deterministic lab runtime for testing.
#[must_use]
pub fn test_lab() -> LabRuntime {
    LabRuntime::new(LabConfig::new(DEFAULT_TEST_SEED))
}

/// Create a lab runtime with a specific seed.
#[must_use]
pub fn test_lab_with_seed(seed: u64) -> LabRuntime {
    LabRuntime::new(LabConfig::new(seed))
}

/// Create a lab runtime with a larger trace buffer for debugging.
#[must_use]
pub fn test_lab_with_tracing() -> LabRuntime {
    LabRuntime::new(LabConfig::new(DEFAULT_TEST_SEED).trace_capacity(64 * 1024))
}

/// Create a lab runtime from a [`TestContext`], using the context's seed.
#[must_use]
pub fn test_lab_from_context(ctx: &TestContext) -> LabRuntime {
    LabRuntime::new(LabConfig::new(ctx.seed))
}

/// Create a [`TestContext`] for an integration test with the default seed.
#[must_use]
pub fn test_context(test_id: &str) -> TestContext {
    TestContext::new(test_id, DEFAULT_TEST_SEED)
}

/// Create a [`TestContext`] for an integration test with a specific seed.
#[must_use]
pub fn test_context_with_seed(test_id: &str, seed: u64) -> TestContext {
    TestContext::new(test_id, seed)
}

/// Run async test code using a lightweight current-thread runtime.
pub fn run_test<F, Fut>(f: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    init_test_logging();
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(f());
}

/// Run async test code with a test `Cx`.
pub fn run_test_with_cx<F, Fut>(f: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    init_test_logging();
    let cx: Cx = Cx::for_testing();
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(f(cx));
}

fn conformance_artifacts_dir() -> Option<PathBuf> {
    if let Ok(value) = std::env::var(CONFORMANCE_ARTIFACTS_DIR_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    if std::env::var("CI").is_ok() {
        return Some(PathBuf::from("target/conformance"));
    }

    None
}

fn topology_artifacts_dir() -> Option<PathBuf> {
    if let Ok(value) = std::env::var(TOPOLOGY_ARTIFACTS_DIR_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    if std::env::var("CI").is_ok() {
        return Some(PathBuf::from("target/topology"));
    }

    None
}

pub fn write_conformance_artifacts(suite_name: &str, summary: &conformance::runner::SuiteResult) {
    let Some(dir) = conformance_artifacts_dir() else {
        return;
    };

    if let Err(err) = std::fs::create_dir_all(&dir) {
        tracing::warn!(error = %err, path = %dir.display(), "failed to create conformance artifact dir");
        return;
    }

    let json_path = dir.join(format!("{suite_name}.json"));
    if let Err(err) = conformance::write_json_report(summary, &json_path) {
        tracing::warn!(
            error = %err,
            path = %json_path.display(),
            "failed to write conformance json report"
        );
    }

    let txt_path = dir.join(format!("{suite_name}.txt"));
    let summary_text = conformance::render_console_summary(summary);
    if let Err(err) = std::fs::write(&txt_path, summary_text) {
        tracing::warn!(
            error = %err,
            path = %txt_path.display(),
            "failed to write conformance text report"
        );
    }

    tracing::info!(
        path = %dir.display(),
        suite = %suite_name,
        "conformance artifacts written"
    );
}

pub fn write_topology_report<T: serde::Serialize>(suite_name: &str, report: &T) {
    let Some(dir) = topology_artifacts_dir() else {
        return;
    };

    if let Err(err) = std::fs::create_dir_all(&dir) {
        tracing::warn!(error = %err, path = %dir.display(), "failed to create topology artifact dir");
        return;
    }

    let json_path = dir.join(format!("{suite_name}.json"));
    let json = match serde_json::to_string_pretty(report) {
        Ok(json) => json,
        Err(err) => {
            tracing::warn!(error = %err, "failed to serialize topology report");
            return;
        }
    };

    if let Err(err) = std::fs::write(&json_path, json) {
        tracing::warn!(
            error = %err,
            path = %json_path.display(),
            "failed to write topology json report"
        );
        return;
    }

    tracing::info!(
        path = %json_path.display(),
        suite = %suite_name,
        "topology report written"
    );
}

#[allow(clippy::too_many_arguments)]
pub fn topology_report_json(
    suite_name: &str,
    scenario_name: &str,
    baseline: &asupersync::lab::explorer::ExplorationReport,
    topology: &asupersync::lab::explorer::ExplorationReport,
    top_ledgers: &[asupersync::trace::EvidenceLedger],
    scoring_overhead_ms: Option<u64>,
    scoring_work_units: u64,
    execution_steps: u64,
) -> serde_json::Value {
    fn report_metrics(report: &asupersync::lab::explorer::ExplorationReport) -> serde_json::Value {
        let novelty_histogram = serde_json::to_value(&report.coverage.novelty_histogram)
            .unwrap_or(serde_json::Value::Null);
        let saturation = serde_json::json!({
            "window": report.coverage.saturation.window,
            "saturated": report.coverage.saturation.saturated,
            "existing_class_hits": report.coverage.saturation.existing_class_hits,
            "runs_since_last_new_class": report.coverage.saturation.runs_since_last_new_class,
        });
        let violation_seeds: Vec<u64> = report.violation_seeds();
        let first_violation = report.violations.iter().min_by_key(|v| v.seed);
        let first_violation_seed = first_violation.map(|v| v.seed);
        let first_violation_steps = first_violation.map(|v| v.steps);

        serde_json::json!({
            "total_runs": report.total_runs,
            "unique_classes": report.unique_classes,
            "new_class_discoveries": report.coverage.new_class_discoveries,
            "violations": report.violations.len(),
            "violation_seeds": violation_seeds,
            "first_violation_seed": first_violation_seed,
            "first_violation_steps": first_violation_steps,
            "novelty_histogram": novelty_histogram,
            "saturation": saturation,
        })
    }

    let baseline_metrics = report_metrics(baseline);
    let topology_metrics = report_metrics(topology);
    let top_ledger_summaries: Vec<String> = top_ledgers
        .iter()
        .map(asupersync::trace::EvidenceLedger::summary)
        .collect();

    let scoring_disabled = top_ledgers.iter().all(|ledger| ledger.entries.is_empty());
    let scoring_note = if scoring_overhead_ms.is_some() {
        None
    } else if scoring_disabled {
        Some("scoring produced no ledger entries")
    } else {
        Some("timing disabled for determinism; use work units")
    };

    serde_json::json!({
        "suite": suite_name,
        "scenario": scenario_name,
        "baseline": baseline_metrics,
        "topology": topology_metrics,
        "top_ledger_summaries": top_ledger_summaries,
        "scoring_overhead_ms": scoring_overhead_ms,
        "scoring_work_units": scoring_work_units,
        "execution_steps": execution_steps,
        "scoring_disabled": scoring_disabled,
        "scoring_note": scoring_note,
    })
}

/// Assert that an async operation completes within a timeout.
pub async fn assert_completes_within<F, Fut, T>(
    timeout_duration: Duration,
    description: &str,
    f: F,
) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let fut = Box::pin(f());
    timeout(Time::ZERO, timeout_duration, fut)
        .await
        .map_or_else(
            |_| panic!("operation '{description}' did not complete within {timeout_duration:?}"),
            |value| {
                tracing::debug!(
                    description = %description,
                    timeout_ms = timeout_duration.as_millis(),
                    "operation completed within timeout"
                );
                value
            },
        )
}

/// Log a test phase transition with a visual separator.
#[macro_export]
macro_rules! test_phase {
    ($name:expr) => {
        tracing::info!(phase = %$name, "========================================");
        tracing::info!(phase = %$name, "TEST PHASE: {}", $name);
        tracing::info!(phase = %$name, "========================================");
    };
}

/// Log a section within a test phase.
#[macro_export]
macro_rules! test_section {
    ($name:expr) => {
        tracing::debug!(section = %$name, "--- {} ---", $name);
    };
}

/// Log test completion with summary.
#[macro_export]
macro_rules! test_complete {
    ($name:expr) => {
        tracing::info!(test = %$name, "test completed successfully: {}", $name);
    };
    ($name:expr, $($key:ident = $value:expr),* $(,)?) => {
        tracing::info!(
            test = %$name,
            $($key = %$value,)*
            "test completed successfully: {}",
            $name
        );
    };
}

/// Log before assertions for context.
#[macro_export]
macro_rules! assert_with_log {
    ($cond:expr, $msg:expr, $expected:expr, $actual:expr) => {
        tracing::debug!(
            expected = ?$expected,
            actual = ?$actual,
            "Asserting: {}",
            $msg
        );
        assert!($cond, "{}: expected {:?}, got {:?}", $msg, $expected, $actual);
    };
}

/// Assert that an outcome is Ok with a specific value.
#[macro_export]
macro_rules! assert_outcome_ok {
    ($outcome:expr, $expected:expr) => {
        match $outcome {
            ::asupersync::types::Outcome::Ok(v) => assert_eq!(v, $expected),
            other => panic!("expected Outcome::Ok({:?}), got {:?}", $expected, other),
        }
    };
}

/// Assert that an outcome is Cancelled.
#[macro_export]
macro_rules! assert_outcome_cancelled {
    ($outcome:expr) => {
        match $outcome {
            ::asupersync::types::Outcome::Cancelled(_) => {}
            other => panic!("expected Outcome::Cancelled, got {:?}", other),
        }
    };
}

/// Assert that an outcome is Err.
#[macro_export]
macro_rules! assert_outcome_err {
    ($outcome:expr) => {
        match $outcome {
            ::asupersync::types::Outcome::Err(_) => {}
            other => panic!("expected Outcome::Err, got {:?}", other),
        }
    };
}

/// Assert that an outcome is Panicked.
#[macro_export]
macro_rules! assert_outcome_panicked {
    ($outcome:expr) => {
        match $outcome {
            ::asupersync::types::Outcome::Panicked(_) => {}
            other => panic!("expected Outcome::Panicked, got {:?}", other),
        }
    };
}

/// Mock connection for pool testing.
#[derive(Debug)]
pub struct MockConnection {
    id: usize,
    query_count: std::sync::atomic::AtomicUsize,
}

impl MockConnection {
    /// Create a new mock connection with a stable ID.
    #[must_use]
    pub fn new(id: usize) -> Self {
        Self {
            id,
            query_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Returns the connection ID.
    #[must_use]
    pub const fn id(&self) -> usize {
        self.id
    }

    /// Returns how many queries were issued.
    #[must_use]
    pub fn query_count(&self) -> usize {
        self.query_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Simulate a query.
    #[allow(clippy::unnecessary_wraps)]
    pub fn query(&self, _sql: &str) -> Result<(), MockError> {
        self.query_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Mock error for testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockError(pub String);

impl std::error::Error for MockError {}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MockError: {}", self.0)
    }
}

// =============================================================================
// Failure Recording Infrastructure (asupersync-kbg7)
// =============================================================================

/// Record a property test failure for regression testing.
///
/// Saves the failure input to a JSON file in the regression directory.
pub fn record_failure<T: serde::Serialize>(
    test_name: &str,
    input: &T,
    regression_dir: Option<&std::path::Path>,
) -> std::io::Result<std::path::PathBuf> {
    let dir = regression_dir.unwrap_or_else(|| std::path::Path::new("tests/regressions"));

    // Ensure directory exists
    std::fs::create_dir_all(dir)?;

    // Generate filename with timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let filename = format!("{test_name}_{timestamp}.json");
    let path = dir.join(&filename);

    // Serialize and write
    let json = serde_json::to_string_pretty(input)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    std::fs::write(&path, json)?;

    tracing::warn!(
        test = %test_name,
        path = %path.display(),
        "recorded property test failure for regression testing"
    );

    Ok(path)
}

/// Load a regression test case from a JSON file.
pub fn load_regression<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
) -> std::io::Result<T> {
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Find all regression test files for a given test name.
pub fn find_regressions(
    test_name: &str,
    regression_dir: Option<&std::path::Path>,
) -> std::io::Result<Vec<std::path::PathBuf>> {
    let dir = regression_dir.unwrap_or_else(|| std::path::Path::new("tests/regressions"));

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    let prefix = format!("{test_name}_");

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with(&prefix)
                    && path
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                {
                    files.push(path);
                }
            }
        }
    }

    // Sort by filename (which includes timestamp) for consistent ordering
    files.sort();

    Ok(files)
}

/// Run a regression test with the loaded input.
///
/// This is a helper for running regression tests in a consistent way.
pub fn run_regression_test<T, F>(test_name: &str, input: T, test_fn: F)
where
    F: FnOnce(T),
{
    init_test_logging();
    tracing::info!(
        test = %test_name,
        "running regression test"
    );
    test_fn(input);
    tracing::info!(
        test = %test_name,
        "regression test passed"
    );
}

// =============================================================================
// Shrinking Helper Macros (asupersync-kbg7)
// =============================================================================

/// Helper macro for recording failures in proptest.
///
/// Use this in proptest! blocks to automatically record failures:
///
/// ```ignore
/// proptest! {
///     #[test]
///     fn my_property_test(input in any::<MyInput>()) {
///         let result = test_with(&input);
///         if result.is_err() {
///             record_on_failure!("my_property_test", &input);
///         }
///         prop_assert!(result.is_ok());
///     }
/// }
/// ```
#[macro_export]
macro_rules! record_on_failure {
    ($test_name:expr, $input:expr) => {
        let _ = $crate::common::record_failure($test_name, $input, None);
    };
    ($test_name:expr, $input:expr, $dir:expr) => {
        let _ = $crate::common::record_failure($test_name, $input, Some($dir));
    };
}
