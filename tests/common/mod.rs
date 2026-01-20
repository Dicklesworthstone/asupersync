#![allow(dead_code)]
//! Shared integration test utilities.
//!
//! Import with:
//! ```
//! mod common;
//! use common::*;
//! ```

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::timeout;
use asupersync::types::Time;
use std::future::Future;
use std::sync::Once;
use std::time::Duration;
use tracing_subscriber::fmt::format::FmtSpan;

static INIT_LOGGING: Once = Once::new();

/// Default seed used by test lab helpers.
pub const DEFAULT_TEST_SEED: u64 = 0xDEADBEEF;

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
    let cx = Cx::for_testing();
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(f(cx));
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
    match timeout(Time::ZERO, timeout_duration, fut).await {
        Ok(value) => {
            tracing::debug!(
                description = %description,
                timeout_ms = timeout_duration.as_millis(),
                "operation completed within timeout"
            );
            value
        }
        Err(_) => {
            panic!(
                "operation '{}' did not complete within {:?}",
                description, timeout_duration
            );
        }
    }
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
    pub async fn query(&self, _sql: &str) -> Result<(), MockError> {
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
