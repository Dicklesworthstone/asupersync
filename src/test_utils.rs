#![allow(clippy::all)]
//! Test utilities for Asupersync.
//!
//! This module provides shared helpers for unit tests:
//! - Scoped tracing-based logging
//! - Phase/section macros for readable test output
//! - Lab runtime constructors
//! - Async test runners
//! - Outcome assertion macros
//! - Test types for pool-style tests
//!
//! # Example
//! ```
//! use asupersync::test_utils::run_test;
//!
//! fn my_async_test() {
//!     run_test(|| async {
//!         // async test code
//!     });
//! }
//! ```

use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::RuntimeBuilder;
pub use crate::test_logging::{
    ARTIFACT_SCHEMA_VERSION, AllocatedPort, DockerFixtureService, EnvironmentMetadata, FixtureLogs,
    FixtureService, InProcessService, NoOpFixtureService, PinnedProcessIdentity, PortAllocator,
    ProcessFixtureService, ProcessReadiness, ReproManifest, TempDirFixture, TestContext,
    TestEnvironment, derive_component_seed, derive_entropy_seed, derive_scenario_seed,
    wait_until_healthy,
};

pub use crate::test_ndjson::{
    NDJSON_SCHEMA_VERSION, NdjsonEvent, NdjsonLogger, artifact_base_dir, artifact_bundle_dir,
    ndjson_file_name, trace_file_name, write_artifact_bundle,
};
use crate::time::timeout;
use parking_lot::Mutex;
use std::future::Future;
use std::sync::{Arc, Once};
use std::time::Duration;
use tracing::Dispatch;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::FmtSpan;

static GLOBAL_INIT_LOGGING: Once = Once::new();
#[allow(dead_code)] // Used by other modules' #[cfg(test)] blocks via test-internals feature
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Default seed used by test lab helpers.
pub const DEFAULT_TEST_SEED: u64 = 0xDEAD_BEEF;
/// Deterministic fallback used when `RUST_LOG` is unset or malformed.
pub const DEFAULT_TEST_LOG_FILTER: &str = "warn,asupersync=debug";

/// Parsed logging policy for scoped test subscribers.
///
/// `from_env` accepts a wholly valid `RUST_LOG`. Invalid input fails
/// closed to [`DEFAULT_TEST_LOG_FILTER`] rather than being partially accepted.
/// Regex field matching is disabled so an ambient filter cannot introduce
/// regex compilation or surprising partial matches into a deterministic test.
#[derive(Clone, Debug)]
pub struct TestLogConfig {
    filter: EnvFilter,
    effective_filter: String,
    rust_log_fallback_reason: Option<RustLogFallbackReason>,
}

/// Error returned when an explicit test logging filter is invalid.
///
/// The display text is stable and bounded: it never includes the caller's raw
/// filter. [`Parse`](Self::Parse) retains the underlying parser error as its
/// source for callers that need structured diagnostics.
#[derive(Debug)]
pub enum TestLogConfigError {
    /// The supplied filter was empty or contained only whitespace.
    Empty,
    /// The supplied nonempty filter was not a valid `EnvFilter` directive set.
    Parse(tracing_subscriber::filter::ParseError),
}

impl std::fmt::Display for TestLogConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("test log filter must not be empty"),
            Self::Parse(_) => f.write_str("test log filter is invalid"),
        }
    }
}

impl std::error::Error for TestLogConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Empty => None,
            Self::Parse(error) => Some(error),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum RustLogFallbackReason {
    Empty,
    Parse,
    NonUnicode,
}

impl RustLogFallbackReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Parse => "parse",
            Self::NonUnicode => "non_unicode",
        }
    }
}

impl TestLogConfig {
    /// Build the deterministic safe default.
    #[must_use]
    pub fn safe_default() -> Self {
        Self::try_new(DEFAULT_TEST_LOG_FILTER)
            .expect("DEFAULT_TEST_LOG_FILTER must remain a valid EnvFilter")
    }

    /// Build an explicit filter, rejecting the entire value on any bad directive.
    ///
    /// The input is trimmed before parsing and storage. Empty or whitespace-only
    /// input returns [`TestLogConfigError::Empty`]; use
    /// [`with_test_logging_disabled`] when the intended policy is explicitly
    /// disabled logging.
    ///
    /// # Errors
    ///
    /// Returns [`TestLogConfigError::Empty`] for empty or whitespace-only input
    /// and [`TestLogConfigError::Parse`] for any other invalid directive set.
    pub fn try_new(filter: impl AsRef<str>) -> Result<Self, TestLogConfigError> {
        let filter = filter.as_ref().trim();
        if filter.is_empty() {
            return Err(TestLogConfigError::Empty);
        }
        let parsed = Self::filter_builder()
            .parse(filter)
            .map_err(TestLogConfigError::Parse)?;
        Ok(Self {
            filter: parsed,
            effective_filter: filter.to_string(),
            rust_log_fallback_reason: None,
        })
    }

    /// Read `RUST_LOG`, using the safe default when it is absent or invalid.
    ///
    /// An absent variable selects the safe default silently. Empty, malformed,
    /// or non-Unicode values select the same default and emit one bounded,
    /// redacted reason when the resulting policy is applied.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("RUST_LOG") {
            Ok(value) => match Self::try_new(&value) {
                Ok(config) => config,
                Err(TestLogConfigError::Empty) => {
                    Self::fallback_after_rust_log_error(RustLogFallbackReason::Empty)
                }
                Err(TestLogConfigError::Parse(_)) => {
                    Self::fallback_after_rust_log_error(RustLogFallbackReason::Parse)
                }
            },
            Err(std::env::VarError::NotPresent) => Self::safe_default(),
            Err(std::env::VarError::NotUnicode(_)) => {
                Self::fallback_after_rust_log_error(RustLogFallbackReason::NonUnicode)
            }
        }
    }

    /// Explicit all-target TRACE policy.
    ///
    /// This is deliberately opt-in. Runtime helpers never select it by default.
    #[must_use]
    pub fn trace() -> Self {
        Self::try_new("trace").expect("the TRACE directive must remain valid")
    }

    /// The filter that will actually be applied.
    #[must_use]
    pub fn effective_filter(&self) -> &str {
        &self.effective_filter
    }

    /// Whether an invalid present `RUST_LOG` forced the deterministic fallback.
    #[must_use]
    pub const fn used_rust_log_fallback(&self) -> bool {
        self.rust_log_fallback_reason.is_some()
    }

    fn filter_builder() -> tracing_subscriber::filter::Builder {
        EnvFilter::builder().with_regex(false)
    }

    fn fallback_after_rust_log_error(reason: RustLogFallbackReason) -> Self {
        let mut config = Self::safe_default();
        config.rust_log_fallback_reason = Some(reason);
        config
    }

    fn report_fallback(&self) {
        if let Some(reason) = self.rust_log_fallback_reason {
            tracing::warn!(
                target: "asupersync::test_utils",
                reason = reason.as_str(),
                fallback = DEFAULT_TEST_LOG_FILTER,
                "invalid RUST_LOG; using deterministic test logging fallback"
            );
        }
    }
}

impl Default for TestLogConfig {
    fn default() -> Self {
        Self::safe_default()
    }
}

fn test_dispatch<W>(config: &TestLogConfig, writer: W) -> Dispatch
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(config.filter.clone())
        .with_writer(writer)
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .with_thread_ids(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_ansi(false)
        .finish();
    Dispatch::new(subscriber)
}

/// Execute a closure under an explicitly configured scoped subscriber.
///
/// The prior dispatcher is restored even when `f` panics. This function never
/// modifies the process-global tracing subscriber or the global `log` logger.
pub fn with_test_logging<F, R>(config: &TestLogConfig, f: F) -> R
where
    F: FnOnce() -> R,
{
    let dispatch = test_dispatch(config, tracing_subscriber::fmt::writer::TestWriter::new());
    tracing::dispatcher::with_default(&dispatch, || {
        config.report_fallback();
        f()
    })
}

/// Execute a closure with tracing explicitly disabled for the current thread.
///
/// This installs a real scoped subscriber with the `off` filter, so runtime
/// helpers preserve the policy instead of mistaking it for ambient subscriber
/// absence. A nested [`with_test_logging`] scope can explicitly re-enable
/// logging. The prior dispatcher is restored on normal return and panic, and no
/// process-global tracing subscriber or `log` logger is modified.
///
/// The scope is synchronous and thread-local. If `f` merely returns a future,
/// that future is polled after this function has restored the prior dispatcher.
/// Drive asynchronous work inside the closure instead:
///
/// ```
/// use asupersync::test_utils::{run_test, with_test_logging_disabled};
///
/// with_test_logging_disabled(|| {
///     run_test(|| async {
///         tracing::info!("suppressed");
///     });
/// });
/// ```
pub fn with_test_logging_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let config = TestLogConfig::try_new("off").expect("the OFF directive must remain valid");
    with_test_logging(&config, f)
}

fn with_default_test_logging<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // `NoSubscriber` is tracing's ambient-absence sentinel, so raw use cannot
    // communicate an explicit disabled policy. Callers that require OFF
    // authority must use `with_test_logging_disabled`, whose concrete scoped
    // subscriber is preserved by this check.
    let current_dispatch_is_noop = tracing::dispatcher::get_default(|dispatch| {
        dispatch.is::<tracing::subscriber::NoSubscriber>()
    });
    if current_dispatch_is_noop {
        with_test_logging(&TestLogConfig::from_env(), f)
    } else {
        f()
    }
}

/// Install a process-global test subscriber.
///
/// This is an irreversible, explicitly global opt-in for legacy tests that
/// cannot yet use [`with_test_logging`]. It never installs a `log` bridge.
/// Prefer scoped logging for all new tests.
pub fn install_global_test_subscriber(
    config: &TestLogConfig,
) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    let dispatch = test_dispatch(config, tracing_subscriber::fmt::writer::TestWriter::new());
    tracing::dispatcher::set_global_default(dispatch)?;
    config.report_fallback();
    Ok(())
}

/// Irreversibly bridge global `log` records into the active tracing dispatcher.
///
/// Runtime helpers intentionally do not call this. Consumers must opt in when
/// diagnosing a dependency that emits through `log`, and should do so only in
/// a fresh test process because the global logger cannot be uninstalled.
pub fn install_global_test_log_bridge() -> Result<(), tracing_log::log::SetLoggerError> {
    tracing_log::LogTracer::init()
}

/// Runtime-isolated subscriber handle for per-runtime tracing.
///
/// **CRITICAL**: This fixes the global subscriber conflict where multiple
/// runtimes in the same process would interfere with each other's tracing.
/// Each runtime gets its own isolated subscriber instead of sharing global state.
#[derive(Debug, Clone)]
pub struct RuntimeSubscriberHandle {
    _dispatch: Arc<Dispatch>,
    #[allow(dead_code)]
    runtime_id: String,
}

impl RuntimeSubscriberHandle {
    /// Create a per-runtime subscriber with isolation from other runtimes.
    ///
    /// **SECURITY FIX**: This prevents global subscriber state conflicts
    /// where the second runtime would lose tracing output due to the
    /// Once guard in the old implementation.
    pub fn new_isolated(runtime_id: String, level: tracing::Level) -> Self {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_test_writer()
            .with_file(true)
            .with_line_number(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_span_events(FmtSpan::CLOSE)
            .with_ansi(false)
            .finish();

        let dispatch = Arc::new(Dispatch::new(subscriber));

        Self {
            _dispatch: dispatch,
            runtime_id,
        }
    }

    /// Execute a closure with this runtime's subscriber as the default.
    ///
    /// **ISOLATION**: Tracing events within the closure use this runtime's
    /// subscriber, regardless of global subscriber state.
    pub fn with_subscriber<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        tracing::dispatcher::with_default(&*self._dispatch, f)
    }
}

/// Initialize legacy process-global test logging with a safe filter.
///
/// This explicit legacy opt-in is retained while older test modules migrate to
/// [`with_test_logging`]. It does not install `LogTracer`, and it honors a
/// wholly valid `RUST_LOG`; otherwise it uses [`DEFAULT_TEST_LOG_FILTER`].
///
/// Safe to call multiple times; only initializes once per process.
pub fn init_test_logging() {
    GLOBAL_INIT_LOGGING.call_once(|| {
        let _existing_global_is_preserved =
            install_global_test_subscriber(&TestLogConfig::from_env());
    });
}

/// Initialize legacy process-global test logging with an explicit level.
///
/// This is an explicit global opt-in. Prefer [`with_test_logging`] with an
/// explicit [`TestLogConfig`] for deterministic scoped behavior.
pub fn init_test_logging_with_level(level: tracing::Level) {
    GLOBAL_INIT_LOGGING.call_once(|| {
        let config = TestLogConfig::try_new(level.as_str())
            .expect("tracing::Level must map to a valid EnvFilter directive");
        let _existing_global_is_preserved = install_global_test_subscriber(&config);
    });
}

/// Initialize per-runtime logging with trace-level output.
///
/// **RECOMMENDED**: Use this for new test code that needs runtime isolation.
/// Returns a handle that can be used to execute code with this runtime's
/// subscriber active.
///
/// **SAFETY**: Each runtime gets its own isolated subscriber, preventing
/// global subscriber conflicts that break tracing for subsequent runtimes.
pub fn init_runtime_logging(runtime_id: String) -> RuntimeSubscriberHandle {
    init_runtime_logging_with_level(runtime_id, tracing::Level::TRACE)
}

/// Initialize per-runtime logging with a custom level.
///
/// **ISOLATION**: Creates a completely isolated subscriber for this runtime.
/// Multiple runtimes can coexist without interfering with each other's
/// tracing output.
pub fn init_runtime_logging_with_level(
    runtime_id: String,
    level: tracing::Level,
) -> RuntimeSubscriberHandle {
    RuntimeSubscriberHandle::new_isolated(runtime_id, level)
}

/// Acquire the global environment lock for tests that mutate env vars.
#[allow(dead_code)] // Used by other modules' #[cfg(test)] blocks
pub(crate) fn env_lock() -> parking_lot::MutexGuard<'static, ()> {
    ENV_LOCK.lock()
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

/// Create a lab runtime and hand it to a closure for deterministic execution.
///
/// This is the escape hatch for tests that need direct control over a [`LabRuntime`].
/// Callers can configure the runtime, drive it with
/// [`crate::conformance::ConformanceTarget::block_on`], or step it manually.
pub fn lab_with_config<F, R>(f: F) -> R
where
    F: FnOnce(&mut LabRuntime) -> R,
{
    with_default_test_logging(|| {
        let mut lab = test_lab();
        f(&mut lab)
    })
}

/// Create a [`TestContext`] for a unit test with the default seed.
#[must_use]
pub fn test_context(test_id: &str) -> TestContext {
    TestContext::new(test_id, DEFAULT_TEST_SEED)
}

/// Create a [`TestContext`] for a unit test with a specific seed.
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
    with_default_test_logging(|| {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("failed to build test runtime");
        runtime.block_on(f());
    });
}

/// Run async test code with a test `Cx`.
pub fn run_test_with_cx<F, Fut>(f: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    with_default_test_logging(|| {
        let cx: Cx = Cx::for_testing();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("failed to build test runtime");
        runtime.block_on(f(cx));
    });
}

/// Assert that an async operation completes within a timeout.
pub async fn assert_completes_within<F, Fut, T>(
    timeout_duration: Duration,
    description: &str,
    f: F,
) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T> + Unpin,
{
    // Keep standalone usage correct: `TimeoutFuture` uses `Sleep`, whose fallback clock is
    // `wall_now()`. Passing `Time::ZERO` here can cause immediate timeouts if `wall_now()`
    // has already advanced earlier in the process.
    let now = Cx::current()
        .and_then(|cx| cx.timer_driver())
        .map_or_else(crate::time::wall_now, |driver| driver.now());

    let Ok(value) = timeout(now, timeout_duration, f()).await else {
        unreachable!("operation '{description}' did not complete within {timeout_duration:?}");
    };
    tracing::debug!(
        description = %description,
        timeout_ms = timeout_duration.as_millis(),
        "operation completed within timeout"
    );
    value
}

#[cfg(test)]
#[path = "test_utils_inline_tests.rs"]
mod tests;

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
    ($cond:expr, $msg:expr, $expected:expr, $actual:expr) => {{
        tracing::debug!(
            expected = ?$expected,
            actual = ?$actual,
            "Asserting: {}",
            $msg
        );
        assert!($cond, "{}: expected {:?}, got {:?}", $msg, $expected, $actual);
    }};
}

/// Assert that an outcome is Ok with a specific value.
#[macro_export]
macro_rules! assert_outcome_ok {
    ($outcome:expr, $expected:expr) => {
        match $outcome {
            $crate::types::Outcome::Ok(v) => assert_eq!(v, $expected),
            other => unreachable!("expected Outcome::Ok({:?}), got {:?}", $expected, other),
        }
    };
}

/// Assert that an outcome is Cancelled.
#[macro_export]
macro_rules! assert_outcome_cancelled {
    ($outcome:expr) => {
        match $outcome {
            $crate::types::Outcome::Cancelled(_) => {}
            other => unreachable!("expected Outcome::Cancelled, got {:?}", other),
        }
    };
}

/// Assert that an outcome is Err.
#[macro_export]
macro_rules! assert_outcome_err {
    ($outcome:expr) => {
        match $outcome {
            $crate::types::Outcome::Err(_) => {}
            other => unreachable!("expected Outcome::Err, got {:?}", other),
        }
    };
}

/// Assert that an outcome is Panicked.
#[macro_export]
macro_rules! assert_outcome_panicked {
    ($outcome:expr) => {
        match $outcome {
            $crate::types::Outcome::Panicked(_) => {}
            other => unreachable!("expected Outcome::Panicked, got {:?}", other),
        }
    };
}

/// Deterministic in-memory connection for pool testing.
#[derive(Debug)]
pub struct TestConnection {
    id: usize,
    query_count: std::sync::atomic::AtomicUsize,
}

impl TestConnection {
    /// Create a new test connection with a stable ID.
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
    pub fn query(&self, _sql: &str) -> Result<(), TestError> {
        self.query_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Test error for pool testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestError(pub String);

impl std::error::Error for TestError {}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestError: {}", self.0)
    }
}

// ============================================================================
// Evidence Logging for Structured Test Analysis
// ============================================================================

use crate::test_logging::{TestEvent, TestLogLevel};
use std::path::PathBuf;

/// Evidence sink for capturing structured JSON events during test execution.
///
/// Automatically writes test events to `tests/_evidence/<test_name>.jsonl`
/// for post-hoc analysis, flake pattern detection, and regression tracking.
///
/// # Example
/// ```
/// use asupersync::test_utils::EvidenceSink;
///
/// let mut evidence = EvidenceSink::for_test("my_test");
/// evidence.phase("setup");
/// evidence.event("task_spawn", &[("task_id", "1"), ("name", "worker")]);
/// evidence.outcome("passed");
/// evidence.save().unwrap();
/// ```
pub struct EvidenceSink {
    logger: NdjsonLogger,
    test_name: String,
    current_phase: String,
}

impl EvidenceSink {
    /// Create a new evidence sink for the given test.
    ///
    /// Uses a default seed and subsystem. Call `with_context()` for custom configuration.
    pub fn for_test(test_name: &str) -> Self {
        let ctx = TestContext::new(test_name, DEFAULT_TEST_SEED);
        let logger = NdjsonLogger::enabled(TestLogLevel::Debug, Some(ctx));

        Self {
            logger,
            test_name: test_name.to_string(),
            current_phase: "init".to_string(),
        }
    }

    /// Create evidence sink with custom test context.
    pub fn with_context(test_name: &str, ctx: TestContext) -> Self {
        let logger = NdjsonLogger::enabled(TestLogLevel::Debug, Some(ctx));

        Self {
            logger,
            test_name: test_name.to_string(),
            current_phase: "init".to_string(),
        }
    }

    /// Record a test phase transition.
    ///
    /// Phase examples: "setup", "execution", "teardown", "validation"
    pub fn phase(&mut self, phase: &str) {
        self.current_phase = phase.to_string();
        self.logger.log(TestEvent::Custom {
            category: "test",
            message: format!(
                "phase_transition: phase={} test_name={}",
                phase, self.test_name
            ),
        });
    }

    /// Record a structured event with key-value data.
    ///
    /// Event examples: "task_spawn", "region_close", "obligation_leak", "cancel_request"
    pub fn event(&self, event: &str, data: &[(&str, &str)]) {
        let data_str = data
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .chain(std::iter::once(format!("phase={}", self.current_phase)))
            .chain(std::iter::once(format!("test_name={}", self.test_name)))
            .collect::<Vec<_>>()
            .join(" ");

        self.logger.log(TestEvent::Custom {
            category: "evidence",
            message: format!("{}: {}", event, data_str),
        });
    }

    /// Record test outcome: "passed", "failed", "skipped", or "error".
    pub fn outcome(&self, outcome: &str) {
        self.logger.log(TestEvent::Custom {
            category: "test",
            message: format!(
                "outcome: outcome={} test_name={} final_phase={}",
                outcome, self.test_name, self.current_phase
            ),
        });
    }

    /// Record a context ID from the async runtime.
    ///
    /// Useful for correlating events with specific execution contexts.
    pub fn cx_id(&self, cx_id: &str) {
        self.logger.log(TestEvent::Custom {
            category: "runtime",
            message: format!(
                "cx_active: cx_id={} phase={} test_name={}",
                cx_id, self.current_phase, self.test_name
            ),
        });
    }

    /// Save evidence to `tests/_evidence/<test_name>.jsonl`.
    ///
    /// Creates the evidence directory if it doesn't exist.
    pub fn save(&self) -> std::io::Result<PathBuf> {
        let evidence_dir = std::path::Path::new("tests/_evidence");
        std::fs::create_dir_all(evidence_dir)?;

        let file_path = evidence_dir.join(format!("{}.jsonl", self.test_name));
        self.logger.write_ndjson_file(&file_path)?;
        Ok(file_path)
    }

    /// Access the underlying NDJSON logger for advanced usage.
    pub fn logger(&self) -> &NdjsonLogger {
        &self.logger
    }
}

/// Enhanced test phase macro that automatically logs to evidence.
///
/// Usage: `evidence_phase!(evidence_sink, "setup");`
#[macro_export]
macro_rules! evidence_phase {
    ($sink:expr, $phase:expr) => {
        $sink.phase($phase);
        tracing::info!(phase = %$phase, "TEST PHASE: {}", $phase);
    };
}

/// Helper to create and configure evidence sink for LabRuntime tests.
///
/// Integrates with the existing lab runtime helpers while adding structured logging.
pub fn lab_with_evidence<F, T>(test_name: &str, f: F) -> (T, EvidenceSink)
where
    F: FnOnce(&LabRuntime, &mut EvidenceSink) -> T,
{
    let mut evidence = EvidenceSink::for_test(test_name);
    evidence.phase("lab_setup");

    let result = lab_with_config(|runtime| {
        evidence.event(
            "lab_start",
            &[
                ("seed", &runtime.config().seed.to_string()),
                ("deterministic", "true"),
            ],
        );

        let result = f(runtime, &mut evidence);

        evidence.phase("lab_complete");
        result
    });

    evidence.outcome("passed");
    (result, evidence)
}
