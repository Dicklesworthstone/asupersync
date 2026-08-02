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
/// [`crate::conformance::LabRuntimeTarget::block_on`], or step it manually.
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget};
    use futures_lite::future;
    use std::ffi::OsStr;
    #[cfg(any(unix, windows))]
    use std::ffi::OsString;
    use std::io::{self, Write};
    use std::process::{Command, Output};
    use std::sync::mpsc;
    use std::time::Duration;

    const LOGGING_CHILD_CASE_ENV: &str = "ASUPERSYNC_LOGGING_CHILD_CASE";
    const LOGGING_CHILD_TEST: &str = "test_utils::tests::logging_fresh_process_child";
    const ASUPERSYNC_DEBUG_MARKER: &str = "ASUPERSYNC_DEBUG_MARKER_7MF9BT";
    const TOKENIZERS_TRACE_MARKER: &str = "TOKENIZERS_TRACE_MARKER_7MF9BT";
    const TOKENIZERS_LOG_MARKER: &str = "TOKENIZERS_LOG_MARKER_7MF9BT";
    const FALLBACK_MARKER: &str = "invalid RUST_LOG; using deterministic test logging fallback";
    const RAW_RUN_TEST_MARKER: &str = "RAW_NO_SUBSCRIBER_RUN_TEST_MARKER_OE2RHS";
    const RAW_RUN_TEST_WITH_CX_MARKER: &str = "RAW_NO_SUBSCRIBER_RUN_TEST_WITH_CX_MARKER_OE2RHS";
    const RAW_LAB_MARKER: &str = "RAW_NO_SUBSCRIBER_LAB_MARKER_OE2RHS";
    const OFF_AFTER_NESTED_MARKER: &str = "OFF_AFTER_NESTED_MARKER_OE2RHS";
    const UNPROPAGATED_DEFAULT_MARKER: &str = "UNPROPAGATED_DEFAULT_MARKER_OE2RHS";
    const PROPAGATED_OFF_MARKER: &str = "PROPAGATED_OFF_MARKER_OE2RHS";
    const LOGGING_GIT_REVISION_ENV: &str = "ASUPERSYNC_LOGGING_GIT_REVISION";
    const LOGGING_STRICT_RECEIPT_ENV: &str = "ASUPERSYNC_LOGGING_STRICT_RECEIPT";

    #[derive(Clone, Default)]
    struct CaptureWriter {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    struct CaptureGuard {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl CaptureWriter {
        fn text(&self) -> String {
            let bytes = self.bytes.lock().expect("capture mutex was poisoned");
            String::from_utf8(bytes.clone()).expect("tracing output must be UTF-8")
        }

        fn len(&self) -> usize {
            self.bytes.lock().expect("capture mutex was poisoned").len()
        }
    }

    impl Write for CaptureGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("capture mutex was poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CaptureWriter {
        type Writer = CaptureGuard;

        fn make_writer(&'writer self) -> Self::Writer {
            CaptureGuard {
                bytes: Arc::clone(&self.bytes),
            }
        }
    }

    fn capture_dispatch(filter: &str) -> (Dispatch, CaptureWriter) {
        let writer = CaptureWriter::default();
        let config = TestLogConfig::try_new(filter).expect("test filter must be valid");
        (test_dispatch(&config, writer.clone()), writer)
    }

    fn emit_filter_probe_events() {
        tracing::debug!(
            target: "asupersync::logging_contract",
            "{ASUPERSYNC_DEBUG_MARKER}"
        );
        tracing::trace!(
            target: "tokenizers::normalizer",
            "{TOKENIZERS_TRACE_MARKER}"
        );
        tracing_log::log::trace!(
            target: "tokenizers::normalizer",
            "{TOKENIZERS_LOG_MARKER}"
        );
    }

    fn combined_output(output: &Output) -> String {
        let mut bytes = output.stdout.clone();
        bytes.extend_from_slice(&output.stderr);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn active_logging_features() -> Vec<&'static str> {
        macro_rules! feature_states {
            ($($feature:literal),+ $(,)?) => {
                [$(($feature, cfg!(feature = $feature))),+]
            };
        }

        feature_states![
            "default",
            "nightly-outcome-try",
            "messaging-fabric",
            "waker-profiling",
            "runtime-metrics",
            "wasm-browser-preview",
            "wasm-runtime",
            "browser-io",
            "browser-trace",
            "deterministic-mode",
            "native-runtime",
            "wasm-browser-dev",
            "wasm-browser-prod",
            "wasm-browser-deterministic",
            "wasm-browser-minimal",
            "test-internals",
            "legacy-internal-test-harnesses",
            "serialization-golden-harnesses",
            "real-service-e2e",
            "channel-mpsc-select-e2e",
            "h3-websocket-e2e",
            "raptorq-roundtrip-e2e",
            "obligation-cleanup-e2e",
            "metrics",
            "tracing-integration",
            "proc-macros",
            "tower",
            "trace-compression",
            "debug-server",
            "config-file",
            "dependency-ledger",
            "lock-metrics",
            "obligation-leak-detection",
            "io-uring",
            "tls",
            "tls-native-roots",
            "tls-webpki-roots",
            "cli",
            "atp-cli",
            "sqlite",
            "postgres",
            "mysql",
            "quic",
            "http3",
            "tailscale-path-provider",
            "tokio-compat",
            "kafka",
            "ci-cross-platform",
            "compression",
            "simd-intrinsics",
            "loom-tests",
            "cancel-correctness-oracle",
            "lab-stack-traces",
            "benchmark-adapters",
            "criterion-benches",
            "atpd-daemon",
            "fuzz",
        ]
        .into_iter()
        .filter_map(|(feature, active)| active.then_some(feature))
        .collect()
    }

    fn logging_profile() -> &'static str {
        if cfg!(debug_assertions) {
            "test-debug-assertions"
        } else {
            "test-no-debug-assertions"
        }
    }

    fn valid_git_revision(value: &str) -> Option<&str> {
        let value = value.trim();
        (value.len() >= 7
            && value.len() <= 64
            && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(value)
    }

    fn repository_git_revision() -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(env!("CARGO_MANIFEST_DIR"))
            .args(["rev-parse", "--verify", "HEAD"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let value = std::str::from_utf8(&output.stdout).ok()?;
        valid_git_revision(value).map(str::to_string)
    }

    fn logging_git_revision() -> &'static str {
        static REVISION: std::sync::OnceLock<String> = std::sync::OnceLock::new();

        REVISION
            .get_or_init(|| {
                let repository_revision = repository_git_revision();
                let strict_receipt = match std::env::var(LOGGING_STRICT_RECEIPT_ENV) {
                    Ok(value) => {
                        assert_eq!(value, "1", "strict logging receipt flag must equal 1");
                        true
                    }
                    Err(std::env::VarError::NotPresent) => false,
                    Err(std::env::VarError::NotUnicode(_)) => {
                        panic!("strict logging receipt flag must be Unicode")
                    }
                };
                match std::env::var(LOGGING_GIT_REVISION_ENV) {
                    Ok(value) => {
                        let requested = valid_git_revision(&value)
                            .expect("logging git revision override must be a hexadecimal revision");
                        if let Some(repository_revision) = &repository_revision {
                            assert_eq!(
                                requested, repository_revision,
                                "logging git revision override does not match checked-out HEAD"
                            );
                        }
                        requested.to_string()
                    }
                    Err(std::env::VarError::NotPresent) => {
                        if strict_receipt {
                            panic!(
                                "strict logging receipt requires an explicit hexadecimal git revision"
                            );
                        }
                        repository_revision.unwrap_or_else(|| "unavailable".to_string())
                    }
                    Err(std::env::VarError::NotUnicode(_)) => {
                        panic!("logging git revision override must be Unicode")
                    }
                }
            })
            .as_str()
    }

    fn logging_replay_command(git_revision: &str, features: &[&str]) -> String {
        let default_active = features.contains(&"default");
        let explicit_features = features
            .iter()
            .copied()
            .filter(|feature| *feature != "default")
            .collect::<Vec<_>>()
            .join(",");

        let mut feature_args = if default_active {
            String::new()
        } else {
            " --no-default-features".to_string()
        };
        if !explicit_features.is_empty() {
            feature_args.push_str(" --features ");
            feature_args.push_str(&explicit_features);
        }
        let profile_arg = if cfg!(debug_assertions) {
            ""
        } else {
            " --release"
        };

        format!(
            "RCH_REQUIRE_REMOTE=1 rch exec --base {git_revision} --clean-overlay --no-overlay -- env CARGO_TARGET_DIR=\"${{RCH_TARGET_BASE:-${{TMPDIR:-/tmp}}}}/rch_target_test_log_empty_off_receipt\" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' {LOGGING_STRICT_RECEIPT_ENV}=1 {LOGGING_GIT_REVISION_ENV}={git_revision} cargo test -p asupersync --lib{profile_arg}{feature_args} test_utils::tests::logging_fresh_process_contract_matrix -- --exact --nocapture --test-threads=1"
        )
    }

    fn logging_filter_classification(case: &str) -> &'static str {
        match case {
            "unset-rust-log" => "safe-default-absent",
            "valid-rust-log" => "explicit-valid",
            "empty-rust-log" => "safe-default-invalid-empty",
            "malformed-rust-log" => "safe-default-invalid-parse",
            "non-unicode-rust-log" => "safe-default-invalid-non-unicode",
            "explicit-off" => "explicit-off",
            "raw-no-subscriber" => "ambient-no-subscriber",
            "off-nested-enabled" => "explicit-off-with-explicit-inner",
            "thread-propagation" => "mixed-thread-propagation",
            "public-global-subscriber" => "explicit-global",
            "explicit-log-bridge" => "explicit-global-log-bridge",
            "globals-untouched" | "preexisting-global" | "panic-restoration" => "ambient-contract",
            _ => "unknown",
        }
    }

    fn byte_line_count(bytes: &[u8]) -> usize {
        bytes.iter().filter(|byte| **byte == b'\n').count()
            + usize::from(bytes.last().is_some_and(|byte| *byte != b'\n'))
    }

    fn observed_output_marker_occurrences(text: &str) -> usize {
        [
            ASUPERSYNC_DEBUG_MARKER,
            TOKENIZERS_TRACE_MARKER,
            TOKENIZERS_LOG_MARKER,
            RAW_RUN_TEST_MARKER,
            RAW_RUN_TEST_WITH_CX_MARKER,
            RAW_LAB_MARKER,
            OFF_AFTER_NESTED_MARKER,
            UNPROPAGATED_DEFAULT_MARKER,
            PROPAGATED_OFF_MARKER,
        ]
        .into_iter()
        .map(|marker| text.matches(marker).count())
        .sum()
    }

    fn run_logging_child(case: &str, rust_log: Option<&OsStr>) -> Output {
        let mut command = Command::new(
            std::env::current_exe().expect("current test executable must be available"),
        );
        command
            .arg(LOGGING_CHILD_TEST)
            .arg("--exact")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(LOGGING_CHILD_CASE_ENV, case)
            .env_remove("RUST_LOG");
        if let Some(rust_log) = rust_log {
            command.env("RUST_LOG", rust_log);
        }
        command
            .output()
            .expect("fresh-process logging test failed to launch")
    }

    #[cfg(unix)]
    fn non_unicode_rust_log() -> OsString {
        use std::os::unix::ffi::OsStringExt;

        OsString::from_vec(b"secret-prefix-\xff-secret-suffix".to_vec())
    }

    #[cfg(windows)]
    fn non_unicode_rust_log() -> OsString {
        use std::os::windows::ffi::OsStringExt;

        OsString::from_wide(&[
            b's' as u16,
            b'e' as u16,
            b'c' as u16,
            b'r' as u16,
            b'e' as u16,
            b't' as u16,
            0xD800,
        ])
    }

    fn assert_child_passed(case: &str, output: &Output) -> String {
        let text = combined_output(output);
        let features = active_logging_features();
        let features_text = if features.is_empty() {
            "none".to_string()
        } else {
            features.join(",")
        };
        let git_revision = logging_git_revision();
        let replay_command = logging_replay_command(git_revision, &features);
        let exit_status = output.status.code().unwrap_or(-1);
        let line_count = byte_line_count(&output.stdout) + byte_line_count(&output.stderr);
        let byte_count = output.stdout.len() + output.stderr.len();
        let output_marker_count = observed_output_marker_occurrences(&text);

        eprintln!(
            "ASUPERSYNC_LOGGING_RECEIPT case={case:?} git_revision={git_revision:?} features={features_text:?} profile={:?} filter_classification={:?} exit_status={exit_status} line_count={line_count} byte_count={byte_count} observed_output_marker_occurrences={output_marker_count} capture_scope=\"child-stdout-stderr-probe-markers\" replay_command={replay_command:?}",
            logging_profile(),
            logging_filter_classification(case),
        );
        assert!(
            output.status.success(),
            "fresh-process logging case {case:?} failed with {:?}:\n{text}",
            output.status.code()
        );
        assert!(
            line_count < 10_000,
            "fresh-process logging case {case:?} exceeded the line cap"
        );
        assert!(
            byte_count < 8 * 1024 * 1024,
            "fresh-process logging case {case:?} exceeded the byte cap"
        );
        if case == "explicit-off" {
            assert_eq!(
                output_marker_count, 0,
                "explicit OFF emitted probe records to child output:\n{text}"
            );
        }
        text
    }

    fn release_logging_workers(
        ready: &mpsc::Receiver<&'static str>,
        expected: [&'static str; 2],
        go: [mpsc::Sender<()>; 2],
    ) {
        let mut observed = Vec::with_capacity(2);
        for _ in 0..2 {
            observed.push(
                ready
                    .recv_timeout(Duration::from_secs(10))
                    .expect("logging worker did not reach the overlap gate"),
            );
        }
        for worker in expected {
            assert!(
                observed.contains(&worker),
                "logging worker {worker:?} did not reach the overlap gate: {observed:?}"
            );
        }
        for sender in go {
            sender
                .send(())
                .expect("logging worker exited before overlap release");
        }
    }

    fn assert_single_fallback(case: &str, text: &str, reason: &str) {
        assert_eq!(
            text.matches(FALLBACK_MARKER).count(),
            1,
            "fresh-process logging case {case:?} must emit one fallback diagnostic:\n{text}"
        );
        let diagnostic = text
            .lines()
            .find(|line| line.contains(FALLBACK_MARKER))
            .expect("fallback diagnostic line must exist");
        assert!(
            diagnostic.len() < 512,
            "fallback diagnostic must remain bounded: {diagnostic:?}"
        );
        assert!(
            diagnostic.contains(reason),
            "fallback diagnostic omitted reason {reason:?}: {diagnostic:?}"
        );
        assert!(
            text.contains(ASUPERSYNC_DEBUG_MARKER),
            "fallback did not apply the safe default:\n{text}"
        );
        assert!(
            !text.contains(TOKENIZERS_TRACE_MARKER),
            "fallback admitted third-party TRACE:\n{text}"
        );
    }

    #[test]
    fn test_log_config_rejects_empty_and_preserves_typed_parse_source() {
        for filter in ["", " ", "\n\t "] {
            let error = TestLogConfig::try_new(filter).expect_err("empty filter must fail");
            assert!(matches!(&error, TestLogConfigError::Empty));
            assert_eq!(error.to_string(), "test log filter must not be empty");
            assert!(std::error::Error::source(&error).is_none());
        }

        let raw = format!("asupersync=not-a-level,{}", "secret".repeat(1024));
        let error = TestLogConfig::try_new(&raw).expect_err("malformed filter must fail");
        assert!(matches!(&error, TestLogConfigError::Parse(_)));
        assert_eq!(error.to_string(), "test log filter is invalid");
        assert!(std::error::Error::source(&error).is_some());
        assert!(!error.to_string().contains("secret"));
        assert!(error.to_string().len() < 64);

        let mut source = std::error::Error::source(&error);
        while let Some(current) = source {
            let rendered = current.to_string();
            assert!(!rendered.contains("secret"));
            assert!(rendered.len() < 512, "unbounded error source: {rendered:?}");
            source = current.source();
        }
    }

    #[test]
    fn test_log_config_accepts_trimmed_nonempty_policies() {
        for (input, expected) in [
            (" off ", "off"),
            ("error", "error"),
            ("warn", "warn"),
            ("my_crate=debug", "my_crate=debug"),
            ("trace", "trace"),
        ] {
            let config = TestLogConfig::try_new(input).expect("policy must be valid");
            assert_eq!(config.effective_filter(), expected);
            assert!(!config.used_rust_log_fallback());
        }
    }

    // Bead: asupersync-7mf9bt
    // Scenario: an ambient scoped dispatcher must remain authoritative before,
    // during future polling, during LabRuntime construction, and afterward.
    // Seed: DEFAULT_TEST_SEED.
    // Artifact: the in-memory capture is asserted for every lifecycle marker.
    #[test]
    fn logging_helpers_preserve_existing_scoped_dispatcher() {
        let (dispatch, writer) = capture_dispatch("trace");

        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "asupersync::logging_contract", "scoped-before");
            run_test(|| async {
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "scoped-run-test-polled"
                );
            });
            run_test_with_cx(|_cx| async {
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "scoped-run-test-with-cx-polled"
                );
            });
            lab_with_config(|_lab| {
                tracing::info!(target: "asupersync::logging_contract", "scoped-lab");
            });
            tracing::info!(target: "asupersync::logging_contract", "scoped-after");
        });

        let text = writer.text();
        for marker in [
            "scoped-before",
            "scoped-run-test-polled",
            "scoped-run-test-with-cx-polled",
            "scoped-lab",
            "scoped-after",
        ] {
            assert!(text.contains(marker), "missing {marker:?} in:\n{text}");
        }
    }

    // Bead: asupersync-test-log-empty-off-authority-oe2rhs
    // Scenario: explicit OFF authority covers runtime construction, future
    // polling, cancellation-by-drop, helper cleanup, and dispatcher restoration.
    #[test]
    fn logging_disabled_scope_covers_runtime_lifecycle_and_restores() {
        struct PendingTraceFuture;

        impl Future for PendingTraceFuture {
            type Output = ();

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "off-pending-future-polled"
                );
                std::task::Poll::Pending
            }
        }

        impl Drop for PendingTraceFuture {
            fn drop(&mut self) {
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "off-pending-future-dropped"
                );
            }
        }

        let (outer_dispatch, outer_writer) = capture_dispatch("trace");
        tracing::dispatcher::with_default(&outer_dispatch, || {
            tracing::info!(target: "asupersync::logging_contract", "off-outer-before");
            let bytes_before_off = outer_writer.len();

            let value = with_test_logging_disabled(|| {
                assert!(tracing::dispatcher::get_default(|dispatch| {
                    !dispatch.is::<tracing::subscriber::NoSubscriber>()
                }));
                assert!(!tracing::enabled!(
                    target: "asupersync::logging_contract",
                    tracing::Level::TRACE
                ));
                tracing::info!(target: "asupersync::logging_contract", "off-direct");

                run_test(|| async {
                    tracing::info!(target: "asupersync::logging_contract", "off-run-test");
                });
                run_test_with_cx(|_cx| async {
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "off-run-test-with-cx"
                    );

                    let mut pending = std::pin::pin!(PendingTraceFuture);
                    let waker = std::task::Waker::noop();
                    let mut task_cx = std::task::Context::from_waker(waker);
                    assert!(pending.as_mut().poll(&mut task_cx).is_pending());
                });
                lab_with_config(|_lab| {
                    tracing::info!(target: "asupersync::logging_contract", "off-lab");
                });
                42
            });

            assert_eq!(value, 42);
            assert_eq!(
                outer_writer.len(),
                bytes_before_off,
                "the outer sink received records from the OFF scope"
            );

            let explicitly_enabled = with_test_logging_disabled(|| {
                let explicitly_enabled = with_test_logging(&TestLogConfig::trace(), || {
                    tracing::enabled!(
                        target: "asupersync::logging_contract",
                        tracing::Level::TRACE
                    )
                });
                assert!(!tracing::enabled!(
                    target: "asupersync::logging_contract",
                    tracing::Level::TRACE
                ));
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "{OFF_AFTER_NESTED_MARKER}"
                );
                explicitly_enabled
            });
            assert!(
                explicitly_enabled,
                "an explicit inner policy must override OFF"
            );

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                with_test_logging_disabled(|| panic!("OFF restoration probe"));
            }));
            assert!(panic.is_err());
            tracing::info!(target: "asupersync::logging_contract", "off-outer-after");
        });

        let text = outer_writer.text();
        assert!(text.contains("off-outer-before"));
        assert!(text.contains("off-outer-after"));
        for marker in [
            "off-direct",
            "off-run-test",
            "off-run-test-with-cx",
            "off-pending-future-polled",
            "off-pending-future-dropped",
            "off-lab",
            OFF_AFTER_NESTED_MARKER,
        ] {
            assert!(
                !text.contains(marker),
                "OFF leaked {marker:?} into:\n{text}"
            );
        }
    }

    // Bead: asupersync-test-log-empty-off-authority-oe2rhs
    // Scenario: explicit per-thread enabled and OFF dispatchers remain isolated.
    #[test]
    fn logging_enabled_and_disabled_threads_do_not_cross_contaminate() {
        let (enabled_dispatch, enabled_writer) = capture_dispatch("trace");
        let (disabled_dispatch, disabled_writer) = capture_dispatch("off");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (enabled_go_tx, enabled_go_rx) = mpsc::channel();
        let (disabled_go_tx, disabled_go_rx) = mpsc::channel();

        let enabled_ready = ready_tx.clone();
        let enabled = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&enabled_dispatch, || {
                run_test(|| async move {
                    enabled_ready
                        .send("enabled")
                        .expect("enabled worker could not report readiness");
                    enabled_go_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("enabled worker was not released");
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "enabled-thread-marker"
                    );
                });
            });
        });

        let disabled_ready = ready_tx;
        let disabled = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&disabled_dispatch, || {
                run_test(|| async move {
                    disabled_ready
                        .send("disabled")
                        .expect("disabled worker could not report readiness");
                    disabled_go_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("disabled worker was not released");
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "disabled-thread-marker"
                    );
                });
            });
        });

        release_logging_workers(
            &ready_rx,
            ["enabled", "disabled"],
            [enabled_go_tx, disabled_go_tx],
        );

        enabled.join().expect("enabled logging thread panicked");
        disabled.join().expect("disabled logging thread panicked");

        let enabled_text = enabled_writer.text();
        assert!(enabled_text.contains("enabled-thread-marker"));
        assert!(!enabled_text.contains("disabled-thread-marker"));
        assert_eq!(disabled_writer.len(), 0, "OFF thread emitted a record");
    }

    // Bead: asupersync-7mf9bt
    // Scenario: two concurrent current-thread runtimes inherit only their
    // caller's thread-scoped dispatcher.
    // Seed: no scheduler randomness; a bounded gate forces overlapping execution.
    // Artifact: two independent in-memory sinks with cross-contamination checks.
    #[test]
    fn logging_concurrent_runtimes_keep_distinct_sinks() {
        let (dispatch_a, writer_a) = capture_dispatch("trace");
        let (dispatch_b, writer_b) = capture_dispatch("trace");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (go_a_tx, go_a_rx) = mpsc::channel();
        let (go_b_tx, go_b_rx) = mpsc::channel();

        let ready_a = ready_tx.clone();
        let thread_a = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch_a, || {
                run_test(|| async move {
                    ready_a
                        .send("runtime-a")
                        .expect("runtime A could not report readiness");
                    go_a_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("runtime A was not released");
                    tracing::info!(target: "asupersync::logging_contract", "runtime-a-only");
                });
            });
        });

        let ready_b = ready_tx;
        let thread_b = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch_b, || {
                run_test(|| async move {
                    ready_b
                        .send("runtime-b")
                        .expect("runtime B could not report readiness");
                    go_b_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("runtime B was not released");
                    tracing::info!(target: "asupersync::logging_contract", "runtime-b-only");
                });
            });
        });

        release_logging_workers(&ready_rx, ["runtime-a", "runtime-b"], [go_a_tx, go_b_tx]);

        thread_a.join().expect("runtime A thread panicked");
        thread_b.join().expect("runtime B thread panicked");

        let text_a = writer_a.text();
        let text_b = writer_b.text();
        assert!(
            text_a.contains("runtime-a-only"),
            "runtime A output:\n{text_a}"
        );
        assert!(
            !text_a.contains("runtime-b-only"),
            "runtime B leaked into runtime A output:\n{text_a}"
        );
        assert!(
            text_b.contains("runtime-b-only"),
            "runtime B output:\n{text_b}"
        );
        assert!(
            !text_b.contains("runtime-a-only"),
            "runtime A leaked into runtime B output:\n{text_b}"
        );
    }

    // Bead: asupersync-7mf9bt
    // Scenario: TRACE remains available only through an explicit filter.
    // Seed: not applicable.
    // Artifact: captured third-party-target tracing event.
    #[test]
    fn logging_explicit_trace_filter_is_opt_in() {
        let writer = CaptureWriter::default();
        let config = TestLogConfig::trace();
        let dispatch = test_dispatch(&config, writer.clone());

        tracing::dispatcher::with_default(&dispatch, emit_filter_probe_events);

        let text = writer.text();
        assert!(
            text.contains(TOKENIZERS_TRACE_MARKER),
            "explicit TRACE did not capture tracing event:\n{text}"
        );
        assert!(
            !text.contains(TOKENIZERS_LOG_MARKER),
            "a log record crossed into tracing without the explicit bridge:\n{text}"
        );
    }

    // Bead: asupersync-7mf9bt
    // Scenario: process-global subscriber/logger state must be tested in fresh
    // processes because successful installation is irreversible.
    // Seed: DEFAULT_TEST_SEED for the LabRuntime case.
    // Command: current test binary, exact child test, nocapture, one test thread.
    // Artifact: captured child stdout/stderr.
    #[test]
    fn logging_fresh_process_contract_matrix() {
        let unset = run_logging_child("unset-rust-log", None);
        let unset_text = assert_child_passed("unset-rust-log", &unset);
        assert!(
            unset_text.contains(ASUPERSYNC_DEBUG_MARKER),
            "safe default suppressed Asupersync DEBUG:\n{unset_text}"
        );
        assert!(
            !unset_text.contains(TOKENIZERS_TRACE_MARKER),
            "safe default admitted third-party tracing TRACE:\n{unset_text}"
        );
        assert!(
            !unset_text.contains(TOKENIZERS_LOG_MARKER),
            "runtime helper implicitly installed LogTracer:\n{unset_text}"
        );
        assert_eq!(unset_text.matches(FALLBACK_MARKER).count(), 0);

        let valid = run_logging_child(
            "valid-rust-log",
            Some(OsStr::new("warn,tokenizers::normalizer=trace")),
        );
        let valid_text = assert_child_passed("valid-rust-log", &valid);
        assert!(
            valid_text.contains(TOKENIZERS_TRACE_MARKER),
            "valid RUST_LOG was not honored:\n{valid_text}"
        );
        assert!(
            !valid_text.contains(ASUPERSYNC_DEBUG_MARKER),
            "valid RUST_LOG was replaced by the safe fallback:\n{valid_text}"
        );
        assert!(
            !valid_text.contains(TOKENIZERS_LOG_MARKER),
            "valid RUST_LOG implicitly enabled the global log bridge:\n{valid_text}"
        );
        assert_eq!(valid_text.matches(FALLBACK_MARKER).count(), 0);

        let empty = run_logging_child("empty-rust-log", Some(OsStr::new(" \t ")));
        let empty_text = assert_child_passed("empty-rust-log", &empty);
        assert_single_fallback("empty-rust-log", &empty_text, "empty");

        let malformed_raw = format!(
            "asupersync=definitely-not-a-level,{}",
            "secret-filter-value".repeat(64)
        );
        let malformed = run_logging_child("malformed-rust-log", Some(OsStr::new(&malformed_raw)));
        let malformed_text = assert_child_passed("malformed-rust-log", &malformed);
        assert_single_fallback("malformed-rust-log", &malformed_text, "parse");
        assert!(!malformed_text.contains("secret-filter-value"));

        #[cfg(any(unix, windows))]
        {
            let non_unicode_raw = non_unicode_rust_log();
            let non_unicode =
                run_logging_child("non-unicode-rust-log", Some(non_unicode_raw.as_os_str()));
            let non_unicode_text = assert_child_passed("non-unicode-rust-log", &non_unicode);
            assert_single_fallback("non-unicode-rust-log", &non_unicode_text, "non_unicode");
            assert!(!non_unicode_text.contains("secret-prefix"));
        }

        let explicit_off = run_logging_child("explicit-off", None);
        let explicit_off_text = assert_child_passed("explicit-off", &explicit_off);
        for marker in [ASUPERSYNC_DEBUG_MARKER, TOKENIZERS_TRACE_MARKER] {
            assert!(
                !explicit_off_text.contains(marker),
                "explicit OFF emitted {marker:?}:\n{explicit_off_text}"
            );
        }

        let raw_no_subscriber = run_logging_child("raw-no-subscriber", None);
        let raw_no_subscriber_text = assert_child_passed("raw-no-subscriber", &raw_no_subscriber);
        for marker in [
            RAW_RUN_TEST_MARKER,
            RAW_RUN_TEST_WITH_CX_MARKER,
            RAW_LAB_MARKER,
        ] {
            assert!(
                raw_no_subscriber_text.contains(marker),
                "raw NoSubscriber did not trigger safe default for {marker:?}:\n{raw_no_subscriber_text}"
            );
        }

        let nested_enabled = run_logging_child("off-nested-enabled", None);
        let nested_enabled_text = assert_child_passed("off-nested-enabled", &nested_enabled);
        assert!(
            nested_enabled_text.contains(TOKENIZERS_TRACE_MARKER),
            "explicit enabled scope did not override OFF:\n{nested_enabled_text}"
        );
        assert!(
            !nested_enabled_text.contains(OFF_AFTER_NESTED_MARKER),
            "nested enabled scope did not restore OFF:\n{nested_enabled_text}"
        );

        let thread_propagation = run_logging_child("thread-propagation", None);
        let thread_propagation_text =
            assert_child_passed("thread-propagation", &thread_propagation);
        assert!(
            thread_propagation_text.contains(UNPROPAGATED_DEFAULT_MARKER),
            "unpropagated worker did not use the safe default:\n{thread_propagation_text}"
        );
        assert!(
            !thread_propagation_text.contains(PROPAGATED_OFF_MARKER),
            "explicitly propagated OFF emitted a record:\n{thread_propagation_text}"
        );

        let public_global = run_logging_child("public-global-subscriber", None);
        let public_global_text = assert_child_passed("public-global-subscriber", &public_global);
        assert!(public_global_text.contains(TOKENIZERS_TRACE_MARKER));

        for case in [
            "globals-untouched",
            "preexisting-global",
            "panic-restoration",
            "explicit-log-bridge",
        ] {
            let output = run_logging_child(case, None);
            let _text = assert_child_passed(case, &output);
        }
    }

    // This test is invoked directly by `logging_fresh_process_contract_matrix`.
    // Its cases intentionally make irreversible process-global changes.
    #[test]
    fn logging_fresh_process_child() {
        let Ok(case) = std::env::var(LOGGING_CHILD_CASE_ENV) else {
            return;
        };

        match case.as_str() {
            "unset-rust-log"
            | "valid-rust-log"
            | "empty-rust-log"
            | "malformed-rust-log"
            | "non-unicode-rust-log" => {
                run_test(|| async {
                    emit_filter_probe_events();
                });
            }
            "explicit-off" => {
                with_test_logging_disabled(|| {
                    emit_filter_probe_events();
                    run_test(|| async { emit_filter_probe_events() });
                    run_test_with_cx(|_cx| async { emit_filter_probe_events() });
                    lab_with_config(|_lab| emit_filter_probe_events());
                });
            }
            "raw-no-subscriber" => {
                let raw_no_subscriber = Dispatch::new(tracing::subscriber::NoSubscriber::default());
                tracing::dispatcher::with_default(&raw_no_subscriber, || {
                    run_test(|| async {
                        tracing::debug!(
                            target: "asupersync::logging_contract",
                            "{RAW_RUN_TEST_MARKER}"
                        );
                    });
                    run_test_with_cx(|_cx| async {
                        tracing::debug!(
                            target: "asupersync::logging_contract",
                            "{RAW_RUN_TEST_WITH_CX_MARKER}"
                        );
                    });
                    lab_with_config(|_lab| {
                        tracing::debug!(
                            target: "asupersync::logging_contract",
                            "{RAW_LAB_MARKER}"
                        );
                    });
                });
            }
            "off-nested-enabled" => {
                with_test_logging_disabled(|| {
                    with_test_logging(&TestLogConfig::trace(), emit_filter_probe_events);
                    assert!(!tracing::enabled!(
                        target: "asupersync::logging_contract",
                        tracing::Level::TRACE
                    ));
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "{OFF_AFTER_NESTED_MARKER}"
                    );
                });
            }
            "globals-untouched" => {
                run_test(|| async {});
                run_test_with_cx(|_cx| async {});
                lab_with_config(|_lab| {});
                with_test_logging_disabled(|| {
                    run_test(|| async {});
                    run_test_with_cx(|_cx| async {});
                    lab_with_config(|_lab| {});
                });

                tracing::dispatcher::set_global_default(Dispatch::new(
                    tracing::subscriber::NoSubscriber::default(),
                ))
                .expect("runtime helpers mutated the global tracing subscriber");

                struct NoopLogger;
                impl tracing_log::log::Log for NoopLogger {
                    fn enabled(&self, _metadata: &tracing_log::log::Metadata<'_>) -> bool {
                        false
                    }

                    fn log(&self, _record: &tracing_log::log::Record<'_>) {}

                    fn flush(&self) {}
                }
                static NOOP_LOGGER: NoopLogger = NoopLogger;
                tracing_log::log::set_logger(&NOOP_LOGGER)
                    .expect("runtime helpers mutated the global log logger");
            }
            "preexisting-global" => {
                let (dispatch, writer) = capture_dispatch("trace");
                tracing::dispatcher::set_global_default(dispatch)
                    .expect("fresh process must accept the test global subscriber");

                tracing::info!(
                    target: "asupersync::logging_contract",
                    "preexisting-global-before"
                );
                run_test(|| async {
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "preexisting-global-run-test"
                    );
                });
                run_test_with_cx(|_cx| async {
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "preexisting-global-run-test-with-cx"
                    );
                });
                lab_with_config(|_lab| {
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "preexisting-global-lab"
                    );
                });
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "preexisting-global-after"
                );

                let text = writer.text();
                for marker in [
                    "preexisting-global-before",
                    "preexisting-global-run-test",
                    "preexisting-global-run-test-with-cx",
                    "preexisting-global-lab",
                    "preexisting-global-after",
                ] {
                    assert!(
                        text.contains(marker),
                        "global subscriber missed {marker:?}:\n{text}"
                    );
                }
            }
            "panic-restoration" => {
                let cases: [Box<dyn FnOnce() + std::panic::UnwindSafe>; 3] = [
                    Box::new(|| run_test(|| async { panic!("run_test panic probe") })),
                    Box::new(|| {
                        run_test_with_cx(|_cx| async { panic!("run_test_with_cx panic probe") });
                    }),
                    Box::new(|| {
                        lab_with_config(|_lab| panic!("lab_with_config panic probe"));
                    }),
                ];

                for panic_case in cases {
                    let result = std::panic::catch_unwind(panic_case);
                    assert!(result.is_err(), "panic probe unexpectedly returned");
                    let restored = tracing::dispatcher::get_default(|dispatch| {
                        dispatch.is::<tracing::subscriber::NoSubscriber>()
                    });
                    assert!(restored, "scoped dispatcher leaked after panic");
                }
            }
            "thread-propagation" => {
                with_test_logging_disabled(|| {
                    let disabled_dispatch =
                        tracing::dispatcher::get_default(|dispatch| dispatch.clone());

                    let unpropagated = std::thread::spawn(|| {
                        assert!(tracing::dispatcher::get_default(|dispatch| {
                            dispatch.is::<tracing::subscriber::NoSubscriber>()
                        }));
                        run_test(|| async {
                            tracing::debug!(
                                target: "asupersync::logging_contract",
                                "{UNPROPAGATED_DEFAULT_MARKER}"
                            );
                        });
                    });
                    unpropagated
                        .join()
                        .expect("unpropagated logging worker panicked");

                    let propagated = std::thread::spawn(move || {
                        tracing::dispatcher::with_default(&disabled_dispatch, || {
                            assert!(tracing::dispatcher::get_default(|dispatch| {
                                !dispatch.is::<tracing::subscriber::NoSubscriber>()
                            }));
                            run_test(|| async {
                                tracing::debug!(
                                    target: "asupersync::logging_contract",
                                    "{PROPAGATED_OFF_MARKER}"
                                );
                            });
                        });
                    });
                    propagated
                        .join()
                        .expect("explicitly propagated logging worker panicked");
                });
            }
            "public-global-subscriber" => {
                install_global_test_subscriber(&TestLogConfig::trace())
                    .expect("fresh process must accept explicit global subscriber");
                emit_filter_probe_events();
                run_test(|| async { emit_filter_probe_events() });
            }
            "explicit-log-bridge" => {
                let (dispatch, writer) = capture_dispatch("trace");
                install_global_test_log_bridge()
                    .expect("fresh process must accept explicit LogTracer installation");
                tracing::dispatcher::with_default(&dispatch, || {
                    tracing::trace!(
                        target: "tokenizers::normalizer",
                        "{TOKENIZERS_TRACE_MARKER}"
                    );
                    tracing_log::log::trace!(
                        target: "tokenizers::normalizer",
                        "{TOKENIZERS_LOG_MARKER}"
                    );
                });

                let text = writer.text();
                assert!(
                    text.contains(TOKENIZERS_TRACE_MARKER),
                    "explicit bridge case lost tracing record:\n{text}"
                );
                assert!(
                    text.contains(TOKENIZERS_LOG_MARKER),
                    "explicit LogTracer bridge lost log record:\n{text}"
                );
            }
            other => panic!("unknown fresh-process logging case {other:?}"),
        }
    }

    #[test]
    fn assert_completes_within_uses_wall_time_when_no_runtime_is_active() {
        // Ensure the wall clock origin is initialized and has advanced beyond the timeout.
        let _t0 = crate::time::wall_now();
        std::thread::sleep(Duration::from_millis(50));

        // This should not spuriously time out in standalone mode.
        let value = future::block_on(assert_completes_within(
            Duration::from_millis(10),
            "standalone immediate future",
            || std::future::ready(7_u8),
        ));
        assert_eq!(value, 7);
    }

    #[test]
    fn lab_with_config_exposes_a_usable_lab_runtime() {
        let (seed, value) = lab_with_config(|runtime| {
            let seed = runtime.config().seed;
            let value = LabRuntimeTarget::block_on(runtime, async { 42_u8 });
            (seed, value)
        });

        assert_eq!(seed, DEFAULT_TEST_SEED);
        assert_eq!(value, 42);
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
