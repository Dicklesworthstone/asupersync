//! Instrumented future wrapper for await point tracking.
//!
//! The [`InstrumentedFuture`] wrapper tracks await points for cancellation
//! injection testing. It enables deterministic testing of cancel-correctness
//! by recording when futures yield and allowing cancellation to be injected
//! at specific await points.
//!
//! # Design
//!
//! ## Await Point Identification
//!
//! Each await point is identified by a monotonic counter within the future.
//! Combined with a task ID, this gives unique identification:
//! `(task_id, await_counter) → AwaitPoint`
//!
//! This approach is deterministic if the same code path is followed, which
//! is guaranteed in the Lab runtime with deterministic scheduling.
//!
//! ## Recording Mode
//!
//! In recording mode, the future tracks each poll invocation:
//! - Increments the await counter on each poll
//! - Records the await point to the injector
//!
//! ## Injection Mode
//!
//! In injection mode, the future checks if cancellation should be injected:
//! - On each poll, checks the injector for the target await point
//! - If matched, returns a cancellation result instead of polling the inner future
//!
//! # Example
//!
//! ```ignore
//! use asupersync::lab::instrumented_future::{InstrumentedFuture, CancellationInjector};
//!
//! // Create an injector that will cancel at await point 3
//! let injector = CancellationInjector::inject_at(3);
//!
//! // Wrap a future
//! let future = InstrumentedFuture::new(my_future, injector);
//!
//! // When polled, if await_counter reaches 3, it will trigger cancellation
//! ```

use std::fmt::Write as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use crate::types::TaskId;

/// Identifies a specific await point within a task.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AwaitPoint {
    /// The task this await point belongs to.
    pub task_id: Option<TaskId>,
    /// The sequential number of this await point (1-based).
    pub sequence: u64,
    /// Optional source location (file:line) for this await point.
    pub source_location: Option<String>,
}

impl AwaitPoint {
    /// Creates a new await point identifier.
    #[must_use]
    pub fn new(task_id: Option<TaskId>, sequence: u64) -> Self {
        Self {
            task_id,
            sequence,
            source_location: None,
        }
    }

    /// Creates an await point without task association (for testing).
    #[must_use]
    pub fn anonymous(sequence: u64) -> Self {
        Self {
            task_id: None,
            sequence,
            source_location: None,
        }
    }

    /// Creates an await point with a source location.
    #[must_use]
    pub fn with_source(mut self, location: impl Into<String>) -> Self {
        self.source_location = Some(location.into());
        self
    }

    /// Returns the source location if available.
    #[must_use]
    pub fn source_location(&self) -> Option<&str> {
        self.source_location.as_deref()
    }
}

/// Strategy for selecting which await points to inject cancellation at.
///
/// This controls which points are selected for injection during a test run.
/// Use with [`InjectionRunner::run_with_injection`] for automated test execution.
#[derive(Debug, Clone, Default)]
pub enum InjectionStrategy {
    /// Never inject cancellation (recording mode only).
    #[default]
    Never,
    /// Inject at a specific await point sequence number.
    AtSequence(u64),
    /// Inject at a specific await point.
    AtPoint(AwaitPoint),
    /// Inject at every Nth await point.
    EveryNth(u64),
    /// Test every await point (most thorough, N+1 runs for N await points).
    AllPoints,
    /// Test n randomly-selected await points using deterministic RNG.
    RandomSample(usize),
    /// Test only specified await points.
    SpecificPoints(Vec<u64>),
    /// Test first n await points.
    FirstN(usize),
    /// Each await point has probability p (0.0-1.0) of injection.
    Probabilistic(f64),

    // --- Cancel-phase-aware strategies ---
    /// Test a window of points around a center point.
    ///
    /// Selects all recorded points in `[center - radius, center + radius]`.
    /// Useful for targeting a specific code region (e.g., around a known
    /// cancel checkpoint) without testing every point in the entire run.
    WindowAround {
        /// The center await point sequence number.
        center: u64,
        /// Number of points on each side to include.
        radius: u64,
    },

    /// Skip the first N points, test the rest.
    ///
    /// Useful for bypassing initialization and focusing on steady-state
    /// or cleanup/finalization phases where cancellation handling matters most.
    ExceptFirst(usize),

    /// Test only the last N recorded await points.
    ///
    /// Targets the tail of execution — typically the finalization and
    /// cleanup phases — where cancel-correctness bugs are most common.
    LastN(usize),
}

impl InjectionStrategy {
    /// Selects the await points to test based on this strategy.
    ///
    /// # Arguments
    /// * `recorded` - The await points recorded during the recording run
    /// * `seed` - Deterministic seed for random selection
    ///
    /// # Returns
    /// A vector of await point sequence numbers to test
    #[must_use]
    pub fn select_points(&self, recorded: &[u64], seed: u64) -> Vec<u64> {
        match self {
            Self::Never => vec![],
            Self::AtSequence(seq) => {
                if recorded.contains(seq) {
                    vec![*seq]
                } else {
                    vec![]
                }
            }
            Self::AtPoint(point) => {
                if recorded.contains(&point.sequence) {
                    vec![point.sequence]
                } else {
                    vec![]
                }
            }
            Self::EveryNth(n) => {
                if *n == 0 {
                    return vec![];
                }
                recorded
                    .iter()
                    .filter(|seq| *seq % n == 0)
                    .copied()
                    .collect()
            }
            Self::AllPoints => recorded.to_vec(),
            Self::RandomSample(n) => {
                if *n == 0 || recorded.is_empty() {
                    return vec![];
                }
                // Deterministic selection using linear congruential generator
                let mut selected = Vec::with_capacity((*n).min(recorded.len()));
                let mut rng_state = seed;
                let mut indices: Vec<usize> = (0..recorded.len()).collect();

                // Fisher-Yates shuffle with deterministic RNG
                for i in (1..indices.len()).rev() {
                    // LCG: state = (a * state + c) mod m
                    rng_state = rng_state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    // Use upper bits for better randomness, as lower bits of LCG have short periods
                    let j = ((rng_state >> 32) % ((i + 1) as u64)) as usize;
                    indices.swap(i, j);
                }

                for &idx in indices.iter().take(*n) {
                    selected.push(recorded[idx]);
                }
                selected.sort_unstable();
                selected
            }
            Self::SpecificPoints(points) => points
                .iter()
                .filter(|p| recorded.contains(p))
                .copied()
                .collect(),
            Self::FirstN(n) => recorded.iter().take(*n).copied().collect(),
            Self::Probabilistic(p) => {
                if *p <= 0.0 {
                    return vec![];
                }
                if *p >= 1.0 {
                    return recorded.to_vec();
                }
                // Deterministic selection based on seed
                let mut selected = Vec::new();
                let mut rng_state = seed;
                for &seq in recorded {
                    rng_state = rng_state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    // Use upper bits for better distribution
                    // Precision loss is intentional here - we only need a random float in [0,1)
                    #[allow(clippy::cast_precision_loss)]
                    let rand_val = (rng_state >> 32) as f64 / (f64::from(u32::MAX) + 1.0);
                    if rand_val < *p {
                        selected.push(seq);
                    }
                }
                selected
            }
            Self::WindowAround { center, radius } => recorded
                .iter()
                .filter(|&&seq| {
                    seq >= center.saturating_sub(*radius) && seq <= center.saturating_add(*radius)
                })
                .copied()
                .collect(),
            Self::ExceptFirst(n) => recorded.iter().skip(*n).copied().collect(),
            Self::LastN(n) => {
                let skip = recorded.len().saturating_sub(*n);
                recorded.iter().skip(skip).copied().collect()
            }
        }
    }
}

/// Mode of operation for the injector during a test run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InjectionMode {
    /// Recording await points without injecting.
    #[default]
    Recording,
    /// Injecting cancellation at a specific target point.
    Injecting {
        /// The await point sequence to inject at.
        target: u64,
    },
}

/// The outcome of a single injection test run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionOutcome {
    /// The test completed successfully (cancellation was handled correctly).
    Success,
    /// The test panicked during execution.
    Panic(String),
    /// An assertion failed during the test.
    AssertionFailed(String),
    /// The test timed out.
    Timeout,
    /// The test detected a resource leak after cancellation.
    ResourceLeak(String),
}

/// Result of injecting cancellation at a specific await point.
#[derive(Debug, Clone)]
pub struct InjectionResult {
    /// The await point where cancellation was injected.
    pub injection_point: u64,
    /// The outcome of this injection test.
    pub outcome: InjectionOutcome,
    /// Number of await points reached before injection.
    pub await_points_before: usize,
}

impl InjectionResult {
    /// Creates a new successful injection result.
    #[must_use]
    pub fn success(injection_point: u64, await_points_before: usize) -> Self {
        Self {
            injection_point,
            outcome: InjectionOutcome::Success,
            await_points_before,
        }
    }

    /// Creates a new panic injection result.
    #[must_use]
    pub fn panic(injection_point: u64, message: String, await_points_before: usize) -> Self {
        Self {
            injection_point,
            outcome: InjectionOutcome::Panic(message),
            await_points_before,
        }
    }

    /// Returns true if this result indicates success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.outcome, InjectionOutcome::Success)
    }

    /// Returns a human-readable summary of the outcome.
    #[must_use]
    pub fn outcome_summary(&self) -> String {
        match &self.outcome {
            InjectionOutcome::Success => "Success".to_string(),
            InjectionOutcome::Panic(msg) => format!("Panic: {msg}"),
            InjectionOutcome::AssertionFailed(msg) => format!("Assertion failed: {msg}"),
            InjectionOutcome::Timeout => "Timeout".to_string(),
            InjectionOutcome::ResourceLeak(msg) => format!("Resource leak: {msg}"),
        }
    }
}

/// Report summarizing all injection test runs.
#[derive(Debug, Clone)]
pub struct InjectionReport {
    /// Total number of await points discovered during recording.
    pub total_await_points: usize,
    /// Number of injection tests performed.
    pub tests_run: usize,
    /// Number of successful tests.
    pub successes: usize,
    /// Number of failures.
    pub failures: usize,
    /// Individual results for each injection point.
    pub results: Vec<InjectionResult>,
    /// The strategy used for this test run.
    pub strategy: String,
    /// The seed used for deterministic execution.
    pub seed: u64,
}

impl InjectionReport {
    /// Creates a new report from a list of results.
    #[must_use]
    pub fn from_results(
        results: Vec<InjectionResult>,
        total_await_points: usize,
        strategy: &str,
    ) -> Self {
        Self::from_results_with_seed(results, total_await_points, strategy, 0)
    }

    /// Creates a new report from a list of results with a specific seed.
    #[must_use]
    pub fn from_results_with_seed(
        results: Vec<InjectionResult>,
        total_await_points: usize,
        strategy: &str,
        seed: u64,
    ) -> Self {
        let successes = results.iter().filter(|r| r.is_success()).count();
        let failures = results.len() - successes;
        Self {
            total_await_points,
            tests_run: results.len(),
            successes,
            failures,
            results,
            strategy: strategy.to_string(),
            seed,
        }
    }

    /// Returns true if all tests passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failures == 0
    }

    /// Returns the failed results.
    #[must_use]
    pub fn failures(&self) -> Vec<&InjectionResult> {
        self.results.iter().filter(|r| !r.is_success()).collect()
    }

    /// Returns whether this report indicates success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.failures == 0
    }

    /// Converts the report to JSON format for CI integration.
    ///
    /// # Example JSON output:
    /// ```json
    /// {
    ///   "total_await_points": 47,
    ///   "tests_run": 47,
    ///   "successes": 45,
    ///   "failures": 2,
    ///   "strategy": "AllPoints",
    ///   "seed": 12345,
    ///   "passed": false,
    ///   "results": [...]
    /// }
    /// ```
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut json = String::from("{\n");
        let _ = writeln!(
            json,
            "  \"total_await_points\": {},",
            self.total_await_points
        );
        let _ = writeln!(json, "  \"tests_run\": {},", self.tests_run);
        let _ = writeln!(json, "  \"successes\": {},", self.successes);
        let _ = writeln!(json, "  \"failures\": {},", self.failures);
        let _ = writeln!(json, "  \"strategy\": \"{}\",", escape_json(&self.strategy));
        let _ = writeln!(json, "  \"seed\": {},", self.seed);
        let _ = writeln!(json, "  \"passed\": {},", self.is_success());
        json.push_str("  \"results\": [\n");

        for (i, result) in self.results.iter().enumerate() {
            let comma = if i < self.results.len() - 1 { "," } else { "" };
            let _ = writeln!(
                json,
                "    {{\n      \"injection_point\": {},\n      \"await_points_before\": {},\n      \"success\": {},\n      \"outcome\": \"{}\"\n    }}{comma}",
                result.injection_point,
                result.await_points_before,
                result.is_success(),
                escape_json(&result.outcome_summary()),
            );
        }

        json.push_str("  ]\n");
        json.push('}');
        json
    }

    /// Converts the report to JUnit XML format for test framework integration.
    ///
    /// # Example XML output:
    /// ```xml
    /// <?xml version="1.0" encoding="UTF-8"?>
    /// <testsuite name="CancellationInjection" tests="47" failures="2" time="0">
    ///   <testcase name="await_point_1" classname="injection"/>
    ///   <testcase name="await_point_2" classname="injection">
    ///     <failure message="Panic: test panic"/>
    ///   </testcase>
    /// </testsuite>
    /// ```
    #[must_use]
    pub fn to_junit_xml(&self) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        let _ = writeln!(
            xml,
            "<testsuite name=\"CancellationInjection\" tests=\"{}\" failures=\"{}\" time=\"0\">",
            self.tests_run, self.failures
        );

        for result in &self.results {
            let name = format!("await_point_{}", result.injection_point);
            if result.is_success() {
                let _ = writeln!(
                    xml,
                    "  <testcase name=\"{}\" classname=\"injection\"/>",
                    escape_xml(&name)
                );
            } else {
                let _ = writeln!(
                    xml,
                    "  <testcase name=\"{}\" classname=\"injection\">",
                    escape_xml(&name)
                );
                let _ = writeln!(
                    xml,
                    "    <failure message=\"{}\"/>",
                    escape_xml(&result.outcome_summary())
                );
                xml.push_str("  </testcase>\n");
            }
        }

        xml.push_str("</testsuite>\n");
        xml
    }

    /// Generates reproduction code for a specific failure.
    #[must_use]
    pub fn reproduction_code(&self, injection_point: u64) -> String {
        format!(
            r"Lab::new()
    .with_seed({})
    .with_injection_point({})
    .run(test_fn);",
            self.seed, injection_point
        )
    }
}

impl std::fmt::Display for InjectionReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Cancellation Injection Test Report")?;
        writeln!(f, "===================================")?;
        writeln!(f)?;
        writeln!(f, "Summary:")?;
        writeln!(f, "  Await points discovered: {}", self.total_await_points)?;
        writeln!(
            f,
            "  Points tested: {} (strategy: {})",
            self.tests_run, self.strategy
        )?;
        writeln!(f, "  Passed: {}", self.successes)?;
        writeln!(f, "  Failed: {}", self.failures)?;
        writeln!(f, "  Seed: {}", self.seed)?;
        writeln!(f)?;

        if self.failures > 0 {
            writeln!(f, "Failures:")?;
            writeln!(f)?;

            let failures = self.failures();
            for (i, result) in failures.iter().enumerate() {
                writeln!(f, "  [{}] Await point {}", i + 1, result.injection_point)?;
                writeln!(f, "      Seed: {}", self.seed)?;
                writeln!(
                    f,
                    "      Await points before injection: {}",
                    result.await_points_before
                )?;
                writeln!(f, "      Outcome: {}", result.outcome_summary())?;
                writeln!(f)?;
                writeln!(f, "      To reproduce:")?;
                for line in self.reproduction_code(result.injection_point).lines() {
                    writeln!(f, "        {line}")?;
                }
                writeln!(f)?;
            }
        } else {
            writeln!(f, "All tests passed!")?;
        }

        Ok(())
    }
}

/// Escapes a string for JSON output.
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Escapes a string for XML output.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Runner that orchestrates recording and injection test cycles.
///
/// The runner performs a two-phase test:
/// 1. **Recording run**: Execute the test once to discover all await points
/// 2. **Injection runs**: Re-run the test for each selected await point,
///    injecting cancellation and verifying correct handling
///
/// # Example
///
/// ```ignore
/// use asupersync::lab::instrumented_future::{InjectionRunner, InjectionStrategy};
///
/// let runner = InjectionRunner::new(42); // seed for determinism
/// let report = runner.run_with_injection(
///     InjectionStrategy::AllPoints,
///     || async { my_async_operation().await },
///     |result| result.is_ok(), // success check
/// );
///
/// assert!(report.all_passed(), "Cancellation handling failed");
/// ```
#[derive(Debug)]
pub struct InjectionRunner {
    /// Deterministic seed for random selection strategies.
    seed: u64,
    /// Mode tracking for current run.
    current_mode: InjectionMode,
}

impl InjectionRunner {
    /// Creates a new injection runner with the given seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            current_mode: InjectionMode::Recording,
        }
    }

    /// Returns the current injection mode.
    #[must_use]
    pub const fn current_mode(&self) -> InjectionMode {
        self.current_mode
    }

    /// Returns the seed used for deterministic selection.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Runs a cancellation injection test with the given strategy.
    ///
    /// This method performs:
    /// 1. A recording run to discover all await points
    /// 2. Injection runs at points selected by the strategy
    /// 3. Collection of results into a report
    ///
    /// # Arguments
    ///
    /// * `strategy` - The strategy for selecting injection points
    /// * `test_fn` - A closure that creates the future to test
    /// * `poll_fn` - A closure that polls the instrumented future to completion
    ///   and returns an `InjectionOutcome`
    ///
    /// # Returns
    ///
    /// An `InjectionReport` summarizing all test runs.
    #[allow(clippy::needless_pass_by_value)] // API design: take ownership for flexibility
    pub fn run_with_injection<F, Fut, P>(
        &mut self,
        strategy: InjectionStrategy,
        test_fn: F,
        poll_fn: P,
    ) -> InjectionReport
    where
        F: Fn(Arc<CancellationInjector>) -> Fut,
        Fut: Future,
        P: Fn(Fut) -> InjectionOutcome,
    {
        // Phase 1: Recording run
        self.current_mode = InjectionMode::Recording;
        let recording_injector = CancellationInjector::recording();
        let future = test_fn(recording_injector.clone());
        let _ = poll_fn(future);

        let recorded_points = recording_injector.recorded_points();
        let total_await_points = recorded_points.len();

        // Phase 2: Select injection points based on strategy
        let injection_points = strategy.select_points(&recorded_points, self.seed);

        // Phase 3: Injection runs
        let mut results = Vec::with_capacity(injection_points.len());

        for point in injection_points {
            self.current_mode = InjectionMode::Injecting { target: point };
            let injector = CancellationInjector::inject_at(point);
            let future = test_fn(injector.clone());
            let outcome = poll_fn(future);

            let await_points_before = injector.recorded_points().len().saturating_sub(1);
            results.push(InjectionResult {
                injection_point: point,
                outcome,
                await_points_before,
            });
        }

        // Reset to baseline mode so subsequent runs start from a consistent state.
        self.current_mode = InjectionMode::Recording;

        // Phase 4: Generate report
        let strategy_name = format!("{strategy:?}");
        InjectionReport::from_results_with_seed(
            results,
            total_await_points,
            &strategy_name,
            self.seed,
        )
    }

    /// Runs injection tests using a simpler interface for basic futures.
    ///
    /// This is a convenience method that handles the common case where:
    /// - The future's output can be checked for success
    /// - No special polling logic is needed
    ///
    /// # Arguments
    ///
    /// * `strategy` - The strategy for selecting injection points
    /// * `test_fn` - A closure that creates the instrumented future
    /// * `check_fn` - A closure that checks if an instrumented poll result indicates success
    pub fn run_simple<F, Fut, T, C>(
        &mut self,
        strategy: InjectionStrategy,
        test_fn: F,
        check_fn: C,
    ) -> InjectionReport
    where
        F: Fn(Arc<CancellationInjector>) -> InstrumentedFuture<Fut>,
        Fut: Future<Output = T>,
        T: std::fmt::Debug,
        C: Fn(&InstrumentedPollResult<T>) -> bool,
    {
        self.run_with_injection(
            strategy,
            test_fn,
            |instrumented: InstrumentedFuture<Fut>| {
                // Poll to completion using catch_unwind for panic detection
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::poll_instrumented_to_completion(instrumented)
                }));

                match result {
                    Ok(poll_result) => {
                        if check_fn(&poll_result) {
                            InjectionOutcome::Success
                        } else {
                            InjectionOutcome::AssertionFailed(format!(
                                "Check function returned false for result: {poll_result:?}"
                            ))
                        }
                    }
                    Err(e) => {
                        let message = e.downcast_ref::<&str>().map_or_else(
                            || {
                                e.downcast_ref::<String>()
                                    .cloned()
                                    .unwrap_or_else(|| "Unknown panic".to_string())
                            },
                            |s| (*s).to_string(),
                        );
                        InjectionOutcome::Panic(message)
                    }
                }
            },
        )
    }

    /// Polls an instrumented future to completion.
    fn poll_instrumented_to_completion<F: Future>(
        future: InstrumentedFuture<F>,
    ) -> InstrumentedPollResult<F::Output> {
        use std::task::Waker;

        let waker = Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut pinned = Box::pin(future);

        loop {
            match pinned.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => {}
            }
        }
    }
}

/// Records await points and controls cancellation injection.
///
/// The injector has two modes:
/// - **Recording**: Tracks all await points reached (strategy = `Never`)
/// - **Injection**: Triggers cancellation at specific points
#[derive(Debug)]
pub struct CancellationInjector {
    /// The injection strategy.
    strategy: InjectionStrategy,
    /// Recorded await points (sequence numbers in order).
    recorded: parking_lot::Mutex<Vec<u64>>,
    /// Number of injections performed.
    injection_count: AtomicU64,
    /// Associated task ID (optional).
    task_id: Option<TaskId>,
}

impl CancellationInjector {
    /// Creates a new injector in recording mode.
    #[must_use]
    pub fn recording() -> Arc<Self> {
        Arc::new(Self {
            strategy: InjectionStrategy::Never,
            recorded: parking_lot::Mutex::new(Vec::new()),
            injection_count: AtomicU64::new(0),
            task_id: None,
        })
    }

    /// Creates an injector that injects at a specific sequence number.
    #[must_use]
    pub fn inject_at(sequence: u64) -> Arc<Self> {
        Arc::new(Self {
            strategy: InjectionStrategy::AtSequence(sequence),
            recorded: parking_lot::Mutex::new(Vec::new()),
            injection_count: AtomicU64::new(0),
            task_id: None,
        })
    }

    /// Creates an injector that injects at a specific await point.
    #[must_use]
    pub fn inject_at_point(point: AwaitPoint) -> Arc<Self> {
        let task_id = point.task_id;
        Arc::new(Self {
            strategy: InjectionStrategy::AtPoint(point),
            recorded: parking_lot::Mutex::new(Vec::new()),
            injection_count: AtomicU64::new(0),
            task_id,
        })
    }

    /// Creates an injector that injects at every Nth await point.
    #[must_use]
    pub fn inject_every_nth(n: u64) -> Arc<Self> {
        Arc::new(Self {
            strategy: InjectionStrategy::EveryNth(n),
            recorded: parking_lot::Mutex::new(Vec::new()),
            injection_count: AtomicU64::new(0),
            task_id: None,
        })
    }

    /// Creates an injector with a specific strategy.
    #[must_use]
    pub fn with_strategy(strategy: InjectionStrategy) -> Arc<Self> {
        let task_id = match &strategy {
            InjectionStrategy::AtPoint(point) => point.task_id,
            _ => None,
        };
        Arc::new(Self {
            strategy,
            recorded: parking_lot::Mutex::new(Vec::new()),
            injection_count: AtomicU64::new(0),
            task_id,
        })
    }

    /// Sets the associated task ID.
    pub fn set_task_id(&mut self, task_id: TaskId) {
        self.task_id = Some(task_id);
    }

    /// Records an await point.
    pub fn record_await(&self, sequence: u64) {
        self.recorded.lock().push(sequence);
    }

    /// Checks if cancellation should be injected at this await point.
    #[must_use]
    pub fn should_inject_at(&self, sequence: u64) -> bool {
        // Selection-only strategies don't inject at the point level.
        match &self.strategy {
            InjectionStrategy::Never
            | InjectionStrategy::AllPoints
            | InjectionStrategy::RandomSample(_)
            | InjectionStrategy::SpecificPoints(_)
            | InjectionStrategy::FirstN(_)
            | InjectionStrategy::Probabilistic(_)
            | InjectionStrategy::WindowAround { .. }
            | InjectionStrategy::ExceptFirst(_)
            | InjectionStrategy::LastN(_) => false,
            InjectionStrategy::AtSequence(target) => {
                if sequence == *target {
                    self.injection_count.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            InjectionStrategy::AtPoint(point) => {
                // If task_id doesn't match, don't inject
                if point.task_id.is_some() && point.task_id != self.task_id {
                    return false;
                }
                if sequence == point.sequence {
                    self.injection_count.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            InjectionStrategy::EveryNth(n) => {
                if *n > 0 && sequence.is_multiple_of(*n) {
                    self.injection_count.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Returns the recorded await points.
    #[must_use]
    pub fn recorded_points(&self) -> Vec<u64> {
        self.recorded.lock().clone()
    }

    /// Returns the number of injections performed.
    #[must_use]
    pub fn injection_count(&self) -> u64 {
        self.injection_count.load(Ordering::SeqCst)
    }

    /// Clears recorded await points.
    pub fn clear_recorded(&self) {
        self.recorded.lock().clear();
    }
}

/// The result of polling an instrumented future when cancellation is injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrumentedPollResult<T> {
    /// The inner future returned this result.
    Inner(T),
    /// Cancellation was injected at this await point.
    CancellationInjected(u64),
}

/// A future wrapper that tracks await points for cancellation injection.
///
/// This wrapper instruments a future to:
/// 1. Count poll invocations (await points)
/// 2. Record await points to a [`CancellationInjector`]
/// 3. Optionally inject cancellation at specific await points
///
/// # Type Parameters
///
/// * `F` - The inner future type
#[pin_project::pin_project]
pub struct InstrumentedFuture<F> {
    /// The wrapped future.
    #[pin]
    inner: F,
    /// The cancellation injector.
    injector: Arc<CancellationInjector>,
    /// Current await point counter (1-based, incremented before each poll).
    await_counter: u64,
    /// Whether cancellation was injected.
    cancellation_injected: bool,
    /// The await point where cancellation was injected.
    injection_point: Option<u64>,
}

impl<F> InstrumentedFuture<F> {
    /// Creates a new instrumented future.
    #[must_use]
    pub fn new(inner: F, injector: Arc<CancellationInjector>) -> Self {
        Self {
            inner,
            injector,
            await_counter: 0,
            cancellation_injected: false,
            injection_point: None,
        }
    }

    /// Creates an instrumented future in recording mode.
    #[must_use]
    pub fn recording(inner: F) -> Self {
        Self::new(inner, CancellationInjector::recording())
    }

    /// Returns the current await counter value.
    #[must_use]
    pub fn await_count(&self) -> u64 {
        self.await_counter
    }

    /// Returns whether cancellation was injected.
    #[must_use]
    pub fn was_cancelled(&self) -> bool {
        self.cancellation_injected
    }

    /// Returns the await point where cancellation was injected.
    #[must_use]
    pub fn injection_point(&self) -> Option<u64> {
        self.injection_point
    }

    /// Returns a reference to the injector.
    #[must_use]
    pub fn injector(&self) -> &Arc<CancellationInjector> {
        &self.injector
    }
}

impl<F: Future> Future for InstrumentedFuture<F> {
    type Output = InstrumentedPollResult<F::Output>;

    /// br-asupersync-7w790g: when cancellation is injected, the
    /// inner future is NOT polled in this tick. The wrapper holds
    /// the inner future until the wrapper itself is dropped — at
    /// which point the inner's `Drop` runs and tears down any
    /// resources it held (channel waker registrations, obligation
    /// permits, sleep timers). Callers MUST drop the wrapper
    /// promptly after observing `Poll::Ready(CancellationInjected)`
    /// — holding the wrapper alive keeps the inner future's
    /// resources alive too.
    ///
    /// The asupersync invariant "cancellation is a protocol —
    /// request → drain → finalize" applies to the inner future's
    /// own Cx; the InstrumentedFuture wrapper merely short-circuits
    /// the SCHEDULER's poll-driven progress. Inner futures that
    /// rely on their own checkpoint() observing a cancelled Cx must
    /// have that Cx cancelled by the harness BEFORE invoking the
    /// wrapper's poll path. The wrapper does not (and cannot)
    /// cancel the inner's Cx on the caller's behalf — it has no
    /// reference to the inner's Cx.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // If cancellation was already injected, return immediately
        if *this.cancellation_injected {
            return Poll::Ready(InstrumentedPollResult::CancellationInjected(
                this.injection_point.unwrap_or(0),
            ));
        }

        // Increment await counter before polling
        *this.await_counter += 1;
        let current_point = *this.await_counter;

        // Record this await point
        this.injector.record_await(current_point);

        // Check if we should inject cancellation here
        if this.injector.should_inject_at(current_point) {
            *this.cancellation_injected = true;
            *this.injection_point = Some(current_point);
            // br-asupersync-7w790g: WAKE the polling task so a
            // caller that races the cancellation-injection from
            // outside our pin tree (e.g. observing the injector
            // state via a shared Arc) does not park forever
            // waiting for a Poll::Pending → Poll::Ready transition.
            // The pre-fix shape returned Poll::Ready(Cancelled)
            // without any waker activity; a downstream
            // executor-side waker observer that had just woken us
            // for "should_inject" purposes is now consistently
            // signalled.
            cx.waker().wake_by_ref();
            return Poll::Ready(InstrumentedPollResult::CancellationInjected(current_point));
        }

        // Poll the inner future
        match this.inner.poll(cx) {
            Poll::Ready(output) => Poll::Ready(InstrumentedPollResult::Inner(output)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
#[path = "instrumented_future_inline_tests.rs"]
mod tests;
