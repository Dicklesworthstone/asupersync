//! Cancellation injection integration with Lab runtime and Oracles.
//!
//! This module provides integration between the cancellation injection framework
//! and the Lab runtime's oracle system, enabling comprehensive testing of
//! cancel-correctness at every await point.
//!
//! # Example
//!
//! ```
//! use asupersync::lab::injection::{LabInjectionRunner, LabInjectionConfig};
//! use asupersync::lab::{InjectionStrategy, InstrumentedFuture};
//! use asupersync::runtime::yield_now;
//!
//! let config = LabInjectionConfig::new(42)
//!     .with_strategy(InjectionStrategy::AllPoints)
//!     .with_all_oracles();
//!
//! let mut runner = LabInjectionRunner::new(config);
//! // The closure builds a fresh instrumented future for every run: one
//! // recording run, then one run per injected await point.
//! let report = runner.run_simple(|injector| {
//!     InstrumentedFuture::new(async { yield_now().await; 42 }, injector)
//! });
//!
//! assert!(report.all_passed(), "Cancellation handling failed: {:?}", report.failures());
//! ```

use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;

use crate::lab::LabConfig;
use crate::lab::instrumented_future::{
    CancellationInjector, InjectionMode, InjectionOutcome, InjectionResult, InjectionStrategy,
    InstrumentedFuture, InstrumentedPollResult,
};
use crate::lab::oracle::{OracleSuite, OracleViolation};
use crate::lab::runtime::LabRuntime;

/// Configuration for Lab injection testing.
#[derive(Debug, Clone)]
pub struct LabInjectionConfig {
    /// Seed for deterministic execution.
    seed: u64,
    /// Injection strategy to use.
    strategy: InjectionStrategy,
    /// Whether to use all oracles.
    use_all_oracles: bool,
    /// Whether to stop on first failure.
    stop_on_failure: bool,
    /// Maximum steps per run (for futurelock detection).
    max_steps_per_run: Option<u64>,
}

impl LabInjectionConfig {
    /// Creates a new configuration with the given seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            strategy: InjectionStrategy::Never,
            use_all_oracles: false,
            stop_on_failure: false,
            max_steps_per_run: None,
        }
    }

    /// Sets the injection strategy.
    #[must_use]
    pub fn with_strategy(mut self, strategy: InjectionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Enables all oracles for verification.
    ///
    /// After each injection run, the runner runs the lab runtime until it is
    /// idle, then checks both the suite passed to the test and the runtime's
    /// own oracles, hydrated from the state the test left behind.
    #[must_use]
    pub const fn with_all_oracles(mut self) -> Self {
        self.use_all_oracles = true;
        self
    }

    /// Sets whether to stop on first failure.
    #[must_use]
    pub const fn stop_on_failure(mut self, stop: bool) -> Self {
        self.stop_on_failure = stop;
        self
    }

    /// Sets maximum steps per run.
    #[must_use]
    pub const fn max_steps_per_run(mut self, max: u64) -> Self {
        self.max_steps_per_run = Some(max);
        self
    }

    /// Returns the seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the strategy.
    #[must_use]
    pub fn strategy(&self) -> &InjectionStrategy {
        &self.strategy
    }
}

/// Result of an injection test run with oracle verification.
#[derive(Debug, Clone)]
pub struct LabInjectionResult {
    /// The underlying injection result.
    pub injection: InjectionResult,
    /// Oracle violations detected after this injection.
    pub oracle_violations: Vec<OracleViolation>,
}

impl LabInjectionResult {
    /// Returns true if both injection and oracles passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.injection.is_success() && self.oracle_violations.is_empty()
    }
}

/// Report summarizing all Lab injection test runs.
#[derive(Debug, Clone)]
pub struct LabInjectionReport {
    /// Total number of await points discovered during recording.
    pub total_await_points: usize,
    /// Number of injection tests performed.
    pub tests_run: usize,
    /// Number of successful tests (both injection and oracles passed).
    pub successes: usize,
    /// Number of failures.
    pub failures: usize,
    /// Individual results for each injection point.
    pub results: Vec<LabInjectionResult>,
    /// The strategy used for this test run.
    pub strategy: String,
    /// The seed used for determinism.
    pub seed: u64,
}

impl LabInjectionReport {
    /// Creates a new report from results.
    #[must_use]
    pub fn from_results(
        results: Vec<LabInjectionResult>,
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
    pub fn failures(&self) -> Vec<&LabInjectionResult> {
        self.results.iter().filter(|r| !r.is_success()).collect()
    }

    /// Returns a config that reproduces a specific failure from this report.
    ///
    /// Given an injection point from a failed result, returns a `LabInjectionConfig`
    /// with the same seed and a targeted strategy (`AtSequence`) that re-runs
    /// only that injection point with full oracle checking enabled.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let report = runner.run_with_lab(test_fn);
    /// if !report.all_passed() {
    ///     let failure = &report.failures()[0];
    ///     let repro_config = report.reproduce_config(failure.injection.injection_point);
    ///     let mut repro_runner = LabInjectionRunner::new(repro_config);
    ///     let repro_report = repro_runner.run_with_lab(test_fn);
    ///     // repro_report should show the same failure
    /// }
    /// ```
    #[must_use]
    pub fn reproduce_config(&self, injection_point: u64) -> LabInjectionConfig {
        LabInjectionConfig::new(self.seed)
            .with_strategy(InjectionStrategy::AtSequence(injection_point))
            .with_all_oracles()
    }

    /// Returns reproduction configs for all failures in this report.
    #[must_use]
    pub fn reproduce_all_failures(&self) -> Vec<(u64, LabInjectionConfig)> {
        self.failures()
            .iter()
            .map(|f| {
                let point = f.injection.injection_point;
                (point, self.reproduce_config(point))
            })
            .collect()
    }

    /// Returns failures grouped by type: injection failures vs oracle failures.
    #[must_use]
    pub fn categorize_failures(&self) -> (Vec<&LabInjectionResult>, Vec<&LabInjectionResult>) {
        let mut injection_failures = Vec::new();
        let mut oracle_failures = Vec::new();

        for result in &self.results {
            if !result.injection.is_success() {
                injection_failures.push(result);
            } else if !result.oracle_violations.is_empty() {
                oracle_failures.push(result);
            }
        }

        (injection_failures, oracle_failures)
    }

    /// Converts the report to JSON format for CI integration.
    ///
    /// The JSON includes all summary statistics and detailed failure information,
    /// suitable for parsing by CI systems and test aggregators.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        let failures: Vec<serde_json::Value> = self
            .failures()
            .iter()
            .enumerate()
            .map(|(i, result)| {
                json!({
                    "index": i + 1,
                    "injection_point": result.injection.injection_point,
                    "outcome": format!("{:?}", result.injection.outcome),
                    "await_points_before": result.injection.await_points_before,
                    "oracle_violations": result.oracle_violations.iter()
                        .map(|v| format!("{v}"))
                        .collect::<Vec<_>>(),
                    "reproduction_code": result.reproduction_code(self.seed),
                })
            })
            .collect();

        json!({
            "summary": {
                "total_await_points": self.total_await_points,
                "tests_run": self.tests_run,
                "passed": self.successes,
                "failed": self.failures,
                "strategy": self.strategy,
                "seed": self.seed,
                "verdict": if self.all_passed() { "PASS" } else { "FAIL" },
            },
            "failures": failures,
        })
    }

    /// Converts the report to JUnit XML format for test framework integration.
    ///
    /// The XML follows the JUnit format used by most CI systems and test aggregators.
    #[must_use]
    pub fn to_junit_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push('\n');
        let _ = write!(
            xml,
            r#"<testsuite name="CancellationInjectionTests" tests="{}" failures="{}" errors="0" skipped="{}">"#,
            self.tests_run,
            self.failures,
            self.total_await_points.saturating_sub(self.tests_run)
        );
        xml.push('\n');

        for result in &self.results {
            let test_name = format!("await_point_{}", result.injection.injection_point);
            let _ = write!(
                xml,
                r#"  <testcase name="{test_name}" classname="CancellationInjection" time="0">"#,
            );
            xml.push('\n');

            if !result.is_success() {
                let failure_message = if result.injection.is_success() {
                    result
                        .oracle_violations
                        .iter()
                        .map(|v| format!("{v}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                } else {
                    format!("Injection failed: {:?}", result.injection.outcome)
                };

                let _ = write!(
                    xml,
                    r#"    <failure message="{}" type="CancellationFailure">"#,
                    escape_xml(&failure_message)
                );
                xml.push('\n');
                let _ = write!(
                    xml,
                    "Seed: {}\nInjection point: {}\n\nReproduction:\n{}",
                    self.seed,
                    result.injection.injection_point,
                    result.reproduction_code(self.seed)
                );
                xml.push_str("    </failure>\n");
            }

            xml.push_str("  </testcase>\n");
        }

        xml.push_str("</testsuite>\n");
        xml
    }

    /// Returns a display formatter for human-readable output.
    #[must_use]
    pub fn display(&self) -> LabInjectionReportDisplay<'_> {
        LabInjectionReportDisplay { report: self }
    }
}

impl LabInjectionResult {
    /// Generates Rust code to reproduce this specific failure.
    ///
    /// The returned code snippet can be copy-pasted into a test to
    /// reproduce the exact failure condition.
    #[must_use]
    pub fn reproduction_code(&self, seed: u64) -> String {
        format!(
            r"let config = LabInjectionConfig::new({})
    .with_strategy(InjectionStrategy::AtSequence({}));
let mut runner = LabInjectionRunner::new(config);
let report = runner.run_simple(|injector| {{
    InstrumentedFuture::new(your_future(), injector)
}});
assert!(report.all_passed());",
            seed, self.injection.injection_point
        )
    }
}

/// Display wrapper for human-readable report output.
pub struct LabInjectionReportDisplay<'a> {
    report: &'a LabInjectionReport,
}

impl std::fmt::Display for LabInjectionReportDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = self.report;

        writeln!(f, "Cancellation Injection Test Report")?;
        writeln!(f, "==================================")?;
        writeln!(f)?;
        writeln!(f, "Summary:")?;
        writeln!(f, "  Await points discovered: {}", r.total_await_points)?;
        writeln!(
            f,
            "  Points tested: {} (strategy: {})",
            r.tests_run, r.strategy
        )?;
        writeln!(f, "  Passed: {}", r.successes)?;
        writeln!(f, "  Failed: {}", r.failures)?;
        writeln!(f, "  Seed: {}", r.seed)?;
        writeln!(
            f,
            "  Verdict: {}",
            if r.all_passed() { "PASS" } else { "FAIL" }
        )?;

        if r.failures > 0 {
            writeln!(f)?;
            writeln!(f, "Failures:")?;

            for (i, result) in r.failures().iter().enumerate() {
                writeln!(f)?;
                writeln!(
                    f,
                    "  [{}] Await point {}",
                    i + 1,
                    result.injection.injection_point
                )?;
                writeln!(f, "      Seed: {}", r.seed)?;

                if !result.injection.is_success() {
                    writeln!(f, "      Injection outcome: {:?}", result.injection.outcome)?;
                }

                if !result.oracle_violations.is_empty() {
                    writeln!(f, "      Failed oracles:")?;
                    for violation in &result.oracle_violations {
                        writeln!(f, "        - {violation}")?;
                    }
                }

                writeln!(f)?;
                writeln!(f, "      To reproduce:")?;
                for line in result.reproduction_code(r.seed).lines() {
                    writeln!(f, "        {line}")?;
                }
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for LabInjectionReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display().fmt(f)
    }
}

/// Escapes special XML characters.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Runner that integrates cancellation injection with Lab runtime and Oracles.
///
/// This runner performs:
/// 1. A recording run to discover all await points
/// 2. For each selected injection point:
///    a. Create fresh Lab runtime and oracle suite
///    b. Run with injection at that point
///    c. Verify oracles after completion/cancellation
///    d. Collect results
/// 3. Generate comprehensive report
#[derive(Debug)]
pub struct LabInjectionRunner {
    /// Configuration for this runner.
    config: LabInjectionConfig,
    /// Current injection mode.
    current_mode: InjectionMode,
}

impl LabInjectionRunner {
    /// Creates a new Lab injection runner.
    #[must_use]
    pub const fn new(config: LabInjectionConfig) -> Self {
        Self {
            config,
            current_mode: InjectionMode::Recording,
        }
    }

    /// Returns the current injection mode.
    #[must_use]
    pub const fn current_mode(&self) -> InjectionMode {
        self.current_mode
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &LabInjectionConfig {
        &self.config
    }

    /// Runs injection tests using a closure that creates instrumented futures.
    ///
    /// The test function receives:
    /// - An `Arc<CancellationInjector>` to use with `InstrumentedFuture`
    /// - A `&mut LabRuntime` for runtime access
    /// - A `&mut OracleSuite` for oracle registration
    ///
    /// # Example
    ///
    /// ```ignore
    /// let report = runner.run_with_lab(|injector, runtime, oracles| {
    ///     // Setup test state in runtime
    ///     let future = my_async_operation();
    ///     InstrumentedFuture::new(future, injector)
    /// });
    /// ```
    pub fn run_with_lab<F, Fut, T>(&mut self, test_fn: F) -> LabInjectionReport
    where
        F: Fn(
            Arc<CancellationInjector>,
            &mut LabRuntime,
            &mut OracleSuite,
        ) -> InstrumentedFuture<Fut>,
        Fut: Future<Output = T>,
        T: std::fmt::Debug,
    {
        // Phase 1: Recording run
        self.current_mode = InjectionMode::Recording;
        let mut lab_config = LabConfig::new(self.config.seed);
        if let Some(max) = self.config.max_steps_per_run {
            lab_config = lab_config.max_steps(max);
        }
        let mut runtime = LabRuntime::new(lab_config);
        let mut oracles = OracleSuite::new();
        let recording_injector = CancellationInjector::recording();

        let instrumented = test_fn(recording_injector.clone(), &mut runtime, &mut oracles);
        if Self::poll_to_completion(instrumented, self.config.max_steps_per_run).is_err() {
            let strategy_name = format!("{:?}", self.config.strategy);
            let recorded_points = recording_injector.recorded_points();
            return LabInjectionReport::from_results(
                vec![LabInjectionResult {
                    injection: InjectionResult {
                        injection_point: 0,
                        outcome: InjectionOutcome::Timeout,
                        await_points_before: recorded_points.len(),
                    },
                    oracle_violations: Vec::new(),
                }],
                recorded_points.len(),
                &strategy_name,
                self.config.seed,
            );
        }

        let recorded_points = recording_injector.recorded_points();
        let total_await_points = recorded_points.len();

        // Phase 2: Select injection points based on strategy
        let injection_points = self
            .config
            .strategy
            .select_points(&recorded_points, self.config.seed);

        // Phase 3: Injection runs with oracle verification
        let mut results = Vec::with_capacity(injection_points.len());

        for point in injection_points {
            self.current_mode = InjectionMode::Injecting { target: point };

            // Fresh runtime and oracles for each run
            let mut lab_config = LabConfig::new(self.config.seed);
            if let Some(max) = self.config.max_steps_per_run {
                lab_config = lab_config.max_steps(max);
            }
            let mut runtime = LabRuntime::new(lab_config);
            let mut oracles = OracleSuite::new();
            let injector = CancellationInjector::inject_at(point);

            // Run the test
            let instrumented = test_fn(injector.clone(), &mut runtime, &mut oracles);
            let (mut outcome, poll_result) =
                Self::run_with_panic_catch(instrumented, self.config.max_steps_per_run);

            // A successful run must actually inject cancellation at the target point.
            // If the future completed normally, the target point was not reached.
            if matches!(outcome, InjectionOutcome::Success)
                && matches!(poll_result, Some(InstrumentedPollResult::Inner(_)))
            {
                outcome = InjectionOutcome::AssertionFailed(format!(
                    "Injection target {point} was not reached; future completed without cancellation injection"
                ));
            }

            let await_points_before = injector.recorded_points().len().saturating_sub(1);

            // Check oracles
            let oracle_violations = if self.config.use_all_oracles {
                Self::check_oracles(&mut runtime, &mut oracles)
            } else {
                Vec::new()
            };

            let lab_result = LabInjectionResult {
                injection: InjectionResult {
                    injection_point: point,
                    outcome,
                    await_points_before,
                },
                oracle_violations,
            };

            let should_stop = self.config.stop_on_failure && !lab_result.is_success();
            results.push(lab_result);

            if should_stop {
                break;
            }
        }

        // Reset mode so callers can inspect it between runs.
        self.current_mode = InjectionMode::Recording;

        // Phase 4: Generate report
        let strategy_name = format!("{:?}", self.config.strategy);
        LabInjectionReport::from_results(
            results,
            total_await_points,
            &strategy_name,
            self.config.seed,
        )
    }

    /// Simplified runner for basic test cases.
    ///
    /// This method creates a simple test harness that:
    /// - Creates an instrumented future from the provided factory
    /// - Polls it to completion
    /// - Verifies oracles (if enabled)
    pub fn run_simple<F, Fut, T>(&mut self, test_fn: F) -> LabInjectionReport
    where
        F: Fn(Arc<CancellationInjector>) -> InstrumentedFuture<Fut>,
        Fut: Future<Output = T>,
        T: std::fmt::Debug,
    {
        // Wrap with Lab runtime and oracles
        self.run_with_lab(|injector, _runtime, _oracles| test_fn(injector))
    }

    /// Checks the oracles after one injection run.
    ///
    /// The caller's suite holds only what the test fed it by hand. The lab
    /// runtime's own suite also sees the runtime: it is fed while the lab
    /// runs, and hydrated here from the state the test left behind. Runnable
    /// work runs first, until the lab is idle (br-asupersync-vcu2oz H2).
    fn check_oracles(runtime: &mut LabRuntime, oracles: &mut OracleSuite) -> Vec<OracleViolation> {
        runtime.run_until_idle();
        let now = runtime.now();
        let mut violations = oracles.check_all(now);
        runtime
            .oracles
            .hydrate_temporal_from_state(&runtime.state, now);
        violations.extend(runtime.oracles.check_all(now));
        violations
    }

    /// Polls an instrumented future to completion with panic catching.
    fn run_with_panic_catch<F, T>(
        future: InstrumentedFuture<F>,
        max_polls: Option<u64>,
    ) -> (InjectionOutcome, Option<InstrumentedPollResult<T>>)
    where
        F: Future<Output = T>,
        T: std::fmt::Debug,
    {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::poll_to_completion(future, max_polls)
        }));

        match result {
            Ok(Ok(poll_result)) => {
                let outcome = match &poll_result {
                    InstrumentedPollResult::Inner(_)
                    | InstrumentedPollResult::CancellationInjected(_) => InjectionOutcome::Success,
                };
                (outcome, Some(poll_result))
            }
            Ok(Err(outcome)) => (outcome, None),
            Err(e) => {
                let message = e
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| e.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "Unknown panic".to_string());
                (InjectionOutcome::Panic(message), None)
            }
        }
    }

    /// Polls an instrumented future to completion.
    fn poll_to_completion<F: Future>(
        future: InstrumentedFuture<F>,
        max_polls: Option<u64>,
    ) -> Result<InstrumentedPollResult<F::Output>, InjectionOutcome> {
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut pinned = Box::pin(future);
        let mut polls = 0u64;

        loop {
            if max_polls.is_some_and(|max| polls >= max) {
                return Err(InjectionOutcome::Timeout);
            }
            polls = polls.saturating_add(1);
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return Ok(output),
                Poll::Pending => {}
            }
        }
    }
}

/// Builder for creating lab injection test configurations.
///
/// This provides a fluent API for configuring cancellation injection, oracle
/// coverage, and run limits.
///
/// # Example
///
/// ```
/// use asupersync::lab::{lab, InjectionStrategy, InstrumentedFuture};
///
/// let report = lab(42)
///     .with_cancellation_injection(InjectionStrategy::AllPoints)
///     .with_all_oracles()
///     .max_steps(10_000)
///     .run(|injector| {
///         let fut = async { 42 };
///         InstrumentedFuture::new(fut, injector)
///     });
///
/// assert!(report.all_passed());
/// ```
#[derive(Debug)]
pub struct LabBuilder {
    config: LabInjectionConfig,
}

impl LabBuilder {
    /// Creates a new Lab builder with the given seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            config: LabInjectionConfig::new(seed),
        }
    }

    /// Sets the cancellation injection strategy.
    #[must_use]
    pub fn with_cancellation_injection(mut self, strategy: InjectionStrategy) -> Self {
        self.config = self.config.with_strategy(strategy);
        self
    }

    /// Enables all oracles.
    #[must_use]
    pub fn with_all_oracles(mut self) -> Self {
        self.config = self.config.with_all_oracles();
        self
    }

    /// Sets stop-on-failure behavior.
    #[must_use]
    pub fn stop_on_failure(mut self, stop: bool) -> Self {
        self.config = self.config.stop_on_failure(stop);
        self
    }

    /// Sets maximum steps per run.
    #[must_use]
    pub fn max_steps(mut self, max: u64) -> Self {
        self.config = self.config.max_steps_per_run(max);
        self
    }

    /// Builds the runner and runs the test.
    pub fn run<F, Fut, T>(self, test_fn: F) -> LabInjectionReport
    where
        F: Fn(Arc<CancellationInjector>) -> InstrumentedFuture<Fut>,
        Fut: Future<Output = T>,
        T: std::fmt::Debug,
    {
        let mut runner = LabInjectionRunner::new(self.config);
        runner.run_simple(test_fn)
    }

    /// Builds the runner and runs the test with full Lab access.
    pub fn run_with_lab<F, Fut, T>(self, test_fn: F) -> LabInjectionReport
    where
        F: Fn(
            Arc<CancellationInjector>,
            &mut LabRuntime,
            &mut OracleSuite,
        ) -> InstrumentedFuture<Fut>,
        Fut: Future<Output = T>,
        T: std::fmt::Debug,
    {
        let mut runner = LabInjectionRunner::new(self.config);
        runner.run_with_lab(test_fn)
    }
}

/// Convenience function for creating a Lab builder.
#[must_use]
pub fn lab(seed: u64) -> LabBuilder {
    LabBuilder::new(seed)
}

#[cfg(test)]
#[path = "injection_inline_tests.rs"]
mod tests;
