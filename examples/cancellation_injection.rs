//! Cancellation Injection Testing Example for Asupersync
//!
//! This example demonstrates how to use cancellation injection to verify that
//! async code handles cancellation correctly at every await point.
//!
//! # What is Cancellation Injection?
//!
//! Cancellation can occur at any `.await` point in async Rust. Traditional
//! testing only exercises the happy path where futures run to completion.
//! Cancellation injection systematically tests what happens when a future
//! is cancelled at each await point.
//!
//! # The Testing Process
//!
//! 1. **Recording**: Run the future once to discover all await points
//! 2. **Injection**: Re-run the future N times, injecting cancellation at each point
//! 3. **Verification**: Check that oracles pass after each injection
//!
//! # Determinism
//!
//! Given the same seed, cancellation injection produces identical results.
//! This makes failures reproducible:
//!
//! ```text
//! FAIL at await point 7, seed 12345. Re-run with same seed to reproduce.
//! ```
//!
//! # Running This Example
//!
//! ```bash
//! cargo run --example cancellation_injection
//! ```

use asupersync::lab::injection::{LabInjectionConfig, LabInjectionRunner, lab};
use asupersync::lab::{
    CancellationInjector, InjectionRunner, InjectionStrategy, InstrumentedFuture,
    InstrumentedPollResult,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

/// A future that yields N times before completing.
struct YieldingFuture {
    remaining: u32,
    value: i32,
}

impl YieldingFuture {
    fn new(yields: u32, value: i32) -> Self {
        Self {
            remaining: yields,
            value,
        }
    }
}

impl Future for YieldingFuture {
    type Output = i32;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.remaining == 0 {
            Poll::Ready(self.value)
        } else {
            self.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// A noop waker for polling futures in tests.
struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

/// Polls a future to completion using a noop waker.
fn poll_to_completion<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut pinned = Box::pin(future);

    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => {}
        }
    }
}

fn main() {
    println!("=== Asupersync Cancellation Injection Example ===\n");

    // Example 1: Basic recording and inspection
    example_recording();

    // Example 2: Injection at specific point
    example_injection_at_point();

    // Example 3: Using InjectionRunner for systematic testing
    example_injection_runner();

    // Example 4: Lab integration with fluent API
    example_lab_fluent_api();

    // Example 5: Different injection strategies
    example_strategies();

    // Example 6: Understanding and using reports
    example_reports();

    println!("\n=== All examples completed successfully! ===");
}

/// Example 1: Recording await points without injection.
/// This shows how InstrumentedFuture tracks await points.
fn example_recording() {
    println!("--- Example 1: Recording Await Points ---");

    // Create a recording injector (no injection, just observation)
    let injector = CancellationInjector::recording();

    // Wrap the future with instrumentation
    let future = YieldingFuture::new(5, 42);
    let instrumented = InstrumentedFuture::new(future, injector.clone());

    // Run to completion
    let result = poll_to_completion(instrumented);

    // Inspect what was recorded
    let recorded = injector.recorded_points();
    println!("  Future completed with value: {result:?}");
    println!("  Await points recorded: {recorded:?}");
    println!("  Total await points: {}", recorded.len());

    match result {
        InstrumentedPollResult::Inner(val) => {
            assert_eq!(val, 42);
            println!("  Result: Inner({val})");
        }
        InstrumentedPollResult::CancellationInjected(point) => {
            println!("  (Unexpected) Cancellation at point {point}");
        }
    }
    println!();
}

/// Example 2: Injecting cancellation at a specific await point.
fn example_injection_at_point() {
    println!("--- Example 2: Injection at Specific Point ---");

    // Create an injector that will inject cancellation at await point 3
    let injector = CancellationInjector::inject_at(3);

    let future = YieldingFuture::new(10, 42);
    let instrumented = InstrumentedFuture::new(future, injector.clone());

    let result = poll_to_completion(instrumented);

    let recorded = injector.recorded_points();
    println!("  Await points before injection: {recorded:?}");
    println!("  Injection count: {}", injector.injection_count());

    match result {
        InstrumentedPollResult::Inner(val) => {
            println!("  (Unexpected) Completed with: {val}");
        }
        InstrumentedPollResult::CancellationInjected(point) => {
            println!("  Cancellation injected at point: {point}");
            assert_eq!(point, 3);
        }
    }
    println!();
}

/// Example 3: Using InjectionRunner for systematic testing.
/// This is the lower-level API without Lab runtime integration.
fn example_injection_runner() {
    println!("--- Example 3: InjectionRunner Systematic Testing ---");

    let mut runner = InjectionRunner::new(42); // seed for determinism

    // Test with AllPoints strategy - tests every await point
    let report = runner.run_simple(
        InjectionStrategy::AllPoints,
        |injector| {
            let future = YieldingFuture::new(4, 42);
            InstrumentedFuture::new(future, injector)
        },
        |result| {
            // Check function: return true if the test passed
            // Both completion and proper cancellation handling are acceptable
            matches!(
                result,
                InstrumentedPollResult::Inner(_) | InstrumentedPollResult::CancellationInjected(_)
            )
        },
    );

    println!(
        "  Total await points discovered: {}",
        report.total_await_points
    );
    println!("  Tests run: {}", report.tests_run);
    println!("  Passed: {}", report.successes);
    println!("  Failed: {}", report.failures);
    println!("  All passed: {}", report.all_passed());
    println!();
}

/// Example 4: Lab integration with the fluent API.
/// This is the recommended high-level API.
fn example_lab_fluent_api() {
    println!("--- Example 4: Lab Fluent API ---");

    // Simple usage with the fluent builder
    let report = lab(42)
        .with_cancellation_injection(InjectionStrategy::FirstN(3))
        .run(|injector| {
            let future = YieldingFuture::new(5, 42);
            InstrumentedFuture::new(future, injector)
        });

    println!("  Strategy: FirstN(3)");
    println!("  Total await points: {}", report.total_await_points);
    println!("  Tests run: {} (limited to first 3)", report.tests_run);
    println!("  All passed: {}", report.all_passed());

    // Using the configuration struct for more control
    let config = LabInjectionConfig::new(42)
        .with_strategy(InjectionStrategy::AllPoints)
        .with_all_oracles()
        .stop_on_failure(false);

    let mut runner = LabInjectionRunner::new(config);
    let report = runner.run_simple(|injector| {
        let future = YieldingFuture::new(3, 42);
        InstrumentedFuture::new(future, injector)
    });

    println!("\n  With all oracles enabled:");
    println!("  Tests run: {}", report.tests_run);
    println!(
        "  Oracle violations: {}",
        report
            .results
            .iter()
            .filter(|r| !r.oracle_violations.is_empty())
            .count()
    );
    println!();
}

/// Example 5: Demonstrating different injection strategies.
fn example_strategies() {
    println!("--- Example 5: Injection Strategies ---");

    let strategies = [
        ("Never", InjectionStrategy::Never),
        ("AtSequence(3)", InjectionStrategy::AtSequence(3)),
        ("FirstN(2)", InjectionStrategy::FirstN(2)),
        ("EveryNth(2)", InjectionStrategy::EveryNth(2)),
        ("RandomSample(3)", InjectionStrategy::RandomSample(3)),
        ("AllPoints", InjectionStrategy::AllPoints),
    ];

    for (name, strategy) in strategies {
        let report = lab(42)
            .with_cancellation_injection(strategy)
            .run(|injector| {
                let future = YieldingFuture::new(6, 42);
                InstrumentedFuture::new(future, injector)
            });

        println!(
            "  {}: {} tests (of {} points)",
            name, report.tests_run, report.total_await_points
        );
    }
    println!();
}

/// Example 6: Understanding and using reports.
fn example_reports() {
    println!("--- Example 6: Working with Reports ---");

    // Create a report with a simulated failure for demonstration
    let report = lab(42)
        .with_cancellation_injection(InjectionStrategy::AllPoints)
        .run(|injector| {
            let future = YieldingFuture::new(5, 42);
            InstrumentedFuture::new(future, injector)
        });

    // Human-readable display
    println!("  Report summary:");
    println!(
        "    Verdict: {}",
        if report.all_passed() { "PASS" } else { "FAIL" }
    );
    println!("    Total await points: {}", report.total_await_points);
    println!("    Tests run: {}", report.tests_run);
    println!("    Successes: {}", report.successes);
    println!("    Failures: {}", report.failures);
    println!("    Seed: {}", report.seed);

    // Categorize failures (injection vs oracle)
    let (injection_failures, oracle_failures) = report.categorize_failures();
    println!("\n  Failure breakdown:");
    println!("    Injection failures: {}", injection_failures.len());
    println!("    Oracle failures: {}", oracle_failures.len());

    // JSON output for CI
    let json = report.to_json();
    println!("\n  JSON output (truncated):");
    println!("    verdict: {:?}", json["summary"]["verdict"]);
    println!("    tests_run: {:?}", json["summary"]["tests_run"]);

    // JUnit XML (preview)
    let xml = report.to_junit_xml();
    println!("\n  JUnit XML starts with:");
    for line in xml.lines().take(3) {
        println!("    {line}");
    }

    // Reproduction code for failures
    if report.failures().is_empty() {
        println!("\n  No failures - no reproduction code needed!");
    } else {
        println!("\n  Reproduction code for first failure:");
        let first_failure = report.failures()[0];
        for line in first_failure.reproduction_code(report.seed).lines() {
            println!("    {line}");
        }
    }
}
