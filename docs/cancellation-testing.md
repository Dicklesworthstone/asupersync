# Cancellation Injection Testing

Asupersync provides a deterministic framework for testing that your async code handles
cancellation correctly at every await point. This document explains how to use it.

## Overview

### The Problem: Cancellation Can Strike Anywhere

In async Rust, a future can be cancelled at any `.await` point. Consider this code:

```rust
async fn transfer_money(from: Account, to: Account, amount: u64) {
    from.debit(amount).await;          // await point 1
    to.credit(amount).await;           // await point 2
    log_transaction(from, to, amount).await;  // await point 3
}
```

If this future is cancelled after the debit but before the credit, money vanishes.
Traditional testing cannot catch this because:

- Unit tests run futures to completion
- Integration tests don't systematically test every cancellation point
- Production bugs are non-deterministic and hard to reproduce

### The Solution: Systematic Cancellation Injection

Asupersync's lab runtime enables deterministic cancellation testing:

1. **Recording Phase**: Run your async code once to discover all await points
2. **Injection Phase**: Re-run with cancellation injected at each await point
3. **Verification Phase**: Oracles check that invariants hold after cancellation

The lab runtime's virtual time and deterministic scheduling guarantee reproducibility:
same seed = same execution order = same test results.

## Quick Start

Add a cancellation injection test to your test suite:

```rust
use asupersync::lab::{lab, InjectionStrategy, InstrumentedFuture};

#[test]
fn my_async_code_is_cancel_safe() {
    let report = lab(42)  // seed for determinism
        .with_cancellation_injection(InjectionStrategy::AllPoints)
        .with_all_oracles()
        .run(|injector| {
            InstrumentedFuture::new(my_async_function(), injector)
        });

    assert!(report.all_passed(), "Cancellation failures:\n{}", report);
}
```

This will:
1. Run `my_async_function` once to record await points
2. Re-run it N times, injecting cancellation at each of the N await points
3. Verify oracles after each run
4. Report any failures with reproduction instructions

## Injection Strategies

Choose the right strategy for your testing needs:

### `AllPoints` - Exhaustive Testing

```rust
InjectionStrategy::AllPoints
```

Tests cancellation at every discovered await point. Use for:
- Critical code paths (payment processing, data persistence)
- Small tests with few await points
- Pre-release validation

**Trade-off**: O(N) test runs for N await points. Thorough but slow for large tests.

### `RandomSample(n)` - Probabilistic Coverage

```rust
InjectionStrategy::RandomSample(5)  // test 5 random points
```

Selects n random await points using a deterministic RNG seeded by the test seed.
Use for:
- Large tests with many await points
- CI pipelines with time constraints
- Fuzzing campaigns

**Trade-off**: May miss edge cases, but same seed = same points tested.

### `SpecificPoints(vec)` - Targeted Regression Testing

```rust
InjectionStrategy::SpecificPoints(vec![3, 7, 12])
```

Tests only the specified await points. Use for:
- Regression tests for known-problematic points
- Focused testing during development
- Reproducing specific failures

### `Probabilistic(p)` - Chaos Testing

```rust
InjectionStrategy::Probabilistic(0.1)  // 10% chance per await point
```

Each await point has probability p of being tested. Use for:
- Long-running chaos/soak tests
- Random exploration of the cancellation space
- Discovering unexpected interactions

### `FirstN(n)` - Early Await Points

```rust
InjectionStrategy::FirstN(3)  // test first 3 await points
```

Tests the first n await points. Use for:
- Testing initialization/setup code
- When early cancellation is most critical
- Quick smoke tests

### `EveryNth(n)` - Periodic Sampling

```rust
InjectionStrategy::EveryNth(5)  // test every 5th await point
```

Tests every nth await point. Use for:
- Systematic sampling of large futures
- When you expect periodic patterns

### `Never` - Recording Only

```rust
InjectionStrategy::Never
```

Records await points without testing. Use for:
- Discovering how many await points exist
- Debugging instrumentation
- Baseline measurements

## Understanding Failures

When a test fails, the report provides actionable information.

### Reading the Report

```
Cancellation Injection Test Report
==================================

Summary:
  Await points discovered: 15
  Points tested: 15 (strategy: AllPoints)
  Passed: 14
  Failed: 1
  Seed: 42
  Verdict: FAIL

Failures:

  [1] Await point 7
      Seed: 42
      Failed oracles:
        - ObligationLeak: Resource 'db_connection' was not released

      To reproduce:
        let config = LabInjectionConfig::new(42)
            .with_strategy(InjectionStrategy::AtSequence(7));
        let mut runner = LabInjectionRunner::new(config);
        let report = runner.run_simple(|injector| {
            InstrumentedFuture::new(your_future(), injector)
        });
        assert!(report.all_passed());
```

### Common Oracle Violations

#### ObligationLeak

**Symptom**: A resource was acquired but not released after cancellation.

**Common causes**:
- RAII guard not used (relying on explicit cleanup)
- Cleanup code after an await point that never runs
- Shared state not properly cleaned up on drop

**Fix**: Use RAII guards and register finalizers for critical cleanup.

#### TaskLeak

**Symptom**: Spawned tasks were not joined after the parent was cancelled.

---

## Conformal Bounds on Cancellation Latency (spec)

We want **distribution-free** guarantees on how long cancellation/drain takes.
Conformal prediction gives a simple, deterministic bound that holds under
minimal assumptions.

### Definitions

- `T_request`: time (or tick) when cancellation is requested
- `T_complete`: time (or tick) when the task reaches `Completed(Cancelled)`
- `L = T_complete - T_request`: observed drain latency

### Calibration (per workload or policy)

Collect a calibration set of latencies `L_1..L_n` from lab runs (or production
traces with deterministic replay). For a target coverage `1 - alpha`, compute:

```
k = ceil((n + 1) * (1 - alpha))
bound = kth_order_statistic(L_1..L_n, k)
```

This `bound` is a **distribution-free** upper bound: future latencies exceed it
with probability at most `alpha`, assuming exchangeability.

### Reporting format (diagnostics)

Report the bound alongside the target coverage:

```
CancelLatencyBound {
  coverage: 0.99,
  bound_ticks: 1234,
  sample_count: 512,
  scope: "task" | "region" | "workload"
}
```

### Integration points

- Lab runtime: compute bounds from deterministic test suites and emit in reports.
- Production traces: compute bounds from replayable traces, tagged by workload.
- CI: verify coverage on synthetic schedules (below).

### Synthetic coverage tests (acceptance)

1. Generate a known distribution of drain latencies in the lab runtime.
2. Calibrate on a subset; evaluate on a held-out subset.
3. Assert empirical coverage `>= 1 - alpha` within tolerance.

This provides an automated check that the conformal bound is correctly computed.

**Common causes**:
- Spawning without storing the join handle
- Not cancelling child tasks when parent is cancelled
- Infinite loops in spawned tasks

**Fix**: Use structured concurrency - always join or cancel child tasks.

#### QuiescenceViolation

**Symptom**: The runtime did not reach quiescence after region close.

**Common causes**:
- Tasks still pending after cancellation
- Unbounded work queues
- Livelock between tasks

**Fix**: Ensure all work can complete or be cancelled.

#### LoserDrainViolation

**Symptom**: Race losers were not properly drained.

**Common causes**:
- `select!` without draining losing branches
- Incomplete cancellation protocol

**Fix**: Always await or cancel all select branches.

## Best Practices

### Pattern 1: Two-Phase Commit

For operations that modify multiple resources, use two-phase commit:

```rust
async fn transfer(cx: &Cx, from: &Account, to: &Account, amount: u64) -> Outcome<(), Error> {
    // Phase 1: Prepare (can be cancelled)
    let debit_voucher = from.prepare_debit(cx, amount).await?;
    let credit_voucher = to.prepare_credit(cx, amount).await?;

    // Phase 2: Commit (masked from cancellation)
    cx.mask_cancellation(|cx| async {
        debit_voucher.commit(cx).await?;
        credit_voucher.commit(cx).await?;
        Ok(())
    }).await
}
```

### Pattern 2: RAII Guards

Use guard types that clean up on drop:

```rust
struct ConnectionGuard {
    conn: Connection,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        // Cleanup happens even if cancelled
        self.conn.release();
    }
}

async fn use_connection(cx: &Cx) -> Outcome<(), Error> {
    let guard = ConnectionGuard { conn: acquire_connection().await? };

    do_work(&guard.conn).await?;

    // guard.drop() runs even if we're cancelled here
    Ok(())
}
```

### Pattern 3: Finalizer Registration

For cleanup that must run even after cancellation:

```rust
async fn process_batch(cx: &Cx, batch: Batch) -> Outcome<(), Error> {
    // Register finalizer before acquiring resources
    let finalizer_id = cx.register_finalizer(|| {
        batch.abort();
    });

    batch.process(cx).await?;

    // Deregister on success
    cx.deregister_finalizer(finalizer_id);
    batch.commit();
    Ok(())
}
```

### Pattern 4: Masking Critical Sections

For code that must not be cancelled:

```rust
async fn atomic_update(cx: &Cx, state: &State) -> Outcome<(), Error> {
    // This section will complete even if cancellation arrives
    cx.mask_cancellation(|cx| async {
        state.begin_transaction();
        state.update();
        state.commit_transaction();
    }).await
}
```

## CI Integration

### JSON Output for Parsing

```rust
let report = lab(seed).run(/* ... */);
let json = report.to_json();
println!("{}", serde_json::to_string_pretty(&json).unwrap());
```

Output:
```json
{
  "summary": {
    "total_await_points": 15,
    "tests_run": 15,
    "passed": 14,
    "failed": 1,
    "strategy": "AllPoints",
    "seed": 42,
    "verdict": "FAIL"
  },
  "failures": [
    {
      "index": 1,
      "injection_point": 7,
      "outcome": "Success",
      "await_points_before": 6,
      "oracle_violations": ["ObligationLeak: ..."],
      "reproduction_code": "..."
    }
  ]
}
```

### JUnit XML for Test Frameworks

```rust
let report = lab(seed).run(/* ... */);
std::fs::write("test-results.xml", report.to_junit_xml()).unwrap();
```

Most CI systems (Jenkins, GitHub Actions, GitLab CI) can parse JUnit XML for
test result visualization and failure tracking.

### Recommended CI Strategy

For CI pipelines, balance coverage with execution time:

```rust
#[test]
fn cancellation_injection_ci() {
    // Use environment variable for seed to enable reproduction
    let seed = std::env::var("CI_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

    println!("Using seed: {}", seed);

    // In CI, use RandomSample for speed; locally, use AllPoints for thoroughness
    let strategy = if std::env::var("CI").is_ok() {
        InjectionStrategy::RandomSample(10)
    } else {
        InjectionStrategy::AllPoints
    };

    let report = lab(seed)
        .with_cancellation_injection(strategy)
        .with_all_oracles()
        .run(|injector| {
            InstrumentedFuture::new(my_critical_operation(), injector)
        });

    if !report.all_passed() {
        // Output JSON for CI parsing
        eprintln!("{}", serde_json::to_string_pretty(&report.to_json()).unwrap());
        panic!("Cancellation injection tests failed. Seed: {}", seed);
    }
}
```

## Troubleshooting

### Test Hangs

**Symptom**: Test never completes.

**Cause**: The instrumented future entered an infinite loop or deadlock.

**Fix**: Set `max_steps` on the lab builder:

```rust
lab(42)
    .max_steps(10000)  // Fail after 10000 steps
    .run(/* ... */);
```

### Non-Deterministic Failures

**Symptom**: Same seed gives different results.

**Cause**: Code uses real time, random numbers, or non-deterministic I/O.

**Fix**: Ensure all randomness and time comes from the lab runtime's virtual clock.

### Too Many Await Points

**Symptom**: Test takes too long with AllPoints.

**Cause**: Complex futures with many await points.

**Fix**: Use `RandomSample` or `FirstN` for routine CI, AllPoints for release validation.

## API Reference

### Key Types

#### AwaitPoint

Identifies a specific await point within a task:

```rust
pub struct AwaitPoint {
    /// The task this await point belongs to (optional).
    pub task_id: Option<TaskId>,
    /// The sequential number of this await point (1-based).
    pub sequence: u64,
    /// Optional source location (file:line) for debugging.
    pub source_location: Option<String>,
}

// Creation
let point = AwaitPoint::new(Some(task_id), 5);
let anonymous = AwaitPoint::anonymous(10);  // No task association
let with_location = AwaitPoint::anonymous(5).with_source("src/lib.rs:42");
```

#### InstrumentedFuture

Wraps any future to track await points:

```rust
pub struct InstrumentedFuture<F> {
    inner: F,
    injector: Arc<CancellationInjector>,
    await_counter: u64,
    // ...
}

// Creation
let instrumented = InstrumentedFuture::new(my_future, injector);
let recording = InstrumentedFuture::recording(my_future);

// Inspection
instrumented.await_count()      // Current await counter
instrumented.was_cancelled()    // Whether cancellation was injected
instrumented.injection_point()  // Which point was injected (if any)
instrumented.injector()         // Reference to the injector
```

Output type wraps the inner future's result:

```rust
pub enum InstrumentedPollResult<T> {
    /// The inner future returned this result.
    Inner(T),
    /// Cancellation was injected at this await point.
    CancellationInjected(u64),
}
```

#### CancellationInjector

Controls when and where cancellation is injected:

```rust
// Recording mode - tracks await points without injecting
let injector = CancellationInjector::recording();

// Inject at specific sequence number
let injector = CancellationInjector::inject_at(3);

// Inject at specific await point (task-aware)
let injector = CancellationInjector::inject_at_point(await_point);

// Inject at every Nth await point
let injector = CancellationInjector::inject_every_nth(4);

// Custom strategy
let injector = CancellationInjector::with_strategy(InjectionStrategy::FirstN(5));

// Query recorded points
let points: Vec<u64> = injector.recorded_points();
let count: u64 = injector.injection_count();
injector.clear_recorded();  // Reset for reuse
```

#### InjectionRunner (Low-Level)

Orchestrates recording and injection phases without Lab integration:

```rust
let mut runner = InjectionRunner::new(42);  // seed

// Full control over polling
let report = runner.run_with_injection(
    InjectionStrategy::AllPoints,
    |injector| InstrumentedFuture::new(my_future(), injector),
    |instrumented| {
        // Custom poll logic
        let result = poll_to_completion(instrumented);
        match result {
            InstrumentedPollResult::Inner(_) => InjectionOutcome::Success,
            InstrumentedPollResult::CancellationInjected(_) => InjectionOutcome::Success,
        }
    },
);

// Simpler interface
let report = runner.run_simple(
    InjectionStrategy::FirstN(5),
    |injector| InstrumentedFuture::new(my_future(), injector),
    |result| matches!(result, InstrumentedPollResult::Inner(_) | InstrumentedPollResult::CancellationInjected(_)),
);
```

#### LabInjectionConfig

Configuration for Lab-integrated injection testing:

```rust
let config = LabInjectionConfig::new(42)       // seed
    .with_strategy(InjectionStrategy::AllPoints)
    .with_all_oracles()                         // Enable oracle verification
    .stop_on_failure(true)                      // Stop at first failure
    .max_steps_per_run(10_000);                 // Prevent infinite loops

// Query
config.seed()       // u64
config.strategy()   // &InjectionStrategy
```

#### LabInjectionRunner

Runner with Lab runtime and oracle integration:

```rust
let mut runner = LabInjectionRunner::new(config);

// Simple interface
let report = runner.run_simple(|injector| {
    InstrumentedFuture::new(my_future(), injector)
});

// Full Lab access
let report = runner.run_with_lab(|injector, runtime, oracles| {
    // Access runtime state, register with oracles
    InstrumentedFuture::new(my_future(), injector)
});

runner.current_mode()  // InjectionMode::Recording or InjectionMode::Injecting
runner.config()        // &LabInjectionConfig
```

#### LabInjectionReport

Extended report with oracle violations:

```rust
pub struct LabInjectionReport {
    pub total_await_points: usize,
    pub tests_run: usize,
    pub successes: usize,
    pub failures: usize,
    pub results: Vec<LabInjectionResult>,
    pub strategy: String,
    pub seed: u64,
}

// Query
report.all_passed()         // bool
report.failures()           // Vec<&LabInjectionResult>
report.categorize_failures() // (injection_failures, oracle_failures)

// Output
report.to_json()       // serde_json::Value
report.to_junit_xml()  // String
report.display()       // LabInjectionReportDisplay (implements Display)
format!("{}", report)  // Human-readable output
```

#### LabInjectionResult

Individual test result with oracle information:

```rust
pub struct LabInjectionResult {
    pub injection: InjectionResult,
    pub oracle_violations: Vec<OracleViolation>,
}

result.is_success()  // Both injection and oracles passed
result.reproduction_code(seed)  // Rust code to reproduce this failure
```

#### InjectionOutcome

Classification of test results:

```rust
pub enum InjectionOutcome {
    Success,                    // Handled correctly
    Panic(String),              // Panicked
    AssertionFailed(String),    // Assertion failed
    Timeout,                    // Timed out
    ResourceLeak(String),       // Resource leaked
}
```

### Module Structure

```
asupersync::lab
├── mod.rs                      # Re-exports
├── instrumented_future.rs      # Core injection framework
│   ├── AwaitPoint
│   ├── InstrumentedFuture<F>
│   ├── InstrumentedPollResult<T>
│   ├── CancellationInjector
│   ├── InjectionStrategy
│   ├── InjectionMode
│   ├── InjectionRunner
│   ├── InjectionReport
│   ├── InjectionResult
│   └── InjectionOutcome
├── injection.rs                # Lab runtime integration
│   ├── LabInjectionConfig
│   ├── LabInjectionRunner
│   ├── LabInjectionReport
│   ├── LabInjectionResult
│   ├── LabBuilder
│   └── lab()
└── oracle/                     # Verification oracles
    ├── OracleSuite
    ├── TaskLeakOracle
    ├── QuiescenceOracle
    ├── LoserDrainOracle
    ├── ObligationLeakOracle
    ├── FinalizerOracle
    └── DeterminismOracle
```

### Fluent API Quick Reference

```rust
use asupersync::lab::injection::lab;

lab(seed)                                           // Create builder
    .with_cancellation_injection(strategy)          // Set strategy
    .with_all_oracles()                             // Enable oracles
    .stop_on_failure(true)                          // Stop on first failure
    .max_steps(10_000)                              // Prevent hangs
    .run(|injector| /* ... */)                      // Simple run
    .run_with_lab(|injector, runtime, oracles| /* ... */) // Full Lab access
```

## See Also

- [Macro DSL](./macro-dsl.md) - Structured concurrency macros
- Source: [`lab::injection`](../src/lab/injection.rs)
- Source: [`lab::instrumented_future`](../src/lab/instrumented_future.rs)
- Source: [`lab::oracle`](../src/lab/oracle/mod.rs)
