# Deterministic Testing And Failure Forensics

This is one of Asupersync's strongest differentiators. Build it into the development loop, not just the incident-response loop.

## Test Ladder

Use the lightest tool that still proves the invariant:

1. `test_utils::run_test(...)` / `run_test_with_cx(...)` for ordinary async tests.
2. `LabRuntime` for concurrency-sensitive behavior.
3. Scenario-based lab runs when you need recurring chaos/failure matrices.
4. Crashpack/replay artifacts when a failure deserves long-lived forensic value.

## Domain-Specific Test Targets

| Migration Slice | Test Focus |
|-----------------|------------|
| runtime / spawn / cancellation | task leaks, loser drain, region quiescence |
| channels / sync | obligation leaks, cancellation safety, waiter cleanup |
| I/O / net | cancel during read/write, lost wakeups, deterministic harnesses where possible |
| web / HTTP / gRPC | request lifecycle, middleware behavior, drain on shutdown |
| database | cancellation mid-query, transaction cleanup, pool lifecycle |
| browser / wasm | canonical browser examples, runtime guardrails, package diagnostics |

## Start With Deterministic Helpers

For day-to-day replacement of `#[tokio::test]` style bootstraps:

- `test_utils::run_test(...)`
- `test_utils::run_test_with_cx(...)`

These should be your default unless the test needs stronger scheduling control.

## Reach For `LabRuntime` Early

Use `LabRuntime` and `LabConfig` when the code involves:

- cancellation-sensitive cleanup,
- races,
- retry/timeout orchestration,
- network timing,
- actor/supervision behavior,
- obligation resolution,
- quiescence guarantees.

Minimal shape:

```rust,ignore
let lab = LabRuntime::new(
    LabConfig::new(42)
        .panic_on_leak(true)
        .futurelock_max_idle_steps(10_000)
        .panic_on_futurelock(true)
        .capture_trace(true),
);
```

## The Invariants That Must Become Concrete

Do not mark a migration "done" until tests make these explicit:

- no orphan tasks,
- region close implies quiescence,
- no obligation leaks,
- losers are drained after races,
- cancellation follows request -> drain -> finalize,
- blocking work and external resources shut down cleanly.

## Use Oracles As Gates

Asupersync has a real oracle suite. Use it.

At minimum, care about:

- quiescence,
- obligation leaks,
- loser drain,
- cancellation protocol,
- deterministic replay where relevant.

Use report-based oracle checks. For lab runs, inspect `LabRunReport`:
`report.lab_test_passed()`, `report.oracle_report.all_passed()`, and
`report.oracle_report.entry("quiescence")` /
`entry("obligation_leak")` when a specific invariant matters. The broader
lab/oracle suite also tracks loser-drain and cancellation-protocol invariants.
Use those as regression guards, not just informational reports.

If the migrated slice is supposed to be strict, make the test prove it instead
of trusting review intuition.

Relevant sources:

- `src/lab/oracle/`
- `src/lab/runtime.rs`
- `tests/e2e/combinator/cancel_correctness/`

## Chaos Presets Matter

Do not hand-roll flaky randomness.

Use:

- `with_light_chaos()` for CI-friendly signal,
- `with_heavy_chaos()` for deeper shakeout,
- `with_chaos(...)` for focused campaigns,
- fixed seeds for exact reproduction.

Relevant example:

- `examples/chaos_testing.rs`

Use chaos when you want evidence about cleanup and scheduler behavior, not when
you want to replace deterministic reasoning with noise.

## Futurelock Is A First-Class Detector

`futurelock` is not "task ran longer than N seconds."

It means a task:

- still holds obligations,
- is not making poll progress,
- has crossed the configured idle-step threshold.

That makes it ideal for catching shutdown wedges and leaked cleanup responsibility.

High-value knobs:

- `futurelock_max_idle_steps(...)`
- `panic_on_futurelock(...)`

Treat futurelock failures as design bugs until proven otherwise. They usually
mean a task is awaiting while still owning obligation-bearing state.

## Preserve Failure Artifacts

When a concurrency failure matters, keep:

- seed,
- trace fingerprint,
- oracle failures,
- crashpack path,
- replay command metadata.

Crashpacks are worth preserving because they turn a vague failure into a deterministic repro anchor.

Also preserve:

- replay command,
- CI artifact pointer,
- scenario id if the failure came from a scenario-based run.

Relevant source:

- `src/trace/crashpack.rs`

## Scenario-Based Testing

When the failure mode is bigger than a unit test, codify it as a lab scenario.

The repo already carries reusable scenario YAML for:

- heavy chaos,
- partitions,
- host crash / restart,
- clock skew / lease behavior,
- cancellation campaigns.

Use this style when the downstream system has recurring operational regimes that deserve named, repeatable validation.

Relevant paths:

- `examples/scenarios/*.yaml`
- `src/lab/scenario.rs`
- `src/lab/scenario_runner.rs`

## Network And Distributed Test Advice

- Use deterministic network surfaces like `VirtualTcp` when you need network behavior without kernel nondeterminism.
- Do not depend on ambient time or randomness; prefer `cx.now()` and `cx.random_u64()`.
- For distributed logic, test quorum loss, recovery, and cancellation explicitly instead of assuming the happy path plus retries is enough.

## Evidence-Ledger And Diagnostics Workflow

When a failure is subtle:

1. capture the seed and trace,
2. inspect oracles,
3. inspect futurelock and held-obligation details,
4. use structured diagnostics and task inspection,
5. preserve the crashpack,
6. only then add more instrumentation.

Relevant deep sources:

- `src/lab/oracle/evidence.rs`
- `src/observability/diagnostics.rs`
- `src/observability/task_inspector.rs`
- `README.md`

## Avoid These Failure Patterns

- `std::time::Instant::now()` inside deterministic test logic,
- ambient RNG,
- tests that only assert "it didn't panic",
- detached tasks that are never joined or drained,
- migrations that port production code but leave Tokio-era tests untouched.

## Forensics Workflow

When a concurrency bug is suspected:

1. reproduce under `LabRuntime` with a fixed seed,
2. enable trace capture and futurelock detection,
3. inspect oracle failures and drain/quiescence behavior,
4. preserve crashpack/replay artifacts if the issue is nontrivial,
5. only then widen the test campaign or add heavier chaos.

## Practical Migration Rule

Every major migrated slice should gain at least one deterministic regression test proving:

- the native replacement works,
- cancellation is observable,
- cleanup completes,
- ownership is explicit,
- the relevant oracle stays green.
