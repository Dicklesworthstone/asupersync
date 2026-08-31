# Deterministic Testing And Failure Forensics

This is one of Asupersync's strongest differentiators. Build it into the development loop, not just the incident-response loop.

Start with `TESTING_FOR_AGENTS.md` (repo root): it is the decision-tree entry
point for choosing a test shape. `TESTING.md` holds the full contracts.

## Table of Contents

- [Test Ladder](#test-ladder)
- [Domain-Specific Test Targets](#domain-specific-test-targets)
- [Start With Deterministic Helpers](#start-with-deterministic-helpers)
- [Reach For `LabRuntime` Early](#reach-for-labruntime-early)
- [The Invariants That Must Become Concrete](#the-invariants-that-must-become-concrete)
- [Use Oracles As Gates](#use-oracles-as-gates)
- [Native Cancellation Boundaries Are A Release Gate](#native-cancellation-boundaries-are-a-release-gate)
- [Proof Admission And External-Consumer Evidence](#proof-admission-and-external-consumer-evidence)
- [Exact `ForcedSchedule` Workflow](#exact-forcedschedule-workflow)
- [Chaos Presets Matter](#chaos-presets-matter)
- [Futurelock Is A First-Class Detector](#futurelock-is-a-first-class-detector)
- [Preserve Failure Artifacts](#preserve-failure-artifacts)
- [Scenario-Based Testing](#scenario-based-testing)
- [Network And Distributed Test Advice](#network-and-distributed-test-advice)
- [Evidence-Ledger And Diagnostics Workflow](#evidence-ledger-and-diagnostics-workflow)
- [Avoid These Failure Patterns](#avoid-these-failure-patterns)
- [Forensics Workflow](#forensics-workflow)
- [Escaped Defects Need Receipts](#escaped-defects-need-receipts)
- [Practical Migration Rule](#practical-migration-rule)

## Test Ladder

Use the lightest tool that still proves the invariant:

1. `test_utils::run_test(...)` / `run_test_with_cx(...)` for ordinary async tests.
2. `LabRuntime` for concurrency-sensitive behavior.
3. Native runtime worker tests for real wakeup, local-lane, cross-thread, or
   shutdown behavior that Lab cannot prove.
4. Exact `ForcedSchedule` capture/replay for a known deterministic Lab run.
5. Scenario-based lab runs when you need recurring chaos/failure matrices.
6. Crashpack/replay artifacts when a failure deserves long-lived forensic value.

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

Attribute macros also exist (`asupersync-macros`): `#[asupersync::test]` runs on
the production runtime; `#[lab_test]` (including
`#[asupersync::lab_test(seeds = A..B)]` for seed matrices) runs on the
deterministic lab runtime.

These should be your default unless the test needs stronger scheduling control.

They are not a local-task executor. `spawn_local` requires a scheduler-worker
TLS lane owned by the same runtime. For a `!Send` future, enter a worker using
`runtime.block_on(runtime.handle().spawn(async { ... }))`, obtain
`Cx::current()` there, acquire the non-Send guard inside the local future, then
call `spawn_local`.

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
        .trace_capacity(16_384),
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
`entry("obligation_leak")` when a specific invariant matters. Other registered
entry names include `task_leak`, `region_leak`, `loser_drain`, and
`cancellation_protocol` (see `src/lab/oracle/` for the full registry).
Use those as regression guards, not just informational reports.

If the migrated slice is supposed to be strict, make the test prove it instead
of trusting review intuition.

Relevant sources:

- `src/lab/oracle/`
- `src/lab/runtime.rs`
- `tests/e2e/combinator/cancel_correctness/`

## Native Cancellation Boundaries Are A Release Gate

Lab and model tests do not prove that a real worker wakes a genuinely parked
future, or that a spawn wrapper publishes the exact nested result through
`TaskHandle`. Since v0.4.4, the native parked-task cancellation lane
(`tests/runtime_abort_vs_cancel_semantics_audit.rs`, manifest lane
`native-parked-task-cancellation`, run first by `scripts/run_proof_checks.sh`)
is a release-blocking behavioral contract. Any change to `Cx`, `TaskHandle`,
scheduler cancellation wakeup, spawn wrappers, or cancel-aware primitives must
run that lane; a red, zero-test, filtered, or skipped result blocks release.
See "Do not model away a native cancellation boundary" in
`TESTING_FOR_AGENTS.md`.

The permanent regression shape is:

1. enter the same execution class the consumer used (including a true local
   worker for `!Send` tasks),
2. prove the task reached the blocked/parked state without a timing sleep,
3. abort/cancel through the public API,
4. assert the exact outer join plus inner operation result,
5. assert waiter/timer/task/region/obligation cleanup and no late work.

`OwnedMutexGuard` can solve a `Send` bound, but it does not prove cancellation
delivery. `Sleep` cancellation resolves its `()` output; timeout/deadline
classification belongs to the surrounding combinator.

## Proof Admission And External-Consumer Evidence

Do not confuse proof admission with proof execution. For a remote-required
lane, a worker assignment, PID, queue entry, admission receipt, preflight or
resource/toolchain refusal, `exit 103`, and any local-fallback banner all mean
zero admissible executed tests. Cite the lane only after terminal remote output
from the exact snapshot shows a positive count for every named sentinel and
zero failed, ignored, measured, or filtered tests.

Interpret repository proof through three separate objects:

1. `artifacts/proof_lane_manifest_v1.json` defines the exact command,
   guarantee, resource envelope, and explicit no-claims.
2. `artifacts/proof_status_snapshot_v1.json` records freshness and known
   validation-frontier blockers.
3. A terminal receipt from the admitted environment proves whether that command
   actually ran and how many named cases passed.

A structural artifact-contract test proves only its declared schema/docs
surface. It cannot promote itself into broad runtime, performance, workspace,
or release evidence.

Crate-internal tests can see `cfg(test)` helpers and a dependency graph that real
users do not. Compile the relevant public API and feature profiles through an
actual external-consumer manifest as a separate gate. Resolve that consumer by
manifest or explicit configuration, never by assuming checkout authority from
`/dp`, `/data/projects`, or an RCH worker's hashed checkout path. An incomplete
portfolio mount is a bounded external blocker, not a worker-lottery test result.

For feature-wide compiler and lint frontiers, preserve `--all-targets
--all-features --keep-going`; a fail-fast run can hide the rest of a large error
frontier and is not an honest inventory. Narrower commands remain appropriate
only when the live proof manifest or task scope deliberately narrows the claim.

## Exact `ForcedSchedule` Workflow

The public family lives under `asupersync::lab::runtime`, not entirely under the
short `asupersync::lab` re-export path.

1. Create a fresh `LabRuntime` with the intended `LabConfig`.
2. Call `start_forced_schedule_recording(max_dispatches)` before any
   schedule-relevant step.
3. Drive the source run to the intended terminal/quiescent point.
4. Call `finish_forced_schedule_recording()`; truncation fails closed instead of
   returning a partial schedule.
5. Persist with `to_canonical_bytes()` if needed.
6. Decode untrusted bytes only through `try_from_canonical_bytes(bytes,
   ForcedScheduleDecodeLimits::new(max_encoded_bytes, max_dispatches,
   max_decoded_dispatch_bytes))` with caller-controlled bounds.
7. Recreate the workload on a fresh compatible Lab runtime and call
   `run_forced_schedule(&schedule,
   ForcedScheduleLimits::new(max_dispatches, max_steps))`.

There is no RNG fallback. The schedule binds task generation, worker, lane,
step, virtual time, and terminal certificate. SHA-256 is integrity against
corruption, not authentication. Deletion-only candidates cannot synthesize new
choices and are minimization substrate only; their execution report does not
prove that the original failure survives.

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

1. reproduce the consumer-visible API sequence in the same execution class,
2. for native wakeup, parked-task, local-lane, shutdown, or cancellation
   delivery bugs, keep a native-runtime reproducer as the authoritative test,
3. add a fixed-seed `LabRuntime` model when it can explore the same invariant,
4. enable trace capture and futurelock detection,
5. inspect oracle failures and drain/quiescence behavior,
6. preserve crashpack/replay artifacts if the issue is nontrivial,
7. only then widen the test campaign or add heavier chaos.

## Escaped Defects Need Receipts

For a defect that escaped to users, AGENTS.md's escaped-defect protocol applies:
reproduce at the consumer-visible boundary, prove the test reached the failing
state (an observable parked/queued/owned state, not a sleep), assert the exact
result shape and cleanup invariants, and preserve an old-code-red plus
repaired-code-green receipt before closing. Removing or weakening such a
reproducer, its state witness, or its exact oracle requires explicit written
user approval.

## Practical Migration Rule

Every major migrated slice should gain regression coverage proving:

- the native replacement works,
- cancellation is observable,
- cleanup completes,
- ownership is explicit,
- the relevant oracle stays green.

Use deterministic Lab coverage where the model is authoritative, and add the
native worker/socket/runtime lane whenever the claim depends on native polling,
wakeup, thread-local ownership, or shutdown behavior.
