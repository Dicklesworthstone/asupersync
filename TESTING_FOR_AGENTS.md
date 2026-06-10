# Testing For Agents

This is the compressed testing router for agents working in this repo. Use it
to choose the right test shape quickly, then fall back to `TESTING.md`,
`docs/replay-debugging.md`, and the module under test for full contracts.

Heavy Cargo work must run through `rch exec -- env CARGO_TARGET_DIR=... cargo`.
Do not run broad local Cargo validation because shared agent sessions can starve
the workstation and the RCH fleet.

## Decision Tree

| Claim | Use | Anchor |
| --- | --- | --- |
| Pure function, parser, state transition, error mapping | Inline unit test | `src/*` module `#[cfg(test)]` |
| Cancellation, task ownership, obligation, virtual time | Lab integration test | `src/lab/*`, `src/test_utils.rs` |
| Same invariant across seed/config matrix | Lab test macro recipe | `asupersync-lab-dx-v2-n2v2fi.1` until `#[lab_test]` lands |
| Schedule sensitivity, DPOR, seed search, replay equivalence | Exploration test | `src/lab/explorer.rs`, `src/lab/replay.rs` |
| User-visible workflow across modules | Scenario YAML or e2e script | `examples/scenarios/*.yaml`, `scripts/run_all_e2e.sh` |

If a bead changes production behavior, add the narrowest unit or lab proof first.
Only then run broader gates. If a proof lane is already active or
progress-stale, coordinate by Agent Mail before starting another RCH job.

## Required Metadata

Every new deterministic test or script should expose these in the test name,
artifact, or closeout note:

- `bead_id`: owning bead or explicit `N/A`
- `scenario_id`: stable, grep-friendly scenario token
- `seed_or_fixture`: fixed seed, fixture path, or why none is needed
- `command`: exact RCH-wrapped replay command
- `artifact_path`: summary JSON, NDJSON log, crashpack, or replay pointer
- `expected_outcome`: `pass`, `fail`, `blocked`, `unsupported`, or `no_win`

Use `ASUPERSYNC_TEST_ARTIFACTS_DIR=target/test-artifacts/agent-lane` when a test
emits repro bundles. E2E suites should write under their
`target/e2e-results/$SUITE` directory.

## Recipe 1: Oracle Unit Test

Use this for local invariants that do not need real scheduler interleavings.
Keep the test inline with the module it protects.

```rust
#[test]
fn scenario_id_happy_and_edge_cases() {
    let input = build_fixture();
    let observed = check_invariant(&input);
    assert_eq!(observed.verdict(), Expected::Pass);
}
```

Backed by compiling tests: `src/lab/fuzz.rs` regression-corpus unit tests and
`src/lab/scenario.rs` validation tests.

Run:

```bash
TEST_FILTER=lab::fuzz
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_agents_unit" cargo test --lib --features test-internals "$TEST_FILTER" -- --nocapture
```

## Recipe 2: Lab Integration Test

Use this for cancellation, virtual-time, region, and obligation behavior. Prefer
`run_test_with_cx` when the tested API expects a `Cx`; use direct `LabRuntime`
only when you need scheduler or trace control.

```rust
#[test]
fn scenario_id_cancel_path_is_clean() {
    asupersync::test_utils::run_test_with_cx(|cx| async move {
        let outcome = exercise_cancel_path(&cx).await;
        assert!(outcome.is_ok(), "scenario_id failed: {outcome:?}");
    });
}
```

Backed by compiling code: `src/test_utils.rs::{run_test, run_test_with_cx}` and
lab runtime tests under `src/lab/runtime.rs`.

Run:

```bash
TEST_FILTER=cancel_path_is_clean
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_agents_lab" cargo test --lib --features test-internals "$TEST_FILTER" -- --nocapture
```

## Recipe 3: Lab Test Matrix

The planned `#[lab_test]` attribute is tracked by
`asupersync-lab-dx-v2-n2v2fi.1`. Until it lands, spell out the matrix as ordinary
tests with fixed seeds and shared helper functions.

```rust
#[test]
fn scenario_id_seed_matrix() {
    for seed in [1_u64, 2, 13, 55] {
        let mut lab = asupersync::lab::LabRuntime::new(asupersync::lab::LabConfig::new(seed));
        let report = run_scenario(&mut lab);
        assert!(report.passed(), "seed={seed} report={report:?}");
    }
}
```

Backed by compiling code: seed and replay tests in `src/lab/scenario_runner.rs`
and deterministic corpus tests in `src/lab/fuzz.rs`.

Run:

```bash
TEST_FILTER=seed_matrix
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_agents_seed_matrix" cargo test --lib --features test-internals "$TEST_FILTER" -- --nocapture
```

When the attribute lands, migrate the helper body behind the macro rather than
changing the scenario meaning.

## Recipe 4: Exploration And Replay

Use this when a bug depends on interleavings, seed search, or trace equivalence.
The closeout must include the seed range and replay command.

```rust
#[test]
fn scenario_id_explores_seed_space() {
    let scenario = build_scenario();
    let report = asupersync::lab::ScenarioRunner::explore_seeds(&scenario, 0, 16)
        .expect("seed exploration");
    assert!(report.all_passed(), "scenario_id report={report:?}");
}
```

Backed by compiling code: `src/lab/scenario_runner.rs` exploration tests,
`src/lab/replay.rs`, and `tests/frankenlab_integration.rs`.

Run:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_agents_explore" cargo test --lib --features test-internals scenario_runner -- --nocapture
```

If exploration finds a failure, preserve the smallest seed, the scenario hash,
and the normalized trace fingerprint in the bead notes.

## Recipe 5: Scenario YAML E2E

Use this for user-visible or cross-component workflows. Prefer an existing
scenario under `examples/scenarios/` and extend it only when the scenario
meaning truly changes.

```rust
let raw = std::fs::read_to_string("examples/scenarios/smoke_happy_path.yaml")?;
let scenario: asupersync::lab::Scenario = serde_yaml::from_str(&raw)?;
let result = asupersync::lab::ScenarioRunner::run(&scenario)?;
assert!(result.passed());
```

Backed by compiling code: `src/lab/scenario_runner.rs` module doctest and
`tests/frankenlab_integration.rs`.

Run one scenario-backed integration test:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_agents_scenario_yaml" cargo test --test frankenlab_integration --features test-internals -- --nocapture
```

Run an E2E suite only when the bead specifically owns that workflow:

```bash
SUITE=stub-resolution
rch exec -- bash scripts/run_all_e2e.sh --suite "$SUITE"
```

## Failure Forensics Loop

1. Capture the exact command, RCH build id if present, `CARGO_TARGET_DIR`, and
   dirty-tree state.
2. Find the artifact root: `ASUPERSYNC_TEST_ARTIFACTS_DIR`, `target/e2e-results`,
   or the suite-specific summary path.
3. Read `summary.json`, `repro_manifest.json`, and the primary NDJSON/event log.
4. Minimize only the scenario inputs or seed range. Do not rewrite unrelated
   fixtures or delete artifacts.
5. Replay with the smallest deterministic command, still through RCH:

```bash
TEST_FILTER=cancel_path_is_clean
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_agents_replay" ASUPERSYNC_TEST_ARTIFACTS_DIR=target/test-artifacts/agent-lane cargo test "$TEST_FILTER" --features test-internals -- --nocapture
```

6. Record the minimized seed, fixture path, artifact path, and first failing
   assertion in the bead before changing code.
7. After the fix, rerun the smallest repro first, then the nearest contract gate.

## Determinism Checklist

- Use virtual time or explicit fixture clocks; avoid wall-clock sleeps.
- Use fixed seeds and record them in the test name, artifact, or summary.
- Use deterministic maps/sets where output order is observed.
- Do not depend on thread scheduling unless the lab/explorer owns the schedule.
- Sort listings before asserting on public diagnostic output.
- Avoid ambient randomness, global env mutation, and process-wide tracing state
  unless the test holds the relevant repo helper lock or runtime subscriber.
- Do not make logs the assertion. Assert structured fields and keep logs as
  forensics.

## RCH Gotchas

- Always pass `CARGO_TARGET_DIR`; repeated commands in one lane can reuse the
  same isolated target dir.
- For full lib or all-target lanes, prefer link-light flags when the lane owner
  asks for them: `CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-C debuginfo=0"`.
- `active_project_exclusion` means another asupersync job owns admission. Check
  `rch queue --json` and coordinate before retrying.
- Heartbeat-live/progress-stale is not automatically a source failure. Wait,
  inspect queue metadata, and coordinate before canceling a build you do not own.
- If RCH falls back local, the result is not valid proof for a remote-required
  lane. Record it as degraded or blocked instead of green.
- `cargo fmt --check` may be rejected as non-compilation work; if so, use the
  repo-accepted local read-only formatter check on the touched files and say so.

## Closeout Shape

Use this compact closeout in bead notes or Agent Mail:

```text
Bead: <id>
Surface: unit|lab|explore|e2e|docs
Command: rch exec -- env CARGO_TARGET_DIR=... cargo ...
Artifact: <path or N/A>
Result: pass|blocked|degraded|not-run
Replay: <seed/fixture/filter or N/A>
Residual risk: <one sentence>
```

If this guide conflicts with `AGENTS.md`, `AGENTS.md` wins. If it conflicts with
`TESTING.md`, use `TESTING.md` for the detailed contract and update this router
afterward.
