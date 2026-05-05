# Runtime Wait-Cause Remediation Contract

Bead: `asupersync-d87ytw.12`

## Purpose

This contract turns runtime wait diagnostics into deterministic operator remediation reports. A raw deadlock, future wait, or obligation row is not enough for a large swarm: the operator needs a ranked root cause, evidence references, safe next actions, and explicit warnings about actions that would destroy evidence.

The contract composes existing observability surfaces instead of inventing a second diagnostic stack:

1. Directional wait-for cycles come from `DirectionalDeadlockReport`.
2. Task-level waits come from `TaskBlockedExplanation` through `WaitCauseTaskEvidence`.
3. Obligation metadata comes from `ObligationLeak` through `WaitCauseObligationEvidence`.
4. Tail taxonomy linkage uses `runtime-tail-latency-taxonomy-v1`.
5. Verification and report construction live in `src/observability/diagnostics.rs`.
6. Machine-readable requirements live in `artifacts/runtime_wait_cause_remediation_v1.json`.

## Verifier Inputs

Each evidence packet carries:

- `report_id`
- `scenario_id`
- `replay_command`
- `tail_taxonomy_version`
- optional directional deadlock report
- zero or more task wait rows
- zero or more obligation leak rows
- evidence references for artifacts, certificates, or source snapshots

The verifier refuses empty report ids, empty scenario ids, missing replay commands, wrong tail taxonomy versions, and packets with no wait-cause evidence.

## Report Verdicts

### Actionable

`actionable` means the report contains at least one strong root cause: a deadlock cycle, futurelock, or obligation leak.

### Investigate

`investigate` means the evidence is structurally valid, but every finding is an `unknown_wait`. The report still emits safe next actions, but it does not pretend to know the root cause.

### Refused

`refused` means the evidence packet is off-contract. The report is fail-closed, contains no findings, and exposes a stable refusal reason.

## Finding Categories

The stable categories are:

1. `deadlock_cycle`
2. `futurelock`
3. `obligation_leak`
4. `unknown_wait`

Findings are ranked deterministically by severity, confidence, category, blocked resource, and owner task. Trapped deadlock cycles outrank obligation leaks, futurelocks, and unknown waits.

## Safe Action Policy

Every finding includes non-destructive safe actions and forbidden actions. Safe actions emphasize evidence capture, replay/minimization, ownership inspection, and protocol-level obligation resolution. Forbidden actions explicitly reject deleting files, resetting git state, discarding trace artifacts, or killing unknown tasks/processes before ownership is known.

## Fail-Closed Rules

The report builder refuses:

- empty report ids
- empty scenario ids
- missing replay commands
- wrong tail taxonomy contract versions
- evidence packets with no deadlock, task wait, or obligation rows

Refusal returns `refused` with zero findings. It never emits actionable remediation from incomplete evidence.

## Redaction

Operator-supplied blocked-resource text is sanitized before entering findings. Control characters are stripped, path-like tokens become `[redacted-path]`, and identity-like tokens become `[redacted-identity]`. Evidence references remain intact so report rows can still point to checked-in artifacts.

## Smoke Runner

The deterministic runner is `scripts/run_wait_cause_remediation_smoke.sh`.

It exercises:

1. An actionable report with a trapped wait cycle, futurelock, and obligation leak.
2. An investigate report with only an unknown wait.
3. A refused report with missing replay metadata and a wrong taxonomy version.

Each execute-mode run logs:

- scenario id
- report id and hash
- wait-cause graph hash
- tail taxonomy version
- verdict and refusal reason
- ranked finding categories and severities
- confidence basis points
- blocked resources
- owner task and region ids
- safe actions
- forbidden action disclaimer
- artifact path
- replay command

The runner routes the Rust proof through `rch` and writes a run report under the selected output root.

## Validation

Focused reproduction:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wait_cause_remediation cargo test -p asupersync --test runtime_wait_cause_remediation_contract --features test-internals -- --nocapture
```

Smoke reproduction:

```bash
bash scripts/run_wait_cause_remediation_smoke.sh --execute --output-root target/wait-cause-remediation-smoke
```

The invariant suite checks that:

1. The artifact matches the code-backed schema constants.
2. Required report and finding fields are present.
3. All categories are represented by the artifact.
4. The verifier emits actionable, investigate, and refused reports.
5. The runner supports list, dry-run, and rch-backed execute modes.

## Cross-References

- `src/observability/diagnostics.rs`
- `src/observability/mod.rs`
- `artifacts/runtime_wait_cause_remediation_v1.json`
- `artifacts/runtime_latency_budget_certificate_v1.json`
- `artifacts/runtime_tail_latency_taxonomy_v1.json`
- `tests/runtime_wait_cause_remediation_contract.rs`
- `tests/runtime_latency_budget_certificate_contract.rs`
- `tests/runtime_tail_latency_taxonomy_contract.rs`
- `scripts/run_wait_cause_remediation_smoke.sh`
