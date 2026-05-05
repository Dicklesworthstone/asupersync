# Runtime Latency-Budget Certificate Contract

Bead: `asupersync-d87ytw.2`

## Purpose

This contract turns compact tail-causal attribution rows into an operator-facing latency-budget certificate. It is the first proof surface that can say whether a candidate controller or profile preserves tail latency, should fall back with a no-win verdict, or must fail closed because the evidence is weak.

The contract is intentionally grounded in the existing tail taxonomy instead of adding another vocabulary:

1. Compact input rows come from `TailLatencyCompactEvent`.
2. Verification lives in `src/observability/diagnostics.rs`.
3. The machine-readable contract is `artifacts/runtime_latency_budget_certificate_v1.json`.
4. Invariants and the smoke report live in `tests/runtime_latency_budget_certificate_contract.rs`.

## Verifier Inputs

Each certificate input carries:

- `certificate_id`
- `scenario_id`
- `candidate_id`
- `fallback_profile`
- `replay_command`
- sample count and evidence epoch
- p50, p95, p99, and p999 latency quantiles
- lower and upper uncertainty bounds
- baseline and candidate p999 values for asymmetric regression checks
- p999 budget, sample-size, calibration, unknown-residual, and regression gates
- compact tail events backed by `runtime-tail-latency-taxonomy-v1`

Mean-only evidence is not accepted. A verifier caller must provide quantiles and uncertainty bounds, because controllers need tail behavior and confidence, not a single average.

## Verdicts

### Pass

`pass` means the evidence is current, sufficiently sampled, includes direct-duration tail evidence, preserves the unknown residual, and keeps p999 plus uncertainty inside the requested budget.

### No-Win

`no_win` means the evidence is structurally valid, but the conservative fallback is safer. Current no-win rules are:

- `p999_budget_exceeded`
- `unknown_residual_above_limit`
- `unknown_fraction_above_limit`
- `asymmetric_regression_gate`

### Fail Closed

`fail_closed` means the evidence is not safe to use for a runtime decision. The verifier refuses:

- missing compact tail events
- missing required fields
- missing canonical terms
- hidden or contradictory unknown buckets
- proxy-only green rows
- mean-only evidence
- missing or invalid uncertainty bounds
- insufficient sample counts
- stale calibration
- wrong compact-event schema or taxonomy version
- missing certificate ids, scenario ids, candidate ids, fallback profiles, or replay commands

## Term Breakdown

Every certificate includes a deterministic term breakdown in taxonomy order:

1. `queueing`
2. `service`
3. `io_or_network`
4. `retries`
5. `synchronization`
6. `allocator_or_cache`
7. `unknown`

The breakdown keeps direct-duration evidence distinct from proxy signals. `retries` and `synchronization` can carry direct nanosecond durations in the compact core. Queueing, service, I/O or network, and allocator/cache rows are proxy signals unless a later contract adds direct duration producers. The `unknown` row is always an explicit unknown bucket, never an omitted field.

## Fail-Closed Rules

Fail-closed reason codes are stable and machine-readable. They identify evidence that cannot be used for a runtime decision at all: missing fields, missing terms, hidden unknown residuals, proxy-only green rows, mean-only evidence, stale calibration, invalid uncertainty, insufficient samples, wrong schemas, or missing decision identity and replay metadata.

## No-Win Rules

No-win reason codes are valid evidence with a conservative outcome: the candidate exceeded p999 budget after uncertainty, carried too much unknown residual, had too large an unknown fraction, or regressed against the baseline beyond the asymmetric gate.

## Unknown Residual Policy

Unknown contribution is part of the certificate, not a footnote. The verifier compares both total unknown nanoseconds and unknown basis points against configured gates. Missing producers are allowed only when the unknown bucket remains visible and the resulting evidence still passes the no-win gates.

## Smoke Runner

The deterministic runner is `scripts/run_latency_budget_certificate_smoke.sh`.

It exercises:

1. A passing certificate with direct retry and synchronization evidence.
2. A no-win certificate where valid evidence still exceeds the p999/regression gates.
3. A fail-closed certificate with stale mean-only evidence.

Each execute-mode run logs:

- certificate id and hash
- scenario id
- candidate id, fallback profile, and taxonomy version
- p50, p95, p99, and p999
- p999 budget
- term breakdown
- uncertainty interval
- sample count
- unknown residual
- fallback reason
- replay command

The runner routes the Rust proof through `rch` and writes a run report under the selected output root.

## Validation

Focused reproduction:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_latency_budget_certificate cargo test -p asupersync --test runtime_latency_budget_certificate_contract --features test-internals -- --nocapture
```

Smoke reproduction:

```bash
bash scripts/run_latency_budget_certificate_smoke.sh --execute --output-root target/latency-budget-certificate-smoke
```

The invariant suite checks that:

1. The artifact matches the code-backed schema constants.
2. The term breakdown covers every taxonomy term.
3. Required smoke report fields include quantiles, uncertainty, unknown residual, fallback reason, and replay command.
4. The verifier emits pass, no-win, and fail-closed certificates.
5. The runner supports list, dry-run, and rch-backed execute modes.

## Cross-References

- `src/observability/diagnostics.rs`
- `src/observability/mod.rs`
- `artifacts/runtime_latency_budget_certificate_v1.json`
- `artifacts/runtime_tail_latency_taxonomy_v1.json`
- `tests/runtime_latency_budget_certificate_contract.rs`
- `tests/runtime_tail_latency_taxonomy_contract.rs`
- `scripts/run_latency_budget_certificate_smoke.sh`
- `scripts/run_tail_causal_attribution_emitters_smoke.sh`
