# Swarm Pressure Preflight Report

`scripts/swarm_pressure_preflight_report.py` emits a deterministic, dry-run
operator report for deciding whether the shared-main checkout is ready to
dispatch proof lanes or release gates.

The report composes existing artifacts instead of replacing them:

- `artifacts/proof_lane_manifest_v1.json`
- `artifacts/proof_status_snapshot_v1.json`
- `artifacts/runtime_pressure_control_evidence_contract_v1.json`
- proof artifact freshness receipts from `scripts/proof_artifact_freshness_receipt.py`
- proof admission receipts from `scripts/proof_lane_admission_decision.py`
- dirty-tree ownership receipts from `scripts/dirty_tree_ownership_receipt.py`

It is non-mutating. It does not run Cargo, RCH, git mutations, Beads mutations,
Agent Mail sends, cache writes, staging, cleanup, or file deletion.

## Fixture Command

```bash
python3 scripts/swarm_pressure_preflight_report.py \
  --fixture tests/fixtures/swarm_pressure_preflight_report/mixed_pressure.json \
  --repo-path /data/projects/asupersync \
  --generated-at 2026-06-05T08:10:00Z \
  --output json
```

## E2E Logging Command

```bash
scripts/run_swarm_pressure_preflight_report_e2e.sh \
  --fixture tests/fixtures/swarm_pressure_preflight_report/mixed_pressure.json \
  --repo-path /data/projects/asupersync \
  --output-dir "${TMPDIR:-/tmp}/asupersync-swarm-pressure-preflight-e2e"
```

The E2E wrapper logs source artifact paths, versions, digests, proof-lane
envelope states, proof-status decisions, proof-freshness classifications,
admission decisions, pressure classes, dirty-tree blockers, aggregated blockers,
warnings, and the final operator decision.

For the full no-mock acceptance suite, run:

```bash
scripts/run_swarm_pressure_preflight_report_e2e.sh \
  --suite \
  --repo-path /data/projects/asupersync \
  --generated-at 2026-06-05T08:10:00Z \
  --output-dir "${TMPDIR:-/tmp}/asupersync-swarm-pressure-preflight-e2e"
```

The suite covers green workflow, stale exact-filter Cargo proofs that execute
zero tests, missing proof-lane resource envelopes, remote-required lanes
attempted through local fallback, peer-owned dirty-tree blockers, chaos
proof-lane pressure admission queueing, and combined multi-blocker output.

Each case logs its case id, fixture path, source artifact paths, proof-lane
commands, normalized resource envelope values, parsed exact-filter test counts,
dirty-path classifications, expected decision, actual decision, expected and
actual blocker/warning kinds, and the final blocker list. The wrapper also
writes `swarm_pressure_preflight_e2e_summary.json`, a stable JSON summary with
case-level pass/fail rows suitable for CI artifacts.

## Decisions

`preflight-pass` means all configured source artifacts loaded and no blockers or
warnings were found.

`preflight-attention` means no blocker was found, but at least one warning still
requires operator attention before citing proof. Typical examples are
`rerun-required` proof evidence or high pressure telemetry that suggests queuing
broad lanes.

`preflight-blocked` means at least one configured source proves a preflight
blocker, such as a missing proof-lane resource envelope, exact-filter proof that
ran zero tests, blocked proof status, failed admission decision, insufficient
disk headroom, or peer-owned dirty-tree release blocker.

## Proof Boundary

This report is current-source diagnosis, not behavioral correctness proof. It
proves the configured artifacts were parsed and aggregated consistently. Cargo
checks, clippy, tests, rustdoc, fuzzing, formal Lean builds, and release gates
still require their canonical RCH proof lanes before any behavioral correctness
or release-readiness claim.

## Validation

Rust contract test:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_swarm_pressure_preflight_report" \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS="-D warnings -C debuginfo=0" \
  cargo test -p asupersync --test swarm_pressure_preflight_report_contract -- --nocapture
```

Formatting and syntax checks:

```bash
python3 -m py_compile scripts/swarm_pressure_preflight_report.py
bash -n scripts/run_swarm_pressure_preflight_report_e2e.sh
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_swarm_pressure_preflight_fmt" \
  cargo fmt --check
```
