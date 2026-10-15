# Coordination Workload Bridge Final Signoff

This is the qn8i0p.8 operator signoff for the real agent-swarm coordination workload bridge. It does not ingest live Agent Mail, Beads, bv, rch, git, or home-directory state. It replays checked fixtures and records the exact control-plane commands the closeout operator must run separately.

## Files

- `artifacts/coordination_workload_bridge_signoff_v1.json`
- `scripts/run_coordination_workload_bridge_signoff.sh`
- `tests/coordination_workload_bridge_signoff.rs`
- `artifacts/coordination_workload_bridge_smoke_contract_v1.json`
- `scripts/run_coordination_workload_bridge_smoke.sh`
- `docs/coordination_workload_bridge_smoke_runbook.md`

## Execute

```bash
bash scripts/run_coordination_workload_bridge_signoff.sh --execute --fixture --output-root target/coordination-workload-bridge-signoff --generated-at 2026-05-05T05:00:00Z
```

The runner writes:

- `coordination-workload-bridge-signoff-report.json`
- `coordination-workload-bridge-signoff.jsonl`
- `coordination-workload-bridge-signoff.summary.txt`
- `child-evidence-matrix.json`
- `fingerprint-comparison.json`
- `field-derivation-map.json`
- `fail-closed-diagnostics.json`
- `dependency-boundary.json`
- `logs/*.log`

## What It Proves

1. The qn8i0p.1 through qn8i0p.7 child outputs exist, are represented as closed evidence, and are mapped to the final bridge requirement they satisfy.
2. The qn8i0p.7 fixture bridge smoke runs twice from independent output roots and produces identical canonical row fingerprints.
3. Every generated `ASWARM-WL-*` workload field is traced to one of:
   - `artifacts/runtime_workload_corpus_v1.json::coordination_workload_synthesis.scenario_family_mapping`
   - the redacted collector bundle accepted events grouped by `workload_family`
   - a fixed coordination workload synthesis rule
4. Malformed, stale, unredacted, unsupported, missing-dimension, and schema-mismatch inputs fail closed with a diagnostic.
5. The core runtime dependency boundary is preserved by checking Cargo dependency keys against the forbidden Agent Mail, Beads, br, bv, and rch keys.
6. The capacity/profile handoff keeps used, refused, and absent coordination-pack states explicit and conservative.
7. The signoff records the exact `br`, `bv`, local shell, and `RCH_REQUIRE_REMOTE=1 rch exec -- env ... cargo ...` commands required for closeout.

## Required Validation

```bash
bash -n scripts/run_coordination_workload_bridge_signoff.sh
jq empty artifacts/coordination_workload_bridge_signoff_v1.json
bash scripts/run_coordination_workload_bridge_signoff.sh --list
bash scripts/run_coordination_workload_bridge_signoff.sh --dry-run --fixture --output-root target/coordination-workload-bridge-signoff-dry-run --generated-at 2026-05-05T05:00:00Z
bash scripts/run_coordination_workload_bridge_signoff.sh --execute --fixture --output-root target/coordination-workload-bridge-signoff --generated-at 2026-05-05T05:00:00Z
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_coordination_workload_bridge_signoff cargo test -p asupersync --test coordination_workload_bridge_signoff --features test-internals -- --nocapture
```

Before closing the parent epic, run:

```bash
br show asupersync-qn8i0p --json
br show asupersync-qn8i0p.8 --json
br ready --json
bv --robot-alerts
```

Only close `asupersync-qn8i0p` after qn8i0p.8 is closed and the parent shows no open child beads.
