# Tracker Graph Drift Report

The tracker graph drift report turns explicit `br` and `bv` JSON snapshots into
a deterministic operator receipt for shared-main swarm sessions. Use it when
`br ready --json` and `bv --robot-next` disagree, when `bv` reports no top pick
but `br` still exposes ready work, or when a parent feature is ready but needs a
concrete child bead before source edits.

The helper is read-only. It does not run commands, mutate beads, inspect Git,
query Agent Mail, or rewrite artifacts. Fixture snapshots do not override live
state; they only explain the state they were given.

## Contract Surface

- Helper: `scripts/tracker_graph_drift_report.py`
- Contract artifact: `artifacts/tracker_graph_drift_report_contract_v1.json`
- Rust contract test: `tests/tracker_graph_drift_report_contract.rs`
- Report schema: `tracker-graph-drift-report-v1`

## Classifications

- `command-provenance-failure`: a required `br` or `bv` command was missing or
  failed; rerun the command before using the snapshot.
- `data-hash-mismatch`: `bv --robot-next` and `bv --robot-triage` came from
  different graph snapshots; refresh both.
- `stale-graph-snapshot`: at least one snapshot is older than the configured
  freshness window.
- `br-ready-bv-empty-divergence`: `br ready` has concrete work but `bv` reports
  no top pick; do not treat this as no work.
- `br-bv-actionable-mismatch`: both tools name actionable work, but not the same
  bead; resolve the mismatch before claiming.
- `parent-only-ready-queue`: the ready queue contains only a feature/epic parent
  without touched paths; create or select a child bead first.
- `consistent-actionable`: `br` and `bv` agree on a concrete task; normal claim,
  reservation, RCH validation, commit, and push workflow still applies.
- `consistent-no-work`: both tools agree there is no actionable issue in the
  fixture; use an approved planning, audit, or testing fallback.

## Usage

Emit deterministic JSON from the checked contract fixture:

```bash
python3 scripts/tracker_graph_drift_report.py \
  --fixture artifacts/tracker_graph_drift_report_contract_v1.json \
  --generated-at 2026-06-06T13:40:00Z \
  --output json
```

Emit Markdown for Agent Mail or release handoff:

```bash
python3 scripts/tracker_graph_drift_report.py \
  --fixture artifacts/tracker_graph_drift_report_contract_v1.json \
  --generated-at 2026-06-06T13:40:00Z \
  --output markdown
```

Focused validation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_tracker_graph_drift_report" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test tracker_graph_drift_report_contract -- --nocapture
```

## Non-Claims

This report does not prove source correctness, does not authorize branch or
worktree creation, does not override Agent Mail reservations, and does not make
local Cargo fallback acceptable proof. It is a coordination receipt that helps
future agents decide whether to claim, refresh, create a child bead, or stop
with an explicit blocker.
