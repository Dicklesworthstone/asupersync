# Third-Wave Swarm Guardrail E2E

This bundle is the operator e2e surface for `asupersync-ol11aa.9.6`. It invokes
child helpers for stale in-progress reaping, br/bv graph drift, reservation
lease coverage, lane closeout receipts, and RCH quiet-phase receipts against
their checked fixtures.

The report is intentionally narrow. It verifies that the child guardrail
fixtures still fail closed and emit the expected classifications and marker
rows. It is not a broad workspace health proof, not a release publish proof,
and not a substitute for broad check/clippy/test gates.

## Canonical Files

- Contract artifact: `artifacts/third_wave_swarm_guardrail_e2e_contract_v1.json`
- Helper: `scripts/third_wave_swarm_guardrail_e2e.py`
- E2E runner: `scripts/run_third_wave_swarm_guardrail_e2e.sh`
- Contract test: `tests/third_wave_swarm_guardrail_e2e_contract.rs`
- Operator docs: `docs/third_wave_swarm_guardrail_e2e.md`
- Operator runbook: `docs/third_wave_swarm_operator_runbook.md`

## Refresh Procedure

Regenerate the JSON report from the checked fixture:

```bash
python3 scripts/third_wave_swarm_guardrail_e2e.py \
  --fixture artifacts/third_wave_swarm_guardrail_e2e_contract_v1.json \
  --repo-root . \
  --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output json
```

Regenerate the Markdown operator summary:

```bash
python3 scripts/third_wave_swarm_guardrail_e2e.py \
  --fixture artifacts/third_wave_swarm_guardrail_e2e_contract_v1.json \
  --repo-root . \
  --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output markdown
```

Run the bounded E2E wrapper for a line log and summary JSON:

```bash
bash scripts/run_third_wave_swarm_guardrail_e2e.sh \
  --run-id release-prep
```

The wrapper writes only below `target/third-wave-swarm-guardrail-e2e/run_<id>/`:
JSON report, Markdown report, line-oriented log, and summary JSON. It invokes child helpers.
It does not run proof commands, mutate tracker state, inspect live services,
close beads, push refs, mirror refs, or release reservations.

## Required Child Surfaces

| Component | Helper | Contract fixture |
| --- | --- | --- |
| `stale-in-progress-reaper` | `scripts/stale_in_progress_bead_reaper.py` | `artifacts/stale_in_progress_bead_reaper_contract_v1.json` |
| `tracker-graph-drift` | `scripts/tracker_graph_drift_report.py` | `artifacts/tracker_graph_drift_report_contract_v1.json` |
| `reservation-lease-watchdog` | `scripts/reservation_lease_watchdog.py` | `artifacts/reservation_lease_watchdog_contract_v1.json` |
| `swarm-lane-closeout` | `scripts/swarm_lane_closeout_receipt.py` | `artifacts/swarm_lane_closeout_receipt_contract_v1.json` |
| `rch-quiet-phase` | `scripts/rch_quiet_phase_receipt.py` | `artifacts/rch_quiet_phase_receipt_contract_v1.json` |

## Contract Semantics

Each component must emit the expected child schema, summary fields, required
classification counts, and three marker rows. The aggregate report fails closed
if a child helper exits nonzero, emits invalid JSON, changes schema, drops a
classification, changes a marker classification, or changes marker booleans.

The aggregate expected summary is five passed components, thirty-five child
scenarios, thirty-five required classifications, fifteen marker rows, no live
external services, no mutation commands, and no proof commands.

## Contract Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_third_wave_swarm_guardrail_e2e CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test third_wave_swarm_guardrail_e2e_contract -- --nocapture
```
