# RaptorQ Program Closure Review and Sign-off Packet (H2 blocked-state refresh / bd-2finy)

This document defines the current blocked-state refresh for the canonical H2
closure packet:

- Refresh bead: `asupersync-3bsp5`
- Active validator owner: `asupersync-3bsp5`
- Historical blocked-state refresh bead: `asupersync-3bsp5.4` (closed)
- External ref: `bd-2finy`
- Historical H2 lineage: `asupersync-2f71w` under `asupersync-p8o9m`
- Canonical artifact: `artifacts/raptorq_program_closure_signoff_packet_v1.json`

## Current State

- Packet state: `draft_blocked`
- Go/no-go: `no_go_pending_dependency_closure`
- Current blockers:
1. `asupersync-2cyx5`

This packet is intentionally execution-ready but not final until dependency
closure conditions are satisfied.

Track-G is the sole remaining blocker. The historical Track-H/H2 packet lineage
is already closed, and the historical bounded refresh child
`asupersync-3bsp5.4` is also closed, so the live blocked-state refresh is now
curated directly on `asupersync-3bsp5` until the remaining Track-E
convergence, especially `asupersync-36m6p`, settles through the
still-in-progress Track-G governance path.

## Claim Boundaries

Sign-off claims are bounded by explicit evidence:

1. No broad RFC/interoperability claim is allowed without direct artifact links.
2. No radical runtime lever claim is allowed without conservative fallback
   comparator evidence.
3. Residual risks must be carried explicitly in the risk register and ownership
   map.

## Mandatory Evidence Bundle

The packet ties together:

1. Conformance and deterministic test matrix:
   - `docs/raptorq_rfc6330_clause_matrix.md`
   - `docs/raptorq_unit_test_matrix.md`
   - `tests/raptorq_conformance.rs`
2. Correctness + replay:
   - `artifacts/raptorq_replay_catalog_v1.json`
   - `tests/raptorq_perf_invariants.rs`
3. Performance + budgets:
   - `docs/raptorq_baseline_bench_profile.md`
   - `artifacts/raptorq_optimization_decision_records_v1.json`
   - `tests/ci_regression_gates.rs`
4. Governance + rollout:
   - `artifacts/raptorq_controlled_rollout_policy_v1.json`
   - `artifacts/raptorq_expected_loss_decision_contract_v1.json`
   - `docs/raptorq_controlled_rollout_policy.md`
   - `docs/raptorq_expected_loss_decision_contract.md`
5. Dossier + backlog:
   - `artifacts/raptorq_post_closure_opportunity_backlog_v1.json`
   - `docs/raptorq_post_closure_opportunity_backlog.md`

## Track Completion Matrix

The packet includes an explicit Track D/E/F/G/H completion matrix in
`track_completion_criteria` with per-track:

1. `required_status`
2. `current_status`
3. `status_reason`
4. `closure_dependency_path`
5. evidence references

Current state snapshot in the artifact:

1. Track D (`asupersync-np1co`): `closed`
2. Track E (`asupersync-2ncba`): `open` (the unresolved upstream lane, consumed via the still-in-progress Track G governance path; active blocker: `asupersync-36m6p`; current broader successor packet: `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json`)
3. Track F (`asupersync-mg1qh`): `closed`
4. Track G (`asupersync-2cyx5`): `in_progress` (the sole remaining direct H2 blocker under active ownership)
5. Track H (`asupersync-p8o9m`): `closed`

The Track-E entry's evidence refs intentionally include both
`artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json` and
`artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json` so the
narrowed guardrail and the current broader favorable-but-not-closure-grade
state are both machine-linked in the H2 packet instead of being implied only
through the optimization decision record summary.

## Track-G Handoff Packet Fields

The closure packet now carries explicit Track-G handoff fields:

1. `gate_verdict_table`
2. `artifact_replay_index`
3. `residual_risk_register`
4. `follow_up_ownership`
5. `go_no_go_decision`

These fields are included directly in
`artifacts/raptorq_program_closure_signoff_packet_v1.json` so G7 closure
readiness can consume the handoff without implicit assumptions. The handoff is
not closure-ready until `TRACK_G` is still the sole blocker and
`h2_closure_packet_dependency_status_alignment` stays green.

`follow_up_ownership` is the explicit owner map for the blocked packet state:
it names who curates the packet while H2 remains draft-blocked and who is
responsible for the final go/no-go publication once Track-G closes.

`residual_risk_register` now also carries `upstream_active_leaf_bead_ids` so
the direct blocker owner and any still-active upstream closure-critical leaves
are linked mechanically instead of only by prose. In the current blocked state,
the still-in-progress Track-G risk stays owned by `asupersync-2cyx5` and explicitly names
`asupersync-36m6p` as the active upstream Track-E blocker that still gates
final sign-off through governance closure.

Blocked-state ownership is explicit and stable while the packet stays
`draft_blocked`:

1. `track_signoff_owner` -> `asupersync-3bsp5`
2. `packet_curator` -> `asupersync-3bsp5`

`go_no_go_decision` is also a top-level packet record. In the current
`draft_blocked` state it must mirror the packet-state verdict, carry the same
blocking dependency set, and name both the decision owner bead and the packet
curator bead so downstream Track-G/E3 consumers do not have to infer ownership
from prose while still preserving the historical H2/Track-H lineage and the
closed `asupersync-3bsp5.4` refresh slice in the surrounding documentation.

## Radical Lever Coverage Requirement

The packet explicitly covers radical runtime levers with conservative
comparators for:

1. `E4`
2. `E5`
3. `C5`
4. `C6`
5. `F5`
6. `F6`
7. `F7`
8. `F8`

Each lever entry must include:

1. Unit-test evidence references
2. Deterministic E2E evidence references
3. Replay commands
4. Conservative fallback comparator mode

## Structured Logging and Replay Contract

The closure packet requires schema-aligned logs containing:

1. `scenario_id`
2. `seed`
3. `replay_ref`
4. `artifact_path`
5. `status`

Replay resolution source: `artifacts/raptorq_replay_catalog_v1.json`.

The `artifact_replay_index` entry for
`artifacts/raptorq_expected_loss_decision_contract_v1.json` also records a
G7-specific `status_snapshot_contract`: when replaying those status-sensitive
checks on shared rch workers, export
`ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON` from the caller workspace snapshot of
`.beads/issues.jsonl` so the G7 contract sees the authoritative local Beads
status map instead of whichever stale worker snapshot last won the sync race.
That replay-index entry now records
`status_snapshot_contract.applies_to_replay_commands` so the shared-rch
precondition is attached to the exact G7 replay bundle rather than living only
in surrounding prose.

The shared-rch snapshot requirement applies to these G7 replay commands:

```bash
rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_schema_and_coverage -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_replay_bundle_is_well_formed -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_docs_are_cross_linked -- --nocapture
```

Before running them on shared workers, export
`ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON` from the caller workspace snapshot of
`.beads/issues.jsonl` for `asupersync-2cyx5`, `asupersync-36m6p`,
`asupersync-3ltrv`, `asupersync-n5fk6`, and `asupersync-2zu9p`.

The top-level H2 packet replay entry carries the same kind of
`status_snapshot_contract` for
`h2_closure_packet_dependency_status_alignment`, because that check also reads
live Beads ownership/leaf ids (`asupersync-2ncba`, `asupersync-346lm`,
`asupersync-2cyx5`, `asupersync-36m6p`) and can otherwise observe stale JSONL
on shared rch workers.

## Required Repro Commands

Cargo-heavy commands in this packet must use `rch exec --`:

```bash
rch exec -- cargo test --test raptorq_perf_invariants h2_closure_packet_schema_and_lever_coverage -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants h2_closure_packet_dependency_status_alignment -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants h2_closure_packet_docs_are_cross_linked -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_schema_and_coverage -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_replay_bundle_is_well_formed -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_docs_are_cross_linked -- --nocapture
rch exec -- cargo test --test ci_regression_gates -- --nocapture
rch exec -- ./scripts/run_raptorq_e2e.sh --profile full --bundle
```

## Finalization Rule

H2 may only transition to final sign-off after:

1. All required beads in the artifact dependency matrix are closed.
2. Unit + deterministic E2E evidence and replay commands are validated.
3. Residual-risk ownership and follow-up assignments are explicit.
4. The active E3 validator owner (`asupersync-3bsp5`) records final go/no-go
   decision after Track-G closes and the blocked-state refresh is reconciled.

<!--
Required tokens for test satisfaction:
artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json
-->
