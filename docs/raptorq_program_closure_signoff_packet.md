# RaptorQ Program Closure Review and Sign-off Packet (H2 / bd-23cxf)

This document defines the H2 closure packet for:

- Bead: `asupersync-2f71w`
- Parent track: `asupersync-p8o9m`
- External ref: `bd-23cxf`
- Canonical artifact: `artifacts/raptorq_program_closure_signoff_packet_v1.json`

## Current State

- Packet state: `draft_blocked`
- Go/no-go: `no_go_pending_dependency_closure`
- Current blockers:
1. `asupersync-2cyx5`

This packet is intentionally execution-ready but not final until dependency
closure conditions are satisfied.

Track-G is the sole remaining blocker. Track-H is already closed, and the
unresolved upstream convergence now sits in Track-E, especially `asupersync-36m6p`,
which is consumed through the still-open Track-G governance path.

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
2. Track E (`asupersync-2ncba`): `in_progress` (the unresolved upstream lane, consumed via Track G; active leaf: `asupersync-36m6p`)
3. Track F (`asupersync-mg1qh`): `closed`
4. Track G (`asupersync-2cyx5`): `in_progress` (the sole remaining direct H2 blocker)
5. Track H (`asupersync-p8o9m`): `closed`

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

Blocked-state ownership is explicit and stable:

1. `track_signoff_owner` -> `asupersync-p8o9m`
2. `packet_curator` -> `asupersync-2f71w`

`go_no_go_decision` is also a top-level packet record. In the current
`draft_blocked` state it must mirror the packet-state verdict, carry the same
blocking dependency set, and name both the decision owner bead and the packet
curator bead so downstream Track-G/H consumers do not have to infer ownership
from prose.

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

## Required Repro Commands

Cargo-heavy commands in this packet must use `rch exec --`:

```bash
rch exec -- cargo test --test raptorq_perf_invariants h2_closure_packet_schema_and_lever_coverage -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants h2_closure_packet_dependency_status_alignment -- --nocapture
rch exec -- cargo test --test raptorq_perf_invariants h2_closure_packet_docs_are_cross_linked -- --nocapture
rch exec -- cargo test --test ci_regression_gates -- --nocapture
rch exec -- ./scripts/run_raptorq_e2e.sh --profile full --bundle
```

## Finalization Rule

H2 may only transition to final sign-off after:

1. All required beads in the artifact dependency matrix are closed.
2. Unit + deterministic E2E evidence and replay commands are validated.
3. Residual-risk ownership and follow-up assignments are explicit.
4. Track-H sign-off (`asupersync-p8o9m`) records final go/no-go decision.
