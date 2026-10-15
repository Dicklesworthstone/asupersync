# Formal Semantics Mechanization

This folder hosts proof-assistant artifacts for the Asupersync small-step semantics.
The source of truth for the rules is:

- `asupersync_v4_formal_semantics.md`

## Current proof posture (asupersync-rckfrm)

The Lean project under `formal/lean/` is build-checked, not merely a planning
stub. The canonical proof command for this repository is:

```bash
rch exec -- lake --dir formal/lean build
```

The current machine-readable inventory
`formal/lean/coverage/invariant_status_inventory.json` reports all six
Asupersync non-negotiable invariants as `fully_proven`:

- `inv.structured_concurrency.single_owner`
- `inv.region_close.quiescence`
- `inv.cancel.protocol`
- `inv.race.losers_drained`
- `inv.obligation.no_leaks`
- `inv.authority.no_ambient`

That is the Lean-checked core invariants posture. It is not a blanket mechanized proof
of every adapter, protocol implementation, platform backend, or distributed runtime transport path. Runtime-facing confidence remains
tiered: the semantics document is the rule source, TLA+/TLC and exported traces
cover bounded model checking surfaces, Lean checks the core invariant theorem
families, and Rust lab/refinement/conformance tests bind those claims back to
executable runtime behavior.

The posture contract is recorded in
`artifacts/formal_proof_posture_contract_v1.json` and enforced by
`tests/formal_proof_posture_contract.rs`.

Wave2 adapter/protocol refinement coverage is recorded separately in
`artifacts/formal_wave2_refinement_coverage_v1.json` and enforced by
`tests/formal_wave2_refinement_coverage_contract.rs`. That artifact maps
selected adapter, protocol, platform, runtime, and broker lanes to explicit
proof tiers, source/test/artifact evidence, assumptions, and missing-evidence
owners. It extends the runtime-facing refinement inventory without changing the
current no-blanket-proof boundary.

Lean coverage planning artifacts live in `formal/lean/coverage/`:
- `README.md`: ontology, statuses, blocker codes, evidence fields, validation rules
- `lean_coverage_matrix.schema.json`: canonical machine-readable schema (v1.0.0)
- `lean_coverage_matrix.sample.json`: sample matrix instance with row types/statuses/evidence
- `theorem_surface_inventory.json`: theorem declaration inventory for Lean coverage baselining
- `step_constructor_coverage.json`: constructor-level Step coverage map with proof status
- `theorem_rule_traceability_ledger.json`: theorem-to-rule mapping ledger used for stale-link detection
- `invariant_status_inventory.json`: invariant-level proof status and test-link inventory
- `gap_risk_sequencing_plan.json`: risk-ranked gap classification and Track 2-6 sequencing graph
- `baseline_report_v1.json`: reproducible baseline snapshot + cadence/change-control policy
- `baseline_report_v1.md`: human-readable baseline report for contributors
- `ci_verification_profiles.json`: smoke/frontier/full Lean CI profile definitions for deterministic gates
- `lean_frontier_buckets_v1.json`: deterministic Lean build frontier error buckets with bead linkage
- `../../artifacts/formal_wave2_refinement_coverage_v1.json`: wave2 adapter/protocol lane proof-tier inventory

## Lean (preferred)

The Lean project is self-contained under `formal/lean/` and does not affect the Rust
crate or Cargo builds. Use `rch` for repository validation:

```bash
rch exec -- lake --dir formal/lean build
```

Local interactive proof work may still enter the directory and run `lake build`,
but closeout evidence for shared-main beads should record the `rch exec` form.

## Remaining work

- Keep `runtime_state_refinement_map.json` synchronized when Rust scheduler,
  region, cancellation, race, obligation, or authority behavior changes.
- Extend proof/refinement coverage beyond the six core invariants to broader
  adapter and protocol lanes only when each lane has a checked artifact and an
  executable runtime mapping.
- Treat assumption IDs in `invariant_theorem_test_link_map.json` as live
  guardrails that need conformance evidence before claims are broadened.
