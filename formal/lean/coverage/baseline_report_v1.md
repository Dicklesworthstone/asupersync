# Lean Coverage Baseline Report v1

This report is the canonical, self-contained Track-1 baseline for Lean coverage execution.
Machine-readable source: `formal/lean/coverage/baseline_report_v1.json`.

## Snapshot

- Theorem surface: `136` total theorems (`removeObligationId_not_mem` .. `cancelChild_preserves_wellformed_constructor`)
- Step constructor coverage: `22` total, `22` covered, `0` partial, `0` missing
- Invariant status: `1` fully proven, `3` partially proven, `2` unproven
- Invariant witness linkage: `6` invariants mapped, `5` with theorem witnesses, `6` with executable checks
- Frontier buckets: `32` errors grouped into `7` deterministic buckets (largest: `proof-shape.type-mismatch`)
  - Unproven invariants:
    - `inv.race.losers_drained`
    - `inv.authority.no_ambient`

## Risk-Ranked Gap Summary

First-class blockers (highest urgency):
1. `gap.declaration_order.helper_frontier`
2. `gap.proof_shape.preservation_branches`
3. `gap.missing_lemma.invariant_witness_bundle`
4. `gap.model_code_mismatch.refinement_table`

Top-3 priority order:
1. `gap.declaration_order.helper_frontier`
2. `gap.proof_shape.preservation_branches`
3. `gap.missing_lemma.invariant_witness_bundle`

Recommended track execution order:
1. `track-2`
2. `track-3`
3. `track-4`
4. `track-5`
5. `track-6`

## Track-2 Frontier Burn-down Dashboard (Deterministic)

Dashboard ID: `lean.track2.frontier_burndown.v1`

Latest recorded run:
- run_id: `track2.frontier.baseline.2026-02-15`
- source_log: `target/lean-e2e/bd-cspxm_lake_build.log`
- toolchain_key: `lean4+rust-nightly-2026-02-05`
- frontier artifact: `formal/lean/coverage/lean_frontier_buckets_v1.json`
- totals: diagnostics `86`, errors `32`, warnings `54`, bucket_count `7`
- delta vs previous: all `0` (baseline run)

Current bucket trend table (lexicographic by `(failure_mode,error_code)`):
- `proof-shape.application-type-mismatch`: count `1`, delta `0`, trend `baseline`
- `proof-shape.omega-goal-not-proved`: count `1`, delta `0`, trend `baseline`
- `proof-shape.other`: count `1`, delta `0`, trend `baseline`
- `proof-shape.rewrite-failed`: count `3`, delta `0`, trend `baseline`
- `proof-shape.subst-failed`: count `9`, delta `0`, trend `baseline`
- `proof-shape.type-mismatch`: count `14`, delta `0`, trend `baseline`
- `proof-shape.unsolved-goals`: count `3`, delta `0`, trend `baseline`

Repro command:
- `cargo test --test lean_baseline_report baseline_report_track2_burndown_and_closure_gate_are_well_formed -- --nocapture`

## Track-2 Closure Gate (Objective)

Policy ID: `lean.track2.closure_gate.v1`

Current status:
- `not-satisfied`

Blocking classes that must remain at zero:
- `declaration-order.unknown-identifier`
- `declaration-order.helper-availability`
- `tactic-instability.recursion-depth`

Stability requirement before Track-2 closure:
- `2` consecutive deterministic runs
- no regressions in diagnostics/errors/warnings/bucket_count
- no regressions in per-bucket counts

References:
- Track-2 close decision: `bd-k6fj1`
- Closure gate owner: `bd-5wwbm`
- Track-3 dependency: `bd-1egsf`
- Track-5 CI policy linkage: `bd-1hkjl`, `bd-2ruh1`

## Ownership Map (Current)

- `bd-3kzbt` Track-1 baseline/scope execution: `MagentaBridge` (`closed`)
- `bd-5w2lq` Track-1 baseline report/cadence: `MagentaBridge` (`closed`)
- `bd-2iwok` Track-1 invariant theorem/test linkage: `MagentaBridge` (`closed`)
- `bd-1dorb` Track-2 frontier extractor: `MagentaBridge` (`closed`)
- `bd-53a0d` Track-2 declaration-order stabilization: unassigned (`open`)
- `bd-kf0mv` Track-2 tactic stability: `MagentaBridge` (`closed`)
- `bd-112rm` Track-3 constructor-total preservation: `MagentaBridge` (`in_progress`)
- `bd-244p5` Track-3 invariant witness bundle: unassigned (`open`)
- `bd-2ve1x` Track-4 refinement mapping: unassigned (`open`)

## Maintenance Cadence

Refresh baseline artifacts when:
1. Any change touches `formal/lean/Asupersync.lean`.
2. Any change affects refinement-conformance/runtime alignment.
3. Weekly proof-health pass or milestone boundary.

When refreshing, update:
- `theorem_surface_inventory.json`
- `step_constructor_coverage.json`
- `theorem_rule_traceability_ledger.json`
- `invariant_status_inventory.json`
- `invariant_theorem_test_link_map.json`
- `gap_risk_sequencing_plan.json`
- `ci_verification_profiles.json`
- `lean_frontier_buckets_v1.json`
- `baseline_report_v1.json`
- `baseline_report_v1.md`

Required verification gates:
- `cargo fmt --check`
- `cargo check --all-targets`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

## Change-Control Rules

Controlled definitions:
- failure-mode taxonomy in `gap_risk_sequencing_plan.json`
- invariant status scale in `invariant_status_inventory.json`
- linkage policy and witness map semantics in `invariant_theorem_test_link_map.json`
- frontier error-code/failure-mode taxonomy in `lean_frontier_buckets_v1.json`
- row/status/blocker ontology in Lean coverage matrix schema/model

Protocol for changes:
1. Document rationale in bead notes.
2. Update all affected artifacts/tests in one changeset.
3. Pass full gates before closure.
4. Ensure bead references in baseline artifacts resolve and first-class blocker changes include dependency-impact rationale.
