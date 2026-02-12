# Formal Semantics Mechanization

This folder hosts proof-assistant artifacts for the Asupersync small-step semantics.
The source of truth for the rules is:

- `asupersync_v4_formal_semantics.md`

The Lean scaffold lives in `formal/lean/` and is intentionally minimal at first:
- Core domains and state skeletons
- Labels + step relation placeholders
- A place to incrementally encode the rules from the semantics document

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

## Lean (preferred)

The Lean project is self-contained under `formal/lean/` and does not affect the Rust
crate or Cargo builds. Enter that directory to build:

```bash
cd formal/lean
lake build
```

## Next steps (bd-330st)

- Encode the full domain/state definitions from §1 of the semantics
- Add the small-step rules as inductive constructors
- Prove well-formedness preservation and progress for the operational rules
