# Lean Coverage Matrix (v1)

This directory contains the canonical machine-readable artifacts for Lean proof coverage tracking:

- `lean_coverage_matrix.schema.json` - JSON Schema (`schema_version = 1.0.0`)
- `lean_coverage_matrix.sample.json` - deterministic sample matrix instance
- `theorem_surface_inventory.json` - complete theorem declaration inventory from `Asupersync.lean`
- `step_constructor_coverage.json` - constructor-by-constructor coverage status and theorem mappings
- `theorem_rule_traceability_ledger.json` - theorem-to-rule traceability ledger for stale-link detection
- `invariant_status_inventory.json` - non-negotiable invariant status map with theorem/test linkage
- `invariant_theorem_test_link_map.json` - canonical invariant -> theorem witness -> executable test map
- `gap_risk_sequencing_plan.json` - deterministic gap classification, risk scoring, and execution sequencing plan
- `baseline_report_v1.json` - reproducible Track-1 baseline snapshot (counts, blockers, ownership, cadence)
- `baseline_report_v1.md` - human-readable baseline report synchronized with JSON snapshot
- `ci_verification_profiles.json` - deterministic smoke/frontier/full CI profile definitions and comparability keys
- `lean_frontier_buckets_v1.json` - deterministic frontier error buckets with failure-mode + bead linkage

## Ontology

`row_type` values:
- `semantic_rule`
- `invariant`
- `refinement_obligation`
- `operational_gate`

`status` values:
- `not-started`
- `in-progress`
- `blocked`
- `proven`
- `validated-in-ci`

## Canonical Invariant Lexicon

The following invariant names are canonical and must match across docs, Lean coverage artifacts,
and Rust conformance tests:

- `inv.structured_concurrency.single_owner`: Structured concurrency: every task is owned by exactly one region
- `inv.region_close.quiescence`: Region close = quiescence
- `inv.cancel.protocol`: Cancellation is a protocol: request -> drain -> finalize (idempotent)
- `inv.race.losers_drained`: Losers are drained after races
- `inv.obligation.no_leaks`: No obligation leaks
- `inv.authority.no_ambient`: No ambient authority

## Blocker Taxonomy (deterministic codes)

- `BLK_PROOF_MISSING_LEMMA`
- `BLK_PROOF_SHAPE_MISMATCH`
- `BLK_MODEL_GAP`
- `BLK_IMPL_DIVERGENCE`
- `BLK_TOOLCHAIN_FAILURE`
- `BLK_EXTERNAL_DEPENDENCY`

## Evidence Fields

Each row may contain `evidence` entries with:
- `theorem_name`
- `file_path`
- `line`
- `proof_artifact`
- `ci_job`
- `reviewer`

## Validation Rules

The Rust model in `conformance/src/lean_coverage_matrix.rs` enforces:
- `schema_version` must match `1.0.0`
- stable lowercase IDs (`[a-z0-9._-]+`) for `matrix_id` and row `id`
- unique row IDs
- dependencies must reference existing row IDs
- `blocked` rows require a non-empty blocker payload
- `proven` and `validated-in-ci` rows require non-empty evidence
- `validated-in-ci` rows require at least one evidence item with `ci_job`
- evidence with `line` must also provide `file_path`

## Gap Prioritization and Sequencing

`gap_risk_sequencing_plan.json` captures:
- canonical gap categories across declaration-order, missing-lemma, proof-shape, model-code-mismatch, tactic-instability
- canonical `error_code_catalog` mapping each deterministic frontier `error_code` to one primary `failure_mode`
- deterministic scoring (`priority_score = 2*product_risk + unblock_potential - implementation_effort`)
- first-class blockers and critical path for Tracks 2-6
- explicit dependency edges and phase exits for execution planning

Validation for this artifact is enforced in `tests/lean_gap_risk_sequencing_plan.rs`, including:
- scoring formula consistency
- bead link existence
- edge/critical-path integrity

## Baseline Cadence

`baseline_report_v1.json` and `baseline_report_v1.md` define:
- reproducible baseline snapshot for theorem/constructor/invariant/gap status
- ownership map for active blocker beads
- refresh triggers and required verification gates
- change-control protocol for taxonomy/definition updates

Validation for baseline consistency is enforced in `tests/lean_baseline_report.rs`.

## Invariant Witness Link Map

`invariant_theorem_test_link_map.json` defines the canonical witness mapping for each non-negotiable
invariant:
- theorem witnesses with theorem-line anchors and rule-link evidence (when available)
- executable Rust conformance checks
- explicit gaps with owner and dependency-bead blockers

Validation for this artifact is enforced in `tests/lean_invariant_theorem_test_link_map.rs`.

## CI Verification Profiles

`ci_verification_profiles.json` defines three deterministic Lean verification tiers:
- `smoke` for fast PR feedback on high-signal coverage regressions
- `frontier` for blocker-focused burn-down validation
- `full` for merge/release assurance and audit-grade comparability

Validation for profile structure, runtime ordering, and bead-link integrity is enforced in
`tests/lean_ci_verification_profiles.rs`.

## Frontier Extractor and Buckets

`conformance/src/lean_frontier.rs` provides deterministic parsing and bucketing for Lean build logs.

- Bucket key: `(failure_mode, error_code)` in lexicographic order
- Signature normalization: stable across line-number and identifier churn
- Gap/bead tagging: linked from `gap_risk_sequencing_plan.json` by failure mode

Artifact generation command:

```bash
cargo run --manifest-path conformance/Cargo.toml --bin lean_frontier_extract -- \
  --log target/lean-e2e/bd-1dorb_lake_build.log \
  --gap-plan formal/lean/coverage/gap_risk_sequencing_plan.json \
  --out formal/lean/coverage/lean_frontier_buckets_v1.json \
  --source-log target/lean-e2e/bd-1dorb_lake_build.log
```

Validation for extractor determinism and frontier artifact integrity is enforced in:
- `tests/lean_frontier_extractor.rs`
- `tests/lean_frontier_buckets.rs`
