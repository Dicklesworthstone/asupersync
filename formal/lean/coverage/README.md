# Lean Coverage Matrix (v1)

This directory contains the canonical machine-readable artifacts for Lean proof coverage tracking:

- `lean_coverage_matrix.schema.json` - JSON Schema (`schema_version = 1.0.0`)
- `lean_coverage_matrix.sample.json` - deterministic sample matrix instance
- `theorem_surface_inventory.json` - complete theorem declaration inventory from `Asupersync.lean`
- `step_constructor_coverage.json` - constructor-by-constructor coverage status and theorem mappings
- `theorem_rule_traceability_ledger.json` - theorem-to-rule traceability ledger for stale-link detection
- `runtime_state_refinement_map.json` - explicit RuntimeState + scheduler/combinator operation map to Lean Step labels/theorem obligations
- `runtime_state_refinement_map.json` also carries the deterministic divergence triage decision matrix (`code-first` vs `model-first` vs `assumptions-or-harness-first`) and canonical triage examples
- `invariant_status_inventory.json` - non-negotiable invariant status map with theorem/test linkage
- `invariant_theorem_test_link_map.json` - canonical invariant -> theorem witness -> executable test map
- `gap_risk_sequencing_plan.json` - deterministic gap classification, risk scoring, and execution sequencing plan
- `baseline_report_v1.json` - reproducible Track-1 baseline snapshot (counts, blockers, ownership, cadence)
- `baseline_report_v1.md` - human-readable baseline report synchronized with JSON snapshot
- `ci_verification_profiles.json` - deterministic smoke/frontier/full CI profile definitions and comparability keys
- `lean_full_repro_bundle_manifest.schema.json` - JSON Schema for `lean-full/repro_bundle_manifest.json` emitted by the full CI profile
- `lean_frontier_buckets_v1.json` - deterministic frontier error buckets with failure-mode + bead linkage
- `proof_guided_performance_opportunity_map.json` - deterministic Track-6 optimization envelope map with theorem-linked constraints and required conformance checks
- `proof_impact_closed_loop_report_v1.json` - deterministic Track-6 closed-loop impact report linking coverage maturity to performance/reliability/correctness outcomes

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

## Lemma Canonicalization and Layering Rules (Track-3 / asupersync-3qo95)

Theorem-family canonicalization is recorded in
`theorem_surface_inventory.json` under `lemma_canonicalization`.

Usage contract:
- Use `canonical_theorem` as the first import target when a family offers
  multiple theorem variants.
- Treat listed `variants` as purpose-specific projections (simulation witness,
  ledger projection, constructor projection), not as alternate canonical names.
- Keep liveness decomposition families (`cancel_*`, `close_*`) anchored to their
  canonical termination/quiescence theorem before introducing state-specific
  projections.
- Keep frame/update lemmas (`set*`/`get*` families) dependency-free from
  preservation or refinement master theorems.
- Keep constructor-specific theorem helpers depending on canonical lifecycle
  lemmas, never the reverse.

Safe rewrite/simp patterns for active Track-3 work:
- Prefer `[simp]` frame lemmas (`setTask_getTask_same`,
  `setTask_getTask_other`, `setRegion_getRegion_same`,
  `setObligation_getObligation_same`) for local state updates.
- Rewrite state transitions with `get*`/`set*` lemmas before attempting
  constructor discharges.
- For obligation lifecycle branches, normalize through canonical lemmas:
  `commit_resolves`, `abort_resolves`, `leak_marks_leaked`.
- Use simulation-only variants (`*_resolves_obligation`) after canonical state
  normalization, when proving Rust-to-Lean projection details.

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
- machine-readable `coverage_gate_policy` thresholds for theorem/constructor/invariant/conformance/frontier categories
- first-class blockers and critical path for Tracks 2-6
- explicit dependency edges and phase exits for execution planning

## Coverage Gate Policy (Track-5)

`gap_risk_sequencing_plan.json` now includes a `coverage_gate_policy` section used as the
canonical threshold/escalation contract for proof-health governance:
- per-category thresholds (`theorem`, `constructor`, `invariant`, `conformance`, `frontier`)
- explicit owner assignment and escalation beads
- severity-ordered SLA targets (TTFR/TTR)
- temporary-regression bounds with required expiry windows
- exception lifecycle policy (`draft/active/closed/expired`) with required waiver fields

Governance enforcement is machine-checked in `tests/lean_gap_risk_sequencing_plan.rs` so CI
fails on malformed thresholds, missing owner routes, invalid SLA ordering, or invalid waiver
lifecycle records.

## Divergence Repair Routing (Track-4)

`runtime_state_refinement_map.json` is the canonical source for deterministic divergence routing.

- `divergence_triage_decision_matrix` defines route selection rules:
- `code-first`: patch Rust runtime/conformance when executable behavior drifts from stable mapped proofs.
- `model-first`: patch Lean theorem/helper structure when frontier evidence shows proof-shape or declaration-order instability.
- `assumptions-or-harness-first`: patch assumptions/comparability harness when mismatch is due to stale fixtures or profile drift.
- `divergence_triage_examples` provides auditable historical examples with route choice, evidence artifacts, and sign-off roles.

For bead `bd-3mo4f`, the recorded example `triage-example.bd-cspxm.2026-02-11` demonstrates a `model-first` route with deterministic frontier evidence and explicit ownership.

## Refinement Trace Equivalence Noise Filter (Track-4.2a)

Refinement mismatch triage uses deterministic trace-class comparison to avoid
false positives from benign scheduling reordering.

Algorithm (deterministic):
1. Capture the two traces under comparison (reference vs candidate).
2. Compute canonical class fingerprints with `trace_fingerprint(...)`.
3. Classify as schedule-noise equivalent when fingerprints match.
4. Classify as semantic mismatch when fingerprints differ.
5. Keep the raw traces for audit so reviewers can distinguish "different order"
   from "different behavior".

Primary executable checks:
- `tests/refinement_conformance.rs`:
  - `refinement_trace_equivalence_filters_schedule_noise`
  - `refinement_trace_equivalence_detects_semantic_mismatch`

Repro commands:

```bash
rch exec -- cargo test --test refinement_conformance refinement_trace_equivalence_filters_schedule_noise -- --nocapture
rch exec -- cargo test --test refinement_conformance refinement_trace_equivalence_detects_semantic_mismatch -- --nocapture
```

## Scheduler and Combinator Mapping Rows (Track-4.1b)

`runtime_state_refinement_map.json` now carries explicit scheduler/combinator rows for:
- `scheduler.three_lane.next_task`
- `scope.race_all_loser_drain`

Each row includes:
- formal transition labels
- theorem obligations with line anchors
- deterministic `expected_trace_signatures` used by conformance checks
- `conformance_test_links` to executable regression coverage

Validation for these rows is enforced in `tests/runtime_state_refinement_map.rs`.

Validation for this artifact is enforced in `tests/lean_gap_risk_sequencing_plan.rs`, including:
- scoring formula consistency
- bead link existence
- edge/critical-path integrity

## Baseline Cadence

`baseline_report_v1.json` and `baseline_report_v1.md` define:
- reproducible baseline snapshot for theorem/constructor/invariant/gap status
- deterministic Track-2 frontier burn-down dashboard (run totals + per-bucket trends + deltas)
- objective Track-2 closure gate policy (zero-class requirements + stability criteria)
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

The full profile manifest contract is explicit and versioned:
- schema version: `lean.full.repro.bundle.v1`
- schema path: `formal/lean/coverage/lean_full_repro_bundle_manifest.schema.json`
- required contract fields include deterministic repro metadata (`toolchain`, `inputs`,
  `commands`, `artifacts`) and routing ownership context.

Retention policy is also enforced from `ci_verification_profiles.json`:
- default retention: 30 days
- bounded range: 30 to 90 days
- expiry reference: `ci_run_created_at_utc`

## Governance Cadence and Decision Records (Track-5)

`ci_verification_profiles.json` includes `governance_policy` as the canonical governance contract:
- deterministic review cadence definitions for `weekly-proof-health` and `phase-exit-signoff`
- required participants and required artifact sets per review
- explicit rules for bead status updates and dependency-edge updates from each review
- decision-record template with required fields, temporary-decision expiry semantics, and
  dependency change type constraints

CI failure payload generation consumes this policy so triage artifacts include governance context
and explicit `br` update/dependency command templates for operational follow-through.

## Proof-Safe Hot-Path Refactor Checklist (Track-6 T6.1b)

Canonical checklist location:
- `docs/integration.md` under **Proof-Safe Hot-Path Refactor Checklist (Track-6 T6.1b)**.
- `docs/integration.md` under **Optimization Constraint Sheet (Track-6 T6.1a / bd-3fooi)**.

When performance refactors touch scheduler/cancellation/obligation hot paths, review artifacts
must include:
- checklist completion status for lane ordering, lock ordering, cancellation protocol, and
  obligation totality;
- theorem/invariant anchors from:
  - `formal/lean/coverage/runtime_state_refinement_map.json`
  - `formal/lean/coverage/invariant_theorem_test_link_map.json`;
- deterministic executable evidence from:
  - `tests/refinement_conformance.rs`
  - `tests/lean_invariant_theorem_test_link_map.rs`.

Constraint-ID policy for optimization tracks:
- Performance/refactor work in scheduler/cancellation/obligation hot paths must cite `OPT-*`
  constraint IDs from `docs/integration.md`.
- Missing constraint IDs indicate missing proof-impact linkage.
- Constraint violations must be converted to blocker beads before merge/sign-off.

## Proof-Guided Opportunity Map (Track-6 / bd-1lda7)

`proof_guided_performance_opportunity_map.json` is the canonical machine-readable
optimization envelope map for Track-6 performance work. It defines:
- deterministic priority bands (`P0`-`P3`) with impact/risk/proof-confidence semantics
- `PG-OPT-*` opportunity envelopes with explicit:
  - allowed transformations
  - prohibited transformations
  - required `rch`-offloaded conformance checks
  - theorem/invariant constraint anchors (`OPT-*`)
- consumption contract fields required in performance bead payloads
- closed-loop consumer bead linkage for impact measurement

Validation is enforced in:
- `tests/lean_proof_guided_performance_opportunity_map.rs`

## Closed-Loop Impact Report (Track-6 / asupersync-3gf4i)

`proof_impact_closed_loop_report_v1.json` is the canonical machine-readable
closed-loop report contract for Track-6 measurement work. It defines:
- deterministic periodicity and reproducibility rules (`weekly` cadence, UTC windows,
  explicit `rch` command recording);
- measurement framework contracts for:
  - performance (`asupersync-228pu`)
  - reliability (`asupersync-2ue65`)
  - correctness (`asupersync-3o1ga`);
- required before/after/delta fields, confidence notes, and attribution metadata
  (`coverage_change_beads` + `source_field_path`);
- explicit performance workload definitions and reproducible commands for
  `asupersync-228pu` measurement cycles;
- explicit reliability milestone snapshots and delta summaries for
  `asupersync-2ue65` (diagnostic-time, incident-frequency, and severity-index trends);
- reliability attribution method contract (`method_id`, required `rch` commands,
  assumptions) plus mandatory caveats for confidence scoping;
- explicit correctness maturity snapshots and delta summaries for
  `asupersync-3o1ga` (regression-rate, rework burden, and time-to-diagnosis trends);
- reproducible correctness query contract (`repro_queries`) and governance-adjustment
  hooks for workflow/policy feedback;
- playbook handoff contract feeding the final case-study bead (`asupersync-3gfir`),
  including:
  - repeatable workflow template (steps/checklists/failure modes/templates)
  - three canonical case studies (performance/reliability/correctness) with
    baseline/intervention/measured outcome, artifact links, bead lineage, and
    reproducible commands.

Validation is enforced in:
- `tests/lean_proof_impact_closed_loop_report.rs`

Canonical validation command:

```bash
rch exec -- cargo test --test lean_proof_impact_closed_loop_report -- --nocapture
```

## Waiver Lifecycle Policy (Track-5.3a)

`ci_verification_profiles.json` now includes `waiver_policy` for proof-debt exception control:
- required waiver template fields: owner, reason, risk class, expiry, closure dependency path, status
- governance checks that fail on any active waiver whose expiry is at/before reference time
- closure requirements for closed waivers (`closure_bead`, `closed_at_utc`)

This policy is machine-enforced in `tests/lean_ci_verification_profiles.rs` to prevent permanent
exception creep.

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
