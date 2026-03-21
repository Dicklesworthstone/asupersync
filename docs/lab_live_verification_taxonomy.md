# Lab-vs-Live Verification Taxonomy and Logging Standard

**Bead**: `asupersync-2a6k9.1.4`  
**Parent**: `asupersync-2a6k9.1`, `asupersync-2a6k9`  
**Author**: WhiteCrane (codex-cli / gpt-5)  
**Date**: 2026-03-18  
**Standard Version**: `lab-live-verification-taxonomy-v1`

## Purpose

This document defines the minimum verification and logging contract for the
lab-vs-live differential program.

The scope matrix already says which semantic surfaces are admitted. The
normalized observable schema already says what semantic equality means. The
divergence taxonomy already says how failures are classified.

What was still too implicit was the question every implementation bead needs to
answer before it can claim to be "tested":

1. what unit or contract tests are mandatory,
2. what end-to-end differential runs are mandatory,
3. what negative-control or self-calibration evidence is mandatory,
4. what structured logs and artifacts are mandatory when those runs execute.

This document makes those requirements explicit so later beads do not invent
their own private definition of sufficient coverage.

## Upstream Contracts

This standard is downstream of:

- `docs/lab_live_differential_scope_matrix.md`
- `docs/lab_live_normalized_observable_schema.md`
- `docs/lab_live_divergence_taxonomy.md`
- `docs/lab_live_scenario_adapter_contract.md`
- `docs/tokio_differential_behavior_suites.md`
- `TESTING.md`
- `tests/common/mod.rs`

It must be read with one hard rule in mind:

- the scope matrix decides whether a surface may be differentialized,
- the scenario adapter decides how a shared scenario binds to lab and live,
- the normalized schema decides what semantic record both sides must emit,
- this document decides what verification depth and what logging bundle a bead
  must deliver before the program treats that surface as credibly covered.

## Core Rule

No later `asupersync-2a6k9.*` bead is complete with only prose, only unit
tests, or only one successful differential run.

Every executable bead in this program must provide evidence in the following
layers unless this document explicitly marks a layer as not yet required for
that bead class:

1. **unit or contract verification** for the local rule set,
2. **golden or schema verification** for any normalized record or report shape,
3. **dual-run smoke coverage** through the real shared lab/live contract when
   the bead changes executable differential behavior,
4. **negative-control or self-calibration evidence** when the bead changes
   classifier, comparator, logging, or artifact policy,
5. **structured logs and retained artifacts** for every failure or suspicious
   run class the bead can produce.

If a bead cannot satisfy one of these layers, it must say why in its contract
or notes. Silence is not acceptable.

## Verification Taxonomy

The differential program uses the following taxonomy. Later beads should reuse
these labels rather than inventing new categories.

| Tier | Canonical label | Purpose | Typical proof artifact |
|---|---|---|---|
| `T0` | `unit_contract` | Lock local semantics, field sets, policy tokens, and validation commands | direct Rust tests against a doc contract or helper behavior |
| `T1` | `golden_fixture` | Freeze normalized records, schema outputs, or report bundles | checked-in JSON/NDJSON fixture or direct schema assertions |
| `T2` | `dual_run_smoke` | Prove the same scenario executes through lab and live adapter lanes | one deterministic lab/live smoke path |
| `T3` | `pilot_surface` | Exercise the admitted semantic surface with multiple scenario families | phase-1 pilot suites for cancellation, combinators, channels, obligations, region close/quiescence |
| `T4` | `negative_control` | Prove the comparator and policy layers fail for the right reasons | intentionally divergent or artifact-incomplete scenarios |
| `T5` | `stress_nightly` | Explore adversarial or noisy corners after the core contract is stable | retained rerun corpus, nightly seeds, drift bundles |

The important distinction is that these are not five optional ideas. They are
the vocabulary the whole program must use when describing verification depth.

## Minimum Requirements by Bead Class

### 1. Policy or Contract Beads

Examples:

- `asupersync-2a6k9.1.1`
- `asupersync-2a6k9.1.2`
- `asupersync-2a6k9.1.3`
- `asupersync-2a6k9.1.4`

Minimum requirements:

- `T0 unit_contract` is mandatory.
- The contract test must pin:
  - bead ID,
  - parent IDs,
  - upstream dependency documents,
  - key field tokens,
  - downstream bead bindings,
  - `rch exec -- ...` validation commands.
- `T1 golden_fixture` is optional unless the bead defines a concrete serialized
  schema example.
- `T2 dual_run_smoke` is not required if the bead only defines policy and does
  not change executable harness behavior.
- The document must still define what future executable beads owe.

### 2. Shared Harness or Helper Beads

Examples:

- `asupersync-2a6k9.2.2`
- `asupersync-2a6k9.2.4`

Minimum requirements:

- `T0 unit_contract` is mandatory for helper behavior and mismatch messages.
- `T1 golden_fixture` is mandatory whenever helper output is serialized or
  schema-shaped.
- `T2 dual_run_smoke` is mandatory if the helper is consumed by lab/live
  execution paths.
- A helper bead is not complete until at least two differential suites or two
  surface-specific scenarios use the shared helper instead of hand-rolling their
  own assertions.

### 3. Live Evidence, Normalizer, and Comparator Beads

Examples:

- `asupersync-2a6k9.4.*`
- `asupersync-2a6k9.5.*`

Minimum requirements:

- `T0 unit_contract` for mapping rules, classifier logic, and invariant
  interpretation.
- `T1 golden_fixture` for normalized record and report bundle shapes.
- `T2 dual_run_smoke` for at least one shared scenario that emits the changed
  record/report path.
- `T4 negative_control` is mandatory.

Required negative-control cases:

- a semantic mismatch that must classify as a hard failure,
- an artifact-missing run that must classify as `artifact_schema_violation`,
- a provenance-only drift case that must not be promoted to semantic mismatch,
- when applicable, a rerun bundle that stabilizes into the expected final policy
  class.

### 4. Pilot Surface Beads

Examples:

- `asupersync-2a6k9.6.1`
- `asupersync-2a6k9.6.2`
- `asupersync-2a6k9.6.3`
- `asupersync-2a6k9.6.4`
- `asupersync-2a6k9.6.5`
- `asupersync-2a6k9.6.6`

Minimum requirements:

- `T0 unit_contract` for surface-local invariants.
- `T2 dual_run_smoke` for the surface's canonical shared scenario.
- `T3 pilot_surface` for multiple scenario families on the admitted surface.
- `T4 negative_control` for at least one semantic failure witness.
- Logs and artifacts must use the exact vocabulary in this document.

### 5. Expansion, Eligibility, and Operations Beads

Examples:

- `asupersync-2a6k9.7.*`
- `asupersync-2a6k9.8.*`

Minimum requirements:

- inherit all earlier applicable tiers,
- explicitly name the new surface or operator policy being promoted,
- declare whether `T5 stress_nightly` becomes mandatory,
- retain contributor-facing repro commands and operator-facing artifact indexes.

Eligibility-gate beads for external surfaces must do more than say "not yet" or
"probably okay." They must publish the exact boundary, evidence, and failure
contract a later promotion bead must satisfy.

## Eligibility-Gate Matrix for External Surfaces

For `asupersync-2a6k9.7.3`-style work, the gate itself may be contract-only
today, but it must still define the executable floor before any meaningful
parity claim is allowed.

| Surface family | Gate-specific `T0` requirements | Promotion floor before `T2/T3` claims count | Mandatory `T4` rejection cases |
|---|---|---|---|
| `raw_socket` | boundary contract, virtualization boundary, connection-lifecycle field map, unsupported red lines | bounded loopback or virtual transport runner with shared normalized records and retained repro artifacts | unsupported-surface rejection, missing-capture rejection, and kernel-timing non-claim proof |
| `http_surface` | request/response field map, peer-model contract, timeout/cancellation boundary, artifact schema | virtualized or loopback HTTP runner with shared normalized request/response records and shutdown coverage | malformed artifact rejection, under-observed peer rejection, and real-network non-claim proof |
| `browser_surface` | host-role contract, lane-selection policy, downgrade semantics, explicit support boundaries | admitted browser runner lanes with shared normalized semantic subset and retained downgrade artifacts | unsupported-host rejection, downgrade-path proof, and ambient-host-timing non-claim proof |

### Required Eligibility-Gate Log Fields

When a bead publishes or evaluates an external-surface gate, the stable record
must include:

- `eligibility_verdict`
- `surface_family`
- `virtualization_boundary`
- `observability_status`
- `capture_manifest_path`
- `normalized_record_path`
- `artifact_bundle`
- `repro_command`
- `unsupported_reason`

Browser-facing gate records must additionally include:

- `host_role`
- `support_class`
- `reason_code`
- `lane_id`

These are not optional operator niceties. They are the minimum machine-readable
fields required to keep "eligible later" and "unsupported today" from
collapsing into vague prose.

## Minimum Coverage Matrix for Phase 1 Surfaces

The first active rollout lane is still the `Phase 1` ladder from
`docs/lab_live_differential_scope_matrix.md`:

`cancellation -> combinators -> channels -> obligations -> region close/quiescence`

Before the program claims Phase 1 closure, the minimum matrix is:

| Surface | Minimum `T0` coverage | Minimum `T2/T3` coverage | Minimum `T4` coverage |
|---|---|---|---|
| `cancellation` | request/ack/finalize semantics, checkpoint acknowledgement, hard mismatch fields | one shared lab/live scenario with explicit cancel request and completed cleanup | at least one case proving missing cleanup/finalization is a hard failure |
| `combinators` | winner/loser semantics, severity aggregation, join/race intent | one shared loser-drain scenario through both adapters | one case where losers do not drain and the mismatch is retained |
| `channels` | reserve/commit semantics, committed vs aborted accounting, receiver-visible meaning | one shared reserve/send differential scenario | one artifact or semantic case showing cancel-correct delivery was not observed |
| `obligations` | committed/aborted/leaked/unresolved accounting and `balanced` derivation | one shared scenario that exercises real obligation closure at the surface boundary | one case where unresolved or leaked obligations force failure |
| `region_close` / `quiescence` | region-close facts and close boundary invariants | one shared scenario that reaches `quiescent = true` with no live children | one case where region close remains incomplete or non-quiescent |

No Phase 2 surface should be allowed to claim stronger differential closure
while any of the Phase 1 rows still lack their minimum `T0`, `T2/T3`, and `T4`
evidence.

### Core Pilot Refinement Matrix (`asupersync-2a6k9.6.6`)

`asupersync-2a6k9.6.6` exists to turn the Phase 1 floor into an
implementation-facing matrix. Pilot beads should not be allowed to say "we hit
the cancellation surface" or "we ran one channel scenario" without naming which
invariants, scenario families, and retained fields were actually covered.

The rows below refine the minimum matrix above. They do not replace it. A Phase
1 pilot bead is incomplete if its notes, tests, or retained bundles cannot be
mapped back to every applicable row here.

| Surface | Required `T0` unit-contract checks | Required shared `T2/T3` scenario families | Required `T4` adversarial witnesses | Required invariant-log focus |
|---|---|---|---|---|
| `cancellation` | `cancel_request_recorded`, `checkpoint_acknowledged`, `cleanup_finalized`, `repeat_cancel_idempotent` | `cancel_before_first_poll`, `cancel_during_child_await`, `cancel_during_cleanup_budget` | `missing_cleanup_ack_hard_failure`, `cleanup_budget_exhausted`, `late_cancel_after_finalize_rejected` | `cancellation.requested`, `cancellation.acknowledged`, `cancellation.finalized`, `terminal_outcome`, `repro_command` |
| `combinators` | `join_loser_drain`, `race_winner_commit_boundary`, `severity_aggregation_stable`, `nested_join_race_outcome_visibility` | `join_all_success`, `race_single_winner`, `mixed_success_failure_aggregation`, `nested_join_race_chain` | `loser_not_drained_hard_failure`, `winner_masked_by_late_failure`, `aggregate_severity_misclassified` | `loser_drain`, `terminal_outcome`, `policy_class`, `artifact_bundle`, `normalized_record_path` |
| `channels` | `reserve_abort_invisible_to_receiver`, `reserve_commit_visible_once`, `fifo_sender_order_preserved`, `sender_cancel_after_reserve_balanced` | `single_sender_commit`, `reserve_then_abort`, `multi_sender_fifo`, `receiver_retry_after_pending` | `committed_message_missing_hard_failure`, `aborted_message_delivered`, `permit_leak_forces_failure` | `resource_surface`, `obligation_balance`, `terminal_outcome`, `artifact_bundle`, `repro_command` |
| `obligations` | `balanced_after_commit_and_abort`, `unresolved_obligation_reported`, `recovery_path_preserves_lineage`, `close_boundary_obligation_snapshot` | `commit_abort_mix_at_surface_boundary`, `recovery_after_interrupted_flow`, `close_with_no_live_obligations` | `leaked_obligation_forces_failure`, `stale_recovery_overwrite_rejected`, `unresolved_on_close_hard_failure` | `obligation_balance`, `policy_class`, `normalized_record_path`, `artifact_bundle`, `repro_command` |
| `region_close` / `quiescence` | `close_boundary_rejects_new_children`, `quiescent_after_last_child`, `finalizer_completion_counted`, `nested_region_close_visibility` | `close_with_nested_children`, `close_after_child_cancel`, `close_after_finalizer_completion` | `late_spawn_after_close_rejected`, `non_quiescent_close_hard_failure`, `stuck_finalizer_retained` | `region_close`, `terminal_outcome`, `artifact_bundle`, `normalized_record_path`, `repro_command` |

Interpretation rules for the refinement matrix:

- every Phase 1 pilot surface must name at least one concrete scenario family
  for each row it claims to satisfy; "misc smoke coverage" is not enough
- every retained bundle must make the required invariant-log focus discoverable
  either directly in the scenario result record or through a stable referenced
  artifact path
- a pilot may reuse the same executable scenario across multiple rows only if
  the scenario result explicitly reports all required invariant-log focus fields
- `asupersync-2a6k9.6.6` should be treated as the checklist upgrade that future
  `2a6k9.6.*` implementation beads must point at when they claim closure

## Structured Logging Standard

Every executable differential bead must emit structured logs or records with a
minimum vocabulary that is stable across suites.

### Required Identity Fields

Every scenario-level log or record must include:

- `schema_version`
- `suite_id`
- `scenario_id`
- `surface_id`
- `surface_contract_version`
- `seed_lineage_id`
- `phase`
- `runtime_kind`
- `runner_profile`
- `adapter`

### Required Execution Fields

Every scenario result or mismatch record must include:

- `attempt_index`
- `rerun_count`
- `status`
- `divergence_class`
- `policy_class`
- `known_nondeterminism_qualifier`
- `normalized_record_path`
- `artifact_bundle`
- `repro_command`

### Required Semantic Summary Fields

When a run emits a normalized record summary, the log vocabulary must preserve
the fields that later operators and comparators need to reason about:

- `terminal_outcome`
- `cancellation`
- `loser_drain`
- `region_close`
- `obligation_balance`
- `resource_surface`

These may appear as embedded objects, stable summaries, or referenced paths,
but the scenario result record must make them discoverable.

### Required Artifact Records

The retained bundle for a differential run must be discoverable through stable
names. At minimum, executable program beads should converge on:

- `differential_summary.json`
- `differential_event_log.jsonl`
- `differential_failures.json`
- `differential_deviations.json`
- `differential_repro_manifest.json`

When normalized records are emitted as standalone artifacts, both sides should
also expose:

- `lab_normalized.json`
- `live_normalized.json`

### Forbidden Logging Habits

The following do not satisfy the standard:

- free-form human prose with no machine-readable fields,
- logs that omit `scenario_id` or `seed_lineage_id`,
- logs that record raw trace drift without saying whether semantic fields differ,
- logs that record a failure with no `repro_command`,
- logs that bury the artifact bundle path only in stderr text.

## Failure Diagnostics and Retention

This standard inherits the final policy classes from
`docs/lab_live_divergence_taxonomy.md` and adds minimum logging obligations:

| Policy class | Minimum retention required |
|---|---|
| `runtime_semantic_bug` | full bundle, normalized lab/live records, repro commands, rerun summary, artifact pointer |
| `lab_model_or_mapping_bug` | full bundle plus the inconsistent mapping or comparator evidence |
| `artifact_schema_violation` | malformed or missing artifact summary plus direct repro command |
| `insufficient_observability` | reduced bundle plus explicit missing field list and blocked-surface note |
| `unsupported_surface` | reduced bundle plus explicit scope rejection reason |
| `scheduler_noise_suspected` | reduced bundle plus rerun summary and provenance drift summary |
| `irreproducible_divergence` | full bundle plus rerun chronology and ownership handoff note |

## Validation Commands

Heavy validation commands must run through `rch exec --`.

- `rch exec -- cargo fmt --check`
- `rch exec -- cargo check --all-targets`
- `rch exec -- cargo clippy --all-targets -- -D warnings`
- `rch exec -- cargo test --test lab_live_verification_taxonomy_contract -- --nocapture`

If this bead or a later bead adds executable helper code, it should also run
the narrowest relevant contract or smoke test under `rch exec -- ...`.

## Downstream Binding

This standard is upstream policy for the immediate follow-on beads:

| Downstream bead | What it must consume from this document |
|---|---|
| `asupersync-2a6k9.2.2` | shared helper behavior and mismatch messages must satisfy `T0`, and helper usage must expand beyond one bespoke suite |
| `asupersync-2a6k9.2.5` | harness contract tests and smoke e2e coverage must satisfy the minimum bead-class matrix here |
| `asupersync-2a6k9.4.5` | live evidence and normalization tests must provide `T1` golden records and structured summary fields |
| `asupersync-2a6k9.5.4` | reusable runner scripts and report pipeline must emit the exact required identity, execution, and artifact fields |
| `asupersync-2a6k9.5.5` | negative-control and self-calibration scenarios must use the `T4 negative_control` requirements here |
| `asupersync-2a6k9.6.6` | the pilot coverage matrix and invariant log contract must refine, not replace, the minimum Phase 1 matrix here |
| `asupersync-2a6k9.7.3` | eligibility gates for raw-socket, HTTP, and browser surfaces must publish the external-surface gate matrix, required gate log fields, and rejection cases defined here |
| `asupersync-2a6k9.8.*` | CI, nightly, summaries, and contributor playbooks must preserve these tier names and required artifact fields |

If a later bead claims completion with weaker evidence than this document
requires, that bead is incomplete even if the implementation itself looks good.

## Explicit Non-Goals

This document does not:

- replace the semantic equality rules in
  `docs/lab_live_normalized_observable_schema.md`,
- replace the final policy classes in `docs/lab_live_divergence_taxonomy.md`,
- require every contract-only bead to invent fake executable differential runs,
- treat performance parity as a substitute for semantic coverage,
- allow manual inspection alone to stand in for structured logs or retained
  artifacts.

## Exit Criteria

`asupersync-2a6k9.1.4` is complete when:

1. this document exists and is substantial,
2. the taxonomy tiers are explicit and reusable,
3. minimum unit/e2e/negative-control requirements are stated for later beads,
4. structured logging vocabulary is concrete enough to validate mechanically,
5. downstream beads can reference this document directly instead of guessing
   what "tested" means,
6. the contract test for this document passes deterministically.
