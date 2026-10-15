# Lab-vs-Live Divergence Taxonomy and Escalation Policy

**Bead**: `asupersync-2a6k9.1.3`  
**Parent**: `asupersync-2a6k9.1`, `asupersync-2a6k9`  
**Author**: QuietMoose  
**Date**: 2026-03-18  
**Policy Version**: `lab-live-divergence-policy-v1`

## Purpose

This document defines how the lab-vs-live differential program classifies mismatches, when it reruns them, which artifacts it must preserve, and when a mismatch is a real semantic failure versus a limitation of the current comparison surface.

Without this policy, every divergence turns into an argument about whether the runtime is wrong, the lab is incomplete, the comparator is too weak, or the environment is simply noisy. The point of this contract is to make that judgment explicit and repeatable.

## Upstream Contracts

This policy is downstream of:

- `docs/lab_live_differential_scope_matrix.md`
- `docs/lab_live_normalized_observable_schema.md`
- `docs/tokio_differential_behavior_suites.md`
- `docs/replay-debugging.md`

It must be read with the following boundary in mind:

1. the scope matrix decides whether a surface is even eligible for differential claims,
2. the normalized observable schema decides what counts as semantic equality,
3. this document decides what to do when the comparison does not come out clean.

## Core Distinctions

The differential program distinguishes four different things that are often conflated:

- **semantic mismatch**: normalized semantic fields differ,
- **artifact failure**: the run failed to emit the evidence needed for a valid comparison,
- **observability gap**: the surface may be meaningful in principle, but current instrumentation cannot classify it honestly,
- **noise or instability**: the raw execution differs, but the program cannot yet defend that difference as a true semantic bug.

Raw trace divergence is not automatically a semantic regression. Only divergence that survives scope checks and normalized comparison rules is eligible for promotion into a runtime or lab-model bug.

## Canonical Policy Classes

Every failed or suspicious comparison must land in exactly one final policy class:

| Policy class | Meaning | Blocking on `supported-now` surfaces | Default outcome |
|---|---|---|---|
| `runtime_semantic_bug` | Live runtime violates the admitted semantic contract | yes | regression |
| `lab_model_or_mapping_bug` | Lab model, normalizer, scenario adapter, or comparator mapping is wrong | yes | regression |
| `artifact_schema_violation` | Required comparison artifacts or fields are missing/malformed | yes | regression |
| `insufficient_observability` | Surface is in-bounds in principle, but current evidence cannot classify it honestly | yes | surface blocked until instrumentation improves |
| `unsupported_surface` | The comparison targeted a surface the scope matrix does not currently admit | no semantic verdict | surface rejected |
| `scheduler_noise_suspected` | Difference appears confined to unpromoted ordering/timing/provenance noise | no, but not a pass | triage |
| `irreproducible_divergence` | A semantic-looking mismatch occurred, but reruns could not stabilize it into a stronger class | not a pass | forensics required |

These are policy classes, not raw trace categories. They are intentionally fewer and more operational than `trace::divergence::DivergenceCategory`.

## Classification Order

Classification is ordered. Later classes may only be chosen after earlier checks have passed.

1. **Scope gate**  
   Use `docs/lab_live_differential_scope_matrix.md`. If the surface is `unsupported`, or `supported-later` but not yet promoted into the active rollout set, classify as `unsupported_surface`.
2. **Artifact completeness gate**  
   Verify the run emitted the required normalized record, scenario ID, seed lineage, repro command, and artifact pointers expected for the surface. Missing mandatory evidence is `artifact_schema_violation`.
3. **Semantic comparison gate**  
   Compare only the fields admitted by `docs/lab_live_normalized_observable_schema.md`. If no semantic fields differ, the run is not a semantic regression. Any remaining concern is either diagnostic-only or `scheduler_noise_suspected`.
4. **Observability sufficiency gate**  
   If semantic classification depends on fields the surface cannot currently emit, classify as `insufficient_observability` rather than guessing.
5. **Rerun gate**  
   Apply the rerun matrix in this document.
6. **Final promotion**  
   Promote to `runtime_semantic_bug`, `lab_model_or_mapping_bug`, `scheduler_noise_suspected`, or `irreproducible_divergence` based on rerun results and evidence stability.

## Policy-Class Definitions

### `runtime_semantic_bug`

Use this class when all of the following hold:

- the surface is admitted by the scope matrix,
- artifact completeness is satisfied,
- normalized semantic fields differ on a field that the surface contract marks as meaningful,
- the mismatch survives the rerun policy strongly enough to implicate the live path.

This class includes cases such as:

- terminal outcome mismatch on a `supported-now` surface,
- loser drain incomplete on the live path,
- region close not reaching quiescence when the scenario requires it,
- obligation leaks or unresolved obligations at the observation boundary,
- a panic or hard cancellation-protocol violation that the live runner surfaces but the lab contract forbids.

### `lab_model_or_mapping_bug`

Use this class when the divergence is better explained by the lab side or the comparison machinery than by the live runtime.

This includes:

- a deterministic lab replay with the same seed producing inconsistent normalized records,
- a normalizer or adapter mapping that misclassifies a lab fact,
- a comparator rule that treats a non-semantic field as semantic,
- a scenario adapter that feeds materially different inputs into lab and live runs,
- a lab oracle or harness conclusion that contradicts its own retained artifacts.

This class deliberately covers mapping and comparator mistakes, because those are effectively "lab-side bugs" from the standpoint of differential trust.

### `artifact_schema_violation`

Use this class when the run cannot be compared honestly because the required evidence bundle is incomplete or malformed.

Examples:

- missing normalized observable record,
- missing `scenario_id`, `surface_id`, or schema version,
- no repro command for a failing run,
- missing artifact pointer or crashpack linkage where the policy requires it,
- malformed or internally inconsistent rerun metadata,
- missing required semantic fields that the surface contract marks mandatory.

This is not a soft warning. A differential system without complete evidence is not trustworthy.

### `insufficient_observability`

Use this class when the surface is conceptually valid, but the current live or lab instrumentation cannot distinguish the required semantic cases.

Examples:

- a surface needs a loser-drain witness but only emits winner completion,
- a live runner can tell that a timeout happened but cannot separate cancel request from cancel acknowledgement,
- a comparison depends on obligation balance but only success/failure counters are available,
- timer or transport behavior is being compared before the necessary normalized clocks or captured boundary artifacts exist.

The key rule: if the system cannot justify a stronger class with current evidence, it must admit the observability gap.

### `unsupported_surface`

Use this class when the attempted comparison violates the scope matrix.

Typical examples:

- raw socket or reactor behavior,
- real network behavior over uncontrolled peers,
- browser-host behavior outside an explicit captured boundary,
- any `supported-later` surface pulled into the active gate before its admission bead lands.

This class does not mean "everything is fine." It means "this program is not allowed to make this claim yet."

### `scheduler_noise_suspected`

Use this class when the evidence points to ordering or timing instability that does not survive semantic normalization.

Examples:

- schedule hashes differ but normalized semantics match,
- the only differences are in unpromoted trace order, checkpoint ordering, or provenance-only fields,
- a one-off live mismatch disappears on immediate reruns and no stable semantic field set remains inconsistent,
- trace-level `SchedulingOrder`, `WakerMismatch`, or `TimeDivergence` appears without a surviving semantic mismatch on an admitted surface.

This class is triage, not success. Repeated noise on a supposedly stable surface should still trigger instrumentation work.

### `irreproducible_divergence`

Use this class when a semantic-looking mismatch occurred, artifacts are complete, but the rerun policy cannot stabilize it into a stronger explanation.

This class exists to prevent two failure modes:

- overreacting to one noisy live execution as if it were a confirmed bug,
- dismissing a real bug just because it is hard to reproduce.

An irreproducible divergence must still retain evidence and ownership. It just has not earned a stronger causal label yet.

## Rerun Policy

### General Rules

1. All reruns must preserve scenario identity and seed lineage.
2. Reruns are for classification, not for erasing evidence.
3. Once a run is provisionally classified, the original artifacts must be retained even if reruns later pass.
4. A rerun budget may be skipped only for classes that are immediately invalid by policy, such as `unsupported_surface` or `artifact_schema_violation`.

### Automatic Rerun Matrix

| Provisional class | Automatic reruns | Finalization rule |
|---|---|---|
| `unsupported_surface` | none | final immediately |
| `artifact_schema_violation` | none | final immediately |
| `insufficient_observability` | at most 1 confirmation rerun if richer instrumentation is already enabled in the same lane | otherwise final immediately |
| semantic mismatch on admitted surface | 1 deterministic lab replay + 2 live confirmation reruns | promote using the rules below |
| `scheduler_noise_suspected` | at most 2 live confirmation reruns | if semantic fields remain equal, final as noise |

The default live confirmation budget is therefore **3 total live observations**: the original failing run plus 2 immediate reruns.

### Promotion Rules After Reruns

Promote to `runtime_semantic_bug` when either condition holds:

1. the same semantic field set diverges in at least 2 of 3 live observations, or
2. any single observation shows a hard contract break on a `supported-now` surface:
   - leaked obligations,
   - unresolved obligations at close,
   - loser drain incomplete,
   - root region not quiescent when completion is required,
   - terminal panic where the contract forbids panic,
   - missing live cleanup/finalization after acknowledged cancellation.

Promote to `lab_model_or_mapping_bug` when either condition holds:

1. the deterministic lab replay with the same seed changes its own normalized result, or
2. repeated live observations agree with the retained surface evidence, but the lab-side mapping or comparator remains the unstable side.

Promote to `scheduler_noise_suspected` when:

- the mismatch does not survive semantic normalization across reruns, and
- only unpromoted ordering, timing, or provenance fields continue to drift.

Promote to `irreproducible_divergence` when:

- the mismatch cannot be downgraded to noise,
- artifacts are complete,
- reruns do not stabilize into either a runtime bug or a lab-side bug within the default budget.

## Artifact Preservation Policy

Artifact preservation is mandatory for every non-pass class. The difference is how much must be retained.

### Full Preservation Required

The following classes require the full evidence bundle:

- `runtime_semantic_bug`
- `lab_model_or_mapping_bug`
- `irreproducible_divergence`
- `artifact_schema_violation`

The minimum retained bundle must include:

- normalized lab record,
- normalized live record,
- scenario ID and surface ID,
- seed lineage,
- rerun count and rerun outcomes,
- divergence class,
- repro command bundle,
- repro manifest path,
- artifact pointer or bundle root,
- crashpack link when available,
- trace divergence report when available,
- minimal divergent prefix length when available.

### Reduced Preservation Allowed

The following classes may retain a lighter bundle, but still need a durable summary:

- `unsupported_surface`
- `insufficient_observability`
- `scheduler_noise_suspected`

The minimum reduced bundle must still include:

- scenario ID,
- surface ID,
- scope bucket,
- provisional and final class,
- seed lineage if present,
- explanation of why the stronger claim was not allowed,
- rerun commands if any reruns were attempted.

### Retention and Redaction

This policy inherits retention and redaction defaults from `docs/replay-debugging.md`:

- local retention default: 14 days,
- CI retention default: 30 days,
- default redaction mode: `metadata_only`.

This document does not define a second retention regime.

## Divergence Corpus Registry

Retained mismatches must also be recorded in a machine-readable registry so
future contributors can shrink, replay, and promote the case without manual
archaeology. The canonical schema id is:

- `lab-live-divergence-corpus-v1`

Each registry entry must record at least:

- `entry_id`
- `scenario_id`
- `surface_id`
- `surface_contract_version`
- `divergence_class`
- `policy_class`
- `first_seen.runner_profile`
- `first_seen.attempt_index`
- `first_seen.rerun_count`
- `seed_lineage`
- `minimization_lineage`
- `artifact_bundle`
- `regression_promotion_state`
- `retention.bundle_level`
- `retention.local_retention_days`
- `retention.ci_retention_days`
- `retention.redaction_mode`

### Stable Artifact Bundle Layout

When an entry points at a retained bundle, the bundle root must expand into the
same stable file set used by the broader differential program:

- `differential_summary.json`
- `differential_event_log.jsonl`
- `differential_failures.json`
- `differential_deviations.json`
- `differential_repro_manifest.json`
- `lab_normalized.json`
- `live_normalized.json`

`differential_failures.json` is the runtime-artifact index for the divergence
and must retain, per side:

- `failure_artifacts`
- `runtime_kind`
- `normalized_record_path`
- `artifact_path`
- `repro_command`
- `crashpack_link` when the retained artifact is a crashpack

`differential_repro_manifest.json` is the replay/minimization control plane for
the bundle and must retain at least:

- `summary_path`
- `deviations_path`
- `failure_artifacts_path`
- `lab_normalized_path`
- `live_normalized_path`
- `repro_commands`
- `promoted_scenario_id` when the case has already become a durable regression

### Lifecycle and Promotion Rules

`regression_promotion_state` must follow an explicit lifecycle instead of ad-hoc
operator notes:

- `investigating`: first-seen divergence retained with its original lineage
- `minimized`: a shrinker produced a smaller reproducer that preserved the same
  divergence/policy class
- `promoted_regression`: the minimized or original case was admitted into the
  durable regression corpus
- `known_open`: retained for forensics, but intentionally not promoted yet
- `rejected`: explicitly excluded because shrink/promotion did not preserve the
  semantic claim

`minimization_lineage` must preserve semantic meaning, not merely shrink event
count or bytes. At minimum it must record:

- `original_seed`
- `minimized_seed` when available
- `shrinker`
- `shrink_status`
- whether the minimized case preserved the same divergence class
- whether the minimized case preserved the same policy class

### Bundle Strength Mapping

The registry must mirror the retention strength already implied by the policy
class:

- `runtime_semantic_bug`, `lab_model_or_mapping_bug`, `artifact_schema_violation`,
  and `irreproducible_divergence` require `retention.bundle_level = full`
- `insufficient_observability`, `unsupported_surface`, and
  `scheduler_noise_suspected` require `retention.bundle_level = reduced`

## Diagnostic Evidence Mapping

`trace::divergence::DivergenceCategory` is diagnostic evidence, not the final policy label.

| Diagnostic signal | Typical policy interpretation |
|---|---|
| `SchedulingOrder`, `WakerMismatch` | `scheduler_noise_suspected` unless the surface explicitly promotes ordering |
| `TimeDivergence`, `TimerMismatch` | `unsupported_surface`, `insufficient_observability`, or a real bug depending on whether timer semantics are admitted for that surface |
| `OutcomeMismatch` | usually `runtime_semantic_bug` or `lab_model_or_mapping_bug` |
| `RegionMismatch`, `CheckpointMismatch` | usually `runtime_semantic_bug` or `lab_model_or_mapping_bug` |
| `IoMismatch` | not automatically meaningful unless the I/O boundary is virtualized and admitted |
| `LengthMismatch` | diagnostic-only unless it survives normalized comparison |

The diagnostic category may help explain a policy class, but it must never bypass the scope or normalized-schema gates.

## Escalation Policy

### On `supported-now` Surfaces

| Final class | Required action |
|---|---|
| `runtime_semantic_bug` | fail the differential gate, retain full artifacts, open or update a regression bead |
| `lab_model_or_mapping_bug` | fail the differential gate, retain full artifacts, open or update a lab/comparator bug bead |
| `artifact_schema_violation` | fail the differential gate, fix the evidence pipeline before trusting the surface again |
| `insufficient_observability` | block the surface from positive claims until instrumentation or normalization improves |
| `scheduler_noise_suspected` | do not mark pass; record triage item, continue only if the release policy treats this lane as informational |
| `irreproducible_divergence` | do not mark pass; retain full bundle and route to forensics owner |

### On `supported-later` Surfaces

Non-pass classes are informative, but they do not count as runtime regressions against the main trust claim. The default response is:

1. retain the evidence,
2. avoid promoting the surface into `supported-now`,
3. open the instrumentation, virtualization, or harness bead that would make the class more decisive next time.

### On `unsupported` Surfaces

The only correct action is to reject the claim surface. Repeated runs do not convert an unsupported surface into a supported one.

## Operational Examples

### Example 1: One-Off Timing Drift

- Timer surface is still `supported-later`.
- Lab and live raw traces disagree on timing order.
- No normalized Phase-1 semantic field differs.

Final class: `unsupported_surface` or `scheduler_noise_suspected`, depending on whether the surface was admitted at all. It is not a runtime regression.

### Example 2: Stable Loser-Drain Failure

- Surface: combinator race on a `supported-now` path.
- Live run reports `loser_drain.status = incomplete`.
- Lab record says `complete`.
- Same semantic mismatch appears in 2 of 3 live observations.

Final class: `runtime_semantic_bug`.

### Example 3: Lab Replay Changes Its Own Answer

- Original lab run says the scenario is quiescent.
- Deterministic lab replay with the same seed yields a different normalized record.

Final class: `lab_model_or_mapping_bug`.

### Example 4: Missing Required Cancellation Evidence

- Surface contract requires cancellation acknowledgement.
- Live runner emits request and terminal outcome but no acknowledgement or cleanup witness.

Final class: `insufficient_observability`, unless the missing field was marked mandatory and omitted from the artifact schema entirely, in which case `artifact_schema_violation`.

## Downstream Binding

This document is normative for:

| Downstream bead family | What it must consume |
|---|---|
| `asupersync-2a6k9.2.*` | scenario runners must emit enough evidence to support these classes |
| `asupersync-2a6k9.4.*` | live evidence capture must retain the fields this policy needs |
| `asupersync-2a6k9.4.4` | timing and scheduler-noise qualification must refine how `scheduler_noise_suspected`, `TimeDivergence`, and `TimerMismatch` are interpreted |
| `asupersync-2a6k9.5.*` | comparator outputs must produce one of these final policy classes |
| `asupersync-2a6k9.6.*` | pilot suites must treat scope and escalation rules here as binding |
| `asupersync-2a6k9.7.*` | CI and stress lanes must wire gate behavior to these classes rather than inventing new verdict labels |

If a later bead introduces a new divergence label, it must either map cleanly into one of these classes or revise this policy deliberately.

## Validation Expectations

Future contract tests for this policy should verify:

1. all final policy classes remain present and stable,
2. scope checks happen before semantic promotion,
3. artifact/schema failures are not misreported as runtime bugs,
4. rerun budgets and promotion rules remain explicit,
5. `supported-now`, `supported-later`, and `unsupported` surfaces escalate differently.

## Cross-References

- `docs/lab_live_differential_scope_matrix.md`
- `docs/lab_live_normalized_observable_schema.md`
- `docs/replay-debugging.md`
- `docs/semantic_divergence_rubric.md`
- `docs/semantic_divergence_options.md`
- `docs/semantic_maintainer_playbook.md`
- `src/trace/divergence.rs`
- `src/trace/replayer.rs`
- `src/lab/replay.rs`
