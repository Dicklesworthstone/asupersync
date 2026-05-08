# Lab-vs-Live Time and Scheduler-Noise Normalization Policy

**Bead**: `asupersync-2a6k9.4.4`  
**Parent**: `asupersync-2a6k9.4`, `asupersync-2a6k9`  
**Author**: WhiteCrane  
**Date**: 2026-03-19  
**Policy Version**: `lab-live-time-normalization-v1`

## Purpose

This document defines how the lab-vs-live differential program treats
time-related evidence, scheduler noise, and rerun qualification during live
re-execution.

The differential program already has:

- a scope ladder in `docs/lab_live_differential_scope_matrix.md`,
- a semantic denominator in `docs/lab_live_normalized_observable_schema.md`,
- a final policy-class system in `docs/lab_live_divergence_taxonomy.md`,
- a minimum verification/logging contract in `docs/lab_live_verification_taxonomy.md`,
- and concrete live-run metadata in `src/lab/dual_run.rs`.

What was still too implicit was the boundary between:

- time facts that are genuinely semantic,
- time facts that are only admissible after normalization,
- time facts that are provenance only,
- and scheduler-noise signals that must be explained in reports but must not
  silently rewrite the semantic verdict.

Without this policy, contributors can easily make one of two bad mistakes:

1. treat every timing drift as a real bug, which makes the program brittle and
   noisy, or
2. wave away real timer/deadline bugs as "just scheduler noise," which makes
   the differential program dishonest.

The purpose of this document is to remove that ambiguity.

## Upstream Contracts

This policy is downstream of:

- `docs/lab_live_differential_scope_matrix.md`
- `docs/lab_live_normalized_observable_schema.md`
- `docs/lab_live_divergence_taxonomy.md`
- `docs/lab_live_verification_taxonomy.md`
- `docs/lab_live_scenario_adapter_contract.md`
- `docs/tokio_differential_behavior_suites.md`
- `src/lab/dual_run.rs`
- `tests/common/mod.rs`

It must be read with the following division of labor:

1. the scope matrix decides whether timer or transport timing is even allowed to
   participate in the trust claim,
2. the normalized observable schema decides which record fields are semantic
   versus provenance by default,
3. this document decides when time facts stay suppressed, when they become
   qualified comparison inputs, and how scheduler-noise explanations must appear
   in reports,
4. the divergence taxonomy decides which final policy class to emit after the
   time and noise rules here are applied.

## Core Rule

Only scenario-clocked and contract-promoted time facts may affect semantic
equality.

Everything else must be one of:

- `qualified_time`, meaning comparison is allowed only under an explicit
  normalization rule,
- `provenance_only_time`, meaning retained for replay and forensics but never a
  semantic verdict input,
- `scheduler_noise_signal`, meaning diagnostic evidence that can explain drift
  but cannot erase a hard semantic mismatch,
- `unsupported_time_surface`, meaning the comparison is not yet allowed to make
  a timing claim at all.

The critical non-negotiables are:

1. `Phase 1` `supported-now` surfaces do not become timing-sensitive just
   because they emit `schedule_hash`, `event_hash`, `steps_delta`, or
   `nondeterminism_notes`.
2. `Phase 2` `supported-later` timer and virtualized-transport surfaces may
   promote time facts only through scenario clocks, explicit deadline identities,
   and normalization windows.
3. wall-clock timestamps, raw elapsed nanoseconds, trace lengths, and scheduler
   queue detail are provenance-only unless a later contract explicitly promotes
   them.
4. scheduler noise may qualify or explain a mismatch, but it must never be used
   to downgrade a hard semantic contract break such as leaked obligations,
   incomplete loser drain, or failed close-to-quiescence.

## Canonical Time and Noise Classes

Every time-related observation in the differential program must land in exactly
one of the following classes before final policy classification:

| Class | Meaning | Equality role | Typical examples |
|---|---|---|---|
| `semantic_time` | A time fact the surface contract explicitly promotes into the semantic surface | compared directly after normalization | `timeout_outcome_class`, deadline met/violated, logical-time progression on an admitted timer surface |
| `qualified_time` | A time fact that may be compared only with an explicit scenario clock and normalization rule | compared only through a declared rule | bounded timeout window, rerun-stable ordering window, scenario-clock elapsed bucket |
| `provenance_only_time` | A retained timing artifact with replay/debug value but no default semantic force | audit only | `wall_elapsed_ns`, `now_nanos`, `steps_delta`, `monotonic_start_ns`, `monotonic_end_ns` |
| `scheduler_noise_signal` | A diagnostic signal suggesting ordering or host jitter drift | explanation only | `schedule_hash`, `event_hash`, `event_count`, `nondeterminism_notes`, raw wake ordering |
| `unsupported_time_surface` | A timing claim the scope ladder does not currently admit | rejected | raw host-clock latency, uncontrolled network delay, browser host scheduler quirks |

These classes are intentionally narrower than the divergence taxonomy. The
divergence taxonomy answers "what is the final policy class?" This document
answers "what kind of time/noise evidence is even being discussed before that?"

## Phase Policy

### 1. `Phase 1` `supported-now` Surfaces

For `Phase 1` surfaces such as cancellation, combinators, channels,
obligations, region close/quiescence, and bounded sync primitives:

- time is not a first-class semantic target,
- ordering and timing drift may appear in artifacts,
- `schedule_hash`, `event_hash`, `event_count`, `steps_delta`, and
  `nondeterminism_notes` are explanatory only,
- a `Phase 1` pass/fail verdict must still be driven by normalized semantic
  records such as terminal outcome, cancellation lifecycle, loser drain,
  obligation balance, and quiescence.

In other words: `Phase 1` may record timing instability, but it must not make
timing the thing being proved.

### 2. `Phase 2` `supported-later` Timer and Virtualized-Transport Surfaces

For `Phase 2` surfaces, time may become semantic only when all of the following
are true:

1. the scenario declares a stable `scenario_clock_id`,
2. the surface declares a `clock_source`,
3. the surface names a stable `logical_deadline_id` or equivalent boundary,
4. the surface defines a `normalization_window`,
5. the surface explains whether the compared time fact is `semantic_time` or
   `qualified_time`,
6. reruns preserve seed lineage and the same clock interpretation.

If any of those are missing, the surface is not timing-comparison-ready and
must classify the missing capability as `insufficient_observability` or
`unsupported_time_surface`, not as a weak pass.

### 3. `Phase 3` and `Phase 4`

For richer protocol, browser, or raw-host surfaces:

- `Phase 3` may promote time only through captured boundaries and virtualized
  or explicitly modeled clocks,
- `Phase 4` remains out of scope for raw host timing claims,
- repeated real-world latency observations do not promote an unsupported surface
  into a supported one.

## Eligibility-Gate Timing Rules for Raw-Socket, HTTP, and Browser Surfaces

Bead `asupersync-2a6k9.7.3` depends on this section when deciding whether an
external surface is timing-comparison-ready or still blocked.

| Surface family | Timing claims rejected now | Timing claims admissible later |
|---|---|---|
| `raw_socket` | kernel wake ordering, epoll/kqueue/io_uring latency, DNS timing, TLS handshake timing, remote RTT, and wall-clock throughput/latency claims | only scenario-clocked timeout or cancellation facts over loopback or virtual transport with declared `scenario_clock_id`, `clock_source`, `logical_deadline_id`, and `normalization_window` |
| `http_surface` | real-internet RTT, CDN or upstream service latency, uncontrolled peer processing time, and raw wall-clock request timing | only request/response timeout and termination semantics over captured or virtualized transport with the same scenario clock and deadline vocabulary |
| `browser_surface` | browser event-loop jitter, rendering cadence, service-worker lifetime timing, shared-worker host timing, and opaque Web API latency | only admitted lane-selection or timeout semantics when `host_role`, `lane_id`, `support_class`, and `reason_code` are captured and the time fields satisfy this policy's scenario-clock requirements |

If an external-surface proposal cannot satisfy the "admissible later" column,
its timing claim must remain `unsupported_time_surface` or
`insufficient_observability`.

## Field-Level Normalization Contract

The following field classes are normative for later runners, comparators, and
report pipelines:

| Field | Class | Comparison policy | Required report behavior |
|---|---|---|---|
| `scenario_clock_id` | `semantic_time` gate | exact match when time is admitted | always emit when a timing claim is made |
| `clock_source` | `semantic_time` gate | exact match | state whether the source is logical, virtualized, or host-derived |
| `logical_deadline_id` | `semantic_time` | exact match | explain which deadline or timeout boundary was under test |
| `timeout_budget_class` | `qualified_time` | exact or declared bucket match | show whether the budget is semantic or advisory |
| `timeout_outcome_class` | `semantic_time` when admitted | exact match | explicitly say whether the timeout completed, cancelled, or remained pending |
| `logical_elapsed_ticks` | `qualified_time` | compare only through `normalization_window` | never compare raw values without a scenario clock |
| `normalization_window` | policy metadata | exact match | state the admitted tolerance or bucket rule |
| `rerun_interval_class` | `qualified_time` | compare by class, not raw duration | explain rerun pacing when timing instability is suspected |
| `wall_elapsed_ns` | `provenance_only_time` | ignore for equality | retain for forensics only |
| `monotonic_start_ns` | `provenance_only_time` | ignore for equality | retain for audit only |
| `monotonic_end_ns` | `provenance_only_time` | ignore for equality | retain for audit only |
| `now_nanos` | `provenance_only_time` | ignore for equality | do not promote without a later contract |
| `steps_delta` | `provenance_only_time` | ignore for equality | useful for replay, not semantic equality |
| `schedule_hash` | `scheduler_noise_signal` | ignore for equality by default | may justify a `scheduler_noise_suspected` explanation |
| `event_hash` | `scheduler_noise_signal` | ignore for equality by default | record as divergence evidence only |
| `event_count` | `scheduler_noise_signal` | ignore for equality by default | may support triage, not verdict |
| `nondeterminism_notes` | `scheduler_noise_signal` | explanation only | must be retained verbatim in report output |
| `suppression_reason` | policy metadata | informational only | mandatory whenever time or order drift is suppressed |
| `rerun_decision` | policy metadata | informational only | mandatory whenever timing/noise drives an automatic rerun choice |

## Mapping Rules

### Lab Mapping

Lab-side time and scheduler evidence may use deterministic artifacts such as:

- `ReplayMetadata`,
- `LabRunReport.seed`,
- `LabRunReport.steps_delta`,
- `LabRunReport.steps_total`,
- `trace_fingerprint`,
- `trace_certificate.schedule_hash`,
- `trace_certificate.event_hash`,
- oracle timing checks,
- scenario-declared logical clocks.

Normative lab rules:

1. `steps_delta` and `steps_total` are provenance-only unless a later surface
   contract explicitly promotes them.
2. a deterministic lab replay with the same seed may be used to stabilize a
   `qualified_time` interpretation, but it does not make raw step counts
   semantic.
3. lab traces may expose richer timing detail than live runs; that detail must
   still be suppressed unless the surface contract promotes it on both sides.

### Live Mapping

Live-side time and scheduler evidence must flow through explicit metadata and
capture surfaces, not ambient inference.

The current concrete anchors are:

- `LiveRunMetadata`,
- `LiveRunMetadata.nondeterminism_notes`,
- `ReplayMetadata`,
- `CaptureManifest`,
- stable witness fields emitted by the scenario adapter or live runner.

Normative live rules:

1. live adapters must record `nondeterminism_notes` whenever scheduler jitter,
   host latency, or timing instability is relevant to interpreting a run,
2. `nondeterminism_notes` are explanation only and must not be compared as a
   semantic field set,
3. if the live path cannot name a stable `scenario_clock_id`, its timing facts
   remain `provenance_only_time` or `unsupported_time_surface`,
4. if the live path cannot connect a timing observation to a declared deadline,
   timeout, or clock boundary, it must not emit that observation as
   `semantic_time`,
5. `CaptureManifest` should mark whether a timing-related field was observed,
   inferred, or unsupported whenever the surface claims timing readiness.

## Report Semantics and Suppression Contract

Every report, artifact bundle, or CI summary that suppresses timing/order drift
or that compares a promoted time fact must emit the following fields:

- `time_policy_class`
- `scheduler_noise_class`
- `scenario_clock_id`
- `clock_source`
- `normalization_window`
- `suppression_reason`
- `rerun_decision`
- `nondeterminism_notes`

Recommended companion fields are:

- `logical_deadline_id`
- `timeout_budget_class`
- `timeout_outcome_class`
- `wall_elapsed_ns`
- `schedule_hash`
- `event_hash`
- `event_count`

Required interpretation rules:

1. if a field is suppressed, the report must say **why** via
   `suppression_reason`,
2. if timing caused an automatic rerun, the report must say so via
   `rerun_decision`,
3. if a surface claims semantic timing support, the report must identify the
   `scenario_clock_id`, `clock_source`, and `normalization_window`,
4. if only provenance or scheduler-noise fields differ, the report must not
   imply that semantic equality failed,
5. if a hard semantic mismatch and scheduler noise both appear, the report must
   preserve both facts and may not let noise erase the semantic mismatch.

## Qualification and Rerun Matrix

| Observation pattern | Time/noise interpretation | Required final behavior |
|---|---|---|
| only `wall_elapsed_ns`, `monotonic_*`, or `now_nanos` differs | `provenance_only_time` | keep semantic comparison unchanged, retain artifacts, emit `suppression_reason` |
| only `schedule_hash`, `event_hash`, `event_count`, or `nondeterminism_notes` differs on a `Phase 1` surface | `scheduler_noise_signal` | semantic verdict unchanged; may classify as `scheduler_noise_suspected` if the report needs a triage label |
| a `Phase 1` surface uses timing drift to explain away a semantic mismatch | policy violation | timing explanation rejected; classify using the semantic mismatch rules |
| a `Phase 2` timer surface emits `scenario_clock_id`, `logical_deadline_id`, and a stable `normalization_window`, then still disagrees on `timeout_outcome_class` | `semantic_time` mismatch | eligible for `runtime_semantic_bug`, `lab_model_or_mapping_bug`, or `irreproducible_divergence` after reruns |
| a live run emits timer evidence but cannot name the scenario clock or deadline boundary | `unsupported_time_surface` or `insufficient_observability` | do not compare as semantic time |
| reruns preserve seed lineage but timing buckets still oscillate within the admitted window | `qualified_time` remains stable | do not promote to a semantic mismatch |
| reruns preserve seed lineage and timing buckets cross the admitted window on an admitted timer surface | `qualified_time` instability | escalate through the divergence taxonomy rather than silently broadening tolerance |

The governing rule is simple: reruns may help classify time/noise observations,
but reruns do not authorize inventing a larger tolerance after the fact.

For external-surface gates, that means:

1. `host_role`, `lane_id`, `support_class`, and `reason_code` may explain a
   browser decision, but they do not promote raw browser host timing into
   `semantic_time`,
2. loopback or virtual transport is necessary but not sufficient for
   `raw_socket` or `http_surface` timing claims; the proposal still needs the
   declared scenario clock and deadline boundary,
3. wall-clock improvements or regressions remain `provenance_only_time` until a
   later contract explicitly promotes a narrower timing surface.

## Operational Examples

### Example 1: `Phase 1` Race With Different Scheduler Order

- lab and live disagree on `schedule_hash`,
- `nondeterminism_notes` mention winner-before-cleanup ordering variance,
- normalized semantic fields are identical,
- loser drain and quiescence are both complete.

Result:

- the run remains semantically equal,
- timing/order drift is recorded as `scheduler_noise_signal`,
- a report may say `scheduler_noise_suspected`,
- the system must not manufacture a runtime bug from raw order drift alone.

### Example 2: Timer Surface With Admitted Scenario Clock

- surface is promoted into `Phase 2`,
- scenario declares `scenario_clock_id = logical_clock.v1`,
- both sides emit the same `logical_deadline_id`,
- lab says timeout fired,
- live says timeout remained pending,
- the mismatch survives reruns.

Result:

- this is eligible `semantic_time`,
- the mismatch is not suppressed as provenance,
- the divergence taxonomy decides whether the final class is
  `runtime_semantic_bug`, `lab_model_or_mapping_bug`, or
  `irreproducible_divergence`.

### Example 3: Live Wall-Clock Drift With Stable Semantics

- `wall_elapsed_ns` differs materially across reruns,
- semantic records stay equal,
- live metadata records `nondeterminism_notes = ["host jitter"]`.

Result:

- this remains `provenance_only_time`,
- the human report should preserve the drift for forensics,
- no semantic mismatch is produced.

## Downstream Binding

This policy is normative for the following beads:

| Downstream bead | What it must consume from this contract |
|---|---|
| `asupersync-2a6k9.4.5` | live evidence tests must encode the field classes and suppression rules here rather than ad hoc timing assertions |
| `asupersync-2a6k9.5.1` | the differential executor must emit `time_policy_class`, `scheduler_noise_class`, `suppression_reason`, and `rerun_decision` consistently |
| `asupersync-2a6k9.5.3` | mismatch classification and rerun heuristics must treat `qualified_time`, `provenance_only_time`, and `scheduler_noise_signal` differently |
| `asupersync-2a6k9.5.4` | runner scripts and reports must expose the report fields and explanation rules defined here |
| `asupersync-2a6k9.6.6` | the pilot coverage matrix must keep `Phase 1` time qualification distinct from future timer semantics |
| `asupersync-2a6k9.7.1` | timer parity suites may only promote time into semantic comparison through `scenario_clock_id`, `clock_source`, and `normalization_window` |
| `asupersync-2a6k9.7.3` | eligibility gates for raw-socket, HTTP, and browser surfaces must use the external-surface timing table here to reject raw host timing claims and to require scenario-clocked boundaries before promotion |
| `asupersync-2a6k9.7.4` | virtualized-surface observability contracts must reuse the timing/noise vocabulary here |

If a later bead wants to compare raw wall-clock latency, host scheduler quirks,
or uncontrolled browser timing directly, that bead is wrong until this policy
is deliberately revised.

## Validation Commands

Heavy validation commands must run through `rch exec --`.

- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_lab_live_time_docs cargo fmt --check`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_lab_live_time_docs cargo check --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_lab_live_time_docs cargo clippy --all-targets -- -D warnings`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_lab_live_time_docs cargo test --test lab_live_time_normalization_policy_contract -- --nocapture`

## Exit Criteria

`asupersync-2a6k9.4.4` is complete when:

1. this document exists and is substantial,
2. it makes the boundary between semantic time, qualified time,
   provenance-only time, scheduler-noise signals, and unsupported timing claims
   explicit,
3. it makes `Phase 1` and `Phase 2` timing treatment mechanically different,
4. it defines how suppression and rerun explanations appear in reports,
5. downstream beads can reference it directly instead of inventing local timing
   tolerance language.
