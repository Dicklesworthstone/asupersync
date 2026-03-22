# Lab-vs-Live Virtualized Surface Coverage Matrix and Observability Contract

**Bead**: `asupersync-2a6k9.7.4`  
**Parent**: `asupersync-2a6k9.7`, `asupersync-2a6k9`  
**Author**: SilentFinch (codex-cli / gpt-5-codex)  
**Date**: 2026-03-21  
**Contract Version**: `lab-live-virtualized-surface-matrix-v1`  
**Dependencies**: `docs/lab_live_differential_scope_matrix.md`, `docs/lab_live_verification_taxonomy.md`, `docs/lab_live_time_normalization_policy.md`, `docs/lab_live_scenario_adapter_contract.md`, `docs/lab_live_normalized_observable_schema.md`, `docs/lab_live_divergence_taxonomy.md`, `src/lab/dual_run.rs`, `tests/common/mod.rs`, `README.md`, `docs/WASM.md`

## Purpose

This document defines the Phase 2 coverage matrix and observability contract
for virtualized expansion surfaces in the lab-vs-live differential program.

`asupersync-2a6k9.6.6` defines the core pilot coverage matrix for Phase 1
semantic-runtime surfaces. That matrix is the base contract. This document does
not replace it and it does not invent a second testing language. Instead, it
extends the same `T0` / `T1` / `T2` / `T3` / `T4` / `T5` vocabulary to the
first expansion surfaces where timing, virtualization, and external-boundary
truthfulness become the dominant risk.

The goal is simple: make future timer and transport beads prove that they are
running controlled experiments instead of fragile demos with optimistic prose.

## Upstream Contracts

This matrix is downstream of:

- `docs/lab_live_differential_scope_matrix.md`
- `docs/lab_live_verification_taxonomy.md`
- `docs/lab_live_time_normalization_policy.md`
- `docs/lab_live_scenario_adapter_contract.md`
- `docs/lab_live_normalized_observable_schema.md`
- `docs/lab_live_divergence_taxonomy.md`
- `src/lab/dual_run.rs`
- `tests/common/mod.rs`

These documents already define the admitted rollout ladder, the
`lab-live-scenario-spec-v1` contract, the `lab-live-normalized-observable-v1`
schema, the `lab-live-verification-taxonomy-v1` tiers, and the
`lab-live-time-normalization-v1` timing/noise classes.

This bead exists because Phase 2 needs one more layer:

1. a matrix that says which virtualized surfaces are being widened,
2. the unit/e2e/logging floor for each surface,
3. the machine-readable field contract that must appear in `CaptureManifest`,
   `LiveRunMetadata`, and retained reports,
4. the failure patterns that must be treated as scope violations instead of
   runtime bugs.

## Core Rule

No Phase 2 widening work is complete unless the bead can point to one explicit
matrix row in this document and satisfy every required column in that row.

That means:

- the row must reuse the Phase 1 vocabulary instead of inventing new tiers,
- the row must name the exact virtualization boundary,
- the row must declare the minimum unit checks and dual-run scripts,
- the row must declare the minimum observability hooks and required logs,
- the row must say which failures are genuine semantic mismatches and which
  failures are merely invalid or weakly-controlled experiments.

If a timer or transport-style experiment cannot meet that bar, the correct
result is `insufficient_observability`, `blocked_missing_virtualization`,
`blocked_missing_verification`, `blocked_scope_red_line`, or
`unsupported_time_surface`, not a soft "probably okay."

## Relationship to the Core Pilot Matrix

This document explicitly extends `asupersync-2a6k9.6.6`.

The Phase 1 matrix already proves:

- which semantic-core surfaces are worth trusting first,
- that `T0 unit_contract`, `T2 dual_run_smoke`, `T3 pilot_surface`, and
  `T4 negative_control` are mandatory for executable parity claims,
- that future beads must retain structured logs and replayable artifacts.

Phase 2 inherits those same requirements and adds four new obligations:

1. every widened surface must declare a `virtualization_boundary`,
2. every widened surface must declare how time facts land in
   `semantic_time`, `qualified_time`, `scheduler_noise_signal`,
   `provenance_only_time`, or `unsupported_time_surface`,
3. every widened surface must declare the minimum `CaptureManifest`
   observability floor using `observed`, `inferred`, and `unsupported`,
4. every widened surface must define "invalid experiment" cases that are not
   allowed to masquerade as real runtime defects.

The important discipline rule is:

- reuse the core pilot vocabulary and expand it,
- do not invent a second testing language,
- do not fork the differential program into a separate Phase 2 dialect.

## Matrix Schema

Every Phase 2 matrix row must publish the following machine-readable columns:

| Column | Meaning | Why it is mandatory |
|---|---|---|
| `surface_family` | stable surface token | keeps Phase 2 rows queryable and comparable |
| `phase` | rollout phase (`Phase 2` or gated Phase 3 descendant) | binds the row back to the scope ladder |
| `runtime_profile` | declared scenario/runtime lane | keeps adapters from silently widening ambient execution |
| `virtualization_boundary` | exact boundary that constrains externality | prevents over-claiming uncontrolled host behavior |
| `unit_checks` | minimum `T0 unit_contract` floor | ensures local contracts are pinned before wider runs |
| `golden_fixtures` | minimum `T1 golden_fixture` floor | freezes any normalized or report-shaped artifacts |
| `dual_run_scripts` | minimum `T2 dual_run_smoke` or `T3 pilot_surface` commands | proves the shared lab/live scenario contract is really exercised |
| `required_log_fields` | mandatory field set for reports, bundles, and logs | keeps operator/debug evidence stable |
| `invalid_experiment_signals` | failures that mean the experiment was under-controlled | prevents policy drift into false bug reports |
| `promotion_floor` | minimum evidence required before the row may be widened further | blocks scope creep from getting ahead of observability |

Rows may add explanatory prose, but they are not allowed to omit any of these
columns.

## Phase 2 Coverage Matrix

The rows below are the normative matrix for timer, transport, and the first
captured-boundary descendants of transport.

| `surface_family` | `phase` | `runtime_profile` | `virtualization_boundary` | `unit_checks` | `golden_fixtures` | `dual_run_scripts` | `required_log_fields` | `invalid_experiment_signals` | `promotion_floor` |
|---|---|---|---|---|---|---|---|---|---|
| `timer_surface` | `Phase 2` | `phase2.timer_virtualized` | scenario-declared clock and deadline boundary only; no ambient wall-clock claim | timeout classification, timer cancellation, logical deadline mapping, scenario-clock validation | normalized time bundle and capture-manifest shape for timer scenarios | one `T2 dual_run_smoke` plus one `T3 pilot_surface` family over admitted timer semantics | `scenario_clock_id`, `clock_source`, `logical_deadline_id`, `timeout_budget_class`, `timeout_outcome_class`, `logical_elapsed_ticks`, `normalization_window`, `time_policy_class`, `scheduler_noise_class`, `CaptureManifest`, `LiveRunMetadata`, `ReplayMetadata` | missing `scenario_clock_id`, missing `logical_deadline_id`, wall-clock-only reasoning, or unsupported timer fields marked as semantic | `T0`, `T1`, `T2`, `T3`, `T4` complete before broader timing claims |
| `virtual_transport_surface` | `Phase 2` | `phase2.transport_loopback` | loopback or explicit virtual transport with captured peer model; no ambient internet | ordering-class contract, in-flight cancel cleanup, transport-close semantics, capture-manifest completeness | normalized transport summary and retained bundle schema | one `T2 dual_run_smoke` plus one `T3 pilot_surface` family over virtualized delivery/cancel cases | `virtualization_boundary`, `capture_manifest_path`, `normalized_record_path`, `artifact_bundle`, `repro_command`, `event_hash`, `schedule_hash`, `nondeterminism_notes`, `surface_family`, `observability_status` | uncontrolled peer timing, real network dependency, missing capture packet, or transport evidence only inferred from wall-clock logs | `T0`, `T1`, `T2`, `T3`, `T4` complete before HTTP/gRPC-on-captured-boundaries claims |
| `http_surface` | gated `Phase 3` descendant of `Phase 2` transport proof | `phase3.http_captured_boundary` | HTTP over loopback or virtualized transport with explicit timeout and peer-model contract | request/response termination contract, protocol-version mapping, shutdown/cancel boundary, malformed-artifact rejection | normalized request/response bundle and gate packet fixture | one `T2 dual_run_smoke`, one `T3 pilot_surface`, and at least one `T4 negative_control` proving malformed or under-observed traces are rejected | `surface_family`, `virtualization_boundary`, `scenario_clock_id`, `logical_deadline_id`, `capture_manifest_path`, `normalized_record_path`, `artifact_bundle`, `eligibility_verdict`, `observability_status`, `unsupported_reason` | real-internet RTT, uncontrolled TLS/DNS timing, opaque upstream behavior, or missing normalized peer evidence | transport row must already be credible; no direct jump from Phase 1 to HTTP parity |
| `browser_surface` | gated `Phase 3` descendant of captured transport and host-boundary work | `phase3.browser_captured_boundary` | explicit host-role contract plus admitted lane boundary; no opaque browser-host parity claim | lane classification, downgrade semantics, host-role logging, unsupported-host rejection, bridge-only proof | host classification packet, downgrade artifact, and gate packet fixture | one `T2 dual_run_smoke` on an admitted lane, one `T4 negative_control`, and `T5 stress_nightly` before noisy multi-host claims | `surface_family`, `host_role`, `support_class`, `reason_code`, `lane_id`, `eligibility_verdict`, `observability_status`, `capture_manifest_path`, `artifact_bundle`, `repro_command`, `unsupported_reason` | opaque browser scheduler claims, service-worker lifetime parity claims, shared-worker parity without promotion, or missing lane/host metadata | captured transport row plus host gate must already hold; browser support remains lane-scoped, not host-global |

The `http_surface` and `browser_surface` rows are deliberately included here
because Phase 2 transport evidence is what makes those later captured-boundary
surfaces honest. They are not promoted by this bead; they are constrained by
it.

## Surface-Specific Guidance

### 1. `timer_surface`

The timer row is the first place where time may become semantic instead of
remaining explanatory. That promotion is only legitimate when the row carries:

- `scenario_clock_id`
- `clock_source`
- `logical_deadline_id`
- `timeout_budget_class`
- `timeout_outcome_class`
- `logical_elapsed_ticks`
- `normalization_window`
- `suppression_reason`
- `rerun_decision`

The row must also name which fields are merely `qualified_time` and which are
actually `semantic_time`. For example:

- `timeout_outcome_class` may be semantic when the scenario clock and deadline
  are explicit,
- `logical_elapsed_ticks` may only be compared through the declared
  `normalization_window`,
- `wall_elapsed_ns`, `monotonic_start_ns`, `monotonic_end_ns`, `now_nanos`,
  and `steps_delta` remain provenance only.

The timer row must never accept a report that explains a semantic mismatch with
"scheduler noise" alone. `scheduler_noise_signal` may explain drift, but it may
not erase a real timeout or cancellation contract break.

### 2. `virtual_transport_surface`

The transport row is still about semantic control, not about network realism.

The minimum truthful boundary is:

- loopback or explicitly virtualized transport only,
- captured peer behavior only,
- explicit cancel/close semantics,
- retained lab/live normalized records and reproducible artifacts,
- no ambient DNS, TLS, packet loss, or remote-peer timing claims.

The required logs for this row must be strong enough to answer:

1. what transport model was used?
2. what peer boundary was captured?
3. which delivery/cancel/close events were observed versus inferred?
4. what artifact bundle or replay command reproduces the mismatch?

If the row cannot answer those questions from stable fields, it is not ready to
host `asupersync-2a6k9.7.2`.

### 3. `http_surface`

This row exists to stop future HTTP work from treating "runs over loopback" as
synonymous with "truthful parity."

The HTTP row inherits the transport row and additionally requires:

- request/response termination semantics,
- protocol version evidence,
- timeout/cancel boundary evidence,
- explicit peer-model capture,
- rejection of malformed or under-observed artifacts.

The row must classify weak experiments as blocked work rather than accepting
them as partial passes. The correct results for weak experiments are
`blocked_missing_virtualization`, `blocked_missing_observability`, or
`blocked_missing_verification`.

### 4. `browser_surface`

The browser row is the most likely place for over-claiming.

This row therefore requires explicit browser-boundary metadata:

- `host_role`
- `support_class`
- `reason_code`
- `lane_id`
- `eligibility_verdict`
- `observability_status`

The row must also preserve the code-facing downgrade vocabulary already present
in `src/lab/dual_run.rs`, especially:

- `support_class = bridge_only`
- `reason_code = downgrade_to_server_bridge`
- `reason_code = unsupported_runtime_context`

An admitted `bridge_only` downgrade can be a truthful captured lane. It is not
proof of full browser-runtime parity. The matrix must keep those ideas
separate.

## Required Machine-Readable Log Contract

Every Phase 2 row must emit or define the following stable fields whenever it
claims meaningful differential evidence:

- `surface_family`
- `phase`
- `runtime_profile`
- `virtualization_boundary`
- `scenario_clock_id`
- `clock_source`
- `logical_deadline_id`
- `timeout_budget_class`
- `timeout_outcome_class`
- `logical_elapsed_ticks`
- `normalization_window`
- `time_policy_class`
- `scheduler_noise_class`
- `suppression_reason`
- `rerun_decision`
- `observability_status`
- `eligibility_verdict`
- `capture_manifest_path`
- `normalized_record_path`
- `artifact_bundle`
- `repro_command`
- `unsupported_reason`

Rows that touch host or external-surface gates must additionally emit:

- `host_role`
- `support_class`
- `reason_code`
- `lane_id`

The retained bundle must be rich enough to connect those report fields back to:

- `CaptureManifest`
- `FieldObservability`
- `LiveRunMetadata`
- `ReplayMetadata`
- `nondeterminism_notes`
- `artifact_path`
- `config_hash`
- `trace_fingerprint`
- `schedule_hash`
- `event_hash`
- `event_count`

This is how future contributors prove that a row is controlled, replayable, and
auditable instead of merely "covered."

## Capture Manifest Rules

`CaptureManifest` is the minimum observability packet for live-side widening
work.

Every executable Phase 2 bead must say which of its important fields are:

- `observed`
- `inferred`
- `unsupported`

and it must retain `unsupported_fields` explicitly.

Normative rules:

1. a field may not be presented as semantic if the best available capture class
   is `unsupported`,
2. a field marked only as `inferred` may support triage or a gate packet, but
   it should not silently satisfy a row that demands direct semantic capture,
3. when the row depends on `CaptureManifest`, a missing manifest is itself an
   `invalid_experiment_signal`,
4. `observability_status` must summarize whether the live adapter actually met
   the row's declared capture floor.

This is the main discipline tool that keeps widened surfaces from being graded
with weaker evidence than the core semantic pilots.

## Invalid Experiment and Scope-Violation Matrix

The table below defines failure patterns that must be classified as invalid
experiments or scope violations rather than runtime bugs.

| Failure pattern | Required classification | Why |
|---|---|---|
| timer report lacks `scenario_clock_id` or `logical_deadline_id` but compares timeout behavior semantically | `insufficient_observability` | the time contract is incomplete |
| timer suite relies only on `wall_elapsed_ns` or other wall-clock values | `unsupported_time_surface` | raw wall-clock evidence is not an admitted semantic surface |
| transport suite talks to uncontrolled remote peers or ambient internet services | `blocked_scope_red_line` | the virtualization boundary was abandoned |
| transport bundle lacks `capture_manifest_path` or stable normalized records | `blocked_missing_observability` | the experiment cannot defend its observables |
| surface row changes comparator/report behavior without `T1 golden_fixture` or `T4 negative_control` evidence | `blocked_missing_verification` | policy-shaping work needs stronger proof than a single pass |
| browser row omits `host_role`, `support_class`, `reason_code`, or `lane_id` | `blocked_missing_observability` | host-boundary truthfulness depends on those fields |
| browser claim treats `bridge_only` downgrade as full host parity | `blocked_scope_red_line` | downgrade is an admitted fallback, not a full support proof |
| a report uses `scheduler_noise_signal` to erase a hard semantic mismatch | policy violation | noise may explain drift, but it cannot rewrite a real failure |

These classifications are deliberately conservative. The whole point of this
bead is to keep Phase 2 from diluting the trust story established by Phase 1.

## Downstream Binding

This matrix is directly downstream of `asupersync-2a6k9.6.6` and directly
constrains:

| Downstream bead | What it must inherit from this document |
|---|---|
| `asupersync-2a6k9.7.1` | timer and virtual-time suites must use the timer row, its field vocabulary, and its invalid-experiment policy |
| `asupersync-2a6k9.7.2` | virtualized transport suites must use the transport row, the capture-manifest floor, and the loopback/virtual boundary law |
| `asupersync-2a6k9.7.3` | raw-socket, HTTP, and browser gate packets must use the exact `eligibility_verdict`, `support_class`, `reason_code`, `lane_id`, and observability vocabulary here |
| `asupersync-2a6k9.8.1` | normal CI gates must not treat a widened Phase 2 surface as credible unless the row-level log and artifact floor is met |
| `README.md` and `docs/WASM.md` | browser-facing support claims must remain lane-scoped and downgrade-aware, not host-global |

If a later bead makes a broader claim than one of these rows allows, that bead
is out of contract even if its code "works" in a demo.

## Contributor Template

Future widening beads should be able to copy this checklist directly into their
notes or PR description:

1. Name the `surface_family`.
2. Name the `phase` and `runtime_profile`.
3. State the exact `virtualization_boundary`.
4. List the minimum `T0 unit_contract` checks.
5. List the minimum `T1 golden_fixture` outputs.
6. List the exact `T2 dual_run_smoke` and `T3 pilot_surface` scripts.
7. List the exact `T4 negative_control` and `T5 stress_nightly` expectations.
8. Declare the required `CaptureManifest` and `LiveRunMetadata` fields.
9. Declare which failures are semantic mismatches versus invalid experiments.
10. Provide `rch`-offloaded validation commands.

If a widening bead cannot fill out all ten items, it is still planning work,
not completed verification work.

## Validation Commands

Every change to this contract must be validated with:

- `rch exec -- cargo fmt --check`
- `rch exec -- cargo check --all-targets`
- `rch exec -- cargo clippy --all-targets -- -D warnings`
- `rch exec -- cargo test --test lab_live_virtualized_surface_matrix_contract -- --nocapture`

Rows that move from contract-only status into executable timer or transport work
should additionally replay the relevant executable anchors, such as:

- `rch exec -- cargo test --test time_e2e -- --nocapture`
- `rch exec -- cargo test --test e2e_transport -- --nocapture`

The purpose of the extra commands is not to inflate ceremony. It is to ensure
that Phase 2 widening beads keep the same disciplined proof posture as the core
Phase 1 pilots.
