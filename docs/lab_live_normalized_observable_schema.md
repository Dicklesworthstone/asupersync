# Lab-vs-Live Normalized Observable Schema

**Bead**: `asupersync-2a6k9.1.2`  
**Author**: QuietMoose  
**Date**: 2026-03-18  
**Schema Version**: `lab-live-normalized-observable-v1`

## Purpose

This document defines the single semantic record that both deterministic lab runs and live runtime executions must normalize into before any differential verdict is computed.

The goal is not to preserve every runtime detail. The goal is to preserve the details that matter to Asupersync's semantic contracts:

- final outcome,
- cancellation lifecycle facts,
- loser-drain completion,
- region-close quiescence,
- obligation balance,
- selected resource accounting for the surface under test,
- replay and evidence metadata needed to rerun or explain a mismatch.

Everything else is noise unless a surface-specific contract explicitly promotes it into the semantic surface.

## Scope

This schema is the comparison denominator for phase-1 lab-vs-live differential validation.

It is intentionally:

- stricter than a log envelope,
- looser than a raw trace,
- portable across lab and live runners,
- stable under harmless scheduler interleavings.

This document does not replace:

- `docs/semantic_verification_log_schema.md`, which defines per-entry verification logging,
- `docs/tokio_differential_behavior_suites.md`, which defines suite rows, verdict classes, and artifacts,
- surface-specific contracts that define domain payload equivalence for HTTP, database, transport, messaging, or other runtime layers.

## Design Rules

The normalized record must satisfy all of the following:

1. It must be strong enough to catch real semantic divergence.
2. It must be weak enough to ignore incidental ordering noise.
3. It must be representable by both lab and live runners without depending on hidden in-process pointers or unstable IDs.
4. It must make cancellation, loser drain, and close-to-quiescence first-class facts rather than derived afterthoughts.
5. It must separate semantic equality from reproduction metadata.

## Canonical Record

Every compared run pair must normalize into a record with this top-level shape:

```json
{
  "schema_version": "lab-live-normalized-observable-v1",
  "scenario_id": "string",
  "surface_id": "string",
  "surface_contract_version": "string",
  "runtime_kind": "lab|live",
  "semantics": {
    "terminal_outcome": {},
    "cancellation": {},
    "loser_drain": {},
    "region_close": {},
    "obligation_balance": {},
    "resource_surface": {}
  },
  "provenance": {
    "seed": "optional u64",
    "trace_fingerprint": "optional u64",
    "schedule_hash": "optional u64",
    "event_hash": "optional u64",
    "event_count": "optional u64",
    "steps_total": "optional u64",
    "artifact_path": "optional string",
    "repro_command": "optional string",
    "repro_manifest": "optional string",
    "config_hash": "optional string"
  }
}
```

`semantics` is compared for equivalence. `provenance` is retained for replay and audit, but is not itself a semantic equality target unless a surface-specific contract explicitly says otherwise.

## Field Contract

| Path | Required | Compare Policy | Meaning |
|---|---|---|---|
| `schema_version` | yes | exact match | Stable schema discriminator |
| `scenario_id` | yes | exact match | Stable scenario token from the suite |
| `surface_id` | yes | exact match | Semantic surface being compared |
| `surface_contract_version` | yes | exact match | Versioned comparator contract |
| `runtime_kind` | yes | informational only | `lab` or `live` origin |
| `semantics.terminal_outcome` | yes | normalized equality | Final externally meaningful result |
| `semantics.cancellation` | yes | normalized equality | Whether cancel protocol facts occurred and completed |
| `semantics.loser_drain` | yes | normalized equality | Whether losing branches were fully drained |
| `semantics.region_close` | yes | normalized equality | Whether the owning region closed to quiescence |
| `semantics.obligation_balance` | yes | normalized equality | Whether obligations resolved without leak |
| `semantics.resource_surface` | yes | contract-defined equality | Resource accounting declared by the surface contract |
| `provenance.*` | conditional | audit only by default | Reproduction and trace identity aids |

## Semantic Subrecords

### Terminal Outcome

`semantics.terminal_outcome` must contain:

| Field | Required | Description |
|---|---|---|
| `class` | yes | One of `ok`, `err`, `cancelled`, `panicked` |
| `severity` | yes | One of `ok`, `err`, `cancelled`, `panicked` following `Ok < Err < Cancelled < Panicked` from `Outcome` |
| `surface_result` | conditional | Canonical result token, hash, or compact projection defined by the surface contract |
| `error_class` | conditional | Stable error classifier, not a free-form string |
| `cancel_reason_class` | conditional | Stable cancellation classifier |
| `panic_class` | conditional | Stable panic classifier when a panic is semantically exposed |

Normalization rule:

- Raw payloads, pointer identity, backtraces, and formatting-specific error strings must not be compared directly.
- Surface contracts may define `surface_result` more precisely, but it must be stable across runtimes.

### Cancellation

`semantics.cancellation` must contain:

| Field | Required | Description |
|---|---|---|
| `requested` | yes | Whether cancellation was requested anywhere in the scenario |
| `acknowledged` | yes | Whether the cancelled work observed or acknowledged cancellation |
| `cleanup_completed` | yes | Whether cancellation cleanup completed |
| `finalization_completed` | yes | Whether finalization after cancellation completed |
| `terminal_phase` | yes | One of `not_cancelled`, `cancel_requested`, `cancelling`, `finalizing`, `completed` |
| `checkpoint_observed` | conditional | Whether the cancelled path crossed a checkpoint acknowledging cancellation |

Normalization rule:

- Lab-side internal `TaskPhase` and `CxInner.cancel_acknowledged` may be richer than live-side evidence.
- Live-side mappings may infer the same facts from externally visible lifecycle hooks, joined task handles, stream termination, or explicit cleanup witnesses.
- If a surface cannot observe `checkpoint_observed`, the surface contract must mark that field unsupported on both sides rather than fabricating a value.

### Loser Drain

`semantics.loser_drain` must contain:

| Field | Required | Description |
|---|---|---|
| `applicable` | yes | Whether the scenario includes a race or speculative loser path |
| `expected_losers` | yes | Number of loser branches that must drain |
| `drained_losers` | yes | Number of loser branches proven drained |
| `status` | yes | One of `not_applicable`, `complete`, `incomplete` |
| `evidence` | conditional | Stable evidence token such as `oracle.loser_drain`, `join_all`, `stream_closed`, `task_joined` |

Normalization rule:

- Exact drain ordering is not semantic.
- Whether all losers were drained before scenario completion is semantic.

### Region Close

`semantics.region_close` must contain:

| Field | Required | Description |
|---|---|---|
| `root_state` | yes | One of `open`, `closing`, `draining`, `finalizing`, `closed` |
| `quiescent` | yes | Whether the owning region reached quiescence |
| `live_children` | yes | Remaining live child count at observation boundary |
| `finalizers_pending` | yes | Remaining finalizers at observation boundary |
| `close_completed` | yes | Whether the root region completed close |

Normalization rule:

- The semantic contract is close-to-quiescence, not internal scheduler history.
- Any record with `quiescent = false`, `live_children > 0`, or `close_completed = false` at the required observation boundary is a hard mismatch unless the scenario explicitly expects non-quiescent operation.

### Obligation Balance

`semantics.obligation_balance` must contain:

| Field | Required | Description |
|---|---|---|
| `reserved` | yes | Total obligations reserved in the observed surface |
| `committed` | yes | Total obligations committed |
| `aborted` | yes | Total obligations aborted |
| `leaked` | yes | Total leaked obligations |
| `unresolved` | yes | Reserved minus terminal obligations |
| `balanced` | yes | True when the obligation ledger is semantically closed |

Normalization rule:

- `balanced` must be equivalent to `leaked == 0 && unresolved == 0`.
- Lab and live implementations may maintain different internal ledgers, but they must normalize to the same semantic obligation totals for the declared surface.

### Resource Surface

`semantics.resource_surface` contains only counters that the surface-specific contract declares semantically meaningful.

It must contain:

| Field | Required | Description |
|---|---|---|
| `contract_scope` | yes | Stable token naming the resource surface |
| `counters` | yes | Map of stable counter names to integer values |
| `tolerances` | yes | Map of counter names to comparison mode |

Allowed comparison modes are:

- `exact`
- `at_least`
- `at_most`
- `unsupported`

Examples of allowed counters:

- bytes delivered to a protocol consumer,
- committed messages,
- completed timers,
- accepted connections,
- completed stream frames.

Examples of forbidden default counters:

- raw wake count,
- incidental poll count,
- pointer addresses,
- lock acquisition order,
- wall-clock latency unless the surface contract explicitly promotes it.

## Provenance Fields

`provenance` exists to explain and reproduce a mismatch. It does not decide semantic equality by default.

Recommended fields:

| Field | Lab Mapping | Live Mapping |
|---|---|---|
| `seed` | `LabRunReport.seed` | deterministic scenario seed when available |
| `trace_fingerprint` | `LabRunReport.trace_fingerprint` | optional externally captured fingerprint if supported |
| `schedule_hash` | `LabRunReport.trace_certificate.schedule_hash` | optional |
| `event_hash` | `LabRunReport.trace_certificate.event_hash` | optional |
| `event_count` | `LabRunReport.trace_certificate.event_count` | optional |
| `steps_total` | `LabRunReport.steps_total` | optional runner step count |
| `artifact_path` | crash pack, replay trace, or artifact bundle path | bundle path or live artifact path |
| `repro_command` | deterministic rerun command | deterministic rerun command |
| `repro_manifest` | replay manifest or bundle manifest path | workload bundle or repro manifest path |
| `config_hash` | lab config summary hash when available | live config hash when available |

Fields such as `now_nanos`, `steps_delta`, and oracle check timestamps may be preserved in local artifacts, but they are provenance-only and must not create semantic mismatches on their own. Promotion of any time-related provenance field is governed by `docs/lab_live_time_normalization_policy.md`, not by ad hoc suite logic.

## Mapping Rules

### Lab-to-Normalized Mapping

Lab runners must derive the normalized record from the existing deterministic evidence surfaces, including:

- `src/lab/runtime.rs`:
  - `LabRunReport.seed`
  - `LabRunReport.steps_delta`
  - `LabRunReport.steps_total`
  - `LabRunReport.quiescent`
  - `LabRunReport.trace_fingerprint`
  - `LabRunReport.trace_certificate`
  - `LabRunReport.invariant_violations`
  - `LabRunReport.temporal_invariant_failures`
- `src/lab/oracle/mod.rs`:
  - `OracleReport.entries`
  - `OracleReport.total`
  - `OracleReport.passed`
  - `OracleReport.failed`
- `src/lab/scenario_runner.rs`:
  - `TraceCertificateSnapshot`
  - `ScenarioRunResult`
- core runtime state machines:
  - `RegionState`
  - `TaskPhase`
  - `ObligationState`
  - `CheckpointState`

Normative lab mapping requirements:

1. `terminal_outcome.class` must reflect the semantic scenario result, not merely the absence of a panic.
2. `cancellation` must be informed by temporal oracle outcomes and task lifecycle facts when available.
3. `loser_drain.status` must map failed `loser_drain` oracle evidence to `incomplete`.
4. `region_close.quiescent` must map from `LabRunReport.quiescent`.
5. `obligation_balance.leaked` must include any leaked obligations surfaced by runtime invariants or oracle evidence.
6. Provenance fields should retain trace identity and replay metadata, but those values must not override semantic comparison.

### Live-to-Normalized Mapping

Live runners must map externally visible behavior and retained artifacts into the same semantic fields without assuming lab-only introspection.

Normative live mapping requirements:

1. `terminal_outcome` must be derived from the user-visible surface result or a declared surface witness.
2. `cancellation.requested`, `acknowledged`, `cleanup_completed`, and `finalization_completed` must come from explicit runtime hooks, structured witness events, joined handles, or equivalent stable artifacts.
3. `loser_drain` must be derived from actual loser completion evidence, not from "winner completed so losers probably drained."
4. `region_close` must only report `quiescent = true` when the owning scope or scenario boundary has no live child work remaining.
5. `obligation_balance` must come from a real ledger, counter set, or witness stream that can distinguish `committed`, `aborted`, `leaked`, and `unresolved`.
6. If a live surface cannot produce a required semantic field, that surface is not yet comparison-ready and must fail contract validation rather than silently dropping the field.
7. Time and scheduler-local fields remain provenance-only unless `docs/lab_live_time_normalization_policy.md` explicitly promotes them through a scenario clock and normalization rule.

## Explicit Non-Goals

The following are intentionally absent from the normalized semantic record unless a surface contract explicitly opts in:

- exact raw event ordering,
- thread IDs,
- memory addresses or pointer identity,
- internal slab indices,
- scheduler-local queue positions,
- waker identity,
- incidental poll counts,
- formatting-specific error text,
- wall-clock timestamps,
- exact trace length as a semantic value,
- hash values used only for replay and audit.

These values may still appear in artifacts or debugging bundles, but they must not determine equality by default.

## Comparison Rules

The differential comparator must apply these rules in order:

1. Reject if `schema_version`, `scenario_id`, `surface_id`, or `surface_contract_version` differ.
2. Compare all required `semantics.*` fields using their declared comparison policy.
3. Treat missing required semantic fields as `artifact_schema_violation`.
4. Treat unsupported resource counters as absent from equality, but only when both sides declare `unsupported`.
5. Ignore `provenance.*` during semantic equality unless the surface contract explicitly promotes a provenance field into the semantic surface.

## Hard Mismatch Conditions

The comparator must emit a semantic mismatch when any of the following hold:

- terminal outcome class differs,
- cancellation requested or acknowledged differs for a scenario where cancellation is part of the semantic surface,
- loser-drain status differs,
- one side is quiescent and the other is not,
- one side leaks obligations or leaves obligations unresolved,
- a required resource counter differs under an `exact`, `at_least`, or `at_most` policy,
- a surface claims comparison readiness but cannot populate required semantic fields.

## Example: Different Traces, Same Semantics

Two runs may differ in raw ordering:

- lab trace: winner finishes, cancel signal is delivered, loser acknowledges at the next checkpoint, finalizer runs, region closes,
- live trace: cancel signal lands first, loser cleanup completes before the winner commit is observed by the recorder, region still closes cleanly.

These runs must compare equal if both normalize to:

```json
{
  "semantics": {
    "terminal_outcome": {
      "class": "ok",
      "severity": "ok",
      "surface_result": "reply:200"
    },
    "cancellation": {
      "requested": true,
      "acknowledged": true,
      "cleanup_completed": true,
      "finalization_completed": true,
      "terminal_phase": "completed"
    },
    "loser_drain": {
      "applicable": true,
      "expected_losers": 1,
      "drained_losers": 1,
      "status": "complete"
    },
    "region_close": {
      "root_state": "closed",
      "quiescent": true,
      "live_children": 0,
      "finalizers_pending": 0,
      "close_completed": true
    },
    "obligation_balance": {
      "reserved": 1,
      "committed": 1,
      "aborted": 0,
      "leaked": 0,
      "unresolved": 0,
      "balanced": true
    },
    "resource_surface": {
      "contract_scope": "http.reply",
      "counters": {
        "responses_completed": 1
      },
      "tolerances": {
        "responses_completed": "exact"
      }
    }
  }
}
```

The differing event order, trace length, and schedule hash remain useful provenance, but they do not change the semantic verdict.

## Validation Expectations

Any future contract tests for this schema must at minimum verify:

1. the schema version stays stable,
2. all required semantic subrecords remain present,
3. non-goal fields do not accidentally become equality inputs,
4. missing required semantic fields fail comparison readiness,
5. provenance fields stay non-semantic unless a surface contract opts them in explicitly.

## Cross-References

- `docs/tokio_differential_behavior_suites.md`
- `docs/runtime_workload_corpus_contract.md`
- `docs/semantic_verification_log_schema.md`
- `docs/lab_live_time_normalization_policy.md`
- `src/lab/runtime.rs`
- `src/lab/scenario_runner.rs`
- `src/lab/oracle/mod.rs`
- `src/types/outcome.rs`
- `src/types/task_context.rs`
- `src/record/region.rs`
- `src/record/task.rs`
- `src/record/obligation.rs`
