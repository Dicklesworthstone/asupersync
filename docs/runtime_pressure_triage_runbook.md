# Runtime Pressure Triage and Replay Runbook

This runbook is the operator handoff for diagnosing large-swarm runtime stalls
with the pressure-control evidence lane. It is intentionally scoped: it explains
how to move from a symptom to replayable evidence without claiming production
throughput, autonomous scheduler rewrites, or proven deadlock from advisory
signals alone.

Canonical contract:

- Evidence contract: `artifacts/runtime_pressure_control_evidence_contract_v1.json`
- Contract verifier: `tests/runtime_pressure_control_evidence_contract.rs`
- Manifest lane: `runtime-pressure-control-evidence-contract`
- Manifest file: `artifacts/proof_lane_manifest_v1.json`
- Source surface: `src/runtime/resource_monitor.rs`

The pressure-control lane proves contract alignment for schema versions,
deterministic lab scenario families, documentation markers, and operator scope
limits. It does not prove real-host throughput, production-on-by-default
admission/backpressure, scheduler rewrites, or a deadlock without explicit
trapped-cycle proof.

## First Classify the Symptom

| Symptom | First evidence | Expected operator path |
| --- | --- | --- |
| Runtime feels slow but work drains | `RuntimePressureSnapshot.overall_verdict` plus `signal_statuses` | Treat as advisory. Confirm which signal is degraded before changing policy. |
| Optional work should stop entering a saturated runtime | `RuntimePressureAdmissionDecision` with `policy_enabled=true` | Use only the opt-in admission policy. Required cleanup and quiescence work must remain admitted. |
| Resource readings look incomplete or platform-specific | `platform_probe_operator_verdict` and `platform_probes` signal row | Prefer degraded/fallback interpretation. Do not turn probe absence into throughput claims. |
| Structural wait graph looks fragmented or critical | `spectral` row plus `spectral_recommendations` | Run trapped-cycle detection before making a deadlock claim. Fragmentation alone is not proof. |
| A lab scenario disagrees with its expected pressure verdict | `RuntimePressureLabScenarioEvidence.classification_matches_expected=false` | Reproduce under the deterministic lab fixture before touching live policy. |

## Read the Snapshot

Start from the stable fields:

- `schema_version`: must match `asupersync.runtime-pressure-snapshot.v1`.
- `overall_verdict`: `healthy`, `unknown`, `degraded`, or `critical`.
- `missing_signal_count`, `degraded_signal_count`,
  `critical_signal_count`: aggregate evidence quality.
- `signal_statuses`: ordered status rows for resources, scheduler, spectral
  health, and platform probes.
- `spectral_recommendations`: advisory next actions, not deadlock proof unless
  `deadlock_proven=true`.

Interpretation rules:

- `healthy` means all required pressure signals were present and inside the
  current contract envelope.
- `unknown` means evidence is missing. Operators should improve evidence or use
  deterministic replay before widening control behavior.
- `degraded` means at least one signal crossed an advisory threshold. Optional
  work may be deferred only through an explicit opt-in policy.
- `critical` means one or more signals crossed a critical advisory threshold.
  Optional work may be rejected only through an explicit opt-in policy.

## Admission Decisions

`RuntimePressureAdmissionPolicy::default()` is disabled and has no effect.
The conservative opt-in policy converts snapshots into deterministic
`RuntimePressureAdmissionDecision` rows:

| Work class | Snapshot state | Action | Reason |
| --- | --- | --- | --- |
| Required | Any state, including unknown schema | `admit` | Required cleanup, cancellation, and quiescence paths are not backpressured. |
| Optional | Healthy | `admit` | Pressure envelope is clear. |
| Optional | Unknown or degraded | `defer` | Evidence is incomplete or degraded; do not silently overcommit. |
| Optional | Critical | `reject` | Runtime pressure is critical for this policy envelope. |
| Optional | Unknown snapshot schema | `reject` | Fail closed until the schema is understood. |

Required work bypass is not a throughput optimization. It preserves the runtime
invariant that cleanup, cancellation, finalizers, and region quiescence cannot be
blocked by optional admission control.
Optional work fails closed for unknown pressure snapshot schemas.

## Replay Before Policy Changes

Use deterministic lab evidence before promoting a policy change:

| Scenario family | Expected verdict | Diagnostic labels |
| --- | --- | --- |
| `healthy` | `healthy` | `all_signals_present` |
| `cpu_lane_pressure` | `critical` | `cpu_load_hard_limit`, `resource_heavy_degradation`, `scheduler_tail_pressure` |
| `resource_fallback_degraded` | `degraded` | `memory_soft_pressure`, `platform_probe_fallback` |
| `structural_warning` | `critical` | `spectral_fragmented_topology`, `trapped_cycle_detection_required` |

If live behavior and lab behavior disagree, treat the live claim as unproven
until there is a replay artifact or a narrower contract test that explains the
gap.

## Scoped Proof Command

Run the pressure-control evidence contract when changing pressure snapshots,
lab pressure evidence, admission-policy docs, or this runbook:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_runtime_pressure_control_evidence_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test runtime_pressure_control_evidence_contract -- --nocapture
```

For changes that touch the proof-lane manifest, also run the manifest contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_manifest_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test proof_lane_manifest_contract -- --nocapture
```

These commands must run through RCH. Do not substitute a local Cargo run for a
CPU-intensive validation lane.

## Closeout Checklist

Before closing a pressure-control bead:

1. Cite the exact pressure-control contract lane that passed or explain the
   first blocker.
2. State whether the evidence is advisory, replay-backed, or trapped-cycle
   proven.
3. Name every changed source path in the commit.
4. Confirm adaptive admission/backpressure remains opt-in unless a stronger
   policy bead explicitly proves otherwise.
5. If broad validation was skipped, record the narrower RCH proof and why it is
   sufficient for the touched surface.
