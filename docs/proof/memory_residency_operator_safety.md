# Memory-Residency Operator Safety Runbook

This runbook is the scoped M5 operator packet for
`asupersync-memory-residency-control-ho2itz.5`. The source contract is
[`artifacts/memory_residency_operator_safety_contract_v1.json`](../../artifacts/memory_residency_operator_safety_contract_v1.json),
and the focused verifier is
[`tests/memory_residency_operator_safety_contract.rs`](../../tests/memory_residency_operator_safety_contract.rs).

## Proof Command

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_residency_operator_safety_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test memory_residency_operator_safety_contract -- --nocapture
```

Local Cargo output is not acceptable evidence for this lane.

## Enablement Prerequisites

The memory-residency profile is default-off. Operators must keep the runtime on
`MemoryResidencyPolicy::default()` unless all of these prerequisites are true:

- M1 inventory evidence exists at
  `artifacts/memory_residency_inventory_v1.json`.
- M2 policy evidence exists at
  `artifacts/memory_residency_policy_contract_v1.json` and keeps live-task
  behavior recommendation-only.
- M3 accounting evidence exists at
  `artifacts/memory_residency_accounting_snapshot_v1.json` and exposes the
  disabled/fresh/stale/unknown status vocabulary.
- M4 replay evidence exists at
  `artifacts/memory_residency_replay_e2e_contract_v1.json`, covers the
  deterministic scenario matrix, and includes no benchmark evidence.
- The focused M5 proof command above is run through `RCH_REQUIRE_REMOTE=1`
  with an isolated `CARGO_TARGET_DIR`.

The operator-visible knobs are the trace storage profile, arena temperature
policy, locality report age, artifact-cache pressure, runtime pressure snapshot,
proof-pack warmth, and record-pool counters. Missing, stale, contradictory, or
locally-proven evidence fails closed to the disabled default.

## Safety Gates

| Gate | Fails Closed When | Operator Action |
| --- | --- | --- |
| `m1_inventory_fresh` | inventory artifact missing, schema unknown, parent bead wrong, next-child pointer missing | Keep the default policy and rerun the M1 inventory contract. |
| `m2_policy_known` | policy artifact missing, schema unknown, recommendation-only boundary absent, RCH-only proof absent | Keep the default policy and rerun the M2 policy contract through RCH. |
| `m3_accounting_available` | accounting artifact missing, schema unknown, debug provider unavailable, record counters unavailable | Return to unified allocation and rerun the M3 accounting snapshot contract through RCH. |
| `m4_replay_artifacts_fresh` | replay artifact missing, schema unknown, deterministic scenario missing, required artifact missing, benchmark overclaim present | Keep the profile disabled and rerun the M4 replay e2e contract through RCH. |
| `no_local_cargo_fallback` | proof command lacks `RCH_REQUIRE_REMOTE=1`, lacks isolated `CARGO_TARGET_DIR`, or contains a local fallback marker | Refuse the evidence and rerun the exact manifest lane remotely. |

## Rollback

Rollback is non-destructive:

1. Remove the explicit experimental opt-in from the caller or operator profile.
2. Return to `MemoryResidencyPolicy::default()` and the existing unified
   allocation behavior.
3. Treat stale topology, unknown accounting, and missing proof-pack warmth as
   fallback evidence.
4. Keep runtime records and trace artifacts intact. This runbook grants no
   destructive authority: no permission to delete files, clean worktrees, create
   branches, or create worktrees.
5. Rerun the focused M5 proof lane through RCH before re-enabling.

## Incident Checklist

- Capture the failing `gate_id` and operator message.
- Attach the exact proof command and RCH admission/result state.
- Send Agent Mail on thread `asupersync-memory-residency-control-ho2itz.5`.
- Record whether M1, M2, M3, or M4 evidence was missing, stale, unknown, or
  contradictory.
- Do not cite broad workspace health, release readiness, runtime correctness
  outside the memory-residency policy/accounting/operator-safety surfaces, live
  RCH fleet availability, local Cargo fallback approval, or performance
  improvement.

## Agent Mail Handoff

Subject:

```text
[asupersync-memory-residency-control-ho2itz.5] Memory-residency safety gate handoff
```

Required body fields:

- `gate_id`
- `status`
- `proof_command`
- `rch_worker_or_refusal`
- `dirty_frontier`
- `rollback_action`
- `no_claim_boundaries`

## Closeout Checklist

- All source-of-truth paths in the contract exist.
- README.md and AGENTS.md contain the memory-residency operator safety contract
  marker.
- Proof manifest and proof-status snapshot map
  `memory-residency-operator-safety-contract`.
- The focused verifier passes through remote-required RCH.
- The bead closeout states any RCH admission blocker exactly if proof cannot
  start.

## No-Claim Boundaries

This runbook does not prove release readiness, broad workspace health, allocator
replacement, broad allocator performance, live host throughput, p50, p95, p999,
memory-use reduction, NUMA performance improvement, cache hit-rate improvement,
no-regression benchmark results, live RCH fleet availability, local Cargo
fallback approval, or source correctness outside the memory-residency
policy/accounting/operator-safety surfaces.
