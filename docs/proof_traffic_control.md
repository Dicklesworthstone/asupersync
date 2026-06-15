# Proof Traffic Control

This document is the operator note for the proof-traffic control lane under
`asupersync-proof-traffic-control-kuyx64`. It is intentionally narrower than the
existing validation-frontier and clean-overlay proof-orchestration contracts: it
records what the installed RCH binary can actually run before agents trust a
focused proof command, and it defines the admission receipt that records queue
and refusal decisions without pretending they are green proof evidence.

## Why This Exists

Shared-main agents routinely hold small, valid proof intents while unrelated
peer edits and long-running remote builds are active. In that state, a focused
Cargo lane can fail before it reaches the owned file, or RCH can refuse before a
worker is assigned. A refusal, stale-progress job, or unsupported command flag
is not green evidence.

The current installed `rch exec --help` surface for version `1.0.41` does not
expose the clean-overlay execution flags documented by the clean-overlay
runbook examples in `docs/clean_overlay_proof_orchestration_runbook.md`:

- `--base`
- `--clean-overlay`
- `--overlay-path`
- `--no-overlay`

Until installed capability evidence says those flags are supported, proof
traffic control must classify that path as `blocked-by-capability-drift` and
emit no Cargo proof command that assumes peer dirt was excluded.

## Decision Seed

The A1 artifact seeds the decision taxonomy used by later proof-traffic beads:

- `run-now`
- `queue-wait`
- `park-rerun-required`
- `blocked-by-peer`
- `blocked-by-capability-drift`
- `remote-required-refused`
- `report-only`

The taxonomy is deliberately fail-closed. A parked or refused proof is
`rerun-required`, not passed.

## Operator Requirements

- Every CPU-intensive Cargo proof command remains behind
  `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=...`.
- `RCH_QUEUE_WHEN_BUSY=1` may be used to request queueing, but it does not
  weaken the remote-required proof boundary.
- No local Cargo fallback is allowed for proof admission.
- Do not cancel peer-owned builds. Heartbeat-fresh/progress-stale peer jobs are
  handoff evidence, not cancellation authority.
- Do not use a branch, worktree, scratch clone, file deletion, `git clean`, or
  `git reset` as an overlay substitute.

## Required Handoff Fields

Every proof-traffic operator report should include:

- `gate_id`
- `status`
- `head_commit`
- `command_intent`
- `target_dir`
- `selected_paths`
- `capability_probe_version`
- `capability_findings`
- `rch_worker_or_refusal`
- `retry_condition`
- `no_claim_boundaries`

## Proof-Traffic A2 Admission Receipts

`asupersync-proof-traffic-control-kuyx64.2` installs the deterministic admission
receipt schema in `src/audit/proof_traffic_receipt.rs`, guarded by
`tests/proof_traffic_admission_receipt_contract.rs` and the machine artifact
`artifacts/proof_traffic_admission_receipts_v1.json`.

The admission receipt is pure reporting logic. It does not start RCH, Cargo, or
tracker commands. A caller supplies the focused proof intent, installed
capability probe, and current queue/refusal snapshot; the classifier emits one
of the following statuses:

- `run-now`
- `queue-wait`
- `park-rerun-required`
- `blocked-by-peer`
- `blocked-by-capability-drift`
- `remote-required-refused`
- `report-only`

The fail-closed classification order is:

1. `report-only` if the caller requested dry-run reporting.
2. `blocked-by-capability-drift` if the proof requires clean-overlay flags that
   the installed RCH binary does not expose.
3. `remote-required-refused` if `RCH_REQUIRE_REMOTE=1` refused before assigning a
   worker.
4. `blocked-by-peer` for peer-owned heartbeat-fresh/progress-stale builds.
5. `park-rerun-required` for active-project exclusion, worker-health refusal, or
   self-owned stale-progress builds.
6. `queue-wait` for healthy active builds ahead of the proof.
7. `run-now` only when no queue/refusal/capability blocker remains.

Unit fixtures cover empty queue, active project exclusion, worker-health
refusal, heartbeat-fresh/progress-stale peer builds, peer-owned stale builds,
self-owned stale builds, remote-required refusal, healthy queue wait,
report-only, and unsupported overlay capability. The Markdown and JSON reports
include `head_commit`, `command_intent`, `target_dir`, `selected_paths`, active
build ids, retry condition, capability findings, and no-claim boundaries. The
Agent Mail and `br` comment renderers put structured fields first so another
agent can paste the handoff without reinterpreting the receipt.

No decision path recommends local Cargo fallback, cancelling or preempting a
peer-owned build, creating a branch/worktree/scratch clone, or deleting files.
Peer-owned stale-progress builds are handoff evidence only; they do not grant
authority to interrupt another agent's RCH work.

## No-Claim Boundaries

This gate does not prove release readiness, broad workspace health, runtime
correctness, performance improvement, live RCH fleet availability, local Cargo
fallback approval, or permission to delete files, clean worktrees, create
branches, or create worktrees.

It also does not prove that documented clean-overlay flags are available unless
the installed capability artifact says they are supported.
