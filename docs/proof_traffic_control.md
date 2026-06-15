# Proof Traffic Control

This document is the operator note for
`asupersync-proof-traffic-control-kuyx64.1`, the installed RCH capability drift
gate. It is intentionally narrower than the existing validation-frontier and
clean-overlay proof-orchestration contracts: it records what the installed RCH
binary can actually run before agents trust a focused proof command.

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

## No-Claim Boundaries

This gate does not prove release readiness, broad workspace health, runtime
correctness, performance improvement, live RCH fleet availability, local Cargo
fallback approval, or permission to delete files, clean worktrees, create
branches, or create worktrees.

It also does not prove that documented clean-overlay flags are available unless
the installed capability artifact says they are supported.
