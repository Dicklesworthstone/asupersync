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

The current installed `rch exec --help` surface for version `1.0.49` does not
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
- `clean_overlay_supported`
- `missing_flags`
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

## Proof-Traffic A3 Clean-Overlay Handshake

`asupersync-proof-traffic-control-kuyx64.3` connects the existing
`clean_overlay_planner` and `overlay_proof_command` surfaces to the installed RCH
capability evidence from `artifacts/proof_traffic_rch_capabilities_v1.json`.
The checked contract is
`tests/proof_traffic_clean_overlay_runner_handshake_contract.rs`; the machine
artifact is `artifacts/proof_traffic_clean_overlay_runner_handshake_v1.json`.

The handshake accepts a fixed snapshot:

- the clean-overlay planner request,
- the exact `target_dir`,
- the installed clean-overlay capability probe,
- the gate id used in Agent Mail and `br` handoffs.

It admits a proof command only when all of the following are true:

- selected dirty or untracked paths are covered by exclusive self reservations,
- selected deleted paths are absent,
- peer-dirty unselected paths are absent from the enforced proof,
- installed `rch exec` supports the clean-overlay flags required by the rendered
  command, as parsed from option declarations in captured help text,
- the installed capability probe has a non-empty version/evidence identity;
  prose and example mentions do not count as option declarations,
- the request is not report-only.

Unsupported backend capability emits `blocked-by-capability-drift` and a blocker
marker instead of an RCH/Cargo command. This is the current installed state for
`rch 1.0.49`, whose help text lacks `--base`, `--clean-overlay`,
`--overlay-path`, and `--no-overlay`.

Peer-dirty and unselected paths fail closed in enforced mode. The contract uses
a poison peer path fixture to prove that an unowned path cannot appear in an
admitted command. Report-only mode may name excluded paths in Markdown/JSON, but
still emits no proof command and makes no proof claim.

Capability support and admission are still pre-execution facts. They do not
prove that peer dirt was excluded from a completed build. That narrower claim
requires a supported capability snapshot, an admitted command, and terminal
execution evidence with a durable worker transcript or receipt reference.

The A3 report includes `selected_paths`, `included_paths`, `excluded_paths`,
`reservation_evidence`, `capability_probe_version`, `clean_overlay_supported`,
`missing_flags`, `capability_findings`, `rendered_command`, `admitted`,
`report_only`, retry condition, terminal execution evidence,
`rch_worker_or_refusal`, dirty-frontier/rollback guidance, and no-claim
boundaries. Agent Mail and `br` bodies are structured-field-first. Generated
handshake bodies set terminal evidence to `none` because they are pre-execution
admission receipts; an operator must enrich the handoff after terminal output.

No handshake path uses local Cargo fallback, branch creation, worktree creation,
scratch clones, file deletion, `git clean`, or `git reset`.

## Proof-Traffic A4 Parking Lot

`asupersync-proof-traffic-control-kuyx64.4` defines the parked proof manifest in
`src/audit/proof_traffic_parking_lot.rs`, checked by
`tests/proof_traffic_parking_lot_contract.rs` and
`artifacts/proof_traffic_parking_lot_v1.json`.

The parking lot is not a second issue tracker and is not proof evidence. It is a
resume packet for proof attempts that were parked, refused, or blocked. Each
attempt records:

- `head_commit`
- `command_intent`
- exact RCH command or blocker marker
- `target_dir`
- owned paths
- reservation evidence
- blocker class
- blocker owner or handoff thread when known
- retry predicate
- no-claim boundaries

Duplicate parked attempts are grouped by `blocker_key` so agents can see that
several proof attempts are waiting on the same blocker without losing per-agent
command details, owned paths, or reservation evidence.

The resume renderer has one hard rule: it emits the exact RCH command only when
the retry predicate is satisfied and the attempt recorded an exact command. If
the predicate is not satisfied, or the attempt only recorded a blocker marker,
the renderer emits a fresh parked blocker marker instead.

Parked, refused, and stale attempts are not green proof evidence. They can be
cited only as handoff context for a future retry.

## Proof-Traffic A5 Blocked-Loop E2E

`asupersync-proof-traffic-control-kuyx64.5` composes the A2 admission receipt,
A3 clean-overlay handshake, and A4 parking lot into a deterministic blocked
proof-loop e2e packet in `src/audit/proof_traffic_blocked_loop_e2e.rs`. It is
checked by `tests/proof_traffic_blocked_loop_e2e_contract.rs`; the machine
artifact is `artifacts/proof_traffic_blocked_loop_e2e_v1.json`.

The A5 fixture simulates a fresh agent trying to validate a focused proof slice
while shared-main hazards are present. It covers:

- an owned dirty path with exclusive self reservations,
- a peer poison path that would not compile if it entered an admitted command,
- missing overlay capability in the installed RCH command surface,
- active-project refusal,
- a progress-stale peer build,
- one admitted-command positive control so the peer poison exclusion is tested
  against a real rendered command.

Each step emits structured logs with `input_command`, `selected_paths`,
`reservation_state`, `queue_snapshot`, `decision`, `rendered_handoff`,
`no_claim_boundary`, and `replay_or_resume_command`. The artifact bundle includes
a JSON receipt, Markdown report, Agent Mail body, `br` comment body, and replay
or resume command.

The e2e fails closed if any admitted proof command contains local Cargo
fallback, branch/worktree/scratch-clone setup, peer build cancellation, file
deletion, `git clean`, `git reset`, or the peer poison path. Live RCH fleet state
may be attached only as operator evidence. In A5, deterministic fixtures are the correctness source.

## Proof-Traffic A6 Final Signoff

`asupersync-proof-traffic-control-kuyx64.6` aggregates the A1-A5 proof-traffic
controller artifacts into the final signoff packet
`artifacts/proof_traffic_final_signoff_v1.json`, checked by
`tests/proof_traffic_final_signoff_contract.rs`. The focused proof manifest lane
is `proof-traffic-final-signoff`.

The A6 packet records these child evidence rows:

- A1 capability-drift gate:
  `artifacts/proof_traffic_rch_capabilities_v1.json`,
  `tests/proof_traffic_rch_capability_contract.rs`
- A2 admission receipts:
  `artifacts/proof_traffic_admission_receipts_v1.json`,
  `tests/proof_traffic_admission_receipt_contract.rs`
- A3 clean-overlay handshake:
  `artifacts/proof_traffic_clean_overlay_runner_handshake_v1.json`,
  `tests/proof_traffic_clean_overlay_runner_handshake_contract.rs`
- A4 proof parking lot:
  `artifacts/proof_traffic_parking_lot_v1.json`,
  `tests/proof_traffic_parking_lot_contract.rs`
- A5 blocked-loop e2e:
  `artifacts/proof_traffic_blocked_loop_e2e_v1.json`,
  `tests/proof_traffic_blocked_loop_e2e_contract.rs`

The final signoff preserves the proof-traffic controller's fail-closed policy:
capability drift blocks clean-overlay command emission, parked or refused proof
attempts remain `rerun-required`, and blocked/stale RCH rows are handoff
evidence only. No proof-traffic path authorizes local Cargo fallback or peer build cancellation.
The aggregate also does not prove peer-dirt exclusion without supported
capability evidence, an admitted command, and terminal execution evidence with
a durable worker transcript or receipt reference.

The closeout checklist requires a live dependency-cycle check with
`br dep cycles` before the parent can be closed. The expected signal is no
dependency cycles.

## No-Claim Boundaries

This gate does not prove release readiness, broad workspace health, runtime
correctness, performance improvement, live RCH fleet availability, local Cargo
fallback approval, or permission to delete files, clean worktrees, create
branches, create worktrees, or cancel peer builds.

It also does not prove that documented clean-overlay flags are available unless
the installed capability artifact says they are supported.
