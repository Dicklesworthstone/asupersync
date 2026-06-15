# Clean-overlay proof orchestration — operator runbook (PROOF-ORCH A4)

> Scoped operator packet for the **clean-overlay proof orchestration contract**
> (`clean-overlay-proof-orchestration-contract`). It explains when the
> shared-`main` clean-overlay lane may be used, how to read its receipts, and
> exactly what it does **not** prove.

This runbook is contract-guarded. The source of truth is:

- Contract artifact: `artifacts/clean_overlay_proof_orchestration_v1.json`
- This runbook: `docs/clean_overlay_proof_orchestration_runbook.md`
- Verifier: `tests/clean_overlay_proof_orchestration_contract.rs`
- Proof-lane manifest: `artifacts/proof_lane_manifest_v1.json`
  (`tests/proof_lane_manifest_contract.rs`)
- Proof-status snapshot: `artifacts/proof_status_snapshot_v1.json`
  (`tests/proof_status_snapshot_contract.rs`)

The lane is built from the A1–A3 surfaces it documents:

- A1 planner: `src/audit/clean_overlay_planner.rs`
- A2 blocker receipt: `src/audit/blocker_receipt.rs`
- A3 overlay command + focused E2E: `src/audit/overlay_proof_command.rs`,
  `tests/proof_orch_clean_overlay_e2e.rs`
- A1 planner contract: `tests/clean_overlay_proof_planner_contract.rs`

## What this lane proves

The clean-overlay lane lets one agent prove a **focused slice** on shared `main`
without dragging a peer's unrelated dirty edits into the build. The A1 planner
decides which paths may overlay `HEAD`; the A3 `OverlayProofCommand` emits an
**overlay-scoped** RCH invocation that uploads *only* the manifest's included
paths on top of `HEAD`. An excluded poison path — even one that would fail
compilation — can never reach the compiler. The guarantee is mechanical, not
aspirational.

This contract lane verifies that the operator packet (this runbook, the
artifact, the manifest/status rows, and the README/AGENTS markers) stays aligned
with the A1–A3 lane surfaces.

## Prerequisites

Before running a clean-overlay proof:

1. You are on `main` only.
   **Main only — no branches, no worktrees, no scratch clones, no destructive cleanup.**
   The lane never creates a git branch, a worktree, or a clone, and never
   deletes files.
2. You hold an Agent Mail file reservation for every path you intend to overlay
   (`file_reservation_paths`). Unreserved selected paths fail closed.
3. The paths you select are dirty edits *you own*; peer-dirty paths are excluded
   from the overlay, not blocked.
4. RCH is reachable. **No local Cargo fallback** is ever permitted: every Cargo
   invocation is routed through `rch exec` with `RCH_REQUIRE_REMOTE=1`. If RCH is
   unavailable, the proof is blocked — you do not run Cargo locally.

## Command examples

Run this contract's own verifier (proof that the packet is internally aligned):

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_clean_overlay_proof_orchestration_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test clean_overlay_proof_orchestration_contract -- --nocapture
```

Build a focused overlay-scoped proof command for an admitted manifest (the A3
`OverlayProofCommand::rendered_command` shape — overlay paths only, never the
whole tree):

```sh
RCH_REQUIRE_REMOTE=1 rch exec --base <HEAD> --clean-overlay --overlay-path <path> -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test cargo test --test <focused_test>
```

Re-derive a fail-closed decision (the A3 reproduction command for a blocked run):

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test cargo test --test proof_orch_clean_overlay_e2e -- --nocapture
```

## Reservation expectations

- Selected paths must be covered by a held Agent Mail reservation. The planner
  records the reservation pattern as `reservation_evidence`; an **unreserved
  selection** is excluded with reason `UnreservedSelection` and the run fails
  closed.
- Renew long-running reservations (`renew_file_reservations`) so the lease does
  not expire mid-proof.
- Release reservations (`release_file_reservations`) only after the proof
  receipt is captured and the handoff comment is posted.
- A **shared reservation** (a path another agent also holds) is still excluded
  unless you are the holder; the lane never overlays a path you do not own.

## Stale-progress cancellation guidance

RCH jobs may be **heartbeat-fresh but progress-stale**: the worker is alive
(heartbeat is recent) yet the build has made no forward progress for a long
time, usually because a peer's broken edit elsewhere stalls the shared tree.

- A **heartbeat-fresh / progress-stale** job is the signature case the
  clean-overlay lane exists to avoid: scope the overlay to your owned paths so a
  peer's poison path is never synced.
- Do **not** cancel a peer-owned build. The stale-progress policy is
  `never_cancel_peer_owned_builds`. Cancel only a job you own that is
  progress-stale, then re-issue the overlay-scoped command.
- Never cite a stale or partial RCH job as green evidence. If the job is
  progress-stale, the proof is `rerun-required`, not passed.

## Peer-dirty blocker receipts

When a run is refused, the A2 `blocker_receipt` / A3 `OverlayProofCommand`
render a deterministic receipt instead of a green claim:

- `# BLOCKED: clean-overlay refused; no RCH proof command emitted (<n> fail-closed path(s))`
- `# REPORT-ONLY: clean-overlay dry run; no RCH proof command emitted`

A blocked manifest is **never admitted** (`admitted=false`) and emits **no**
Cargo invocation, so the run cannot accidentally report green. Excluded paths
are reported with their reason: peer-dirty (unselected), unreserved selection,
or deleted selection (an overlay cannot prove a removal). Paste the receipt into
the bead and the Agent Mail thread; it is the honest artifact of a refused run.

## Non-destructive cleanup and rollback

- The lane performs **no I/O** and never branches, clones, makes a worktree, or
  deletes. There is nothing to clean up after a blocked run.
- To roll back, simply leave peer dirt unstaged and re-run the overlay-scoped
  command after your owned edits settle. **No permission to delete files, clean
  worktrees, create branches, or create worktrees** is granted or implied.
- Never run `git clean`, `git reset --hard`, `rm -rf`, or a local Cargo build as
  a "fix"; those are forbidden orchestration operations for this lane.

## Agent Mail handoff template

Thread: `asupersync-proof-orch-clean-overlay-5ve2ao.4`

```
Subject: [clean-overlay proof] <focused slice> — <admitted|blocked|report-only>
Body (required fields):
- gate_id: clean-overlay-proof-orchestration-contract
- status: <admitted|blocked|report-only>
- head_commit: <HEAD sha>
- overlay_paths: <included paths>
- excluded_paths: <path — reason, ...>
- proof_command: <exact RCH_REQUIRE_REMOTE=1 rch exec ... command>
- rch_worker_or_refusal: <worker id | refusal reason>
- dirty_frontier: <owned | peer-dirty excluded | none>
- rollback_action: leave peer dirt unstaged; re-run overlay-scoped command
- no_claim_boundaries: <the lane's no-claim boundary list>
```

## br comment handoff template

```
br comments add asupersync-proof-orch-clean-overlay-5ve2ao.4 --author <agent> --message '
clean-overlay proof: <admitted|blocked|report-only>
HEAD: <sha>
overlay paths: <included>
excluded: <path — reason>
exact RCH command: <command>
no-claim boundaries: does not prove broad workspace health, release readiness,
runtime correctness outside cited surfaces, performance, live RCH fleet
availability, or permission to delete files; no local Cargo fallback.
'
```

## Bead closeout checklist

1. The overlay was scoped to owned, reserved paths; peer dirt was excluded, not
   synced.
2. The proof receipt (admitted command or blocker line) is captured in the bead
   and the Agent Mail thread.
3. No branch/worktree/clone/deletion was performed; no local Cargo fallback was
   cited.
4. Reservations are renewed (if work continues) or released (if done).
5. The claim cites only this lane's exact guarantee and no-claim boundaries.

## No-claim boundaries

This lane and runbook do **not** prove, and must never be cited as:

- No release-readiness claim.
- No broad workspace-health claim.
- No runtime-correctness claim outside the cited clean-overlay planner, blocker,
  and overlay-command surfaces.
- No performance-improvement claim.
- No live RCH fleet-availability claim.
- No local Cargo fallback approval.
- No permission to delete files, clean worktrees, create branches, or create
  worktrees.
