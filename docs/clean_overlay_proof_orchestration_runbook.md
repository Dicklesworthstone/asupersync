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
- A3 installed-capability handshake + contract:
  `src/audit/proof_traffic_overlay_handshake.rs`,
  `tests/proof_traffic_clean_overlay_runner_handshake_contract.rs`
- A1 planner contract: `tests/clean_overlay_proof_planner_contract.rs`

## What this packet verifier aligns

The A4 verifier proves only that this operator packet, its source-path
references, manifest/status rows, and discoverability markers remain aligned.
It does not execute or prove behavioral correctness of the referenced A1-A3
parser, planner, blocker, command builder, or handshake; their focused
behavioral tests are separate evidence.

The referenced clean-overlay implementation classifies a **focused slice** on shared `main` without
silently feeding unrelated edits to Cargo. The A1 planner decides which paths
may overlay `HEAD`; any unselected peer-dirty path makes an enforced attempt
fail closed. Only an otherwise admitted manifest reaches the A3
`OverlayProofCommand`, which emits an **overlay-scoped** RCH invocation that
uploads *only* the manifest's included paths and only after installed RCH
clean-overlay capability evidence confirms the complete required flag surface.
If peer dirt is present, the client is unsupported, or any other admission gate
fails, the lane emits a deterministic receipt and no command. The guarantee is
mechanical, not aspirational.

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
   from the overlay and make an enforced manifest fail closed rather than enter
   the build.
4. Captured `rch exec --help` output declares all four required options:
   `--base`, `--clean-overlay`, `--overlay-path`, and `--no-overlay`. The pure
   capability parser and A3 handshake must classify the snapshot as
   `clean_overlay_supported=true`; prose or example mentions do not count.
5. RCH is reachable. **No local Cargo fallback** is ever permitted: every Cargo
   invocation is routed through `rch exec` with `RCH_REQUIRE_REMOTE=1`. If RCH is
   unavailable, the proof is blocked — you do not run Cargo locally.

## Installed RCH capability gate

Capture the installed client evidence before asking the builder for a command:

```sh
rch --version
rch exec --help
```

Pass the captured help text through
`CleanOverlayCapability::from_rch_exec_help`, then through the
`ProofTrafficOverlayHandshake` / capability-aware `OverlayProofCommand`
constructor. There is no public constructor that assumes support. Every one of
these option declarations must be present:

- `--base`
- `--clean-overlay`
- `--overlay-path`
- `--no-overlay`

If even one option is missing, `admitted=false`, no RCH or Cargo proof command
is rendered, and the only command field is this receipt:

```text
# BLOCKED: installed RCH clean-overlay capability unsupported; no proof command emitted
```

This capability-drift decision takes precedence even for a report-only planner
request; report-only mode never masks an unsupported installed client.

If the probe identity is blank, retry only after capturing a fresh, non-empty
installed RCH version/evidence identifier plus `rch exec --help`. If flags are
missing, retry only after the installed client declares every required option.
A capability blocker does not authorize an RCH upgrade, a mixed-tree build, or
local Cargo fallback.

## Command examples

Run this contract's own verifier only when its ordinary RCH input tree contains
no peer dirt (proof that the packet is internally aligned):

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_clean_overlay_proof_orchestration_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test clean_overlay_proof_orchestration_contract -- --nocapture
```

With peer dirt present, do not issue that ordinary RCH command. Use the
capability-gated handshake; if the installed client is unsupported, record the
capability blocker and stop.

For a focused slice, do not hand-author an overlay command. Run the installed
capability probe above and use the A3 handshake. Only a receipt containing both
`clean_overlay_supported=true` and `admitted=true` may carry an exact
overlay-scoped proof command. The emitted command is the source of truth; if the
receipt is blocked, there is no command to paste.

Every non-admitted reproduction is the same deterministic blocker or
report-only receipt. It is intentionally non-executable: ordinary RCH could
sync the peer dirt that caused the refusal. Refresh the input evidence and ask
the capability-gated handshake for a new decision; do not paste an ordinary RCH
command for a blocked manifest.

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

- A **heartbeat-fresh / progress-stale** job is a reason to stop and reassess
  admission. The lane refuses an enforced run while unselected peer dirt is
  present; it does not turn that refusal into proof that the peer path was
  excluded. Only a supported, admitted command with terminal execution evidence
  can support that narrower claim.
- Do **not** cancel a peer-owned build. The stale-progress policy is
  `never_cancel_peer_owned_builds`. Cancel only a job you own that is
  progress-stale, then refresh evidence and ask the capability-gated handshake
  for a new decision. Re-issue only the newly admitted command.
- Never cite a stale or partial RCH job as green evidence. If the job is
  progress-stale, the proof is `rerun-required`, not passed.
- If the installed client lacks any clean-overlay option, emit the capability
  blocker and stop. Do not retry an unsupported command or let ordinary RCH
  sync the peer-dirty tree.

## Peer-dirty blocker receipts

When a run is refused, the A2 `blocker_receipt` / A3 `OverlayProofCommand`
render a deterministic receipt instead of a green claim:

- `# BLOCKED: clean-overlay refused; no RCH proof command emitted (<n> fail-closed path(s))`
- `# BLOCKED: installed RCH clean-overlay capability unsupported; no proof command emitted`
- `# REPORT-ONLY: clean-overlay dry run; no RCH proof command emitted`

A blocked manifest is **never admitted** (`admitted=false`) and emits **no**
Cargo invocation, so the run cannot accidentally report green. Excluded paths
are reported with their reason: peer-dirty (unselected), unreserved selection,
or deleted selection (an overlay cannot prove a removal). Paste the receipt into
the bead and the Agent Mail thread; it is the honest artifact of a refused run.

## Non-destructive cleanup and rollback

- The lane performs **no I/O** and never branches, clones, makes a worktree, or
  deletes. There is nothing to clean up after a blocked run.
- To roll back, simply leave peer dirt unstaged and re-run the capability-gated
  handshake after your owned edits settle and after refreshing installed
  capability evidence. **No permission to delete files, clean worktrees, create
  branches, or create worktrees** is granted or implied.
- Never run `git clean`, `git reset --hard`, `rm -rf`, or a local Cargo build as
  a "fix"; those are forbidden orchestration operations for this lane.

## Agent Mail handoff template

Thread: `asupersync-proof-orch-clean-overlay-5ve2ao.4`

The generated handshake body is a pre-execution admission receipt and therefore
sets `terminal_execution_evidence=none`. After an admitted command finishes, the
operator-enriched handoff must replace that placeholder with a worker/terminal
status and durable transcript or receipt reference before making any
peer-exclusion claim.

```
Subject: [clean-overlay proof] <focused slice> — <run-now|park-rerun-required|blocked-by-peer|blocked-by-capability-drift|report-only>
Body (required fields):
- gate_id: clean-overlay-proof-orchestration-contract
- status: <run-now|park-rerun-required|blocked-by-peer|blocked-by-capability-drift|report-only>
- head_commit: <HEAD sha>
- selected_paths: <requested paths>
- included_paths: <paths eligible for an admitted overlay>
- excluded_paths: <path — reason, ...>
- rendered_command: <exact emitted RCH command | blocker receipt>
- capability_probe_version: <captured rch version/help evidence id>
- clean_overlay_supported: <true|false>
- missing_flags: <--base, --clean-overlay, --overlay-path, --no-overlay | none>
- capability_findings: <captured-help parser findings>
- admitted: <true|false>
- report_only: <true|false>
- retry_condition: <none | refresh non-empty probe identity | wait for every required flag>
- terminal_execution_evidence: <worker + terminal status + transcript/receipt reference | none; pre-execution admission receipt only>
- rch_worker_or_refusal: <worker id | refusal reason>
- dirty_frontier: <owned/clean at admission; execution not attested | peer-dirty observed; no command admitted and no exclusion claim | none>
- rollback_action: leave peer dirt unstaged; refresh evidence and re-run capability-gated handshake
- no_claim_boundaries: <the lane's no-claim boundary list>
```

## br comment handoff template

```
br comments add asupersync-proof-orch-clean-overlay-5ve2ao.4 --author <agent> --message '
clean-overlay proof: <run-now|park-rerun-required|blocked-by-peer|blocked-by-capability-drift|report-only>
HEAD: <sha>
selected paths: <requested>
included paths: <eligible overlay>
excluded: <path — reason>
exact command or blocker receipt: <rendered field>
capability_probe_version: <evidence id>
clean_overlay_supported: <true|false>
missing_flags: <flags | none>
capability_findings: <findings>
admitted: <true|false>
report_only: <true|false>
retry_condition: <condition>
terminal_execution_evidence: <worker + terminal status + transcript/receipt reference | none; pre-execution admission receipt only>
rch_worker_or_refusal: <worker id | refusal reason>
dirty_frontier: <owned/clean at admission; execution not attested | peer-dirty observed; no command admitted and no exclusion claim | none>
rollback_action: leave peer dirt unstaged; refresh evidence and rerun capability-gated handshake
no-claim boundaries: does not prove broad workspace health, release readiness,
runtime correctness outside cited surfaces, performance, live RCH fleet
availability, or permission to delete files; no local Cargo fallback.
'
```

## Bead closeout checklist

1. Record the handshake's exact decision. If capability evidence or another
   admission gate refused the command, capture the status-appropriate
   deterministic receipt instead of a proof command.
2. Only when a supported, admitted command completed with terminal execution
   evidence: record that the overlay was scoped to owned, reserved paths and
   peer dirt was excluded. Otherwise record no peer-exclusion claim.
3. The proof receipt (admitted command or blocker line) is captured in the bead
   and the Agent Mail thread.
4. No branch/worktree/clone/deletion was performed; no local Cargo fallback was
   cited.
5. Reservations are renewed (if work continues) or released (if done).
6. The claim cites only this lane's exact guarantee and no-claim boundaries.

## No-claim boundaries

This lane and runbook do **not** prove, and must never be cited as:

- No release-readiness claim.
- No broad workspace-health claim.
- No runtime-correctness or behavioral-correctness claim for the referenced
  A1-A3 parser, planner, blocker, command-builder, or handshake surfaces; their
  focused behavioral tests are separate evidence.
- No performance-improvement claim.
- No live RCH fleet-availability claim.
- No claim that peer dirt was excluded unless installed RCH clean-overlay
  capability evidence is supported and an admitted command completed with
  terminal execution evidence.
- No local Cargo fallback approval.
- No permission to delete files, clean worktrees, create branches, or create
  worktrees.
