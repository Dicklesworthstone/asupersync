# Agent-Swarm Safe Proof Runner

The proof runner (`scripts/proof_runner.py`) provides preflight checks before expensive validation commands, ensuring they won't fail due to unrelated dirty surfaces or reservation conflicts.

## Quick Start

```bash
# Check if a proof lane is safe to run
./scripts/proof_runner.py --lane rustfmt-check --touched-files src/runtime/state.rs

# Get suggestions for what lanes to run based on your changes
./scripts/proof_runner.py --suggest-lanes --touched-files src/sync/mutex.rs tests/sync_test.rs

# List all available proof lanes
./scripts/proof_runner.py --list-lanes

# Run preflight and execute the proof if safe
./scripts/proof_runner.py --lane lib-tests --touched-files src/channel/mpsc.rs --execute
```

## Common Workflows

### 1. Before Committing Changes

```bash
# Get suggestions for your changed files
CHANGED_FILES=$(git diff --name-only --cached)
./scripts/proof_runner.py --suggest-lanes --touched-files $CHANGED_FILES

# Check if broad validation is safe
./scripts/proof_runner.py --lane all-targets-check --touched-files $CHANGED_FILES
```

### 2. In Bead Close Reasons

When the proof runner blocks broad validation, use the output in your close reason:

```bash
# Run the check
./scripts/proof_runner.py --lane clippy-all-targets --touched-files src/obligation/ledger.rs
```

If blocked, the output will include a `validation_frontier_record` that you can cite:

```
blocked-external: intended `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_docs cargo clippy -p asupersync --all-targets -- -D warnings`;
stopped at `src/sync/semaphore.rs:37` (`clippy_lint_wall`, unused imports) while touching 
`src/obligation/ledger.rs`; supplemental proof `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_docs cargo check --lib`.
```

### 3. Checking File Reservations

The proof runner checks for:
- Uncommitted changes in unrelated files
- Staged changes from other agents  
- Active Agent Mail file reservations (when available)

If blocked by any of these, it will suggest a narrower supplemental proof.

## Output Format

The proof runner returns structured JSON with:

```json
{
  "preflight_passed": true,
  "lane_id": "rustfmt-check", 
  "command_would_run": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_docs cargo fmt --check",
  "validation_frontier_record": {
    "command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_docs cargo fmt --check",
    "proof_lane_id": "rustfmt-check",
    "commit": "abc1234def56",
    "timestamp": "2026-05-07T19:30:00Z",
    "touched_files": ["src/runtime/state.rs"],
    "dirty_tree_summary": {
      "tracked_modified": ["src/runtime/state.rs"],
      "deleted": [],
      "untracked": [],
      "staged": [],
      "overlaps_touched_files": true,
      "touched_dirty_files": ["src/runtime/state.rs"]
    },
    "rch_result": {
      "admission": "not-applicable",
      "worker": null,
      "local_fallback_refused": false
    },
    "exit_status": 0,
    "decision": "pass",
    "error_class": "none",
    "first_blocker": null,
    "first_failure": {
      "crate_or_surface": "",
      "target": "",
      "file": "",
      "line": 0
    },
    "error_buckets": [],
    "affected_files": [],
    "likely_owner": "local_change",
    "likely_bead": null,
    "external_to_narrow_fuzz_target_work": false,
    "green_proof_claimed": true,
    "supplemental_proof_command": "rch exec -- rustfmt --edition 2024 --check src/runtime/state.rs",
    "summary": "preflight checks passed"
  },
  "recommendation": "proceed"
}
```

## Validation Frontier Compatibility

The proof runner emits records compatible with the validation frontier ledger schema (`artifacts/validation_frontier_ledger_schema_v1.json`). Key decisions:

- **`pass`**: Safe to run the intended broad proof
- **`blocked-external`**: Blocked by unrelated changes, use supplemental proof
- **`failed-local`**: Your changes have issues, fix them first

Each record carries the proof lane id, target commit, dirty-tree summary, RCH
admission receipt, process exit status, first blocker, grouped error buckets,
affected files, and `green_proof_claimed`. Closeout text may only claim a green
proof when `green_proof_claimed=true` and the cited lane's own verdict supports
the claim.

## Pressure-Control RCH Fallback Evidence

The pressure-control evidence contract
(`artifacts/runtime_pressure_control_evidence_contract_v1.json`, verified by
`tests/runtime_pressure_control_evidence_contract.rs`) treats local Cargo
fallback as a fail-closed validation issue for remote-required proof lanes. A
pressure-control closeout may cite a green RCH Cargo proof only when the saved
command and transcript prove remote execution:

- command starts with `RCH_REQUIRE_REMOTE=1 rch exec -- `
- command contains `rch exec -- env` and `CARGO_TARGET_DIR=`
- transcript contains `Selected worker:`, `Executing command remotely:`,
  `Remote command finished: exit=0`, and `[RCH] remote`
- transcript does not contain `[RCH] local`, `Executing command locally`, or
  `local fallback accepted`

When the proof runner is classifying admission receipts rather than a transcript,
the equivalent no-local-RCH fallback evidence is:

- `remote_required=true`
- `local_fallback_allowed=false`
- `refusal_code=local_fallback_refused`
- `reason_codes` contains both `remote_required` and `local_fallback_refused`

These markers prove only that the cited proof did not silently substitute local
Cargo for a remote-required pressure-control lane. They do not prove RCH fleet
availability, real-host throughput, production admission control, or scheduler performance.

Saved RCH transcript classification also emits a deterministic
`closeout_summary` object for Beads and Agent Mail. Pass `--bead-id` (alias
`--likely-bead`) and `--likely-owner` when the transcript belongs to a known
slice:

```bash
python3 scripts/proof_runner.py \
  --classify-rch-log tests/fixtures/proof_runner/cargo_error.log \
  --command "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p asupersync --test proof_runner_contract -- --nocapture" \
  --touched-files tests/proof_runner_contract.rs \
  --bead-id asupersync-oxqrae.1 \
  --likely-owner DustyGorge \
  --output json
```

The `closeout_summary.beads_comment` and `closeout_summary.agent_mail_body`
strings are safe to paste as summaries. They use `NO_GREEN_PROOF` whenever the
classified transcript is failed or externally blocked, even when a blocker is
well identified, so closeouts do not accidentally overstate evidence.

## Swarm Proof-Lane Atlas Receipt Runbook

The swarm proof-lane planner contract is
`artifacts/swarm_proof_lane_planner_contract_v1.json`, verified by
`tests/swarm_proof_lane_planner_contract.rs`, and backed by the runtime planner
`asupersync::lab::plan_swarm_proof_lane` plus
`asupersync::lab::render_swarm_proof_lane_agent_mail_summary`. Its deterministic
decision scenario corpus is `admission-aware-atlas-decision-scenarios-v1`.

Run the scoped verifier before changing planner receipt claims:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_bt63nr8_swarm_planner cargo test -p asupersync --test swarm_proof_lane_planner_contract -- --nocapture
```

Use this taxonomy when reading one planner receipt or writing a bead/Agent Mail
closeout:

| Receipt signal | Claim label | Evidence to cite | Closeout rule |
|----------------|-------------|------------------|---------------|
| `admission_decision=Admit` with `decision=Ready`, `remote_required=true`, `fallback_policy=RemoteOnly`, remote transcript markers, and no findings | `replay-backed` | `command`, worker/transcript footer, `source_rows`, `covers`, and `does_not_cover` | Claim only the listed `covers` fields. Do not claim workspace release health, broad conformance, or RCH fleet health unless a separate lane proves them. |
| `admission_decision=Defer` or `Batch` with saturation or batching reason codes | `advisory` | `reason_codes`, `source_rows`, `target_dir_isolation_status`, and `peer_reservation_overlap_status` | Treat this as scheduling guidance. Record the suggested lane grouping or wait condition, but do not call validation green. |
| `admission_decision=AdvisorySpectralWarning` and `trapped_cycle_witness_status=RequiredMissing` | `advisory` | spectral wait-graph rows, missing witness status, `reason_codes` | Preserve the warning and request trapped-cycle replay evidence before claiming a deadlock. |
| `admission_decision=TrappedCycleProven` and `trapped_cycle_witness_status=Proven` | `trapped-cycle-proven` | replay witness row, spectral wait-graph row, `source_rows`, `reason_codes`, and verifier command | Claim a trapped cycle only for the cited witness and scenario. Validated-only or advisory rows are not enough. |
| `admission_decision=Reject`, `Blocked`, or `Malformed` | `validation-blocked` | first finding code, dirty/reservation/local-fallback marker, `source_rows`, and `agent_mail_summary` | Stop the broad lane. Cite the blocker exactly and use only a narrower supplemental proof if one ran. |
| `admission_decision=StaleEvidence` | `stale` | stale row id, expected/observed head, `reason_codes`, and `source_rows` | Refresh the narrow atlas rows before rerunning. Do not paste an old green transcript as current proof. |

Every closeout receipt must keep these stable fields visible enough for review:
`lane_id`, `scenario_id`, `command`, `target_dir`, `remote_required`,
`fallback_policy`, `decision`, `admission_decision`, `source_rows`,
`reason_codes`, `target_dir_isolation_status`,
`peer_reservation_overlap_status`, `trapped_cycle_witness_status`, `covers`,
`does_not_cover`, `findings`, `agent_mail_summary`, `mutates_external_state`,
`destructive_cleanup_required`, and `branch_or_worktree_required`.

Before pasting a planner summary into Beads or Agent Mail, verify the receipt in
this order:

1. Confirm the `command` starts with `RCH_REQUIRE_REMOTE=1 rch exec -- env` and
   names an isolated `CARGO_TARGET_DIR`.
2. Confirm `remote_required=true`, `fallback_policy=RemoteOnly`, and no local
   fallback marker such as `[RCH] local`, `local fallback`, or `executing
   locally` appears in the transcript.
3. Read `admission_decision` first, then map it through the taxonomy table
   above. This is the operator-facing claim label.
4. Cite `source_rows` and `reason_codes` that explain the decision. If they are
   empty, the receipt is malformed for closeout purposes.
5. Copy the exact `covers` and `does_not_cover` boundary. Never broaden the claim in prose.
6. Keep `mutates_external_state=false`, `destructive_cleanup_required=false`,
   and `branch_or_worktree_required=false`. If any are true, stop and coordinate
   instead of running or committing.
7. Prefer the rendered `agent_mail_summary` when it matches the plan. It is
   stable handoff text, not a replacement for the remote transcript or artifact
   evidence.

Acceptable closeout examples:

```text
replay-backed: `swarm-workload-corpus-focused` admitted and passed through
remote RCH on `ts2`; source_rows=`src/lab/swarm_replay.rs`,
`artifacts/swarm_workload_scenario_corpus_v1.json`; covers=
`scenario_schema_validation`; does_not_cover=`workspace_release_health`.
```

```text
advisory: atlas returned `AdvisorySpectralWarning` because
`trapped_cycle_detection_required` and witness status is `RequiredMissing`.
No deadlock proof claimed; next action is to run trapped-cycle replay evidence.
```

```text
trapped-cycle-proven: atlas returned `TrappedCycleProven` for
`spectral_wait_graph:deadlocked` with witness
`trapped_cycle_witness:validated-replay-row`; claim is limited to that scenario.
```

```text
validation-blocked: intended remote lane rejected before proof because
`rch_proof_lane_admission:local-fallback-refused` and transcript requires remote
execution. Supplemental local evidence, if any, is not the green RCH lane.
```

```text
stale: atlas row `atlas_stale_evidence` mismatched the expected head. Refreshed
atlas rows are required before this lane can be admitted or summarized green.
```

Misleading closeout language:

```text
Atlas was green, so the swarm proof lanes are healthy.
```

This omits the `covers` boundary and overclaims broad release health.

```text
Spectral warning proves a deadlock.
```

This is only true when `admission_decision=TrappedCycleProven` and the receipt
cites a proven trapped-cycle witness row.

## Declared-Path Commit Preflight

Before committing from a dirty shared-main checkout, run the dirty-tree receipt
helper with declared commit paths. The helper is non-mutating in preflight mode:
it prints the declared paths, currently staged paths, dirty peer paths outside
scope, final commit path set, and the exact path-limited command. It exits with
status 2 when the declaration is empty, escapes the repository, names a path
with known peer/conflicting ownership, names an untracked file that still needs
`git add --`, or would mix tracker state with implementation paths. Tracked
declared paths without ownership evidence are allowed, but they are surfaced in
`declared_commit.unattributed_declared_paths` so the operator can decide
whether to proceed or coordinate first.

The helper reads offline Agent Mail file reservation artifacts from the local
mail archive by default:

```text
~/.mcp_agent_mail_git_mailbox_repo/projects/data-projects-asupersync/file_reservations
```

Use `--reservation-artifact-dir <dir>` only for deterministic tests or
emergency recovery from a relocated archive. The guard treats active
peer-reserved, unreserved, unknown, or tracker staged paths outside the
declared set as commit-race blockers and exits before Git creates a commit.

Required shared-main sequence:

1. Reserve the exact files you intend to edit.
2. Run the focused proof lane for those files with `rch exec -- ...` and an
   isolated `CARGO_TARGET_DIR`.
3. Run this declared-path preflight with every path that should enter the
   commit.
4. Commit only those paths with `git commit --only -- <declared paths>`.
5. Push `main`, then sync `master` with `git push origin main:master`.
6. Close or update the bead, release reservations, and send Agent Mail closeout.

Normal code commit:

```bash
python3 scripts/dirty_tree_ownership_receipt.py \
  --repo-path . \
  --agent "$AGENT_NAME" \
  --declared-commit-preflight \
  --commit-path src/net/atp/quic/metrics.rs \
  --commit-path tests/atp_native_quic_endpoint_contract.rs \
  --output json

git commit --only \
  -m "fix(atp): diagnose QUIC PTO path pressure br-asupersync-ambb2w" \
  -- \
  src/net/atp/quic/metrics.rs \
  tests/atp_native_quic_endpoint_contract.rs
```

Docs-only commit:

```bash
python3 scripts/dirty_tree_ownership_receipt.py \
  --repo-path . \
  --agent "$AGENT_NAME" \
  --declared-commit-preflight \
  --commit-path docs/proof_runner_usage.md \
  --output json

git commit --only \
  -m "docs: document declared-path commit preflight br-asupersync-oxqrae.7.1" \
  -- docs/proof_runner_usage.md
```

Tracker-only commit:

```bash
python3 scripts/dirty_tree_ownership_receipt.py \
  --repo-path . \
  --agent "$AGENT_NAME" \
  --declared-commit-preflight \
  --commit-path .beads/issues.jsonl \
  --output json

git commit --only \
  -m "chore(beads): sync ASW-7A tracker state br-asupersync-oxqrae.7.1" \
  -- .beads/issues.jsonl
```

Abort after a race is detected:

```bash
python3 scripts/dirty_tree_ownership_receipt.py \
  --repo-path . \
  --agent "$AGENT_NAME" \
  --declared-commit-preflight \
  --commit-path scripts/dirty_tree_ownership_receipt.py \
  --output json
```

If the command exits with status 2 or `declared_commit.allowed=false`, do not
commit. Use `declared_commit.dirty_peer_paths_outside_scope`,
`declared_commit.currently_staged_paths`, and
`declared_commit.unsafe_declared_paths` to route the race through Agent Mail or
rerun with a narrower declared path set.

Recovery after an accidental mixed commit is coordination-first and
non-destructive. Do not rewrite history, reset the checkout, clean files, or
unstage peer paths by guesswork. Send Agent Mail with the commit hash, the
unexpected paths, the preflight output if available, and the path-limited
follow-up plan. Then land a normal forward commit that restores ownership
clarity: either move the accidental peer changes into the peer's next commit
with their explicit agreement, or add a narrow corrective commit that re-aligns
the intended path ownership without discarding anyone's work.

Agent Mail closeout template:

```text
Commit: <sha>
Declared paths: <declared_commit.declared_paths>
Commit-race blockers: <declared_commit.commit_race_blockers or "none">
Proof: <rch command and result>
Tracker state: <committed | local-only due shared tracker dirt>
```

If no explicit bead id is supplied, the classifier best-effort maps the first
blocker path to `git log -20 -- <path>`. The resulting
`validation_frontier_record.blocker_origin` and
`closeout_summary.blocker_origin` include the recent commit, subject, author,
and the first `asupersync-*` bead id parsed from that recent history. This is
provenance evidence only: it helps route a blocker to a recent slice, but the
`decision` and `green_proof_claimed` fields remain authoritative for whether a
closeout may claim a green proof.

## Proof-Lane Resource Envelopes

The proof runner reads resource-envelope metadata from
`artifacts/proof_lane_manifest_v1.json`, verified by
`tests/proof_lane_manifest_contract.rs`. Every lane declares a
`resource_envelope_class` whose class records:

- `timeout_seconds`
- `memory_mb`
- `remote_required`
- `local_fallback_allowed`
- `resource_pressure`
- admitted lane kinds

The contract rejects missing classes, unknown classes, zero or negative budgets,
lane-kind mismatches, missing remote-required semantics, and any
remote-required class that permits local fallback. Bad-envelope diagnostics must
carry the lane id, required command prefix, envelope class, timeout, memory,
remote-required decision, local-fallback decision, and the exact fail-closed
reason so an operator can route the blocker without guessing.

This metadata hardens proof admission and closeout evidence only. It does not
implement, replace, or prove OS-level RCH worker controls such as systemd
`MemoryMax`, cgroup CPU quotas, scheduler backpressure, or fleet-level admission
limits. A manifest envelope makes an expensive lane visible and rejectable
before dispatch; worker-enforced resource limits remain a separate operations
control.

## Available Proof Lanes

The proof runner reads from `artifacts/proof_lane_manifest_v1.json`. Common lanes:

| Lane ID | Purpose | When to Use |
|---------|---------|-------------|
| `rustfmt-check` | Code formatting | Any file changes |
| `all-targets-check` | Compilation check | Rust source changes |
| `clippy-all-targets` | Lint check | Rust source changes |
| `lib-tests` | Unit tests | Library code changes |
| `default-production-tokio-tree` | Dependency audit | Cargo.toml changes |
| `rustdoc-api` | Documentation | Public API changes |
| `runtime-pressure-control-evidence-contract` | Pressure-control evidence scope | Pressure snapshot/lab evidence/docs changes |
| `dirty-tree-ownership-receipt-contract` | Shared-main commit guard | ASW-7 guard or docs changes |

## Integration with Beads Workflow

### Standard Close Reason Pattern

When proof runner passes:
```
Completed. Proof: rch-routed lib-tests emitted 42 passed; supplemental rustfmt check passed.
```

When proof runner blocks:
```
Completed. blocked-external: intended all-targets-check stopped at audit/semaphore.rs:37 
(clippy_lint_wall) while touching src/channel/mpsc.rs; supplemental proof lib-tests passed.
```

### Before `br close`

```bash
# 1. Get appropriate lanes for your changes
LANES=$(./scripts/proof_runner.py --suggest-lanes --touched-files $(git diff --name-only))

# 2. Check if broad proof is safe
./scripts/proof_runner.py --lane all-targets-check --touched-files $(git diff --name-only)

# 3. If blocked, run the suggested supplemental proof instead
./scripts/proof_runner.py --lane lib-tests --touched-files $(git diff --name-only) --execute

# 4. Close with proper citation
br close <bead-id> --reason "Completed. Proof: supplemental lib-tests passed (broad check blocked by peer lint debt)."
```

## Disk-Pressure Closeouts

When local disk pressure affects an `rch` proof, keep the remote verdict separate
from local artifact handling. A closeout must capture these fields before it
claims proof coverage:

- `command`: exact command that was run.
- `worker_or_local_path`: worker identifier when `rch` reports one, otherwise
  the local fallback path used for a non-`rch` proof.
- `remote_exit`: remote exit code or pass/fail footer if observed; use `unknown`
  when the command timed out before a verdict.
- `first_unrelated_blocker`: first unrelated file/error that stopped a broad
  gate, or `none`.
- `artifact_status`: `retrieved`, `retrieval_failed:<path or reason>`,
  `not_requested`, or `not_available`.
- `process_status`: whether any `rch`, Cargo, or helper process remains running.

For reusable closeout receipts, run `scripts/rch_retrieval_receipt.py` with
`--proof-lifecycle-contract`. The emitted `proof_lifecycle_contract` object is
the stable disk-pressure lifecycle shape:

- `remote_result`: remote exit status and pass/fail/unknown reason.
- `retrieval_result`: local artifact retrieval status, blocker kind, and
  blocker line.
- `local_pressure`: explicit disk-pressure signal such as `critical`/`enospc`
  when observed.
- `cleanup_authorization`: report-only cleanup posture. It must keep
  `authorized=false` and `executable_cleanup_commands=[]` until the user gives
  explicit written permission to delete files or directories.

Use this interpretation table:

| Situation | Closeout rule |
|-----------|---------------|
| Remote pass plus artifact retrieval failure | You may cite the remote proof as passed only if the remote pass/fail line or exit status was visible. State that local artifact retrieval failed separately, including the path or filesystem that filled. |
| Timeout before verdict | Do not claim proof success. Report `remote_exit=unknown`, the last visible phase, and whether any process remains running. |
| Timeout after pass footer | You may cite the visible pass footer, but still record the timeout and artifact status separately. |
| Local fallback | Label it as supplemental/local evidence, not as the original broad `rch` proof. Include the fallback command/path. |
| Cleanup requires deletion | Do not delete caches, `/tmp`, `/dev/shm`, target dirs, logs, or artifacts without explicit user permission. Report the cleanup need as a blocker or next action. |

Acceptable closeout language:

```
Completed. Proof: `rch exec -- env -u CARGO_TARGET_DIR cargo fmt --check`
showed remote exit 0 on worker `rch-a`; artifact_status=retrieval_failed:/dev/shm
full; process_status=no rch/cargo process remains running. This proves rustfmt
passed remotely, but not that artifacts were retrieved locally.
```

```
Completed with supplemental proof only. Broad clippy timed out before verdict:
remote_exit=unknown; first_unrelated_blocker=none observed; artifact_status=not_available;
process_status=no rch/cargo process remains running. Local fallback `git diff --check`
passed.
```

Misleading closeout language:

```
All validation passed; only artifact retrieval failed.
```

This omits the command, remote exit, artifact status, and process status.

```
Clippy passed after timeout.
```

This is only accurate when a pass footer or remote exit status was visible before
the timeout; otherwise the verdict is unknown.

## Swarm Resource-Control Runbook

This runbook is part of the proof-lane documentation contract. It must keep
pointing at the canonical manifest, `artifacts/proof_lane_manifest_v1.json`, and
its verifier, `tests/proof_lane_manifest_contract.rs`. It also must keep pointing
at the current proof-claim dashboard, `artifacts/proof_status_snapshot_v1.json`,
and its verifier, `tests/proof_status_snapshot_contract.rs`. Do not add a proof
claim here unless the lane exists in the manifest or the status snapshot names
the exact blocked frontier row.

The pressure-control evidence lane is recorded in
`artifacts/runtime_pressure_control_evidence_contract_v1.json` and verified by
`tests/runtime_pressure_control_evidence_contract.rs`. Use the canonical manifest
lane `runtime-pressure-control-evidence-contract` when changes touch runtime
pressure snapshots, region memory-budget pressure rows, RCH proof-lane pressure
rows, scheduler pressure flamegraph attribution, deterministic pressure lab
evidence, or pressure-control operator docs.

The dedicated operator runbook is `docs/runtime_pressure_triage_runbook.md`. It
maps symptoms to snapshot fields, admission decisions, lab replay evidence, and
the exact RCH verifier commands without widening the contract's claims.

That lane proves only contract alignment: source schema versions, documented
region memory-budget pressure row semantics, RCH proof-lane pressure row
semantics, scheduler pressure flamegraph attribution, scenario families, docs
markers, and the exact RCH command. Scheduler attribution links
`scheduler_tail_pressure` evidence to the Phase 6 flamegraph gate,
`artifacts/flamegraphs/main-<bead-or-short-sha>.svg`, and the
`methodology_baselines` rows
`methodology/task_spawn/inject_ready_global_queue`,
`methodology/task_spawn/local_queue_push`, and
`methodology/task_spawn/local_queue_spawn_batch/1000`. It does not prove
real-host throughput, performance improvement, scheduler regression closure,
autonomous scheduler rewrites, production-on-by-default admission/backpressure,
per-region allocator enforcement, RCH fleet availability, or a deadlock without
explicit trapped-cycle proof. Treat live production pressure signals as
advisory unless they are paired with lab/replay evidence, the required
flamegraph attribution for triggered scheduler hot-path work, or trapped-cycle
proof. Adaptive controls remain opt-in until stronger evidence supports a
broader policy.

Run the scoped verifier:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_runtime_pressure_control_evidence_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test runtime_pressure_control_evidence_contract -- --nocapture
```

Generate the manifest-backed status dashboard before changing proof claims:

```bash
python3 scripts/proof_runner.py --proof-status-dashboard --output json
```

For reviewable fixtures or contract tests, pass
`--proof-status-snapshot <path>` and
`--proof-console-generated-at <timestamp>`. The dashboard fails closed when a
claim references a missing manifest lane, names an unsupported guarantee, or
keeps a red blocker row without fresh file-and-line evidence. When it fails,
update `artifacts/proof_lane_manifest_v1.json`,
`artifacts/proof_status_snapshot_v1.json`, and the exact validation frontier
record together instead of broadening the claim.

Promote a red proof into the deterministic failure corpus when the blocker is
likely to recur and the raw stage log can be replayed without contacting the
original service. The canonical manifest is
`artifacts/failure_corpus_manifest_v1.json`, checked by
`tests/failure_corpus_manifest_contract.rs`.

Replay a stored corpus case:

```bash
python3 scripts/proof_runner.py --failure-corpus-replay FC-RCH-ADMISSION-001 --output json
```

Scrub a raw transcript before adding a new case:

```bash
python3 scripts/proof_runner.py --failure-corpus-scrub-input /path/to/raw.log --output json
```

Only promote cases that preserve the first blocker, proof lane, decision class,
stage logs, and replay command after scrubbing. Do not promote cases that require
live credentials, peer-owned dirty paths, or external services to reproduce.

Use these colors for operator and agent decisions:

| State | Meaning | Allowed agent action |
|-------|---------|----------------------|
| Green | No active disk, memory, reservation, or dirty-path blocker is visible for the chosen lane. | Run the exact manifest lane through `rch exec -- ...` with an isolated `CARGO_TARGET_DIR`, then cite the visible remote verdict. |
| Yellow | The lane is intentionally scoped, fixture-only, or broad frontier evidence rather than a production guarantee. | Use it as scoped evidence only. Do not broaden the claim beyond the manifest `covers` and `explicit_not_covered` fields. |
| Orange | Work can continue, but a safer lane exists because disk, memory, rch capacity, peer reservations, or dirty paths make broad proof risky. | Prefer source-only docs, fixtures, rustfmt, exact golden diffs, or tracker-only closeout. Announce the narrowed validation class in Agent Mail. |
| Red | The intended lane is blocked by critical disk pressure, no remote worker, peer-owned dirty paths, active reservations, or a compile/test error outside the touched slice. | Stop the broad lane, record the first blocker exactly, and use only a narrower supplemental proof. Never force release or delete files without explicit user authorization. |

Resource-control artifacts are evidence, not daemons:

- `scripts/reservation_aware_work_finder.py --output json` is the stable machine
  receipt for ready work, active reservations, dirty paths, disk pressure, stale
  in-progress rows, and cleanup authorization.
- `scripts/reservation_aware_work_finder.py --output markdown` is the compact
  human dashboard for the same receipt. It must stay non-mutating: no Beads
  mutation, no Agent Mail mutation, no Cargo execution, no branch/worktree
  operations, and no cleanup commands.
- `scripts/rch_retrieval_receipt.py --proof-lifecycle-contract` is the closeout
  shape for remote proof result, local artifact retrieval result, local pressure,
  and cleanup authorization.

Keep proof verdicts separate from artifact movement:

- A remote `exit 0` or visible pass footer proves only the command that ran on the
  worker. It does not prove local artifact retrieval succeeded.
- A retrieval failure after a remote pass is not a proof failure. It is an
  artifact-status blocker that must name the path or filesystem that filled.
- A timeout before a visible verdict is unknown. Do not summarize it as passed.
- A local fallback is supplemental/local evidence, not the original `rch` proof
  lane. If `RCH_REQUIRE_REMOTE=1` refuses local fallback, record that refusal.

Cleanup remains report-only. Do not delete `/tmp`, target directories, caches,
logs, proof artifacts, or ballast unless the user gives explicit written
authorization for the exact cleanup target. Dashboard and receipt outputs must
keep cleanup candidates as recommendations, not executable deletion commands.

## Error Handling

Exit codes:
- **0**: Preflight passed, safe to proceed
- **1**: Preflight blocked, use supplemental proof  
- **2**: Error in proof runner itself

The tool never runs destructive operations - it only analyzes and suggests.

## Testing

The proof runner has comprehensive contract tests in `tests/proof_runner_contract.rs`:

```bash
# Run the proof runner tests
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_docs cargo test proof_runner_contract -- --nocapture
```

Tests cover:
- Deterministic output for same inputs
- Proper validation frontier record format
- Correct supplemental proof suggestions
- Integration with proof lane manifest
- Schema compatibility
