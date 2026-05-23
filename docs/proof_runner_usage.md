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
