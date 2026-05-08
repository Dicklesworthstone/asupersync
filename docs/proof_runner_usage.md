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
  "command_would_run": "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_docs cargo fmt --check",
  "validation_frontier_record": {
    "command": "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_docs cargo fmt --check",
    "timestamp": "2026-05-07T19:30:00Z",
    "touched_files": ["src/runtime/state.rs"],
    "decision": "pass",
    "supplemental_proof_command": "rch exec -- rustfmt --edition 2024 --check src/runtime/state.rs"
  },
  "recommendation": "proceed"
}
```

## Validation Frontier Compatibility

The proof runner emits records compatible with the validation frontier ledger schema (`artifacts/validation_frontier_ledger_schema_v1.json`). Key decisions:

- **`pass`**: Safe to run the intended broad proof
- **`blocked-external`**: Blocked by unrelated changes, use supplemental proof
- **`failed-local`**: Your changes have issues, fix them first

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
