# Dirty-Tree Ownership Receipt

`scripts/dirty_tree_ownership_receipt.py` builds a non-mutating receipt for
shared-main release prep. It correlates `git status --porcelain=v1` paths with
Agent Mail file reservations, recent lane subjects, Beads issue text, and
ignored generated-artifact patterns so operators can see which dirty paths are
owned, unowned, stale, ignored, or release blocking.

The motivating release-prep failure mode is a dirty tree where `git status`
lists files from several agents, while the ownership evidence lives elsewhere:
MCP Agent Mail reservations, handoff mail, and bead IDs. The receipt keeps those
signals together and avoids unsafe advice. It never edits, stages, reverts,
cleans, deletes, branches, creates worktrees, mutates Beads, sends Agent Mail, or
runs Cargo.

## Fixture Mode

Use fixture mode for deterministic tests and handoffs when MCP is unavailable:

```bash
python3 scripts/dirty_tree_ownership_receipt.py \
  --fixture tests/fixtures/dirty_tree_ownership_receipt/release_prep_shared_main.json \
  --repo-path /data/projects/asupersync \
  --agent TopazGoose \
  --generated-at 2026-06-05T06:05:00Z \
  --release-prep-report \
  --output json
```

The optional `release_prep_report` section contains:

- `input_files`: dirty paths from the porcelain fixture or live probe.
- `reservation_holders`: active, stale, and released reservation rows.
- `rows`: per-path owner classification, matched lane subjects, reservations,
  staging decision, and release-blocker status.
- `release_blocker_summary`: deterministic blocker count, class rollup, and
  blocker paths.

The report classifies paths as:

- `owned`: current-agent ownership evidence exists.
- `unowned`: no active reservation, lane subject, or bead evidence names an
  owner.
- `stale-reservation`: only expired reservations match the path.
- `ignored-artifact`: path matches ignored generated-output patterns.
- `release-blocker`: peer ownership, overlapping reservations, tracker state, or
  another unsafe release boundary blocks final gates.

## E2E Logging

The E2E wrapper uses the synthetic release-prep fixture plus the real repository
path shape and prints detailed logs for operator review:

```bash
scripts/run_dirty_tree_ownership_receipt_e2e.sh \
  --fixture tests/fixtures/dirty_tree_ownership_receipt/release_prep_shared_main.json \
  --repo-path /data/projects/asupersync
```

The log includes input files, reservation holders, matched lane subjects,
classifications, and the release-blocker summary. It does not print destructive
cleanup commands or instructions to edit, stage, or revert peer-owned files.

Focused validation:

```bash
python3 -m py_compile scripts/dirty_tree_ownership_receipt.py
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_dirty_tree_ownership_receipt cargo test -p asupersync --test dirty_tree_ownership_receipt_contract -- --nocapture
```
