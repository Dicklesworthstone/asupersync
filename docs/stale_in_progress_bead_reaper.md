# Stale In-Progress Bead Reaper

The stale in-progress bead reaper turns explicit bead rows and Agent Mail
active-agent snapshots into a deterministic operator receipt. Use it when a
shared-main session contains beads marked `in_progress` by agents that appear
inactive, but only after checking live Agent Mail state.

Report mode is the default. It does not run `br`, mutate `.beads/issues.jsonl`,
inspect Git, query Agent Mail, or reserve files. Apply mode must be requested
explicitly and still only emits deterministic post-mutation objects to stdout;
it does not rewrite the tracker file in place.

## Contract Surface

- Helper: `scripts/stale_in_progress_bead_reaper.py`
- Contract artifact: `artifacts/stale_in_progress_bead_reaper_contract_v1.json`
- Rust contract test: `tests/stale_in_progress_bead_reaper_contract.rs`
- Report schema: `stale-in-progress-bead-reaper-report-v1`

## Classifications

- `stale-reopen-candidate`: an `in_progress` bead is assigned to a known inactive
  agent and exceeds the inactivity threshold.
- `live-agent-excluded`: the assignee appears active; coordinate instead of
  reopening.
- `recent-update-excluded`: the assignee is inactive, but the bead was updated
  too recently.
- `missing-timestamp-refused`: stale age cannot be proven from the row.
- `malformed-row-refused`: required tracker fields are missing.
- `ambiguous-ownership-refused`: the assignee is absent from the active-agent
  snapshot.
- `non-in-progress-ignored`: the bead is not in progress and should not be
  touched by this helper.

## Usage

Dry-run JSON report from the checked contract fixture:

```bash
python3 scripts/stale_in_progress_bead_reaper.py \
  --fixture artifacts/stale_in_progress_bead_reaper_contract_v1.json \
  --generated-at 2026-06-06T14:30:00Z \
  --output json
```

Explicit apply-mode receipt:

```bash
python3 scripts/stale_in_progress_bead_reaper.py \
  --fixture artifacts/stale_in_progress_bead_reaper_contract_v1.json \
  --generated-at 2026-06-06T14:30:00Z \
  --mode apply \
  --output markdown
```

Focused validation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_stale_in_progress_bead_reaper" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test stale_in_progress_bead_reaper_contract -- --nocapture
```

## Shared-Main Staging

If a future operator chooses to reopen real beads from a report, stage only the
intended tracker rows; in other words, stage only the intended tracker rows and
do not absorb unrelated `.beads/issues.jsonl` dirt from peer lanes. Do not cite
stale fixture snapshots as live authority. Recheck `br --no-auto-import ready
--json`, `bv --robot-triage`, active Agent Mail agents, and file reservations
before applying any tracker mutation.

## Non-Claims

This report does not prove source correctness, does not authorize branch or
worktree creation, does not override Agent Mail reservations, and does not make
local Cargo fallback acceptable proof. It is a fail-closed coordination receipt
for deciding whether stale in-progress tracker ownership is safe to reopen.
