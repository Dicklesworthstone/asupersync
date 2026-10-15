# Reservation-Aware Fallback Work Finder

The reservation-aware fallback work finder turns read-only tracker, dirty-tree,
and Agent Mail reservation fixture snapshots into deterministic next-action
recommendations for shared-main swarm sessions. It is for the moment when
`br ready` is blocked, epic-only, or ambiguous and an agent needs to keep moving
without entering communication purgatory.

This report does not certify source correctness. It does not authorize editing
peer-reserved paths, does not create branches or worktrees, does not override
Agent Mail reservations, and does not turn local Cargo fallback into proof.

## Contract Surface

- Helper: `scripts/reservation_aware_fallback_work_finder.py`
- Contract artifact: `artifacts/reservation_aware_fallback_work_finder_contract_v1.json`
- Rust contract test: `tests/reservation_aware_fallback_work_finder_contract.rs`
- Operator documentation: `docs/reservation_aware_fallback_work_finder.md`
- Report schema: `reservation-aware-fallback-work-finder-v1`

The helper is read-only. It consumes an explicit fixture or contract JSON file
and emits JSON or Markdown to stdout. It does not run Cargo, inspect Git, mutate
the tracker, query Agent Mail, or rewrite artifacts.

## Classifications

The contract fixture covers these shared-main cases:

- `claimable-ready-task`: a concrete ready non-epic issue has no active peer
  reservation overlap and can be claimed after exact file reservations.
- `epic-only-ready-queue`: the ready queue contains only an epic; create or
  select a concrete child bead before touching source files.
- `blocked-by-active-reservation`: a ready task overlaps an active peer
  reservation; coordinate or wait instead of editing those paths.
- `stale-in-progress-candidate`: an in-progress issue is idle past the threshold
  and has no active reservation overlap, so reopening/adopting it is allowed.
- `tracker-only-dirt`: dirty paths are limited to tracker metadata such as
  `.beads/`; closeout can proceed while source dirt remains untouched.
- `source-peer-dirt`: source or test dirt is owned by another active lane; avoid
  those files and do not stage them.
- `no-useful-bead`: there is no claimable ready task, stale candidate,
  tracker-only lane, or approved fallback surface; stop with the blocker.
- `planning-fallback-recommended`: no source task is claimable, but an approved
  docs/script/test-only surface can be turned into a bounded planning bead.

Every row includes a recommended action, whether work is safe to start, the
issue to claim or reopen when applicable, exact files to avoid, forbidden
actions, blockers, and non-claims.

## Usage

Emit deterministic JSON from the checked contract fixture:

```bash
python3 scripts/reservation_aware_fallback_work_finder.py \
  --fixture artifacts/reservation_aware_fallback_work_finder_contract_v1.json \
  --generated-at 2026-06-06T10:20:00Z \
  --output json
```

Emit Markdown for operator handoff:

```bash
python3 scripts/reservation_aware_fallback_work_finder.py \
  --fixture artifacts/reservation_aware_fallback_work_finder_contract_v1.json \
  --generated-at 2026-06-06T10:20:00Z \
  --output markdown
```

Validate the contract with the focused RCH lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_reservation_aware_fallback_work_finder" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test reservation_aware_fallback_work_finder_contract -- --nocapture
```

Use this helper after `bv --robot-*`, `br --no-auto-import`, and Agent Mail
reservation checks have narrowed the situation but no immediately safe source
lane is obvious. The output is a next-action recommendation, not a replacement
for live reservations, tracker updates, or RCH validation.
