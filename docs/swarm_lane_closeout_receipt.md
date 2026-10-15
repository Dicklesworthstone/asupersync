# Swarm Lane Closeout Receipt

The swarm lane closeout receipt turns explicit shared-main lane evidence into a
deterministic operator receipt. Use it when a proof/admission lane needs a
machine-readable closeout that future agents can verify without reading a chat
transcript.

The helper is read-only. It does not run `br`, RCH, Cargo, Git, or Agent Mail,
and it does not mutate `.beads/issues.jsonl` or write artifacts. It evaluates a
fixture that already contains bead state, Agent Mail coordination, reservation
leases, proof command results, pushed-ref evidence, and remaining dirty-tree
classification.

## Contract Surface

- Helper: `scripts/swarm_lane_closeout_receipt.py`
- Contract artifact: `artifacts/swarm_lane_closeout_receipt_contract_v1.json`
- Rust contract test: `tests/swarm_lane_closeout_receipt_contract.rs`
- Report schema: `swarm-lane-closeout-receipt-v1`

## Classifications

- `admissible-closeout`: the receipt contains bead state, coordination, active
  reservations through validation, green proof commands, verified pushed refs,
  and no remaining dirty-tree rows.
- `failed-proof-cited-green`: a proof command exited nonzero but was cited as
  green; the receipt fails closed.
- `missing-remote-worker-evidence`: a remote-required RCH proof lacks a worker
  identity; rerun the lane with remote proof evidence.
- `zero-test-exact-filter`: an exact test filter succeeded while running zero
  tests; rerun with a nonzero test count before citing it.
- `expired-reservation-gap`: at least one owned path lacked an active exclusive
  reservation through the validation window.
- `unverified-pushed-refs`: pushed refs, ahead/behind state, or the legacy
  mirror check were not verified.
- `peer-dirt-shared-main`: the lane is otherwise admissible while remaining
  dirty files are classified as peer-owned or intentionally unstaged and outside
  the owned path set.

## Usage

Emit deterministic JSON from the checked contract fixture:

```bash
python3 scripts/swarm_lane_closeout_receipt.py \
  --fixture artifacts/swarm_lane_closeout_receipt_contract_v1.json \
  --generated-at 2026-06-06T15:30:00Z \
  --output json
```

Emit Markdown for Agent Mail or release handoff:

```bash
python3 scripts/swarm_lane_closeout_receipt.py \
  --fixture artifacts/swarm_lane_closeout_receipt_contract_v1.json \
  --generated-at 2026-06-06T15:30:00Z \
  --output markdown
```

Focused validation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_swarm_lane_closeout_receipt" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test swarm_lane_closeout_receipt_contract -- --nocapture
```

## Shared-Main Staging

The receipt can explain remaining peer dirt, but it is not a staging tool. When
closing a real lane, stage only the intended tracker rows and owned files. Do
not absorb unrelated `.beads/issues.jsonl` rows or peer-owned source dirt into a
commit just because the receipt classifies them.

## Non-Claims

This receipt does not prove source correctness beyond the listed commands, does
not authorize branches or worktrees, does not make local fallback acceptable
remote proof, and does not override live Agent Mail reservations. It is a
fail-closed closeout artifact for deciding whether a shared-main lane has enough
evidence to close, commit, push, mirror the legacy ref, release reservations,
and send a handoff.
