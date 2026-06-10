# RCH Stale-Progress Receipt

The RCH stale-progress receipt turns an RCH status snapshot plus an explicit
operator decision into deterministic infrastructure evidence. It is for
remote-required Cargo lanes that keep heartbeating while compiler progress is
stale, or that are canceled after RCH marks the build stale.

The helper is read-only. It consumes checked fixture data and emits JSON or
Markdown to stdout. It does not run Cargo, query live RCH, inspect Git, mutate
beads, send Agent Mail, or write artifacts.

## Contract Surface

- Helper: `scripts/rch_stale_progress_receipt.py`
- Contract artifact: `artifacts/rch_stale_progress_receipt_contract_v1.json`
- Rust contract test: `tests/rch_stale_progress_receipt_contract.rs`
- Report schema: `rch-stale-progress-receipt-v1`

## Classifications

- `heartbeat-live-progress-stale-wait`: the worker heartbeat is fresh and the
  lane has crossed only the quiet warning. Keep polling; this is not a source
  result and not a reason to cancel peer work.
- `owned-stale-cancel-recommended`: the current agent owns the build, detector
  progress is stale, and cancellation is allowed by policy.
- `stale-progress-canceled`: the current agent owns the stale build and
  cancellation completed with cleanup metadata. Retry is allowed only because
  the stale receipt is deterministic.
- `peer-owned-do-not-cancel`: the build is stale but peer-owned. Never cancel it
  from another agent; coordinate through Agent Mail.
- `heartbeat-stale-infra`: heartbeat is stale. Treat the receipt as
  infrastructure evidence, not a Rust diagnostic.
- `local-fallback-refused`: remote-required proof could not use a remote worker
  and local fallback was refused or detected. This is never valid proof.

## Usage

Emit deterministic JSON from the checked contract fixture:

```bash
python3 scripts/rch_stale_progress_receipt.py \
  --fixture artifacts/rch_stale_progress_receipt_contract_v1.json \
  --generated-at 2026-06-10T12:40:00Z \
  --output json
```

Emit Markdown for Agent Mail handoff:

```bash
python3 scripts/rch_stale_progress_receipt.py \
  --fixture artifacts/rch_stale_progress_receipt_contract_v1.json \
  --generated-at 2026-06-10T12:40:00Z \
  --output markdown
```

Focused validation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_rch_stale_progress_receipt" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test rch_stale_progress_receipt_contract -- --nocapture
```

## Operator Notes

Use this receipt when an RCH lane is heartbeat-live but progress-stale, or when
you have canceled your own stale build and need to record why the result is not
source-code evidence. The receipt must carry build id, worker id, command,
target dir, heartbeat/progress ages, detector confidence, ownership, peer-owned
active builds, cancellation outcome, retry policy, and explicit no-claim
boundaries.

Retry only after a deterministic stale receipt or a real compiler/runtime
diagnostic. Never cancel peer-owned builds. Never cite stale progress,
heartbeat-stale infrastructure, or local fallback as fresh proof.

## Non-Claims

This receipt does not prove source correctness, release readiness, workspace
health, live RCH fleet availability, or a successful proof lane. It only
explains why a remote-required RCH lane did not produce a citeable Rust result
and what an operator may safely do next.
