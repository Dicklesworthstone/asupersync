# Proof Lane Failure Repro Receipts

The proof lane failure repro receipt helper turns saved RCH/proof-runner failure
transcripts into deterministic minimal repro plans. It is for blocker triage:
given a failed broad or focused proof lane, it identifies the first hard blocker,
names the smallest useful rerun command, and records what that command does and
does not prove.

This report does not certify workspace health. A generated repro command is not
a fresh proof until it is rerun through RCH. Local fallback evidence remains
rejected for remote-required proof lanes.

## Contract Surface

- Helper: `scripts/proof_lane_failure_repro_receipt.py`
- Contract artifact: `artifacts/proof_lane_failure_repro_receipt_contract_v1.json`
- Rust contract test: `tests/proof_lane_failure_repro_receipt_contract.rs`
- Operator documentation: `docs/proof_lane_failure_repro_receipt.md`

The helper is read-only. It consumes an explicit fixture or contract JSON file
and emits JSON or Markdown to stdout. It does not run Cargo, inspect Git, mutate
the tracker, query Agent Mail, or rewrite artifacts.

## Classifications

The contract fixture covers these failure classes:

- `rustc-compile-error`: the first hard blocker is a Rust compiler diagnostic
  with file, line, column, code, and message.
- `test-assertion-failure`: a named test panicked or failed and should be rerun
  with the exact filter and `--nocapture`.
- `timeout-after-first-failure`: the lane timed out, but the log already contains
  a first hard failure that should drive the minimal repro.
- `worker-disk-pressure`: the worker reported `ENOSPC` or an equivalent disk
  blocker; do not widen to local Cargo.
- `ssh-transport-failure`: RCH transport failed before the proof command could
  run; retry remotely after transport recovers.
- `retrieval-timeout-after-pass`: the remote proof exited successfully, but
  artifact retrieval timed out and needs separate classification.
- `zero-test-proof`: the command executed zero tests and is not proof evidence.
- `local-fallback-refused`: remote-required policy correctly rejected local
  fallback; wait for RCH admission or choose non-Cargo fallback work.

Every Cargo repro command must preserve `RCH_REQUIRE_REMOTE=1`, `rch exec --`,
and a lane-specific `CARGO_TARGET_DIR=${TMPDIR:-/tmp}/...` envelope. The helper
never recommends branch/worktree reruns, local Cargo fallback, or broad retries
when a smaller target/filter is available.

## Usage

Emit deterministic JSON from the checked contract fixture:

```bash
python3 scripts/proof_lane_failure_repro_receipt.py \
  --fixture artifacts/proof_lane_failure_repro_receipt_contract_v1.json \
  --generated-at 2026-06-06T09:20:00Z \
  --output json
```

Emit Markdown for operator handoff:

```bash
python3 scripts/proof_lane_failure_repro_receipt.py \
  --fixture artifacts/proof_lane_failure_repro_receipt_contract_v1.json \
  --generated-at 2026-06-06T09:20:00Z \
  --output markdown
```

Validate the contract with the focused RCH lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_proof_lane_failure_repro_receipt" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test proof_lane_failure_repro_receipt_contract -- --nocapture
```

Use this helper before release prep or large shared-main closeout when a broad
proof lane fails. Pair its output with the proof evidence debt graph when
deciding whether evidence is stale, blocked, superseded, zero-test, or invalid
to cite.
