# RCH Quiet-Phase Receipt

The RCH quiet-phase receipt turns saved RCH transcripts into deterministic
progress and timeout-forecast evidence. It is for long proof lanes that spend
minutes without stdout while compiling workspace crates or retrieving artifacts.

The helper is read-only. It consumes explicit fixture data and emits JSON or
Markdown to stdout. It does not run Cargo, inspect Git, query RCH, mutate beads,
or write artifacts.

## Contract Surface

- Helper: `scripts/rch_quiet_phase_receipt.py`
- Contract artifact: `artifacts/rch_quiet_phase_receipt_contract_v1.json`
- Rust contract test: `tests/rch_quiet_phase_receipt_contract.rs`
- Report schema: `rch-quiet-phase-receipt-v1`

## Classifications

- `remote-success-with-quiet-progress`: the transcript has remote worker
  evidence, remote command start, remote exit zero, and artifact retrieval
  completion. The proof is citeable because of exit and retrieval evidence;
  quiet progress is not success.
- `remote-command-failed`: the remote worker ran the command and exited
  nonzero. Use the failure; do not cite quiet progress as green evidence.
- `artifact-retrieval-stall`: the remote command exited zero, but artifact
  retrieval started and did not complete.
- `local-fallback-refused`: a remote-required lane refused or attempted local
  fallback. Local fallback is not proof.
- `envelope-timeout-risk`: the transcript shows remote progress but the quiet
  phase has crossed the lane envelope or warning boundary without a remote exit.
- `missing-remote-required-evidence`: remote-required provenance, worker
  identity, remote command start, or no-local-fallback envelope evidence is
  missing.

## Usage

Emit deterministic JSON from the checked contract fixture:

```bash
python3 scripts/rch_quiet_phase_receipt.py \
  --fixture artifacts/rch_quiet_phase_receipt_contract_v1.json \
  --generated-at 2026-06-06T16:50:00Z \
  --output json
```

Emit Markdown for Agent Mail handoff:

```bash
python3 scripts/rch_quiet_phase_receipt.py \
  --fixture artifacts/rch_quiet_phase_receipt_contract_v1.json \
  --generated-at 2026-06-06T16:50:00Z \
  --output markdown
```

Focused validation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_rch_quiet_phase_receipt" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test rch_quiet_phase_receipt_contract -- --nocapture
```

## Operator Notes

Use this receipt while waiting on long `cargo check --all-targets`,
`cargo clippy --all-targets -- -D warnings`, or focused contract lanes. A quiet
phase can show that the worker is still moving through expected milestones, but
it cannot make the lane green. Closeout still needs remote exit evidence,
nonzero test counts where applicable, artifact retrieval status, and the normal
bead, reservation, push, and mirror workflow.

If artifact retrieval stalls after remote exit zero, classify retrieval
separately before citing the proof. If local fallback appears anywhere in the
transcript, fail closed and rerun with remote-required RCH once a worker is
available.

## Non-Claims

This receipt does not prove source correctness, does not replace live RCH queue
state, does not make local fallback acceptable, and does not authorize closing a
lane without remote exit evidence. It only explains RCH progress, quiet phases,
timeout risk, and retrieval status from an explicit transcript.
