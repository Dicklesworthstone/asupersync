# ATP vs rsync — benchmark matrix runbook

Operator guide for the matrix harness specified in
[`docs/atp_bench_matrix_spec.md`](../../docs/atp_bench_matrix_spec.md), obeying the
BENCHMARK INTEGRITY STANDARD (`docs/atp_rq_beat_rsync_ledger.md`).

This is the **new, rigorous** matrix harness. The older
`scripts/atp_bench/run_bench.sh` + `report.py` (br-asupersync-iiz6jk) and
`scripts/atp_rq_regime_bench.sh` still exist for their own purposes; the matrix
harness below supersedes them for the "right way" scorecard.

## The four pieces (cc_1 lane)

| file | role |
|---|---|
| `matrix_bench.sh`    | **planner / resume layer** — enumerates every `(workload, regime, tier, method, rep)`, emits a resumable plan JSONL, skips cells already present in the results, and shells out to a per-cell command. |
| `run_matrix_cell.sh` | **per-cell runner** — the `--run-cell-command`. Hermetic netns+veth+netem (rate-capped, symmetric), runs ONE transfer, measures wall + peak/avg RSS (both ends) + CPU% + feedback_rounds, SHA-256 verifies, appends one result JSONL row. **Fail-closed.** |
| `gen_tree.py`        | **deterministic, seeded power-law tree generator** (`tree_small`, `tree_big`) + per-file manifest JSONL. |
| `score_matrix.py`    | **scorer** — JSONL → median + cv + atp/rsync wall & RSS ratios + per-regime geomean → markdown scorecard. Headline = **atp-vs-rsync only**. |

## Quick plan (dry-run, no root, no transfers)

```bash
# Print the resumable matrix plan (one JSONL row per cell):
bash scripts/atp_bench/matrix_bench.sh
# Narrow it:
bash scripts/atp_bench/matrix_bench.sh \
  --workloads 50M,tree_small --regimes good,bad --tiers nocrypto
```

## Execute (root required for netns/tc)

```bash
sudo env BIN=/tmp/atp_bench/atp \
  bash scripts/atp_bench/matrix_bench.sh \
    --execute --generate-workloads \
    --workloads 50M,tree_small \
    --regimes perfect,good,bad,broken \
    --tiers nocrypto \
    --run-cell-command 'bash scripts/atp_bench/run_matrix_cell.sh'
```

`BIN` must be a **release** `atp` build (large-K RaptorQ decode is too slow in
debug). Build it with `--features atp-cli` from this source tree; that feature
includes the TLS support required by the encrypted `atp-quic-tls13` tier. The
runner picks the method per `(tier)`:

| tier | atp method | rsync method (optimally tuned) |
|---|---|---|
| `nocrypto`  | `atp-rq-lab` (`--rq-allow-unauthenticated-lab`) | `rsyncd` (plaintext daemon) |
| `auth`      | `atp-rq-auth` (`--rq-auth-key-hex`)            | `rsync-ssh-aes128gcm` |
| `encrypted` | `atp-quic-tls13` (TLS-1.3 + symbol auth)       | `rsync-ssh-aes128gcm` |

rsync is always `-aW --inplace --no-compress` (whole-file, in-place, no `-z` on
incompressible payloads), and over ssh uses `-c aes128-gcm@openssh.com`. This is
the toughest-possible rsync, per the integrity standard.

## Score

```bash
RUN=$(ls -dt artifacts/atp_bench_matrix/* | head -1)
python3 scripts/atp_bench/score_matrix.py "$RUN/results.jsonl" --out-md "$RUN/scorecard.md"
# CI gate: non-zero exit if any row failed sha / completion:
python3 scripts/atp_bench/score_matrix.py "$RUN/results.jsonl" --fail-on-mismatch
```

### Focused Encrypted ATP Gate

For QUIC/TLS source-stream changes, run the real netns ATP cells before closing
the bead. This catches sender/receiver completion bugs that a CLI compile cannot:

```bash
sudo env BIN=/tmp/atp_bench/atp ATP_MATRIX_TIMEOUT=90 \
  bash scripts/atp_bench/matrix_bench.sh \
    --execute --generate-workloads \
    --workloads 50M \
    --regimes perfect,good \
    --tiers encrypted \
    --methods atp-quic-tls13 \
    --reps 1 \
    --fail-on-mismatch \
    --run-cell-command 'bash scripts/atp_bench/run_matrix_cell.sh'
```

## Integrity guarantees (why a failure can never read as a win)

- **Every transfer is SHA-256 verified** (file: digest; tree: sorted per-file
  digest set vs the gen_tree manifest). A mismatch/timeout/error is recorded with
  `status != "ok"` and `sha_ok = false`.
- The scorer admits **only** verified, completed reps to medians and headline
  ratios. Failed/timed-out cells are listed in "Failed or excluded rows" and are
  **excluded** from the per-regime geomean — the known 50M/3%/broken
  source-first sha-MISS (123s) shows up as a failure, not a 123s "loss" or a win.
- Comparison is **atp-vs-rsync only**, same workload + regime + **crypto tier**
  (crypto-symmetric). Never atp-lab vs ssh-rsync; never "vs old atp".
- Links are **rate-capped** netem (`perfect` 1gbit / `good` 200mbit / `bad`
  50mbit / `broken` 10mbit) applied symmetrically on both veth ends — an uncapped
  link is an unrealistic ∞-bandwidth cell.
- **Resumable:** re-run with the same `--out`/`--results` to skip cells already
  marked `ok`; failures are retried. Long cells (`5G`×`broken`) get REPS=1 + a
  generous timeout. Nothing is silently truncated.

## Reps / regimes / netem (defaults, from the spec)

- REPS = 3 (5 for `500K`/`tree_small`; 1 for `5G`×`broken`); report median + cv%
  (cv > 5% flagged as noisy).
- Regimes (rate, delay±jitter, loss, extra): `perfect` 1gbit/2ms/0;
  `good` 200mbit/25ms/0.1%; `bad` 50mbit/80±20ms/2%;
  `broken` 10mbit/200±50ms/10% + reorder 5% + dup 1%.
