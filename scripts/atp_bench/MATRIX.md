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
| `auth`      | `atp-rq-auth` (fresh key over protected stdin) | `rsync-ssh-aes128gcm` |
| `encrypted` | `atp-quic-tls13` (TLS-1.3 transport auth)      | `rsync-ssh-aes128gcm` |

Every authenticated RQ cell generates a fresh 32-byte key before the timed
transfer and gives the receiver and sender one copy each through
`--rq-auth-key-stdin`. The key never enters a process argument, environment,
`/usr/bin/time` command record, or result artifact. The old `RQ_AUTH_KEY_HEX`
and `ATP_RQ_AUTH_KEY_HEX` environment inputs are rejected. QUIC cells do not
receive an RQ key in the default whole-object scorecard: TLS 1.3 already
authenticates every symbol datagram at the transport layer. The separate
authenticated-delta profile below keeps TLS and additionally delivers a fresh
protected key to both QUIC endpoints. The key HMAC-authenticates the sender's
session-bound manifest proof; TLS 1.3 authenticates and encrypts the bound
request/proof frames that authorize live receiver-state inspection.

This protection applies to newly produced artifacts. Older retained matrix-cell
`send.time` / `recv.time`, fleet receiver `recv_time.txt`, and sender
`atp_bench_one.*/time.txt` files may contain raw key-designated values from the
former argv-based interface. Treat them as expired and compromised, do not
reuse them, and audit both local and fleet retention before sharing historical
results. The current harness does not rewrite or delete old artifacts, and its
Bash overwrite-and-unset cleanup is best effort rather than cryptographic heap
zeroization.

The resume key includes `cell_profile`, stable `case_id`, git HEAD, SHA success,
stream count, and the exact transport/control authentication postures. Within a
profile-compatible result file, stale git or posture rows are rerun. Failed and
stale attempts remain in append-only results for diagnosis; the acceptance
report selects the current case/git identity, rejects malformed `status=ok`
rows, and requires exactly one accepted attempt per planned cell. Profile-
specific default result files and a mixed-or-missing-profile preflight prevent
unchanged-object acceptance rows from entering `score_matrix.py` medians. This
does not make old `.time` artifacts safe to share; the retention warning above
still applies.

rsync is always `-aW --inplace --no-compress` (whole-file, in-place, no `-z` on
incompressible payloads), and over ssh uses `-c aes128-gcm@openssh.com`. This is
the toughest-possible rsync, per the integrity standard.

## Authenticated unchanged-object delta acceptance (not scored)

This separate profile runs exactly the strict RQ and QUIC ATP methods against a
locally pre-seeded, byte-identical regular file. The preseed is outside the
timed interval. The measured transfer leaves delta enabled and must negotiate
`AlreadyInSync` on the live framed control connection. QUIC retains TLS 1.3 and
also receives the fresh control key through protected stdin. That key proves
sender possession over the session-bound manifest; the subsequent bound
request and proof remain authenticated by TLS.

```bash
sudo env BIN=/tmp/atp_bench/atp ATP_MATRIX_TIMEOUT=90 \
  bash scripts/atp_bench/matrix_bench.sh \
    --cell-profile authenticated-delta-unchanged-v1 \
    --execute --generate-workloads \
    --workloads 5M \
    --regimes perfect \
    --tiers auth,encrypted \
    --reps 1 \
    --fail-on-mismatch \
    --run-cell-command 'bash scripts/atp_bench/run_matrix_cell.sh'
```

The profile rejects trees, symlinks, empty files, `5G`, nocrypto, rsync, and all
other methods. It accepts only flat workloads through `500M`, which remain
within both transports' 4,096-chunk manifest bound. Each endpoint must exit zero
naturally; sender/receiver transfer IDs must match; commit, SHA, and Merkle bits
must pass; top-level and nested payload/symbol/feedback counters must all be
zero; QUIC decode counters must be zero; and the destination file's device,
inode, size, mode, owner, and mtime must remain unchanged. The isolated veth
counter must show `0 < control_wire_bytes < source_bytes`: authenticated control
and TLS still use wire bytes, while ATP payload counters remain zero.

Results go to `authenticated_delta_unchanged_results.jsonl` by default and are
validated into `authenticated_delta_unchanged_acceptance.md`; never append them
to headline results or pass them to `score_matrix.py`.

This profile proves only that an identical pre-seeded single file negotiates
`AlreadyInSync` over authenticated framed control, both endpoints close
successfully, payload counters remain zero, and the destination remains
unchanged. Recorded wall time and wire bytes are diagnostic only. It does not
prove zero total wire traffic, throughput or bandwidth improvement, rsync
superiority/inferiority, changed-chunk reuse, `DeltaChunks`, tree/rename
behavior, lossy-link resilience, or broad transport correctness.

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
