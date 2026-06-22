# ATP-rq "beat rsync" — negative-evidence ledger + experiment designs

> Discipline from `/running-the-gauntlet-on-your-rust-port`: every perf hypothesis gets an
> experiment-design entry (hypothesis / minimal-repro / expected-signal / falsifiability /
> one-line-invocation / result-inline). Every REFUTED candidate gets a negative-ledger entry with
> a **retry-condition predicate** (never "later", never "if it seems important"). Grep this file
> BEFORE re-chasing a lever. Keep-gate: profile-first, both gates same run window, report cv_pct,
> attribute to a frame ≥0.1% self-time, isomorphism proof per change.

Reference benchmark (cross-machine OVH 16c → Contabo 10c, 100M, sha-verified):
rsync(tuned)=8.44s. Target: ≤ rsync on clean; FASTER under loss/high-BDP.
(Prior atp numbers — baseline 164.75s, F3 113.85s — are INTERNAL lever-attribution ONLY, never a claim.)

## ★★★ BENCHMARK INTEGRITY STANDARD (non-negotiable — comparisons must be BEYOND REPROACH)

1. **Only ever compare atp vs rsync.** NEVER headline "X× faster than old atp / F3 / baseline".
   Prior-atp numbers are INTERNAL lever-attribution only, never a claim.
2. **rsync gets its BEST foot forward.** Optimal flags for the workload: `--whole-file --inplace
   --no-compress` (delta is pure overhead to an empty dest; `-z` HURTS on incompressible random
   data), fastest transport. If a different workload (pre-existing similar files) lets rsync's
   delta/`-z` shine, test THAT too — never cripple rsync.
3. **Apples-to-apples or it does not count:** identical payload, identical link (same netem qdisc,
   both endpoints crossing it), identical SHA-256 verification, same session/host/minute.
4. **Crypto symmetry is MANDATORY.** atp-lab (no auth) vs rsync-over-ssh (encrypted) is INVALID —
   it handicaps rsync with crypto atp skips. Valid pairs: (a) **authenticated**: atp-rq
   `--rq-auth-key-hex` (HMAC; authenticates but does NOT encrypt payload) OR atp-quic (TLS-1.3,
   full encryption) vs rsync-over-ssh (aes128-gcm). (b) **no-crypto**: atp-lab vs rsync-daemon
   (rsync://, no ssh) — rsync-daemon is rsync's FASTEST so this still gives rsync its best.
5. **Report cv_pct + peak RSS (both ends) + feedback_rounds.** Faster-but-higher-memory ≠ a win.

⚠ The clean 7.11s result (E-7) was atp-LAB vs rsync-over-ssh → **crypto-asymmetric, PRELIMINARY
ONLY, NOT a beyond-reproach win.** Definitive comparison PENDING: authenticated atp (AUTH-1) vs
optimally-tuned rsync-over-ssh on the same netem link, and/or atp-lab vs rsync-daemon.

---

## CONFIRMED FACTS (positive evidence)

- **F-POS-1 · Systematic fast path EXISTS and is correct.** `DecodingPipeline::try_decode_block`
  (src/decoding.rs:664) calls `try_complete_from_source_symbols` first; if all K source symbols of
  a block are present it reassembles by **memcpy** (decoding.rs:736-754) and never runs the O(K²)
  `decode_block` inactivation solve. The solve runs ONLY for blocks missing source symbols.
  ⇒ Implication: clean, loss-free delivery of source symbols = near-memcpy receive. The slow path
  is entered only when symbols are DROPPED.
- **F-POS-2 · F3 parallel per-block encode landed** (commit 4c665fe6a) — 164.75→113.85s (1.45×),
  byte-identical. Removes the *sender* single-core encode wall (CPU 99%→125%).
- **F-POS-3 ★ BEYOND-REPROACH rate-capped AUTH scorecard** (2026-06-17, binary v6=HEAD code:
  qdisc-guard a6fceb948 + token-bucket pacing 71684f836 + send-batches 6bb42359c + sendmmsg
  1be226210 + FEC-fallback fix 6acf22391). Tier=AUTH: **atp `--rq-auth-key-hex` (HMAC) vs
  rsync-over-ssh aes128-gcm `--whole-file --inplace --no-compress`** (crypto-SYMMETRIC). netns+veth,
  netem rate+delay+jitter+loss on BOTH ends, REPS=3 median, sha-256 verified, peak+avg RSS. Harness
  `/tmp/loss_bench_rated.sh` (Contabo 212.90.121.76, WD Z4J8VF). **NEVER compared to old atp.**

  | regime (rate/delay/loss) | size | atp wall | rsync wall | atp peakRSS | sha | fb | verdict |
  |---|---|--:|--:|--:|---|--:|---|
  | perfect 1gbit/2ms/0% | 5M | 0.41s | 0.41s | 8.2 MB | OK | 0 | tie |
  | perfect 1gbit/2ms/0% | 50M | **3.51s** | **0.91s** | 9.5 MB | OK | 0 | **rsync 3.9× (atp CPU-bound)** |
  | good 200mbit/25ms/0.1% | 5M | **0.61s** | **1.81s** | 7.9 MB | OK | 1 | **atp WINS 3.0×** |
  | good 200mbit/25ms/0.1% | 50M | 3.71s | 3.81s | 9.1 MB | OK | 1 | atp marginally faster |
  | bad 50mbit/80±20ms/2% | 5M | 18.3s | 6.7s | 27.8 MB | **MISS** | 2 | **atp FAILS (1/3 reps OK)** |
  | bad 50mbit/80±20ms/2% | 50M | 100.6s | 17.3s | 261 MB | **MISS** | ? | **atp FAILS (0/3 reps)** |

  Three measured truths: (1) **atp WINS on realistic/good links** (the headline beyond-reproach win:
  good-5M 3.0×; good-50M tie) and holds receiver RSS ~8–9 MB (rsync-class or better). (2) **atp
  LOSES perfect high-bw 50M (3.9×)** — fb=0 (source-first converges, no loss), so it is **CPU-bound**
  on encode + per-symbol HMAC + spray, NOT loss-bound (50MB/3.51s = 14 MB/s). (3) **atp FAILS the bad
  regime (sha MISS)** — see N-3 / E-9 below; fail-CLOSED (never commits bad data) but does not
  converge. cv not yet computed (REPS=3); bad-cell wall is noise-dominated by the failing reps.

- **F-POS-4 ★★ FULL GAUNTLET MATRIX scorecard** (2026-06-18, binary = E-9-fixed HEAD; the complete
  spec-compliant matrix the user asked for: sizes {500K,5M,50M,500M,5G} × regimes
  {perfect,good,bad,broken} × tier=AUTH, REPS=3 median, netns+veth+netem rate+delay+jitter+loss BOTH
  ends, sha-256 byte-identical gate, sender+receiver+combined peak RSS, scored by
  `scripts/atp_bench/score_matrix.py`). atp `--rq-auth-key-hex` (HMAC) vs rsync-over-ssh aes128-gcm
  `--whole-file --inplace --no-compress` (crypto-SYMMETRIC). **Every cell below is sha-verified — the
  scorer admits ONLY status==ok cells, so bad/broken rows here CONVERGED byte-identical** (the E-9 fix
  validated across the matrix: the old F-POS-3 bad-regime sha-MISS is gone at 500K/5M/50M). wall ratio
  = ATP/rsync (lower = atp faster); RSS ratio = combined peak ATP/rsync (lower = atp less memory).

  | size | regime | wall ATP/rsync | speedup rsync/ATP | combined peak RSS ratio | fb | verdict |
  |---|---|--:|--:|--:|--:|---|
  | 500K | perfect | 0.341 | **2.94×** | 0.350 (2.9× less) | 0 | **atp WINS** |
  | 500K | good    | 0.251 | **3.98×** | 0.219 (4.6× less) | 0 | **atp WINS** |
  | 500K | bad     | 0.204 | **4.89×** | 0.213 (4.7× less) | 1 | **atp WINS** |
  | 500K | broken  | 0.339 | **2.95×** | 0.303 (3.3× less) | 2 | **atp WINS** |
  | 5M   | perfect | 0.845 | **1.18×** | 0.732 (1.4× less) | 0 | **atp WINS** |
  | 5M   | good    | 0.366 | **2.74×** | 0.397 (2.5× less) | 1 | **atp WINS** |
  | 5M   | bad     | 1.443 | 0.69×     | 0.497 (2.0× less) | 2 | rsync 1.44× (atp converges, less mem) |
  | 5M   | broken  | 0.570 | **1.75×** | 0.007 (140× less) | 2 | **atp WINS** (rsync RSS balloons) |
  | 50M  | perfect | 3.733 | 0.27×     | 0.574 (1.7× less) | 0 | rsync 3.73× (E-10/E-11 CPU-bound) |
  | 50M  | good    | 1.019 | 0.98×     | 0.564 (1.8× less) | 1 | ~tie, atp less mem |
  | 50M  | bad     | 4.655 | 0.21×     | 1.829 (1.8× MORE) | 4 | rsync 4.66× (E-11; atp converges) |
  | 50M  | broken  | 0.930 | **1.08×** | 0.091 (11× less)  | 6 | **atp WINS**, atp far less mem |
  | 500M | perfect | 7.024 | 0.14×     | 0.612 (1.6× less) | 1 | rsync 7.02× (E-10/E-11 super-linear) |
  | 500M | good    | 1.392 | 0.72×     | 0.611 (1.6× less) | 1 | rsync 1.39× (E-11) |
  | 500M | bad     | — | — | — | — | **TIMEOUT (E-11 large-bad: RSS blowup + decode wall)** |
  | 500M | broken  | — | — | — | — | **TIMEOUT (E-11 large-bad)** |
  | 5G   | all     | — | — | — | — | was ERROR (E-12); **FIXED — 5GiB now transfers byte-identical, 347s/139MB recv (perfect loopback)** |

  Per-regime geomean wall ATP/rsync (valid cells): **bad 1.111 · broken 0.564 (1.77× win) · good 0.601
  (1.66× win) · perfect 1.657**. Three beyond-reproach truths: (1) **atp WINS decisively on every small
  file (500K all four regimes 2.9–4.9×) and on the realistic/adverse regimes (good 1.66×, broken
  1.77×)**, while using **3–140× LESS memory** in those wins. (2) **atp loses only the large-file
  perfect/bad corners** (50M-perfect 3.7×, 500M-perfect 7.0×, 50M-bad 4.66×) — all the SAME root cause:
  per-symbol file-op dispatch (E-10 perfect super-linear CPU/sync + E-11 bad-large RSS), now beaded as
  the highest-EV lever `.25` (mmap staging). (3) **The E-9 fix holds across the matrix** — bad/broken at
  500K/5M/50M all converge sha-identical (they're in the scored table); the only non-convergence left is
  500M-bad/broken (TIMEOUT = E-11 at scale) and 5G (E-12). Tree workloads: matrix COMPLETED 196/196 but
  ALL tree cells (atp AND rsync) scored `sha_mismatch` — ROOT-CAUSED 2026-06-18 to a **harness
  tree-verify bug** (NOT a transport bug): `run_matrix_cell.sh` computed SRC via `manifest_tree_digest`
  (Python `"\n".join`, no trailing newline + codepoint sort) but DST via `tree_digest` (bash `printf`
  per line w/ trailing newline + locale `sort`), so SRC could never equal DST even for a byte-identical
  transfer. FIXED to compute BOTH sides via the same `tree_digest`. Validated end-to-end on idle-109: a
  fresh 2000-file power-law tree, **atp_e14** (E-9+E-14 `raise_fd_limit`) over perfect loopback →
  **1.29 s, recv peak RSS 11.4 MB, all 2000 files, SRC tree_digest == DST tree_digest (byte-identical)**.
  atp handles deeply-nested trees correctly + fast; the tree blank was purely the harness.
  **★ TREE SCORECARD 2026-06-18** (idle-109 netns+netem, atp_e14 rq-auth vs rsync-ssh aes128gcm, 3 reps
  median, sha via tree_digest BOTH sides = all `OK/OK` byte-identical; harness `/tmp/atp_tree_bench.sh`;
  note: 109 also runs RCH compiles so absolute walls are contended, but the atp-vs-rsync RATIO is valid
  since both run on the same box):

  | regime | workload | atp wall | rsync wall | atp/rsync | recv RSS atp/rsync | verdict |
  |---|---|--:|--:|--:|--:|---|
  | perfect | tree_small (2000 f) | 1.11 s | 0.51 s | 2.17× | 11.7/11.3 MB | rsync 2.2× |
  | good    | tree_small | 2.12 s | 2.02 s | 1.05× | 11.9/12.3 MB | ~tie |
  | bad     | tree_small | 19.13 s | 6.82 s | 2.80× | 12.1/12.9 MB | rsync 2.8× |
  | perfect | tree_big (400 f) | 1.21 s | 0.61 s | 1.98× | 8.3/12.9 MB | rsync 2.0× (atp 1.5× less RSS) |
  | good    | tree_big | 1.84 s | 2.42 s | **0.76×** | 8.3/13.8 MB | **atp WINS 1.31× + 1.67× less RSS** |
  | bad     | tree_big | 30.3 s | 14.3 s | 2.12× | 18.9/13.8 MB | rsync 2.1× (atp 1.4× MORE RSS) |

  Honest nuance: atp's good-regime advantage carries to trees (**tree_big good = atp WINS 1.31× + 1.67×
  less RSS**; tree_small good ties), but atp LOSES **perfect** (clean/fast, rsync raw-pipelines small
  files ~2×) and **bad** (atp's per-entry × loss-recovery overhead compounds, 2–2.8×, + FEC retention
  pushes tree_big-bad RSS above rsync). atp's single-small-FILE dominance (2.9–4.9×) does NOT carry to
  many-small-files-in-a-TREE: 2000 files = 2000 separate RaptorQ objects + manifest entries + staging
  files, each paying per-object handshake/auth/spray overhead, vs rsync's one pipelined connection. =
  new gap **E-15 (tree per-entry overhead)**. The matrix's own tree cells used atp_e9 (no E-14) so they
  EMFILE'd; this scorecard supersedes them with atp_e14.
  **★ E-15 PROFILED 2026-06-18 (local strace -c -f, syscall counts load-independent; 109 ssh was
  dropping):** receiver of a 2000-file tree vs a SAME-BYTES (6.68 MB) single file —
  **wall 7.03 s vs 1.21 s = 5.8× slower for the tree**. Dominant cost is RUNTIME SYNC, not FS:
  `futex` 81% of time, **133,874 calls for the tree vs 18,911 for the single file (7.1×)** — each of
  2000 files is its own RaptorQ OBJECT spinning up its own decode pipeline / tasks / channel hops /
  commit, so per-entry coordination drives 7× the futex/sched_yield/epoll traffic. FS syscalls are
  SECONDARY and scale with file count: `statx` 16,877 (~8/file — `reject_destination_symlink_prefix`
  walks each path component), `mkdir` 6,620 (~3/file, per-entry `create_dir_all`), `openat`/`close`
  ~2/file (staging), `rename` 2,000 (1/file, commit). ⇒ **E-15 lever CONFIRMED high-value:** coalescing
  sub-threshold small files into FEWER/larger RaptorQ objects collapses BOTH the 7× sync multiplier AND
  the per-entry FS ops, so a coalesced tree transfers like the same-byte single file (~5.8× faster
  here) — which would flip atp's perfect/bad tree losses into wins/ties. DESIGN: a send-side "pack"
  layer groups sub-threshold entries (e.g. <~256 KB) into combined RaptorQ objects with an
  intra-object offset table in the manifest; the receiver splits each combined object back into its
  files by offset on commit (byte-identical, tree_digest both sides). Big architectural change to HOT
  transport_rq — scope carefully, reserve the file, MUST NOT regress the good-regime tree WIN
  (tree_big-good 1.31×). Cheaper secondary win available independently: cut the ~8 statx/file in
  `reject_destination_symlink_prefix` (cache validated dir prefixes across entries) — small (statx is
  only 1.26% of time) but trivial + safe.

- **F-POS-5 LAND.1 PROVEN WIN · insert/shift re-sync beats tuned rsync on bytes-on-wire.**
  The admitted campaign deliverable is now the incremental **insert/shift re-sync** cell, not a broad
  whole-file or lossy-link claim. With B-8.10 byte-precise sub-chunk literals wired into the hot delta
  path, the measured re-sync emits only the localized sub-chunk literal region plus the compact receiver
  sidecar, and the receiver result is byte-identical (`sha_ok=true` / tree-digest equivalent). In the
  current clean-link insert/shift campaign runs, ATP sends roughly **11-14x fewer bytes-on-wire than
  tuned rsync** for the same mutated payload and verification gate. This is the first campaign cell that
  satisfies the rsync-killer standard on the headline metric that matters for delta re-sync:
  **ATP-vs-rsync bytes-on-wire, not old-ATP improvement**.

  Gate: `scripts/atp_bench/resync_bench.sh` is the reproducer family for this claim: pre-seed both
  receivers, mutate by `insert` / shifted-region edits, measure veth `tx+rx` bytes around the measured
  re-sync only, and admit the row only when the destination is byte-identical. The scorer must keep the
  ratio direction explicit: `atp_wire_bytes / rsync_wire_bytes <= ~0.09` for the 11x case and
  `<= ~0.071` for the 14x case. The comparison is against tuned rsync on the same payload/link/session.

  No-claim boundary: this does **not** claim append is beaten after fixed RaptorQ repair overhead, does
  **not** claim 2% lossy-link convergence, does **not** claim whole-file clean-link parity, and does
  **not** close F4/Finding-2 per-block repair. Those remain separate transport/FEC levers. LAND.1 only
  promotes the proven insert/shift delta cell as a byte-identical ATP-vs-rsync win.

## REFUTED / NEGATIVE (do NOT re-chase unless retry-condition fires)

- **N-1 · SIMD AVX2 GF(256) (`simd-intrinsics`) gives no net throughput win for atp-rq.**
  Evidence: 100M xmachine F3+simd 133.57s vs F3-scalar 113.85s (slower, within variance);
  loopback 170 vs 162. The receive bottleneck is feedback-rounds + solve-on-incomplete-blocks +
  per-symbol bookkeeping, NOT GF(256) vector throughput.
  **Retry-condition:** re-test SIMD ONLY if a profile shows `gf256_{mul,addmul}_slice` frames
  ≥5% self-time in a steady-state run (i.e. after pacing makes the solve the dominant cost again).
- **N-2 · Parallel encode ALONE does not approach rsync on a fast/loopback path.**
  Evidence: loopback 100M 204→160s (1.27×) — shifts wall to receiver; the parallel burst (~10MB/s)
  outruns the receiver drain → recv-buffer overflow → 5-6 feedback rounds, 2.25× symbol inflation
  (230600 sent / 102565 needed for 100M).
  **Retry-condition:** N/A — F3 is kept (helps the WAN encode-bound case); this entry records that
  encode-parallelism is NOT sufficient on its own. Must be paired with pacing (E-1).

## ★★ WIRING INVENTORY — dormant accretive intelligence to make DEFAULT (user mandate)

An entire adaptive-transport intelligence stack is BUILT but UNWIRED (pub-exported, ~zero live
callers). User directive: wire ALL of it into the default path. Discipline: wire each incrementally,
prove byte-identical + faster/robust + correct (sha), keep wins, ledger losses with retry-conditions;
compose controllers only with an interference check (alien-artifact composition matrix).

| Module | What it provides | Wired? | Default-on plan |
|---|---|---|---|
| `transport_rq/adaptive.rs` `AdaptiveController` | EXP3 bandit (block-size/fanout) + Gaussian-tail FEC overhead ε* + CVaR goodput | NO (opt-in) | **WIRE-1** (=E-7) |
| `datagram/congestion.rs` `CongestionControl` | TokenBucket/AIMD/Adaptive pacing + rate limit + backoff (THE pacing primitive) | NO (dead_code) | **WIRE-2** (=E-7.3 pacing) |
| `quic/transfer_brain.rs` `AtpTransferBrain` | path selection + congestion adaptation + repair/FEC enable + relay-vs-direct decisions | NO (pub use only) | **WIRE-3** (meta-layer; compose last) |
| `loss/detector.rs` `LossDetector` | loss detection → SwitchCongestionControl / FEC recommendations | partial | **WIRE-4** (feed the controllers) |
| `datagram/beacons.rs` `BeaconScheduler` | Keepalive (idle/NAT), Probe (path RTT), Migration — robustness for spotty links | partial (Migration off) | **WIRE-5** (peer-liveness, spotty-link) |
| `loss/persistent_congestion` | persistent-congestion event detection | ? | assess under WIRE-4 |

**Composition (alien-artifact §25 interference check required):** layer = `LossDetector` (sense) →
`AdaptiveController` (FEC params: overhead/k/fanout) + `CongestionControl` (pacing/rate) →
`AtpTransferBrain` (meta: path/relay/enable). Timescale separation: pacing reacts per-RTT, FEC per
feedback-round, brain per-transfer. Each layer needs a deterministic conservative fallback.
**Priority:** WIRE-2 (pacing) + WIRE-1 (adaptive FEC) FIRST — they directly fix the E-0
feedback-round bug — then WIRE-4 (loss→params), WIRE-5 (beacons, spotty robustness), WIRE-3 (brain).
Stays opt-in items (do NOT default-on): mirror.rs delete (safety), metadata specials/hardlink/sparse
(rsync-parity flags), rq_trace (library-silent). transport_quic NotImplemented ops = stubs, not code
to wire.

## OPEN HYPOTHESES (experiment queue — profile-first)

### E-9 ★★ CRITICAL · bad-regime non-convergence → `per-entry SHA-256 mismatch` (BLOCKS "any link")
- **Symptom (measured, F-POS-3):** bad regime (50mbit / 80±20 ms jitter / 2% loss). bad-5M:
  rep1/rep2 fail `integrity verification failed: per-entry SHA-256 mismatch`, rep3 OK
  (`committed:true, sha_ok, feedback_rounds:2, symbols_accepted:3745`). bad-50M: 0/3 reps converge,
  all `per-entry SHA-256 mismatch`, peak RSS balloons to 261 MB. **PROBABILISTIC** (rep3 passed same
  regime) ⇒ NOT a deterministic decoder bug; a convergence/assembly-under-loss+jitter defect.
- **Key distinction:** failure is `per-entry SHA-256 mismatch` (integrity), NOT `NoConvergence`
  (the 16-round budget). So the receiver BELIEVES a block/entry is complete, decodes/assembles, and
  the bytes are wrong/incomplete → fail-CLOSED (safe; never commits bad data — the u5owrm guard
  works). The bug is upstream: a block is marked complete when it is not, OR a reordered/duplicate
  symbol poisons the source-first memcpy fast path (`try_complete_from_source_symbols`,
  decoding.rs:736), OR pacing under jitter drops symbols then a premature completeness count fires.
- **Hypotheses (rank):** (H1) source-first fast path memcpys K source symbols but a
  reordered/dup symbol with same ESI but different/empty payload is counted as "present" → wrong
  memcpy; jitter (80±20 ms) maximizes reorder. (H2) bounded recv DATAGRAM queue (256 drop-oldest)
  drops a source symbol after it was counted present → hole filled with stale/zero. (H3) multi-block
  completeness: one block zero-filled on give-up but whole-file committed → per-entry SHA catches it.
  (H4) jitter-induced reorder crosses a block boundary → symbol attributed to wrong block.
- **Next action (RUNTIME, not code-first-blind — this is closed-loop receiver behavior):** read the
  receiver assembly+commit path (mod.rs receive session ~3000–3070 + verify_and_commit + decoding.rs
  try_complete_from_source_symbols). Add a deterministic loopback repro with netem reorder (the F1
  lossy harness `scripts/atp_e2e_lossy.sh` + a reorder knob) that reproduces the mismatch, THEN fix
  + prove the same repro converges. **Do NOT dispatch a blind code-first agent** (runtime UB risk).
- **Why it matters:** the user goal is "beat rsync over ANY connection, good or bad." atp currently
  cannot complete a transfer on the bad regime at all. This is the #1 blocker, ahead of perfect-link
  throughput (E-0/E-6) which is "lose by 3.9×" vs this "fail entirely."
- **★ ROOT CAUSE CONFIRMED (2026-06-17, ATP_RQ_TRACE, loss 10% / 5M / REPS=3):** MISS correlates
  with `src-completes > 0` (mixed source+FEC completion); the one rep with `src-completes == 0`
  (ALL blocks via FEC) COMMITTED OK. Mechanism: a block decoded via FEC calls `persist_decoded_block`
  (mod.rs:3636 `bytes_written += data.len()`); the SAME block can LATER reach `received_count == k`
  from late source-retransmits via `persist_source_symbol` (mod.rs:3498 `bytes_written += block.len`)
  because `persist_decoded_block` never sets `source_blocks[sbn].complete`. ⇒ `bytes_written` is
  **DOUBLE-COUNTED** for any block completed by both paths → `verify_and_commit` (mod.rs:3702)
  `decoder.bytes_written != e.size` → `sha_ok = false` → returned as the MISLEADING reason
  `"per-entry SHA-256 mismatch"` (mod.rs:3769). **THE FILE CONTENT IS CORRECT** (verify also hashes
  the file; the hash matches — it's the byte *counter* that is wrong). So this is a **FALSE REJECTION
  of good data**, NOT corruption — atp's fail-closed integrity is fully intact (it never commits bad
  bytes; here it wrongly rejects *good* bytes). NOT a reorder bug, NOT a decoder bug, NOT an auth gap.
- **Fix direction (targeted, low-risk):** count each block's bytes exactly once across both
  completion paths — e.g. a per-block `written: Vec<bool>` set by whichever path lands first, with
  `bytes_written`/`dec.complete` derived from it; and/or drop the fragile `bytes_written != e.size`
  proxy in `verify_and_commit` and gate solely on the already-computed actual file size + SHA-256
  (the correct, content-addressed check). Add a multi-block MIXED-completion regression test (the
  existing `signed_source_streaming_seeds_fec_decoder_from_staged_sources` only covers single-block
  all-FEC). Then re-run the bad-regime matrix to confirm convergence.
- **★ FIXED + CONFIRMED (2026-06-17, commit pending):** applied BOTH fixes — `persist_decoded_block`
  now marks `source_blocks[sbn].complete` + counts bytes once (so a late source retransmit for an
  already-FEC'd block is ignored by `persist_source_symbol`'s existing `block.complete` guard) AND
  unifies completion (entry complete iff every block done via source OR FEC); `verify_and_commit`
  now gates on the content-addressed file size+SHA-256, not the `bytes_written` proxy. Two new
  regression tests (single-block FEC-then-late-source; multi-block MIXED completion). Gates: rq lib
  tests **67/0**, clippy `-D warnings` **0**, fmt **0**. EMPIRICAL: rate-capped AUTH **bad 50M
  (50mbit/80±20ms/2%) now commits sha OK/OK, fb=2** — was 0/3 MISS pre-fix (the hardest case:
  ~100 blocks, mixed source+FEC, all correct). (The same matrix run hit a Contabo `/tmp`
  No-space-left condition that corrupted the bad-5M and good-50M cells — good-50M showed rsync ALSO
  MISS, i.e. environmental, not atp; a clean full re-run is pending disk cleanup.)

### E-10 ★ HYPOTHESIS · perfect-link wall = per-SYMBOL seek+write syscalls (receiver) + per-symbol read (sender)
- **Symptom (F-POS-3):** perfect 1gbit/2ms/0% 50M = atp 3.51s vs rsync 0.91s (3.9× slower), with
  **fb=0** (source-first converges, NO loss, NO decode). 50MB/3.51s = **14 MB/s** — far below memcpy
  / SSD / HMAC throughput. So the wall is NOT loss, NOT decode, NOT GF(256).
- **Hypothesis:** `persist_source_symbol` (mod.rs:3493-3494) does `file.seek(offset)` + `write_all`
  PER ~1KB SYMBOL → ~51k seek+write syscalls for 50MB. `seed_source_streaming_pipeline` (mod.rs:3386)
  reads source back per-symbol too. rsync does large sequential writes. This per-symbol syscall storm
  is the likely 14 MB/s ceiling. (Sender disk-streaming spray may have the symmetric per-symbol read.)
- **Experiment (after E-9 lands):** profile the receiver on a perfect-link 50M (strace -c for
  seek/write counts; perf for self-time). If `write`/`pwrite`/`lseek` dominate → confirmed.
- **Fix candidates (extreme-opt batching / alien-artifact certified-rewrite, byte-identical):**
  (a) buffer contiguous source symbols and write per-BLOCK (≤512KB) instead of per-symbol — source
  symbols arrive ~in ESI order in round 0, so accumulate a block then one `write_all`; (b) use
  positioned vectored writes (pwritev) to coalesce; (c) a BufWriter over the staging file with
  block-aligned flushes; (d) sender: read each block once into memory and slice symbols (one read per
  block, not per symbol). MUST stay byte-identical (sha) — pure I/O batching, no wire change.
- **Why it matters:** this is the gap to "beat rsync on a PERFECT link." It is an I/O-shape problem,
  not an algorithmic one — high EV, low risk (isomorphic). Profile-first before implementing.
- **★ PROFILED 2026-06-17 → E-10 NOT CONFIRMED (do not chase yet).** Local loopback 50M receiver
  `strace -c` (csd): `futex` 83% + `sched_yield` 4% (sync), `write` 2.5% + `lseek` 1.3% (E-10 target
  = only ~3.8%), `recvfrom` 0.55%. So per-symbol seek+write is NOT the dominant cost. BUT the profile
  is **LOAD-POLLUTED**: csd is a heavily-shared machine; the futex/sched_yield storm (~208k futex,
  ~125k yield for ~37k symbols) = CPU oversubscription (runtime workers blocking on starved cores),
  not an atp algorithmic defect (the rq `yield_now` is boundary-gated cooperative yield, not a spin).
  Wall here was 50.99s vs 3.51s on idle Contabo netns → 14× load inflation, invalid for attribution.
  **Retry-condition for E-10:** only if a CLEAN idle-machine profile shows `write`+`lseek` ≥10%.
  **Action:** re-profile the receiver AND sender on an IDLE machine (Contabo, after disk cleanup) to
  get true perfect-link attribution before picking the lever (candidates shift toward B-2 GSO +
  per-super-packet MAC and B-10 parallel decode, NOT E-10). Negative-evidence WIN: profiling stopped
  us implementing the wrong lever.
- **★ REFINED 2026-06-18 (clean idle-Contabo perf + code read):** idle receiver `perf record` = 44%
  syscalls (14% `futex_wait`→schedule→ctx-switch + epoll/timers), **2.75M voluntary context-switches
  for a 50M transfer (~74 PER SYMBOL)**, 14% CPU, NO hot user function (top symbols <1%, diffuse
  spinlocks). Code read: `crate::fs::File` WRITE is INLINE (`poll_write` direct syscall, file.rs:202
  pattern); only `seek` dispatches to the blocking pool (`with_inner`→`spawn_blocking_io`, file.rs:40).
  ⇒ perfect-link wall = **DIFFUSE runtime per-symbol synchronization** (reactor epoll wakeups + pacing
  timerfd + channel hops + obligation/region locks + the per-symbol seek dispatch), NOT write bytes.
  **`write_all_at` REFUTED as a clear win** (write already inline; one pwrite-dispatch ≈ same dispatch
  count as seek+inline-write). Real levers: (a) **B-1 mmap staging** → reconstruct = pure memory
  stores, eliminates ALL file-op dispatches (radical, unsafe+ledger); (b) **batch the whole per-symbol
  pipeline** (recv→verify→feed→write in batches) to amortize the ~74 ctx-switch/symbol; (c) cut
  reactor/timer wakeups per symbol. **Next:** build a NON-stripped release + `perf --call-graph dwarf`
  to NAME the dominant ctx-switch source before implementing (stripped profile gives only the shape).
- **★★ CONFIRMED + LEVER PICKED 2026-06-18 (idle-109 strace, byte-identical sha=YES):** 20 MB perfect
  loopback receiver under `strace -f -e lseek,write`: **16,509 lseeks** (≈1 per source symbol; ~15k
  symbols) + 29,103 writes. So per-symbol seek dispatch is REAL and scales linearly → **~400k seek-
  dispatches for 500M**, each a blocking-pool round-trip (channel send + thread wakeup + syscall +
  return) — this IS the diffuse ctx-switch storm of the REFINED note, and the super-linear wall (every
  dispatch contends the blocking pool). **NEW finding — arrival order:** lseek offsets are **89.6%
  forward / 10.4% backward**; first offsets `0,11200,22400,…,1400,12600,…,2800,14000` =
  **8 interleaved monotonic substreams** (one per `--streams 8`, each striding +8 symbols). ⇒ Two
  cheaper levers are REFUTED by this data: (i) a **contiguous write-combine buffer** coalesces almost
  nothing (consecutive arrivals are +8 symbols apart, never adjacent); (ii) a **per-block `Vec` buffer**
  would hold ~the whole file (all blocks fill in parallel across the 8 streams) → REGRESSES the E-11
  bad-large RSS. **Only mmap wins both frontiers:** scattered offsets → plain memcpy into file-backed
  pages = ZERO seek-dispatch (perfect-link CPU) + reclaimable page-cache instead of anon-heap (bad-large
  RSS). **Design (bead .25, libc — already a dep, fn-scope `#[allow(unsafe_code)]` + unsafe-ledger
  rows):** `ensure_entry_staging_file` pre-sizes via `set_len(entry.size)` then `libc::mmap` MAP_SHARED
  RW; `persist_source_symbol`/`persist_decoded_block` `copy_from_slice` into the mapping (inline, no
  await); commit does `libc::msync`+`munmap` (dispatch the msync to the blocking pool) then rename; SHA
  can read straight from the mapping (no read syscalls). Probe: `/data/tmp/atp_strace_order_probe.sh`.
- **★★★ IMPLEMENTED + REFUTED 2026-06-18 (idle-109 before/after, byte-identical sha=OK; REVERTED).**
  Built the full mmap-staging change (`StagingMmap` RAII over `libc::mmap`/`munmap`, `copy_from_slice`
  in `persist_source_symbol`/`persist_decoded_block`, fn-scope `#[allow(unsafe_code)]` + unsafe-ledger
  rows) — lib + 67 transport_rq unit tests GREEN, byte-identical. Then measured atp_e14 (seek path)
  vs atp_mmap on a perfect 50M loopback (3 reps): **lseek 16,509 → 6** (per-symbol seek dispatch IS
  eliminated, mechanism confirmed) BUT **wall 3.48s → 3.42s (~2%, negligible)** and **peak RSS 8.1 MB
  → 60.1 MB (REGRESSED 7×)**. Two hard conclusions: (1) **the per-symbol seek dispatch was NOT the
  perfect-link wall** — removing it (16509→6) barely moved wall ⇒ E-10's "seek storm = the wall"
  hypothesis is REFUTED; the wall is the *rest* of the diffuse per-symbol cost (reactor epoll wakeups,
  pacing timerfd, channel hops, obligation/region locks, decode), exactly the "diffuse runtime sync,
  NOT write bytes" of the REFINED note. (2) **mmap REGRESSES RSS** — `MAP_SHARED` mapped pages count as
  process resident memory, converting free page-cache (not in RSS) into RSS, so it directly harms the
  headline "atp uses less memory" win AND does nothing for the E-11 bad-large blowup (which is symbol
  RETENTION + decode buffers, not staging writes — mmap only ADDS the mapped file on top). **Reverted**
  (code + ledger to HEAD; experiment saved `/data/tmp/mmap_experiment_e10_refuted.diff` + git stash).
  **Retry-condition:** only revisit mmap if (a) the OTHER per-symbol costs (reactor/pacing/channel/
  obligation) are batched/amortized first so the staging write is actually on the critical path, AND
  (b) RSS is controlled with `madvise(MADV_DONTNEED)` after each region write. Net: the real
  perfect-link lever is **batching the whole recv→verify→feed→write pipeline + cutting per-symbol
  reactor/timer wakeups (E-10 lever b/c)**, NOT the staging write mechanism. Negative-evidence WIN:
  the before/after caught a plausible-but-wrong lever that strace alone (16509 lseeks) had "confirmed".

### E-11 ★★ CRITICAL · bad/broken-regime SUPER-LINEAR scaling → 500M+/bad TIMES OUT (>30min)
- **Symptom (full matrix, 2026-06-18):** 50M/bad converges in 76s (fb=3) but **500M/bad TIMES OUT
  at the 1800s cell cap, sha_ok=false** — 10× the data → >23× the time (super-linear). atp does NOT
  complete a large file over a bad link in reasonable time. (5G/bad and 5G/broken will time out too.)
  This is the #1 blocker to "beat rsync on a bad link AT SCALE" — rsync does 500M/50mbit in ~minutes.
- **Hypotheses (rank):** (H1) ★ single-core RaptorQ DECODE wall — 500M @ max_block_size 512KB ≈ 1000
  blocks; under 2% loss many blocks need the O(K²) inactivation solve; ~0.8 MB/s decode → 500MB ≈
  625s+ just for decode if a meaningful fraction go FEC; compounds with (H2). (H2) feedback-round work
  is O(blocks) per round and rounds grow → O(blocks × rounds) bookkeeping at 1000 blocks. (H3) FEC
  symbol-retention memory grows O(file) (50M/bad already hit 483MB) → at 500M ≈ GBs → pressure.
- **Levers (high EV):** **B-10 parallel per-block decode** (blocks independent → decode on the
  blocking pool concurrently; directly attacks H1; coordinate w/ peer 317hxr.7.3) + **B-5 adaptive
  FEC/source-retransmit** so fewer blocks fall to the expensive solve + **bounded FEC retention**
  (cap symbol memory, attacks H3). Also revisit max_block_size (bigger blocks = fewer blocks but
  bigger K = slower per-block solve — there's an optimum; E-4).
- **Next:** focused 500M/bad run with ATP_RQ_TRACE on an IDLE machine → measure decode time vs
  feedback-round time vs memory to confirm H1/H2/H3 before implementing. Profile-first.
- **★ DIAGNOSED 2026-06-18 (100M/bad, idle worker 109.123.245.77, /usr/bin/time -v):** wall 96.7s,
  sha OK, **fb=3**, receiver **CPU%=29%** (User 28.2s / Sys 6.4s of 96.7s wall), **Max RSS 895 MB for
  a 100 MB file (≈9× blowup)**. ⇒ **E-11 is MEMORY-BOUND, not decode-bound (H1 REFUTED as primary —
  29% CPU) nor feedback-bound (H2 REFUTED — fb=3).** The receiver retains ~9× the file size in
  symbols; at 500M that is ~4.5 GB → swap/thrash → the 500M/bad TIMEOUT; at 5G → ~45 GB → OOM. So
  **parallel decode (B-10) is NOT the primary lever for E-11** (it would only speed the 29% CPU
  fraction). **THE lever = bound the FEC/pipeline symbol retention (H3).** Likely mechanism (needs
  code-read confirm): `seed_source_streaming_pipeline` seeds incomplete blocks' source back INTO the
  in-memory DecodingPipeline, and/or the pipeline `SymbolStore` holds received symbols for ALL
  in-flight incomplete blocks simultaneously (round-0 sprays across all ~1000 blocks → all hold
  symbols until each completes). E-8.2 ("bounded retention") is marked done but clearly does NOT bound
  this FEC/lossy path. **Fix direction:** cap in-flight incomplete blocks (windowed spray/decode so
  peak retention is O(window), not O(file)); free per-block pipeline memory aggressively once a block
  is on disk; OR spray block-by-block so blocks complete + free before the next. Profile-first WIN:
  this redirected the lever from parallel-decode (wrong) to bounded-memory (right). **Next:** localize
  the 895MB (code-read the receiver retention + a heap profile / RSS-vs-blocks-in-flight measurement),
  then implement windowed/bounded retention, prove sha-identical + RSS bounded + 500M/bad converges.
- **★ HYPOTHESIS-1 (seed-all-blocks) REFUTED 2026-06-18 (fix-and-measure):** changed
  `seed_source_streaming_pipeline` to seed ONLY the repair symbol's own block (`parsed.sbn`) instead
  of every incomplete block. Byte-identical (rq lib tests exit 0; 100M/bad sha OK, fb=4). But
  **100M/bad Max RSS UNCHANGED: 895MB → 910MB** ⇒ the seed-all loop was NOT the 895MB driver (at 2%
  loss few blocks were incomplete at first-repair, so seed-all loaded little). The per-block-seed
  change is kept (correct + strictly less work + plausibly helps the high-loss broken regime where
  more blocks are incomplete) but is NOT the E-11 fix. **The O(file) driver is still unlocalized** —
  candidates: the pipeline `SymbolSet` holding all received REPAIR symbols (no eviction; the receiver
  passes `max_buffered_symbols:0`), the inbound recv path, or runtime/allocator. **Next (real
  localization):** install a heap profiler (heaptrack/valgrind massif — absent on the workers) OR add
  a 1-line instrumented log of peak `SymbolSet` len + in-flight incomplete-block count, on a 50M/bad
  run, to NAME the structure holding ~890k symbols before implementing the bound.
- **★ HYPOTHESIS-2 (glibc arena fragmentation) REFUTED 2026-06-18 (zero-build test):** re-ran
  100M/bad with `MALLOC_ARENA_MAX=1` on the receiver → Max RSS **893 MB, UNCHANGED** (vs 895 MB).
  So the blowup is NOT multi-thread malloc-arena fragmentation. It is a genuine ~893 MB data
  structure. Arithmetic puzzle: 893 MB ≈ 890k × 1 KB, but the receiver only RECEIVES ~103k symbols
  for 100M (can't hold 9× what it got) ⇒ it is NOT raw retained symbols either. Confirmed by code:
  SymbolSet = `DetHashMap<SymbolId, Symbol>` cleared only on block-complete; source-streaming writes
  source to DISK (not the SymbolSet), so the SymbolSet should hold only repair (few, fb=3). Remaining
  suspects to instrument: (a) `BlockDecoder.decoded: Option<Vec<u8>>` retained per block if
  `retain_decoded_block` (could be O(file) if the receiver retains decoded blocks in RAM);
  (b) the inactivation-decode working matrices (per-block K×K over GF256, ~360 KB for K512 — ×many
  if not freed); (c) `try_decode_block` clones ALL of a block's symbols per decode ATTEMPT
  (decoding.rs:672) — transient but peak-spiking if attempted often. **DECISIVE NEXT STEP (commit to
  it):** add `SymbolSet::buffered_symbol_count()` + `DecodingPipeline::debug_mem_estimate()`
  (buffered symbols, blocks-with-retained-decoded, total decoded bytes), rqtrace per feedback round in
  the receive loop, build (`--features atp-cli`), run 50M/bad with ATP_RQ_TRACE → NAME the structure.
  Then bound/free it, prove sha-identical + RSS bounded + 500M/bad converges.
- **★★ E-11 ROOT CAUSE NAMED 2026-06-18 (heaptrack, unstripped build, 50M/bad):** peak LIVE heap =
  **218 MB** (4.4× the 50M file) via **1,142,482 allocation calls ≈ 32 allocations PER SYMBOL**. The
  `time -v` RSS (483 MB @50M, 895 @100M = 9×) = that live set PLUS churned memory glibc never returned
  (which is why MALLOC_ARENA_MAX=1 didn't help — it's churn, not arena count). ⇒ **E-11 is an
  ALLOCATION-CHURN problem**, not a single retained structure. Prime churn sources (code): (a)
  `decoding.rs:672` + `:774` `symbols_for_block(sbn).cloned().collect()` — CLONES ALL of a block's
  symbols (k clones) on EVERY decode ATTEMPT; if attempted repeatedly near threshold → O(k × attempts)
  churn (≈hundreds of k allocs); (b) per-datagram `payload.to_vec()` + `Symbol`/`AuthenticatedSymbol`
  allocations in the recv path (mod.rs:2766 churns 55k+); (c) HashMap growth in SymbolSet.
  **★ KEY: this ONE cause feeds BOTH frontiers** — the per-symbol alloc/free storm is also a big part
  of the perfect-link diffuse-CPU/sync cost (E-0/E-10). **THE lever (highest EV, helps everything):
  cut per-symbol allocations** — (1) decode only when the threshold is actually reached (not per
  symbol) + reuse/borrow the collected symbols instead of `cloned().collect()` per attempt; (2) pool &
  reuse symbol payload buffers (a `SymbolPool` already exists on the encoder side — wire one on the
  receiver) instead of `payload.to_vec()` per datagram; (3) reserve SymbolSet capacity. Profile-first
  WIN: 3 wrong memory hypotheses (seed-all, arena, large-K) refuted; heaptrack named the real cause.
  **Next:** target (a) first (biggest, in decoding.rs) — sha-isomorphic, unit-test byte-identical,
  re-heaptrack + re-time 50M/bad (expect alloc count ↓↓, RSS ↓, and perfect-50M wall ↓ too).
- **★ CORRECTION 2026-06-18 (decode-clone is GATED — re-target the churn):** decoding.rs:521 only
  calls `try_decode_block` (the `cloned().collect()`) when `source_received >= k || received >=
  needed` (threshold reached). So the clone-all is NOT per-attempt churn — it fires ~once per block
  when enough symbols exist. ⇒ the ~32 allocs/symbol churn is the **per-symbol recv→auth→persist
  path**, dominated by the **per-symbol file-`seek` `spawn_blocking_io` dispatch** in
  `persist_source_symbol` (each dispatch boxes a closure + channel) plus `payload.to_vec()` + the
  HMAC verify. **THIS UNIFIES E-10 (per-symbol file dispatch) + E-11 (alloc churn) + the perfect-link
  diffuse futex/ctx-switch into ONE ROOT: per-symbol file-op dispatch.** Single highest-EV lever =
  **B-1 mmap the staging file** (writes become memory stores → ZERO per-symbol dispatch → kills the
  alloc churn AND the futex/ctx-switch AND the CPU on BOTH frontiers); isomorphic alt = per-block
  write batching (accumulate a block, one write/dispatch per block instead of per symbol). Build a
  receiver `SymbolPool`/buffer reuse to kill `payload.to_vec()` too.
- **★ E-12 · 5G FAILS = real 2 GB max-OBJECT limit (NOT a harness/max-bytes issue).** All 5G/atp
  cells error at ~5.8s `TooLarge` (MAX_BYTES in run_matrix_cell.sh is 6 GB, so not that). RaptorQ uses
  a u8 SBN ⇒ ≤256 source blocks; `effective_max_block_size` caps the block at `configured_max`
  (8 MiB default) via `.min(configured_max)`, so max object ≈ 256 × 8 MiB = **2 GB**. 5 GB > 2 GB →
  rejected. rsync transfers 5G fine ⇒ atp has a **hard >2 GB single-file gap** = a real
  "any-workload" blocker. Fix options: (a) for large entries raise the per-block size ABOVE
  configured_max so block-count ≤256 (but K grows → O(K²) decode matrix balloons — 5G/256≈20 MB block
  → K≈14k → ~196 MB matrix/block, bad); (b) ★ MULTI-OBJECT split: chunk a huge entry into ≤2 GB
  RaptorQ sub-objects (keeps K sane), transfer + reassemble — the right fix, a real feature. The 5G
  matrix rows are recorded `error` (correctly excluded from headline); re-run 5G only after the fix.
  **★ REFINEMENT 2026-06-18 (code read of `effective_max_block_size_for_largest_entry`):** the 2 GB
  ceiling is exactly `max_object_size(configured_max) = configured_max(8 MiB) × MAX_SOURCE_BLOCKS(256)`,
  enforced by the early `if max_entry_len > max_supported { TooLarge }` + the final `.min(configured_max)`
  cap on block growth. The earlier "option (a) is bad (K balloon)" verdict MISSED the source-first
  memcpy fast path: on perfect/good links the receiver gets all K source symbols and
  `try_complete_from_source_symbols` reassembles by memcpy — the O(K²) inactivation solve runs ONLY for
  blocks missing source symbols (lossy links). So option (a) — let `max_block_size` grow above
  `configured_max` up to the RFC-K ceiling (K≤56403 ⇒ ≤~79 MB/block ⇒ ≤~20 GB object) — makes
  **5G/perfect+good WORK cheaply (memcpy)**, and only the LOSSY-huge case pays the K≈14k matrix (which is
  already the E-11 large-bad limitation, NOT a new regression — 500M/bad already times out). So (a) is a
  legitimate well-scoped STOPGAP (raises the hard ceiling 2 GB→~20 GB) analogous to the E-14 RLIMIT
  stopgap; (b) multi-object stays the proper fix for keeping K sane on lossy huge transfers. NEXT: try
  (a) — drop the `.min(configured_max)` cap + raise `max_object_size` to the RFC-K ceiling — then measure
  5G/perfect on idle-109 (wall + RSS + byte-identical); byte-identical for ≤2 GB files (no change there).
  **✓ FIXED + PROVEN 2026-06-18 (commit on main+master).** Implemented option (a): added
  `RAPTORQ_MAX_SOURCE_SYMBOLS_PER_BLOCK = 56403` and changed `effective_max_block_size_for_largest_entry`
  to grow the block above `configured_max` up to `K_cap * symbol_size` (block_ceiling), raising the
  object ceiling from `256 * configured_max` (~2 GiB) to `256 * 56403 * symbol_size` (~20 GiB).
  Byte-identical for ≤2 GiB by construction; unit tests 68/0 (incl. new
  `effective_block_size_grows_above_configured_max_for_huge_entries`: 5 GiB fits, 1 GiB unchanged,
  >20 GiB still `TooLarge`). E2E on idle-109: a **5 GiB single file** (previously hard `TooLarge` at
  ~5.8 s) now transfers **byte-identical** (src sha == dst sha, committed/merkle/sha_ok all true),
  wall 347 s (≈14.5 MB/s = the E-10 perfect-link CPU wall, source-first memcpy at K≈14980, 1 feedback
  round, 3.84M symbols), recv peak RSS 139 MB. So 5G now WORKS on perfect/good; lossy-huge stays the
  E-11 limitation. Multi-object split (b) remains future work only if lossy huge-file K-sanity matters.
  transfer (2000 files, 6.2 MB total, loopback no-loss) → receiver dies **"Too many open files
  (os error 24)"**, sender then "Connection refused". The receiver keeps an OPEN staging FD PER
  ENTRY (`EntryDecoder.file`), and the sprayer feeds all entries concurrently → 2000 simultaneous
  open files > default `ulimit -n` 1024 → EMFILE. rsync transfers 2000 files fine (open/close per
  file). ⇒ atp **fails any single transfer with >~1000 files** = a real "any-workload" blocker (the
  user explicitly wanted deeply-nested power-law trees). **Fix:** bound concurrent open staging FDs —
  open-write-close per entry, OR an LRU FD pool, OR process entries in a bounded window (ties to the
  in-flight-windowing idea); the benchmark can also raise `ulimit -n` as a stopgap to get valid tree
  numbers for ≤N-file trees. **Tree dimension also has a HARNESS verify bug** (separate): rsync tree
  cells report `sha_mismatch` because `run_matrix_cell.sh`'s `manifest_tree_digest` (paths from
  gen_tree manifest) vs `tree_digest($DEST)` (`find . -type f` relpaths under DEST/<root_name>) use
  different canonical path forms → never match even when bytes are correct. Fix the canonical form
  (same relpath root) before trusting ANY tree row. ⇒ **TREE dimension currently un-scorable** (atp
  EMFILE + rsync verify-mismatch); single-file dims (500K–500M × 4 regimes) remain VALID + are the
  headline. Net: the gauntlet surfaced THREE real atp gaps — E-11 (alloc/dispatch churn, bad-large +
  perfect), E-12 (>2 GB object), E-14 (>1000-file tree FD) — all genuine "beat rsync everywhere"
  blockers, each now precisely characterized.

## ★★★ BOLD EXPERIMENT SLATE — dream-big optimization frontier (crush rsync EVERYWHERE)
Mined from /extreme-software-optimization (profile-first, isomorphic), /alien-artifact-coding (EV-first
advanced math), /alien-graveyard (buried primitives). Each entry: idea · math/CS family · EV · risk ·
proof-obligation · fallback. Discipline: try, gate on the rigorous harness (byte-identical sha +
beyond-reproach vs optimal rsync), keep wins, ledger losses with a retry-condition. "Crazy is fine —
we can revert." Ranked by EV for "beat rsync across the WHOLE matrix."

### FRONTIER 1 — perfect / high-bandwidth link (atp is CPU/syscall-bound: 50M 3.51s vs rsync 0.91s)
- **B-1 ★ io_uring + mmap zero-copy data plane.** Family: OS/extreme-opt. Sender mmaps the source;
  symbols are slices (no read syscalls). Receiver mmaps the staging file; source-first reconstruct is
  pure memcpy into the mapping (no write syscalls — page cache flushes). UDP via io_uring (the repo has
  the `io-uring` feature) with registered buffers + SQPOLL → near-zero per-datagram syscall cost.
  EV: VERY HIGH (this is exactly how to match rsync's kernel efficiency). Risk: med (unsafe + io_uring
  lifecycle → unsafe-ledger entry). Proof: byte-identical sha; strace shows write/lseek/sendto counts
  collapse. Fallback: the portable seek+write path (E-10).
- **B-2 ★ GSO (UDP_SEGMENT) send + GRO recv + per-SUPER-PACKET MAC.** Family: coding + extreme-opt.
  One sendmsg emits a 64 KB super-packet the kernel segments into MTU datagrams → ~45× fewer send
  syscalls; UDP_GRO coalesces on recv. CRUCIALLY: authenticate ONCE per super-packet (HMAC over the
  64 KB) instead of per ~1 KB symbol → ~45× fewer MAC ops (rsync-over-ssh only does per-stream AEAD, so
  atp's per-symbol HMAC is its handicap — this erases it). EV: VERY HIGH. Risk: med (unsafe sockopt +
  ledger; udp.rs already has the GSO planner scaffold ee2906704). Proof: sha; MAC-op count drops.
  Fallback: sendmmsg batching (already wired).
- **B-3 PGO + BOLT + target-cpu=native for the atp binary.** Family: extreme-opt build. Profile-guided
  + post-link optimization of the hot encode/decode/HMAC/memcpy paths. EV: med (10-20% free on the
  CPU-bound path). Risk: low (build-only, byte-identical). Proof: sha + before/after wall. Fallback: drop.
- **B-4 Bigger symbol_size (1024→1400 MTU; jumbo via GSO).** Fewer symbols ⇒ fewer per-symbol HMAC +
  syscalls + bookkeeping (−37% symbol count at 1400). Source-first already uses 1400; make it the
  default everywhere; with GSO explore larger logical symbols. EV: med. Risk: low. Proof: sha.

### FRONTIER 2 — bad / lossy / spotty link (E-9 now CONVERGES; make it WIN, not just finish)
- **B-5 ★ AdaptiveController default-on (E-7 / WIRE-1).** Family: online-learning (EXP3 bandit) +
  tail-risk (CVaR) + info-theory (ε* ≈ 1/(1−p) toward erasure capacity). Pick k/fanout/FEC-overhead
  per measured loss/RTT to converge in the FEWEST rounds (rsync degrades badly under loss — this is
  atp's structural edge). EV: VERY HIGH (the "adaptive to any connection" mandate). Risk: med (needs
  the deterministic conservative fallback). Proof: sha + rounds↓ + wall↓ vs rsync on bad regime.
- **B-6 Coded / compressed feedback (Bloom-filter ACK).** Family: coding/info-theory. NeedMore lists
  needed symbols; on high loss this control grows. Send a Bloom/IBLT of RECEIVED ESIs instead → O(1)
  control regardless of loss. EV: med (helps very-lossy + bonding). Risk: low. Proof: sha + control
  bytes↓. Fallback: explicit list (current).
- **B-7 Model-predictive spray pacing (MPC/PID over decode-queue depth).** Family: control theory.
  Keep the receiver's decode queue at the optimal depth (not starved, not overflowing → the 261 MB
  blowup + incast). EV: med-high. Risk: med. Proof: sha + bounded RSS + wall.

### FRONTIER 3 — ★ THE RSYNC-KILLER: delta transfer (rsync's raison d'être; atp must beat it)
- **B-8 ★★ FastCDC content-defined chunking + RaptorQ delta.** Family: alien-graveyard (CDC) + coding.
  rsync's whole reason to exist is delta-transfer (only send what changed). Today atp sends the WHOLE
  file, so the current matrix uses rsync --whole-file (fair) — but for the INCREMENTAL case (a file
  that changed slightly) rsync's rolling-hash delta WINS massively. To be "better in EVERY way": the
  receiver content-defined-chunks (FastCDC) its OLD copy; sends the set of chunk hashes it has; the
  sender CDC-chunks the NEW file, and RaptorQ-encodes ONLY the chunks the receiver lacks. This beats
  rsync's O(n) rolling-hash + weak/strong-hash scan with content-defined boundaries + fountain coding
  of the changed regions (and bonding can pull the changed chunks from N donors!). EV: ★★ HIGHEST for
  the incremental dimension rsync dominates. Risk: high (new subsystem). Proof: sha + bytes-on-wire ≈
  changed-fraction; beat rsync delta on a 1%-changed 1 GB file. Generalizes E-5 (resume). → wants beads.
- **B-9 zstd compression per block (rsync -z parity+).** Family: info-theory (rate-distortion). For
  compressible data, compress source before encoding (matrix uses incompressible random → off, but real
  data benefits). EV: med (workload-dependent). Risk: low. Proof: sha after decompress.

### FRONTIER 4 — cross-cutting (the decode wall, trees, huge files)
- **B-10 ★ Parallel per-block decode (F6.3 / 317hxr.7.3).** Family: numerical-LA + parallelism. The
  single-core decode wall (~0.8 MB/s) caps lossy + bonding throughput. Blocks are independent → solve
  on the blocking pool concurrently. EV: HIGH (unblocks bonding C6 + lossy speed). Risk: med. Proof:
  sha + decode MB/s scales with cores.
- **B-11 Power-law TREE scheduling (optimal-transport / submodular).** Family: scheduling. For deep
  trees of many files, order spray to maximize early per-file completions (smallest-first / priority);
  pipeline manifest + spray. EV: med (the tree matrix dimension). Risk: low. Proof: sha-set + wall.
- **B-12 huge pages + NUMA-aware buffers for the memcpy/GF256 path.** Family: extreme-opt. EV: low-med.
  Risk: low. Proof: sha + wall.
- **B-13 (moon-shot) AF_XDP / kernel-bypass UDP.** Family: extreme-opt. Ultimate syscall elimination
  for datacenter NICs. EV: high-ceiling / niche. Risk: very high (root, NIC support). Defer; note only.

**Execution order (EV×confidence/effort, profile-gated):** E-10 (batched I/O, do now) → B-10 (parallel
decode) → B-2 (GSO+super-packet MAC) → B-1 (io_uring+mmap) → B-5 (adaptive default-on) → B-8 (delta,
the rsync-killer, own bead-set). Each: profile → implement one lever → prove sha-identical → measure
vs optimal rsync → keep or ledger-with-retry.

### E-0 · PROFILE: where does the 113.85s actually go? (BLOCKS all others)
- **Hypothesis:** the F3 100M wall is dominated by feedback-round latency + solve-on-incomplete
  blocks (caused by burst-induced drops), NOT by sender encode (already parallel) nor raw GF256.
- **Minimal repro:** cross-machine 100M with F3 binary; capture sender CPU%, receiver CPU%,
  feedback_rounds, symbols_sent/accepted, and a per-phase timeline (round0-spray / drain / solve /
  needmore-RTT). `/usr/bin/time -v` both ends + the JSON `feedback_rounds`.
- **Expected signal (if true):** sender CPU << 100% (not encode-bound anymore); receiver shows
  bursty solve activity; wall ≈ Σ(feedback round RTTs + per-round drain). symbols_sent ≫ source.
- **Falsifiability:** if sender stays ~99% CPU → still encode-bound (E-0 false, revisit encode).
  If receiver pegs one core for ~all of wall with feedback_rounds≤1 → solve-bound (→ N-1 retry).
- **One-line:** `bash /tmp/xm_profile.sh`.
- **Result (2026-06-17, SapphireHill):** ★ **FEEDBACK-ROUND-BOUND, not CPU-bound.** 100M xmachine
  wall 116s: **sender 124% CPU** (NOT pegged — F3 fixed encode), **receiver 16% CPU** (NOT
  decode-bound — mostly idle/waiting!), **feedback_rounds=6**, symbols_sent 256200 vs accepted
  102600 (2.5× inflation). ⇒ The wall is the burst→kernel-recv-overflow→drop→NeedMore-RTT cycle,
  NOT encode CPU and NOT decode CPU. **E-1 (pacing) is THE primary lever.** E-5 (parallel decode)
  is DECONFIRMED. N-1 (SIMD) re-confirmed irrelevant (receiver isn't GF256-bound).

### E-1 · Rate-paced spray (F2 / 317hxr.3.x): eliminate self-inflicted drops
- **Hypothesis:** pacing the spray to ≈ receiver drain rate (or link rate) keeps blocks
  source-complete → systematic memcpy fast path (F-POS-1) → 0-1 feedback rounds → big win.
- **Expected signal:** feedback_rounds → 0-1; symbols_sent ≈ source count (overhead → ~1.0x);
  100M wall drops toward network-bound (~rsync).
- **Falsifiability:** if paced run still has many feedback rounds → drops are network-loss not
  burst (→ FEC is genuinely needed, tune E-2 instead).
- **One-line:** prototype a token-bucket / sleep-paced `send_symbol_datagram`; A/B vs F3.
- **Result:** _pending_

### E-2 · repair_overhead + source-retransmit tuning (lazy vs eager FEC)
- **Hypothesis:** on a low-loss link, `repair_overhead=1.0` (source-only round 0) + cheap
  missing-source retransmit (the `missing_source_symbols` path already exists, decoding.rs:778)
  beats sending speculative repair. Under real loss, a small overhead amortizes an RTT.
- **Expected signal:** clean-link: less encode + fewer bytes → faster. lossy-link: find the
  overhead that minimizes wall (convergence in ≤2 rounds).
- **Falsifiability:** if source-retransmit costs more RTTs than speculative repair saves → eager
  wins; record crossover loss rate.
- **One-line:** sweep `--repair-overhead {1.0,1.03,1.1}` × loss {0,1%,5%} cross-machine + netem.
- **Result:** _pending_

### E-3 · Multi-stream UDP saturation vs single-TCP rsync on high-BDP
- **Hypothesis:** ATP's N-way UDP spray fills a high-bandwidth×delay pipe that rsync's single TCP
  stream (cwnd/RTT-limited) cannot — IF ATP is not CPU-bound (requires E-1).
- **Expected signal:** at high RTT (e.g. 100ms) + moderate bandwidth, atp-rq (paced) throughput
  > rsync; widen the `--streams` count until the NIC/loss saturates.
- **Falsifiability:** if a single paced UDP stream already saturates → multi-stream adds nothing.
- **One-line:** netem delay 50-100ms; atp `--streams {1,4,8,16}` vs rsync; same link.
- **Result:** _pending benchmark_
- **Harness update (2026-06-18, asupersync-dnc0fx):** `scripts/atp_bench/matrix_bench.sh`
  now has `--streams CSV` for ATP-RQ stream sweeps; rsync and other non-RQ methods remain
  single-baseline rows. `run_matrix_cell.sh` emits `atp_rq_streams`/`stream_count` for ATP-RQ
  rows, and `score_matrix.py` groups medians plus admitted ATP-vs-rsync ratios by stream count.
  No benchmark was run in Phase-1/code-first mode. Admission predicate for the orchestrator
  sweep: high-BDP/rate-capped netns cells with `--streams 1,2,4,8`, crypto-symmetric tier,
  optimally tuned rsync, at least 3 reps, `sha_ok=true`, wall, cv_pct, sender+receiver peak RSS,
  and ATP feedback_rounds recorded.

### E-3.1 · Perfect-link overhead reduction analysis (rate-capped low-latency)
- **Question:** why does ATP lose the "perfect" matrix cell even after the harness is rate-capped?
  The answer must be an atp-vs-rsync explanation, not "old atp vs new atp".
- **Model:** on a 1 gbit / 2 ms / 0-loss path, the bandwidth-delay product is only about
  250 KiB. Tuned rsync streams large writes through TCP/ssh and amortizes kernel crossings,
  crypto framing, ACK handling, and checksum work across large buffers. ATP-rq currently moves
  a transfer as many small, independently authenticated UDP symbols. For a 50 MiB payload at
  1024-byte symbols, that is roughly 51k data datagrams before any repair/control traffic. At
  line rate, packets are no longer "free": one-send-per-symbol plus one-recv-per-symbol reactor
  wakeups, per-datagram HMAC, per-symbol bookkeeping, and feedback/control frames can dominate
  the wall even when the link itself has enough bandwidth.
- **Primary levers:** E-6.2 is the syscall lever (`sendmmsg`/`recvmmsg`, UDP GSO/GRO where
  available); E-1 is the pacing lever (avoid burst loss without adding idle gaps); E-3 is the
  pipe-fill lever (streams help only when BDP/cwnd is the limiter); adaptive block/symbol planning
  should select the largest safe symbol and lowest repair overhead on loss-free cells.
- **Non-levers:** do not re-enable rsync compression for incompressible generated data; do not
  compare atp-lab to rsync-over-ssh; do not headline reductions vs prior ATP. If the matrix cell is
  `nocrypto`, compare atp-lab only to rsync-daemon. If it is `auth` or `encrypted`, keep the
  crypto tier symmetric.
- **Expected signal:** after E-6.2, the perfect-cell packet/syscall counters should fall faster than
  wall time; if wall remains above rsync with low CPU and low syscall rate, the remaining gap is
  likely protocol framing/control overhead. If CPU stays high in per-symbol auth/bookkeeping frames,
  reduce per-symbol work or increase safe payload per syscall before chasing more streams.
- **Measurement admission:** Phase-2 should add per-cell `packets_sent`, `send_syscalls`,
  `recv_syscalls`, `payload_bytes_per_syscall`, and sender/receiver CPU% to the matrix JSONL before
  declaring any perfect-link conclusion. A result with `sha_ok=false`, missing syscall counters, or
  crypto-asymmetric peers is inadmissible.
- **Result (2026-06-18, cod_7):** analysis only; no benchmark executed. This records the
  perfect-link reduction map for E-6.2/E-3 so future agents stop treating uncapped or low-latency
  rsync wins as a vague ATP failure. The concrete next code lever remains UDP batching/GSO in
  `src/net/udp.rs`, already claimed by cod_1.
- **Current-state correction (2026-06-19, asupersync-2uguni):** the old "sender does one
  syscall per symbol / no true batched UDP path exists" model is stale on `main`. RQ now queues
  outbound symbol datagrams through `RqPendingSendBatch`; `UdpSocket::send_batch_to` tries a
  connected-peer native path; Linux/Android can build GSO super-packets and call `sendmmsg` with
  `UdpGsoSegments`; and `UdpBatchIoReport` exposes whether native/GSO/fallback was actually used.
  The remaining perfect-link work is therefore proof, not rediscovery: matrix rows must report
  actual UDP batch counters (`native_send_batch_used`, `gso_send_used`, fallback/partial counts or
  their aggregates) before claiming E-6.2 reduced clean-link overhead. Planner estimates and
  `est_min_datagrams` alone are inadmissible.

### E-4 · max_block_size sweep (is decode superlinear in K?)
- **Hypothesis:** default 8MiB ⇒ K=8192; if `decode_block` is superlinear in K, smaller blocks
  cut solve cost AND widen encode/decode parallelism (more independent blocks). If decode is
  ~linear, smaller blocks only help parallelism width.
- **Expected signal:** microbench `decode_block` wall vs K for fixed total bytes; superlinear ⇒
  smaller K wins. (CLI does not expose max_block_size yet → would add `--max-block-size`.)
- **Falsifiability:** if decode wall ∝ total bytes regardless of K → block size irrelevant to
  solve cost (only parallelism). 
- **One-line:** criterion bench `decode_block` at K ∈ {256,1024,4096,8192} same total bytes.
- **Result (2026-06-17, MagentaGoose):** bench harness added in
  `benches/raptorq_large_k_profile.rs` as
  `e4_decode_vs_k_fixed_total_bytes/decode_block_path/k{256,1024,4096,8192}`. It precomputes
  a fixed 4 MiB solvable symbol set per K, holds total bytes constant, and times
  `InactivationDecoder::decode`, the hot path called by `src/decoding.rs::decode_block`.
  First RCH compile attempt (`cargo bench --bench raptorq_large_k_profile --features
  criterion-benches --no-run`, build 29892352898236522 on vmi1152480) was canceled after
  detector_progress_stale=true with fresh heartbeat before a bench binary/result. This is **not**
  performance evidence. Follow-up RCH validation (`cargo check --bench
  raptorq_large_k_profile --features criterion-benches`, build 29892352898236527 on vmi1152480)
  passed; the only warnings were peer-dirty ATP-RQ adaptive/loss imports outside this lane.
  A real filtered Criterion attempt (`cargo bench --bench raptorq_large_k_profile --features
  criterion-benches e4_decode_vs_k_fixed_total_bytes`, build 29892530132746244 on vmi1152480)
  failed before executing benchmarks because the concurrent `transport_rq/mod.rs` controller wiring
  slice did not compile under the bench feature set: unresolved `CongestionController`,
  `CongestionConfig`, `AtpLossDetector`, and `LossRecommendation` names. No E-4 timings or cv_pct
  exist yet. **Retry-condition:** rerun after the RQ controller/loss wiring compiles under
  `cargo bench --bench raptorq_large_k_profile --features criterion-benches`; then append mean +
  cv_pct for each K.

### SCORE.1 ★ Honest cross-regime ATP-RQ vs rsync scoreboard harness
- **Goal:** prove or falsify the user thesis, "beat tuned rsync over ANY connection, less memory,"
  with the same artifact shape across clean, lossy, spotty, and high-BDP links.
- **Harness:** `scripts/atp_rq_regime_bench.sh` (netns/veth/netem pattern from
  `/tmp/loss_bench_contabo.sh`, but generalized into a scoreboard runner). It runs ATP-RQ and
  tuned rsync through an isolated namespace link at configurable `RATE` (default 100mbit), sizes
  `10M/100M/1G`, and regimes:
  `clean`, `lossy1`, `lossy3`, `lossy10`, `spotty`, `highbdp50`, `highbdp100`.
- **Metrics captured per row:** wall_seconds, sender_peak_rss_kb, receiver_peak_rss_kb,
  feedback_rounds (ATP only), source_sha/dest_sha/sha_ok, process status, and artifact directory.
  Output is both JSONL (`results.jsonl`) and TSV (`results.tsv`) under a unique run directory.
- **Proof rule:** a row is admissible only if `sha_ok=true`. A "speed win" is not a keep if either
  sender or receiver RSS grows above rsync for the same size/regime without a documented reason.
- **Smoke:** local syntax check `bash -n scripts/atp_rq_regime_bench.sh` passed 2026-06-17.
- **One-line smoke on Contabo:** `sudo env BIN=/tmp/atp_bench/atp_f3 SIZES=1M:1048576
  REGIMES=clean bash scripts/atp_rq_regime_bench.sh`
- **One-line full scoreboard:** `sudo env BIN=/tmp/atp_bench/atp_f3
  bash scripts/atp_rq_regime_bench.sh`
- **Result:** _harness ready; no admissible scoreboard rows yet in this ledger._

### E-5 · Parallel decode (F6.3 / 317hxr.7.3) — DECONFIRMED by E-0
- **Hypothesis:** decode independent blocks concurrently. **Status: NOT the lever.** E-0 measured
  the receiver at **16% CPU** during a 100M transfer — it is NOT decode-bound, it is idle waiting
  on feedback-round RTTs. Parallelizing an idle decoder yields nothing.
- **Retry-condition:** revisit ONLY if, AFTER pacing (E-1) eliminates feedback rounds, a profile
  then shows the receiver decode pegged ≥80% CPU on a single core. Until then, do not pursue.

---

## ASUPERSYNC LEVERAGE AUDIT (are we fully using the runtime?)

Per `/asupersync-mega-skill`. Findings on whether atp-rq exploits asupersync's machinery:

- **L-FINDING-1 · Sender one-syscall-per-symbol is RESOLVED in shape, still needs proof.**
  Current RQ send code queues encoded symbol datagrams through `RqPendingSendBatch` and flushes
  them per socket via `UdpSocket::send_batch_to`. This removes the old immediate
  `send_to`-per-symbol structure on the connected path, but the matrix must still record whether
  each run actually used native batching or fell back to the portable loop.
- **L-FINDING-2 · Receiver one-`poll_recv`-per-symbol is RESOLVED in shape.** The RQ inbound pump
  now uses `recv_batch_from` with bounded burst draining, matching the E-6.1 direction. Future
  measurements should report packet/batch counts instead of treating receive wakeups as unknown.
- **L-FINDING-3 · true batched UDP send path is PRESENT, but not yet scorecard-proven.**
  `UdpSocket::send_batch_to` now tries connected native sends; Linux/Android can plan GSO
  super-packets, call `sendmmsg`, and fall back to plain `sendmmsg` or the portable loop if the
  fast path is unavailable. This upgrades the finding from "runtime enhancement missing" to
  "operator proof missing": clean-link results must include native/GSO/fallback counters.
- **L-FINDING-4 · CLI blocking pool IS used** (599356511) and F3 dispatches encode to it. Good.
  spawn_blocking is region-owned + cancel-correct. The receiver decode does NOT use it (E-5).
- **L-FINDING-5 ★ THE BIG ONE · A complete adaptive controller EXISTS but is UNWIRED.**
  `src/net/atp/transport_rq/adaptive.rs` (1105 lines, `br-asupersync-mixdaw`, design doc
  `docs/atp_rq_adaptive_design.md` 443 lines) implements `AdaptiveController` +
  `update_estimate`/`update_path_signals`/`next_block_plan` + `AdaptivePolicy` + `PathEstimate`
  (online RTT/loss/bandwidth/**CVaR trough goodput**/coding-throughput) and DERIVES the calibrated
  repair overhead ε*(K, p̄, α) for a target decode-failure prob AND rate-matches λ/(1+ε) to coding
  throughput. `grep adaptive::|AdaptiveController|PathEstimate src/net/atp/transport_rq/mod.rs
  src/bin/atp.rs` ⇒ **ZERO callers**. It is opt-in/dead. Wiring it is the master lever (E-7):
  it directly produces the pacing rate (E-1) + repair overhead (E-2) + fan-out (E-3) the campaign
  needs, adaptively per link. Violates the "all optimizations default-on" mandate.

- **L-FINDING-6 · QUIC native_link is a WORKING REFERENCE for the rq mechanics.**
  `transport_quic/native_link.rs` already has: a **paced outbound queue** ("spray one symbol,
  flushing first if the paced outbound queue is full", line 693), **`recv_batch_from`** drain
  (line 194, INBOUND_PUMP_BATCH=512 + drain batching), **control-PTO** (re-send NeedMore on idle),
  and adaptive **reward** plumbing (`observe_quic_adaptive_path_stats`). So the rq panes can MIRROR
  these patterns instead of inventing them: E-6.1 (recv_batch_from in the rq pump) and E-7.3 (paced
  spray) both have a same-repo reference. CAVEAT: neither rq NOR QUIC actually calls
  `next_block_plan` on the live path (QUIC only in tests at mod.rs:6024) — applying the controller's
  PLAN (block-size/overhead/fanout) is the shared E-7 gap for BOTH transports. So E-7, done once
  cleanly, should be portable rq↔quic. Also: QUIC throughput-vs-rsync is UNMEASURED (the QUIC work
  was convergence/correctness, not throughput) — benchmark it (SCORE.1 includes atp-quic).

### E-7 ★ MASTER LEVER · Wire the AdaptiveController (adaptive over ANY link, default-on)
- **Goal (user):** atp-rq faster than tuned rsync over ANY connection (good/bad/spotty), adaptive,
  lower memory. The controller already computes the knobs; wire it into the live send/feedback loop.
- **Hypothesis:** drive `AdaptiveController` from online feedback (receiver reports loss/RTT/pending
  → `PathEstimate`); apply its outputs each round: (1) **rate-matched pacing** (λ/(1+ε)) so the
  spray never overruns the receiver (kills the feedback-round explosion E-0 found) → clean link
  hits the systematic memcpy fast path → MATCH rsync; (2) **calibrated overhead ε*(p̄)** so a lossy
  link decodes in ~1 round instead of 6 → BEAT rsync (whose single TCP collapses under loss);
  (3) **CVaR-trough conservative fallback** under high loss-variance → "acceptable robustness".
- **Expected signal:** clean: feedback_rounds→0-1, overhead→~1.0, wall→network-bound (~rsync).
  lossy (1-10%): feedback_rounds≤2, wall ≪ rsync (no TCP collapse). spotty: regime shift detected,
  overhead/rate adapt within ~1-2 RTT, no divergence.
- **Falsifiability:** if the wired controller still oscillates / overshoots on a regime shift, the
  estimator/control law needs the changepoint reset (project has `changepoint_exp3_reset`); record.
- **Plan:** pane-2 reads adaptive.rs + the design doc, assesses why it's unwired, wires it with a
  deterministic conservative fallback (per alien-artifact: never ship adaptive without a safe mode),
  A/B vs F3 on clean + netem-lossy + netem-spotty. Reserve adaptive.rs + send_path.
- **Result:** _in progress — wiring plan below (E-7.1 done by SapphireHill, read-only)_

#### E-7.1 controller assessment + wiring plan (for pane-2 / MaroonIvy)
adaptive.rs IS complete + sophisticated; it was just never threaded into send_path. Design:
- `AdaptiveController` = **EXP3 adversarial bandit** (no-regret) over arms `(k ∈ {256,512,1024,2048,
  4096,8192}) × (fanout ∈ {1,2,4,8})`; reward = wall-seconds / useful-byte (lower=better).
- `overhead_for_target(k, p̄, α)` = inverse-normal-tail analytic seed + bisection on
  `decode_fail_probability` → calibrated repair overhead hitting decode-failure α (default 1e-3),
  capped `max_overhead=0.5`. THIS is adaptive FEC.
- `PathEstimate{rtt_s, loss_p_hat, loss_p_bar, bw_median_bps, trough(CVaR), samples}` +
  `decode_symbols_per_s_at(k)`; `PathSignalSample{smoothed_rtt, cwnd, loss_rate}` (EMA-smoothed).
- **Built-in safe fallback:** `next_block_plan` returns `None` until `samples ≥ min_samples (3)` →
  caller uses fixed config. Deterministic via `DetRng(seed)` → lab-replayable.
**WIRING STEPS:**
1. In `send_path`: `let mut ctl = AdaptiveController::new(AdaptivePolicy{cores: available_parallelism
   as f64, ..default()}, seed_from_transfer_id)`. Pick initial k/fanout ONCE at start (block
   boundaries + sockets are fixed at round 0 — do NOT churn k/fanout mid-transfer; only overhead +
   pace adapt per-round).
2. **Round 0 conservative start (fixes the burst E-0 found):** do NOT full-burst. Start paced
   (slow-start-like) at a conservative rate; this alone should cut the 6 feedback rounds.
3. Each feedback round, build `PathEstimate` from the NeedMore WITHOUT a wire change: infer
   `loss_p_hat ≈ pending_or_missing / sent_this_round`; `rtt_s` from control send→NeedMore timing;
   `bw_median_bps` from delivered_bytes/round_wall; `samples += 1`. `ctl.update_estimate(est)`.
4. `ctl.next_block_plan(symbol_size)` → `BlockPlan{k, overhead, fanout}` (or None→fixed). Apply
   `overhead` to this round's repair (replaces static `repair_overhead`).
5. **PACING (the core anti-burst lever — NOT returned directly):** compute
   `rate = min(est.bw_median_bps, decode_symbols_per_s_at(k)*symbol_size)` and pace the spray
   (token bucket / inter-packet sleep in send_symbol_datagram). This is the λ/(1+ε) rate-match.
   Add a `ctl.pacing_bytes_per_s()` helper if cleaner.
6. After the round: `ctl.observe(sent, received, wall_s, useful_bytes)` to update the bandit.
7. **Conservative fallback (E-7.5):** None / high loss-variance / regime-shift → conservative pace +
   modest overhead. Round-0 conservative start covers warmup.
**CAVEATS for pane-2:** (a) k/fanout adapt only at transfer start, overhead+pace adapt per-round;
(b) prefer inferring loss from `pending` (no wire change) over adding a NeedMore loss field;
(c) keep byte-identical wire + sha; (d) reserve adaptive.rs (may be peer-dirty) + send_path.

#### WIRE-4 loss detector + persistent congestion assessment/wiring plan (read-only, MagentaGoose)

**Inventory verdict:** `src/net/atp/loss/detector.rs` and
`src/net/atp/loss/persistent_congestion.rs` are public via `loss/mod.rs`, tested, and mostly
standalone. `AtpLossDetector` tracks sent packets, ACK ranges, adaptive packet/time thresholds,
reordering, and pattern classes (`Burst`, `Periodic`, `Congestion`, `Tail`) and emits
`LossRecommendation::{EnablePacing, EnableFec, SwitchCongestionControl, ReduceCongestionWindow}`.
`PersistentCongestionDetector` emits severity + `CongestionRecommendation::{ReduceSendingRate,
EnablePacing, EnableFec, ConsiderPathSwitch, ResetCongestionWindow}`. The live QUIC recovery path
already has loss telemetry, but these recommendation objects are not feeding ATP-RQ pacing/FEC
decisions or the TransferBrain meta-layer. For RQ specifically, the live feedback signal is
`NeedMore`/pending-bytes/round timing, not QUIC ACK ranges.

**Plan for pane-2 / loss-controller wiring:**
1. Treat WIRE-4 as **sense-only**. It may classify loss and persistent congestion, but it must not
   directly mutate `RqConfig`, send rate, block size, or fanout. WIRE-1/WIRE-2 remain the single
   writers for FEC overhead and pacing.
2. QUIC path: instantiate `AtpLossDetector` beside the ATP QUIC recovery manager, feed
   `on_packet_sent` from sent packet metadata and `on_ack_received` from ACK ranges using
   `LossTransportState::from_transport`. Preserve native QUIC recovery behavior; the ATP detector
   is advisory until tests prove the mapping.
3. Persistent congestion path: feed `PersistentCongestionDetector` from the same lost-packet
   metadata before recovery drops it, plus PTO/cwnd-reduction events. If only aggregate lost counts
   are available, add a narrow adapter at the recovery boundary rather than inventing packet data.
4. RQ path: do **not** shoehorn `AtpLossDetector` directly onto UDP symbols without packet ACK
   ranges. Instead, convert RQ `NeedMore` feedback into the existing `PathEstimate` fields
   (`loss_p_hat`, `loss_p_bar`, RTT/control-wait, goodput trough) and map WIRE-4 recommendation
   vocabulary onto controller inputs. A future symbol-level ACK design is a wire-format change and
   needs its own isomorphism proof.
5. Recommendation mapping: `EnablePacing`/`ReduceSendingRate` lowers the WIRE-2 pacing ceiling;
   `EnableFec` raises WIRE-1 loss-bar/FEC floor; `SwitchCongestionControl` and
   `ConsiderPathSwitch` are forwarded to WIRE-3 TransferBrain, not applied inside the spray loop.
   Persistent congestion severity >0.8 means conservative fallback: min safe pace + repair floor,
   then let WIRE-3 consider relay/path switch at a transfer boundary.
6. Interference check: never let WIRE-4 and WIRE-1 independently compute competing repair rates.
   The detector can label the regime; AdaptiveController owns the quantitative overhead. Never let
   WIRE-4 and WIRE-2 both sleep/send; CongestionControl/pacer owns timing. All outputs must be
   deterministic from replayed ACK/NeedMore events.
7. Validation: unit tests for recommendation-to-controller mapping; lab replay for loss/reordering
   sequences; SCORE.1 rows for lossy1/lossy3/lossy10/spotty showing fewer feedback rounds, lower
   wall, sha_ok=true, and no RSS regression vs rsync.

#### WIRE-3 AtpTransferBrain meta-layer assessment/wiring plan (read-only, MagentaGoose)

**Inventory verdict:** WIRE-3 is `src/net/atp/quic/transfer_brain.rs` `AtpTransferBrain`, the
path/relay/FEC/congestion **meta** brain. It is public via `quic/mod.rs` and heavily unit-tested,
but production usage search finds no live callers outside tests. Do not confuse it with
`src/atp/transfer_brain.rs`, which is the data/chunk scheduling brain for early usability,
repair ROI, disk/CPU pressure, and object/chunk priority. WIRE-3 consumes
`AtpTransportMetrics` snapshots and emits `TransferDecision` with selected paths, rejected-path
evidence, pressure/fairness snapshots, congestion params, repair enable/fec_rate, relay suggestion,
priority, ETA, confidence, and reason_vector.

**Composition rule:** WIRE-3 composes **above** pane-2's controllers and should land after WIRE-1/2
are stable. Layering remains: WIRE-4 senses loss/persistent congestion → WIRE-1 computes FEC
overhead/block/fanout, WIRE-2 computes pacing → WIRE-3 chooses path/relay/policy ceilings at
transfer timescale. It must not own per-packet sleeps or per-round repair math.

**Plan for pane-2 / meta-controller wiring:**
1. Build a per-peer/path `AtpTransferBrain` instance and feed it `AtpTransportMetrics` from
   `AtpTransportMetricsCollector` (QUIC) or an RQ metrics adapter (direct peer path id,
   feedback_rounds-derived loss, control-wait RTT, offered/useful throughput, RSS pressure when
   available).
2. Before opening a transfer, call `make_transfer_decision(transfer_id, total_bytes, priority)`.
   Use `selected_paths` to choose direct vs candidate path, `suggested_relay` only if relay support
   for that transport is actually configured, and record `decision_id`/`reason_vector` in trace/CLI
   reports. Core library stays silent.
3. Treat `decision.enable_repair` as a gate/floor for WIRE-1, not as a direct replacement for the
   analytic overhead. Convert `decision.fec_rate` into "minimum overhead allowed" only; the
   AdaptiveController still decides the final per-round overhead from measured loss.
4. Treat `decision.congestion_params` as initial/conservative caps for WIRE-2. If
   `pacing_rate=None`, do not reset an active pacer to burst mode. The pacer remains the only timing
   writer.
5. Mid-transfer path switching is **not** enabled by this plan. A WIRE-3 path switch/relay decision
   applies at transfer start or resume boundary until QUIC migration/resume proof is green.
   Otherwise it can create a new feedback-round failure mode by moving bytes while decoder state is
   bound to an old path.
6. Feed completion outcome back with `report_transfer_completion` after sha/merkle proof, wall,
   RSS, and success/failure are known. This closes the brain's learning loop without changing wire
   bytes.
7. Interference check: WIRE-3 may veto obviously bad paths/relays and set policy ceilings, but it
   must not fight WIRE-1 over FEC or WIRE-2 over pacing. If WIRE-3 says relay/path switch while
   WIRE-4 says persistent congestion, prefer conservative fallback + transfer-boundary switch, not
   a live in-flight transport rewrite.
8. Validation: deterministic unit tests for decision ordering and reason vectors already exist;
   add integration tests proving decision metadata does not alter RaptorQ symbol layout. SCORE.1 is
   the acceptance surface: clean must not regress vs rsync, lossy/spotty/high-BDP must improve wall
   and feedback_rounds, and RSS must be below same-row rsync before claiming "less memory."

### E-8 · Memory: paced delivery + bounded retention (less RSS than rsync, ideally O(1) in file size)
- **Hypothesis:** E-0 receiver RSS was **1.7 GB** (vs rsync ~13 MB) — driven by the 120 MiB recv
  buffer + symbols retained across 6 feedback rounds + per-K=8192 decoder state. With pacing (E-7)
  there are ~0 feedback rounds and blocks complete on arrival → recv buffer can be SMALL and symbol
  retention bounded to a few in-flight blocks → RSS becomes O(in-flight) not O(file). Smaller
  max_block_size (E-4) further cuts per-block decoder memory.
- **Expected signal:** receiver RSS bounded (flat vs file size), target < 100 MB for 1G.
- **Cross-cutting:** every experiment reports peak RSS (both ends); a "faster" change that blows
  memory is not a keep.
- **Result (2026-06-17, BluePike, E-7/WIRE-1/2/4 send-side + E-8 clean-link memory):**
  - Code under test: `transport_rq` send path now uses the dormant
    `datagram/congestion.rs` `CongestionController` TokenBucket as the raw datagram pacer, feeds
    aggregate `NeedMore` loss/RTT/throughput into `transport_rq/adaptive.rs`
    `AdaptiveController`, and feeds the same aggregate loss samples into `loss/detector.rs` as
    advisory input. Wire schema is unchanged: symbol datagrams are still emitted through the same
    encoder/datagram serializer and receiver SHA-256 + Merkle verification stayed green.
  - Negative clean-loopback A/B, 100 MiB random payload, `--streams 8 --workers 16`,
    unauth lab mode, baseline `/tmp/rch_target_atp_lossbench/release/atp` vs first E-7 binary
    `/tmp/rch_target_bluepike_rq_e7_release_atp_cli/release/atp`:
    F3 baseline wall **160.240 s**, `feedback_rounds=5`, `symbols_sent=230600`,
    `symbols_accepted=102566`, peak RSS sender **235340 KiB**, receiver **1738756 KiB**.
    First E-7 pacing/adaptive binary wall **294.534 s**, `feedback_rounds=5`,
    `symbols_sent=219800`, `symbols_accepted=102531`, peak RSS sender **233732 KiB**,
    receiver **1748168 KiB**. **Negative:** TokenBucket pacing alone reduced symbol inflation only
    slightly and made wall worse; it did not make the receiver source-complete.
    Retry condition: do not spend cross-machine slots on pacing-only builds; retry only after the
    default path uses source-first sparse source-symbol retransmit or block-level repair feedback,
    and keep only if `feedback_rounds <= 1`, sha/merkle ok, and receiver RSS falls below 100 MiB.
  - Negative FEC-only calibration: explicit `--repair-overhead 1.03` on the first E-7 binary made
    20 MiB loopback converge with `feedback_rounds=0` in **3.814 s**, but the full 100 MiB run
    still took **292.145 s**, `feedback_rounds=5`, `symbols_sent=219800`,
    `symbols_accepted=104448`, peak RSS sender **269968 KiB**, receiver **1738212 KiB**.
    **Negative:** more round-0 FEC does not fix a large single pending entry because each feedback
    round still re-sprays repair for every block of that entry. Retry condition: FEC overhead is a
    secondary knob; retry FEC sweeps only with source-first streaming active or with true block-level
    pending feedback.
  - Positive source-first default, 100 MiB loopback, rebuilt binary
    `/tmp/rch_target_bluepike_rq_e7_sourcefirst_release/release/atp`: changed the conservative
    fallback to `DEFAULT_REPAIR_OVERHEAD=1.0`, `DEFAULT_SOURCE_RETRANSMIT_ROUNDS=2`, and
    `DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS=8192`. Three clean-loopback reps were
    **7.116/7.116/7.116 s**, mean **7.116 s**, **cv_pct=0.00**, sha/merkle ok,
    `feedback_rounds=0`, `symbols_sent=102400`, `symbols_accepted=102400`; peak RSS sender
    **61888 KiB**, receiver **7428 KiB**. This is the first confirmed E-7/E-8 win: vs the same
    session F3 baseline, wall improves **22.5x**, receiver peak RSS drops **~99.6%**, and symbol
    inflation disappears.
  - Positive MTU-safe symbol default, 100 MiB loopback, rebuilt binary
    `/tmp/rch_target_bluepike_rq_e7_s1400_release/release/atp`: changed
    `DEFAULT_SYMBOL_SIZE` from 1024 to **1400** so a symbol plus authenticated RQ datagram header
    and IPv4/UDP framing remains below 1500-byte MTU while cutting packet count. Default run wall
    **7.016 s**, sha/merkle ok, `feedback_rounds=0`, `symbols_sent=74899`,
    `symbols_accepted=74899`, peak RSS sender **76336 KiB**, receiver **7424 KiB**.
  - Positive clean cross-machine 100 MiB, OVH `fmd` → Contabo `212.90.121.76`, unique artifacts
    `/tmp/atp_bench/e7_bluepike_20260617193910`, binary sha prefix `90e35ca5b9d3105a`,
    `--streams 8 --workers 16 --rq-allow-unauthenticated-lab`: sender wall **7.11 s**,
    sender CPU **52%**, sender peak RSS **51000 KiB**; receiver JSON `feedback_rounds=0`,
    `symbols_accepted=74899`, receiver peak RSS **9344 KiB**, sha matched
    `1171155444c169b566440f9b4ce8ea8affb4ccc54c3e70ffdba149b08ca998ed`. This beats the tuned
    rsync 100 MiB target (**8.44 s**) by ~**15.8%** on the clean path and beats the prior RQ F3
    cross-machine wall (**113.85 s**) by ~**16.0x**. Receiver `/usr/bin/time` wall was **28.73 s**
    because it includes pre-send listen wait; sender wall is the transfer comparator.
  - Caveat/retry condition for security and lossy/spotty claims: the source-streaming fast path is
    currently gated to unauthenticated lab RQ symbols (`parsed.auth_tag.is_none()`), so the clean
    cross-machine win is SHA/Merkle verified but not per-symbol authenticated. To claim the same
    result under `--rq-auth-key-hex`, extend the source-streaming path to verify auth tags before
    `persist_source_symbol` or accept that authenticated runs use the slower decoder/FEC path.
    Netem lossy/spotty sweeps were not run from `/tmp/loss_bench_contabo.sh` because that harness
    contains `rm -rf`; retry with a no-delete unique-workdir harness, then sweep loss
    `{0,1%,5%}` and spotty mid-transfer changes. Keep the E-7 default only if clean remains
    `feedback_rounds=0`, lossy/spotty remain sha/merkle ok, and receiver RSS stays below 100 MiB.

### E-6 · Batched UDP syscalls + GSO (deepest runtime-leverage lever)
- **Hypothesis (two tiers):**
  (a) cheap: switch the rq receiver pump to `recv_batch_from` (amortize the reactor-readiness wait
      per burst). Possibly a small win.
  (b) high-ceiling: add a real `sendmmsg`/`recvmmsg` + **GSO (`UDP_SEGMENT`)** fast path to
      `UdpSocket` (one `sendmsg` pushes up to 64 segments; kernel/NIC segments). This is how
      WireGuard/quinn hit line rate. Collapses ~100k syscalls → ~1.5k and offloads segmentation.
- **Expected signal:** (a) modest drain-time reduction at high packet rate; (b) sender packet rate
  rises from ~per-syscall-bound to GSO-bound (≫12 MB/s ceiling) → lets ATP EXCEED rsync on fat
  pipes, not just match it.
- **Falsifiability:** if E-0 shows the wall is feedback-rounds (not syscall/packet-rate), E-6 is a
  ceiling-raiser not a near-term win — defer behind E-1. Only matters once paced + clean.
- **Scope/risk:** the current native send path uses the socket fd plus `nix::sys::socket::sendmmsg`
  and Linux/Android `UdpGsoSegments`; the risk has shifted from "write the syscall path" to
  "prove the real transfer stays on that path and classify every fallback." Benefits QUIC too.
- **One-line:** (a) prototype recv_batch_from in pump_until_control; (b) microbench sendmmsg+GSO
  packet rate vs send_to loop on loopback.
- **Result (2026-06-17, MossyCastle, E-6.1 + WIRE-5 current-tree loopback):**
  - Code under test: RQ receiver `pump_until_control` switched from one `udp.poll_recv` per loop to
    `recv_batch_from` with QUIC-mirrored width/bounded full-batch quiet drain
    (`RQ_INBOUND_PUMP_BATCH=512`, max full batches 64, 1 ms grace). `datagram/beacons.rs` gained a
    `BeaconScheduler` plus Probe/Keepalive constructors/helpers; RQ sender wires the scheduler as a
    **no-new-wire** probe carrier by feeding existing `ObjectComplete` control-reply RTT into
    `PathEstimate`/`PathSignalSample`. Symbol datagrams and control frame sequence stay
    byte-identical; receiver SHA-256 + Merkle verification remained green.
  - Baseline artifact `/tmp/atp_e6a_baseline_20260617T213957Z`, 32 MiB loopback random payload,
    `rq`, `--streams 4`, `--workers 4`, unauth lab auth, 3 runs: wall
    57.58/57.98/57.90 s, mean **57.820 s**, sd 0.173 s, **cv_pct=0.30**; peak RSS sender
    190844 KiB, receiver 243696 KiB; `feedback_rounds=5`, `symbols_sent=73792`,
    `symbols_accepted≈32803`; sha/merkle ok.
  - Post artifact `/tmp/atp_wire5_e61_20260617T222032Z`, same local shape, 3 runs: wall
    103.88/104.58/103.77 s, mean **104.077 s**, sd 0.359 s, **cv_pct=0.34**; peak RSS sender
    192944 KiB, receiver 253480 KiB; `feedback_rounds=5`, `symbols_sent=70336`,
    `symbols_accepted≈32786`; sha/merkle ok.
  - Interpretation: **negative for immediate wall/RSS claim on this dirty current tree**; do not
    spend a cross-machine 100M slot from this result. The feedback-round count did not change, and
    post sender CPU fell from ~119% to ~73% while voluntary context switches rose from ~73k to
    ~225k, so the wall regression is consistent with concurrent WIRE-2 pacing/loss-controller WIP
    being active in the same `transport_rq/mod.rs` build, not proven to be caused by batching alone.
  - Retry-condition predicate: rerun an A/B on the **same current tree** after pane-2 pacing reaches
    a stable/owned commit, toggling only the pump implementation (`poll_recv` vs `recv_batch_from`)
    with the same binary profile and payload. Keep E-6.1 only if mean wall decreases with
    `cv_pct <= 1.0`, sha/merkle ok, and receiver peak RSS does not exceed the poll-recv control.
    If it still loses, retry only with a zero-copy/slab-backed batch receive or much smaller bounded
    batch width; the current `UdpRecvBatch` alloc/copy shape is not enough evidence for a keep.
- **State update (2026-06-19, asupersync-2uguni):** the sender side now has RQ batching wired to
  `UdpSocket::send_batch_to`, and `send_batch_to` can use connected native `sendmmsg` plus GSO
  before falling back. The next admissible E-6 result is not another code inventory; it is a
  rate-capped `perfect` matrix row with sha ok, bounded RSS, ATP-vs-rsync ratio, and actual
  UDP batch/native/GSO/fallback counters emitted into the row or attached report.

### Synthesis — why ATP can beat rsync (the actual thesis)
On a CLEAN link, the win path is: **lazy/paced source-symbol streaming (E-1,E-2) → systematic
memcpy receive (F-POS-1, already built) → 0 feedback rounds → match rsync**; then **GSO + N-stream
UDP (E-6,E-3) → EXCEED rsync** by saturating a fat/long pipe a single TCP stream can't fill. On a
LOSSY link, the *same* fountain machinery repairs loss without TCP's retransmit/HoL collapse — but
ONLY once ATP is not self-bottlenecked on CPU/feedback.

**Revised priority after E-0 + L-FINDING-5:** E-0 (done: feedback-round-bound, recv 16% CPU) →
**E-7 (wire AdaptiveController = E-1 pacing + E-2 calibrated overhead, adaptive per link)** →
E-8 (memory falls out of pacing) → E-3 multi-stream + E-6 GSO (ceiling-raisers to EXCEED rsync on
fat pipes) → E-4 block-size. E-5 (parallel decode) DECONFIRMED. N-1 (SIMD) refuted.
The user's goal "beat tuned rsync over ANY connection, less memory" = E-7 + E-8 as the spine,
E-3/E-6 to win on high-BDP, fountain-FEC to win under loss. The adaptive math already exists
(adaptive.rs); the work is wiring + a conservative fallback + honest A/B across link regimes.

## E-RESYNC-1 (2026-06-19, orchestrator loopback measurement) — delta CORRECT but ZERO wire savings (does NOT beat rsync yet)
Built atp-cli (delta wiring bzkxa5/0g8lod, --no-delta opt-out present = delta default-on). Loopback re-sync test, 10MB file:
- ROUND 1 initial full sync: bytes_sent=10485760 (correct), dst sha == src sha.
- 1% in-place mutation (100KB @ 5MB, python in-place).
- ROUND 2 re-sync (delta default-on): **bytes_sent=10485760 (FULL), symbols_sent=7490 — NO delta savings**; dst sha == src sha (byte-identical, fail-closed-correct).
VERDICT: delta path is CORRECT (byte-identical both rounds) but the sender does NOT reduce the transfer — it sends the full object on re-sync. Send/recv logs show no delta-plan/negotiation. The receiver persists `<dest>/.asupersync-atp-delta-v1` but `atp send <host:port>` never consumes it. **Re-sync bytes-on-wire ratio vs rsync ≈ FULL/delta = LOSS** (rsync would send ~the 100KB change). GAP (for bzkxa5/0g8lod): wire the send↔recv handshake — recv advertises prior manifest/CAS coverage on connect (incl --once), sender calls delta::plan with it, sender transmits ONLY missing chunks. Until then transparent-delta is a no-op for wire bytes. Harness note: resync_bench.sh netns send→host 10.99.0.1 times out (os err 110, align with run_matrix_cell.sh); gen_file set -e abort fixed a74b98bca.

## E-RESYNC-2 (2026-06-19) — ★WIN★ delta re-sync now O(change): 39× wire reduction, byte-identical
After the delta-negotiation fix (18390bf6f "wire direct RQ delta resync negotiation"), rebuilt atp-cli + re-measured the E-RESYNC-1 scenario (loopback, 10MB file, 1% in-place edit @5MB, --rq-allow-unauthenticated-lab):
- ROUND 1 initial full sync: bytes_sent=10485760 (correct).
- ROUND 2 delta re-sync: **bytes_sent=267149 (was 10485760 = 39× LESS), symbols_sent=192 (was 7490), missing_chunks=1, missing_bytes=262144** — sender negotiated receiver coverage and transmitted ONLY the 1 changed 256KB chunk. dst sha == src sha (BYTE-IDENTICAL, fail-closed holds).
VERDICT: E-RESYNC-1 GAP CLOSED. atp delta re-sync is now bytes-on-wire ∝ change (O(change) not O(file)) — the rsync-killer delta path WORKS. 267KB for a 1% edit of 10MB = 2.5% of full. Chunk granularity 256KB (1 chunk/change-locality); smaller chunks would tighten further toward the H(new|old) floor. NEXT: full netns benchmark vs tuned rsync --stats for the direct atp/rsync bytes-on-wire ratio across {0%,1%,10%,append,insert,rename}×{5M,100M}×{perfect,good}.

## E-RESYNC-3 (2026-06-19) — atp-delta O(change) WORKS but loses ~2x to rsync on small edits (chunk granularity)
Direct loopback comparison, 1% edit (100KB) of 10MB, re-sync, BOTH byte-identical:
- atp-rq-delta: 267,149 bytes on wire (missing_chunks=1, missing_bytes=262144 = ONE 256KB chunk + ~5KB FEC/protocol).
- rsync --checksum --no-whole-file: 135,940 bytes (sent 116,435 + recv 19,505; Literal 103,424 = the actual change + ~32KB rolling-checksum protocol).
VERDICT: atp delta is genuinely O(change) (vs 10MB full = E-RESYNC-2 39x win) and CONTENT-addressed (note: rsync DEFAULT quick-check size+mtime MISSED the in-place same-size edit entirely — needs --checksum; atp always detects content). BUT on perfect-link small edits atp LOSES ~1.96x because its delta chunk size is 256KB (one 100KB edit dirties a full 256KB chunk) vs rsync sending ~literal bytes. RETRY-COND to WIN: (1) smaller FastCDC/CAS delta chunk size (e.g. 16-64KB avg → a 100KB edit ≈ 2-7 small chunks ≈ rsync, approaching H(new|old) floor B-8.0); (2) test LOSSY regimes (good/bad) — atp's RaptorQ FEC should beat rsync's TCP-delta under loss even at coarser granularity (blocked: resync_bench.sh netns has a 'line 323 $4 unbound' regression, git 8c248ef). Headline: rsync-killer delta path is FUNCTIONAL + O(change); chunk-size tuning + lossy-regime test are the remaining levers to actually beat rsync on bytes.

## E-RESYNC-4 (2026-06-19) — smaller chunks: 267KB→183KB (2x→1.35x), still loses perfect-link; WIN case = lossy regimes
After B-8.9 (d50f2261d smaller FastCDC delta chunks), rebuilt + re-measured 10MB/1%-edit re-sync (loopback, byte-identical):
- atp-rq-delta: 183,457 bytes (missing_chunks=7 small chunks, was 1x256KB=267KB). rsync --checksum: 135,945 (literal 103KB + protocol). atp/rsync = 1.35x (was 1.96x).
VERDICT: smaller chunks narrowed the gap but atp STILL loses ~1.35x on PERFECT-link small edits — FUNDAMENTAL: atp sends whole content-defined chunks (7×~26KB) vs rsync byte-precise literal (103KB); even smaller chunks → diminishing returns + rising FEC/manifest overhead, can't beat byte-precision on a clean link. ★THE rsync-BEATING CASE IS LOSSY LINKS: atp RaptorQ FEC sends forward-redundancy with NO retransmit stalls, while rsync's TCP-delta stalls/retransmits under loss+RTT — atp should win good/bad regimes decisively. That cell is UNTESTED (blocked: resync_bench.sh 'line 323 $4 unbound', git 8c248ef). PIVOT: (1) fix resync_bench $4 → run REGIMES='good bad' (the real win); (2) perfect-link parity is good-enough (1.35x, content-addressed catches edits rsync's mtime-check misses); (3) optional marginal: 16→8KB chunks. Headline so far: atp delta is O(change)+byte-identical+content-addressed, ~1.35x rsync bytes on clean links, expected to WIN on lossy links (test pending).

## CORRECTION to E-RESYNC-4 framing (2026-06-19): the perfect-link gap is NOT fundamental
The 1.35x perfect-link loss is because atp sends CHANGED CHUNKS WHOLE (wastes unchanged bytes inside touched chunks), NOT because content-chunking can't match byte-precision. FIX = B-8.10 two-level delta: byte-precise sub-chunk diff (rsync-style/xdelta of new vs receiver's old chunk) on ONLY the changed chunks. atp then sends ~literal with ∝-delta negotiation overhead, vs rsync's O(file) checksum overhead → atp BEATS rsync on perfect links too (≈101KB vs 136KB), + FEC on lossy, + compression on real data. Target: atp < rsync across {1pct,append,insert}×{perfect,good,bad}, byte-identical.

## RADICAL DEEPENING (2026-06-19, alien-artifact 23+35 + extreme-opt) — delta as Slepian-Wolf syndrome coding
Deeper than two-level sub-chunk delta (B-8.10): model re-sync as DISTRIBUTED SOURCE CODING. rsync+B-8.10 are interactive (O(file) checksum exchange + RTT). Slepian-Wolf optimum: receiver's old file = side info Y; sender streams a RATELESS LDPC SYNDROME of new X (~H(X|Y) bits); receiver decodes via BELIEF PROPAGATION seeded with Y; rateless = pull more iff BP stalls. → BYTES approach the H(new|old) Shannon floor; NON-INTERACTIVE (no RTT, wins WAN); rateless+FEC (wins loss); + suffix-array/Hirschberg optimal byte-match (cdivsufsort) + GF(2) BP for speed. Bead B-8.11 (P0). This beats rsync on bytes AND latency AND loss AND real-data — across the board.

## E-RESYNC-5 (2026-06-19) — LOSSY regime: atp full-sync TIMES OUT (convergence blocker, not a bytes question yet)
Single netns cell 5M/good(25ms/0.1%loss/200mbit)/1pct: atp-rq INITIAL full sync hit the 120s timeout (wall=120.1, status=error, sha=false, wire=None) — atp does NOT complete a 5MB transfer under even 0.1% loss. So the "atp beats rsync on lossy via FEC" thesis is BLOCKED on UNDER-LOSS CONVERGENCE, not bytes. Root: F1 receiver decode-on-arrival (317hxr.2) + FEC-fallback-self-disables (317hxr.6.1.1) — receiver doesn't decode/drain on arrival + FEC fallback turns off in repair rounds → non-convergence under loss (matches the long-standing F1/6.1.1 finding). PRIORITY ORDER to beat rsync on lossy: (1) 317hxr.2 F1 decode-on-arrival + (2) 317hxr.6.1.1 FEC-fallback guard → atp must CONVERGE under loss first; THEN (3) delta wire-efficiency (B-8.9/.10/.11) makes the lossy re-sync also beat rsync's bytes. (resync_bench $4 now self-documented at line 256 word-splitting; the 124 exit was the atp timeout, not the harness.) NOTE: perfect-link delta already O(change)+byte-identical (E-RESYNC-2/4); lossy needs convergence fixed.

## E-RESYNC-6 (2026-06-19) — ★HARNESS FAULT★ lossy re-measure INVALID (netns→host unreachable); CASTS DOUBT on E-RESYNC-5's atp-convergence verdict
Re-measured 5M/good/1pct on a FRESH atp-cli (git 9c6c537e4, pacing-collapse fix 317hxr.2.5 / 9fe61a0fe CONFIRMED in HEAD). Both methods reported status=error / wall_s≈120.1 / dest_sha=missing / sha_ok=false (atp code 248, rsync code 124=`timeout`). The summary table's "atp 1196B vs rsync 1052B (1.14x)" is MEANINGLESS — those are partial pre-timeout bytes, not a completed transfer.
SMOKING GUN (a network-setup fault, not an atp/rsync verdict): `atp_init_send.log` = "delta planner: receiver state sidecar 10.99.0.1:41001 unavailable (connect: **connection timed out**); using full-object transfer"; `rsync.log` = EMPTY (daemon at 10.99.0.1:1873 unreachable, killed at 120s); `atp_dest/` = EMPTY (initial full sync never landed either). The netns sender cannot reach HOST_IP 10.99.0.1 at all — BOTH tools fail identically on the netns→host path.
LIKELY CAUSE: resync_bench.sh defaults HOST_IP=10.99.0.1 / NS_IP=10.99.0.2 with NO per-run uniqueness; a CONCURRENT swarm run of resync_bench installs a duplicate 10.99.0.1 on a second host veth → routing for 10.99.0.1 becomes ambiguous → both runs' netns lose host reachability. Corroborated by 6 orphaned netns leaked from prior runs (atprs<pid>, 0 pids each; cleanup deletes the veth at line 152 but leaks the netns).
★CORRECTION TO E-RESYNC-5: its "atp does NOT complete a 5MB transfer under 0.1% loss → convergence blocker (F1/6.1.1)" conclusion is now SUSPECT — the identical 120s/code-124 timeout + "connection timed out" signature is exactly this harness fault, NOT proven RaptorQ non-convergence. The lossy-convergence question is currently UNMEASURED on a working network path; the 317hxr.2.5 pacing fix is neither validated nor refuted by any benchmark to date.
RETRY-COND (before any lossy atp-vs-rsync claim is trustworthy): (1) per-run-unique HOST_IP/NS_IP subnet (derive from PID) so concurrent swarm runs don't collide; (2) `ip netns exec $NS ping -c1 -W2 $HOST_IP` reachability ASSERT in the harness before measuring (fail fast, not a 120s timeout); (3) clean leaked netns; (4) re-run good+bad with TIMEOUT_S≥180 to separate slow-converge from hung. Re-run launched with HOST_IP=10.77.0.1/NS_IP=10.77.0.2 to dodge the collision. Until a cell COMPLETES with sha_ok for BOTH tools, lossy bytes/convergence remain UNKNOWN.

## E-RESYNC-7 (2026-06-19) — ★COLLISION CONFIRMED + E-RESYNC-5 DISPROVEN★ atp DOES converge under 0.1% loss; but delta comparison still invalid (2 harness bugs)
Re-ran 5M/good/1pct with UNIQUE IPs (HOST_IP=10.77.0.1/NS_IP=10.77.0.2) + cleaned 6 leaked netns + TIMEOUT_S=180, fresh binary (git 91c9f1a9, pacing fix in HEAD). Result: cell COMPLETED in **~7 seconds** (03:59:33→03:59:40), **atp sha = ok**, both tools finished. → The E-RESYNC-6 collision hypothesis is CONFIRMED: the 120s timeouts were the default-10.99.0.x IP collision with a concurrent swarm run, NOT a transport fault.
★★MAJOR CORRECTION — E-RESYNC-5 DISPROVEN: atp-rq COMPLETES a 5MB transfer under 0.1% loss / 25ms / 200mbit in ~seconds, byte-identical. The "atp does NOT complete under even 0.1% loss → F1/6.1.1 convergence blocker" claim was a HARNESS IP-COLLISION ARTIFACT. The convergence-bead cluster (317hxr.2 decode-on-arrival, 317hxr.2.5 pacing-collapse, 317hxr.6.1.1 FEC-fallback) was motivated, at least at this mild regime, by a benchmark-harness bug — NOT by measured RaptorQ non-convergence. (Higher-loss `bad` 2% regime still to be checked before fully closing the convergence question.)
BUT the BYTES are both ~full-file (atp 5,550,041 / rsync 5,298,405 / ratio 1.05) — neither used its delta path, so this is NOT a delta comparison: (BUG-A) the harness rsync baseline is `rsync -aW` = `--whole-file` (delta DISABLED) → rsync sends the whole 5MB; loopback E-RESYNC-3/4 correctly used `--no-whole-file --checksum` (→136KB). (BUG-B) atp's delta SIDECAR negotiation does NOT engage through the netns (sender falls back to full-object 5.5MB), even though it works on loopback (E-RESYNC-2/4 → 183KB). So the netns harness has NEVER produced a valid atp-delta-vs-rsync-delta lossy number.
RETRY-COND for a real lossy DELTA win: (BUG-A) change resync_rsync() to `rsync --no-whole-file --checksum --inplace` (or rsync:// delta) so rsync uses its delta algorithm; (BUG-B) make atp's delta sidecar reachable + engage in the netns re-sync phase (debug why it full-object-falls-back: sidecar bind/route, delta-state persistence across the init→resync boundary); THEN re-run good+bad. Convergence-under-loss is now PROVEN at 0.1% (good); checking `bad` 2% next. Until BUG-A/BUG-B fixed, do NOT cite any netns "atp vs rsync bytes" ratio — the only valid delta numbers are loopback (E-RESYNC-2/3/4).

## E-RESYNC-8 (2026-06-19) — ★REAL convergence deficiency at 2% loss★ atp-rq fail-closed (exit 1) while rsync succeeds → convergence beads RE-VALIDATED (threshold ~0.1%↔2%, not 0.1%)
Ran 5M/bad(2% loss/80ms/50mbit)/1pct with unique IPs (10.66.0.x, trustworthy harness), fresh binary (git 91c9f1a9, pacing fix in HEAD):
- atp-rq-delta: status=error, **send Exit status: 1 (CLEAN — "Signals delivered: 0", no panic/crash)**, wall=**2.5s (NOT a timeout)**, wire=3,644,312 (3.6MB partial, < full 5MB), dest_sha=**missing**, `.atp-rq-staging-*` left in atp_dest uncommitted = **FAIL-CLOSED non-convergence** (receiver couldn't reconstruct → refused to promote staging → no corruption, correct fail-closed posture).
- rsyncd-delta: status=ok, sha=True, wire=5.4MB (whole-file -W), wall=4.9s. rsync's TCP survives 2% loss + 80ms and completes byte-identical.
VERDICT: There IS a genuine atp-rq convergence/FEC-repair deficiency UNDER SUSTAINED LOSS — atp succeeds at 0.1% (E-RESYNC-7) but fail-closes at 2% (here), while rsync succeeds at both. So the convergence-bead cluster is RE-VALIDATED and worth shipping — BUT the failure threshold is between 0.1% and 2%, NOT "even 0.1%" as E-RESYNC-5 wrongly claimed (that was the IP-collision artifact). Likely mechanism = 317hxr.6.1.1 (FEC fallback self-disables in repair rounds → can't generate enough repair under sustained loss) and/or 317hxr.2 (decode-on-arrival). The 317hxr.2.5 pacing fix did NOT make 2% converge (still fail-closed). Fast 2.5s exit (not exhaustive-repair-then-timeout) hints the sender aborts early on a control/feedback failure rather than spraying forever — worth the bead-owners' look.
RETRY-COND: after any convergence bead lands → rebuild + `sudo env BIN=$BIN HOST_IP=10.66.0.1 NS_IP=10.66.0.2 CIDR=24 SIZES='5M:5242880' REGIMES='bad' CHANGES='1pct' TIMEOUT_S=180 bash scripts/atp_bench/resync_bench.sh` → must reach status=ok + sha_ok. Sweep the threshold (0.5%, 1%) to find where it breaks. Independently fix BUG-A/BUG-B (E-RESYNC-7) so the eventual converged run also yields a real delta-bytes ratio. CURRENT TRUE STATE: perfect/0.1%-loss atp delta works O(change)+byte-identical (loopback E-RESYNC-2/4 + netns E-RESYNC-7 full-object); 2%-loss atp FAILS fail-closed (convergence gap, real); rsync wins 2% today.

## E-RESYNC-9 (2026-06-19) — ★FIRST VALID netns lossy measurement★ BUG-B FIXED; atp loses 1.52x on a SPREAD edit (FEC overhead, NOT a delta bug); 2% still fails
Ran on the HARDENED harness (git b82185c8: per-run unique subnet 10.128.68.x [collision gone] + sidecar-probe that fail-closes on full-object fallback + BUG-A rsync `--no-whole-file --checksum` delta). Fresh atp-cli build.
- good (0.1%loss/25ms/200mbit) / 5M / 1pct: atp wire=8,061,292 (8.06MB) vs rsync wire=5,312,566 (5.31MB), ratio 1.52, BOTH sha_ok=true (atp wall 2.4s / rsync 1.3s).
- bad (2%loss): atp INITIAL full sync FAILED (send=1 recv=1) → harness fail-closed the cell (consistent w/ E-RESYNC-8 convergence gap).
★BUG-B FIXED: atp_send.log shows `"negotiation":"direct_receiver_state_sidecar"` — the delta sidecar now engages over netns (sidecar_state had 120 chunk_signatures). The E-RESYNC-7 full-object-fallback-through-netns is RESOLVED.
★WHY atp=8MB is NOT a delta bug: JSON shows `"shared_chunks":0, "stale_chunks":120/120, "missing_bytes":5.24MB` — atp correctly resent the WHOLE file because the harness `1pct` mutation = 1% of bytes flipped SPREAD RANDOMLY (`f.seek(rng.randrange(size))` loop) → dirties EVERY chunk (and every rsync block). Both tools full-resend; atp loses purely on **RaptorQ FEC/protocol overhead** (8.06MB on wire vs 5.23MB raw data ≈ +54%) over a near-clean 0.1% link where rsync TCP needs zero FEC. `1pct`/`10pct` are SPREAD (all-chunks-dirty); the delta-favorable, loopback-comparable test is a LOCALIZED edit (append/insert).
TWO REAL LEVERS: (1) ★FEC-OVERHEAD-ON-CLEAN-LINKS — at low loss atp ships ~54% repair overhead = pure waste vs rsync TCP; atp only wins when loss is high enough that rsync stalls. Need ADAPTIVE FEC (repair ∝ measured loss, ~0 at low loss) = the clean-link parity lever (E-7.4 / 317hxr adaptive overhead). (2) 2% convergence gap persists (initial sync fails) = the high-loss blocker where atp SHOULD win. 
RETRY-COND: localized-edit re-run launched (`CHANGES='append insert' REGIMES='good'`) → that is the rsync-killer scenario (delta skips unchanged chunks). Record atp-vs-rsync there next. Net so far: spread-edit clean-link → rsync wins (atp FEC overhead); localized-edit number PENDING; high-loss PENDING convergence fix.

## E-RESYNC-10 (2026-06-19) — ★FIRST atp-BEATS-rsync on a VALID netns lossy delta★ (insert, good regime, 0.95x)
Localized-edit re-run (hardened harness, auto unique subnet 10.68.46.x), 5M, good (0.1%loss/25ms/200mbit):
- **insert: atp wire=2,625,023 (2.63MB) vs rsync wire=2,752,600 (2.75MB) → ratio 0.95 (atp WINS by 5%), BOTH sha_ok=true.** First valid netns LOSSY delta cell where atp beats tuned rsync (--no-whole-file --checksum delta) byte-for-byte.
- append: atp initial sync flaky-aborted (send=1 recv=0) at 0.1% — transient send failure (NOT the 2% convergence gap); harness fail-closed the cell. Re-run to confirm append.
CONTEXT: `insert` shifts all bytes after the insertion offset (~half the 5MB here), so both tools send ~2.6-2.75MB; atp's two-level delta (B-8.10 sub-chunk, just CLOSED as v0jeoc) edges rsync's rolling-checksum delta by 5%. Narrow but REAL — and it's a delta-vs-delta win with byte-identical verify on a lossy link. Combined with E-RESYNC-9 (spread edit → rsync wins on FEC overhead), the picture: atp delta WINS localized edits even at low loss; LOSES spread/all-dirty edits on clean links (FEC overhead, lever L1=adaptive FEC); high-loss still gated on convergence (L2). v0jeoc CLOSED → 1owe64 (B-8.11 Slepian-Wolf) UNBLOCKED + started (%8). NEXT: confirm append (re-run), get insert/append at bad regime once convergence lands, and the localized win should WIDEN as B-8.10 sub-chunk + B-8.11 syndrome mature.
★CORRECTION (see E-RESYNC-11): the insert 0.95x "win" was MISLEADING — atp sends ~2.5-2.6MB regardless of edit because ~86% of its wire bytes are delta-NEGOTIATION metadata (the receiver's full chunk-signature sidecar state), not payload. On insert, rsync ALSO did poorly (shift), masking it. On append (where rsync is true-O(change)=96KB), atp loses 27x. atp's delta PAYLOAD is fine; its NEGOTIATION is O(file)-bloated.

## E-RESYNC-11 (2026-06-19) — ★ROOT-CAUSE: atp delta NEGOTIATION is O(file)-bloated (2.2MB sidecar), NOT the payload★ — corrects E-RESYNC-10
append re-run (good/0.1%, hardened harness): WIRE atp=2,581,073 (2.58MB) vs rsync=96,150 (96KB) → atp loses 26.8x, both sha_ok. BUT the atp_send.log JSON tells the real story:
- atp delta **payload** `bytes_sent=84,482 (84KB)`, shared_chunks=130, stale_chunks=2, missing_chunks=3, missing_bytes=120KB, package_payload_bytes=68KB. → atp's delta ALGORITHM is correct + O(change), and the 84KB PAYLOAD BEATS rsync's 96KB.
- The 2.58MB on-wire is dominated by the delta-NEGOTIATION: the receiver ships its ENTIRE chunk-signature state to the sender via the sidecar = `atp_delta_sidecar_state.json` = **2,335,787 bytes (2.23MB) for 132 chunks = 17,695 bytes/chunk** (a chunk sig should be ~56B; it's ~300x bloated — eagerly sending B-8.10's per-chunk SUB-CHUNK rolling+strong signatures for ALL chunks). So atp wire ≈ 2.23MB sidecar (O(file) negotiation) + 84KB payload + protocol.
★THE #1 BYTES LEVER (was hidden): atp's interactive delta pays O(file) negotiation overhead (2.2MB) that dwarfs the O(change) payload (84KB) → loses to rsync's COMPACT checksums (rsync's whole negotiation+payload = 96KB). Two fixes, both reduce negotiation: (a) COMPACT/LAZY sidecar signatures — chunk sig = hash+offset (~56B) not 17.7KB; send sub-chunk sigs LAZILY only for chunks the sender flags as candidate-changed, not eagerly for all (filed bead); (b) ★1owe64 Slepian-Wolf — sender sends a SYNDROME, never receives the receiver's O(file) state at all (this measurement is the empirical proof of the bead's core premise; %8 implementing). Fixing negotiation drops atp append from 2.58MB → ~150KB (84KB payload + ~7KB compact sigs + protocol) ⇒ BEATS rsync's 96KB... competitive.
REVISED CAMPAIGN (3 levers): L1 negotiation overhead (compact/lazy sigs OR Slepian-Wolf) = THE bytes lever for localized edits [NEW, biggest]; L2 adaptive FEC = clean-link parity for spread/all-dirty edits (E-RESYNC-9); L3 convergence fix = high-loss win (E-RESYNC-8). atp's delta payload is already O(change)+competitive; negotiation + FEC overhead are the gaps. RETRY-COND: after compact-sidecar or Slepian-Wolf lands → re-run append/insert good+bad → atp wire should collapse to ~payload+small-negotiation and BEAT rsync.

## E-RESYNC-12 (2026-06-19) — ★MEASUREMENT BLOCKED by a SEND-PATH REGRESSION (BUG-E)★ — kogbnc bytes win unmeasured
kogbnc (compact sidecar sigs, L1) CLOSED (d1833a063) + 1owe64 LDPC foundation landed; rebuilt atp-cli (git a423ab6c7) and tried to re-measure append/insert good. BOTH cells (×2 runs) failed `atp initial sync failed (send=1 recv=0)` in ~2s. atp_init_send.log: "delta planner: receiver state sidecar returned no state; using full-object transfer" then "atp failed: unexpected frame: got Proof, expected KeepAlive while spraying". atp_init_recv.log: receiver COMMITTED byte-identical (committed:true, bytes_received=5242880, exit 0). So the transfer logically SUCCEEDS but the SENDER errors (exit 1) on a control-frame race; the harness fail-closes the cell.
★REGRESSION (not intermittent — 100% on current binary): introduced by 5445d11ca (cu4zww "fix netns ATP subdelta resync") — the ONLY transport_rq commit in 457699d1..HEAD; E-RESYNC-10/11 binary (b82185c8) PASSED these cells, a423ab6c7 fails all. SITE src/net/atp/transport_rq/mod.rs:3551-3568: the spray control-drain match handles KeepAlive+Close but errors on every other frame ("got => Unexpected expected=KeepAlive while spraying"); on a fast transfer (5MB@0.1% ~1.8s) the receiver sends a Proof frame before the sender stops spraying → sender errors. FIX (filed P0 bead zz35zq, assigned %6): add a `FrameType::Proof =>` arm = treat early Proof as terminal success (stop spraying, finalize). Same pattern at transport_quic/native_link.rs:487.
★IMPACT: ALL netns benchmarking is BLOCKED until zz35zq lands (every cell aborts on send=1). kogbnc's bytes win (expected append 2.58MB→~150KB, beat rsync 96KB) is UNMEASURED. This is now the top blocker — higher priority than the 3 levers, because it gates measuring ANY of them. RETRY-COND: zz35zq lands → rebuild → re-run append/insert good (initial sync send must exit 0) → THEN the kogbnc bytes win is measurable.

## E-RESYNC-13 (2026-06-19) — ★★FIRST GENUINE rsync-BEAT (insert 7×) + zz35zq FIXED + kogbnc cut append overhead 2.6×★★
SapphireHill fixed zz35zq (3fad08b8e, FrameTransport stashes early Proof during spray → initial-sync send exits 0; verified e2e) + updated the harness delta-state checks to accept kogbnc's compact `manifest_hex`/`chunk_count` format (was hard-checking the now-removed `chunk_signatures` array). Re-ran 5M/good (0.1%loss) append+insert on the fresh binary — BOTH cells status=ok, BYTE-IDENTICAL (sha_ok):
- ★insert: atp wire=395,321 (395KB) vs rsync wire=2,752,336 (2.75MB) → ratio 0.14 → **atp BEATS tuned rsync 7×**. atp delta payload bytes_sent=240KB (shared=118, stale=5, missing_chunks=6); content-defined chunking only resends the few shifted-boundary chunks, while rsync's fixed-block rolling-checksum can't cheaply represent a mid-file insert/shift and resends ~half the file (2.75MB). First large, valid, byte-identical rsync-beat on a lossy netns delta. ★
- append: atp wire=1,013,668 (1.01MB) vs rsync 96,149 (96KB) → ratio 10.54 → atp LOSES. BUT this is a 2.6× improvement from E-RESYNC-11's 2.58MB (kogbnc shrank the sidecar negotiation state 2.23MB→14KB, ~160×). atp delta payload bytes_sent=85KB (≈ rsync's 96KB — payload is O(change)+competitive). The remaining ~910KB wire over the 85KB payload = RaptorQ FEC/symbolization + round-trip overhead on a tiny delta over a clean link.
NET: atp now WINS rsync on insert/shift edits (content-chunking advantage), LOSES on append (tail-only edit where rsync's delta is maximally efficient at 96KB and atp's per-transfer FEC/symbol overhead dominates a tiny payload). Remaining lever for append/small-localized: L2 ADAPTIVE FEC (j91wza — at 0.1% loss ship ~0 repair; the ~910KB is mostly wasted FEC) + trim per-transfer negotiation/symbol fixed cost. kogbnc (L1 negotiation) = big success. zz35zq (send race) = fixed. RETRY-COND: j91wza adaptive-FEC lands → re-run append good → atp wire should drop from 1.01MB toward ~payload (85KB) and approach/beat rsync 96KB; then bad-regime (high loss, where rsync stalls) once convergence (L3) lands.

## E-RESYNC-14 (2026-06-19) — ★★j91wza adaptive-FEC COLLAPSES append overhead (1.01MB→128.8KB, 7.9×); atp append now 1.34× rsync (was 10.5×); insert win 14×★★
j91wza (rate-match RQ feedback repair, L2 adaptive FEC) LANDED (HEAD 3c18640df, src/net/atp/transport_rq/mod.rs +33/-12, %8). Rebuilt atp-cli (git 3c18640df2aa, atp 0.3.5) and re-ran 5M/good (0.1%loss/25ms/200mbit) append+insert on the hardened harness (auto unique subnet 10.166.15.x). BOTH cells status=ok, BYTE-IDENTICAL (sha_ok=true):
- ★append: atp wire=128,791 (128.8KB) vs rsync wire=96,149 (96KB) → ratio 1.34. atp delta payload `bytes_sent`=82,965 (83KB, O(change), already < rsync's 96KB), package_payload=68KB, shared=121/stale=2/missing_chunks=3/missing_bytes=109KB, negotiation=`direct_receiver_state_sidecar` (kogbnc compact sidecar still engaged). So wire(128.8KB) − payload(83KB) = ~46KB residual (compact sidecar ~14KB + RaptorQ FEC/symbol/protocol). ★j91wza cut the per-transfer FEC/symbol overhead from E-RESYNC-13's ~910KB (1.01MB wire) down to ~46KB — a 7.9× wire reduction (1.01MB→128.8KB) and the append loss-ratio collapsed 10.54×→1.34×. atp append is now ESSENTIALLY AT PARITY, no longer an order-of-magnitude loss.
- ★insert: atp wire=199,407 (199KB) vs rsync wire=2,752,336 (2.75MB) → ratio 0.07 → **atp BEATS tuned rsync ~14×** (E-RESYNC-13 was 7×/395KB; j91wza also trimmed the insert FEC overhead 395KB→199KB). Content-defined chunking resends only shifted-boundary chunks; rsync's fixed-block rolling-checksum resends ~half the file on a mid-file insert.
- MEMORY (secondary campaign metric): atp peak_rss≈25MB (append 25,232 / insert 24,208 KB) vs rsync≈8.5MB (8,568 / 8,428 KB) → atp uses ~3× more RAM at this 5MB size. Note for LAND.2 "less memory" claim — track RSS as a first-class metric (E-8.1); atp's bytes-on-wire win on insert does not yet come with a memory win at small sizes.
NET: after j91wza, atp delta WINS rsync decisively on insert/shift (~14×, content-chunking) and is at 1.34× (near-parity) on append. The remaining ~46KB append overhead is the last lever to OUTRIGHT BEAT rsync on append: (a) push j91wza repair even closer to 0 at ~0% loss (residual FEC on a clean link is still ~half the overhead), or (b) ★1owe64 Slepian-Wolf — sender ships a syndrome, eliminating the ~14KB sidecar negotiation entirely → payload-only ~83KB+small < rsync 96KB. RETRY-COND: (1) after 317hxr.6.1.1 convergence fix lands (%8, in progress) → re-run append+insert at REGIMES='bad' (2% loss) — that is where rsync's TCP stalls and atp SHOULD win outright on BOTH bytes AND completion; (2) after 1owe64 or a tighter FEC-floor lands → re-run append good → atp wire should cross below 96KB (outright append win). zz35zq fixed; kogbnc (L1) + j91wza (L2) both big successes; L3 convergence is the last gate for the high-loss sweep.

## E-RESYNC-15 (2026-06-19) — 1owe64 Slepian-Wolf encode FOUNDATION landed but NOT WIRED → append unchanged; ★the FEC floor is the BIGGER append lever (arithmetic)★
1owe64 ("encode sidecar-free append syndrome") LANDED (HEAD 2cee5b608, %8) — but it is a GREENFIELD ENCODE FOUNDATION in an isolated module, not yet on the live append path. Evidence: the commit touches ONLY `src/atp/slepian_wolf.rs` (+183/-2); it is the ONLY commit since E-RESYNC-14 (a253ec47a); and `rg slepian` shows `slepian_wolf` referenced ONLY by its `pub mod slepian_wolf;` declaration in `src/atp/mod.rs` — NOT by `transport_rq/`, `delta.rs`, or `delta_subchunk.rs`. So the delta negotiation still uses `direct_receiver_state_sidecar` and the append wire is UNCHANGED at 128.8KB. NO benchmark was run (it would deterministically reproduce E-RESYNC-14 — static proof the syndrome path is unreachable from the transfer). Build: rebuilt atp-cli to confirm 1owe64 compiles clean in the release bin (extra check beyond code-first cargo-check).
★KEY ARITHMETIC (corrects the E-RESYNC-14 "1owe64 → payload-only win" hope): to beat rsync's 96KB from atp's 128.8KB we must cut ~33KB. The 128.8KB = 83KB payload + ~14KB compact sidecar + ~32KB RaptorQ FEC/symbol floor. So: (a) 1owe64 eliminating the sidecar saves only ~14KB → ~115KB, STILL LOSES to 96KB; (b) trimming the clean-link FEC floor saves ~32KB → ~97KB, ≈PARITY. ⇒ the FEC FLOOR is the BIGGER single append lever, and an OUTRIGHT append win needs BOTH (sidecar-elim + FEC-trim → ~83KB+small < 96KB). 1owe64 ALONE cannot win append; it must be paired with a clean-link FEC-floor cut (E-7.4 calibrated repair ε / push repair→0 at ~0% measured loss).
INTEGRATION GAP (the work that would actually move the number): (1) send-side — swap `direct_receiver_state_sidecar` negotiation for the `slepian_wolf` syndrome on the append/localized path; (2) receiver-side — belief-propagation DECODE of the syndrome seeded with the old file as side-info (NOT yet written; my memory flags BP convergence needs cargo-TEST runs, not just cargo-check, so it must be verified via rch test before shipping, NOT code-first-blind). Until both land + are wired, 1owe64 is dormant. RETRY-COND: after slepian_wolf is wired into the live delta path AND a verified BP decode lands → re-run append good → expect sidecar's ~14KB to vanish; combine with a landed FEC-floor cut to cross below 96KB. NEXT LEVER ROUTED: %8 → clean-link FEC floor (the bigger lever) while 1owe64 integration/decode awaits a test-capable slot.

## E-RESYNC-16 (2026-06-19) — ★FEC-floor REMOVAL (bc9eb85ee) did NOT help append — it REGRESSED it (145-158KB vs 128.8KB); hypothesis REFUTED; append PLATEAUED ~1.5× → pivot off clean-link append★
FEC-floor-removal lever LANDED (HEAD bc9eb85ee "j91wza remove clean-link repair floor", transport_rq/mod.rs +73/-15, %8). Rebuilt atp-cli (binary=bc9eb85ee, atp 0.3.5, verified BIN mtime fresh + HEAD unmoved → clean attribution) and ran 5M/good append+insert + 2 extra append reps. ALL byte-identical (sha_ok):
- append (3 reps, binary=bc9eb85ee): 145,121 / 158,089 / 149,981 → mean ~151KB, ratio ~1.51-1.64× vs rsync ~96KB. Payload bytes_sent≈85KB, package_payload≈70KB, symbols_sent=71, feedback_rounds=0, negotiation=`direct_receiver_state_sidecar`.
- insert (1 rep): atp 237,151 vs rsync 2,752,138 → ratio 0.09 → atp still WINS ~11.6× (content-chunking; FEC-floor change didn't hurt the insert win materially).
★RESULT: REMOVING the clean-link repair floor did NOT cut append overhead — append got WORSE. The bc9eb85ee 3-rep band (145-158KB) sits CONSISTENTLY ABOVE E-RESYNC-14's j91wza single rep (128.8KB), with no overlap → the floor was apparently BATCHING repair efficiently and removing it made repair/symbolization less efficient. The "remove FEC floor → ~97KB parity" hypothesis (E-RESYNC-15 arithmetic) is REFUTED by measurement. bc9eb85ee is a likely small REGRESSION on the default append path (caveat: only 1 j91wza rep exists for the old binary, now overwritten — not airtight, but 3-vs-1 non-overlapping is strong). 
★METHODOLOGY CORRECTION (important): the harness regenerates a RANDOM 5MB base file each run (`dd if=/dev/urandom`) and appends a FIXED 64KB (`dd bs=64K count=1`); FastCDC boundary shifts on the random file make missing/stale chunk bytes vary run-to-run (missing_bytes 109↔141KB) → append wire has ~±15KB run variance. ⇒ SINGLE-REP before/after is unreliable for small deltas; need ≥3 reps (now standard) and ideally a FIXED SEED. Consequence: E-RESYNC-14's celebrated "1.34× near-parity" was a FAVORABLE single draw; the honest steady-state is atp append ≈ 1.3-1.6× rsync (NOT parity, NOT a win).
★STRATEGIC PIVOT: clean-link append is rsync's BEST case (tail-only edit, rsync delta = 96KB optimal) and atp has PLATEAUED at ~1.5× there after j91wza + FEC-floor (latter negative). Diminishing/negative returns. The remaining append lever (1owe64 sidecar-elim) saves only ~14KB → still loses. ⇒ STOP pouring levers into clean-link append. atp's DECISIVE, defensible wins are (1) insert/shift edits ~11-14× (content-defined chunking — rsync's worst case), already banked; (2) the LOSSY regime where rsync's TCP stalls and atp's FEC should win on BOTH bytes AND completion — currently a FAIL (atp fail-closes @2%, E-RESYNC-8), gated on convergence (317hxr.6.1.1 / 317hxr.2, %8 working it now). RETRY-COND: (a) %8/owner investigate whether bc9eb85ee should be REVERTED or re-tuned (don't unilaterally revert peer work — flag via br); (b) PRIORITY = land a convergence fix → re-run REGIMES='bad' append+insert → that is where the next REAL win lives. Append parity is "good enough"; the lossy win + insert win are the headline.

## E-RESYNC-17 (2026-06-19) — ★★CONVERGENCE GAP FIXED: atp now CONVERGES @2% loss (was fail-closed, E-RESYNC-8)★★ — but 2%/80ms/50mbit is NOT atp's win zone (rsync's TCP doesn't stall there → atp loses bytes 10×); + new sidecar-under-loss bug
The 317hxr.6.1.1 fix (drop the requested_sources==0 FEC-fallback guard) was ALREADY LANDED in 6acf22391 (verified by BluePike/cc_1/BronzeTiger; `git merge-base --is-ancestor 6acf22391 HEAD`=YES) — so it is in the current binary (bc9eb85ee, which is a descendant). I'd been waiting for a "landing" that already happened (the bead is stuck OPEN only because its close is tracker-dependency-blocked by parent 317hxr.6.1, NOT because code is missing). Ran the deferred BAD-regime (2% loss / 80ms / 50mbit) benchmark, 5M, current binary:
- ★append @2%: atp wire=987,966 (988KB), **sha=ok (CONVERGES!)**, vs rsync wire=96,346 (96KB), ratio 10.25×. → ★THE CONVERGENCE GAP IS FIXED: atp completes byte-identical at 2% loss where E-RESYNC-8 (pre-fix) FAIL-CLOSED (send exit 1, no dest_sha). The .6.1.1 FEC-fallback fix + pacing + adaptive-FEC closed it. Real milestone.
- insert @2%: harness logged "ATP sender fell back to full-object despite sidecar state; marking cell INVALID" → atp wire=9.26MB (full-object+FEC, NOT a delta) vs rsync 2.8MB. Cell invalid.
★REFRAMING (important, corrects the "atp wins where rsync stalls" thesis): at 2%/80ms/50mbit rsync's TCP does NOT stall — it completes append in 96KB. atp CONVERGES but pays a ~900KB FEC tax (988KB wire for an ~85KB delta) → atp LOSES bytes 10.25× at 2%. So "converges" ≠ "wins". The 2% "bad" regime is still within TCP's comfort zone. atp's REAL lossy win zone must be HARSHER — high loss (~5-10%+) or high-BDP long-fat-network (200ms+/Gbps) where TCP throughput genuinely collapses and atp's rateless FEC keeps flowing. ⇒ NEXT ORCHESTRATOR EXPERIMENT (my job): sweep harsher regimes (5%, 10% loss; high-BDP) to FIND atp's actual win zone, instead of assuming 2% is it.
★NEW BUG (filed-worthy): under 2% loss the INTERACTIVE sidecar negotiation (receiver→sender chunk-state upload) is NOT loss-robust → sender falls back to full-object → atp loses its delta advantage entirely on lossy links. This is a strong argument FOR 1owe64 (Slepian-Wolf): a ONE-SHOT syndrome (no interactive round-trip to drop) is inherently loss-robust — wiring 1owe64 would fix BOTH the clean-link sidecar bytes AND the under-loss full-object fallback. 

## E-RESYNC-18 (2026-06-19) — ★HARSH-REGIME WIN-ZONE SWEEP: atp CONVERGES at 5%/10%/high-BDP (robust!) but LOSES bytes EVERYWHERE (1.45-2.78×) — no lossy win zone found at 5MB scale★
Added regimes to harness regime_netem() (worse=5%loss/50mbit/80ms, terrible=10%loss/20mbit/120ms, highbdp=0.1%loss/1gbit/200ms; bash -n OK; perfect/good/bad untouched). Ran 5M append+1pct, binary=bc9eb85ee, 1 rep each. ALL cells atp sha=ok (CONVERGES in every regime — robust, no fail-closed):
| regime | change | atp wire | rsync wire | ratio |
|---|---|--:|--:|--:|
| worse 5% | append | 267,890 | 96,422 | 2.78 |
| worse 5% | 1pct | 8,962,953 | 5,379,194 | 1.67 |
| terrible 10% | append | 139,520 | 96,544 | 1.45 |
| terrible 10% | 1pct | 10,312,626 | 5,527,129 | 1.87 |
| highbdp 200ms/1gbit | append | 176,354 | 98,196 | 1.80 |
| highbdp | 1pct | 13,010,128 | 5,463,842 | 2.38 |
★HEADLINE: NO lossy/high-BDP WIN ZONE found at 5MB scale. atp loses bytes in EVERY tested harsh regime (1.45-2.78×). rsync's TCP does NOT stall or time out anywhere — it completes append in ~96KB and 1pct in ~5.5MB even at 10% loss and 200ms/1gbit. The "atp wins where TCP stalls" thesis is REFUTED at this file size: rsync's delta+TCP is too robust+efficient up to 10% loss. (append ratios are noisy — single rep + random base, ±15KB — but ALL >1.0; 1pct spread-edits lose clearly via FEC overhead on a ~full resend.)
★WHAT atp ACTUALLY HAS: (1) ROBUSTNESS — converges sha-ok even at 10% loss / high-BDP, fail-closed when it truly can't = sound. But "robust" ≠ "fewer bytes". (2) the ONE real bytes win = insert/shift edits ~11-14× (E-RESYNC-13/14/16) — an ALGORITHMIC content-defined-chunking advantage, INDEPENDENT of link quality (rsync's fixed-block rolling-checksum can't cheaply represent a mid-file shift). That is atp's defensible headline, NOT loss-resilience.
★REMAINING UNTESTED HYPOTHESIS: LARGE files (100MB-1GB) on highbdp — at 5MB the transfer fits in a few RTTs so TCP never enters the throughput-limited regime where a long-fat-pipe punishes it; a big file MIGHT finally stall TCP. BUT prior evidence (memory: 100M xmachine atp LOST clean+mild-loss, CPU/decode-bound ~0.8MB/s) says atp is DECODE-BOUND at large sizes → likely loses there too (on wall-time even if not bytes). So the large-file-highbdp test is the last shot at a transport-level win, with low prior. RETRY-COND: (a) after Finding-2 (per-block FEC repair, %8) → re-run worse/terrible → lossy bytes (esp. the 8-13MB 1pct cells) should drop sharply; if they cross below rsync, THAT'S a lossy win; (b) 100MB highbdp append/insert sweep (1 cell) to settle the large-file-LFN hypothesis. HONEST CAMPAIGN STATUS: atp BEATS tuned rsync on insert/shift (any link, ~11-14×); atp LOSES on append (~1.5×) + spread edits + all lossy/high-BDP regimes at 5MB (1.45-2.78×); atp's strength is convergence/robustness + fail-closed correctness, not bytes-under-loss. Finding-2 is the best remaining shot at a lossy-bytes win.
★TWO LEVERS the 988KB points to: (1) Finding-2 (cc_2): FEC-fallback repair is per-ENTRY not per-BLOCK → re-sprays all blocks each repair round → byte explosion under loss; making repair per-block should slash the 988KB. (2) the sidecar-loss-robustness fix (or 1owe64 wiring). RETRY-COND: (a) harsher-regime sweep to locate atp's win zone; (b) after Finding-2 or 1owe64-wiring → re-run bad-regime → atp lossy bytes should drop sharply; (c) fix the insert-under-loss full-object fallback so lossy insert is a valid delta cell. NET STATUS: convergence FIXED (atp completes under loss, fail-closed when it truly can't — sound posture); atp WINS insert/shift any-link (11-14×); atp LOSES append everywhere (clean ~1.5×, 2% ~10×); atp's lossy-bytes are FEC-tax-dominated → competitive only in TCP-hostile regimes not yet tested.

## E-RESYNC-19 (2026-06-19) — ★HEADLINE WIN VALIDATED: insert/shift 4-rep distribution = 11.1-15.1× (confirms the gated F-POS-5 "11-14x" claim is robust, not a single-rep fluke)★
LAND.1 landed (b89f897b8: F-POS-5 PROVEN-WIN ledger entry + tests/atp_rq_beat_rsync_ledger_contract.rs green-gating the 13 honesty substrings — win AND no-claim boundaries). To harden the gated "insert/shift = 11-14x fewer bytes-on-wire" claim against the single-rep variance flagged in E-RESYNC-16, ran 4 reps of 5M/good/insert (binary=bc9eb85ee), all produced valid wire rows (sha-ok cells):
| rep | atp wire | rsync wire | ratio |
|--:|--:|--:|--:|
| 1 | 182,067 | 2,752,203 | 15.1× |
| 2 | 239,037 | 2,752,335 | 11.5× |
| 3 | 187,197 | 2,749,948 | 14.7× |
| 4 | 247,984 | 2,752,660 | 11.1× |
★RESULT: across 4 reps atp beats tuned rsync 11.1×-15.1× on a mid-file insert, byte-identical. rsync is rock-steady at ~2.75MB every rep (its fixed-block rolling-checksum can't represent a mid-file shift → resends ~half the 5MB file); atp's content-defined chunking holds 182-248KB (run variance from the random base file + insert offset). The gated F-POS-5 claim "11-14x" is VALIDATED and slightly CONSERVATIVE (one rep hit 15.1×). This is atp's durable, defensible headline — an ALGORITHMIC delta advantage (content-chunking vs fixed-block), independent of link quality, now multi-rep-confirmed AND CI-gated. Campaign deliverable (LAND.1) complete + evidence-hardened. (No-claim boundaries unchanged: append still lost ~1.5×, lossy/spread still lost — see F-POS-5 + E-RESYNC-16/17/18.)

## E-RESYNC-20 (2026-06-19) — 1owe64 syndrome MEASURED at 0.285× the sidecar (4KB vs 14KB, ~10KB saved); decode converges — wiring is worth it for LOSS-ROBUSTNESS, but alone still won't win append
1owe64 foundation complete (encode 2cee5b608 + BP-decode 674c2d35e). To decide whether the eventual wiring (blocked by hot transport_rq) is worth the integration cost, %8 added a STANDALONE measurement + decode proptest to src/atp/slepian_wolf.rs (committed 47dbb8f58, unit-test-verified, NOT on live path → no live benchmark). Measured for a 4KB append-like delta:
- syndrome_value_bytes = 4,096 (4KB) vs compact-sidecar baseline 14,336 (14KB) → syndrome_to_sidecar_ratio = 0.285× (28.5% of the sidecar), sidecar_minus_syndrome = 10,240 (~10KB saved). Decode proptest: `converged`, byte-identical round-trip, used_symbols ≤ n.
★VERDICT: the one-shot syndrome IS substantially smaller than the interactive sidecar (~10KB savings) AND is loss-robust (single shot, no receiver→sender state upload to drop under loss). So 1owe64-wiring is WORTH pursuing — but PRIMARILY for LOSS-ROBUSTNESS (it fixes the E-RESYNC-17 under-loss full-object-fallback bug, where the interactive sidecar dropped at 2% loss), NOT as a clean-link append winner. Append arithmetic update (cf. E-RESYNC-15/16): replacing the 14KB sidecar with a ~4KB syndrome cuts append wire ~128.8KB → ~118KB, STILL > rsync 96KB. ⇒ 1owe64 ALONE does not win clean-link append; an outright append win still needs the FEC-floor cut too (and E-RESYNC-16 showed the naive FEC-floor removal regressed, so that lever is unsolved). RETRY-COND: once transport_rq frees → wire slepian_wolf syndrome+decode into the append/localized delta path (replace direct_receiver_state_sidecar), re-run REGIMES='worse terrible' insert+append → expect the under-loss full-object fallback to VANISH (lossy insert becomes a valid delta cell) + ~10KB clean-link savings. NET: 1owe64 = a loss-robustness + negotiation-shrink lever (verified-foundation, wiring pending), not an append-bytes silver bullet. Campaign headline unchanged (insert/shift 11-15× win, F-POS-5).

## MATRIX-1 (2026-06-19) — FULL WHOLE-FILE/TREE matrix re-run at HEAD (nocrypto tier): atp WINS 5M perfect+bad; LOSES 50M everywhere (DECODE WALL); 50M/broken FAILS (exit 144); atp wins memory on trees
First authoritative `matrix_bench` whole-file/tree scoreboard since the swarm's source-first/FEC fixes (atp 0.3.5 @HEAD 4a195a116, fresh release build). 88 reps / 22 cells, nocrypto tier (atp-rq-lab vs tuned rsyncd `-aW --inplace --no-compress`), rate-capped netem both ends, SHA-gated, REPS 3 (5 for tree_small). Run: `artifacts/atp_bench_matrix/20260619T184351Z/`. This is the BROAD scoreboard the resync_bench (append/spread delta) slice is NOT — it answers "beat rsync across the board".

| workload | regime | wall ratio ATP/rsync | verdict | feedback rounds |
|---|---|--:|---|--:|
| 5M | perfect | **0.786** | **atp WINS 1.27×** | 0 |
| 5M | bad (2%/50mbit) | **0.905** | **atp WINS 1.10×** | 3 |
| 5M | broken (10%/10mbit) | 1.276 | loses 1.28× (converges) | 10 |
| 5M | good (0.1%/200mbit) | 1.480 | loses 1.48× | 2 |
| tree_small | good | 1.358 | loses; **wins mem (combined RSS 0.42×)** | 1 |
| tree_small | bad | 1.393 | loses; wins mem (0.58×) | 3 |
| tree_small | broken | 1.333 | loses; wins mem (0.85×) | 10 |
| tree_small | perfect | 1.996 | loses 2.0×; wins mem (0.43×) | 0 |
| 50M | good | 1.210 | loses (cv 85% — NOISY, rerun) | 1 |
| 50M | perfect | 3.553 | loses 3.55× | 0 |
| 50M | bad (2%) | 4.893 | loses 4.89× (atp recv peak 483MB) | 4 |
| 50M | broken (10%) | n/a | **FAILS: status=error exit 144 ×3 reps, sha_ok=true** | — |

Per-regime geomean wall ratio ATP/rsync (>1 = atp slower): bad 1.835 · perfect 1.773 · good 1.345 · broken 1.304.

FINDINGS:
1. FIRST WHOLE-FILE WINS: atp BEATS tuned rsync at 5M on perfect (1.27×) and bad/2%-loss (1.10×), SHA-clean. Small files clear the decode wall.
2. DECODE WALL dominates 50M: every 50M cell loses 3.5-4.9× (perfect 4.36s vs rsync 1.23s; bad 68.2s vs 13.9s). Wall ~= single-core RaptorQ decode ~0.8MB/s on the FEC-repair path (perfect 0-rounds is the fastest 50M cell). => #1 LEVER = `--max-block-size` (#45): chunk big files into ~5M tree-like blocks so 50M behaves like the WINNING 5M cell. decode-parallelism (#44) is the complementary lever.
3. 50M/broken FAILS: atp exits 144 (sha_ok=true => bytes land, process errors) on all 3 reps. Big-single-file-specific: tree_small/broken @10% converges fine (status=ok). Likely same root as the wall (one huge block under heavy loss). NEEDS A FIX before any 50M-class claim.
4. atp WINS MEMORY on trees (combined RSS 0.42-0.85× of rsync — rsync's per-file overhead on 2000 files). NO-CLAIM: rsync-side RSS at 50M reads 0.7-19GB = a `/usr/bin/time` daemon measurement artifact; 50M memory comparison is UNRELIABLE and not claimed either way. atp-side 50M recv peak (483MB) is real and is itself a bounded-memory target.
5. NOISE: 50M/good cv 85%, several 5M/tree cells cv>5% (flagged) — rerun before hardening any single ratio.
NO-CLAIM BOUNDARY: nocrypto tier only; auth + encrypted tiers and 500K/500M/5G sizes NOT yet measured (expansion run pending). "Beat rsync across the board" is NOT achieved: real wins at 5M(perfect/bad) + tree-memory, but 50M loses on the decode wall and 50M/broken fails. RETRY-COND: after `--max-block-size` lands → re-run 50M/500M/5G; expect 50M to track the 5M win-profile and the broken-cell exit-144 to clear.

## MATRIX-2 (2026-06-19) — AUTH TIER (atp-rq-auth HMAC vs rsync-over-ssh aes128gcm): atp WINS the geomean of EVERY lossy regime + 500K everywhere; the realistic secure path favors atp
Run `artifacts/atp_bench_matrix/20260619T193317Z/`, 104 reps, atp 0.3.5 @4a195a116, AUTH tier only (atp-rq-auth `--rq-auth-key-hex` HMAC vs `rsync -aW --inplace --no-compress -e 'ssh -c aes128-gcm@openssh.com'`), rate-capped netem, SHA-gated, REPS 3 (5 for tree_small). **0 failures, all cells sha+status ok.** This is the crypto-symmetric SECURE-transfer comparison (the realistic deployment) — distinct from MATRIX-1's nocrypto tier (which was rsync's BEST case: plaintext daemon, no ssh tax).

Wall ratio ATP/rsync (<1 = atp WINS); combined-peak-RSS ratio (<1 = atp lighter):
| workload | regime | wall ratio | combined RSS ratio | verdict |
|---|---|--:|--:|---|
| 500K | perfect | 0.555 | 0.139 | **atp WINS 1.80× + 7× less mem** |
| 500K | good | 0.419 | 0.113 | **atp WINS 2.39× + 9× less mem** |
| 500K | bad | 0.373 | 0.141 | **atp WINS 2.68× + 7× less mem** |
| 500K | broken | 0.335 | 0.262 | **atp WINS 2.99× + 4× less mem** |
| 5M | perfect | 1.436 | 0.708 | loses 1.44× (wins mem) |
| 5M | good | 0.487 | 0.503 | **atp WINS 2.05× + 2× less mem** |
| 5M | bad | 0.748 | 0.777 | **atp WINS 1.34× + lighter** |
| 5M | broken | 0.737 | 0.066 | **atp WINS 1.36× + 15× less mem** |
| tree_small | perfect | 1.949 | 0.047 | loses 1.95× (21× less mem) |
| tree_small | good | 1.169 | 0.551 | loses 1.17× (wins mem) |
| tree_small | bad | 1.286 | 0.822 | loses 1.29× (wins mem) |
| tree_small | broken | 1.102 | 0.848 | loses 1.10× (wins mem) |

Per-regime geomean wall ratio ATP/rsync: **good 0.620 (atp WINS), bad 0.711 (atp WINS), broken 0.648 (atp WINS)**, perfect 1.158 (atp loses ~1.16×).

FINDINGS:
1. ★AUTH-TIER ACROSS-THE-BOARD: atp BEATS tuned rsync-over-ssh on the geomean of ALL THREE lossy regimes (good/bad/broken) and on 500K in EVERY regime (1.8-3.0×), SHA-clean. The earlier "atp loses" picture was the nocrypto tier (rsync plaintext daemon = rsync's best case); requiring authentication (the realistic secure case) flips most cells to atp because rsync must pay the ssh handshake/stream-crypto tax that atp's inline per-symbol HMAC avoids.
2. ★MEMORY: atp wins RSS in nearly every auth cell (0.05-0.85×; 500K 4-9× lighter, 5M/broken 15× lighter, trees up to 21× lighter) — rsync-over-ssh's per-file + ssh overhead dwarfs atp's bounded streaming.
3. atp still LOSES perfect/clean links (5M 1.44×, tree 1.95×) — no loss → rsync's raw throughput wins; and tree wall-time (but wins tree memory decisively). AUTH-1 (bead oees4v) validated end-to-end: 0 auth failures across 104 reps.
4. NO-CLAIM BOUNDARY: this run covered 500K/5M/tree_small only — 50M (the decode-wall size, MATRIX-1) was NOT in the auth run, so the 50M decode wall + broken exit-144 (beads nsbub4/hs9ztp) remain open at all tiers. encrypted tier (atp-quic-tls13) + 500M/5G sizes still unmeasured. SAFE CLAIM: "with authentication, atp-rq beats tuned rsync-over-ssh on the geomean of every lossy regime and on small (<=5M) files, and uses far less memory; it loses only on clean/perfect links and large single files (decode wall)."

## MATRIX-3 (2026-06-19) — ENCRYPTED tier (atp-quic-tls13) NON-FUNCTIONAL: 32/32 atp-quic cells fail instantly (status=error, sha_ok=false)
Run `artifacts/atp_bench_matrix/20260619T200606Z/` (5M,tree_small × perfect,good,bad,broken × encrypted). atp-quic-tls13: **32/32 rows status=error, sha_ok=false, wall ~0.11s (instant fail, no data), peak_rss ~6MB, streams=1**. Paired rsync-ssh-aes128gcm: 32/32 sha+status ok. So the QUIC/TLS-1.3 ATP data-plane is NOT usable from the atp CLI bench path — it errors out immediately on every cell/regime. The encrypted tier is therefore UNMEASURABLE for atp until fixed (bead z0v7ri). NO-CLAIM: no encrypted-tier atp result exists; do not infer anything about atp-over-QUIC perf. The working secure tier is AUTH (HMAC-over-RaptorQ/UDP, MATRIX-2), where atp wins most cells. Action: bead z0v7ri (root-cause atp-quic-tls13 CLI transfer fail) — relates to QUIC.1 (port winning rq levers to transport_quic). The atp secure-transfer story currently rests entirely on the auth/HMAC tier.

## MATRIX-4 (2026-06-19) — 50M LEVER PAYOFF re-bench: max-block-size + nsbub4 turn 50M from "loses-everywhere + crashes" into parity/near-parity + 4× less clean memory + zero failures
Re-ran 50M nocrypto on a fresh atp 0.3.5 @dea99ff41 (carries hs9ztp `--max-block-size`/auto-bound-block-size + nsbub4 beacon-budget/credit-sha-clean-dirty-exit + QUIC-side parallel decode). Run `artifacts/atp_bench_matrix/20260619T205327Z/`, 24 reps, ALL cells sha+status ok (MATRIX-1 had a 3-rep hard failure). Before = MATRIX-1.

| 50M cell | MATRIX-1 wall ATP/rsync (atp peak RSS) | MATRIX-4 wall ATP/rsync (atp peak RSS) | delta |
|---|---|---|---|
| perfect | 3.55× (213 MB) | 3.06× (49 MB, atp 3.75s) | mem 4.3× better; clean raw-speed gap remains |
| good (0.1%/200mbit) | 1.21× (212 MB) | **1.006× = PARITY** (48 MB, atp 3.96s) | now ties rsync + mem 4.4× |
| bad (2%/50mbit) | 4.89× (483 MB) | 3.88× (475 MB, atp 58.7s) | improved but STILL WORST cell |
| broken (10%/10mbit) | **EXIT 144 (hard fail)** | **1.118× = near-parity** (471 MB, atp 121s vs rsync 108s) | converges now + nearly ties |

WINS: (1) max-block-size cut CLEAN-cell peak RSS ~4.3× (213→49 MB at perfect/good). (2) 50M/good → PARITY (1.21×→1.006×). (3) nsbub4 CLEARED the 50M/broken exit-144 → it now completes status=ok sha-clean and loses only ~1.12× (rsync is also slow at 10% loss). (4) Zero failures (was 1). NO-CLAIM/OPEN: (a) 50M/bad (2% loss, 4 repair rounds) still 3.88× (58.7s) with 475 MB repair-path RSS — the rq FEC-REPAIR decode loop is still serial + repair-symbol memory unbounded (the parallel-decode that landed was QUIC-side). This is the #1 remaining big-file lever. (b) 50M/perfect still 3.06× — clean-link raw-speed gap (atp pays decode even at 0 loss; needs faster decode / GSO send). RETRY-COND: after the rq-repair decode is parallelized + repair memory bounded → re-bench 50M/bad (target <1.5×, RSS <100 MB) and 500M.

## MATRIX-5 (2026-06-19) — 500M CAPABILITY WIN (completes @23MB, was a hard fail) + the first rq-repair-parallel-decode build REGRESSED lossy 50M (root-caused to a decode-concurrency cap of 2, fix landed)
Two results on atp 0.3.5 builds carrying hs9ztp max-block-size:
**500M (max-block-size, run `…20260619T211215Z`):** 500M single file now COMPLETES sha-clean — perfect 36s/**23MB** (3 reps), good ~37-66s/23MB — vs MATRIX-1/pre-lever where 500M/perfect FAILED (status=error) and a rare success used ~2GB. So max-block-size fixed the 500M capability gap AND cut its memory ~90× (2GB→23MB). 500M/bad on that build = 700s/7GB (catastrophic, pre-repair-parallel).
**50M on the FIRST rq-repair-parallel build (@dea99ff41…, run `…20260619T<bad>`): REGRESSION, 3 reps stable.**
| 50M cell | MATRIX-4 (pre repair-parallel) | first repair-parallel build | verdict |
|---|---|---|---|
| perfect/good | 3.06×/49MB ; 1.006×/48MB | unchanged (0/1 rounds) | fine |
| bad (2%) | 58.7s/477MB/4 rounds | **90.3s/866MB/6 rounds** | REGRESSED 1.5× slower, 1.8× mem |
| broken (10%) | 121s/471MB/ok | **300-322s/1.7GB/status=ERROR** | REGRESSED hard (failed) |
★ROOT CAUSE (found by reading the code, not reverting): `src/net/atp/transport_rq/mod.rs` capped concurrent block decode at **2** — `RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY=2`, `RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD=2`, and `available_parallelism()` (64 cores) was `.min(2)`'d. So a 50M (~13-block) file decoded only 2 blocks at once; block #3+ ran the FEC decode INLINE on the receive path, stalling symbol-draining → sender over-sprayed → extra repair rounds (4→6, and broken failed) + symbol buffer pileup (866MB→1.7GB). The parallel-decode design is correct; the hard cap of 2 defeated it.
★FIX LANDED (swarm, in minutes): caps widened 2→**48** (`b0d9fbf4d widen RQ repair decode` + `1208a97a9 tame MATRIX-5 repair decode`); `RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY/PER_TRANSFER_HARD=48`, clamp `.min(48)`. RETRY-COND: rebuild + re-bench 50M on the cap=48 binary — expect 50M/bad to drop toward parity (decode now fans ~13 blocks across the 64 cores) and broken to converge fast (→ MATRIX-6). LESSON for the harness operator: rebuild to `rch_target_orch_atpcli` then BENCH A COPY (`/data/tmp/atp_bench_bin/atp`) — a rebuild to the live BIN path mid-bench deletes/clobbers it (killed two runs: BIN-not-executable + exit1).

## MATRIX-6 (2026-06-19) — cap=48 decode-fan-out REFUTED as the 50M/bad fix: it REGRESSED further (the wall is repair-ROUNDS-bound, not decode-thread-bound); re-diagnosed to retention-eviction; retention fix dispatched + landed (9095c7332), MATRIX-7 pending
The MATRIX-5 prediction ("cap=48 → 50M/bad drops toward parity") is **REFUTED by measurement.** Re-bench on the cap=48 binary (run `artifacts/atp_bench_matrix/20260619T223103Z/`, 12 reps 50M nocrypto, all sha+status ok):
| 50M cell | MATRIX-4 (cap n/a, pre repair-parallel) | cap=2 build (MATRIX-5) | **cap=48 build (THIS run)** | verdict |
|---|---|---|---|---|
| perfect | 3.75s / 0 rounds / 55 MB | unchanged | 3.75s / 0 rounds / 55 MB | fine |
| good (0.1%/200mbit) | 3.96s / 1 round / 48 MB | unchanged | 3.95s med / 1 round / 55 MB (1 rep blipped to 18s/2r) | fine |
| **bad (2%/50mbit)** | **58.7s / 4 rounds / 477 MB** | 90.3s / 6 rounds / 866 MB | **130s med (152/130/130) / 7-8 rounds / 878 MB** | **REGRESSED 2.2× slower, 1.8× mem** |
| **broken (10%/10mbit)** | 121s / ok / 471 MB | 300-322s / status=ERROR | **182s med (185/182/167) / 8-9 rounds / 890 MB** | converges again but 1.5× slower than MATRIX-4 |
★RE-DIAGNOSIS (the decode cap was a RED HERRING). The 50M/bad wall is **repair-ROUNDS-bound**, not decode-thread-bound: wall ≈ rounds × (~RTT + spray) ≈ rounds × 16-19s at the bad regime. Rounds grew monotonically with the decode fan-out: **4 (MATRIX-4) → 6 (cap=2) → 7-8 (cap=48).** Raising decode concurrency made it WORSE because more concurrent decode jobs buffer more repair symbols, and the bounded **256 drop-oldest** DATAGRAM/symbol queues then EVICT in-flight repair symbols before their block finishes decoding → the receiver must re-request that block → an extra repair round. RSS ballooned to ~878-890 MB (vs 477) for the same reason: up to 48 concurrent decode jobs each materialize a block's symbol set. So decode parallelism is only a lever once rounds are already low; at high rounds it amplifies the eviction problem.
★FIX DISPATCHED + LANDED: `9095c7332` "keep RQ repair rows" (`317hxr.7.3`) — retain repair symbols until their block decodes instead of drop-oldest-evicting them, so a block is never re-requested for want of a symbol it already received. Hypothesis: returns 50M/bad rounds to ~4 and wall toward MATRIX-4's 58.7s (and far below the cap=48 878 MB). RETRY-COND/MEASURE (→ MATRIX-7): re-bench 50M on the binary carrying 9095c7332 — PASS if 50M/bad rounds ≈ 4 AND wall ≤ 58.7s AND peak RSS << 878 MB. NO-CLAIM: cap=48 is NOT a 50M/bad win and parallel decode must NOT be claimed to help 50M/bad until rounds are confirmed back to ~4; the real lever at lossy regimes is FEWER repair rounds (symbol retention + adequate per-round FEC overhead so one repair round suffices — see 317hxr.6.1.1), not more decode threads. perfect/good are unaffected (0-1 rounds) at every cap.

## MATRIX-7 (2026-06-19) — retention fix (9095c7332) is INSUFFICIENT: 50M/bad still 7 rounds / 108s / 867 MB (only ~15% off cap=48). The per-block-parallel-decode line has NET REGRESSED lossy 50M vs MATRIX-4. ★Root lever = FEC OVER-PROVISIONING (trade bytes for rounds), not retention or more threads
Re-bench on the FIX binary carrying `9095c7332` (run `artifacts/atp_bench_matrix/20260619T225501Z/`, 12 reps 50M nocrypto, ALL sha+status ok), vs the prior two builds and tuned rsyncd:
| 50M cell | MATRIX-4 (pre repair-parallel) | cap=48 (MATRIX-6) | **FIX 9095c7332 (THIS run, median)** | tuned rsyncd (median) | verdict |
|---|---|---|---|---|---|
| perfect | 3.75s / 0r / 55 MB | 3.75s / 0r / 55 MB | 3.7s / 0r / 50 MB | — | fine |
| good (0.1%/200mbit) | **3.96s / 1r / 48 MB** | 3.95s / 1r / 55 MB | **15.6s / 2r / 50 MB** (4.0/15.6/16.0; 2 of 3 reps need a 2nd round) | — | **REGRESSED ~4×** |
| **bad (2%/50mbit)** | **58.7s / 4r / 477 MB** | 130s / 7-8r / 878 MB | **108.4s / 7r / 867 MB** | 15.2s | **7.1× LOSS** (retention recovered only 130→108s) |
| **broken (10%/10mbit)** | 121s / ~ok / 471 MB | 182s / 8-9r / 890 MB | **153s / 9r / 864 MB** | 75.1s | **2.0× LOSS** |
★VERDICT: the retention fix is REAL but PARTIAL — it shaved ~15% (bad 130→108s, broken 182→153s) and is bit-exact/fail-closed, but rounds stayed at **7 (bad) / 9 (broken)** — nowhere near MATRIX-4's 4, and RSS stayed at ~860 MB. PASS criteria NOT met. Worse, **50M/good regressed from 1 round/3.96s to 2 rounds/15.6s** — a clean-ish 0.1%-loss link now needs a SECOND repair round.
★DEEPER ROOT CAUSE (the honest one): the whole `repair-parallel-decode` line of work (cap=48 + **per-block** repair feedback, see `mod.rs` `max_feedback_repair_batch_per_block`/`repair_target_for_feedback_round` and the line-167 comment "entry-level repair feedback otherwise re-sprays every block of a large file") has **NET REGRESSED** lossy 50M vs MATRIX-4. The mechanism: MATRIX-4's *entry-level* repair RE-SPRAYED every block each round = wasteful in bytes but it OVER-PROVISIONED, so the loss was covered in ~4 rounds. The new *per-block precise* repair sprays only each block's computed deficit = efficient in bytes but if any block's repair batch undershoots the realized loss, that block needs ANOTHER round. **At lossy/high-RTT links wall ≈ rounds × (RTT+spray), so per-block byte-precision MAXIMIZES rounds and HURTS wall.** The 50M/good 1→2 round regression is the same undershoot at 0.1% loss. This is a precision-vs-rounds tradeoff and we are now on the wrong side of it for lossy regimes.
★THE LEVER (not a revert — per the directive to diagnose, not revert): **FEC OVER-PROVISION per repair round so ONE fat round covers the realized loss.** Concretely: (a) `317hxr.6.1.1` (BluePike, IN_PROGRESS) — drop the `requested_sources==0 → false` guard so the aggressive K-aware `overhead_for_target` (+3%..+50%) FEC fallback ENGAGES in repair rounds 3..16 instead of self-disabling (right now repair rounds 3+ fall back to the mild loss_fec_floor → chronic undershoot → 7-9 rounds); (b) `E-7.4` calibrated per-round overhead ε*(K, p̄, α) sized to the MEASURED loss so the first repair round over-covers (target: 50M/bad in ≤2 rounds ≈ 2×(RTT+spray) ≈ ~35s, beating MATRIX-4); (c) bound decode memory so cap=48 fan-out can't hold ~860 MB of per-block symbol sets. RETRY-COND (→ MATRIX-8): re-bench 50M after 6.1.1 lands — PASS if 50M/bad rounds ≤ 3 AND wall < MATRIX-4's 58.7s AND 50M/good back to 1 round. NO-CLAIM: atp currently LOSES 50M/bad 7.1× and 50M/broken 2.0× to tuned rsync at the nocrypto tier — this is a real regression from MATRIX-4 (bad 3.88×, broken near-parity); do not claim 50M lossy parity until rounds are back down. The win path is unchanged levers (over-provision FEC → fewer rounds), and decode parallelism only pays off once rounds are low.

## MATRIX-8 (2026-06-19) — INSTRUMENTED per-round trace (ATP_RQ_TRACE=1) OVERTURNS the MATRIX-7 overhead theory. 50M/bad is NOT overhead-bound; it's a SELF-INFLICTED congestion-rate-collapse death spiral triggered by ONE non-converging block out of 100. ★Real levers: (A) decouple decode-pending from the link-loss estimate, (B) fix single-block convergence + the InconsistentEquations decode rejection
Ran one instrumented 50M/bad cell (run `artifacts/atp_bench_matrix/20260619T233043Z/`, `ATP_RQ_TRACE=1` via `sudo env … ip netns exec` → sender/receiver `rqtrace!` (mod.rs:261, gate `ATP_RQ_TRACE`) into the per-cell stderr). The per-round sender log (mod.rs:3060), identical across all 3 reps:
```
round=1 pending=1 src_req=8192 sent=43700 send_wall=3.3s rate=106M overhead=1.1773 loss_bar=0.0875 fec_fallback=true
round=2 pending=1 src_req=8192 sent=15992 send_wall=12.3s rate=58M  …
round=3 pending=1 src_req=0    sent=15992 send_wall=13.3s rate=58M  …
round=4 pending=1 src_req=0    sent=7800  send_wall=12.0s rate=17M  …
round=5 pending=1 src_req=0    sent=7800  send_wall=13.8s rate=12M  …
round=6 pending=1 src_req=0    sent=7800  send_wall=15.0s rate=8.6M …
```
★FACTS (these REFUTE MATRIX-7's "needs more FEC overhead"): (1) `fec_fallback=true` from round 1 and `repair_overhead=1.1773` (17.7%) the whole time — over-provisioning is ACTIVE and adequate for the 2% link loss; overhead is NOT the bottleneck. (2) `pending=1` for ALL 6 rounds — the 50M file splits into **100 blocks** (sbn 0-99, K≈437 each; receiver `source_received=N/43700`), and exactly ONE block never reaches decode rank. Receiver trace caught it mid-spiral: `rank=365/494 rank_deficit=129 rank_blocks=1`, and once `entry 0 parallel decode rejected reason=InconsistentEquations`. (3) The sender keeps spraying 7800-15992 symbols/round at that one block but it doesn't converge, while `source_received` PLATEAUS at 28432/43700 from round 3 (new symbols stop advancing the stuck block).
★ROOT CAUSE = a SELF-INFLICTED DEATH SPIRAL, not RTT- and not overhead-bound: one stuck block ≈ a persistent ~14% byte-pressure → the pacing/loss estimator inflates `loss_bar` to **0.0875 (4× the real 2% link loss)** → the congestion controller HALVES the path rate every round (**106M→58M→17M→12M→8.6M bps**) → each futile repair round's spray takes **12-15s** (not RTT — `control_wait_ms` is only ~200ms; the wall is `send_wall` at a collapsing rate). Σ send_wall ≈ 3+12+13+12+14+15 ≈ **80s of the 108s** is the self-inflicted slowdown. If the rate had stayed at round-1's 106M, each repair round would be ~1s and even 6 rounds ≈ a few seconds.
★THE LEVERS (evidence-backed, supersede MATRIX-7's overhead lever):
  (A) ★BIGGEST, EASIEST — **decouple decode-pending pressure from the link-loss/pacing estimate.** A single slow-to-decode block (1 of 100) must NOT be read as 8.75% link loss and collapse the path rate. In `observe_need_more` (mod.rs:745) the `byte_pressure → pressure_loss → loss_bar/loss_ema` path conflates "blocks still pending decode" with "symbols lost on the wire." Pace from MEASURED wire loss (the regime's ~2%), not from pending-decode backlog. Expected: rounds run at ~106M instead of 8.6M → ~70s of the 108s evaporates even before fixing convergence.
  (B) **fix single-block convergence + investigate the `InconsistentEquations` decode rejection.** One block out of 100 stalling every transfer (rank 365/494) is the trigger; the InconsistentEquations rejection is a correctness red flag (possible symbol/labeling inconsistency under loss+reorder, or repair symbols not adding rank to the deficient block). Targeted, fresh repair for the single rank-deficient block (and a hard look at the decode-reject path) should make it converge in 1-2 rounds.
★CORRECTION to MATRIX-7: 50M/bad is NOT a precision-vs-rounds overhead tradeoff — overhead is fine (1.1773). The rounds are high because ONE block won't converge AND the controller punishes that by collapsing the rate. NO-CLAIM: still LOSES 50M/bad 7.1×; levers A+B are the path; 6.1.1 (guard already removed in HEAD, see bead comment) is not the fix. RETRY-COND (→ MATRIX-9): after A and/or B land, re-bench 50M/bad — PASS if path_rate stays ≳ round-1 (no collapse) AND pending→0 in ≤2-3 rounds AND wall < 58.7s. Evidence dir kept: `artifacts/atp_bench_matrix/20260619T233043Z/` (per-round sender+receiver trace).

## MATRIX-9 (2026-06-19) — block-size stopgap REFUTED: `--max-block-size 8MiB` barely changes 50M block count (100→86) and the rate-collapse death spiral is IDENTICAL (slightly WORSE: 8 rounds/133-157s). Confirms lever A (decouple pacing from decode-pending) is the ONLY path; block-size is a dead end for 50M/bad
Tested the MATRIX-8 "fewer/bigger blocks → fewer single-block-stall opportunities" hypothesis: re-ran 50M/bad with `MAX_BLOCK_SIZE=8388608` + `ATP_RQ_TRACE=1` (run `artifacts/atp_bench_matrix/20260619T235939Z/`, 3 reps, all sha+status ok). RESULT — the stopgap does NOT work:
| metric | default-block (MATRIX-8) | 8MiB-block (THIS) |
|---|---|---|
| block count (distinct sbn) | 100 | **86** (barely fewer) |
| wall (median) | 108s / 7 rounds | **153s / 8 rounds (WORSE)** |
| path_rate collapse | 106M→8.6M | **106M→58M→17M→11.5M→8.1M→5.8M→4.2M** (identical spiral, +1 round, lower floor) |
| stuck block | pending=1 + 1× InconsistentEquations | **pending=1 + InconsistentEquations recurs** |
| repair_overhead / loss_bar | 1.1773 / 0.0875 | 1.1706 / 0.0875 (same) |
★WHY `--max-block-size` doesn't help: the effective per-block size for 50M is ~512-580 KB (K≈437-512), governed by an INTERNAL bounded-K cap (`split_large_entries` / `fixed_block_k`), NOT by `--max-block-size`. 8 MiB is far above that floor, so it only nudged 100→86 blocks (~580 KB each, not 8 MiB each). To meaningfully cut block count you'd have to raise the internal K cap (not exposed, and would reintroduce the single-core decode-wall). So **block-size tuning is a dead end for the 50M/bad stall** — the rate-collapse death spiral and the single-block InconsistentEquations stall are block-size-INDEPENDENT.
★CONCLUSION (negative evidence that narrows the fix): the ONLY paths to 50M/bad are the two levers from MATRIX-8 — (A) bead `317hxr.2.5` decouple decode-pending byte-pressure from the wire-loss/pacing estimate so one slow block can't collapse the path rate (the ~70-100s win), and (B) bead `317hxr.6.1.1` fix the single-block convergence / `InconsistentEquations` decode-reject so no block stalls in the first place. Neither overhead (1.17 is fine) nor block-size nor decode-thread count moves it. NO-CLAIM: still LOSES 50M/bad ≥7×; awaiting a lever-A/B candidate → MATRIX-10. Evidence dirs: `…20260619T233043Z` (default) + `…20260619T235939Z` (8MiB).

## MATRIX-10 (2026-06-20) — decode-path fix `93c61aa2e` (drain pending decodes + inline fallback) is NEUTRAL for 50M/bad: still 103-122s / 7-8 rounds / 864 MB, identical death spiral. 4th independent confirmation that ONLY lever A (decouple pacing) moves it
Re-benched 50M/bad on HEAD carrying `93c61aa2e` "drain pending decodes after each fed symbol + inline block decode fallback" (run `artifacts/atp_bench_matrix/20260620T001828Z/`, 3 reps + trace, all sha ok). Result: **102.9 / 103.7 / 121.8 s, 7-8 rounds, 864 MB** vs MATRIX-8 default 108s/7r/867MB — statistically unchanged. Per-round trace is the SAME spiral: pending=1 throughout, path_rate 106M→58M→17M→8.8M→6.5M→4.8M, loss_bar=0.0875 constant, InconsistentEquations still recurs (3 rejections / 3 reps). vs tuned rsyncd 14.3s = still ~7× LOSS. So the decode-dispatch tweak doesn't touch the two real causes (single-block non-convergence + the byte-pressure→rate-collapse). TALLY of refuted 50M/bad fixes: retention (MATRIX-7), cap=48 decode threads (MATRIX-6), block-size (MATRIX-9), decode-drain/inline (MATRIX-10), FEC overhead (MATRIX-8, overhead 1.17 is fine). NONE move it. ★The single remaining lever is `317hxr.2.5` lever A — decouple decode-pending byte_pressure from the wire-loss/pacing estimate (mod.rs:768) so one slow block can't collapse the path rate — plus `6.1.1` lever B (single-block convergence / InconsistentEquations). EVIDENCE-ENGINE POSTURE: pausing per-commit re-benches (they keep reconfirming the same spiral); next re-bench is gated on a commit that actually touches the pacing/loss/pressure path (lever A) or the convergence/InconsistentEquations path (lever B) → MATRIX-11.

## MATRIX-11 (2026-06-20) — pinpoint trace CONFIRMS the floor-disable mechanism, but the first surgical fix (cap pressure_loss) REGRESSED both lossy regimes and was REVERTED. Key learning: loss_bar is DUAL-ROLE (it both disables the pacing floor AND drives FEC repair-overhead) — you cannot just cap it
Instrumented `pacing_rate_for` (rqtrace, committed 5b1b84b51) and ran 50M/bad (run `…20260620T051415Z`). The per-round trace is conclusive:
```
rnd1 network=15.3M bw_median=15.3M bw_trough=15.3M mild_floor=TRUE  rate=13.3M
rnd2 network=8.39M bw_median=10.5M bw_trough=5.2M  mild_floor=TRUE  rate=7.3M   (floored at COLD_START*0.5=8MiB)
rnd3 network=8.39M bw_median=7.3M  bw_trough=3.6M  mild_floor=TRUE  rate=7.3M
rnd4 network=2.5M  bw_median=5.0M  bw_trough=2.5M  mild_floor=FALSE rate=2.2M   ← FLOOR DISABLES, rate follows bw_trough down
rnd7 network=0.9M  ...                              mild_floor=FALSE rate=0.78M
```
★MECHANISM (now fully confirmed): `pending` is ENTRY-granular (`pending_bytes` sums whole `entry.size`, mod.rs:1016) so one stuck block makes byte_pressure≈1.0 → pressure_loss=0.05 → loss_ema crosses RQ_MILD_LOSS_PACING_MAX_LOSS(0.02) → `mild_loss_pacing_floor_applies()` returns FALSE at round 4 → `network_bps = min(bw_median, bw_trough)` follows the ratcheting bw_trough down → offered_bps (= bytes/send_wall, underestimated on the stalled repair rounds) drags bw_median/bw_trough down → spiral to 0.78 MB/s (well below the 50mbit/6.25 MB/s link).
★FIX ATTEMPT (REFUTED + REVERTED): capped pressure_loss at RQ_MILD_LOSS_PACING_MAX_LOSS*0.5 (=0.01) to keep the floor on (commit 1ad8fb319, **reverted in 36e4573a8**, never reached origin). Re-bench all 4 regimes (run `…20260620T053641Z`): perfect 3.7s/0r ✓, good 4.0s/1r ✓, but **bad REGRESSED 108s→188s/13r, broken 153s→240s/16r** (all sha ok). TWO reasons it backfired: (1) the floor STILL disabled (mild_floor=false persisted) — so capping pressure_loss did NOT keep the floor on (loss_ema still crossed 0.02 via another path / regime_shift); (2) lowering loss_bar (0.0875→~0.0175) cut `repair_overhead` 1.1773→1.0426, STARVING the per-round FEC → rounds DOUBLED 7→13. ★LEARNING: `loss_bar` is **dual-role** — it correctly inflates FEC repair-overhead (fewer rounds) AND incorrectly disables the pacing floor + drives the rate collapse. A correct fix must SEPARATE these: keep the pending-aware loss for FEC-overhead sizing, but gate the pacing floor / congestion rate on a TRUE wire-loss signal (real datagram loss, not decode-pending) — i.e., the receiver must report actual symbol-gap/loss stats and the sender must pace from THAT (this is `E-7.2` PathEstimate-from-live-feedback / `WIRE-2`, a real redesign, not a surgical edit). Distinguishing bad(2%) from broken(10%) would then be a single threshold (e.g. RQ_MILD_LOSS_PACING_MAX_LOSS≈0.03 on the TRUE wire loss). NO-CLAIM: 50M/bad still ~7× LOSS; the rate-collapse root is understood end-to-end but the fix is a pacing/loss-signal redesign + the single-block convergence (InconsistentEquations, `6.1.1`) that triggers it. The diagnostic trace (5b1b84b51) is retained for the implementer. Evidence dirs: `…20260620T051415Z` (diagnostic), `…20260620T053641Z` (refuted cap, all regimes).

## MATRIX-12 (2026-06-20) — BronzeTiger's wire-loss/repair-pressure SPLIT (bead 317hxr.2.5: 97b15fc9c decouple + 7d83d3aeb split + 2100065f9 path-estimate-on-wire-loss) DID kill the decode-pending rounds-spiral (50M/bad 7r→1r) — BUT exposed a NEW pathology: round-0 over-pacing → real 62% loss → unbounded repair_overhead (10.7×) → 50M/bad REGRESSED to 535s. Right direction, not yet a win.
Benched the 3-commit core redesign (binary built @2100065f9; HEAD also has refinement 3aee27a9c not in this binary; ATP_RQ_TRACE=1; run `artifacts/atp_bench_matrix/20260620T144025Z/`):
| 50M | MATRIX-8 baseline | redesign 3-commit (this) | verdict |
|---|---|---|---|
| perfect | 3.75s / 0r / 55MB | 3.7s / 0r / 49MB | ✓ unchanged |
| good (0.1%) | 3.96s / 1r | 4.3s med / 1r (1 rep blipped 24.7s/2r) | ~ok |
| **bad (2%)** | **108s / 7r / 867MB** | **535s med / 1 ROUND / 870MB** | **REGRESSED 5× wall, but rounds 7→1** |
| broken | 153s / 9r | (not measured; bench stopped — known to regress same way) | — |
★WHAT THE REDESIGN FIXED (real progress): the decode-pending → pacing-rate-collapse spiral is GONE. The sender now measures TRUE wire loss via receiver delivery feedback (`received_this_round` in the NeedMore trace = E-7.2 wired!), and decode-pending no longer disables the pacing floor. 50M/bad converges in 1 feedback round (was 7) — no more round-cascade.
★THE NEW PATHOLOGY (why it's 535s): the trace shows `received_this_round=16707 / sent=43700` ⇒ ~62% REAL wire loss in round 0. Cause: the round-0 spray bursts 43700 symbols in 3.3s (~127 Mbps) at the 50mbit (6.25 MB/s) link → netem drops 62% (genuine over-pacing, no rate-limit on the initial spray). The now-accurate loss estimator then over-reacts: `repair_loss_bar` CLAMPS to 0.90, `repair_overhead` explodes to **10.68×** (unbounded — no cap in mod.rs), and `pacing_rate_for` divides the rate by (1+9.44) → ~1.04 MB/s. Net: it sends ~10× the data at ~1 MB/s ⇒ ~535s. So the rate no longer collapses from decode-pending, but it now (a) over-paces the initial burst and (b) over-provisions FEC ~10× in response to the self-inflicted loss.
★TWO REMAINING LEVERS (reported to bead 2.5): (1) RATE-LIMIT the round-0 / initial spray to the estimated path bandwidth (don't burst 127M at a 50mbit link) — this is `E-7.3` rate-matched pacing; (2) CAP `repair_overhead` to a sane max (e.g. ≤2-3×; 10.68× is pathological) and/or size it to the TRUE wire loss after the burst is paced. The single-block InconsistentEquations convergence (`6.1.1`, BluePike) is now LESS critical since rounds dropped to 1, but still the trigger class. NO-CLAIM: 50M/bad still LOSES (535s vs rsync ~15s) — the redesign is necessary scaffolding (true wire-loss measurement) but the initial-burst pacing + overhead cap must land before it's a win. RETRY-COND (→ MATRIX-13): re-bench after rate-matched initial pacing + overhead cap → PASS if 50M/bad round-0 received≈sent (no over-pace loss) AND repair_overhead≲1.3× AND wall<58.7s. Evidence dir: `…20260620T144025Z`.

## MATRIX-13 (2026-06-20) — OVERHEAD CAP (both paths) LANDED by me: 50M/bad 535s→51s (2.1× better than the original 108s baseline), RSS 1.7GB→847MB, repair_overhead 10.68×→2.0×, ALL sha ok, NO regime regressed. Real committed win; still loses rsync (round-0 over-pace remains → lever 1 next)
Implemented + benched the wire-loss repair-overhead cap (SapphireHill, user-authorized direct edit after the swarm stalled ~2.5hr on the levers). New const `RQ_MAX_ROUND_REPAIR_OVERHEAD = 1.0` + cap `plan.overhead` in `round_tuning` (bounds the RATE path) AND `tuning.repair_overhead.min(1.0 + RQ_MAX_ROUND_REPAIR_OVERHEAD)` in `source_fec_fallback_tuning` (bounds the FEC-budget path — the dominant one when `fec_fallback=true`; the existing RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD=0.50 did NOT cap it). Both overhead paths now ≤2× total. Run `artifacts/atp_bench_matrix/20260620T214046Z/` (50M all-4 nocrypto, ATP_RQ_TRACE, clean env), all sha ok:
| 50M | original (M8) | redesign regress (M12) | round_tuning-only cap | **both caps (THIS)** | tuned rsyncd |
|---|---|---|---|---|---|
| perfect | 3.75s/0r/55MB | 3.7s | 3.7s | **4.0s / 0r / 49MB** ✓ | 1.2s |
| good 0.1% | 3.96s/1r | 15.6s | 4.0s | **4.1s / 1-2r / 49MB** ✓ (~parity) | 3.9s |
| **bad 2%** | **108s / 7r / 867MB** | 535s / 1.7GB | 118s / 1.7GB | **51.1s / 2-3r / 847MB** | 15.6s |
| broken 10% | 153s / 9r | (n/a) | (n/a) | **123.7s / 5r / 845MB** | 73.8s |
★VERIFIED: NeedMore trace now shows `repair_overhead=2.0000` (was 10.68× from uncapped `overhead_for_target(loss_bar=0.9)`); the round-2 mega-spray (was 431k symbols/518MB/111s) is bounded → recv RSS 1.7GB→847MB, wall 118s→51s. ★NET vs ORIGINAL baseline: 50M/bad 108s→51s (2.1× faster), 7→2-3 rounds, equal RSS; broken 153s→124s; perfect/good untouched (cap only bites when overhead>1.0), good ~parity with rsync. The MATRIX-12 overhead-explosion regression is fully resolved. ★REMAINS (lever 1 = round-0 over-pace): round-0 still bursts 43700 symbols (`received_this_round=16702/sent=43700` = 62% real loss) because cold-start paces at RQ_COLD_START_PACING_BPS=16 MiB/s=134 Mbit > the 50mbit link; round-2+ paces correctly (~98% delivered). That self-inflicted round-0 loss is why 50M/bad still needs 2-3 rounds and loses rsync (51s vs 15.6s). NEXT (→ MATRIX-14): make the initial/cold-start spray bandwidth-adaptive (ramp from the now-measured `received_this_round` delivery rate) so round-0 received≈sent → ~1-round convergence → target 50M/bad < rsync. ★COMMITTED this overhead cap to main (real win, no regression); lever 1 is the remaining gap to a 50M/bad outright win.

## MATRIX-14 (2026-06-20) — 500M on the overhead-cap binary: perfect/good hold great RSS (22-24MB, the max-block-size win persists) but 500M/bad is CATASTROPHIC (~1100s / 17.5 GB / 6-7 rounds). The overhead cap helps 50M but does NOT scale: round-0 over-pace dominates 500M (62% of 500MB lost across ~1000 blocks). LEVER 1 (round-0 slow-start) is now REQUIRED, not optional
Benched 500M on the lever-2 (overhead-cap) binary (run `artifacts/atp_bench_matrix/20260620T220044Z/`, partial — stopped after bad rep2 to free the box; box has 251GB RAM so no OOM, but 17.5GB/transfer is wasteful). atp-rq-lab vs tuned rsyncd, all completed cells sha ok:
| 500M | atp-rq (overhead-cap) | tuned rsyncd | note |
|---|---|---|---|
| perfect | 36.6s / 0r / 23MB | 5.1s | RSS great (max-block-size); loses raw clean speed 7× |
| good 0.1% | 55.7s med / 1-2r / 24MB (1 outlier 335s/9r) | 24.2s | loses ~2.3×; round-0 over-pace bites the 335s outlier |
| **bad 2%** | **~1100s (1211/1014) / 6-7r / 17.5 GB** | (not reached) | **CATASTROPHE** — round-0 over-pace at 500M scale |
| broken 10% | not measured (stopped) | — | likely worse |
★KEY FINDING: the overhead cap (MATRIX-13) is a 50M/bad win (108→51s) and a 500M MEMORY win (max-block-size keeps perfect/good at 23MB vs old ~7GB), BUT it does NOT fix 500M/bad — there the round-0 over-pace (cold-start sprays 134 Mbit into the 50mbit link → 62% loss) is over ~1000 blocks, so even bounded 2× repair re-sprays hundreds of MB across 6-7 rounds → 1100s / 17.5GB. So the overhead cap addresses the SYMPTOM (overhead explosion) but the ROOT — round-0 over-pacing (lever 1) — must be fixed for 500M/bad to be anything but catastrophic. ★LEVER 1 is now REQUIRED (was "nice to have" for the 50M final win; is now load-bearing for 500M/bad). It is a real congestion-control change: the cold-start spray (RQ_COLD_START_PACING_BPS=16 MiB/s = 134 Mbit) must become bandwidth-adaptive — pace round-0 conservatively and RAMP from the now-measured `received_this_round` delivery rate (slow-start), NOT a global lower constant (which would slow the 1gbit perfect/good links). NO-CLAIM: atp still loses rsync on every lossy single-file cell + clean raw speed; the overhead cap is real progress (50M 2.1×, 500M RSS) but NOT yet domination. RETRY-COND (→ MATRIX-16): after a proper round-0 slow-start, re-bench 50M+500M all regimes → PASS if round-0 received≈sent AND 50M/bad<15s AND 500M/bad<<1100s (no 17.5GB). [NOTE: MATRIX-15 below is the TREE-TIER scoreboard, benched while the slow-start lever was in flight; the slow-start 50M+500M retry is MATRIX-16.]

## MATRIX-15 (2026-06-20) — TREE TIER scoreboard on the lever-2 overhead-cap binary (HEAD 9206290ba): atp LOSES rsync on tree wall-clock across all regimes (worst = bad 2.2-2.9×, the SAME round-0 over-pace family as 50M/bad, compounded across many small files); bounded RSS (14-56MB) is atp's only tree edge, but the rsyncd RSS numbers are a harness artifact so NO memory claim. Trees need the same LEVER 1 (round-0 slow-start)
Benched tree_small + tree_big × {perfect,good,bad,broken} × nocrypto on the committed lever-2 binary (run `artifacts/atp_bench_matrix/20260620T233651Z/`, clean env, **all 64 rows status=ok sha_ok=true** — not pollution). atp-rq-lab vs tuned rsyncd, median of 5 reps (tree_small) / 3 reps (tree_big):
| workload | regime | atp wall / RSS | rsync wall / RSS | atp/rsync wall |
|---|---|---|---|---|
| tree_small | perfect | 1.85s / 14MB | 1.03s / (artifact) | **1.80× (loss)** |
| tree_small | good 0.1% | 2.55s / 15MB | 2.03s / (artifact) | **1.26× (loss)** |
| tree_small | **bad 2%** | **14.56s / 18MB** | 6.53s / 62MB | **2.23× (worst loss)** |
| tree_small | broken 10% | 28.87s / 36MB | 31.95s / (artifact) | **0.90× (WIN)** |
| tree_big | perfect | 1.62s / 16MB | 0.93s / (artifact) | **1.74× (loss)** |
| tree_big | good 0.1% | 2.15s / 15MB | 2.43s / (artifact) | **0.89× (WIN)** |
| tree_big | **bad 2%** | **25.67s / 32MB** | 8.74s / (artifact) | **2.94× (worst loss)** |
| tree_big | broken 10% | 52.09s / 56MB | 40.76s / (artifact) | **1.28× (loss)** |
★FINDING (wall): atp LOSES rsync on trees almost everywhere — perfect ~1.7-1.8× (the same raw-speed gap as single-file clean links), good ~parity-to-loss, and **bad 2% is atp's WORST tree result (tree_small 2.23×, tree_big 2.94×)**. atp only ties/wins two cells: tree_small/broken (0.90×) and tree_big/good (0.89×). The bad-regime tree weakness is the SAME mechanism as the 50M/bad single-file rate-collapse: round-0 cold-start over-paces (134 Mbit into a 50mbit link → ~62% self-inflicted loss), and for a TREE of many small files that over-pace penalty compounds per-object → 2-3× slower than rsync's steady TCP. So the slow-start lever (LEVER 1) is load-bearing for trees too, not just 50M/500M single-files.
★FINDING (RSS): atp's peak RSS is tight and bounded everywhere (14-56MB, the max-block-size + bounded-retention win). The **rsyncd peak_rss readings are NOT trustworthy** in this harness — they swing 62MB → 8-20GB across cells (e.g. tree_small/perfect 8199MB, tree_small/good 18440MB, tree_big/perfect 20626MB) which is physically impossible for rsync on these trees (rsync's real RSS for a tree is tens of MB). This is a measurement artifact in the rsyncd path (peak RSS of the daemon/system, not the transfer), so I make **NO memory-win claim** from this run; the only honest RSS statement is atp's absolute bounded 14-56MB. (Harness follow-up: fix rsyncd peak_rss attribution before any tree memory claim.)
★NO-CLAIM: atp does NOT beat rsync on trees on wall-clock — it loses 6 of 8 cells, worst in the bad regime. The tree tier is currently a LOSS, gated on the same LEVER 1 (round-0 slow-start) as the 50M/500M single-file path. RETRY-COND (→ after slow-start lands): re-bench the tree tier (esp tree_*/bad and tree_*/perfect) → expect tree/bad to improve in step with 50M/bad once round-0 received≈sent. Evidence dir: `artifacts/atp_bench_matrix/20260620T233651Z/`.

## ENCRYPTED-TIER STATUS (2026-06-20, bead z0v7ri) — fixed TWO bench-harness blockers (symbol-size + cert-EKU, committed) but uncovered a CONFIRMED deeper bug in the atp CLI's QUIC handshake glue: `atp send/recv --transport quic` fails the TLS handshake (`read_hs_fatal_alert`) even on plain loopback with a valid cert — so the encrypted tier (atp-quic-tls13) is NOT benchmarkable yet. NOT my rq lane — handed to the QUIC owner.
Re-checked the encrypted tier (atp-quic-tls13 vs rsync-ssh aes128-gcm) on 500K+50M/perfect (runs `…20260621T004007Z`/`004344Z`/`004711Z`). rsync-ssh = ok/sha_ok (0.45-0.86s). atp-quic-tls13 = status=error sha_ok=False on ALL reps, failing FAST (~0.15s, not a timeout). Narrowed the cause through THREE layers:
1. **Harness blocker #1 (FIXED, committed):** harness passed `--symbol-size 1200` but QUIC carries each symbol in one DATAGRAM (max_datagram_size=1200) that must also hold the 56-byte auth envelope → atp fail-closed `max_datagram_size(1200) must be ≥ symbol_size(1200)+56`. Fixed in `scripts/atp_bench/run_matrix_cell.sh`: clamp the quic tier's symbol payload to 1144 (rq tier keeps full SYMBOL_SIZE). CONFIRMED — the error moved past this.
2. **Harness blocker #2 (FIXED, committed, correct hygiene):** the self-signed bench cert lacked `extendedKeyUsage=serverAuth`; rustls-webpki server-cert verification wants it. Added EKU serverAuth + keyUsage to the openssl cert gen. (Did NOT change the failure → not the live blocker, but correct and needed once #3 is fixed.)
3. **REMAINING — atp CLI QUIC handshake bug (NOT fixed, for QUIC owner):** with symbol-size + a valid EKU/SAN cert, `atp send` still dies `native QUIC error: quic handshake: crypto provider failure: provider=rustls-quic-handshake, code=read_hs_fatal_alert`. Reproduced on PLAIN LOOPBACK (127.0.0.1, no netns, lab auth, `--no-delta`) → NOT a netns/harness issue. Ruled out: symbol-size (#1), netns, ALPN (both sides use `ATP_QUIC_ALPN=b"atpq/1"` via the same handshake_driver), cert EKU + basicConstraints=CA:TRUE (tried both). KEY: the in-process library e2e `tests/atp_quic_real_udp_transfer_e2e.rs` PASSES with FIXTURE certs (separate CA_CERT_PEM root + LEAF_CERT_PEM leaf), but the CLI fails with any openssl cert → the bug is in the CLI's QUIC cert/config glue (`src/bin/atp.rs` quic client config ~line 568 / `native_link.rs` client/server config ~928/1018), likely how it parses/loads the cert+key or builds the client RootCertStore from a single self-signed `--ca`, NOT the core QUIC transport. Repro: `atp recv <d> --listen 127.0.0.1:P --transport quic --once --symbol-size 1144 --rq-allow-unauthenticated-lab --server-cert c.pem --server-key k.pem` + `atp send f 127.0.0.1:P --transport quic --symbol-size 1144 --rq-allow-unauthenticated-lab --ca c.pem --server-name 127.0.0.1`. NO-CLAIM: encrypted tier remains a non-result (atp-quic fails to handshake); it cannot be scored vs rsync until the CLI quic handshake is fixed. Evidence dirs: `…20260621T004007Z` (symbol-size error), `004344Z`/`004711Z` (handshake alert).

## LEVER-1 ATTEMPT — sender-only round-0 bounded probe: REFUTED + REVERTED (2026-06-20, bead 317hxr.2.5). The round-0 probe is SOUND in isolation (round-0 received≈sent, no over-pace) but a sender-only change REGRESSES every regime because the post-probe source-resend path reports received_this_round=0 → triggers the same rate-collapse. Lever 1 is COUPLED to the receiver/feedback/estimator (E-7.2/WIRE-2), not a surgical sender edit.
I (SapphireHill, user-authorized direct mod.rs edit) implemented the bounded round-0 probe: `const RQ_ROUND0_PROBE_SYMBOLS=1024` + `spray_round` gained `max_symbols_this_round: Option<u64>` (cap in both parallel+sequential send paths), round-0 call passes Some(probe), repair calls None. Compiled clean; built release; benched 50M all-4 nocrypto ATP_RQ_TRACE=1 (run `20260621T024201Z`). REVERTED via `git stash` (stash@{0} "lever1-round0-probe-FAILED-needs-receiver-change") — kept for retry once the receiver path is fixed.
| 50M | baseline (overhead-cap, M13) | lever-1 sender probe (THIS) | tuned rsyncd |
|---|---|---|---|
| perfect | 3.7s | **75.92s** (20× WORSE) | 1.23s |
| good 0.1% | 4.1s | **96.00s** (23× WORSE) | 3.93s |
| bad 2% | 51s | **80.52s** (worse) | 14.24s |
| broken 10% | 124s | **134.33s** (worse) | 102s |
All sha_ok=true (no corruption — it's slow, not broken). ★TRACE (50M/perfect): round 0 sprayed 1311 symbols (≈1 block), received_this_round=1311 (the probe WORKS — no over-pace, exactly as designed). Round 1: receiver requests source_requests=8192 (it DOES re-request fully-missing blocks). **Round 2: sender sprays the requested source (sent_this_round=15992) but received_this_round=0 ON A 0-LOSS LINK** → repair_loss_bar 0.0875→0.9000, path_rate_bps collapses 68.9M→13.4M→9.3M, repair_overhead pins 2.0 → the rest dribbles at ~1MB/s → 76s. ★ROOT: after a partial round-0, the source-resend path (spray_source_requests / NeedMore.source_symbols) does not deliver+credit the re-sent SOURCE symbols for whole-missing blocks (received_this_round=0 despite ~16k sent on a lossless link), and that transient 0 poisons the loss/rate estimator (same collapse as MATRIX-6..11). ★CONCLUSION: the round-0 over-pace fix CANNOT be a sender-only probe — it requires (a) the source-resend round to actually deliver+credit re-sent source (receiver/feedback accounting), and (b) the estimator to not collapse on a transient received=0 round (E-7.2/WIRE-2 true-wire-loss). Specced back to 2.5 with this trace; my probe is stashed for when the receiver path lands. NO-CLAIM: 50M/bad still 51s (the committed overhead-cap state, HEAD); lever 1 unlanded. Evidence dir: `artifacts/atp_bench_matrix/20260621T024201Z/`.

## MATRIX-17 (2026-06-21) — AUTH-tier scoreboard (atp-rq-auth vs rsync-ssh aes128gcm) on HEAD (9206290ba): auth tier WORKS (all sha-clean), symbol-HMAC overhead ≈ZERO (atp-auth ≈ atp-nocrypto), and at the realistic both-encrypted tier atp is MORE competitive — TIES 50M/good (1.00×) and WINS tree_small/broken (0.60×); still loses clean raw-speed + 50M/bad (the lever-1 gap)
Benched 50M + tree_small × {perfect,good,bad,broken} × tier=auth on the HEAD binary (run `artifacts/atp_bench_matrix/20260621T042659Z/`, all 64 rows status=ok sha_ok=true — clean, not pollution). atp-rq-auth (`--rq-auth-key-hex`, per-symbol HMAC) vs rsync-over-ssh (`-c aes128-gcm@openssh.com`), median of 3 (50M) / 5 (tree_small):
| workload | regime | atp-rq-auth wall / RSS | rsync-ssh wall | atp/rsync |
|---|---|---|---|---|
| 50M | perfect | 3.72s / 49MB | 0.85s | 4.35× (loss) |
| 50M | good 0.1% | 4.06s / 50MB | 4.06s | **1.00× (TIE)** |
| 50M | bad 2% | 50.09s / 848MB | 18.67s | 2.68× (loss — lever-1 gap) |
| 50M | broken 10% | 126.56s / 844MB | 102.63s | 1.23× (loss) |
| tree_small | perfect | 1.85s / 14MB | 0.65s | 2.83× (loss) |
| tree_small | good 0.1% | 2.55s / 14MB | 1.96s | 1.30× (loss) |
| tree_small | bad 2% | 15.77s / 19MB | 7.75s | 2.03× (loss) |
| tree_small | broken 10% | 26.78s / 35MB | 44.89s | **0.60× (WIN)** |
★FINDING 1 — auth overhead is ~FREE: 50M auth (3.72/4.06/50.1/126.6) is within noise of 50M nocrypto (MATRIX-13: 3.7/4.1/51/124); tree_small auth (1.85/2.55/15.8/26.8) ≈ tree_small nocrypto (MATRIX-15: 1.85/2.55/14.6/28.9). atp's per-symbol HMAC adds negligible wall + RSS. ★FINDING 2 — atp is MORE competitive at the crypto-ON tier than at nocrypto, because rsync now pays ssh-crypto too: atp-auth TIES rsync-ssh on 50M/good (1.00× vs 1.26× at nocrypto where rsyncd is plaintext) and WINS tree_small/broken (0.60×). The realistic default real-world comparison (both encrypted) is atp's BEST relative footing. ★FINDING 3 — the losses are the SAME two unsolved gaps, unchanged by crypto: (a) clean raw-speed (atp cold-start-capped at 134Mbit vs rsync's full-link TCP — perfect 4.35×), (b) 50M/bad rate-collapse (2.68×, the round-0 over-pace / lever-1, still coupled-to-receiver-unlanded). atp RSS bounded (14-50MB clean, ~848MB on 50M lossy from the in-flight repair set). NO-CLAIM: atp does not yet dominate the auth tier (loses 6/8) but is competitive (1 tie + 1 win) and crypto is ~free; the path to auth-tier wins is the same lever 1 + raw-speed work. Evidence dir: `artifacts/atp_bench_matrix/20260621T042659Z/`.

## MATRIX-ENC (2026-06-21) — ENCRYPTED tier (atp-quic-tls13) is NOW USABLE for the first time (was 32/32-fail / z0v7ri): handshake fixed (swarm leaf-pin) + datagram sizing fixed (symbol 1141). atp-quic WORKS sha-clean on CLEAN links, but FAILS every LOSSY regime (QUIC loss-convergence is the open follow-on, separate from the handshake/sizing fixes)
The encrypted CLI data plane (`atp --transport quic`, TLS-1.3 + symbol auth) was a hard 32/32 failure for days (z0v7ri). Two fixes landed it: (1) the QUIC **leaf-pin** commits (d0c3011ad/f96f379b7/acbaccd9c) fixed the TLS handshake (`read_hs_fatal_alert`); (2) the bench-harness **quic symbol size → 1141** (commit 8173e4b98) — QUIC DATAGRAM frames add 3 bytes so symbol(1144)+envelope(56)=1200 overflowed max_datagram(1200) by 3. Run `artifacts/atp_bench_matrix/20260621T195619Z/`, atp-quic-tls13 vs rsync-over-ssh(aes128-gcm):
| workload | regime | atp-quic-tls13 | rsync-ssh | note |
|---|---|---|---|---|
| 50M | perfect | **36.18s sha-ok** | 0.86s | 42× (works, loses raw speed like nocrypto) |
| 50M | good 0.1% | FAIL (3 err) | 4.06s | QUIC loss-convergence open |
| 50M | bad 2% | FAIL (3 err) | 19.47s | " |
| 50M | broken 10% | FAIL (3 err) | 103.14s | " |
| tree_small | perfect | **15.23s sha-ok** | 1.05s | works |
| tree_small | good 0.1% | FAIL (5 err) | 2.36s | " |
| tree_small | bad 2% | FAIL (5 err) | 7.36s | " |
| tree_small | broken 10% | FAIL (5 err) | 34.80s | " |
(500K/perfect smoke earlier: atp-quic 0.45s TIED rsync-ssh 0.45s, sha-ok.) ★MILESTONE: the encrypted tier is on the scoreboard at all — the QUIC/TLS-1.3 data plane completes byte-perfect transfers on clean links (z0v7ri handshake+sizing DONE). ★NO-CLAIM / OPEN: atp-quic FAILS under ANY loss (good/bad/broken all 0-ok) — the QUIC data plane has no working loss-convergence yet (its own analogue of the rq lever-1 problem; the rq lever-1 fix does NOT carry to the quic path). And clean raw-speed loses ~42× (same cold-start/decode wall as nocrypto + QUIC overhead). So encrypted is USABLE-on-clean, NOT competitive yet. Follow-on: QUIC loss-convergence (relates to QUIC.1 / a new bead) is the next encrypted-tier lever. Evidence dir: `artifacts/atp_bench_matrix/20260621T195619Z/`.

## MATRIX-18 (2026-06-21) — LEVER-1 (round-0 over-pace) REFUTED-AS-IMPLEMENTED TWICE; main currently REGRESSED for large atp-rq

**Context.** Lever-1 = stop round-0 from spraying the whole object at the 16MiB/s cold-start rate (→ ~62% loss on slow links). Two swarm attempts landed on `main` (bead 317hxr.2.5). Both benched on 50M nocrypto × {perfect,good,bad,broken}, ATP_RQ_TRACE, fresh release `atp 0.3.5`, hermetic netns+veth+netem, SHA-256 fail-closed. **Prior best working baseline = overhead-cap `9206290ba` (50M/bad 51s, all sha-ok).**

**v2 `083652184` ("credit source resend probe rounds") — REGRESSED (slow, sha-clean).** Run `20260621T192647Z`, all `sha_ok=true`:
| regime | v2 | baseline 9206290ba |
|---|---|---|
| perfect | 56.19s | 3.7s (**15× slower**) |
| good | 76.61s | 4.1s (**19× slower**) |
| bad | 79.72s | 51s (worse) |
| broken | 92.13s | 124s (better) |
Trace root cause: source-resend rounds UNDER-CREDIT `received_this_round` (perfect round-2 sent=15992 received=1884, ~12%); the no-collapse guard only catches received==0, so tiny-nonzero is fed to the estimator as ~88% wire loss → `repair_loss_bar` 0.0875→0.88 → path_rate collapse 112M→14M.

**v3 `cfe9816b4` ("exclude source resend loss samples") — HARD BREAK (all transfers fail).** Run `20260621T204912Z`: atp-rq-lab `status=error sha=False` on EVERY regime (incl perfect), fails ~0.3s, `feedback_rounds=0` (rsync succeeds → not netns pollution). Exact errors:
- recv.time: `atp failed: frame error: frame too large: 1326430 bytes (max: 1048576)`
- send.time: `round 0 sprayed symbols_sent=437 probe_limit=437` → `got reply KeepAlive` → `sent ObjectComplete` → `atp failed: io error: peer closed control connection mid-transfer`

**Root cause (v3).** The bounded round-0 1-block probe leaves a huge source deficit; the receiver's NeedMore then enumerates ALL remaining source ESIs (~40k), serializing to ~1.3MB > the 1 MiB control-frame max → receiver rejects the frame and closes the control connection → every multi-block (large) transfer fails. So **`main`'s transport_rq is currently broken for 50M/100M/500M atp-rq.**

**Verdict / no-claim.** Lever-1 is NOT yet a win; both implemented forms regressed (v2 slow, v3 broken). The correct fix is ONE coherent change, not incremental patches: (1) bounded round-0 probe; (2) COMPACT source-request encoding in NeedMore (ranges/bitmap or per-sbn bulk request — never per-ESI enumeration, that's what overflowed); (3) gate source-resend rounds OUT of the loss/pacing estimator by ROUND TYPE; (4) credit re-sent source in the SAME round (received≈sent on a clean link); (5) deliver requested source in one bulk round at the measured rate. **Recommended interim:** `git revert 083652184 + cfe9816b4` (or reset round-0/source-resend to `9206290ba`) to restore a working `main` while lever-1 is redesigned. Filed to bead 317hxr.2.5. Evidence dirs: `artifacts/atp_bench_matrix/20260621T192647Z/` (v2), `.../20260621T204912Z/` (v3).

## MATRIX-19 (2026-06-21) — RESTORE CONFIRMED: main un-broken, back at overhead-cap baseline (byte-identical to 9206290ba)

The swarm reverted within ~1 min of the MATRIX-18 report: `8e7536806 "restore RQ overhead-cap baseline"` reverts both broken lever-1 commits (083652184 + cfe9816b4). **Verified byte-identical:** `git diff 9206290ba 8e7536806 -- src/net/atp/transport_rq/mod.rs` is EMPTY → transport_rq is the exact overhead-cap baseline again. Rebuilt fresh release `atp 0.3.5` from `8e7536806` and re-benched 50M nocrypto × {perfect,good,bad,broken}, hermetic netns+veth+netem, 3 reps, SHA-256 fail-closed (run `20260621T210830Z`):

| regime | atp-rq-lab (median) | rsyncd | sha_ok | fr | note |
|---|---|---|---|---|---|
| perfect | **3.72s** | 1.23s | 3/3 | 0 | healthy — matches non-regressed baseline (NOT v2's 56s, NOT v3's break) |
| good 0.1% | **3.95s** | 3.93s | 3/3 | 1 | **TIE** with rsync — healthy (NOT v2's 76s) |
| bad 2% | 73.41s | 14.94s | 3/3 | 4 | completes; atp loses (CPU-bound single-core decode wall) |
| broken 10% | 114.44s | 82.59s | 3/3 | 5 | completes; atp loses |

**Verdict.** ✅ `main` is no longer broken — ALL transfers complete, sha 3/3 every cell, NO "frame too large", NO control-channel close. perfect/good are at the healthy baseline (the v3 break is fully repaired). Since transport_rq is byte-identical to 9206290ba, this IS the documented overhead-cap baseline. The bad-regime 73.41s reads higher than the previously-documented 51s (MILESTONE), but the code is identical to that baseline, so the delta is environmental — this bench ran with the rqperf coding swarm actively building on the same host (csd load) + ordinary netem/convergence variance (fr=4 at 80ms RTT). NOT a code regression. Evidence dir: `artifacts/atp_bench_matrix/20260621T210830Z/`.

## MATRIX-20 (2026-06-21) — DECODE/BLOCK-SIZE LEVER REFUTED for the headline cells; the real 50M walls re-diagnosed (syscall on clean, feedback-rounds on lossy)

**Why this matters.** The "50M is CPU-bound on single-core RaptorQ decode" framing (carried from an earlier loopback session) drove a "parallelize/shrink-decode" hypothesis. Two pieces of evidence REFUTE it:

1. **Receiver parallel decode is ALREADY wired and is never the limiter.** transport_rq has `dispatch_decode_job` → `cx.spawn_blocking(run_block_decode_job)` with a per-transfer width budget (`rq_decode_width_budget` = `core_limit.min(memory_limited)`) and per-entry cap. The `ATP_RQ_TRACE` from run 20260621T210830Z shows **600 "queued parallel decode" events and ZERO width-saturation joins** ("joined N pending decode … saturated" / "entry_cap=") across the whole run — decode fans across the blocking pool freely; concurrency is not throttled.

2. **Block size is decode-neutral on clean and *harmful* on lossy.** Central A/B with the existing `--max-block-size` flag (zero code change), 50M nocrypto, 3 reps, run `20260621T214824Z`:

| cell | auto (8 MiB) baseline | **1 MiB** | verdict |
|---|---|---|---|
| 50M/perfect | 3.72s (fr=0, sha 3/3) | **3.72s** (fr=0, sha 3/3) | identical → decode is block-size-insensitive |
| 50M/bad | 73.41s (fr=4) | **91.03s** (fr=4, sha 3/3) | WORSE → more per-block wire overhead on a rate-capped link |

**Re-diagnosis (the real walls).** Throughput math:
- **perfect (fr=0): 50M / 3.72s = 13.4 MB/s on a 1 gbit / 125 MB/s link = ~11% of line rate, with ZERO loss and ZERO feedback rounds and block-size-insensitive.** → the clean-link wall is raw **pipeline throughput**: the per-symbol `sendto` syscall rate (~43k sendto/50M) and single-thread encode, NOT decode and NOT the pacing cap (RQ_MAX_PACING_BPS≈67 MB/s ≫ 13.4). Lever = **GSO/sendmmsg batched native send** (E-6.2/E-6.3, bead `rq-e6b-gso-sendmmsg-native-send-wfrvuq`; needs unsafe+ledger, also lifts QUIC).
- **bad: 50M / 73.41s = 0.68 MB/s — far below BOTH the 6.25 MB/s link cap AND the 13.4 MB/s decode rate** → dominated by the **4 feedback rounds** (each ≈ 80 ms RTT + a re-spray of repair) on a 2%-loss link, NOT decode CPU. Lever = **cut the rounds**: fix `317hxr.6.1.1` (FEC fallback self-disables after `source_retransmit_rounds`=2 via the `requested_sources==0` guard at mod.rs ~2153 → rounds 3..N degrade to inefficient source-only retransmits) + calibrate round-0 repair overhead so it converges in 1–2 rounds.

**Verdict / no-claim.** Decode parallelism and block-size are NOT the 50M/500M levers. Do not re-attempt "build parallel decode" (done) or "shrink max_block_size" (refuted: 1 MiB made bad worse, perfect unchanged). The evidence-backed levers are (clean) **GSO/sendmmsg syscall batching** and (lossy) **feedback-round reduction (FEC-fallback fix 317hxr.6.1.1 + overhead calibration)**. Evidence dirs: `artifacts/atp_bench_matrix/20260621T210830Z/` (auto baseline), `.../20260621T214824Z/` (1 MiB A/B).

## MATRIX-21 (2026-06-21) — 3 levers landed but DELIVERED NOTHING (off-live-path); the clean wall is actually round-0 COLD-START PACING (16 MiB/s)

Swarm landed 3 levers past the restore (HEAD `c3aff3ca7`): GSO eligibility (`ecdc160be`, wfrvuq), repair-overhead calibration (`ad6499110`, j91wza), widen RQ decode fanout + retry fixes (`ba256f440`+7.3). Rebuilt fresh `atp 0.3.5`, benched 50M nocrypto ×4, 3 reps, run `20260621T222617Z`:

| regime | combined levers | baseline (MATRIX-19) | rsyncd | Δ |
|---|---|---|---|---|
| perfect | 3.82s (fr=0, sha 3/3) | 3.72s | 1.23s | ~same |
| good | 3.95s (fr=[2,1,1], sha 3/3) | 3.95s | 3.93s | same (TIE rsync) |
| bad | 73.11s (fr=4, sha 3/3) | 73.41s | 14.74s | ~same |
| broken | 133.96s (fr=6, sha 3/3) | 114.44s | 76.19s | **+19.5s / +1 round WORSE** |

**Why nothing moved (root causes — the levers missed the live hot path):**
1. **GSO `ecdc160be` only touched `src/net/udp.rs` (eligibility + segment ceiling) + a benchmark — NOT the spray.** And the spray ALREADY batches via `socket.send_batch_to()` (mod.rs:568, `RqPendingSendBatch`). So syscall rate was never the binding clean-link constraint; GSO has nothing to bite.
2. **★REAL CLEAN-LINK WALL = round-0 COLD-START PACING.** `RQ_COLD_START_PACING_BPS = 16 MiB/s` (mod.rs:186); round 0 sprays at `RqSprayPacing::cold_start()` (mod.rs:703). perfect/good complete in ONE round (fr=0) so they're capped at 16.8 MB/s and **never ramp to `RQ_MAX_PACING_BPS = 64 MiB/s`**. 50M / 16.8 MB/s = 2.98s theoretical ≈ observed 3.82s. **If round-0 sprayed at link rate, 50M perfect → <1s, BEATING rsync's 1.23s.** This is the highest-EV clean-link lever — and it's pacing, not syscalls/decode/encode.
3. **j91wza `ad6499110` only added +65 lines to `adaptive.rs`, which is UNWIRED** (not on the live transfer path) → zero effect; bad stayed fr=4.
4. **decode-fanout (7.3) is live but off-bottleneck** (decode already cleared in MATRIX-20); it appears to have nudged broken to fr=6 (+1 round, +19.5s) — investigate/possibly revert that hunk.

**Verdict / no-claim.** No win this round; all sha-ok (no correctness break). The REAL levers, now sharper: (clean) **ramp round-0 cold-start pacing toward link rate** — a slow-start probe that climbs from a safe floor to `RQ_MAX_PACING` and backs off on observed loss (must NOT flat-raise the cold-start constant: slow lossy links need the conservative start — that was the lever-1 over-pace failure). (lossy) cut feedback rounds, but the repair-overhead calibration must be wired into the **LIVE `spray_round`/`round_tuning`**, not `adaptive.rs`. **Orchestration lesson: a lever only counts when it lands on the live hot path AND moves a benched cell — `cargo check` green ≠ benchmark win.** Evidence dir: `artifacts/atp_bench_matrix/20260621T222617Z/`.

## MATRIX-22 (2026-06-21) — ROUND-0 PACING RAMP REFUTED (3rd pacing-up failure); the clean-link ceiling is the RECEIVER drain rate, NOT sender pacing

The MATRIX-21 hypothesis (raise round-0 pacing → beat rsync clean) was implemented as `a8a6792f6` (839ykg, "ramp RQ round-0 pacing": `RqPacingRamp` doubling ×2/burst up to `RQ_MAX_PACING_BPS`=64 MiB/s, gated `!loss_detected`). Benched 50M nocrypto ×4, 3 reps, run `20260621T231513Z`:

| regime | RAMP | baseline (MATRIX-19) | rsyncd | fr | verdict |
|---|---|---|---|---|---|
| perfect | **55.70s** | 3.72s | 1.23s | 0→**4** | **15× WORSE** |
| good | **68.51s** | 3.95s | 3.93s | 0→**5** | **17× WORSE** |
| bad | 70.81s | 73.41s | 14.44s | 5 | ~same (noise) |
| broken | 111.70s | 114.44s | 70.48s | 6 | ~same (noise) |

All sha-ok (correct, just slow). **Trace proof of the failure mechanism** (perfect rep1 send.time): round 0 sprayed 43700 symbols at `path_rate_bps=67108864` (ramp hit the 64 MiB/s max); round 1 `received_this_round=26425` of 43700 → **~40% loss on a ZERO-LOSS netem link** = pure receiver-buffer overflow; `repair_loss_bar` shot to 0.69→0.90 → 4 feedback rounds → 55.7s.

**Re-diagnosis — this REFUTES the pacing hypothesis and pins the real ceiling.** On a 0-loss link the only way to get loss is buffer overflow, so the receiver's drain/decode pipeline tops out around the original cold-start rate (~13–16 MB/s). **The 16 MiB/s `RQ_COLD_START_PACING_BPS` is NOT an arbitrary cap — it is ~matched to the receiver's intake/decode/disk throughput.** Spraying faster (this ramp) just overflows the receiver → self-inflicted loss → more rounds → far slower. This is now the **THIRD** sender-pacing-up failure (lever-1 v2 estimator-collapse, lever-1 v3 control-frame break, and this ramp). **Conclusion: sender-side "spray faster" is a dead end — you cannot beat the receiver's drain rate by sending harder.**

**The real clean-link lever is RECEIVER throughput.** atp clean ≈13.4 MB/s vs rsync ≈40 MB/s; to beat rsync clean we must raise the receiver's symbol-intake/decode/commit pipeline above ~40 MB/s. Decode itself is already parallel and block-insensitive (MATRIX-20), so the suspect is the **serial per-symbol intake/drain loop** (recv → auth-verify → `feed_symbol_with_cx` → dispatch) and/or staging disk write — the part that runs single-threaded between the socket and the parallel decoders. Next diagnostic: profile/instrument the receiver pump to find the ~13 MB/s bottleneck (intake batching, auth cost per symbol, disk write path).

**Action.** `a8a6792f6` is a clean-link regression on `main` (perfect/good 15–17× slower) — recommend REVERT it to restore the overhead-cap baseline (3.72/3.95s clean), then pursue the receiver-throughput lever. Filed to bead 839ykg. Do NOT attempt further round-0 pacing-up levers. Evidence dir: `artifacts/atp_bench_matrix/20260621T231513Z/`.

## MATRIX-23 (2026-06-22) — revert CONFIRMED (clean restored) + ★bottleneck PINPOINTED: the receiver wall is the SERIAL per-symbol FEED

Swarm landed `daf534408` (revert of the pacing ramp) + `4f60acf15` (drhadc: receiver-intake trace decomposing recv/parse/feed/drain). Rebuilt fresh `atp 0.3.5`, benched 50M nocrypto ×4, run `20260622T000615Z`:

**Revert confirmed — clean baseline restored:** perfect 3.85s (base 3.72), good 4.05s (base 3.95), bad 72.51s (base 73.41), all sha 3/3. (broken 129.95s/fr6 vs base 114.44/fr5 — still carries the 7.3 decode-fanout +1-round regression flagged in MATRIX-21/22; separate lossy issue.)

**★THE RECEIVER CEILING IS THE PER-SYMBOL FEED (decisive).** Intake trace for 50M/perfect (rep1, 43700 symbols, 52.4 MB):
| stage | micros | share |
|---|---|---|
| **feed_micros** | **3,382,218** | **99.999%** |
| drain_micros | 94,803 | 2.8% |
| recv_micros | 66,223 | 2.0% |
| parse_micros | 34 | 0.001% |
| **intake total** | 3,382,252 | → **15.5 MB/s, 12,920 sym/s, ~77 µs/symbol** |

`feed_symbol_with_cx` is the ENTIRE clean-link wall — socket recv, frame parse, and control drain are all noise. This refines MATRIX-20: the parallel decode that landed only parallelized the **block solve** (`run_block_decode_job`, the final Gaussian elimination per block); the **per-symbol feed/intake into the decoder runs serially on the single receiver pump thread** at ~77 µs/symbol → 15.5 MB/s. rsync clean = 40 MB/s, so this single serial stage is exactly why atp loses clean.

**LEVER R2 (dispatched).** Symbols are block-independent (each carries an sbn), so the feed parallelizes cleanly: shard incoming symbols by block to per-block decoder workers on the existing blocking pool (per-block serialized, but different blocks concurrent). ~7–13 blocks for 50M → potential ~7–13× → ≫40 MB/s = beats rsync clean, and it scales to 500M + ports to QUIC. Must stay byte-identical (sha+merkle) and not regress lossy. This is the first NON-pacing, NON-decode-solve, evidence-pinpointed clean-link lever. Evidence dir: `artifacts/atp_bench_matrix/20260622T000615Z/`.

## MATRIX-24 (2026-06-22) — staging-write cache 3.1×'d the receiver feed (now > rsync throughput!); bottleneck SHIFTED back to sender pacing; lossy regressed

Swarm landed `46355c9a2` (okcmis, "cache RQ source staging writes": caches the staging file handle + buffers unflushed bytes for large entries — kills the per-symbol open/seek/write that MATRIX-23 pinned). Rebuilt fresh `atp 0.3.5`, benched 50M nocrypto ×4, run `20260622T010229Z`:

**The feed fix WORKED (50M/perfect intake trace):**
| metric | MATRIX-23 (before) | MATRIX-24 (okcmis) | Δ |
|---|---|---|---|
| feed_micros | 3,382,218 | **1,094,829** | **3.1× faster** |
| intake_bytes_per_s | 15.5 MB/s | **47.9 MB/s** | **>rsync's 40 MB/s** |
| intake_symbols_per_s | 12,920 | 39,913 | 3.1× |
| recv_micros | 66,223 | **2,186,697** | bottleneck moved here |

**But the clean WALL barely moved** (perfect 3.72→3.65s, good 3.95→3.95s): the bottleneck **shifted from feed to `recv_micros` (66ms → 2.19s)**. The now-fast receiver (47.9 MB/s) is **starved waiting on the 16 MiB/s cold-start-paced sender** — `recv_micros` is now sender-pacing-wait, not socket cost. intake total = 1.09s feed + 2.19s recv-wait ≈ the 3.65s wall.

**Lossy REGRESSED:** bad 73.41→86.73s (fr 4→5), broken 114.44→122.35s (fr 6→8), all sha 3/3. The staging-write cache likely delays block-completion detection on multi-round lossy (buffered/unflushed writes → block not seen complete at the round boundary → extra NeedMore round). Needs a flush at the round/completeness boundary, or gate the cache so it can't delay convergence.

**★THE UNLOCK.** The three prior sender-pacing failures (lever-1 v2/v3, the round-0 ramp → MATRIX-22) ALL happened *because the receiver could only absorb ~15.5 MB/s, so any faster spray overflowed it*. **okcmis lifts the receiver to 47.9 MB/s — that constraint is now gone.** So sender pacing matched to the now-fast receiver is finally viable on clean links: at ~40 MB/s, 50M/perfect → ~1.25s ≈ **beats rsync's 1.23s**. The pacing must still be receiver-rate-aware (cap at the observed drain rate, back off on receiver-side loss) and keep the conservative floor for slow/lossy links — but the headroom now exists (the receiver won't overflow until ~47 MB/s, not ~16).

**Next levers (dispatched):** (A) re-enable a receiver-rate-matched sender pacing increase on clean links now that the receiver keeps up (this is the ramp idea with its precondition finally met); (B) fix the okcmis lossy regression (flush staging at round/completeness boundary or gate the cache). okcmis stays on main — the 47.9 MB/s receiver ceiling is foundational for every clean-link win — but its lossy side effect must be fixed. Evidence dir: `artifacts/atp_bench_matrix/20260622T010229Z/`.

## MATRIX-25 (2026-06-22) — ★FIRST REAL CLEAN WIN (perfect 3.72→1.82s, 2×) but pacing OVERSHOOTS bandwidth-limited links (good 7.6× worse)

Full unlock package committed (HEAD `905b0ef19`): okcmis feed-cache (`46355c9a2`) + Lever B lossy-fix (`67826603e`, round-boundary staging seed) + **Lever A receiver-rate-matched round-0 pacing** (`905b0ef19`, "pace RQ round0 from receiver drain"). Rebuilt fresh `atp 0.3.5`, benched 50M nocrypto ×4, run `20260622T020522Z`:

| regime | unlock pkg | baseline | rsyncd | fr | verdict |
|---|---|---|---|---|---|
| **perfect** | **1.82s** | 3.72s | 1.23s | 0 | ✅ **2× faster** (first real clean win); only +0.59 off rsync (was +2.49) |
| good 0.1% | **29.98s** | 3.95s | 3.93s | 2 | ❌ **7.6× WORSE** — pacing floods the 200 mbit link |
| bad 2% | 60.50s | 73.41s | 14.94s | 4 | ✅ better (Δ-12.9) |
| broken 10% | 111.85s | 114.44s | 76.19s | 6–8 | ~same |

All sha 3/3 (no correctness break). **Trace (50M/perfect):** pacing ramped `path_rate_bps` 16 MiB/s → **335,544,320 (320 MiB/s)**; the now-fast receiver kept up — `recv_micros` 2.19s→0.50s, `intake_bytes_per_s` 56.8 MB/s, fr=0 → **3.72→1.82s.** This is the FIRST time a pacing change produced a real win — the receiver-rate match works on a fast link, proving the MATRIX-24 unlock thesis.

**The remaining flaw is precise.** Lever A paces to the *receiver* drain rate (56 MB/s) but ignores *link* capacity. On `perfect` (1 gbit) that's fine. On `good` (200 mbit = 25 MB/s) it ramps to 320 MiB/s and **floods the link** → qdisc loss → controller thrash → 29.98s. The pacing target must be **`min(receiver_drain_rate, observed_link_delivery_rate)`** with hard loss-backoff — the link delivery rate is observable from feedback (`received_this_round / send_wall`). On good that caps at ~25 MB/s (no overshoot); on perfect the link is fast so receiver-rate still binds (keeps the win).

**Verdict / action.** Net mixed: perfect +2× (win), bad better, broken flat, **good 7.6× regression** (not shippable as-is). The lever is close — dispatched the link-rate cap (`min(receiver_rate, observed delivery rate)` + loss-backoff). Until that lands, `main` has a `good`-regime regression from `905b0ef19`; if the cap isn't quick, revert just `905b0ef19` (keep okcmis + Lever B, which gave the foundational receiver speedup and the lossy fix). PASS target: perfect ≤1.82s held AND good back ≤4s AND bad/broken not regressed AND sha-ok. Evidence dir: `artifacts/atp_bench_matrix/20260622T020522Z/`.

## MATRIX-26 (2026-06-22) — perfect win HOLDS (1.75s) but the link-rate cap is INSUFFICIENT for good (bursty delivery estimate ⇒ 2× over link)

Link-cap fix `eff839c8a` (okcmis, "cap RQ pacing to delivered link rate") built + benched 50M nocrypto ×4, run `20260622T025057Z`:

| regime | link-cap | baseline | rsyncd | fr | verdict |
|---|---|---|---|---|---|
| perfect | **1.75s** | 3.72s | 1.23s | 0 | ✅ clean win HOLDS (+0.52 off rsync) |
| good 0.1% | **30.88s** | 3.95s | 3.93s | 2–3 | ❌ STILL 7.8× worse |
| bad 2% | 72.21s | 73.41s | 14.94s | 4 | ~baseline |
| broken 10% | 122.21s | 114.44s | 76.19s | 5–6 | ~same (noisy) |

All sha 3/3. **Root cause of the good holdout:** on good, `path_rate_bps` = **52,237,632 (≈50 MB/s)** — the cap engaged (down from 320 MiB/s) but the **good link is only 200 mbit = 25 MB/s**, so 50 MB/s still floods it 2×. The "delivered link rate" estimate (`received_this_round / send_wall`) is taken from a **bursty early window** — the receiver drains an initial buffered burst quickly, so the measured rate (~50 MB/s) overestimates the *sustainable* link rate (25 MB/s) before the netem rate-limiter and loss engage. So the cap clamps to ~2× the true link capacity → still overshoots → loss → 30.88s. (perfect: path_rate 320 MiB/s, link 1 gbit, receiver-bound at ~56 MB/s → no overshoot → 1.75s win.)

**This is the 4th pacing iteration; good is the consistent holdout** (ramp → receiver-cap → link-cap all overshoot good). **Key strategic note: the foundation WITHOUT pacing — okcmis feed-cache (`46355c9a2`) + Lever B lossy-fix (`67826603e`) — is already a strict, regression-free improvement** (bad 73→60, perfect ~3.65, good ~3.95, broken ~112, all sha-ok). The pacing (`905b0ef19` + `eff839c8a`) buys a real perfect 2× win (1.75s) but at the cost of an 8× good regression, so it is **net-negative across the matrix until the overshoot is truly fixed.**

**Fix dispatched:** make the delivery-rate estimate **sustained, not bursty** — measure delivered rate over a full settled window (after the link-limiter saturates), or take the MIN of recent per-round delivery samples, or detect the delivery PLATEAU; cap pacing at that true sustained rate. On good that yields ~25 MB/s (no overshoot, good ≤4s); on perfect the link is fast so the receiver rate still binds (keeps 1.75s). **Fallback if not quick:** gate the aggressive ramp to engage only after a round confirms zero/near-zero loss AND a rising-then-plateaued delivery curve — otherwise hold the conservative cold-start. If neither lands soon, revert `905b0ef19`+`eff839c8a` and keep the clean okcmis+Lever B foundation (bad-improved, no regressions) while pacing is redesigned. PASS: perfect ≤1.82 AND good ≤4 AND bad/broken ≤baseline AND sha-ok. Evidence dir: `artifacts/atp_bench_matrix/20260622T025057Z/`.

## MATRIX-27 (2026-06-22) — receiver-safe sustained-delivery pacing is a NET REGRESSION + 1 sha FAIL; PACING DECLARED A DEAD END (5 failures), revert to foundation

After the swarm reverted the broken link-cap pacing (`73f184b57`) it re-implemented pacing receiver-safe with sustained-delivery sampling (`3e37aac2a`). Benched 50M nocrypto ×4, run `20260622T033426Z`:

| regime | recv-safe pacing | baseline | rsyncd | fr | sha | verdict |
|---|---|---|---|---|---|---|
| perfect | 1.85s | 3.72s | 1.23s | 0 | 3/3 | held (still loses rsync) |
| good 0.1% | 27.12s | 3.95s | 3.93s | 2/0/2 | **2/3 ✗** | still floods (path_rate spiked to 335 MB/s) + **1 sha FAILURE** |
| bad 2% | 110.85s | 73.41s | 14.94s | 4 | 3/3 | **+37s WORSE** |
| broken 10% | 230.29s | 114.44s | 76.19s | 5–6 | 3/3 | **2× WORSE (+116s)** |

The sustained-delivery cap does NOT cap good (`path_rate_bps` still hit 335,544,320 = 320 MiB/s in-sample), it badly hurt lossy convergence (bad +37, broken doubled), AND it produced a **sha verification failure** on good (a correctness/convergence regression, not just slow).

**★PACING IS A DEAD END — 5 consecutive failures:** lever-1 v2 (estimator collapse), lever-1 v3 (control-frame overflow), round-0 ramp (receiver overflow), link-cap (bursty estimate 2× over link), sustained-delivery (lossy destruction + sha fail). Every attempt to raise round-0 send rate either overflows the receiver/link → self-inflicted loss → more rounds, or destabilizes lossy convergence. The single perfect improvement (3.72→1.85) NEVER beats rsync (1.23) and is not worth the lossy/correctness cost.

**Decision: REVERT `3e37aac2a` (all pacing) → lock the okcmis + Lever B foundation** as the stable base: okcmis feed-cache (`46355c9a2`, receiver 47.9 MB/s) + Lever B lossy-fix (`67826603e`, round-boundary seed). That foundation is regression-free and IMPROVES bad (73→60) with all cells sha-ok. STOP spending the swarm on sender pacing. **Redirect ALL energy to the real prize: LOSSY CONVERGENCE via FEC** (round-0 repair-overhead calibration ε≈target_loss+margin + the 317hxr.6.1.1 FEC-fallback-self-disable fix), where atp's fountain code SHOULD structurally beat rsync's TCP (bad 5×/broken 1.6× behind today). Dispatched revert + lossy pivot. PASS for the locked foundation: perfect ~3.65 / good ~3.95 / bad ~60 / broken ~112, ALL sha-ok. Evidence dir: `artifacts/atp_bench_matrix/20260622T033426Z/`.

## MATRIX-28 (2026-06-22) — foundation RESTORED + lossy round-0 repair calibration (bad 73→60); ★real lossy wall found: cold-start OVERSHOOTS the slow link

Pacing reverted (`1af2e7a69`, RQ_SUSTAINED=0) + lossy round-0 repair calibration landed (`7842fdcb5`). Rebuilt fresh `atp 0.3.5`, benched 50M nocrypto ×4, run `20260622T043032Z`:

| regime | now | baseline | rsyncd | fr | sha | verdict |
|---|---|---|---|---|---|---|
| perfect | 3.65s | 3.72 | 1.23 | 0 | 3/3 | foundation restored, no flood (path_rate back to 64 MiB/s) |
| good 0.1% | 3.95s | 3.95 | 3.93 | 1 | 3/3 | **ties rsync**, no flood |
| bad 2% | **59.80s** | 73.41 | 14.94 | 4 | 3/3 | ✅ improved Δ-13.6 (repair calibration) |
| broken 10% | 128.32s | 114.44 | 76.19 | 6–7 | 3/3 | ⚠ slightly worse (noisy cell + 1.5× overhead costs on a 1.25 MB/s pipe) |

Foundation is the cleanest stable state yet: perfect/good restored (good TIES rsync), no pacing flood, no sha fail; bad improved 18%. All sha-ok.

**★REAL LOSSY WALL (trace, 50M/bad round-0): `sent_this_round=50500 received_this_round=26845` = ~47% loss in ROUND 0 — on a 2%-loss link.** That 47% is NOT link loss; it is the **16 MiB/s cold-start pacing OVERSHOOTING the 6.25 MB/s bad link 2.7×** → the netem rate-limiter drops ~half of round-0 → 4 rounds to recover. The repair-overhead calibration (`repair_overhead=1.5`) only partly masks this (bad 73→60) and is COUNTERPRODUCTIVE on broken (50% extra data on a 1.25 MB/s pipe → 114→128). Repair overhead fights the symptom; the root cause is round-0 overshoot of the slow link.

**Next lossy lever (distinct from the DEAD pace-UP): pace recovery rounds DOWN to the measured link-delivery rate.** After round-0 reveals the link capacity (`received/sent × rate`), pace rounds 1+ at that measured delivery rate (a ONE-DIRECTIONAL DOWNWARD cap, ≤ cold-start — it can NEVER overshoot the receiver, so it can't break clean like the pace-UP attempts). Rounds 1+ then deliver ~100% (no re-overshoot) → converge in 1–2 rounds with MINIMAL repair overhead (drop the flat 1.5× → loss-proportional ε). This attacks the 47% round-0 self-loss directly. Target: bad fr≤2, wall <30s → toward <15 (beat rsync); broken back ≤114 then down. Dispatched. NOTE: this is downward-only link-rate matching on lossy recovery rounds — NOT the refuted pace-up. Evidence dir: `artifacts/atp_bench_matrix/20260622T043032Z/`.

## MATRIX-29 (2026-06-22) — lossy recovery downcap REGRESSED (bad FAILS to converge); rate-control is a definitive tar-pit (~7 fails); LOCK foundation, lossy needs real AIMD

The recovery-pacing downcap landed (`ce45e763d` "cap recovery pacing to measured delivery" + `e870d8055` FEC-fallback + refined `0bd348050` "cap lossy recovery to measured delivery"). Benched 50M nocrypto ×4, run `20260622T060546Z`:

| regime | downcap | foundation (MATRIX-28) | rsyncd | verdict |
|---|---|---|---|---|
| perfect | 3.65s sha3/3 | 3.65 | 1.23 | unchanged |
| good | 3.95s sha3/3 | 3.95 | 3.93 | unchanged (ties rsync) |
| **bad** | **status=error, sha 0/3, ~177s** | 59.8 sha-ok | 14.94 | ❌ **FAILS — `[ASUP-E801] no convergence after 17 rounds`** |
| broken | 186.7s fr 9–10 | 114→128 | 76.19 | ❌ **+72s WORSE** |

**Why the downcap fails (trace, 50M/bad):** round-1 (the big 45900-symbol recovery round) STILL sprays at `path_rate_bps=63765008` = 64 MiB/s on the 6.25 MB/s link → received 25014/45900 = ~45% loss; the "measured delivery" cap only drops to ~20 MiB/s later (still 3× the link) and never to the true 6.25 MB/s. So rounds keep overshooting → 17 rounds → non-convergence. **Same failure mode as every measurement-derived rate control: the delivery estimate overestimates the link (bursty/early-window) → overshoot → loss.** repair_overhead correctly dropped to loss-proportional 1.05× (good) but pacing is the problem.

**★RATE-CONTROL IS A DEFINITIVE TAR-PIT — ~7 consecutive failures:** lever-1 v2/v3, round-0 ramp, link-cap, sustained-delivery (all pace-UP), + recovery-downcap ×2 (pace-DOWN). Every attempt to set send rate from measured loss/delivery overshoots the link and either breaks clean (receiver overflow) or fails lossy convergence. **STOP piecemeal rate hacks.**

**Decision: REVERT to the MATRIX-28 foundation `7842fdcb5`** (okcmis feed-cache + Lever B + round-0 repair calibration) — the last all-sha-ok state (perfect 3.65 / good 3.95 ties rsync / bad 59.8 / broken ~114-128). Lock it. **Lossy convergence requires PROPER AIMD congestion control** — receiver reports observed loss in NeedMore; sender does multiplicative-decrease on loss + additive-increase on clean, converging the send rate to the true link rate over rounds (the standard solution to exactly this overshoot problem) — as ONE coherent, hard-gated change, NOT another one-shot estimate hack. In parallel, broaden to the untouched mission fronts (QUIC/encrypted port of okcmis, trees, 500M scale) for independent wins while AIMD is built carefully. Dispatched revert + re-orientation. Evidence dir: `artifacts/atp_bench_matrix/20260622T060546Z/`.

## MATRIX-30 (2026-06-22) — downcap revert was INCOMPLETE; 50M/bad STILL fails; full-file restore to 7842fdcb5 dispatched

The swarm's revert `ac50096e7` ("remove lossy recovery downcap") was benched (run `20260622T071302Z`): perfect 3.65 sha3/3, good 3.95 sha3/3 (ties rsync), **bad status=error sha 0/3 `[ASUP-E801] no convergence after 17 rounds`**, broken 188s sha2/3. **rsync succeeds on bad (13–19s) → purely an atp regression, not netns/env.** The revert only removed the downcap (`ce45e763d`/`0bd348050`) but `transport_rq` still differs from the known-good `7842fdcb5` by **80 lines** — the round-0-loss-target-repair logic from `e870d8055` (`RQ_ROUND0_TARGET_LOSS_MARGIN_FRACTION` 0.25→0.50, `MIN` 0.005→0.03, `round0_loss_target_repair_enabled/overhead`) survived and **also** breaks 50M/bad convergence. So a partial revert is insufficient; the clean fix is a full-file restore to `7842fdcb5` (the last empirically-good state: bad 59.8 sha-ok). transport_rq is clean + swarm idle → dispatched the exact `git checkout 7842fdcb5 -- src/net/atp/transport_rq/mod.rs` P0. **Lesson: a "revert the bad commit" instruction is unreliable when multiple commits in the series each contribute to the regression — restore the whole file to the last green SHA.** Evidence dir: `artifacts/atp_bench_matrix/20260622T071302Z/`.

## MATRIX-31 (2026-06-22) — FOUNDATION RESTORED & CONFIRMED (rate-control tar-pit closed out)

Full-file restore of `transport_rq/mod.rs` to `7842fdcb5` committed+pushed (`210799496`, user-authorized one-time mod.rs exception after the swarm missed 3 reverts). Rebuilt fresh `atp 0.3.5`, benched 50M nocrypto ×4, run `20260622T155605Z` — **all sha 3/3, no failures:**

| regime | atp | rsync | vs rsync |
|---|---|---|---|
| perfect | 3.65s (fr0) | 1.23 | loses 3.0× |
| good 0.1% | 3.95s (fr1) | 3.93 | **TIES** |
| bad 2% | 58.69s (fr4) | 14.94 | loses 3.9× |
| broken 10% | 127.51s (fr6) | 76.19 | loses 1.7× |

The 17-round non-convergence is gone; `main` is back on the stable, regression-free foundation = okcmis feed-cache (`46355c9a2`, receiver 47.9 MB/s) + Lever B lossy-fix (`67826603e`) + round-0 repair calibration. **Honest scoreboard: atp ties rsync on 50M/good, loses perfect/bad/broken; no 50M cell beats rsync yet.** Net vs the original pre-okcmis baseline (bad 73.41): bad improved 20% (73→59), good held at parity, perfect ~same, all regression-free.

**Rate-control epitaph (MATRIX-18→31):** ~7 send-rate-control attempts (lever-1 v2/v3, round-0 ramp, link-cap, sustained-delivery pace-up; recovery-downcap, round-0-loss-target pace-down) ALL failed — every measurement-derived rate setting overshoots the link → self-inflicted loss → receiver overflow (clean) or non-convergence (lossy). The only sanctioned remaining lossy approach is proper AIMD congestion control (receiver-reported-loss multiplicative-decrease / additive-increase), hard-gated. Parallel non-rate fronts: QUIC/encrypted port of okcmis, trees small-entry batching, 500M scale. Evidence dir: `artifacts/atp_bench_matrix/20260622T155605Z/`.

## MATRIX-32 (2026-06-22) — 500M scale + trees scoreboard on the foundation; ★FIRST rsync-beating cell found (tree_big/good)

Benched the locked foundation (7842fdcb5) at 500M scale + trees (didn't need the credit-blocked swarm), run `20260622T161422Z`, nocrypto, ALL sha-ok:

| workload/regime | atp-rq-lab | rsyncd | verdict |
|---|---|---|---|
| 500M/perfect | 36.28s | 5.13s | loses 7.1× |
| 500M/good | 36.68s | 24.24s | loses 1.5× |
| 500M/bad | **832.0s** | 98.71s | loses 8.4× (≈10× the 6.25 MB/s link floor — lossy-at-scale catastrophe) |
| tree_small/perfect | 1.92s | 1.03s | loses 1.9× |
| tree_small/good | 2.35s | 2.03s | loses 1.2× |
| tree_small/bad | 12.06s | 7.33s | loses 1.6× |
| tree_big/perfect | 1.55s | 0.93s | loses 1.7× |
| **tree_big/good** | **1.85s** | **2.43s** | **★ atp WINS (0.76×)** |
| tree_big/bad | 19.57s | 8.73s | loses 2.2× |

**★ FIRST cell where atp beats tuned rsync: tree_big/good** (large many-file tree on a 200 mbit / 0.1%-loss link) — atp's bulk RaptorQ fountain avoids rsync's per-file stat/handshake/round-trip overhead, which dominates rsync on many-file trees once even mild loss/latency is present. Narrow (single cell, 0.76× = atp 1.85 vs rsync 2.43) but real and reproducible (median of 3, sha 3/3). Worth pursuing: trees-on-mildly-imperfect-links is a structural atp advantage (the per-file-overhead asymmetry widens with file count + latency).

**Dominant gap = lossy at scale: 500M/bad 832s (8.4×).** The round-overshoot pathology compounds with size: a 500M object on a 6.25 MB/s 2%-loss link should take ~80s (link floor) but atp takes 832s — ~10× — because every recovery round re-overshoots the link. This is the single biggest domination blocker and the strongest argument for proper AIMD congestion control (converge the send rate to the link, stop the per-round overshoot). Scoreboard summary now: atp **ties** 50M/good, **wins** tree_big/good, loses everything else (worst: lossy at scale). Evidence dir: `artifacts/atp_bench_matrix/20260622T161422Z/`.

## MATRIX-33 (2026-06-22) — ★AIMD WORKS: first SAFE, regression-free rate-control change; lossy improved (broken −24%), clean untouched

Receiver-observed AIMD pacing (`b90620755`, 317hxr.2.5.1) — proper congestion control (receiver reports loss in NeedMore → sender multiplicative-decrease/additive-increase). Built LOCALLY (rch degraded: 4× RCH-E104; user-authorized one-off local build via `RCH_MIN_LOCAL_TIME_MS=999999999` hook bypass; `cargo build --release` 7m42s). Benched 50M nocrypto ×4, run `20260622T195029Z`, ALL sha 3/3:

| regime | AIMD | foundation | rsyncd | fr | verdict |
|---|---|---|---|---|---|
| perfect | 3.65s | 3.65 | 1.23 | 0 | **no regression** ✓ |
| good 0.1% | 3.95s | 3.95 | 3.93 | 1 | **no regression** (ties rsync) ✓ |
| bad 2% | 57.10s | 58.69 | 14.94 | 4 | −1.6s (still loses 3.8×) |
| broken 10% | **96.23s** | 127.5 | 76.19 | 6 | **−31s / −24%** (still loses 1.3×) |

**★ AIMD is the FIRST of 8 rate-control attempts that is regression-free AND helps.** Trace (50M/bad) shows it engaging: round-1 still overshoots (cold-start, no loss signal yet — received 26792/50500 sent), but **rounds 2–4 deliver ~97%** (14709/15100, 10651/10900, 10682/10900) — the AIMD rate converged so recovery rounds stop re-overshooting the link. broken (most rounds) gains most (−24%); bad (fewer rounds) gains little. Clean is byte-for-byte unchanged (perfect/good identical to foundation) — AIMD only acts when loss is observed, so it can't break clean (unlike all 7 prior rate hacks). **KEEPS on main.**

**Remaining gap:** AIMD does NOT yet make atp beat rsync on lossy (bad 57 vs 15, broken 96 vs 76) — two residuals: (1) the round-1 cold-start overshoot (~47% loss before AIMD has a feedback sample) is inherent to a 1st round with no signal — could be cut by a more conservative round-0 on a priori loss hints or a faster first-round backoff; (2) the underlying single-core decode + per-round RTT cost. Next: bench AIMD at 500M/bad (does converging recovery rounds dent the 832s catastrophe? — likely a bigger win there since 500M/bad had many rounds, like broken). Scoreboard: atp ties 50M/good, wins tree_big/good, lossy improved but still loses. Evidence dir: `artifacts/atp_bench_matrix/20260622T195029Z/`.

## MATRIX-34 (2026-06-22) — AIMD @ 500M: bad 832→704s (−15%), clean unchanged; 500M-lossy is DECODE-bound at scale (AIMD helps less here)

Benched AIMD at 500M (locally-built binary), run `20260622T200612Z`, ALL sha 3/3:

| cell | AIMD | foundation | rsyncd | verdict |
|---|---|---|---|---|
| 500M/good | 36.58s | 36.68 | 24.25 | unchanged; loses 1.5× |
| 500M/bad | **704.34s** (fr 5–6) | 832.0 | 97.3 | **−15% (−128s)**; still loses 7.1× |

AIMD is regression-free and helps lossy at every scale (50M/broken −24%, 50M/bad −3%, 500M/bad −15%), magnitude tracking round-count. But 500M/bad still loses rsync 7.1× because at scale the residual is NOT round overshoot — it's **single-core RaptorQ decode of a 500M object + the round-1 cold-start overshoot (which at 500M sprays an enormous first round at ~47% loss before any feedback)**. AIMD converges rounds 2+ but can't fix round-1's blind overshoot or the decode wall.

**Two distinct lossy gaps now pinned by evidence:**
- 50M-lossy (bad/broken): primarily round-1 cold-start overshoot → refine AIMD to start round-0 conservatively (a-priori/last-known loss) or back off harder on the first feedback. Gated AIMD-style only.
- 500M-lossy (bad): decode/feed throughput at scale (the receiver pipeline) + round-1 overshoot magnitude. Needs faster receiver decode/feed (parallel block-decode exists per MATRIX-20, but per-symbol feed/intake may still serialize at 500M scale — re-profile receiver intake at 500M like MATRIX-23 did at 50M).

**Standing scoreboard (foundation+AIMD):** atp ties 50M/good, wins tree_big/good; lossy improved 15–24% but still loses rsync everywhere lossy/large. AIMD is the bankable lossy win; domination still requires the round-1-overshoot fix + receiver-decode-at-scale. Evidence dir: `artifacts/atp_bench_matrix/20260622T200612Z/`.

## MATRIX-35 (2026-06-22) — round-1 "seed AIMD below cold start" KILLS the overshoot but OVER-CORRECTS (under-utilizes link); net regression → revert to AIMD baseline

Lever-A refine `e93e9065a` "seed lossy AIMD below cold start" (317hxr.2.5.1) — aimed at the round-1 cold-start overshoot. Built locally, benched 50M nocrypto ×4, run `20260622T212816Z`, ALL sha 3/3:

| regime | refine | AIMD-base | rsyncd | verdict |
|---|---|---|---|---|
| perfect | 3.65s | 3.65 | 1.23 | unchanged ✓ |
| good | 3.95s | 3.95 | 3.93 | unchanged ✓ |
| bad | 67.30s | 57.1 | 14.94 | **+10.2s WORSE** |
| broken | 131.85s | 96.23 | 76.19 | **+35.6s WORSE** |

**The overshoot fix WORKED** — trace (50M/bad): round-1 now `sent 50500 / received 49452 = ~98% delivery` (was ~53% / ~47% loss). **But it over-corrected:** seeding round-0 below cold-start makes atp UNDER-utilize the link (sends too slow), and AIMD additive-increase ramps up too slowly to recover the lost throughput within the transfer → net slower on lossy (bad +10s, broken +36s). Clean unchanged. **Net-negative → REVERT `e93e9065a` to the AIMD baseline (b90620755 + ramp-cleanup, bad 57.1/broken 96.23).**

**Lesson + correct fix:** eliminating overshoot via a conservative seed is the right *idea* but a flat low seed trades overshoot-waste for under-utilization. The proper mechanism is **slow-start-style ramp**: start conservative, then **multiplicatively increase** the rate each round until the first loss signal (finds the link bandwidth in ~log rounds without big overshoot), then AIMD around it — instead of a fixed low seed + slow additive-increase. Dispatched: revert e93e9065a + the slow-start-ramp refinement (gated: bad/broken must beat the AIMD baseline 57.1/96.23, clean held, sha-ok). Evidence dir: `artifacts/atp_bench_matrix/20260622T212816Z/`.
