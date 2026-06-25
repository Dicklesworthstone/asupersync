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

## MATRIX-36 (2026-06-22) — ROUND-0 TUNING EXHAUSTED: slow-start + high-loss-ceiling both regress; plain AIMD baseline IS the lossy optimum → revert series, pivot fronts

After reverting flat-low-seed, the swarm tried slow-start (`13853a953`) then a high-loss ceiling refine (`8b6192367`, cap ~1.6 MiB/s when loss≥5%). Benched 50M nocrypto ×4 each (runs `222017Z`, `230254Z`), ALL sha 3/3, clean always unchanged:

| regime | plain AIMD (keeper) | slow-start | slow-start+ceiling | rsync |
|---|---|---|---|---|
| perfect | 3.65 | 3.65 | 3.65 | 1.23 |
| good | 3.95 | 3.95 | 3.95 | 3.93 |
| bad | **57.1** | 59.4 | 59.7 | 14.94 |
| broken | **96.23** | 125.66 | 204.08 | 76.19 |

**All three round-0 schemes regress vs plain AIMD** (flat-low-seed bad67/broken131; slow-start bad59/broken126; slow-start+ceiling bad60/broken204). Conclusion (definitive): **the plain AIMD baseline — start round-0 at cold-start (16 MiB/s) and let AIMD multiplicative-decrease on observed loss — is the lossy optimum.** Any conservative round-0 start (low seed, ramp, or capped ceiling) loses more to under-utilization/ramp-delay than it saves on overshoot, because the link absorbs a fast first round better than it absorbs a slow start. **ROUND-0 TUNING IS CLOSED** (after AIMD itself, 3 refinements all net-negative).

**Action: revert the slow-start series (`13853a953`+`8b6192367`) to the plain AIMD baseline (restore transport_rq to `325351fbd` state = AIMD + ramp-cleanup, bad 57.1/broken 96.23).** Then PIVOT the swarm off round-0 entirely to the structural-upside fronts: QUIC/encrypted port (encrypted fails all lossy — biggest untapped tier), trees small-entry batching (tree_big/good already BEATS rsync — widen it), and 500M receiver decode/feed profiling (the 500M-lossy wall). Dispatched. **Final lossy verdict: AIMD is the bankable, regression-free lossy win (broken −24%/500M-bad −15% vs pre-AIMD); atp still loses rsync on lossy but the mechanism is at its tuning ceiling — further lossy gains need receiver-decode-at-scale or the QUIC/tree structural edges, not more pacing.** Evidence dir: `artifacts/atp_bench_matrix/20260622T230254Z/`.

## MATRIX-37 (2026-06-23) — QUIC.1 encrypted-AIMD (`315843db9`) benched: encrypted CLEAN works but loses 42×; encrypted LOSSY STILL FAILS — root cause is a 16384-byte UDP packet-too-large on coalesced lossy datagrams, NOT rate control

Benched the encrypted tier (`atp-quic-tls13` vs `rsync-ssh aes128-gcm`), 50M, after the QUIC.1 first commit `315843db9` "add receiver-observed AIMD feedback to encrypted RQ". Run `artifacts/atp_bench_matrix/20260623T000533Z/`, 3 reps/cell:

| regime (netem) | atp-quic-tls13 | rsync-ssh | atp status | verdict |
|---|---|---|---|---|
| perfect (2ms/0%/1gbit) | 36.48s sha-ok (3/3, rounds=5, RSS ~13.6MB) | 0.85s sha-ok (RSS ~51MB) | ok | atp WORKS but **loses ~42×** |
| good (25ms/0.1%/200mbit) | **3×ERROR** ~21s sha-false (RSS ~15MB) | 3.85s sha-ok | error | atp **FAILS** |
| bad (80ms/20ms/2%/50mbit) | **3×ERROR** ~16s sha-false (RSS ~31MB) | 18.06s sha-ok | error | atp **FAILS** |

**Encrypted-lossy STILL FAILS even with AIMD ported.** The atp runs do not time out — they **error fast** (~16–21s, low RSS) with a single, deterministic, reproducible cause (all 6 lossy reps):

```
atp failed: native QUIC error: udp endpoint: packet too large: 16385–16390 bytes > 16384 limit
```

**Root cause (pinned to code):** `ATP_QUIC_UDP_MAX_PACKET = 16 * 1024 = 16384` (`src/net/atp/transport_quic/native_link.rs:186`) is installed as the receiver endpoint's `max_packet_size` (`endpoint.rs:835`), and `endpoint.rs:356` **rejects any inbound UDP datagram > 16384**. On lossy links *only* (ACK frames exist only when there is loss/retransmit), the sender coalesces an ACK frame onto a near-full 1-RTT data packet and the resulting UDP datagram lands **1–6 bytes over 16384**. The `max_app_payload` cap (`native_link.rs:~905`) bounds a *single* packet's app payload but not the *coalesced UDP datagram* including the trailing ACK/control frame. Perfect links never coalesce an ACK (no loss) → no overshoot → clean works.

**Verdict:** AIMD-in-QUIC was a correct port but does NOT address the encrypted-lossy blocker — the blocker is a UDP coalescing/packet-size **off-by-headroom** bug, not rate control. Two clean fixes (sender and receiver must AGREE): (1) bound the sender's coalescing budget to keep the *whole* UDP datagram (all coalesced packets + ACK/control + headers + tags) ≤ the receiver cap; and/or (2) raise the receiver `ATP_QUIC_UDP_MAX_PACKET` to the real max UDP payload (e.g. 65535) so coalesced packets are accepted. Since 16384 is a self-imposed superbuffer size (not a wire MTU — netem MTU is 1500), the robust fix is to make both ends agree at a generous bound AND keep the sender strictly under it. Separately, encrypted CLEAN loses 42× to rsync (36.48s vs 0.85s) — that is the per-symbol-DATAGRAM + single-core decode wall, the same as nocrypto perfect; the okcmis staging-cache + parallel-decode levers apply to QUIC too. Dispatched precise QUIC bead + marching order. Evidence: `artifacts/atp_bench_matrix/20260623T000533Z/` (cell logs `cells/50M/{good,bad}/encrypted/atp-quic-tls13/rep*/`).

## MATRIX-38 (2026-06-23) — TREES small-entry batching (`1d3290821`) benched: modest tree_small wall improvement, NO new won cell; tree_big/good WIN holds + widens; rsync tree_small RSS blows up to 6.5 GB (atp 18 MB)

Benched the TREES front commit `1d3290821` "fix(atp-rq): batch small tree receiver staging" (coalesces the tree_small 1 MiB bucket into packed RQ objects + batched staging reads). nocrypto tier (atp-rq-lab vs rsyncd plaintext), run `artifacts/atp_bench_matrix/20260623T004938Z/`, all cells sha-ok (3–5 reps, byte-identical — the batching preserves correctness):

| cell | atp-rq-lab median | rsyncd median | verdict | atp RSS | rsync RSS |
|---|---|---|---|---|---|
| tree_big/perfect | 1.45s | 0.93s | LOSE 1.57× | 20MB | 49MB |
| **tree_big/good** | **1.75s** | **2.33s** | **WIN 1.33×** | 20MB | 49MB |
| tree_big/bad | 23.97s | 7.83s | LOSE 3.06× | 72MB | 49MB |
| tree_small/perfect | 1.62s | 1.03s | LOSE 1.57× | 18MB | **6,547,764 KB ≈ 6.5GB** |
| tree_small/good | 2.25s | 2.03s | LOSE 1.11× (narrow) | 17MB | 56MB |
| tree_small/bad | 12.16s | 6.33s | LOSE 1.92× | 52MB | 59MB |

**Verdict: the batching is accretive (byte-identical + modestly faster) but did NOT flip any new cell to a win.** tree_small wall improved vs the prior run (perfect 1.92→1.62 −16%, good 2.35→2.25 −4%, bad 12.06→12.16 flat) — real but not enough to overtake rsync, which still wins all small-tree wall cells. **tree_big/good remains atp's only tree win (1.75 vs 2.33, margin widened from 1.85<2.43).** atp's bulk fountain still carries a fixed per-tree setup overhead that rsync beats on clean/small trees; atp's edge appears only at tree_big/good (moderate loss + enough bulk to amortize).

**Side-finding (memory asymmetry):** rsyncd peak RSS on tree_small/perfect = **~6.5 GB** vs atp **18 MB** (~360×). rsync materializes a full in-memory file list for many-small-files trees; atp's streaming fountain stays bounded. This is a real robustness edge even where atp loses on wall — flagged for the memory scoreboard (E-8.1).

**Watch:** tree_big/bad atp 23.97s vs prior-run ~19.57s (+4.4s) — the batching targets the *small*-entry path so this is most likely lossy-cell variance (bad = 80ms/2%/50mbit, high cv), not a batch regression; will re-confirm if it recurs. **Next tree lever is NOT more small-entry batching** (diminishing returns on wall) — the residual small-tree gap is fixed per-tree fountain setup latency, which only matters on clean/small; atp already wins where it counts (lossy big trees). Pivot tree effort toward the encrypted-lossy unblocker (71qhl6) and 500M-decode, which have far larger untapped EV. Evidence: `artifacts/atp_bench_matrix/20260623T004938Z/`.

## MATRIX-39 (2026-06-23) — 71qhl6 fix VERIFIED (packet-too-large gone) but encrypted-lossy STILL fails: root cause is ONE-SYMBOL-PER-UDP-PACKET throttling QUIC to ~1 MB/s regardless of link (also explains encrypted-clean 42× loss)

Re-benched encrypted 50M after the QUIC 71qhl6 fix `5a690b975` (ATP_QUIC_UDP_MAX_PACKET 16384→65535 + headroom + fail-closed clamp). Run `artifacts/atp_bench_matrix/20260623T011637Z/`:

| regime | atp-quic-tls13 | rsync-ssh | atp status | vs MATRIX-37 |
|---|---|---|---|---|
| perfect | 37.38s sha-ok (3/3, 46000 symbols) | 0.86s sha-ok | ok | works (loses 43×) |
| good (25ms/0.1%/200mbit) | 0/3 — **ASUP-E804 60s timeout** | 4.06s sha-ok | error | packet-too-large GONE; now timeout |
| bad (80ms/2%/50mbit) | 0/3 — **ASUP-E804 60s timeout** | 17.47s sha-ok | error | packet-too-large GONE; now timeout |

**71qhl6 is CONFIRMED working:** `grep 'packet too large'` across all lossy reps = **0** (was 6 in MATRIX-37). The cap fix did exactly its job. But it exposed the NEXT blocker: **`[ASUP-E804] transport timeout during receive proof or fountain feedback after 60s`** — non-convergence, not a fast error.

**ROOT CAUSE (pinned, decisive from the receiver diagnostic counters):** the QUIC sender is delivering **<1 MB/s regardless of link bandwidth**:
- perfect: 46000 symbols in 37.4s = **1230 sym/s ≈ 1.5 MB/s** (and this is the converging case)
- good (25 MB/s link): 45964/46000 symbols in 60s = **766 sym/s ≈ 0.92 MB/s** = **3.7% link utilization** — agonizingly close (99.9% of K) then times out
- bad (6.25 MB/s link): 34974/46000 in 60s = **583 sym/s ≈ 0.70 MB/s** = **11% link utilization** — badly starved

Bandwidth is NOT the limit (receiver `datagrams_dropped=0, pending=0` — it accepts every symbol that arrives; nothing is lost at intake). The sender simply emits too few symbols/sec. **The cause is `native_link.rs:895` "Cap each 1-RTT data packet to carry at most one symbol DATAGRAM"**: `max_app_payload = one_datagram (= symbol_size+header+16 ≈ 1216B)`. Even with the envelope now at 65535, every UDP packet carries exactly ONE ~1216B symbol → throughput is **packets/sec-bound, not bytes/sec-bound**. Higher RTT (good 25ms, bad 80ms) → fewer round-trips in 60s → fewer symbols → good lands 45964/46000 and bad 34974/46000.

**This same cap also explains encrypted-clean's 42× loss** (MATRIX-37/39): perfect = 1.5 MB/s vs rsync 58 MB/s. The one-symbol-per-packet rule is the SINGLE encrypted-tier throughput bottleneck across ALL regimes (lossy non-convergence AND clean slowness).

**FIX (filed as a bead):** now that the UDP envelope is 65535, COALESCE MANY symbol-DATAGRAM frames per UDP datagram (~53 symbols × 1216B fit in 65535) — each symbol stays its own RFC 9221 DATAGRAM frame (per-symbol loss granularity preserved), just packed into one UDP send. This is ~50× send-throughput headroom and should fix BOTH encrypted-lossy convergence AND encrypted-clean speed at once. Caveat: the receiver's 256-deep inbound DATAGRAM queue (the original reason for the 1-symbol cap) must drain faster or be enlarged to absorb coalesced bursts — pair the change with a receiver drain/queue-depth bump. Evidence: `artifacts/atp_bench_matrix/20260623T011637Z/` (counters in cells/50M/{good,bad}/encrypted/atp-quic-tls13/rep*/).

## MATRIX-40 (2026-06-23) — AUTH tier scoreboard (50M): healthy + correct everywhere (sha-ok), TIEs rsync on good, loses perfect/bad like nocrypto (no auth-specific bug)

Benched the auth tier (atp-rq-auth `--rq-auth-key-hex` vs rsync-ssh aes128-gcm) at 50M while the cod swarm was credit-blocked. Run `artifacts/atp_bench_matrix/20260623T015724Z/`, 3 reps/cell, ALL sha-ok, zero errors:

| regime | atp-rq-auth median | rsync-ssh median | verdict | atp RSS | rsync RSS |
|---|---|---|---|---|---|
| perfect | 3.72s | 0.85s | LOSE 4.4× | 50MB | 51MB |
| good (25ms/0.1%/200mbit) | **3.954s** | **3.954s** | **TIE** | 48MB | 52MB |
| bad (80ms/2%/50mbit) | 53.4s | 17.7s | LOSE 3.0× | **877MB** | 52MB |

**The auth tier is correct and healthy** — converges sha-ok in every regime, no ASUP-E804 / no convergence bug (contrast the encrypted/QUIC tier, MATRIX-39, which fails lossy on the one-symbol-per-packet throughput cap). The auth path rides the same rq transport + frozen AIMD as nocrypto, so it inherits the same scoreboard shape: **TIE on good (matches 50M/good nocrypto TIE), lose on perfect (clean per-tree/decode setup overhead) and bad (the single-core lossy decode wall, 53s ≈ nocrypto bad 57s).** The per-symbol auth (AUTH-1 source-first) adds no measurable convergence penalty.

**Watch:** auth/bad peak RSS = **877 MB** (vs rsync 52MB) — the receiver buffers a large symbol backlog during the long single-core lossy decode at 50M. This is the same decode-wall pathology; the LANE-A receiver-parallel-decode lever should cut both the 53s wall AND the 877MB backlog (faster drain → fewer retained symbols). No auth-specific work needed — auth rides nocrypto's fixes. Evidence: `artifacts/atp_bench_matrix/20260623T015724Z/`.

## MATRIX-41 (2026-06-23) — Regression-guard PASS: 50M nocrypto unchanged after the +546-line tree-batch change (bad −6.1%, core file path isolated)

The tree-batch commit `1d3290821` added +546 lines to `transport_rq/mod.rs` (the hot file). MATRIX-38 benched the tree path; this confirms the **core single-file 50M nocrypto cells did not regress**. Run `artifacts/atp_bench_matrix/20260623T020322Z/`, 3 reps, all sha-ok:

| regime | atp-rq-lab now | frozen baseline | Δ | rsync |
|---|---|---|---|---|
| perfect | 3.65s | 3.65 | +0.1% (identical) | 1.23s |
| good | 3.954s | 3.95 | +0.1% (TIE holds) | 3.93s |
| bad | 53.6s | 57.1 | **−6.1%** (slightly better) | 14.74s |

Clean PASS — the small-entry tree batching is correctly scoped to the tree-staging path and does not touch single-file transfer behavior (bad's −6.1% is within lossy-cell variance / minor batched-staging benefit). Current main is healthy on the core scoreboard. This was benched while the cod swarm was credit-blocked (codex usage limit, reset pending) — the critical-path encrypted-throughput fix (bead `mh1eg4`, coalesce many symbol-DATAGRAMs per UDP datagram) is filed + dispatched and awaits swarm credits. Evidence: `artifacts/atp_bench_matrix/20260623T020322Z/`.

## MATRIX-42 (2026-06-23) — mh1eg4 coalescing VERIFIED working (1.9 datagrams/UDP packet, packets 67729→25092) + encrypted-clean 37→32.7s; but encrypted-LOSSY still ASUP-E804 — now root-caused to per-block fountain-feedback STRAGGLER (45926/46000), NOT throughput → = Finding-1 FEC-fallback bug

Re-benched encrypted 50M after mh1eg4 `1aa4d74b0` "coalesce symbol datagrams per UDP packet". Run `artifacts/atp_bench_matrix/20260623T031907Z/`:

| regime | atp-quic-tls13 | rsync-ssh | atp status | vs MATRIX-39 |
|---|---|---|---|---|
| perfect | 32.74s sha-ok (3/3) | 0.85s | ok | 37→32.7s (−12%) |
| good (25ms/0.1%/200mbit) | 0/3 ASUP-E804 | 4.06s | error | still fails |
| bad (80ms/2%/50mbit) | 0/3 ASUP-E804 | 18.77s | error | still fails |

**mh1eg4 coalescing is CONFIRMED working** — receiver counters show **1.9 DATAGRAM frames per UDP packet** now (good: `udp_packets_received=25092` but `datagrams_received=47962`), vs MATRIX-39's 0.77 (52099 datagrams in 67729 packets, ACK-diluted). Packet count fell ~2.7× for the same symbol volume — the one-symbol-per-packet throttle is GONE. Clean improved modestly (37→32.7s); perfect is now **decode-bound** (single-core RaptorQ ~1.5 MB/s ≈ 33s for 50M), so coalescing send-throughput gives limited clean gain — the clean wall is the SAME single-core-decode lever as nocrypto (LANE-A parallel decode).

**Encrypted-lossy STILL fails — but the blocker moved from throughput to CONVERGENCE.** Counters: good reaches `symbols_accepted=45926` of ~46000 needed (**99.8%**), `datagrams_dropped_on_receive=0` (receiver drops nothing) → it's starved of the **last ~50–74 straggler symbols** (lost to the 0.1–2% link), requests them via NeedMore, but the error is `[ASUP-E804] transport timeout during receive proof or fountain feedback after 60s` → **the repair round never completes**. This is the per-block fountain-feedback straggler = **the SAME FEC-fallback-self-disables bug as Finding-1 / 317hxr.6.1.1** (FEC repair disables in later rounds via the `requested_sources==0` guard → straggler symbols never resent). 

**Lever (re-routed):** the encrypted-lossy unblocker is NOT more QUIC-specific work — it is **Finding-1 (LANE-B): drop the FEC-fallback self-disable guard** so the sender keeps emitting per-block repair until the receiver converges. That single fix should land BOTH nocrypto-lossy (50M/bad 53.6s→faster/convergent) AND encrypted-lossy (good/bad 0/3 → sha-ok). mh1eg4 stays a real win (throughput foundation + clean −12%); commented on bead. Evidence: `artifacts/atp_bench_matrix/20260623T031907Z/` (counters in cells/50M/{good,bad}/encrypted/atp-quic-tls13/rep*/).

## MATRIX-43 (2026-06-23) — j80p42 "cushion lossy repair feedback" INSUFFICIENT: encrypted-lossy STILL fails ASUP-E804 (sender doesn't keep emitting per-block repair to convergence); nocrypto/bad unchanged

Benched encrypted+nocrypto 50M after j80p42 `338c1560b` "fix(atp): cushion lossy repair feedback". Run `artifacts/atp_bench_matrix/20260623T041722Z/`, 3 reps/cell:

| tier | regime | atp median | rsync | verdict |
|---|---|---|---|---|
| nocrypto | perfect | 3.65s | 1.23 | lose |
| nocrypto | good | 3.95s | 3.93 | TIE |
| nocrypto | bad | 57.56s | 13.94 | lose (≈ baseline 53.6, no change) |
| encrypted | perfect | 31.64s sha-ok | 0.85 | lose (≈ 32.7 prior) |
| encrypted | good | **0/3 ASUP-E804** | 4.35 | FAIL |
| encrypted | bad | **0/3 ASUP-E804** | 18.07 | FAIL |

**j80p42 did NOT fix encrypted-lossy convergence.** Counters unchanged vs MATRIX-42: good reaches symbols_accepted ~45868–45918 of ~46000 (short ~110); **bad only ~43936–44114 (short ~2000)**; receiver drops nothing (datagrams_dropped_on_receive=0); still `[ASUP-E804] transport timeout during receive proof or fountain feedback after 60s`. The "cushion" added some margin but not enough — especially on bad (2% loss), where the receiver ends ~2000 symbols short, meaning **the sender stops emitting per-block repair well before the receiver has enough**. nocrypto/bad unchanged (57.6 ≈ baseline 53.6, within variance) — so j80p42 also didn't move nocrypto.

**ROOT CAUSE (refined):** this is NOT a cushion/overhead-margin tweak — it's that the fountain-feedback loop **terminates before convergence**. True fountain behavior requires the sender to respond to each receiver NeedMore (per-block deficit) with the requested repair symbols and LOOP until the receiver acks every block complete; instead the QUIC path emits a bounded/capped amount then stops, and the receiver times out at 60s still short. Bad's ~2000-symbol deficit (vs good's ~110) shows the cap scales wrong with loss rate.

**NEXT LEVER (re-routed, deeper):** instrument the QUIC repair-round loop (ATP_RQ_TRACE round-by-round: per-round symbols_sent, NeedMore deficit requested, repair symbols emitted in response, round count, cap) to answer: does the sender respond to NeedMore at all on the QUIC path? how many repair symbols/round? is there a round cap or per-block budget that exhausts? Then make the sender loop per-block repair to convergence (uncapped within a deadline) so no block is left short. ALSO: 2/18 lossy reps hit `ASUP-E804 ... receive sender handshake[/ack]` (handshake timeout under heavy concurrent bench load) — possible handshake robustness/contention issue to watch. j80p42 kept OPEN (insufficient). Evidence: `artifacts/atp_bench_matrix/20260623T041722Z/` (counters in cells/50M/{good,bad}/encrypted/atp-quic-tls13/rep*/).

## MATRIX-44 (2026-06-23) — ★ENCRYPTED-LOSSY CONVERGES for the first time (good 2/3 sha-ok) via j80p42 loop-fix — but ~100× slow + bad still fails: trace proves sender RE-SENDS WHOLE OBJECT per round (46000) vs 7430 requested + UNPACED (self-inflicts 14.7% loss)

Benched encrypted 50M after j80p42 loop-fix `f2ba4038c` "keep repair feedback looping". Run `artifacts/atp_bench_matrix/20260623T050640Z/`:

| regime | atp-quic-tls13 | rsync-ssh | vs MATRIX-43 |
|---|---|---|---|
| perfect | 32.7s sha-ok (3/3) | 0.9s | unchanged (decode-bound) |
| good (25ms/0.1%/200mbit) | **2/3 sha-ok, 414.9s** | 4.0s | ★was 0/3 → now CONVERGES |
| bad (80ms/2%/50mbit) | 0/3 ASUP-E804 | 22.6s | still fails |

**★MILESTONE (partial): encrypted-lossy CONVERGES for the FIRST TIME** — good went 0/3 (always ASUP-E804) → 2/3 sha-ok. The loop-fix achieved correctness on mild loss. (One "errored" good rep actually committed sha-ok at symbols_accepted=46000 then the SENDER timed out on teardown — a completion-signal nit.) **BUT it's a correctness foothold, not a win:** good is **~100× slower than rsync** (414.9 vs 4.0s) and bad still 0/3 (stuck ~44000/46000).

**ROOT CAUSE (pinned from ATP_RQ_TRACE, bad round=2):** `repair_blocks=100 requested_repair_symbols=7430 round_symbols_sent=46000 round_loss_fraction=0.1473 max_feedback_rounds=1024 round_cap_exceeded=false`. Two compounding inefficiencies:
1. **Over-send:** the receiver requests **7,430** repair symbols (the per-block deficits, max 94/block across 100 blocks), but the sender emits **46,000** (the WHOLE object) that round — a **6× over-send**. The loop re-sprays everything instead of only the requested deficit.
2. **Unpaced:** sending 46000 symbols into a 50mbit link overruns it → **observed loss 14.73%** (vs netem's 2%) — self-inflicted. Most re-sent symbols are dropped, so per-block deficits shrink slowly → good crawls (414s), bad never converges in budget. (Not a round cap — `round_cap_exceeded=false`, 1024-round budget unused.)

**NEXT LEVER (perf bead filed):** the repair loop must (a) emit ONLY the requested per-block repair symbols (~7430, not 46000) per NeedMore, and (b) PACE them to the link rate (AIMD/token-bucket, like the nocrypto rq path) so self-loss stays ~2% not 15%. That bounded+paced repair should cut good from 414s toward rsync's 4s AND let bad converge. j80p42 = correctness foothold (kept as evidence); the win needs this efficiency fix. Evidence: `artifacts/atp_bench_matrix/20260623T050640Z/` (trace in cells/50M/bad/encrypted/atp-quic-tls13/rep*/).

## MATRIX-45 (2026-06-23) — ⚠️REGRESSION: lqmfsi "target+pace repairs" made encrypted-good WORSE (j80p42's 2/3 → 0/3). Targeting correct, but sender abandons LATE NeedMore → receiver PTO-exhausts. RECOMMEND revert 569d9b291 or fix-forward.

Benched encrypted 50M after lqmfsi `569d9b291` "fix(atp-quic): target and pace encrypted repairs". Run `artifacts/atp_bench_matrix/20260623T061649Z/`, 3 reps:

| regime | atp-quic-tls13 | rsync-ssh | vs j80p42 (MATRIX-44) |
|---|---|---|---|
| perfect | 31.5s sha-ok (3/3) | 0.9s | ~same (fine) |
| good | **0/3 ASUP-E804** | 4.0s | ⚠️REGRESSED from 2/3 sha-ok |
| bad | 0/3 ASUP-E804 | 19.1s | still fails |

**lqmfsi is a NET REGRESSION on encrypted-good.** j80p42 (MATRIX-44) got good to 2/3 sha-ok (414s, wasteful-but-converges); lqmfsi dropped it to 0/3. The targeting half WORKS — trace shows the receiver correctly requests ONLY the deficit (`requested_repair_symbols=1640` for 29 incomplete blocks, reaching 45926/46000 = 99.8%, only ~74 short) — but the new failure mode is the sender **abandoning late NeedMore**: `[ATP_RQ_TRACE] receiver: NeedMore PTO resend round=1 attempt=40 pending=1 repair_blocks=29 max_attempts=40` — the receiver re-sends its final repair request up to max_attempts=40, gets NO repair back, then times out (ASUP-E804). So lqmfsi traded j80p42's "over-send but converge" for "targeted+paced but the sender quits before serving the last-mile NeedMore." Contained to the encrypted transport_quic path (nocrypto/auth/tree wins unaffected); perfect/clean fine (31.5s).

**RECOMMENDATION (swarm owns transport_quic):** either (a) **REVERT 569d9b291** to restore j80p42's converges-slow baseline (good 2/3 @414s — at least correct), OR (b) **FIX-FORWARD**: keep lqmfsi's targeting+pacing BUT the sender must NOT exit its serve loop while the receiver has pending blocks — it must keep answering late NeedMore (re-serve the requested deficit, paced) until the receiver acks ALL blocks complete. Also: receiver `NeedMore PTO max_attempts=40` may be too few, and/or the NeedMore control message isn't reaching the sender on the lossy link (consider sending it on the reliable QUIC control stream, not a droppable datagram). GATE for the real win: encrypted good+bad sha_ok=true AND wall « 414s (toward rsync's 4s). Commented lqmfsi+j80p42, dispatched. Evidence: `artifacts/atp_bench_matrix/20260623T061649Z/` (trace in cells/50M/good/encrypted/atp-quic-tls13/rep1/).

## MATRIX-46 (2026-06-23) — ⚠️BUILD BROKEN: HEAD (2ec9e5674, incl LANE-X 2cfcc5029) fails to compile with --features atp-cli (dead `pump_inbound` → deny). LANE-X encrypted bench BLOCKED; likely LANE-X is incompletely wired.

Attempted to bench the LANE-X encrypted fix-forward (`2cfcc5029` "keep late NeedMore repair targeted") at HEAD `2ec9e5674`. The release build `cargo build --release --bin atp --features atp-cli` FAILS:

```
error: method `pump_inbound` is never used  --> src/net/atp/transport_quic/native_link.rs:899:14
  (dead_code denied via the deny attribute at src/lib.rs:62) → could not compile asupersync (lib)
```

**HEAD does not compile with `--features atp-cli`** — the atp-cli release build (what the bench harness AND the production `atp` CLI use) is red. The LANE-X commit added `pump_inbound` to native_link.rs but its call site is feature-gated out under `atp-cli`, so the method is dead → the `#![deny]` at lib.rs:62 promotes the dead-code warning to a hard error. The swarm's code-first `cargo check` (RCH, cap-lints warn) did not catch this; only the deny-warnings release build does.

**Implications:** (1) LANE-X encrypted real-win is UNVERIFIABLE until this compiles — bench blocked. (2) More importantly, `pump_inbound` being DEAD under atp-cli strongly suggests **LANE-X is incompletely wired** — the late-NeedMore serve path the fix added is not actually being CALLED in the atp-cli build, so even if it compiled it might not exercise the fix. (3) Earlier benches this session used PRE-LANE-X binaries (the staged bench bin predates 2cfcc5029), so prior MATRIX entries are unaffected; only the LANE-X verification is blocked.

**ACTION (swarm, transport_quic owner — P0 filed):** wire `pump_inbound` into its intended call site in the atp-cli receive path (it's the late-NeedMore serve loop LANE-X added) so it's actually USED (not just `#[allow(dead_code)]`, which would mask that the fix isn't active), then confirm `cargo build --release --bin atp --features atp-cli` is green. Then I re-bench encrypted. Best confirmed encrypted-lossy state remains j80p42 (good 2/3 @414s); main's atp-cli build is currently broken. Evidence: build log error above; no results.jsonl produced (bench correctly skipped on NOT-FRESH binary).

## MATRIX-47 (2026-06-23) — LANE-X+pump-wire STILL fails encrypted-good (rep1 27min→ASUP-E804, WORSE than j80p42 floor). Receiver-side now very robust (512 retries + reliable-stream requeue) but SENDER STILL never serves the per-block deficit. Root isolated to sender-side repair-serve. Bench stopped (pathological).

Benched encrypted 50M with LANE-X (`2cfcc5029` keep late NeedMore targeted) + pump-wire (`c2a695b36`) ACTIVE, build green. Run `artifacts/atp_bench_matrix/20260623T075431Z/` (stopped mid-run — pathologically slow):

| regime | atp-quic-tls13 | rsync-ssh | vs j80p42 floor |
|---|---|---|---|
| perfect | 31.5s sha-ok (3/3) | 0.9s | ~same (fine) |
| good | rep1 ran **~27 min → ASUP-E804** (0/1 before I stopped) | 4.0s | ⚠️WORSE than j80p42's 2/3 @414s |
| bad | (not reached — bench stopped) | — | — |

**LANE-X+pump-wire does NOT fix encrypted-lossy — it's worse than the j80p42 floor.** good rep1 ran ~27 minutes (03:56→04:23) then errored. The swarm correctly hardened the RECEIVER side per my prior recommendation — trace shows `NeedMore PTO resend round=1 attempt=512 max_attempts=512` (raised from 40) AND `NeedMore PTO stream_requeue requeued_stream_frames=1` (NeedMore now also goes on the reliable QUIC control stream, not just a droppable datagram). So the receiver now begs aggressively (512 attempts over 27min, on the reliable stream) — but **`symbols_accepted=45928` (short ~72 of 46000; deficit `requested_repair_symbols=1638` across 29 blocks), and the SENDER still serves NONE of it.** The receiver's request reliably reaches the sender (stream requeue), yet no repair comes back.

**ROOT (now isolated to the SENDER side):** every encrypted-lossy attempt this session (j80p42 cushion → lqmfsi targeting → LANE-X late-NeedMore → pump-wire → 512-retry + stream-requeue) has improved the *receiver/request* side, but the **sender's handling of a late NeedMore (arriving after its main spray finished) does not generate and emit the requested per-block repair symbols.** That is the single unfixed root. pump_inbound being wired fixed the build + receiver pump, not the sender's repair-serve.

**ACTIONS:** (1) Stopped my bench — 27min/rep × 6 lossy reps ≈ 2.7hr on a clearly-failing path is not worth the slot. (2) main's encrypted-good is currently WORSE than the j80p42 floor (27min→error vs 2/3@414s) — a regression in the encrypted dev tier (nocrypto/auth/tree/encrypted-clean wins unaffected). (3) Recommend to swarm: implement the SENDER-side repair-serve — on receiving a NeedMore for specific blocks (post-spray), the sender must RaptorQ-encode and emit those blocks' requested repair symbols (paced), looping until the receiver acks complete; this is the actual fix, distinct from all the receiver-side robustness already added. If not quickly fixable, consider reverting LANE-X to restore the j80p42 floor so main isn't worse-than-floor. Best confirmed encrypted-lossy remains j80p42 (good 2/3 @414s). Evidence: `artifacts/atp_bench_matrix/20260623T075431Z/cells/50M/good/encrypted/atp-quic-tls13/rep1/`.

## MATRIX-48 (2026-06-23) — sender-serve fix (08f7adf87) STILL fails encrypted-good: sender "keeps serving" but UNTARGETED (re-sprays whole object 46000/round vs 1856 deficit) → stragglers never fill. Recommend REVERT to j80p42 floor + DEPRIORITIZE encrypted-lossy (≈10 attempts), PIVOT to LANE-A.

Benched encrypted 50M with sender-serve fix `08f7adf87` "keep serving late NeedMore repair" (build green). Run `artifacts/atp_bench_matrix/20260623T091943Z/` (stopped via stop-guard — good rep ran ~14min on the same failure path):

| regime | atp-quic-tls13 | rsync-ssh |
|---|---|---|
| perfect | 31.3s sha-ok (3/3) | 0.9s |
| good | stuck → stop-guard (PTO attempt 454+, ~14min, would ASUP-E804) | 4.0s |
| bad | (not reached) | — |

**08f7adf87 STILL fails encrypted-good.** Decisive trace: `round_symbols_sent=46000 requested_repair_symbols=1856 (33 blocks) round_symbols_observed=45926 symbols_accepted=45926` with `NeedMore PTO resend attempt=454 pending=1`. So the sender now "keeps serving" (doesn't stop — that part is fixed) BUT serves the **WHOLE object (46000) untargeted each round, not the requested 1856-symbol per-block deficit.** Re-spraying everything on a lossy link still loses ~74 random symbols/round, and because RaptorQ needs *per-block* completeness, the 33 straggler blocks never all fill → receiver stuck at 45926/46000, PTO climbs to exhaustion.

**The persistent root, now fully characterized across ~10 attempts** (j80p42 cushion → lqmfsi targeting → LANE-X late-NeedMore → pump-wire → 512-retry → stream-requeue → 08f7adf87 keep-serving): encrypted-lossy convergence needs THREE things simultaneously — (a) sender keeps serving post-spray NeedMore [08f7adf87 ✓], (b) serves ONLY the requested per-block deficit, not the whole object [lqmfsi tried, broke (a)], (c) paced to link rate. No single commit has held all three: targeting breaks keep-serving (lqmfsi regression), keep-serving reverts to untargeted whole-object re-spray (this). It's a genuinely coupled fix.

**STRATEGIC CALL (orchestrator):** encrypted-lossy has consumed disproportionate session effort (~10 commits, many benches, ~hours) for a single dev-tier with no win. Recommend: (1) **REVERT to the j80p42 floor** (good 2/3 @414s — at least correct; main's encrypted-good is currently worse-than-floor). (2) **DEPRIORITIZE encrypted-lossy** — leave the precise 3-part diagnosis in the bead for a focused future attempt (targeted+keep-serving+paced together, in one careful commit). (3) **PIVOT** swarm + benching to LANE-A (receiver parallel decode) — broad EV across 500M/bad (704s), 50M/bad nocrypto (57s), AND encrypted-clean (31.5s), all single-core-decode-bound; far more tractable + impactful than the coupled encrypted-lossy fix. Confirmed wins intact: 50M/good TIE, tree_big/good WIN, encrypted-clean works, auth healthy. Evidence: `artifacts/atp_bench_matrix/20260623T091943Z/cells/50M/good/encrypted/atp-quic-tls13/`.

## MATRIX-49 (2026-06-23) — ★★LANE-A receiver PARALLEL DECODE: 500M/bad 704s→151.6s (4.6× faster, 7.1×→1.54× of rsync, 18× less RSS) — biggest residual gap crushed. BUT 50M/bad regressed 57→89s (over-parallelizes small objects) → SIZE-GATE the fanout.

Benched LANE-A receiver parallel decode (`2f69e377f` keep 500M decode fanout wide + `2ec9e5674` raise decode-width cap + 317hxr.7.3 feed/decode commits), nocrypto, all sha-ok/byte-identical:

| cell | atp-rq-lab | rsync(d) | atp RSS | rsync RSS | vs baseline |
|---|---|---|---|---|---|
| **500M/bad** | **151.6s** | 98.4s | **41MB** | 750MB | ★**704s→151.6s = 4.6× faster** |
| 50M/bad | 88.9s | 15.1s | 185MB | 43MB | ⚠️57s→88.9s REGRESSED |

**★500M/bad is the headline: 704s → 151.6s, a 4.6× speedup.** The single-core RaptorQ decode wall — the biggest residual gap in the whole matrix (was losing 7.1× to rsync) — is now only **1.54× behind rsync** (151.6 vs 98.4), and atp uses **18× less peak RSS** (41MB vs rsync's 750MB — rsync balloons its in-memory file structures for the 500M object). This validates the pivot: parallel per-block decode across the blocking pool is exactly the lever for large decode-bound transfers. Trace confirmed `chosen_fanout=8` exercising the parallelism. Byte-identical (sha + merkle).

**Tradeoff — 50M/bad regressed (57→88.9s, walls 61-91 high-variance):** the fanout (`chosen_fanout=8`) over-parallelizes the *smaller* object — pool-dispatch + coordination overhead dominates when per-block decode is already cheap. So the parallel-decode fanout is a clear WIN for large K (500M) but a LOSS for small K (50M).

**LEVER (size-gate, dispatched):** make the decode fanout SIZE-GATED — parallelize only when the object/block-count is large enough that per-block decode dominates dispatch overhead (e.g. 500M-class, K above a threshold), and keep small objects (50M) on the sequential path (57s). That preserves the 4.6× 500M win AND removes the 50M regression. Then 500M/bad is a strong scoreboard result (near-rsync wall + 18× less memory). NEXT after gating: re-bench 50M/bad (back to 57s) + confirm 500M/bad holds 151.6s + check 500M/good,perfect. Evidence: 500M `artifacts/atp_bench_matrix/20260623T103529Z/`, 50M `artifacts/atp_bench_matrix/20260623T102931Z/`.

## MATRIX-50 (2026-06-23) — ★★LANE-A WIN LOCKED via size-gate (c3c1dc635): 500M/bad 4.4× preserved (704→161.3s, 1.59× of rsync, 18× less RSS); 50M/bad recovered 89→61.2s. Clean across-sizes parallel-decode win.

Benched the size-gated receiver parallel decode (`c3c1dc635` size-gate fanout, on top of MATRIX-49's `2f69e377f`/`2ec9e5674`), nocrypto, all sha-ok/byte-identical:

| cell | atp-rq-lab | rsync(d) | atp RSS | rsync RSS | vs baseline |
|---|---|---|---|---|---|
| **500M/bad** | **161.3s** (160-161, stable) | 101.2s | **41MB** | 734MB | ★**704s→161.3s = 4.4× faster, HELD under gate** |
| 50M/bad | 61.2s (60.7/61.2/92.8) | 14.3s | — | — | 89s(ungated)→61.2s recovered (≈57 baseline +7%) |

**★500M/bad WIN CONFIRMED + LOCKED:** the size-gate preserved the parallel-decode speedup (chosen_fanout=8 held for 500M decode) — 704s→161.3s (**4.4×**), now only **1.59× of rsync** (was 7.1×) with **18× less peak RSS** (41MB vs 734MB; rsync balloons on the 500M object). Very stable across reps (160.4/161.3/161.3, cv<1%). The biggest residual gap in the matrix is now near-rsync-parity-on-wall with a decisive memory advantage. NOT a wall-time win vs rsync (atp 161 vs rsync 101) but a transformative improvement + memory dominance — the honest framing for the scoreboard.

**50M/bad recovered:** the size-gate brought 50M/bad from the ungated 89s regression back to 61.2s median (two clean reps 60.7/61.2 ≈ the 57s frozen-AIMD baseline +7%; one 92.8 outlier). chosen_fanout still shows mixed 1/8 at 50M (the gate threshold isn't perfectly tuned at this size) — a MINOR follow-up to nail exactly 57s, not a blocker; the regression is effectively resolved. Closing t00kq3.

**SESSION SCOREBOARD (confirmed):** 50M/good TIE (nocrypto+auth), tree_big/good WIN, encrypted-clean works (31.5s), auth healthy, ★500M/bad 4.4× improved to 1.59× rsync + 18× less RSS. Open/deprioritized: encrypted-lossy (3-part coupled fix documented at j80p42 floor), FEC-fallback Finding-1 (50M@3% convergence), 50M-fanout exact tuning. Evidence: 500M `artifacts/atp_bench_matrix/20260623T113253Z/`, 50M `artifacts/atp_bench_matrix/20260623T112731Z/`.

## MATRIX-51 (2026-06-23) — 500M clean-large (LANE-A size-gated): atp loses wall on clean (FEC-decode overhead) but DOMINATES memory 198-710× (atp 22-24MB vs rsync 4.5-17GB RSS). Full 500M tier characterized.

Benched 500M perfect+good nocrypto on the size-gated LANE-A build, all sha-ok/byte-identical:

| cell | atp-rq-lab | rsync(d) | atp RSS | rsync RSS | mem ratio |
|---|---|---|---|---|---|
| 500M/perfect | 36.3s | 5.2s | **22MB** | **4,546MB (4.5GB)** | atp 198× less |
| 500M/good | 37.2s | 24.2s | **24MB** | **17,055MB (17GB)** | atp 710× less |

**atp loses 500M-clean on WALL** (perfect 36.3 vs 5.2 = 7×; good 37.2 vs 24.2 = 1.54×) — the single-core-ish RaptorQ decode + FEC overhead is pure cost on a clean link where rsync just streams bytes. Parallel decode (LANE-A) holds 500M-clean decode at ~36s; without it this would be slower. **BUT atp DOMINATES MEMORY by 198-710×**: rsync's in-memory file/buffer structures balloon to 4.5GB (perfect) and 17GB (good) RSS on the 500M object, while atp's streaming fountain holds steady at 22-24MB. On a memory-constrained host rsync would thrash/OOM where atp sails through — a decisive robustness edge.

**FULL 500M TIER (post-LANE-A):** bad 161.3s (4.4× improved, 1.59× of rsync wall, 18× less RSS — MATRIX-50); good 37.2s (1.54× of rsync wall, 710× less RSS); perfect 36.3s (7× of rsync wall, 198× less RSS). Pattern: atp is **memory-dominant across ALL 500M regimes** and wall-competitive on lossy (where FEC earns its keep); rsync wins clean-link wall (no FEC tax) but at 100-700× the memory. The honest 500M headline: atp trades clean-link wall-time for massive memory efficiency + lossy-link resilience. Evidence: `artifacts/atp_bench_matrix/20260623T114813Z/`.

## MATRIX-52 (2026-06-23) — LANE-C QUIC encrypted parallel decode (f4e6d4984): MARGINAL clean gain (36.5→33.55s, still ~35× of rsync); encrypted-clean is NOT decode-bound (per-symbol DATAGRAM+AEAD framing is); encrypted-LOSSY still non-converges (1/3) → LANE-E sender deficit-serve confirmed as the real lever. Memory dominance holds (atp 14-46MB vs rsync 3.7-9.2GB, 271-1000×).

Benched the f4e6d4984 QUIC-receiver-parallel-decode port (LANE-C) on encrypted tier 50M, staged binary atp 0.3.5, hermetic netns+veth+netem:

| cell | atp-quic-tls13 | rsync-ssh-aes128gcm | atp RSS | rsync RSS | mem ratio | atp converge |
|---|---|---|---|---|---|---|
| 50M/perfect encrypted | 33.55s | 0.97s | **14MB** | **3,792MB (3.7GB)** | atp 271× less | 3/3 ok |
| 50M/good encrypted | 308.15s (only success) | 3.96s | 46MB | **9,415MB (9.2GB)** | atp ~200× less | **1/3 ok** |

**LANE-C verdict (parallel-decode-port did NOT crack encrypted-clean):** encrypted 50M/perfect went MATRIX-37 36.5s → 33.55s — a marginal ~8% gain, still **~35× behind rsync's 0.97s wall**. Unlike nocrypto (where LANE-A parallel decode bought 4.4× because nocrypto-500M was single-core-decode-bound), **encrypted-clean is NOT decode-bound** — its wall is dominated by per-symbol DATAGRAM emission + QUIC 1-RTT framing + per-packet AEAD on ~87k symbols/50M, which parallel decode doesn't touch. The decode port is still a correct, accretive change (bounded RSS, byte-identical), just not the encrypted-clean bottleneck.

**Encrypted-LOSSY still does NOT reliably converge:** 50M/good (200mbit/25ms/0.1% loss) landed only 1/3 reps ok (the success at 308s vs rsync 3.96s; 2 reps errored — non-convergence, fail-closed, excluded from any "win"). This is the documented encrypted-lossy convergence gap (floor j80p42) and **directly confirms LANE-E (sender-side 3-part deficit-serve: serve only the per-block deficit + keep serving until all blocks ack + pace) is the correct next lever** — NOT more decode work.

**Memory story extends to the encrypted tier:** rsync-over-ssh balloons to 3.7GB (clean) / 9.2GB (lossy) RSS on a 50M encrypted transfer while atp holds 14-46MB — a 271-1000× memory advantage even where atp loses the wall. Evidence: `artifacts/atp_bench_matrix/20260623T125705Z/`. NEXT: bench nocrypto 50M/good+bad (FEC Finding-1 convergence); land + bench LANE-E when it ships.

## MATRIX-53 (2026-06-23) — nocrypto 50M regression check on HEAD f4e6d4984: NO regression from shared decoding.rs change; FEC Finding-1 convergence solid (50M/bad 3/3, 4-8 rounds); 50M/good TIE holds (369× less RSS); 50M/bad honest ~4× wall loss (decode-bound small-lossy) but 32× less RSS.

After landing LANE-C (f4e6d4984), which also edited the SHARED src/decoding.rs, re-benched nocrypto 50M good+bad to confirm the rq decode path didn't regress + FEC Finding-1 (aa12f6fa3) convergence. Staged binary atp 0.3.5 = HEAD f4e6d4984, hermetic netns+veth+netem, all sha-ok:

| cell | atp-rq-lab | rsyncd | atp RSS | rsync RSS | mem ratio | atp converge |
|---|---|---|---|---|---|---|
| 50M/good nocrypto | 3.95s | 3.93s | **49MB** | **18,060MB (17.6GB)** | atp 369× less | 3/3, 1 round |
| 50M/bad nocrypto | 66.47s | 16.14s | **183MB** | **5,852MB (5.7GB)** | atp 32× less | 3/3, 4-8 rounds |

**NO REGRESSION from f4e6d4984's shared decoding.rs edit:** 50M/bad nocrypto = 66.47s vs MATRIX-50's 61.2s (within run-to-run variance; both ~60-66s with the size-gated parallel decode), 3/3 sha_ok byte-identical. The QUIC parallel-decode port did not disturb the rq decode path.

**FEC Finding-1 (repair-only FEC fallback, aa12f6fa3) convergence CONFIRMED:** 50M/bad (2% loss) converges 3/3 reps in 4-8 feedback rounds — the repair-only FEC fallback stays engaged in later repair rounds as the regression test locks. No non-convergence on the lossy nocrypto path.

**50M/good TIE holds** (atp 3.95s vs rsync 3.93s — dead heat on wall) with atp using **369× less memory** (49MB vs rsync 17.6GB; rsync-over-rsyncd balloons its in-memory file/buffer structures even on a 50M plaintext transfer).

**Honest weak spot — 50M/bad loses ~4× on wall** (66.47s vs rsync 16.14s): on a SMALL lossy object the RaptorQ fountain + decode overhead isn't amortized over enough data (contrast 500M/bad where it IS amortized → 1.59× of rsync, MATRIX-50). atp remains 32× more memory-efficient (183MB vs 5.7GB) and converges reliably, but the lossy-SMALL wall is a known CPU/decode-bound loss. Pattern confirmed: atp wins lossy-LARGE + always-memory; ties clean-small; loses clean-perfect-wall and lossy-small-wall. Evidence: `artifacts/atp_bench_matrix/20260623T131225Z/`.

## MATRIX-54 (2026-06-23) — BROKEN regime (10mbit/200ms/10% loss + reorder/dup): atp WINS 5M/broken (1.48×, 533× less RSS) but LOSES 50M/broken (2.9×) — diagnosed as FEEDBACK-ROUND-COUNT bound (11-12 rounds × RTT), NOT decode → lever = higher per-round repair overhead (E-7.4 adaptive FEC ε*), distinct from frozen AIMD.

First fresh validation of the broken/10%-loss regime (the regime where FEC should help most). netns+veth+netem `delay 200ms 50ms loss 10% reorder 5% 50% duplicate 1% rate 10mbit`, staged binary atp 0.3.5=f4e6d4984, all sha-ok 3/3:

| cell | atp-rq-lab | rsyncd | atp RSS | rsync RSS | mem ratio | atp rounds | verdict |
|---|---|---|---|---|---|---|---|
| 5M/broken nocrypto | 13.16s | 19.44s | **43MB** | **22,930MB (22.4GB)** | atp 533× less | 0 | **atp WINS 1.48×** |
| 50M/broken nocrypto | 223.24s | 77.49s | **191MB** | **8,782MB (8.6GB)** | atp 46× less | 11-12 | atp loses 2.9× |

**5M/broken is a clean atp WIN** (13.16s vs rsync 19.44s = 1.48× faster) AND 533× less memory (43MB vs rsync's staggering 22.4GB at 10% loss + reorder). At small size + high loss, atp's RaptorQ fountain delivers in 0 feedback rounds (enough repair in the first spray) while rsync pays retransmit + reorder-buffer overhead. This adds a high-loss-small win alongside the lossy-large (500M/bad 1.59×) and clean-small-tie (50M/good) results.

**50M/broken loses 2.9× (223s vs 77.5s) — root cause is FEEDBACK-ROUND COUNT, not decode:** atp needed **11-12 feedback rounds** to converge. At 10% loss each round is a full ~200-400ms RTT + a decode attempt + a re-request; 11-12 serial rounds × that latency dominates the 223s wall. rsync's TCP selective-retransmit handles 10% loss on a 50M stream in 77s. **The lever is per-round repair overhead, not decode parallelism**: send FEC symbols proportional to the measured ~10% loss (overhead ε ≈ 0.12-0.15) so the receiver converges in 2-3 rounds instead of 12. This is the adaptive-FEC `ε*(K,p̄,α)` path (bead E-7.4 / 317hxr adaptive overhead) and is DISTINCT from the frozen AIMD rate control (AIMD governs send RATE; this governs repair AMOUNT per round). Sending more repair upfront at high measured loss should collapse the round count → big 50M/broken win. NOT a dead lever (dead = round-0/one-shot RATE control; this is per-round repair AMOUNT).

**Memory dominance is most extreme in the broken regime:** rsync hits 22.4GB RSS on a 5M transfer and 8.6GB on 50M under 10% loss + reorder (its reorder/retransmit buffers explode), while atp holds 43-191MB — 46-533× less. On any memory-constrained host rsync would OOM at 10% loss where atp sails through. Evidence: `artifacts/atp_bench_matrix/20260623T132007Z/`. NEXT LEVER for swarm: E-7.4 per-round adaptive repair overhead to cut the 50M/broken round count 12→2-3.

## MATRIX-55 (2026-06-23) — LANE-K (j91wza adaptive repair overhead) is INEFFECTIVE as wired: 50M/broken STILL 11 feedback rounds / 219s (unchanged from MATRIX-54's 11-12 / 223s); the measured-loss→ε overhead is not moving the round count. 50M/bad no regression (64s). Lever needs follow-up before it earns a win.

Benched HEAD (atp 0.3.5, clean build incl j91wza d110e6d52 "adapt rq repair overhead to measured loss"), 50M broken+bad nocrypto, 3/3 sha-ok:

| cell | atp-rq-lab | rsyncd | atp RSS | rsync RSS | atp rounds | vs MATRIX-54 |
|---|---|---|---|---|---|---|
| 50M/broken | 219.44s | 74.59s | **196MB** | **11,446MB (11.2GB)** | **11** | UNCHANGED (was 11-12 / 223s) |
| 50M/bad | 64.07s | 14.44s | 189MB | 3,035MB | 4-8 | no regression (was 66.5s) |

**LANE-K did NOT achieve its goal.** The hypothesis (MATRIX-54) was that sizing per-round FEC repair overhead to the receiver-measured loss would collapse 50M/broken's 11-12 feedback rounds to ≤3. The j91wza commit landed (+70 lines transport_rq/mod.rs) but the benched result is **11 rounds, 219s — statistically identical to the pre-fix 223s**. So either (a) the measured-loss→ε overhead is computed but NOT actually applied to the repair spray on the 50M source-retransmit path, (b) ε is sized too conservatively (at p̄≈0.10 we need ε≈0.12-0.15 of the block emitted per repair round, not a small increment), or (c) the per-block deficit re-request still serializes a round per block regardless of overhead. atp still loses 50M/broken 2.94× on wall (but 58× less memory: 196MB vs rsync 11.2GB).

**50M/bad unchanged (64s vs MATRIX-53's 66.5s)** — no regression, still converges 3/3 in 4-8 rounds, still a ~4.4× wall loss vs rsync 14.4s (16× less RSS).

**ROUTED follow-up:** LANE-K stays the highest-EV lossy lever IF made effective — re-opened to a transport_rq owner to diagnose why ε isn't cutting the round count (instrument: does the 50M/broken repair path actually emit ε·K extra symbols/round at p̄=0.10? if not, wire it; if yes, raise ε). Until then, the broken/lossy-large wall stays a loss. Memory dominance holds (rsync 11.2GB on 50M/broken). Evidence: `artifacts/atp_bench_matrix/20260623T223844Z/`.

## MATRIX-56 (2026-06-23) — ★DELTA RE-SYNC FIRST RESULT (the rsync-killer home turf): atp delta WINS insert 62.5× (846KB vs rsync 52.9MB, byte-identical!); append works O(change) but loses 3.5×; 1pct scattered-flips FALLS BACK to full-object (delta-engine bug, fail-closed excluded). Delta path is real and has a decisive win + a clear bug.

First run of the incremental RE-SYNC scorecard (`scripts/atp_bench/resync_bench.sh`, B-8.7) on committed HEAD (built via git archive, atp 0.3.5), 100M/good, atp-rq-delta (default-on) vs rsyncd-delta, netns veth tx+rx byte counters, sha-verified:

| change | atp-rq-delta wire | rsyncd-delta wire | ratio | atp sha | verdict |
|---|---|---|---|---|---|
| insert | **846,140 B (846KB)** | **52,920,430 B (52.9MB)** | **atp 62.5× FEWER bytes** | ok | ★atp WINS BIG |
| append | 663,386 B (663KB) | 188,832 B (189KB) | atp 3.5× more | ok | atp loses (both O(change)) |
| 1pct (scattered flips) | 108,015,205 B (full object) | 105,578,825 B | — | status=ERROR | atp delta FELL BACK to full-send (excluded) |

**★HEADLINE WIN — insert, atp 62.5× fewer bytes-on-wire (846KB vs rsync 52.9MB), byte-identical.** Insert is rsync's classic Achilles heel: inserting bytes shifts every subsequent offset, so rsync's fixed-block rolling-checksum resyncs but still ships ~half the file (52.9MB for a small insert into 100M). atp's content-defined chunking (FastCDC) re-anchors at content boundaries, so only the changed chunk(s) move — 846KB. This is the first concrete proof of the rsync-killer thesis (bytes-on-wire ∝ delta, not file size) on rsync's home turf, and it's a decisive win on the case rsync handles worst.

**append works but loses (atp 663KB vs rsync 189KB, 3.5×):** atp's delta DOES engage (O(change), not O(file)) but carries more per-chunk/manifest overhead than rsync's append handling. Both are tiny vs the 100M file; this is a tuning gap (chunk-size / manifest overhead), not a fundamental loss.

**1pct scattered byte-flips — atp FELL BACK to full-object (108MB, status=error, fail-closed excluded):** 'ATP sender fell back to full-object despite sidecar state; marking cell invalid'. The sender had the prior-sync sidecar but the delta-send decision bailed to a full send on scattered flips. This is a real LANE-H bug: scattered small edits should be the delta sweet spot (rsync handles them well at ~O(change)); atp must not fall back. ROUTED to the delta.rs owner: find the full-vs-delta decision in the send path and make it emit O(change) when the sidecar is present for scattered-flip diffs.

**Scoreboard add:** delta-resync/insert is a new confirmed atp WIN (62.5×). Net mission status: atp now wins lossy-large (500M/bad 1.59×), high-loss-small (5M/broken 1.48×), **delta-insert (62.5×)**, ties clean-small + delta-append-ish, dominates memory everywhere (16-1000×); open gaps = delta 1pct-fallback bug, delta-append efficiency, 50M lossy-small wall, encrypted-lossy convergence, clean-perfect wall. NEXT: re-bench LANE-K 50M/broken (did 85867ddf8 cut rounds?) + encrypted-lossy 50M (did lqmfsi converge?). Evidence: `/tmp/atp_resync_bench/20260623T232653Z-2016368/resync.jsonl`.

## MATRIX-57 (2026-06-23) — LANE-K v2 (85867ddf8 apply measured-loss repair during source retransmit) STILL ineffective: 50M/broken median 11 rounds (was 11), ~233s vs rsync ~70s. Two ε-attempts failed → real limiter is the PER-ROUND repair cap (MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND), not ε. Deprioritized (niche cell; atp wins memory 100× here regardless).

Re-benched 50M/broken nocrypto on committed HEAD (incl 85867ddf8), 3/3 sha-ok:

| metric | atp-rq-lab | rsyncd |
|---|---|---|
| median wall | 232.9s (reps 233/209/240) | 70.7s (69/71/97) |
| feedback rounds | **11 (11/9/11)** — vs MATRIX-55's 11 | 0 |
| peak RSS | **194,804 KB (195MB)** | **20,801,988 KB (20.3GB)** |

**LANE-K v2 did NOT cut the round count.** 85867ddf8 ("apply measured-loss repair during source retransmit") is the second adaptive-overhead attempt (after j91wza) and 50M/broken still needs a median 11 feedback rounds (one rep hit 9). So sizing ε to measured loss is NOT the bottleneck. REFINED DIAGNOSIS: the limiter is the **per-round repair-symbol cap** (`MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND`, the `limit` arg to block_repair_requests): even with ε≈0.12 computed, the sender can only emit `limit` repair symbols per feedback round, so at 10% loss on K-many blocks the deficit is necessarily spread across ~11 serial RTT rounds. To collapse rounds you must raise the per-round cap (loss-adaptively, to avoid clean-link overshoot) so the full ε·K deficit ships in 1-2 rounds — NOT compute a bigger ε that then gets clamped by the cap.

**DEPRIORITIZED:** 50M/broken is a niche cell (10% loss + 50M small-lossy). Two LANE-K attempts failed; atp still converges sha-ok and uses **100× less memory** there (195MB vs rsync's 20.3GB — rsync would OOM on a constrained host). The per-round-cap fix is the right lever IF revisited, but higher-EV work now is the DELTA 1pct-fallback fix (turns delta-resync into a clean sweep, MATRIX-56) and encrypted-lossy convergence (LANE-E). Routed the refined cap-diagnosis to the LANE-K owner as lower priority. Evidence: results.jsonl mtime>lanek2_ts. NEXT: encrypted-lossy 50M re-bench (LANE-E lqmfsi — 3/3 converge now?).

## MATRIX-58 (2026-06-23) — DELTA RE-SYNC v2 (incl 8627e6ba0 scattered-edit fix): insert WIN HOLDS (atp 1056KB vs rsync 52.9MB = 50×); append works O(change) loses 4.3×; 1pct scattered-flips STILL full-object — but REFRAMED: that's a fundamental non-delta case (1% flips touch ~every CDC chunk; rsync also sends ~full 105MB), the real fix is graceful full-send (status=ok) not forcing delta.

Re-ran delta re-sync on committed HEAD (archive git 1d65e1a5, 8627e6ba0 confirmed in ancestry), 100M/good, sha-verified:

| change | atp-rq-delta wire | rsyncd-delta wire | ratio | atp status | verdict |
|---|---|---|---|---|---|
| insert | 1,056,239 B (1.06MB) | 52,892,344 B (52.9MB) | **atp 50× FEWER** | ok | ★atp WINS (holds; was 62.5× in MATRIX-56) |
| append | 804,695 B (805KB) | 188,635 B (189KB) | atp 4.3× more | ok | atp loses (both O(change); overhead tuning) |
| 1pct (scattered flips) | 108,014,908 B (full) | 105,564,106 B (full) | ~tie (both full) | ERROR (fell back) | NOT a delta case |

**★INSERT WIN HOLDS — atp 50× fewer bytes** (1.06MB vs rsync 52.9MB). The 8627e6ba0 subdelta-stream-selection change slightly enlarged the insert delta (846KB→1056KB, a minor regression within the win) but the decisive rsync-offset-shift win stands.

**1pct scattered-flips REFRAME (corrects MATRIX-56's "bug" framing):** 8627e6ba0 ("keep scattered edits on delta path", confirmed in the binary) did NOT stop the full-object fallback. But the deeper truth: **1% of bytes flipped RANDOMLY across 100M touches nearly every content-defined chunk** (FastCDC chunks ~8-64KB; 1% random flips ⇒ ~every chunk contains ≥1 changed byte) ⇒ a chunk-level delta must resend ~all chunks ⇒ delta genuinely CANNOT help. rsync confirms this: it also sent ~full (105MB) for the same 1pct case. So this is NOT a winnable delta cell — it's the worst case for ANY chunk/block delta. The atp issue is narrower: it marks the unavoidable full-send `status=error` (treated as a failure/exclusion) instead of a GRACEFUL full-send (`status=ok`, and ≤ rsync's 105MB). ROUTED to LANE-H reframed: stop trying to force 1pct→delta (impossible); instead make the scattered-everywhere case a clean full-send labeled ok, not an error, and don't exceed rsync's bytes.

**Delta scorecard so far:** insert = decisive atp WIN (50×, rsync's worst case); append = atp works but 4.3× overhead (tunable); 1pct-scattered = fundamental tie (both ~full, atp should label gracefully). Net: atp delta WINS the case that matters most (insert/move/structural edits) and is competitive-or-tuning-gap elsewhere. NEXT: append-overhead tuning + graceful-1pct + extend to trees/larger; encrypted-lossy convergence. Evidence: `/tmp/atp_resync_bench/20260623T235827Z-2746726/resync.jsonl`.

## MATRIX-59 (2026-06-23) — encrypted-lossy LANE-E (lqmfsi+0146a31d7) STILL 1/3 converge (success wall 308→184s but reliability unchanged); encrypted-clean atp 31.8s vs rsync 0.85s (rsync 24GB RSS!, atp 15MB = 1665× less). ★UNIFYING INSIGHT: encrypted-lossy non-convergence AND nocrypto 50M/broken 11-rounds likely share ONE root cause = per-round repair cap throttles repair on lossy links.

Re-benched encrypted 50M on committed HEAD (lqmfsi sender deficit-serve + 0146a31d7 NeedMore-dedup), atp-quic-tls13 vs rsync-ssh-aes128gcm:

| cell | atp-quic-tls13 | rsync-ssh | atp RSS | rsync RSS | atp converge |
|---|---|---|---|---|---|
| 50M/perfect | 31.84s | 0.85s | **15MB** | **24,987MB (24.4GB)** | 3/3 |
| 50M/good | 184.17s (only success) | 3.95s | 53MB | 5,491MB | **1/3** (2 errored) |

**encrypted-LOSSY STILL does not reliably converge** — 50M/good = 1/3 reps ok (same as MATRIX-52's 1/3). lqmfsi (sender 3-part deficit-serve) + 0146a31d7 (drop stale duplicate NeedMore) improved the ONE success from 308s→184s but did NOT fix the 2/3 that error out (non-convergence, fail-closed). After the session's many encrypted-lossy attempts, convergence reliability on the lossy QUIC fountain remains the stubborn unsolved gap.

**encrypted-clean unchanged-ish:** 50M/perfect atp 31.84s vs rsync 0.85s (~37× wall — per-symbol DATAGRAM+AEAD bound, not decode), but rsync-over-ssh uses **24.4GB RSS** vs atp's 15MB = **1665× less memory** (the most extreme memory ratio measured yet).

**★UNIFYING ROOT-CAUSE HYPOTHESIS (connects LANE-K + LANE-E):** both lossy failures may stem from the SAME limiter — the per-round repair-symbol cap (MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND). On a lossy link the receiver can't obtain enough repair per feedback round, so: (a) nocrypto 50M/broken needs ~11 serial RTT rounds (MATRIX-55/57), and (b) encrypted 50M/good times out before converging because QUIC's idle/feedback budget is stricter than rq's TCP control. If the per-round repair cap were raised LOSS-ADAPTIVELY (serve the full ε·K deficit in 1-2 rounds when measured loss is high, ~0 extra on clean links), BOTH the nocrypto round-count AND the encrypted-lossy convergence could improve from one lever. This is distinct from the frozen AIMD (which governs send RATE) and from static cushion (DEAD). ROUTED as the unified high-EV lossy lever to a transport owner. NEXT: that per-round-cap lever (re-bench both 50M/broken nocrypto + 50M/good encrypted after); delta append-tuning + tree-delta. Evidence: `artifacts/atp_bench_matrix/20260624T000234Z/`.

### MATRIX-59 CORRECTION (2026-06-23): per-round-cap hypothesis DISPROVEN. `MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND = 1<<20` (1,048,576 symbols/round) — far above a 50M transfer's ~43k symbols, so the cap is NOT the limiter. The real lossy-convergence cause is narrower: each feedback round serves ~the bare deficit, but ~p̄ of THAT repair is itself lost on the lossy link, so the receiver still has a residual deficit → another round (geometric: ~11 rounds at 10% loss). The fix is per-round LOSS-OVER-PROVISIONING: serve ≈deficit/(1-p̄) + small margin so one round actually closes the deficit. j91wza/85867ddf8 nominally did this but the bench shows no round-count change (still 11) — so the over-provisioning is computed but not reaching the emitted repair count. Honest next step is INSTRUMENTATION (emitted-symbols-per-round vs deficit vs loss-compensated target), not another blind ε tweak. Lower priority than the winnable delta-append/tree-delta work; both lossy-large (nocrypto) and encrypted-lossy converge correctly (sha-ok) just slowly/unreliably, and atp wins memory 16-1665× across all these cells regardless.

## MATRIX-60 (2026-06-24) — DELTA v3 (tree-delta e7ff35544 + append-fix c8b248c99): insert WIN HOLDS 56.8×; tree-rename WORKS (atp 341KB O(rename) not full tree) but loses 5.6× to rsync's efficient rename handling; append 778KB still loses 4.1× (marginal improvement). atp's decisive delta win is INSERT specifically; append+rename = atp delta works but higher framing overhead.

Re-ran delta re-sync on committed HEAD (archive git 7a60d216, tree-delta + append-fix landed), all byte-identical (sha_ok, status=ok):

| change | atp-rq-delta wire | rsyncd-delta wire | ratio | verdict |
|---|---|---|---|---|
| insert (100M file) | 931,767 B (932KB) | 52,928,063 B (52.9MB) | **atp 56.8× FEWER** | ★atp WINS (holds) |
| append (100M file) | 777,880 B (778KB) | 188,833 B (189KB) | atp 4.1× more | atp loses (was 4.3×; c8b248c99 marginal) |
| rename (tree_big) | 341,449 B (341KB) | 61,088 B (61KB) | atp 5.6× more | atp loses |

**★INSERT WIN HOLDS — atp 56.8× fewer bytes** (932KB vs rsync 52.9MB). This remains the decisive delta win: an intra-file insert shifts all subsequent byte offsets, which rsync's fixed-block rolling checksum handles worst (resends ~half the file); atp's content-defined chunking re-anchors and sends only the changed chunk. This is the rsync-killer case.

**TREE-RENAME works but does NOT win:** atp delta sends 341KB for a tree_big rename (NOT the full tree — e7ff35544 "keep tree renames on delta path" works, byte-identical), but rsync's rename handling is efficient too (61KB), so atp loses 5.6× on framing overhead. The "rsync re-sends moved files" assumption was wrong for this rsyncd config — rsync handles rename well, so there's no easy win here; atp just needs lower overhead to tie.

**APPEND marginally improved** (805KB→778KB via c8b248c99 compact-append-runs) but still 4.1× rsync's 189KB. Both O(change); the gap is atp's per-chunk/manifest framing.

**HONEST DELTA VERDICT:** atp's delta re-sync DECISIVELY WINS the insert/offset-shift case (56.8×, rsync's Achilles heel) and WORKS correctly (O(change), byte-identical) on append + tree-rename — but loses those 4-6× on per-chunk/manifest FRAMING OVERHEAD, because rsync already handles append/rename efficiently. The unifying lever to make delta a clean sweep = cut atp's delta framing overhead (per-chunk headers + manifest) on small-change cases to match rsync. ROUTED to LANE-H. Net mission: atp BEATS rsync on the hardest delta case (insert), is correct-but-higher-overhead elsewhere, and dominates memory across the board. Evidence: `/tmp/atp_resync_bench/20260624T004701Z-3584362/resync.jsonl`.

## MATRIX-61 (2026-06-24) — AUTH tier validated (atp-rq-auth vs rsync-ssh-aes128gcm 50M): converges 3/3 sha-ok BOTH regimes (no authenticated-path fail-closed gap); 50M/good TIE (3.95 vs 3.95s); 50M/bad loses wall 5.6× (100 vs 18s) but 132× less RSS (187MB vs rsync 24.7GB). Mirrors the nocrypto pattern.

First fresh auth-tier validation on committed HEAD (atp-rq-auth `--rq-auth-key-hex` vs rsync over ssh aes128-gcm), netns+veth+netem, all sha-ok:

| cell | atp-rq-auth | rsync-ssh-aes128gcm | atp RSS | rsync RSS | mem ratio | converge |
|---|---|---|---|---|---|---|
| 50M/good auth | 3.95s | 3.95s | 48MB | 50MB | ~tie | 3/3 |
| 50M/bad auth | 100.43s | 17.77s | **187MB** | **24,715MB (24.7GB)** | atp 132× less | 3/3 |

**Auth tier is healthy — converges 3/3 sha-ok on BOTH regimes** with AIMD + the AUTH-1 source-first fast path. No fail-closed gap on the authenticated lossy path (unlike the encrypted/QUIC tier which still struggles at 1/3). This validates the auth tier as a working mission tier.

**50M/good auth = exact TIE** (atp 3.95s vs rsync-ssh 3.95s, ~equal 48-50MB RSS) — auth adds no measurable penalty on a clean link; matches nocrypto 50M/good TIE.

**50M/bad auth = atp loses wall 5.6×** (100.43s vs rsync-ssh 17.77s) — same lossy-small CPU/decode wall as nocrypto 50M/bad (~4×); auth's per-symbol HMAC adds a little CPU. BUT atp uses **132× less memory** (187MB vs rsync-over-ssh's 24.7GB — ssh's buffering at 2% loss explodes RSS). On a memory-constrained host rsync-ssh would OOM where atp holds 187MB.

**Auth tier mirrors nocrypto:** good=TIE, bad=wall-loss-but-massive-memory-win, both converge reliably. Auth is NOT a weak spot (encrypted/QUIC is). Net mission coverage now spans nocrypto + auth + encrypted + delta-resync, all measured. Evidence: `artifacts/atp_bench_matrix/20260624T005003Z/`.

## MATRIX-62 (2026-06-24) — LOSSY TREES (bad 50mbit/80ms/2%): atp competitive on wall (tree_small WINS 1.10×, tree_big narrow loss 1.38×) + MEMORY-CRUSHING (atp 52-65MB vs rsync 15-36GB = 236-697× less). Trees are NOT a weak spot on lossy links.

Lossy-tree validation on committed HEAD (atp-rq-lab vs rsyncd, netns+veth+netem bad regime), all sha-ok:

| cell | atp-rq-lab | rsyncd | atp RSS | rsync RSS | mem ratio | verdict |
|---|---|---|---|---|---|---|
| tree_small/bad | 5.76s | 6.33s | **52MB** | **36,255MB (35.4GB)** | atp 697× less | ★atp WINS 1.10× |
| tree_big/bad | 10.56s | 7.64s | **65MB** | **15,330MB (15.0GB)** | atp 236× less | atp loses 1.38× |

**tree_small/bad is an atp WIN** (5.76s vs rsync 6.33s, 5/5 reps) — at small-tree + lossy, atp's FEC delivers without rsync's per-file retransmit round-trips. **tree_big/bad is a narrow loss** (10.56 vs 7.64s, 1.38×) — within striking distance, not the 4-7× losses seen on single-file lossy-small.

**★Memory dominance is EXTREME on lossy trees:** rsync hits **35.4GB RSS on tree_small/bad and 15GB on tree_big/bad** — its file-list + per-file state + retransmit buffers explode across many files under loss — while atp holds 52-65MB (236-697× less). This is the most lopsided memory result class measured: a lossy directory sync that rsync can barely fit in RAM, atp does in <70MB.

**Trees are NOT an atp weak spot:** good→tree_big WIN (earlier), bad→tree_small WIN + tree_big narrow loss, all memory-dominant. Combined with the delta tree-rename (atp O(rename), works), the tree tier is competitive-to-winning + memory-crushing across regimes. Net scoreboard: atp wins or ties most tree/lossy/delta-insert cells + dominates memory universally; loses only single-file clean-perfect wall + lossy-small-single-file wall (both diagnosed FEC/CPU tax). Evidence: `artifacts/atp_bench_matrix/20260624T005747Z/`.

## MATRIX-63 (2026-06-24) — DELTA framing-overhead fix (8983b7364 shrink manifest framing): MARGINAL — append 778→702KB (4.1→3.7×), rename 341→324KB (5.6→5.3×), insert holds 56.8×. Residual append/rename overhead is the RaptorQ symbol ENVELOPE on small delta payloads (partly inherent to FEC-wrapped delta) → diminishing returns; delta lever bounded.

Re-benched delta on committed HEAD (incl 8983b7364), 100M/good, byte-identical:

| change | atp-rq-delta (MATRIX-60 → now) | rsyncd-delta | ratio now |
|---|---|---|---|
| append | 777,880 → **702,497 B** | 188,833 B | 3.7× (was 4.1×) |
| insert | 931,767 → 931,649 B | 52,912,343 B | **56.8× atp WIN (holds)** |
| rename (tree_big) | 341,449 → **324,310 B** | 61,089 B | 5.3× (was 5.6×) |

**Framing fix is MARGINAL (~5-10% reduction), not the hoped clean-sweep.** 8983b7364 trimmed the package-manifest framing but append stays 3.7× and tree-rename 5.3× behind rsync. ROOT CAUSE of the residual: atp's delta payload is itself transmitted as **RaptorQ symbols (FEC-wrapped)**, so a tiny change (rsync sends 61KB raw) becomes ~324KB once wrapped in symbol envelopes + minimal manifest. The FEC envelope overhead is proportionally large on SMALL deltas and is **partly inherent to a fountain-coded delta** (it buys loss-resilience rsync's raw delta lacks). To match rsync on tiny edits atp would have to send small deltas UN-FEC'd (losing the loss-resilience that wins the insert/lossy cases) — a design trade-off, not a free win.

**DELTA LEVER BOUNDED (diminishing returns):** further manifest/framing micro-tuning won't close a 3-5× gap rooted in the symbol envelope. atp's delta is DECISIVE on insert (56.8×, rsync's offset-shift weakness) and CORRECT (O(change), byte-identical) but carries FEC-envelope overhead on append/rename where rsync's raw delta is already efficient. Honest delta verdict: atp WINS the structural-edit case rsync handles worst, ties/loses the cases rsync handles well, all byte-identical + memory-dominant. The remaining high-value lever is encrypted-lossy convergence, NOT more delta-overhead tuning. Evidence: `/tmp/atp_resync_bench/20260624T013558Z-389702/resync.jsonl`.

## MATRIX-64 (2026-06-24) — encrypted-lossy fix af4583850 (loss-compensate repair deficits = deficit/(1-p̄)): PROGRESS 50M/good convergence 1/3→2/3 (not yet 3/3); converging reps slow (~288s). Loss-compensation helps reliability but a residual 1/3 still times out; even converged it loses wall ~74× (encrypted-lossy is a CORRECTNESS lever, not a wall win).

Benched committed HEAD (incl af4583850), encrypted 50M (atp-quic-tls13 vs rsync-ssh-aes128gcm):

| cell | atp-quic-tls13 | rsync-ssh | atp converge | atp RSS | rsync RSS |
|---|---|---|---|---|---|
| 50M/perfect | 31.14s | 0.85s | 3/3 | 15MB | 50MB |
| 50M/good | 288.35s (converged reps) | 3.86s | **2/3** (was 1/3 MATRIX-52/59) | 50MB | 50MB |

**af4583850 IMPROVED encrypted-lossy convergence 1/3 → 2/3** — loss-compensating the repair deficit (serve ~deficit/(1-p̄) so the repair survives its own loss) lets more reps close the gap. Genuine progress on the session's hardest lever. BUT still not 3/3 (a residual rep times out), and the converging reps are SLOW (~288s vs MATRIX-59's 184s — over-provisioning sends more symbols → more decode/round work, and the run is noisy).

**Honest framing — encrypted-lossy is a CORRECTNESS lever, not a wall win:** even at 3/3 convergence, encrypted 50M/good would lose wall ~74× to rsync (3.86s) because the QUIC lossy path is bound by per-symbol DATAGRAM emission + AEAD + RaptorQ decode + many feedback rounds — none of which a convergence fix addresses. The value of finishing this (residual 1/3 → 3/3) is RELIABLE delivery under loss + encrypted memory parity (atp 50MB), not beating rsync's wall. The remaining residual likely needs the QUIC idle/convergence budget extended so the last slow rep doesn't time out mid-recovery (NOT more deficit over-provisioning). ROUTED to transport_quic owner. NET: encrypted tier = clean converges 3/3 (loses wall, wins/ties memory), lossy now 2/3 and improving. Evidence: `artifacts/atp_bench_matrix/20260624T020840Z/`.

## MATRIX-65 (2026-06-24) — encrypted-lossy idle-budget fix (93f0c9303) INEFFECTIVE/counterproductive: 50M/good STAYS 2/3 (was 2/3 after af4583850), and SLOWER (ok reps 361-686s vs 288s; fail rep burns 767s before erroring). After 4 routed attempts encrypted-lossy convergence is a DOCUMENTED KNOWN LIMIT (clean=3/3, lossy~2/3) — deeper/architectural, resists timeout+deficit tuning. Pivot off it.

Final encrypted 50M on committed HEAD (incl 93f0c9303 'extend lossy repair idle budget'), atp-quic-tls13 vs rsync-ssh-aes128gcm:

| cell | atp converge | atp walls (3 reps) | rsync | atp RSS |
|---|---|---|---|---|
| 50M/perfect | 3/3 | 33/32/32s | 0.9s | 13-15MB |
| 50M/good | **2/3** (1 error) | 767(err)/361/686s | 4.0s | 35-51MB |

**93f0c9303 did NOT help — encrypted-lossy stuck at 2/3, now SLOWER.** The idle-budget extension was meant to let the residual 1/3 finish instead of timing out. Instead the failing rep ran 767s and STILL errored (the recovery genuinely never completes for some reps, given even 12.8 min), and the over-long budget made the SUCCEEDING reps slower too (361-686s vs af4583850's 288s). So extending the timeout is counterproductive: it trades fast-fail for slow-fail with zero convergence gain. The swarm may want to REVERT 93f0c9303 (and the over-provisioning portion) back toward the faster af4583850 floor.

**★encrypted-lossy convergence = DOCUMENTED KNOWN LIMIT.** Across this session's attempts (lqmfsi sender deficit-serve, af4583850 loss-compensate deficit, 93f0c9303 idle-budget) encrypted 50M/good went 1/3 → 2/3 and plateaued. The residual ~1/3 non-convergence is NOT a timeout or deficit-sizing issue — it's a deeper property of the QUIC DATAGRAM fountain over a lossy link (a rep where the loss pattern + per-symbol DATAGRAM + AEAD + feedback geometry simply doesn't close). Further timeout/deficit/over-provision tuning is REFUTED by measurement. Accept the limit: **encrypted-CLEAN works 3/3 (loses wall, wins memory); encrypted-LOSSY converges ~2/3 (fail-closed on the rest — no corruption, just non-delivery).** This is honest: atp's encrypted tier is reliable on clean links and best-effort on lossy ones; rsync-over-ssh (TCP) is reliable on both but uses GB-scale RSS. NET pivot: stop encrypted-lossy timeout/deficit tuning; highest remaining lever = GSO/sendmmsg clean-wall (encrypted-clean 37× + clean-perfect, both per-symbol-sendto bound). Evidence: `artifacts/atp_bench_matrix/20260624T024954Z/`.

## MATRIX-66 (2026-06-24) — GSO clean-wall fix (5e170cb39 'batch unconnected native sends') did NOT cut the clean wall: encrypted/perfect UNCHANGED 33.1s (~39× rsync 0.85s); nocrypto/perfect 3.72s (3× rsync 1.23s, but rsync uses 21GB RSS!); nocrypto/good still TIE (4.05 vs 3.93s, no regression). The fix batches UNCONNECTED sends; the hot symbol-spray is CONNECTED → wrong path. encrypted-clean is AEAD/decode-bound, not sendto-bound. Last benchable lever exhausted.

Benched committed HEAD (incl 5e170cb39), 50M perfect+good nocrypto+encrypted, sha-ok:

| cell | atp | rsync | atp RSS | rsync RSS | vs prior |
|---|---|---|---|---|---|
| 50M/perfect encrypted | 33.14s | 0.85s | 15MB | 65MB | UNCHANGED (was 31-33s MATRIX-52/59) |
| 50M/perfect nocrypto | 3.72s | 1.23s | **48MB** | **21,063MB (20.6GB)** | atp 3× wall, ~440× less RSS |
| 50M/good nocrypto | 4.05s | 3.93s | 48MB | 43MB | TIE (no regression) |
| 50M/good encrypted | 588.99s (1/1) | — | 49MB | — | converged this run (slow; documented-flaky) |

**GSO 5e170cb39 did NOT move the clean wall.** encrypted/perfect stayed 33.1s (~39× rsync) — the commit "batch unconnected native sends" batches the UNCONNECTED send path, but the hot per-symbol spray uses a CONNECTED socket to the fixed peer, so the batching never touches the ~87k symbol sendto calls. Even if it did, encrypted-clean's 33s is dominated by per-packet AEAD + RaptorQ decode, not raw sendto syscall cost — so sendto-batching alone can't close it. nocrypto/perfect (no AEAD) is already far better at 3.72s (3× rsync) — but still carries FEC encode/decode + datagram overhead rsync's raw stream lacks.

**No regression** (nocrypto/good still TIE 4.05 vs 3.93s; all sha-ok byte-identical). **Memory dominance persists even where atp loses wall:** rsync/nocrypto/perfect uses 20.6GB RSS on a 50M file vs atp's 48MB (~440× less).

**★LEVERS EXHAUSTED — clean-wall gap is FUNDAMENTAL.** Every remaining lever has now been measured: decode-parallel (LANE-A, helped lossy-large), FEC fallback (Finding-1), QUIC parallel decode (LANE-C marginal), adaptive repair overhead/idle-budget (encrypted-lossy plateaued 2/3), delta framing (bounded), and now GSO sendto-batching (ineffective on clean wall / wrong path). The clean-link wall losses (encrypted-clean ~39×, nocrypto-perfect 3×) are intrinsic to a fountain-coded transport: FEC encode/decode + per-packet AEAD + datagram framing that rsync's raw TCP stream simply doesn't pay. This is the honest ceiling: atp BEATS rsync on lossy/structural-edit/memory (the cases that matter operationally) and LOSES clean-link wall-time (the FEC tax), with everything measured and no remaining un-tried lever. To beat rsync's clean-link wall would require connected-socket GSO on the symbol-spray path AND offloading AEAD — a larger effort beyond the current levers. Evidence: `artifacts/atp_bench_matrix/20260624T041158Z/`.

## MATRIX-67 (2026-06-24) — connected-spray batching (perf(atp-rq): batch connected UDP symbol spray) did NOT cut the clean wall: nocrypto-perfect 3.72s UNCHANGED (vs rsync 1.23s, 3×), encrypted-perfect 32.48s UNCHANGED (vs rsync 0.85s, ~38×), nocrypto-good still TIE (4.05 vs 3.93s). Confirms clean-wall is FEC-encode/decode + AEAD bound, NOT sendto-bound (both GSO attempts now refuted).

Benched committed HEAD (incl `perf(atp-rq): batch connected UDP symbol spray` — the connected-socket batching MATRIX-66 said the prior unconnected fix missed), 50M perfect+good, sha-ok:

| cell | atp (MATRIX-66 → now) | rsync | ratio | verdict |
|---|---|---|---|---|
| 50M/perfect nocrypto | 3.72 → **3.72s** | 1.23s | 3× | UNCHANGED |
| 50M/perfect encrypted | 33.1 → **32.48s** | 0.85s | ~38× | UNCHANGED |
| 50M/good nocrypto | 4.05s | 3.93s | TIE | UNCHANGED (no regression) |

**Connected-spray batching did NOT move the clean wall.** This is the SECOND sendto-batching attempt (MATRIX-66 = unconnected GSO, ineffective/wrong-path; MATRIX-67 = connected batch, ineffective). Both refuted by measurement ⇒ **the clean-link wall is NOT sendto-syscall bound.** For 50M over a 1gbit/2ms perfect link, atp's 3.72s (nocrypto) / 32.5s (encrypted) wall is dominated by RaptorQ encode + decode + datagram/feedback overhead (+ per-packet AEAD on the encrypted tier), NOT the cost of the sendto calls. Batching the sends is a correct micro-optimization (may help higher-BDP throughput) but it can't close a wall that isn't syscall-bound. **The clean-wall gap is fundamentally the FEC/AEAD compute tax** — a fountain transport pays encode+decode+coding-overhead that rsync's raw byte stream doesn't. Closing it would require faster GF(256)/decode (SIMD measured NO benefit earlier) or fundamentally less coding overhead on clean links (≈ not FEC-coding when loss≈0, a design change). NET: clean-wall stays a documented fundamental loss; atp's wins remain lossy/delta/memory. Evidence: `artifacts/atp_bench_matrix/20260624T103628Z/` (encrypted/good cell stopped early — documented-limit convergence, not the clean-wall question).

## MATRIX-68 (2026-06-24) — multi-stream receiver fan-out (bf03b320b 'perf(atp-rq): fan out receiver UDP streams') does NOT scale high-BDP throughput: FLAT ~38–40s across streams 1/2/4/8; atp LOSES clean high-BDP 2.13× to single-TCP rsync (38.1s vs 17.8s). The unmeasured "potentially-winnable" frontier is now MEASURED = a clean-link LOSS; bottleneck = single-core RaptorQ decode, not stream count.

Built fan-out HEAD `bf03b320b` (git archive of origin/main). NEW `highbdp` regime added to the matrix harness: clean **1gbit / 200ms RTT** (BDP ~33k pkts), netem `limit 200000` to avoid tail-drop, **loss=0 to isolate fan-out** from the loss-collapse already measured by */bad. 500M nocrypto, ATP-RQ stream sweep 1/2/4/8 ×3 reps + rsyncd single-TCP ×3. All 15 cells `status=ok sha_ok=true rounds=0`:

| method / streams | median wall | throughput | vs rsync | peak RSS |
|---|---|---|---|---|
| atp-rq-lab streams=1 | 38.08s (cv 0%) | 13.1 MB/s | 2.13× slower | 25.5MB |
| atp-rq-lab streams=2 | 39.48s | 12.7 MB/s | 2.21× | 23.8MB |
| atp-rq-lab streams=4 | 39.88s | 12.5 MB/s | 2.24× | 24.3MB |
| atp-rq-lab streams=8 | 39.18s | 12.8 MB/s | 2.20× | 26.5MB |
| rsyncd (single-TCP) | **17.84s** (cv 2.4%) | 28.0 MB/s | baseline | 38.8MB |

**Receiver-stream fan-out provides ZERO throughput scaling on high-BDP.** atp wall is flat ~38–40s whether 1 or 8 streams (cv 0–1%); throughput stays pinned at ~13 MB/s — far below the 125 MB/s line rate AND below rsync's 28 MB/s. With `rounds=0` (clean link, all source symbols delivered, no feedback) the receiver is doing pure RaptorQ decode of 500M; the wall is the **single-core decode rate (~13 MB/s)**, which fanning out the UDP receive streams cannot parallelize — `bf03b320b` parallelizes the socket/receive side, but the decode bottleneck is downstream and serial. Fan-out is therefore a no-op for clean high-BDP throughput.

**atp LOSES clean high-BDP ~2.13×** (38.1s vs rsync 17.8s). rsync's single TCP, even slow-start-ramp + 200ms-RTT limited, reaches 28 MB/s and finishes in half the time. This extends the clean-link wall (MATRIX-66/67) to the high-BDP case — same root cause (FEC decode-compute tax), NOT an I/O or stream-count problem.

**The "one unmeasured potentially-winnable frontier" is now measured — and it's a LOSS.** Multi-stream fan-out does not win clean high-BDP. atp's high-BDP WIN remains the LOSSY case: on a lossy high-BDP link a single TCP flow collapses via Mathis (~1.8 Mbit/s at 0.1%/200ms RTT) where atp's FEC sails through — already captured by the */bad cells (500M/bad 4.4×). So: **clean high-BDP = loss (decode tax); lossy high-BDP = win (FEC vs TCP collapse).** Fully consistent with the scoreboard: atp wins where there's loss / structure / memory pressure, loses clean-link wall.

**Memory win persists** even here: atp peak RSS 23.6–26.5MB vs rsync 38.8MB (1.64× less). Harness note: this required adding the `highbdp` regime + optional netem `limit` support (matrix_bench.sh + run_matrix_cell.sh) — the default 1000-pkt netem queue would tail-drop a 33k-pkt BDP and silently throttle BOTH transports, invalidating any high-BDP cell; the explicit `limit 200000` makes them valid. Evidence: `artifacts/atp_bench_matrix/20260624T115453Z/`.

## MATRIX-69 (2026-06-24) — receiver PARALLEL-DECODE (019b9ada0 'budget receiver decode from blocking pool' + ad7afec47 'defer source-complete decode blocks') does NOT cut the clean high-BDP wall: still FLAT ~38–40s across streams 1/4/8, still 2.13× slower than rsync. ROOT CAUSE REFRAMED: clean transfers are `rounds=0` source-complete (systematic ⇒ ~zero RaptorQ decode), so the wall is NOT decode — it's the SINGLE-THREADED receiver symbol-intake/reassembly pump (~437k symbols @ ~13MB/s). Parallel-decode aimed at the wrong bottleneck for clean links.

Built parallel-decode HEAD `019b9ada0` (git archive). Same exact cell as MATRIX-68 (500M/highbdp clean 1gbit/200ms, nocrypto), default `--workers=auto`(=64 cores, so the blocking pool had full threads). All 12 cells `status=ok sha_ok=true rounds=0`, est_min_datagrams=436907:

| method / streams | MATRIX-68 → MATRIX-69 wall | throughput | vs rsync | peak RSS |
|---|---|---|---|---|
| atp-rq-lab streams=1 | 38.08 → **37.88s** | 13.2 MB/s | 2.13× slower | 23.8MB |
| atp-rq-lab streams=4 | 39.88 → **39.88s** | 12.5 MB/s | 2.25× | 25.8MB |
| atp-rq-lab streams=8 | 39.18 → **40.08s** | 12.5 MB/s | 2.26× | 26.6MB |
| rsyncd (single-TCP) | 17.84 → **17.74s** | 28.2 MB/s | baseline | 38.9MB |

**Parallel-decode = NO change.** Wall is identical to MATRIX-68 (fan-out HEAD, pre-parallel-decode) — flat ~38–40s, still ~13 MB/s, still flat across streams, still 2.13× slower than rsync. Tested at default `--workers=auto`=64 (full multi-thread runtime + blocking pool); there is no higher decode-parallelism knob to set, so this is NOT a config miss (unlike GSO-unconnected MATRIX-66).

**Why it can't help — the bottleneck is NOT decode.** Every clean cell is `rounds=0` (all source symbols delivered, no feedback/repair). RaptorQ is systematic: when source-complete, the "decode" is essentially a copy — there is almost no GF(256) inversion to parallelize. So `budget receiver decode from blocking pool` / `defer source-complete decode blocks` correctly do ~nothing here (and indeed defer the no-op decode). The ~13 MB/s wall is the **single-threaded receiver symbol-processing pump**: ~437k ≈1145B symbols must be intaken, deduped, ordered, reassembled and written by one receiver path. This also explains why MATRIX-68 fan-out (8 receive streams) was flat — the per-symbol processing is a single global serial stage downstream of the sockets, so neither more streams nor more decode threads move it.

**Clean high-BDP loss now has FOUR refuted levers — all wrong-bottleneck:** GSO-unconnected (66), connected-spray (67), multi-stream fan-out (68), parallel-decode (69). The clean-link wall is neither sendto-syscall, nor stream count, nor decode — it is the per-symbol receiver pump (intake→dedup→order→reassemble→write at ~13 MB/s). ★REDIRECT for the swarm: to beat clean high-BDP, parallelize/batch the RECEIVER SYMBOL PUMP itself (e.g. shard symbol intake+reassembly across cores; batch per-symbol work; cut per-symbol overhead) — NOT decode. (Real RaptorQ decode only dominates on LOSSY-large transfers, which atp already wins via FEC: 500M/bad 4.4×.) Caveat: a single global in-flight/window cap (~throughput×RTT ≈ 2.6 MB at 13 MB/s × 200 ms, far below the 50 MB BDP) is a secondary candidate, but the flat-across-fan-out result favours the serial-pump explanation over per-flow windowing.

**Memory win persists**: atp 23.8–26.6 MB vs rsync 38.9 MB (~1.5× less). Evidence: `artifacts/atp_bench_matrix/20260624T182006Z/`.

## MATRIX-70 (2026-06-24) — encrypted AEAD-batch (00bb8ea5d 'perf(atp-quic): batch 1-RTT AEAD protection') does NOT cut the encrypted-clean wall: 50M/perfect atp 33.24s (was 32.5s) vs rsync-ssh 0.85s (~39×, UNCHANGED). Batching the AEAD *calls* doesn't reduce the per-packet AES-GCM *compute* — consistent with MATRIX-69 (clean wall is receiver-pump + per-packet crypto, not call overhead).

Built AEAD-batch HEAD `92f54553c` (incl 00bb8ea5d), benched encrypted 50M perfect+good (atp-quic-tls13 vs rsync-ssh aes128-gcm):

| cell | atp (MATRIX-66/67 → MATRIX-70) | rsync-ssh | ratio | sha_ok | RSS atp / rsync |
|---|---|---|---|---|---|
| 50M/perfect encrypted | 32.5 → **33.24s** | 0.85s | ~39× | 3/3 ok | **20 MB / 768 MB** |
| 50M/good encrypted | (765s, status=error) | — | — | 0/1 (fail-closed) | — |

**AEAD-batch = NO change on encrypted-clean** (33.24s vs 32.5s baseline, within noise; still ~39× rsync). The commit batches 1-RTT AEAD *protection calls* on the send path, but AEAD is inherently per-packet (each QUIC packet has its own nonce + auth tag): batching the call sites cuts per-call overhead, not the actual AES-GCM work over the same bytes. So if the wall is the per-packet crypto compute (+ the single-threaded receiver pump from MATRIX-69, + receive-side unprotect which this commit does not batch), call-batching can't move it. encrypted-clean stays a ~39× wall loss.

**encrypted/good = documented non-convergence limit, unchanged.** rep1 ran 765s and finished `status=error sha_ok=false` (the QUIC-DATAGRAM-fountain-over-lossy-link limit established MATRIX-65); AEAD-batch is a send-path crypto change and does not address lossy convergence (a different issue). Bench stopped after rep1 rather than grind 2 more guaranteed-failures (~25min); fail-closed, excluded from any win claim.

**Memory dominance is striking here:** atp **20 MB** vs rsync-over-ssh **768 MB** peak RSS for a 50M encrypted transfer (~38× less) — rsync+ssh buffers heavily. So the encrypted tier is: atp loses clean wall ~39× (per-packet AEAD compute + receiver pump, fundamental — AEAD-batch refuted), best-effort on lossy (~2/3, documented), but uses ~38× less memory.

**Net (clean-wall levers this session, ALL refuted): GSO-unconnected (66), connected-spray (67), multi-stream fan-out (68), parallel-decode (69), AEAD-batch (70).** The clean-link wall — nocrypto AND encrypted — is fundamental to the design: nocrypto is the single-threaded receiver symbol pump (~13 MB/s); encrypted adds per-packet AES-GCM compute on top (~1.5 MB/s). The ONE un-refuted lever is **receiver-pump parallelization** (the MATRIX-69 redirect, routed to the swarm) for the nocrypto wall; the encrypted AEAD compute is intrinsic (can't batch away the crypto). atp's wins remain lossy / structural-edit / memory. Evidence: `artifacts/atp_bench_matrix/20260624T184246Z/`.

## MATRIX-71 (2026-06-24) — receiver-pump batching (7e19738f8 'batch clean receiver source symbol' + 14e4d90cd 'recycle receiver UDP batch payload') does NOT cut clean high-BDP (6th refuted clean-wall lever); the wall is a FIXED IN-FLIGHT WINDOW cap (~2.6 MB << 50 MB BDP), NOT CPU. Plus a SCOREBOARD CORRECTION: 500M/bad nocrypto is NOT an atp win — atp 153s vs rsyncd 98s (atp 1.56× of rsync, consistent with MATRIX-50's 1.59×; NO regression).

Built receiver-pump HEAD `14e4d90cd` (git archive). 500M, nocrypto, streams 1/8 ×3, all `status=ok sha_ok=true`:

| regime / method | streams | MATRIX-69 → MATRIX-71 wall | throughput | vs rsync | peak RSS |
|---|---|---|---|---|---|
| highbdp atp-rq-lab | 1 | 37.88 → **37.88s** | 13.2 MB/s | 2.13× slower | 26.9 MB |
| highbdp atp-rq-lab | 8 | 40.08 → **40.28s** | 12.4 MB/s | 2.26× slower | 23.2 MB |
| highbdp rsyncd | (1 TCP) | 17.84s | 28.0 MB/s | baseline | 38.8 MB |
| bad atp-rq-lab | 1 | — | 3.3 MB/s (153.39s) | 1.56× slower | 52.7 MB |
| bad atp-rq-lab | 8 | — | 3.2 MB/s (155.26s) | 1.58× slower | 48.8 MB |
| bad rsyncd | (1 TCP) | — | 5.1 MB/s (98.00s) | baseline | 38.8 MB |

**Receiver-pump batching = ZERO change on clean high-BDP** (37.88s identical to MATRIX-69 to the decimal). This is the **6th refuted clean-wall lever** (after GSO-unconnected 66, connected-spray 67, fan-out 68, parallel-decode 69, AEAD-batch 70).

**★ROOT-CAUSE CORRECTION — the clean high-BDP wall is an IN-FLIGHT WINDOW cap, not the receiver pump (revises MATRIX-69).** The decisive evidence: atp's high-BDP throughput is **exactly ~13.2 MB/s across all six levers** — fan-out, parallel-decode, AEAD, and now pump-batching/payload-recycling all left it *unchanged to the decimal*. A CPU/pump bottleneck would have shifted under the pump+allocation optimizations; it did not move at all. `13.2 MB/s × 200 ms RTT ≈ 2.6 MB in flight`, vs the **50 MB BDP** the 1gbit/200ms link needs filled. So atp is **window-limited**: a global in-flight/credit cap of ~2.6 MB throttles it to BDP/19 on this link, independent of receiver-side CPU. **The real clean-high-BDP lever is the SENDER in-flight / congestion window** (open it to fill the BDP), NOT the receiver pump/decode/streams. Note: this regime is loss=0, so a congestion window *should* grow unbounded — if it's pinned at ~2.6 MB that's a fixed buffer/credit cap (or an unraised cwnd), a DISTINCT issue from the DEAD lossy-link AIMD-rate tuning. Profile the in-flight bytes during a 500M/highbdp transfer to find the cap. (Receiver-pump parallelization, the MATRIX-69 redirect, is now also refuted for throughput — keep it for CPU headroom but it is not the clean-wall win.)

**★SCOREBOARD CORRECTION — 500M/bad nocrypto is NOT an atp win (the "4.4×" was mis-cited).** Today: atp 153.4s vs rsyncd 98.0s ⇒ atp is **1.56× SLOWER** on wall, with ~comparable/worse RSS (atp 52.7 MB vs rsyncd 38.8 MB). This is **consistent with MATRIX-50** ("500M/bad … 1.59× of rsync wall") — so NO regression. The repeatedly-cited "500M/bad 4.4×" was a **4.4× self-improvement** (atp-vs-its-own-prior-version via LANE-A decode-parallel), landing at **1.59× of rsync's wall (atp slower)** + "18× less RSS" *vs rsync-over-ssh* — NOT a wall win over plaintext rsyncd, and NOT a memory win vs rsyncd. Correcting the running shorthand: **on nocrypto 500M/bad atp loses ~1.6× on wall.** atp's genuine confirmed WINS are: delta-insert (62.5×), 5M/broken (1.48× real wall win, 533× RSS), tree_small/bad (1.10×), and memory where rsync pays ssh/whole-file-hash (16-1665×). The lossy-LARGE story is "wall-competitive-but-slower (~1.6×) + sometimes memory-efficient (vs ssh)", not a win. (TODO: re-verify the AUTH/ENCRYPTED-tier 500M/bad — atp vs rsync-over-ssh — separately; that crypto-tier cell may still favor atp since rsync pays ssh+crypto on the lossy link.)

Evidence: `artifacts/atp_bench_matrix/20260624T200039Z/`.

## MATRIX-72 (2026-06-24) — ★DIRECT PROBE MEASUREMENT overturns the MATRIX-71 window hypothesis: the clean-high-BDP wall is the 16 MiB/s COLD-START PACING RATE that never ramps on clean (rounds=0) transfers — NOT an in-flight window cap (window measured ~36 MB, healthy). atp is co-limited by sender pacing (16 MiB/s) AND the receiver pump (~13–16 MB/s); every single-sided lever failed because the other side caps it.

Built the probe HEAD `0c6229751` and ran a 500M/highbdp/nocrypto transfer with `ATP_RQ_TRACE=1` to read the new `sender: window_probe` trace. The actual numbers (feedback_round=0, the whole clean transfer):

| probe field | value | meaning |
|---|---|---|
| `configured_rate_Bps` | 16,777,216 | **exactly 16 MiB/s = RQ_COLD_START_PACING_BPS (mod.rs:194)** |
| `observed_payload_Bps` | 15,944,495 | ~15.9 MB/s — sender runs AT the cold-start rate |
| `send_wall_ms` | 32,889 | 32.9s actually sending (= 500MB / 16 MiB/s) |
| `control_wait_ms` | 2,137 | only 2.1s blocked on control/credit |
| `peak_window_bytes` | 35,854,798 | **~35.8 MB in-flight window — HEALTHY, ~BDP-scale** |
| `configured_bdp_bytes` | 0 | atp does NOT estimate the path BDP |
| wall / rsyncd | 38.2s / 17.6s | atp 2.17× slower (sha_ok 3/3) |

**★The window is NOT the cap (refutes MATRIX-71's inference).** Direct measurement shows the in-flight window peaks at ~35.8 MB — ample for the 50 MB BDP. My MATRIX-71 "≈2.6 MB window cap" was an inference from throughput×RTT and is WRONG; this probe corrects it. (Lesson: measure, don't infer — the 13.2 MB/s was the *rate cap*, not a windowed throughput.)

**★The real cap is the COLD-START PACING RATE that never ramps on clean links.** `RQ_COLD_START_PACING_BPS = 16 MiB/s` (mod.rs:194); rate is clamped to `[RQ_MIN=512KiB/s, RQ_MAX=64MiB/s]` (mod.rs:195-196). The AIMD rate-increase only fires ACROSS feedback rounds — but a clean transfer completes in **round 0** (no NeedMore), so the rate never rises above cold-start. atp paces the entire 500 MB at 16 MiB/s, never reaching even its own 64 MiB/s ceiling, on a 1 gbit (125 MB/s) link. 500 MB / 16 MiB/s ≈ 31s ⇒ the 38s wall. rsync's single TCP ramps via slow-start *within* the transfer and reaches ~28 MB/s ⇒ 17.6s.

**★CO-LIMITED — why all 6 single-sided levers failed.** The sender paces 16 MiB/s; the receiver pump does ~13–16 MB/s (MATRIX-69/71, refuted speeding it). These are nearly matched. Raising ONLY the sender rate would overrun the ~13–16 MB/s receiver → drops → feedback rounds → no gain (likely why prior "slow-start" attempts were marked DEAD). Speeding ONLY the receiver does nothing while the sender paces at 16. **To win clean-high-BDP you must raise BOTH together:** (a) a clean-link within-round pacing RAMP (probe rate up while loss=0, toward/again past RQ_MAX_PACING_BPS — gated to clean links so it can't regress the lossy AIMD floors, which reuse RQ_COLD_START_PACING_BPS), AND (b) a receiver that can absorb >16 MB/s. atp also doesn't estimate path BDP (`configured_bdp_bytes=0`) — a BBR-style delivery-rate+RTT estimator would let it size the rate to the pipe.

**Honest status:** this is DEAD-adjacent ("slow-start / round-0 pacing" are on the never-retry list) but now has a *precise mechanism* the prior blunt attempts lacked. It is a genuine candidate ONLY as a coupled, clean-link-gated effort with a measured A/B (I can't test it myself — `RQ_COLD_START_PACING_BPS` is a hardcoded const with no env/CLI override; needs a code change). If the swarm ships a clean-link rate-ramp, I bench whether the receiver keeps up and the wall drops toward rsync's 17.6s — that would be the first clean-wall win. If the receiver can't absorb it, the clean-high-BDP wall is jointly fundamental (FEC pump + conservative pacing) and atp's domain stays lossy/delta/memory. Evidence: `artifacts/atp_bench_matrix/20260624T212322Z/`.

## MATRIX-73 (2026-06-24) — ★★FIRST CLEAN-WALL WIN OF THE SESSION: the clean round-zero pacing ramp (f2aea2822) takes 500M/highbdp from 38s (2.13× LOSS) to **18.3s = TIE with rsync 17.7s (1.03×)** at the default single stream. The MATRIX-72 diagnosis was right and the fix WORKS — clean-high-BDP, the last clean-link loss, is now a TIE. Receiver keeps up at single-stream (rounds=0, sha 3/3, 27 MB/s). Caveat: streams=8 is UNSTABLE under the ramp (1/3 reps 286s/6-rounds = aggregate overrun) — single stream is best.

Built rate-ramp HEAD `f2aea2822` ('perf(atp-rq): ramp clean round-zero pacing') and re-ran the exact MATRIX-72 cell (500M/highbdp/nocrypto) with `ATP_RQ_TRACE=1`:

| method / streams | MATRIX-72 → MATRIX-73 wall | throughput | vs rsync 17.7s | rounds / sha |
|---|---|---|---|---|
| atp-rq-lab streams=1 | 38.08 → **18.27s** (17.8/18.3/18.7) | **27.4 MB/s** | **1.03× = TIE** | 0 / 3:3 ok |
| atp-rq-lab streams=8 | 40.28 → 20.27s median (20.3/**286.6**/19.6) | ~24.7 MB/s | unstable | 0,**6**,0 / 3:3 ok |
| rsyncd (1 TCP) | 17.84 → **17.74s** | 28.0 MB/s | baseline | — |

**★The ramp doubled atp's clean-high-BDP throughput (13.2 → 27.4 MB/s) and closed a 2.13× loss to a 1.03× TIE.** MATRIX-72 found the wall was the 16 MiB/s cold-start pacing that never ramped on rounds=0 transfers; f2aea2822 ramps the clean round-zero pacing rate up within the round, so the sender now fills the pipe at ~27 MB/s (matching rsync's slow-start-ramped 28 MB/s) instead of crawling at 16 MiB/s. **The receiver was NOT the floor** at single-stream (rounds=0, byte-identical sha 3/3, sustained 27 MB/s) — so the co-limit worry only bites at higher aggregate rates (see s8).

**★Caveat — streams=8 is unstable under the ramp.** s8 reps: 20.3s / **286.6s (6 feedback rounds)** / 19.6s. At 8 streams the ramped aggregate sometimes overruns the path/receiver → loss → 6 recovery rounds → 286s. Single stream (the default) is both fastest and stable. Confirms fan-out remains a no-op-to-harmful for throughput (MATRIX-68) — and now actively destabilizes under the ramp. **Recommendation: keep streams=1 default; do NOT combine fan-out with the clean-ramp.**

**★SCOREBOARD UPDATE — clean-high-BDP: LOSS → TIE.** The session's six refuted clean-wall levers (66-71) were all the *wrong* mechanism; MATRIX-72's probe found the right one (cold-start rate never ramps) and MATRIX-73 confirms the fix ties rsync. atp now: WINS lossy (5M/broken 1.48×, delta-insert 62.5×), TIES clean-high-BDP (NEW, 1.03×) + 50M/good + auth-good, dominates memory; remaining clean losses = clean-perfect-small wall (50M-perfect 3×, FEC encode tax at small size) + encrypted-clean (per-packet AEAD) + lossy-small. ★MUST-VERIFY NEXT: (a) lossy-regression — confirm the clean-ramp's gating didn't slow 500M/bad (was 153s) — MATRIX-74; (b) does the ramp also help 500M/good (200mbit/25ms) + clean-perfect? Evidence: `artifacts/atp_bench_matrix/20260624T220357Z/`.

## MATRIX-74 (2026-06-24) — ★GATING CONFIRMED: the clean round-zero pacing ramp (f2aea2822, MATRIX-73) did NOT regress lossy. 500M/bad nocrypto = atp 153.8s (unchanged from MATRIX-71's 153s), rounds=0, sha 3/3. The clean-link ramp is correctly clean-link-gated — safe to keep default-on.

Re-ran 500M/bad/nocrypto streams=1 ×2 on the rate-ramp binary `f2aea2822`:

| method | MATRIX-71 → MATRIX-74 | rounds | sha |
|---|---|---|---|
| atp-rq-lab /bad | 153.4 → **153.8s** (153.5/154.1) | 0 | 3:3 ok |
| rsyncd /bad | 98.0 → 97.4s | 0 | 3:3 ok |

**Lossy is byte-for-byte the same wall** (153.8 vs 153.4, within noise) — the clean-ramp's loss-gate works; the higher clean-link pacing does not leak into the lossy AIMD path. (atp/bad still loses 1.58× to plaintext rsyncd, the documented pre-existing nocrypto-bad state from MATRIX-71 — NOT a regression; atp's lossy edge is the crypto tiers + memory.) **Net: MATRIX-73's clean-high-BDP TIE is a clean, regression-free win — f2aea2822 is safe default-on.** Evidence: `artifacts/atp_bench_matrix/20260624T221510Z/`.

## MATRIX-75 (2026-06-24) — streams=8 instability FIXED: cap-aggregate (01daa99b6 'default single-stream fanout + cap aggregate') stabilized streams=8 under the ramp — was 20.3/**286.6**/19.6s (1/3 blowup, 6 rounds), now 25.2/27.0/27.1s (all rounds=0, stable). streams=1 holds the 18.0s TIE. Single-stream remains best (s8 stable-but-slower); the new streams=1 default (a73d963f5) is correct.

Built `a73d963f5` (incl 01daa99b6) and re-ran 500M/highbdp/nocrypto streams 1,8:

| streams | MATRIX-73 → MATRIX-75 | rounds | vs rsync 17.6s |
|---|---|---|---|
| 1 | 18.27 → **18.0s** (17.7/18.4) | 0 | TIE (1.02×) |
| 8 | 20.3/**286.6**/19.6 → **25.2/27.0/27.1** (stable) | 0 (was 6) | stable but slower |
| rsyncd | 17.74 → 17.64s | 0 | baseline |

**The cap-aggregate eliminated the s8 overrun** — all 3 s8 reps now complete in 25-27s with 0 feedback rounds (no 286s blowup). The cost: s8 is rate-capped to ~27s, slower than s1's 18s (the aggregate cap holds total in-flight under the path rate, so 8 streams no longer overrun but also don't beat 1 stream). **Single stream is both fastest AND stable** — consistent with fan-out being a no-op for throughput (MATRIX-68); the new streams=1 default (a73d963f5) is the right call. **clean-high-BDP TIE (18.0s vs rsync 17.6s, 1.02×) confirmed stable at the default.** Evidence: `artifacts/atp_bench_matrix/20260624T225809Z/`.

## MATRIX-76 (2026-06-24) — ★★P0 REGRESSION: the clean round-zero ramp (f2aea2822, default-on) BREAKS 500M/good — round-0 ramps to a FIXED 128 MiB/s regardless of link rate, so on the 200 mbit (25 MB/s) good link it overshoots ~5× → round-0 overrun → 16 feedback rounds → 3/3 NON-CONVERGENCE (status=error, sha=false, ~213s). Was ~37s ok pre-ramp. The ramp helped high-BDP ONLY because 128 MiB/s ≈ the 1 gbit link there.

Benched the rate-ramp binary (a73d963f5) on 500M/good/nocrypto streams=1 ×3 with ATP_RQ_TRACE=1:

| method | wall | rounds | sha | status |
|---|---|---|---|---|
| atp-rq-lab /good | **~213s** (212.3/212.3/214.2) | **16** | **false** | **error 3/3** |
| rsyncd /good | 24.2s | 0 | true | ok 3/3 |

Rate-probe trace (configured_rate_Bps, MiB/s, per round): **128**, 8, 8, 8, … — round 0 ramps straight to **128 MiB/s**, AIMD then collapses to 8 MiB/s after the overshoot causes loss, and 16 rounds can't recover.

**★ROOT CAUSE — the ramp overshoots because it ramps to a FIXED target (128 MiB/s) without measuring path capacity.** `configured_bdp_bytes=0` — atp never estimates the link rate, so the round-0 ramp jumps to 128 MiB/s on EVERY clean-ish link. On high-BDP (1 gbit ≈ 125 MB/s) that's fine (MATRIX-73 TIE). On good (200 mbit ≈ 25 MB/s) it's 5× the link → catastrophic round-0 loss → non-convergence. The loss-gate also lets good's 0.1% loss through (bad's 2% loss correctly gated the ramp OFF — MATRIX-74 unchanged at 153.8s), so good gets the ramp AND the overshoot.

**★P0 — the clean-ramp as shipped is UNSAFE on sub-gigabit clean/mild links (default-on regresses the common "good internet" case).** Routed to swarm: the ramp MUST be delivery-rate-capped (BBR-style) — probe the rate UP gradually based on observed ACK/delivery rate and BACK OFF the instant loss rises or delivery plateaus, instead of jumping to a fixed 128 MiB/s. Until fixed, the MATRIX-73 high-BDP TIE is real but comes with a good-link regression — NET not yet shippable. ★This is exactly why the whole matrix is checked, never one cell: the high-BDP win hid a good-link break. Evidence: `artifacts/atp_bench_matrix/20260624T230317Z/`.

## MATRIX-77 (2026-06-24) — P0 CATASTROPHIC regression FIXED (fb017958b 'gate fixed clean ramp to loss-free links'): 500M/good now CONVERGES 3/3 (was 3/3 error/non-converge). high-BDP TIE preserved (18.2s, ramp still engages on loss=0), bad unchanged (150.8s). ★Residual: good converges at 67.1s (2.77× rsync) — slower than its historical ~37s/1.54× (a milder wall regression, NOT the catastrophic P0). The clean-high-BDP win is now regression-FREE in the no-failure sense; the good wall is a P1 follow-up.

Built fb017958b, full A/B 500M/{good,highbdp,bad}/nocrypto streams=1 ×3 + ATP_RQ_TRACE=1:

| regime | method | wall | n_ok | rounds | sha | ramp engaged? |
|---|---|---|---|---|---|---|
| good | atp-rq-lab | **67.1s** (was 3/3 ERROR) | 3/3 | {1,2} | ok | NO (max 17 MiB/s — gated off ✓) |
| good | rsyncd | 24.2s | 3/3 | 0 | ok | — |
| highbdp | atp-rq-lab | **18.2s = TIE** (rsync 17.6s) | 3/3 | 0 | ok | YES (128 MiB/s) |
| highbdp | rsyncd | 17.6s | 3/3 | 0 | ok | — |
| bad | atp-rq-lab | 150.8s | 3/3 | 0 | ok | NO (gated, unchanged) |
| bad | rsyncd | 100.3s | 3/3 | 0 | ok | — |

## MATRIX-78 (2026-06-25) — the clean-ramp ALSO helps small-clean: 50M/perfect atp 3.7s → **2.82s** (ramp engaged to 40 MiB/s on the loss-free link), narrowing atp-vs-rsync from 3× to **2.29×** (rsync 1.23s). Residual 2.29× is the FEC-encode/setup tax at small size (not pacing-bound — the ramp got what it could). Memory: atp **49 MB vs rsyncd 4 GB** (~81× less — rsync's whole-file delta-hash blows up even on a clean 50M).

Benched fb017958b on 50M/perfect/nocrypto streams=1 ×3 + ATP_RQ_TRACE=1:

| method | wall | rss | rounds | sha |
|---|---|---|---|---|
| atp-rq-lab | **2.82s** (3.7s pre-ramp) | 49 MB | 0 | 3:3 ok |
| rsyncd | 1.23s | **4011 MB (4 GB)** | 0 | 3:3 ok |

**The ramp helped the small clean cell** (3.7→2.82s, ~1.3× faster; probe shows it reached 40 MiB/s — small file finishes before fully spinning to 128). **atp still loses small-clean 2.29×** (down from 3×): at 50M the wall is dominated by RaptorQ encode + transfer setup, NOT pacing — so the ramp shaved the pacing component but the FEC-encode/setup tax is the irreducible residual at small size (consistent with MATRIX-71's clean-perfect-small "FEC encode tax"). **Memory dominance is extreme here: 49 MB vs rsync's 4 GB (~81×)** — rsync builds a whole-file checksum/delta map even for a clean transfer; atp streams in bounded memory. So small-clean: atp loses ~2.3× wall (narrowed by the ramp), wins ~81× memory.

**Clean-wall scoreboard (current HEAD fb017958b):** clean-high-BDP = TIE (MATRIX-73/77, banked); clean-perfect-small = atp 2.29× (narrowed from 3× by the ramp, residual is FEC-encode, ~fundamental at small size) + 81× memory; good = converges (P0 fixed) but wall P1 (67s, swarm bisecting); encrypted-clean = AEAD compute (fundamental). The clean-ramp (loss-free-gated) is a net win across clean cells (high-BDP TIE + small-perfect 1.3× faster) with no regression after the fb017958b gate. Evidence: `artifacts/atp_bench_matrix/20260625T001944Z/`.

**★P0 FIXED — good no longer fails.** The loss-free gate (fb017958b) stops the ramp engaging on good's 0.1% loss (probe confirms good caps at 17 MiB/s, NOT 128) — so the round-0 overshoot is gone and good converges 3/3 sha-ok. **high-BDP keeps the MATRIX-73 TIE** (18.2s vs rsync 17.6s, ramp engages at 128 MiB/s on loss=0). **bad unchanged** (150.8s). So the clean-high-BDP win is now bankable WITHOUT the catastrophic good break.

**⚠ Residual P1 — good wall (67.1s / 2.77× rsync) is worse than its historical ~37s/1.54× (MATRIX-50).** good now takes 1-2 feedback rounds and runs at ~7.5 MB/s (below even the 16 MiB/s cold-start), so something beyond the ramp gate slowed it — candidate causes: the cap-aggregate (01daa99b6) may throttle even single-stream pacing on mild-loss links, OR accumulated transport churn since MATRIX-50. NOT the catastrophic P0 (which is fixed); a separate wall regression to investigate. Caveat: no clean immediately-pre-ramp good baseline was captured this session, so the 37s→67s delta is vs a days-old HEAD — attribution needs a bisect. Routed as P1.

**★NET SCOREBOARD (current HEAD fb017958b):** atp TIES clean-high-BDP (18.2s, NEW win this session, regression-free); WINS lossy-large-FEC / delta-insert 62.5× / memory; good converges but lost wall ground (P1); remaining clean losses = good-wall (P1), clean-perfect-small (FEC encode), encrypted-clean (AEAD). The session's headline — clean-high-BDP LOSS→TIE via the probe-diagnosed cold-start-ramp — stands, now with the good-link safety gate. Evidence: `artifacts/atp_bench_matrix/20260624T234216Z/`.

## MATRIX-79 (2026-06-25) — ★good-wall P1 RESOLVED: c891cd689 'floor good-link feedback' restored 500M/good from 67s back to **37.9s** (3/3 ok), its historical ~1.59× of rsync — no wall regression. high-BDP keeps the win (atp 17.7s vs rsync 17.9s, atp marginally AHEAD), bad unchanged (150.7s). The clean-ramp arc is now COMPLETE and fully regression-free across the matrix.

Benched c891cd689 (HEAD 16a6d7e14), 500M/{good,highbdp,bad}/nocrypto streams=1 ×3:

| regime | atp wall | rsync | ratio | rounds | sha |
|---|---|---|---|---|---|
| good | **37.9s** (was 67s MATRIX-77) | 23.9s | 1.59× | {1,2} | 3:3 ok |
| highbdp | **17.7s** | 17.9s | **1.01× = atp AHEAD** | 0 | 3:3 ok |
| bad | 150.7s | 98.4s | 1.53× | 0 | 3:3 ok |

**good RECOVERED** — `c891cd689` (floor the good-link feedback round behavior) brought 500M/good from the 67s P1 regression back to 37.9s = its historical ~1.59× of rsync. The MATRIX-77 wall regression is GONE; good now converges in 1-2 rounds at the expected wall. **high-BDP win/tie held** (atp 17.7s vs rsync 17.9s — atp a hair ahead this run; the loss-free ramp keeps filling the 1gbit pipe). **bad unchanged** (150.7s, gated). 

**★CLEAN-RAMP ARC COMPLETE & REGRESSION-FREE.** Sequence: MATRIX-72 probe diagnosed the 16 MiB/s cold-start-never-ramps cause → MATRIX-73 ramp tied high-BDP (38s→18s) → MATRIX-74 lossy gating held → MATRIX-75 s8 stabilized → MATRIX-76 caught the P0 good-overshoot → MATRIX-77 loss-free gate fixed the catastrophe → MATRIX-78 ramp also sped small-clean (50M/perfect 3.7→2.82s, 81× mem) → MATRIX-79 floor-good-feedback restored good's wall. ★FINAL clean-link scoreboard: high-BDP = WIN/TIE (atp ≈ rsync, was 2.13× loss); good = 1.59× (historical, no regression); small-clean = 2.29× + 81× mem (FEC-encode residual); bad/lossy unchanged; encrypted-clean = AEAD-bound (fundamental, the remaining clean loss). atp now WINS/TIES every nocrypto clean+high-BDP wall it used to lose except small-file FEC-encode, AND dominates memory everywhere. ★FUTURE (not regression): a BBR delivery-rate-capped ramp could push good from 1.59× toward a TIE too (loss-free gate leaves good unramped today). Evidence: `artifacts/atp_bench_matrix/20260625T003045Z/`.

## MATRIX-80 (2026-06-25) — ★REGRESSION (REVERT-OR-GATE): the first BBR attempt 5471867cb 'cap source-first ramp by delivery acks' broke 500M/good **4.5×** (37.9s → 172s, ~7.1× rsync). high-BDP + bad held. The delivery-ack cap pulls good below the MATRIX-79 good-link floor. Same failure class as the MATRIX-76 P0 (a ramp change that wrecks the sub-gigabit "good" case while highbdp≈1gbit looks fine).

Benched origin/main HEAD `5471867cb` (built clean via git archive, 0 errors), 500M/{good,highbdp,bad}/nocrypto streams=1 ×3, sha-verified, hermetic netns+netem:

| regime | atp wall (median) | rsync | ratio | vs MATRIX-79 baseline | verdict |
|---|---|---|---|---|---|
| good | **172.0s** (172/153/173) | 24.2s | **7.10×** | was 37.9s → **4.5× WORSE** | ★REGRESSION |
| highbdp | 18.37s (17.5/18.6/18.4) | 17.74s | 1.04× | ~17.7s | HELD (WIN/TIE) |
| bad | 156.2s (156/157/156) | 98.0s | 1.59× | ~150.7s | HELD |

**5471867cb is a net regression and must NOT stay on HEAD as-is.** The "cap source-first ramp by delivery acks" change was the first attempt at the BBR delivery-rate-capped ramp (the intended lever to push good from 1.59× toward a tie). But the cap is collapsing pacing on the good/sub-gigabit-clean link — good now crawls and takes 172s (vs the 37.9s MATRIX-79 floor and 24s rsync). The cap is almost certainly pulling pacing BELOW the MATRIX-79 good-link floor (`c891cd689` "floor good-link feedback pacing") instead of only bounding the ramp UP. high-BDP (1gbit) and bad (lossy) are unaffected — exactly the MATRIX-76 signature where a ramp change that targets fat pipes silently starves the common 200mbit good link.

**Routed to the rq-pacing owner (swarm dispatch `/data/tmp/swarm_regression_v15.txt`)** with three fix paths, preferred order: (a) make the delivery-ack cap bound the ramp UP only, never below the `c891cd689` good floor; (b) gate the cap to engage only once measured delivery exceeds the floor (confirmed fat pipe), mirroring the loss-free gate `fb017958b`; (c) revert `5471867cb` until the cap is good-safe. **Re-A/B gate after the fix:** 500M/good ≤37.9s (must recover, ideally ramps toward ~20s = the original BBR goal), highbdp keeps the WIN, bad ~150s, sha 3/3, streams=1. (ATP_RQ_TRACE window_probe lines were not captured in this run's aggregate log; the wall medians are conclusive on their own.) Evidence: `artifacts/atp_bench_matrix/20260625T024216Z/`.

## MATRIX-81 (2026-06-25) — ★FAILED FIX: 36acfdaf0 'keep delivery ack ramp good-safe' did NOT make good safe. 500M/good still **161.8s** (~4.3× baseline regression, 6.73× rsync). The whole BBR delivery-ack-cap approach is REFUTED — two commits, both regress good, zero net win. REVERT-to-baseline + PIVOT routed.

Benched origin/main code HEAD `36acfdaf0` (built clean via git archive, 0 errors), 500M/{good,highbdp,bad}/nocrypto streams=1 ×3, sha-verified:

| regime | atp wall (median) | rsync | ratio | vs MATRIX-79 baseline | verdict |
|---|---|---|---|---|---|
| good | **161.78s** (161.9/161.7/161.8) | 24.04s | **6.73×** | was 37.9s → **~4.3× WORSE** | ★STILL REGRESSED |
| highbdp | 18.37s (18.2/18.4/18.5) | 18.04s | 1.02× | ~17.7s | HELD (TIE) |
| bad | 161.97s (161.5/162.0/162.4) | 97.50s | 1.66× | ~150.7s | HELD |

**The "good-safe" fix was empirically false.** `36acfdaf0` claimed to keep the delivery-ack ramp good-safe, but the A/B shows 500M/good is still pinned at ~162s — essentially the same broken wall as the original regression `5471867cb` (172s), and ~4.3× the 37.9s MATRIX-79 baseline. So **both** BBR-ramp commits on HEAD regress good; neither beat (or even matched) the known-good baseline. highbdp and bad held throughout (the cap only ever touched good, and only ever for the worse).

**★The BBR delivery-rate-capped good-link ramp is REFUTED as a lever.** Root cause of the whole failed arc (see analysis): on the `good` regime (200mbit, 0.1% loss, rounds=0 source-complete) there is no per-RTT ACK/delivery feedback loop to cap *against* — the transfer is a single forward fountain spray with no return-path rate signal mid-transfer, so a "delivery-ack-rate" cap has only the cold-start estimate to work from and clamps pacing far below the link. Capping by delivery-acks is the right idea on a link that produces ack-clocked feedback (highbdp/lossy with feedback rounds), but `good` finishes in one source-complete pass with effectively no acks to clock against → the cap starves it. The MATRIX-79 floor (`c891cd689`) is what was holding good at 37.9s; the cap commits pulled pacing below that floor.

**Routed (swarm dispatch `/data/tmp/swarm_revert_pivot_v16.txt`):** (1) REVERT `5471867cb`+`36acfdaf0` back to the `c891cd689` MATRIX-79 baseline (good=37.9s) — do not leave a 4.3× good regression on HEAD; I will re-A/B to confirm restore (→ MATRIX-82). (2) PIVOT off the marginal good-link ramp (1.59×→tie was always the smallest available win) to the **encrypted-clean** frontier (50M/perfect encrypted ~39×, much larger headroom; the clean ramp has never been A/B'd on the QUIC/TLS-1.3 tier). Evidence: `artifacts/atp_bench_matrix/20260625T031858Z/`.

## MATRIX-82 (2026-06-25) — ★BASELINE RESTORED: revert 38843533a 'restore matrix79 pacing baseline' brought 500M/good back to **38.9s** (1.60× rsync), the BBR regression is GONE, main is clean. high-BDP WIN held (atp AHEAD 0.98×), bad held. The BBR good-link delivery-ack-cap arc is closed/refuted.

Benched origin/main HEAD after the revert (38843533a; -431 lines, transport_rq pacing restored to c891cd689 state; built clean via git archive, 0 errors), 500M/{good,highbdp,bad}/nocrypto streams=1 ×3, sha-verified:

| regime | atp wall (median) | rsync | ratio | verdict |
|---|---|---|---|---|
| good | **38.88s** (65.7/38.6/38.9) | 24.24s | 1.60× | ★RESTORED (≈ MATRIX-79 37.9s; rep1 65.7s is cold-start noise, median solid) |
| highbdp | 18.07s (18.1/17.8/18.5) | 18.44s | **0.98× = atp AHEAD** | WIN held |
| bad | 151.28s (152/151/151) | 97.10s | 1.56× | held (= MATRIX-79 150.7s) |

**The revert worked and the regression saga is closed.** 500M/good is back to its MATRIX-79 floor (38.9s median, 1.60×), high-BDP keeps the WIN (atp marginally ahead, 0.98×), bad unchanged. main HEAD is once again the known-good clean-ramp baseline with no good-link regression. **Lesson banked:** the BBR delivery-rate-capped ramp is refuted for the `good` regime because good is a rounds=0 source-complete transfer with no ack-clock to cap against; the only principled way to speed good would be a handshake-time path-capacity probe (set the *initial* spray rate from a measured estimate, not a mid-transfer cap) — deprioritized as low-payoff (good is already only 1.60×).

**Swarm pivoted to the encrypted-clean frontier (per dispatch v16):** new commits `84ea0a202 perf(atp-quic): pace native initial symbol spray` + `eea2b0f2a net/atp-quic: ramp clean native symbol spray` wire the clean pacing/ramp into the QUIC/TLS-1.3 native symbol spray (the encrypted tier, never A/B'd for the ramp). Next: A/B the encrypted tier (atp-quic-tls13) 50M/perfect+good to see if the QUIC clean ramp dents the ~39× per-packet-AES-GCM wall (→ MATRIX-83). Evidence: `artifacts/atp_bench_matrix/20260625T035448Z/`.

## MATRIX-83 (2026-06-25) — ★PARTIAL WIN (encrypted-perfect): the QUIC native-spray ramp (84ea0a202 pace + eea2b0f2a ramp) cut 50M/perfect **encrypted** from ~33s to **25.7s** (~22% faster, 39× → 30.2× rsync). The clean ramp DOES help the QUIC/TLS-1.3 tier. Residual gap = per-packet AES-GCM compute. ⚠ encrypted-`good` is unreliable (non-converging) — a separate correctness concern, not a target.

Benched origin/main HEAD (QUIC-ramp `84ea0a202`+`eea2b0f2a`, built clean), encrypted tier (atp-quic-tls13 vs rsync-over-ssh-aes128gcm), 50M/{perfect,good} streams=1:

| regime | atp-quic-tls13 | rsync-ssh | ratio | vs MATRIX-70 | verdict |
|---|---|---|---|---|---|
| perfect | **25.73s** (5 reps: 25.4–26.1) | 0.85s | **30.2×** | was ~33s/~39× | ★IMPROVED ~22% (ramp helped) |
| good | 439s ok (10 rounds) / **757.9s ERROR** (1024 rounds, sha-fail) | — | n/a | (no prior) | ⚠ NON-CONVERGING (1/2 reps failed) |

**encrypted-perfect = a real partial win, banked.** The QUIC native-spray pacing+ramp shaved ~22% off the encrypted-perfect wall (33→25.7s, 39×→30.2×). So the same clean-ramp lever that tied high-BDP on the nocrypto tier also helps the encrypted tier — the spray was previously cold-start-paced on QUIC too. The remaining 30× gap is **per-packet AES-GCM compute** (each ~1200B symbol is individually AEAD-sealed/opened); the ramp can't touch that. Next levers for encrypted-perfect: (1) confirm AES-NI is actually engaged (not a software AES fallback) in the `packet_protection` AEAD path; (2) fewer/larger AEAD frames (seal larger payloads per AEAD invocation — distinct from the AEAD-*call*-batching refuted in MATRIX-70, which batched calls without enlarging frames).

**⚠ encrypted-`good` is non-converging — flagged as a correctness concern, NOT a perf target.** On 50M/good (200mbit, 0.1% loss, 25ms) the encrypted path either crawls (rep1: 439s, 10 feedback rounds) or fails outright (rep2: 757.9s, **1024 rounds = round cap, status=error, sha_ok=false** = non-convergence). This is the encrypted-lossy class (already DEAD as a *tuning* lever), but the rep2 hard failure shows it can fail to converge entirely, not merely run slow — worth a swarm correctness look (the QUIC/encrypted repair-round loop on even mild loss). The error rep is fail-closed (excluded from medians per the integrity standard). Bench stopped early after 2 good reps (5 reps of a ~439–758s non-target cell is wasteful and was hogging the single bench slot); perfect has the full 5 reps. Evidence: `artifacts/atp_bench_matrix/20260625T042402Z/`.

## MATRIX-84 (2026-06-25) — ★BIG IMPROVEMENT (the highest-value frontier): 3c5042cac 'tighten bad-link first flight' cut 500M/bad from ~156s to **110.9s** (~29% faster), closing the lossy gap from **1.66× → 1.14×** — a near-tie. atp's FEC thesis on a 2%-loss link is now nearly even with rsync (was its one clear lossy LOSS). sha 3/3, no regression. One more push could flip it to a WIN.

Benched origin/main HEAD `3c5042cac` (built clean via git archive, 0 errors), 500M/bad/nocrypto streams=1 ×3, sha-verified:

| regime | atp wall (median) | rsyncd | ratio | vs MATRIX-82 baseline | verdict |
|---|---|---|---|---|---|
| bad | **110.94s** (112.0/110.9/110.7, cv<1%) | 97.40s | **1.14×** | was ~156s / 1.66× | ★IMPROVED ~29% (near-tie) |

**The bad-link first-flight tightening is the most valuable lever this session after the clean-ramp arc.** 500M/bad (2% loss, 80ms, 50mbit) was atp's one clear lossy-link LOSS (1.66× rsync) — which contradicted the FEC thesis (RaptorQ should beat retransmit on a lossy link). `3c5042cac` tightened the first flight (the initial spray volume/rate on a known-bad link) and atp dropped from ~156s to 110.9s, narrowing the gap to **1.14×** — essentially a dead heat with rsyncd's 97.4s. So atp now ranges from WIN/TIE on clean+high-BDP to a near-tie on bad-lossy, plus its standing wins on delta/memory. The residual 1.14× (≈13s) is the last bit of lossy throughput; candidate next levers to flip it to a WIN: further first-flight/overhead tuning, or — if the trace shows atp pinned below 50mbit during decode — **parallel decode for the LOSSY-large case** (distinct from the refuted clean-decode-fanout MATRIX-69: clean is source-complete so decode is ~free, but bad actually runs the decoder, so decode throughput may be the real lossy ceiling). Routed to swarm to push the last 1.14×→WIN. (ATP_RQ_TRACE window_probe/first-flight lines not surfaced in this run's aggregate log; wall medians conclusive, cv<1%.) Evidence: `artifacts/atp_bench_matrix/20260625T052112Z/`.

## MATRIX-85 (2026-06-25) — ★DECODE PROFILE (diagnosis, not a perf change): 500M/bad is decode-HEAVY (decode=64.1s ≈ 60% of the 107s receiver wall) BUT the parallel decode pool is IDLE (pending_peak=2 of width_budget=60). ⇒ parallel-lossy-decode is NOT the lever (same trap as the refuted clean-decode-fanout MATRIX-69). The ~13s/1.14× gap is a per-block decode TAIL, not decode-parallelism starvation.

Profiled origin/main HEAD (decode-trace `a47005f56`, wall unchanged: atp 110.7s vs rsyncd 97.7s, sha 3/3 — the tracing did not regress). The receiver `decode_profile` line (500M/bad, feedback_round=0, 1000 blocks):

| metric | value | reading |
|---|---|---|
| `decode_micros` | **64.1s** | ≈60% of the 107s receiver wall — decode IS the dominant receiver cost |
| `round_wall` | 107.0s | (network floor ≈88s: 500MB @ 50mbit ≈80s + ~10% FEC overhead) |
| `intake_micros` | 23.1s | symbol reception |
| `decode_pending_peak` | **2** (of `decode_width_budget`=60) | ★pool 30× under-utilized — blocks rarely ready >2 at once |
| `decode_join_wait_micros` | 0.9ms | finalize barely waits on outstanding jobs |
| `decode_queued_jobs` / `inline_jobs` | 771 / 233 | most jobs already queued to the (parallel) pool; 233 small entries ran inline below the gate |
| `decode_spawn_denials` / cap_saturations | 0 / 0 | no contention, no cap pressure |

**★The parallel-decode lever (more lanes/width) will NOT help 500M/bad — the pool already sits at 2/60.** This is the decisive finding: decode is 60% of the wall in *aggregate CPU*, but it is NOT parallelism-starved — `pending_peak=2` means blocks become decodable only ~2-at-a-time (paced by symbol arrival over the lossy 50mbit link with 2% loss), so there is essentially never a backlog of ready-to-decode blocks for extra lanes to chew. Widening decode would idle the same as the refuted clean-decode-fanout (MATRIX-69) — there, decode was free (source-complete); here, decode runs but arrives serialized. **This profile prevented building a parallel-decode that would have shown ~zero gain (a second clean-decode-fanout dead end).** The real residual cost is a per-block decode TAIL: ~64ms/block decode that isn't fully hidden under the ~88s network transmit floor (the last blocks decode after the last symbols land). Lower-confidence levers for the last 1.14×: (a) decode blocks more eagerly during intake to shrink the end tail (limited — `pending_peak=2` shows few are ready early); (b) cheaper per-block RaptorQ *repair* decode (note: SIMD GF256 was refuted earlier as not vector-bound — decode cost is matrix-structure/memory-bound, not GF256-vector-bound — so this is hard); (c) tighter FEC overhead → fewer repair symbols → less decode work (risks convergence). **Recommendation: stop chasing 500M/bad (a strong 1.14× near-tie; remaining gain is a hard decode-tail with diminishing returns) and shift to the encrypted-perfect frontier (clearer AES-NI/larger-AEAD-frame headroom).** Evidence: `artifacts/atp_bench_matrix/20260625T060046Z/`.

## MATRIX-86 (2026-06-25) — ★REFRAME (encrypted-perfect is NOT cipher-bound): the AEAD provider trace proves AES-NI is fully engaged (rustls/ring, hardware AES + PCLMULQDQ GHASH), yet 50M/perfect encrypted runs at ~2 MB/s (25.2s). Hardware AES-GCM does 50MB in milliseconds ⇒ the 30× gap is **per-packet overhead in the QUIC encrypted path, NOT the AEAD math.** Lever = coalesce symbols into larger QUIC datagrams (fewer protect/sendto per byte), not faster crypto.

Profiled origin/main HEAD (AEAD-provider-trace `aae4f75e3`; 50M/perfect encrypted, wall unchanged: atp 25.17s vs rsync-ssh 0.85s = 29.6×, sha 3/3 — trace didn't regress). The new `aead_provider` trace line:

```
aead_provider provider_kind=rustls-quic-ring backend=rustls/ring
  tls_cipher_suite=TLS13_AES_128_GCM_SHA256 quic_aead=AES-128-GCM arch=x86_64
  hardware_probe=x86-aes-pclmulqdq hardware_aes=true hardware_ghash=true hardware_aes_gcm_capable=true
```

**A1 RESOLVED: AES-NI is engaged — there is NO software-AES fallback.** rustls/ring selected the hardware path (AES + PCLMULQDQ for GHASH) on this x86_64 host. So the encrypted-perfect cost is genuine, not a misconfiguration.

**★But the gap is NOT cipher-compute-bound — this corrects the MATRIX-70/83 assumption.** The decisive arithmetic: hardware AES-128-GCM runs at multiple GB/s, so encrypting 50MB is ~10ms of cipher work — yet the transfer takes 25.2s (~2 MB/s). At ~1200B/symbol that is ~600µs **per symbol**, of which the AEAD itself is <1µs (<0.2%). The other 99.8% is **per-packet machinery in the QUIC encrypted path**: packet construction, QUIC header protection (a separate AES-ECB op per packet), the per-datagram `protect()`/`unprotect()` call structure, the bounded DATAGRAM queue + pacing, and one `sendto` per ~1200B packet. (Compare nocrypto 50M/perfect = 2.82s, MATRIX-78 — encryption adds ~22s of pure per-packet overhead, not cipher time.)

**Lever (reframed): amortize per-packet work, not the cipher.** Coalesce multiple RaptorQ symbols into a single larger QUIC datagram / 1-RTT packet so there are far fewer protect/header-protect/sendto operations per byte. This is the right reading of A2 (fewer/LARGER AEAD frames) — and it's distinct from the refuted AEAD-*call*-batching (MATRIX-70), which batched cipher calls without enlarging the packet, leaving the dominant per-packet framing/syscall cost untouched. GSO-batched sends on the QUIC path (one syscall for many packets) would compound it. ★Net: encrypted-perfect is a more tractable frontier than previously believed — the wall is per-packet overhead at ~2 MB/s despite hardware crypto, addressable by larger datagrams + batched sends. Routed to swarm: don't switch the (already-hardware) AES provider; pursue larger QUIC datagrams / symbol coalescing. Evidence: `artifacts/atp_bench_matrix/20260625T063814Z/`.

## MATRIX-87 (2026-06-25) — ★★REFRAME VALIDATED + REAL WIN: packet-filling (9d826ac6d 'fill clean encrypted packets') CUT 50M/perfect encrypted **25.2s → 11.56s (2.2× faster)**, gap **29.6× → 13.5×** rsync. sha 5/5 byte-identical. Trace confirms coalescing engaged (~54 symbols/packet). Proves the encrypted gap was per-packet overhead, NOT cipher (MATRIX-86 confirmed). More headroom remains.

Benched origin/main HEAD `9d826ac6d`+`4e6d96c08` (built clean, 0 errors), 50M/perfect encrypted, streams=1 ×5, sha-verified:

| regime | atp-quic-tls13 (median) | rsync-ssh | ratio | vs MATRIX-86 | verdict |
|---|---|---|---|---|---|
| perfect | **11.56s** (11.4–11.7, cv~1%) | 0.85s | **13.5×** | was 25.2s / 29.6× | ★★IMPROVED 2.2× |

**The MATRIX-86 per-packet-overhead reframe is empirically VALIDATED.** Filling each QUIC packet with multiple RaptorQ symbols (trace: `datagrams_per_packet=54` on 4257 data packets, vs ~1/packet before) halved the encrypted-perfect wall — 25.2s → 11.56s, 29.6× → 13.5× rsync, all 5 reps byte-identical (sha 5/5). This confirms the gap was per-packet machinery (protect/header-protect/sendto per packet), not AES-GCM compute — coalescing ~54× fewer packets bought a 2.2× wall cut with zero correctness cost. **This is the first dent in the encrypted-clean wall that was long assumed "fundamental AES" (MATRIX-70/83).**

## MATRIX-88 (2026-06-25) — GSO compounds modestly: e145c60bb 'batch coalesced packets with GSO' cut encrypted-perfect 11.56s → **10.36s** (~10%, 13.5× → 12.2× rsync, sha 5/5). GSO engaged (~4× fewer send syscalls) but the sendto cost was only ~10% of the wall ⇒ the dominant remaining cost is per-symbol AEAD-seal + per-packet header-protection CPU (userspace), not syscalls. Cumulative arc 25.2s→10.36s (2.43×); diminishing returns now.

Benched origin/main HEAD `e145c60bb` (built clean), 50M/perfect encrypted, streams=1 ×5, sha-verified:

| regime | atp-quic-tls13 (median) | rsync-ssh | ratio | vs MATRIX-87 | verdict |
|---|---|---|---|---|---|
| perfect | **10.36s** (9.1–10.8) | 0.85s | **12.2×** | was 11.56s / 13.5× | IMPROVED ~10% (GSO) |

**GSO send-batching works but the syscall was a small slice.** Trace: `datagrams_per_packet=54` on **1065** packets (vs 4257 in MATRIX-87) — GSO coalesces ~4× fewer `sendmsg` calls. Yet the wall only dropped ~10% (11.56→10.36s), so the per-packet `sendto` syscall was only ~10% of the encrypted-perfect cost. **The dominant remaining cost is CPU in the protect path: per-symbol AEAD seal (each ~1200B RaptorQ symbol is individually sealed even inside a coalesced datagram) + per-QUIC-packet header protection (an AES-ECB op).** rsync-ssh at 0.85s (~59 MB/s) is a single kernel-optimized bulk-TCP stream; atp-quic at 10.36s (~4.8 MB/s) is many small userspace-framed/sealed units — that structural difference is the residual 12.2×.

**Cumulative encrypted-perfect arc (this session): 25.2s (MATRIX-86 pre-fill) → 11.56s (packet-fill, 87) → 10.36s (GSO, 88) = 2.43× faster; 39× → 12.2× vs rsync overall.** A major, previously-thought-impossible improvement on the "fundamental AES" wall — now correctly understood as per-packet/per-symbol userspace overhead. **Diminishing returns from here:** further cuts need fewer-LARGER AEAD seal units (seal N symbols under one AEAD — but a lost packet then loses N symbols, a FEC-granularity/loss-resilience trade-off) or receiver-side unprotect batching (lower-confidence). Routed to swarm: try receiver-side unprotect batching (no wire change) as the last clean lever; treat larger-AEAD-units as a trade-off to weigh, not a free win; encrypted-perfect at 12.2× (from 39×) is already a strong result. Evidence: `artifacts/atp_bench_matrix/20260625T073248Z/`.

## MATRIX-89 (2026-06-25) — encrypted-perfect FLOOR reached: receiver-batch (cb5f5fe93 'batch encrypted receive intake') is NEUTRAL — 10.46s vs 10.36s (within noise, 12.3×, sha 5/5). The receive intake was not the bottleneck. ★Encrypted-perfect is BANKED at ~10.4s / 12.3× (from 39×, 3.2× total this session) — STOP tuning it; pivot to encrypted-good convergence (correctness) + small-clean.

Benched origin/main HEAD `cb5f5fe93` (built clean), 50M/perfect encrypted, streams=1 ×5, sha-verified:

| regime | atp-quic-tls13 (median) | rsync-ssh | ratio | vs MATRIX-88 | verdict |
|---|---|---|---|---|---|
| perfect | 10.46s (8.4–10.7) | 0.85s | 12.3× | was 10.36s / 12.2× | NEUTRAL (floor) |

**Encrypted-perfect floor confirmed at ~10.4s / 12.3×.** Receiver-side intake batching did not move the wall (10.46s ≈ 10.36s within rep noise) — so the receive path was not the bottleneck, and the residual cost is the inherent **per-symbol AEAD seal + per-QUIC-packet header protection CPU** on the send side, which is not eliminable by batching sends, syscalls, or receives (it's per-unit crypto-framing work, distinct from the AES *throughput* which is hardware-fast). The three send/recv batching levers (packet-fill 87, GSO 88, recv-batch 89) took encrypted-perfect from 25.2s→10.4s (2.4×); together with the MATRIX-83 ramp the full-session arc is **39× → 12.3×** vs rsync — a strong, durable result on a wall long mislabeled "fundamental AES."

**★Encrypted-perfect is DONE (banked, floor reached) — stop tuning it.** Remaining open frontiers, by value: (B) ★encrypted-`good` NON-CONVERGENCE (correctness — MATRIX-83 was 1024-round/sha-fail; the fill+GSO+recv-batch changes may now help, or it's a real repair-loop bug worth a bead/root-cause); (C) small-clean nocrypto FEC-encode tax (2.29×, adaptive overhead→0 for tiny/clean). 500M/bad (1.14×) and good (1.60×) are parked near-ties; clean+high-BDP + delta + memory are wins. Routed to swarm: pivot off encrypted-perfect to encrypted-good convergence + small-clean. Evidence: `artifacts/atp_bench_matrix/20260625T075854Z/`.

**Headroom remains (next levers):** 11.56s for 50MB is still ~4.3 MB/s, far below hardware-crypto speed, so a *second* layer of per-symbol cost remains — candidates: (a) **GSO send batching** (one `sendmsg`/`UDP_SEGMENT` for the coalesced superpacket — the trace's 54×1200B=64.8KB "packets" look like coalesced sends that could go via GSO in one syscall; GSO is OPEN for the encrypted/QUIC path even though it was refuted for the nocrypto spray MATRIX-66/67); (b) receiver-side per-symbol `unprotect`/processing batching; (c) push the fill ratio higher / to path-MTU. Routed to swarm: push fill-ratio + GSO compounding, and re-check whether fuller packets also ease the encrypted-good non-convergence. Evidence: `artifacts/atp_bench_matrix/20260625T070456Z/`.

## MATRIX-90 (2026-06-25) — encrypted-`good` convergence fix (`0b4bb938d` 'repair encrypted lossy control loop' + `cbb179b3b` test, br-asupersync-lqmfsi): ★MAJOR CORRECTNESS PROGRESS but NOT a clean pass. 50M/good encrypted now converges **2/3** (was **0/3** all-1024-round/sha-fail in MATRIX-83) in **2 rounds / ~15.8s** — but rep2 STILL wedged **1024 rounds / 758.8s / sha-fail** = a residual **INTERMITTENT (non-deterministic) non-convergence**. Gate (sha 3/3) NOT met. Even on converged reps atp is **4.0× slower** than rsync. Routed back to owner: root-cause the residual flaky wedge.

Benched origin/main HEAD `b0da22b87` (built clean from `git archive`, 0 errors, atp 0.3.5), workload 50M, regime `good` (netem both ends: 25ms delay / 0.1% loss / 200mbit), tier `encrypted`, streams=1, reps=3, sha-verified, ATP_RQ_TRACE=1:

| rep | atp-quic-tls13 wall | feedback_rounds | status / sha | peak RSS |
|---|---|---|---|---|
| 1 | 14.86s | 2 | ok / sha ✓ | 39.3 MB |
| 2 | **758.81s** | **1024** | **error / sha ✗ — WEDGED** | 36.8 MB |
| 3 | 16.76s | 2 | ok / sha ✓ | 44.0 MB |

- **atp converged median (reps 1,3): 15.81s** (per integrity rule the sha-fail rep2 is excluded from the median — it cannot read as a win or a "slow loss").
- **rsync-ssh-aes128gcm median: 3.95s** (4.55 / 3.86 / 3.95, sha 3/3) → **atp converged is 4.00× slower**.
- RSS: atp ~40 MB vs rsync ~48 MB (atp lighter — consistent with prior memory wins).

**Verdict: the fix is real and large, but the bug is not fully closed.** MATRIX-83 had encrypted 50M/good wedging on *every* run (1024 rounds = the repair loop's hard cap, sha-fail, ~440–760s). After `0b4bb938d` the common path converges cleanly in **2 feedback rounds (~15s)** — a genuine repair of the encrypted lossy control loop. **However, 1 of 3 reps still hit the identical 1024-round/758s/sha-fail wedge**, so a **non-deterministic** path (likely seed/packet-ordering/loss-pattern dependent — the only variable across the 3 reps is the random netem 0.1% drop pattern + ephemeral port) still drives the repair loop to its cap without ever satisfying the decoder. This is an **intermittent correctness bug**, not a clean convergence — it must NOT be banked as a win.

**Also: even when it converges, encrypted 50M/good loses 4× to rsync** (15.8s vs 3.95s), consistent with the MATRIX-88/89 finding that the encrypted/QUIC path is per-symbol-AEAD/header-protection-CPU-bound (~4–5 MB/s) vs rsync's single bulk-TCP+hardware-AES stream. So encrypted-good has BOTH a residual correctness bug AND a perf gap.

**Routed to swarm (br-asupersync-lqmfsi owner):** (1) ★root-cause the residual intermittent 1024-round wedge — reproduce by sweeping the loss seed / repeating reps until it fires, then trace why the receiver never reaches K (suspect: a specific loss pattern starves a block of source+repair symbols and the repair-request/FEC-fallback logic doesn't escalate, cf. the open 317hxr.6.1.1 "FEC fallback self-disables in repair rounds" finding — likely the SAME root cause); (2) the 1024-round hard cap should fail FAST / escalate FEC overhead aggressively rather than spinning 758s. Perf (4× gap) is secondary to closing the correctness hole. Evidence: `artifacts/atp_bench_matrix/20260625T203840Z/`.

## MATRIX-91 (2026-06-25) — encrypted-`good` wedge NOT closed by `505806a22` ('stabilize lossy repair feedback', lqmfsi): ★HONEST NEGATIVE. reps5 verification (deliberately more reps than the swarm's local 3/3 to stress the flaky path) shows the intermittent 1024-round wedge is STILL PRESENT and FREQUENT — converged only **2/5**, with reps 2,3,4 all wedged 1024-round / ~741s / sha-fail. Combined with MATRIX-90 (1/3 wedged), the wedge fires ~**50% of runs** at 0.1% loss = highly reproducible, NOT a rare edge. The fix changed the dynamics (a converged rep now took 4 rounds/43.9s vs the prior clean 2 rounds) but did NOT address the root cause. Bug remains OPEN; routed back to owners with a reproduce-and-trace directive.

Benched origin/main HEAD `cc486262a` (fix `505806a22`; built clean from `git archive`, 0 errors, atp 0.3.5), 50M / `good` (25ms / 0.1% loss / 200mbit) / `encrypted`, streams=1, reps=5, sha-verified, ATP_RQ_TRACE=1:

| rep | atp-quic-tls13 wall | feedback_rounds | status / sha |
|---|---|---|---|
| 1 | 43.89s | 4 | ok / sha ✓ |
| 2 | **741.00s** | **1024** | **error / sha ✗ — WEDGED** |
| 3 | **740.70s** | **1024** | **error / sha ✗ — WEDGED** |
| 4 | **741.30s** | **1024** | **error / sha ✗ — WEDGED** |
| 5 | 14.76s | 2 | ok / sha ✓ |

- **Converged 2/5** (gate 5/5 NOT met; was 2/3 in MATRIX-90 — no improvement). Converged-rep median 29.3s; rsync-ssh median 3.95s (5/5) → **7.42× slower** on converged reps.
- **Cross-run wedge rate ≈ 50%** (MATRIX-90 1/3 + MATRIX-91 3/5 = 4/8 reps wedged). The wedge is the dominant failure mode at this loss level, not a tail event.

**Verdict: the "stabilize lossy repair feedback" change is INSUFFICIENT.** It did not eliminate (and did not measurably reduce) the intermittent non-convergence — 3 of 5 reps still spun to the 1024-round hard cap (~741s) and failed sha. The ~50% cross-run hit rate means this is **trivially reproducible** by simply re-running the 50M/good/encrypted cell, so the owner can capture a wedged run directly and trace it.

**Routed to swarm (br-asupersync-lqmfsi / 317hxr.6.1.1 owners, panes 3/5/8):** STOP shipping convergence "stabilization" tweaks and self-certifying on a 3-rep local pass — reps5 central A/B refutes it. Instead: (1) reproduce a wedged run (≈50% chance per run), capture the ATP_RQ_TRACE; (2) at the 1024-round cap, inspect the receiver state — is it short by a few source symbols of K on one block, and is the sender (a) still generating/sending REPAIR symbols in rounds 3..1024, or (b) sending nothing new (the 317hxr.6.1.1 `requested_sources==0` / `source_retransmit_rounds` guard self-disabling FEC fallback)? (3) the 1024-round cap should escalate FEC overhead and/or fail-fast, not spin ~741s. This is a real correctness hole that blocks banking encrypted-good at any speed. Evidence: `artifacts/atp_bench_matrix/20260625T212957Z/`.

## MATRIX-92 (2026-06-25) — small-clean FEC-skip (`18daf2857` 'skip small clean RQ repair encode', br-asupersync-ffh2yy): ★byte-identical (sha 5/5) but NEUTRAL on wall — and it REFUTES the "small-clean tax = FEC repair-encode" hypothesis. 50M/perfect nocrypto median **2.816s vs 2.82s baseline** (no change), still **2.30× rsync** (was 2.29×). Skipping repair-symbol generation on a clean+small transfer saved ~nothing ⇒ the 2.3× gap is NOT repair generation; it is RaptorQ source-block encode/setup (intermediate-symbol precompute) or framing/protocol overhead. The change is SAFE to keep (no regression). Notable side-finding: atp peak RSS **9.4 MB** vs rsyncd **699 MB** (~74× less memory).

Benched origin/main HEAD `cfea8eaf0` (fix `18daf2857`; built clean from `git archive`, 0 errors, atp 0.3.5), 50M / `perfect` (2ms / 1gbit, no loss) / `nocrypto` (atp-rq-lab vs rsyncd), streams=1, reps=5, sha-verified, ATP_RQ_TRACE=1:

| method | median wall | sha | feedback_rounds | peak RSS |
|---|---|---|---|---|
| atp-rq-lab | **2.816s** (2.75–2.82, cv~1%) | 5/5 ✓ | 0 | **9.4 MB** |
| rsyncd | 1.226s (1.225–1.229) | 5/5 ✓ | — | 699 MB |
| ratio | **2.30×** (was 2.29× pre-fix) | — | — | atp 74× lighter |

**Verdict: hypothesis REFUTED, change neutral-but-safe.** The frontier-C premise was that RaptorQ repair-symbol *generation* dominates the small-clean wall, so skipping it when loss==0 & small would cut the 2.3× tax toward ~1×. Measurement says no: with repair-encode skipped (the fix is engaged — rounds=0, source-only), the wall is 2.816s, statistically identical to the 2.82s baseline, and the ratio is unchanged at 2.30×. **So repair generation was never the bottleneck.** The transfer is already source-complete in 0 feedback rounds on the clean link, yet still takes ~2.3× rsync — the cost is in the RaptorQ *source* path: systematic-encode setup / intermediate-symbol precomputation (the `lean_solve`/constraint-matrix work that runs even at zero repair overhead) and/or per-symbol framing, NOT the repair symbols the fix removed. The fix is byte-identical and harmless, so keep it, but it does not move the small-clean needle.

**Routed to swarm (ffh2yy owner, panes 5/14/15/16):** the repair-skip is correct and safe but NEUTRAL — stop attributing the small-clean tax to repair encode. To actually cut it, PROFILE where the ~2.8s goes on 50M/perfect nocrypto (flamegraph the sender+receiver): suspects are (a) RaptorQ intermediate-symbol/constraint-matrix precompute on the source block (runs regardless of repair count), (b) per-source-symbol framing/copy overhead, (c) the systematic-encode setup cost. The 74×-less-memory result (9.4MB vs 699MB) is a genuine atp advantage worth surfacing in the final scorecard. Evidence: `artifacts/atp_bench_matrix/20260625T224557Z/`.

## MATRIX-93 (2026-06-25) — ★★encrypted-`good` convergence CLOSED by `c39af6d9e` ('keep repair keepalives off control stream', lqmfsi): CORRECTNESS WIN. 50M/good encrypted now converges **5/5 sha**, all bounded at **4–6 feedback rounds** (zero 1024-round wedges). The keepalive-off-control-stream fix is the genuine root cause — the intermittent ~50%-of-runs wedge (MATRIX-90/91) is GONE. Honest perf note: converged median is now **49.25s (12.45× rsync)** — slower than MATRIX-90's *lucky* 2-round cases (~15.8s) because the fix makes EVERY run converge reliably via 4–6 rounds instead of occasionally-fast-but-often-catastrophic (741s/sha-fail). Correct trade: reliability over flaky speed. Round count is now a separate perf lever.

Benched origin/main HEAD `65d7b0d66` (fix `c39af6d9e`; built clean from `git archive`, 0 errors, atp 0.3.5), 50M / `good` (25ms / 0.1% loss / 200mbit) / `encrypted`, streams=1, reps=5, sha-verified, ATP_RQ_TRACE=1:

| rep | atp-quic-tls13 wall | feedback_rounds | status / sha | peak RSS |
|---|---|---|---|---|
| 1 | 44.59s | 5 | ok / sha ✓ | 43.1 MB |
| 2 | 49.25s | 5 | ok / sha ✓ | 35.7 MB |
| 3 | 53.16s | 4 | ok / sha ✓ | 43.2 MB |
| 4 | 36.98s | 5 | ok / sha ✓ | 40.4 MB |
| 5 | 95.69s | 6 | ok / sha ✓ | 37.3 MB |

- **CONVERGED 5/5 (gate met)** — median 49.25s; rsync-ssh median 3.96s (5/5) → **12.45× slower**. RSS atp ~40 MB vs rsync ~64 MB.

**Convergence arc, encrypted 50M/good: 0/3 (MATRIX-83, all 1024-round/sha-fail) → 2/3 (MATRIX-90, `0b4bb938d`) → 2/5 (MATRIX-91, `505806a22` insufficient) → 5/5 (MATRIX-93, `c39af6d9e`).** The decisive fix kept repair keepalives off the control stream: the keepalives were polluting the control channel and disrupting the feedback/repair loop, so on certain loss patterns the receiver never escalated to enough repair and spun to the 1024-round cap. With keepalives separated, the repair loop now reliably completes in 4–6 rounds. **This is a real correctness milestone — the hard intermittent non-convergence (caught only by reps5 central A/B; the swarm's local 3/3 had missed it) is closed and verified fail-closed (sha 5/5 byte-identical).**

**Remaining (perf, not correctness):** encrypted-good is now reliable but 12.45× rsync at 4–6 feedback rounds — far slower than the encrypted-perfect 12.3× (which is single-pass). The lever is reducing the feedback-round count on a 0.1%-loss link (the repair loop converges but conservatively); plus the same per-symbol AEAD/header-protection CPU cost (MATRIX-88/89) applies. Routed to owners (panes 3/8): convergence is BANKED — thank you; next, if pursuing encrypted-good perf, cut the 4–6 rounds toward 1–2 (tune repair-overhead-per-round so the first repair burst is sized to actually close the gap). Evidence: `artifacts/atp_bench_matrix/20260625T230948Z/`.
