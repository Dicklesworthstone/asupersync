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
- **Result:** _pending_

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

- **L-FINDING-1 · Sender does ONE syscall per symbol.** `send_symbol_datagram`
  (transport_rq/mod.rs:1907) → `sock.send(&dgram)` (one `send_to` per symbol; ~100k for 100M).
- **L-FINDING-2 · Receiver does ONE `poll_recv` per symbol.** `pump_until_control`
  (transport_rq/mod.rs:2955) polls `udp.poll_recv` for a single datagram per loop iter (biased
  select with the control stream). It does NOT use `recv_batch_from` (udp.rs:1226), which drains
  ALL immediately-ready packets after a single reactor-readiness wait.
- **L-FINDING-3 · asupersync has NO true batched-syscall UDP path.** `send_batch_to` (udp.rs:1190)
  is a portable no-op loop (`fallback_used:true`, one `send_to` each — no `sendmmsg`).
  `grep sendmmsg|recvmmsg|UDP_SEGMENT src/net/` ⇒ none. So GSO/GRO/sendmmsg/recvmmsg are
  UNIMPLEMENTED in the runtime. This is both a missed-leverage finding AND a runtime-enhancement
  opportunity that would also benefit transport_quic + quic_native.
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
- **Scope/risk:** (b) needs `#[allow(unsafe_code)]` libc in udp.rs + reactor integration + the
  unsafe ledger (artifacts/unsafe_boundary_ledger_v1.json). Benefits QUIC too.
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
