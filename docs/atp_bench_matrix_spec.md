# ATP vs rsync — comprehensive benchmark matrix (the "right way", per /running-the-gauntlet)

Authoritative spec for the true scoring harness. Obeys the BENCHMARK INTEGRITY STANDARD in
`atp_rq_beat_rsync_ledger.md` (only-vs-rsync, rsync-optimal, apples-to-apples, crypto-symmetric,
report cv + peak/avg RSS + feedback_rounds). Gauntlet Pillar-(a): reproducible, multi-rep,
machine-readable JSONL + scorecard, identical framework cost both engines.

## Honest results so far (no-crypto tier: atp-lab vs rsync-daemon, UNCAPPED netns veth)

| regime (loss/delay) | size | atp-rq wall | rsync-d wall | note |
|---|---|--:|--:|---|
| 0%/0ms (uncapped=unreal) | 10M | 0.71s | 0.108s | rsync wins (∞ local bw; atp CPU overhead) |
| 0%/0ms | 50M | 3.42s | 0.208s | rsync wins (∞ bw) |
| 1%/25ms | 10M | 1.01s | 1.51s | atp wins 1.5× |
| 1%/25ms | 50M | 3.82s | 2.52s | rsync wins 1.5× |
| 3%/50ms | 10M | 1.81s | 9.35s | **atp wins 5.2×** |
| 3%/50ms | 50M | **123s, sha MISS** | 7.5s | **atp FAILS** ← critical |

**Lessons (shape the harness + the work):**
1. ★ **CRITICAL: source-first FAILS under moderate loss at scale** (50M/3%/50ms → 123s + sha MISS).
   Source-retransmit alone (overhead=1.0, retransmit_rounds=2, max 8192) does NOT converge for a
   large file under real loss. ⇒ must fall back to FEC repair (the AdaptiveController's
   `overhead_for_target` calibrated ε*) when source-retransmit isn't converging. AND investigate the
   **sha MISS** — atp must FAIL-CLOSED, never commit mismatched/incomplete data. (Was it a silent
   partial-commit, or a transfer error the harness scored as MISS? Determine + fix.)
2. **Uncapped netns = unrealistic "perfect" link** (∞ local bandwidth → rsync memcpy-streams, atp's
   CPU overhead loses). A real link has finite bandwidth. ⇒ **regimes MUST be rate-capped** (netem
   `rate`), else the perfect-link cell is meaningless. atp's edge is high-BDP + loss, not ∞-bw.
3. source-first holds receiver RSS ~8 MB on clean/mild (great); but the failing lossy-large cell
   ballooned to 247 MB — memory must stay bounded on the FEC fallback path too.

## Workload matrix (deterministic, seeded, generated once per workload, reused for atp+rsync)
- **Single random files:** 500K, 5M, 50M, 500M, 5G (`/dev/urandom`; gen once per cell, same bytes
  fed to atp and rsync; incompressible ⇒ rsync `-z` correctly OFF).
- **Nested trees (power-law file sizes):**
  - `tree_small`: ~2000 files, sizes ~Pareto(α≈1.4) in [1 KiB, 1 MiB], depth ~6, fan-out ~5.
  - `tree_big`: ~400 files, sizes ~Pareto(α≈1.2) in [10 KiB, 50 MiB], depth ~5.
  Generator: python, seeded RNG; emits a manifest (path,size) for reproducibility.

## Connection regimes (netns + veth + netem, RATE-CAPPED — isolated, no rm -rf)
| regime | rate | delay (+jitter) | loss | extra |
|---|---|---|---|---|
| perfect | 1 gbit | 2 ms | 0 | — |
| good | 200 mbit | 25 ms | 0.1% | — |
| bad | 50 mbit | 80 ms ± 20 | 2% | — |
| broken | 10 mbit | 200 ms ± 50 | 10% | reorder 5%, dup 1% |
Apply netem on BOTH veth ends (symmetric). Use `netem ... rate <r>` (or tbf) for the cap.

## Per-cell measurement (gauntlet measure_with_teardown)
- REPS ≥ 3 (≥5 for small/fast cells); report **median wall + cv_pct** (cv>5% ⇒ noise, flag).
- **peak RSS** (both ends): `/usr/bin/time -v` Maximum resident set size.
- **avg RSS** (both ends): background sampler reads `/proc/<pid>/status` VmRSS every 200 ms → mean.
- CPU%, feedback_rounds (atp), bytes; **SHA-256 verify every transfer** (file: digest; tree:
  sorted per-file digest set). Payload gen + teardown OUTSIDE the timed window.
- Resumable: append JSONL; skip cells already present. Long cells (5G×broken) get REPS=1 + a
  generous timeout; LOG any skipped/timed-out cell (no silent truncation).

## Crypto tiers (apples-to-apples; pick per run)
- `nocrypto`: atp-lab (`--rq-allow-unauthenticated-lab`) vs rsync **daemon** (rsync://, no ssh).
- `auth`: atp-rq with a fresh HMAC key delivered through `--rq-auth-key-stdin` vs rsync over
  ssh (aes128-gcm). The key must stay out of argv, environments, time-command records, and
  result artifacts. [needs AUTH-1]
- `encrypted`: atp-quic (TLS-1.3) vs rsync over ssh. [needs QUIC.1; full encryption parity]

## Authenticated unchanged-object delta acceptance profile

`authenticated-delta-unchanged-v1` is an acceptance lane outside the ATP-vs-
rsync scorecard. It admits only one nonempty, non-symlink regular file through
`500M`, `auth/atp-rq-auth`, and `encrypted/atp-quic-tls13`. The 5G and tree
workloads, nocrypto, rsync, and every other method are rejected. The size cap
keeps both RQ and QUIC manifests below the 4,096-chunk protocol bound.

The runner copies the exact source file and portable metadata into the receiver
destination before timing, then performs one measured identical-source transfer
with delta enabled. RQ uses its fresh protected-stdin key. QUIC retains TLS 1.3
transport protection and additionally receives a fresh protected-stdin key for
the session-bound manifest proof; TLS protects the bound request/proof frames.
The primary `auth_posture` continues to describe transport/symbol security;
`delta_control_auth_posture` describes the combined TLS/session/HMAC receiver-
state authorization.

Acceptance is fail-closed and requires exactly one sender and receiver JSON
report, the expected transport, nonempty matching transfer IDs, zero endpoint
statuses, `committed=true`, `files=1`, sender SHA/Merkle success, zero top-level
and nested payload/symbol/feedback counters, and zero QUIC decode counters. The
destination SHA and its device/inode/size/mode/owner/mtime stamp must remain
unchanged. Isolated veth accounting must satisfy
`0 < control_wire_bytes < source_bytes`; zero ATP payload does not mean zero
authenticated-control or TLS wire traffic.

Profile, stable case ID, git HEAD, SHA success, stream count, and both auth
postures participate in resume matching. Default artifact names are profile-
specific, and explicit result files containing another or missing profile are
rejected. Failed and stale attempts remain available in append-only results;
the current plan requires exactly one fully accepted row for each current
case/git identity and rejects malformed successful rows. These rows must never
enter `score_matrix.py`.

This profile proves only that an identical pre-seeded single file negotiates
`AlreadyInSync` over authenticated framed control, both endpoints close
successfully, payload counters remain zero, and the destination remains
unchanged. Recorded wall time and wire bytes are diagnostic only. It does not
prove zero total wire traffic, throughput or bandwidth improvement, rsync
superiority/inferiority, changed-chunk reuse, `DeltaChunks`, tree/rename
behavior, lossy-link resilience, or broad transport correctness.

## Output
- `JSONL`: one row per (workload, regime, method, rep): all metrics above + explicit
  `cell_profile`, stable `case_id`, `auth_posture`,
  `delta_control_auth_posture`, binary sha prefix, netem params, and git HEAD.
  Acceptance rows additionally require `delta_mode_observed`,
  `delta_acceptance_ok`, exact sender/receiver payload and symbol counters,
  `control_wire_bytes`, `payload_file_identity_unchanged`, and
  `performance_claim:false`. (artifacts/ is gitignored → write under a tracked
  path or attach to ledger.)
- `score_matrix.py`: JSONL → per-cell median + cv + atp/rsync wall & RSS ratios + per-regime geomean
  + a markdown scorecard. Missing/mismatched current QUIC auth postures are quarantined before
  median grouping. Headline = atp-vs-rsync ONLY.

## Files
- `scripts/atp_bench/matrix_bench.sh` — the harness (gen + regimes + run + measure + JSONL).
- `scripts/atp_bench/gen_tree.py` — power-law tree generator (seeded).
- `scripts/atp_bench/score_matrix.py` — scorer → markdown.
(extend the existing `scripts/atp_rq_regime_bench.sh` / `scripts/atp_bench/*` where sensible.)

## SWARM OPERATING MODE — Code-First / Batch-Verify (9 panes: cod_1-7 + cc_1-2)

Builds (rch serializes same-project) and cross-machine/netem benchmarks (one Contabo receiver) are
the SCARCE SERIALIZED resource. Writing code is free + parallel. So:
- **PHASE 1 (all agents, parallel):** write your lane's real code + tests → `cargo check -p
  asupersync` (syntax ONLY, the MAX) → COMMIT IMMEDIATELY (msg "…— code-first, batch-verify
  pending", reference the bead, leave it in_progress) → next. **NO `cargo test`, NO rch full build,
  NO cross-machine/netem runs.** KPI = commit stream. Coordinate via bead-assignee + this ledger
  (Agent Mail degraded). File-exclusive lanes (below) — never edit another lane's file.
- **PHASE 2 (orchestrator = SapphireHill, central, periodic):** when commit-rate dips (queue dry),
  run ONE build + targeted tests over the union of touched crates on an EXEMPT target dir; fix
  compile errors FIRST (cargo early-abort masks the true count); cluster failures by file → dispatch
  one agent per cluster; close ONLY green beads with the suite as evidence. Then run the matrix
  benchmark centrally. **Enforcement:** orchestrator kills any per-agent rch/cargo-test build
  (pkill on pane target dirs); its own batch build uses an exempt dir. No git surgery on shared main
  (verify no commit lost). Watch disk/build-proc spikes (= enforcement slipped → re-kill).

### File-exclusive lanes (no collisions)
| pane | lane | owns (file-exclusive) |
|---|---|---|
| cod_2 (BluePike) | source-first: AUTH-1 + FEC-fallback-under-loss + sha-MISS fail-closed fix | transport_rq send/receive source-first path + adaptive.rs |
| cc_1 | the matrix harness scripts (per this spec) | scripts/atp_bench/{matrix_bench.sh,gen_tree.py,score_matrix.py} |
| cod_1 | E-6 GSO/sendmmsg fast path | src/net/udp.rs |
| cod_4 | QUIC.1 port source-first to quic | src/net/atp/transport_quic/* (coordinate w/ peer swarm) |
| cod_5 | WIRE-4 loss-detector + WIRE-3 transfer_brain | src/net/atp/loss/* + quic/transfer_brain.rs |
| cod_6 | WIRE-5 beacons finalize | src/net/atp/datagram/beacons.rs |
| cod_3 | E-4 decode-vs-K bench + power-law tree gen helper | benches/ |
| cod_7 | perfect-link overhead reduction analysis (rate-capped) + E-3 streams | (analysis/ledger; minimal edits, coordinate) |
| cc_2 | scorer/analysis + Phase-2 failure triage helper + correctness review of cod_2's source-first | review-only unless dispatched a triage cluster |
