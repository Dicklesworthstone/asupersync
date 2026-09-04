# ATP vs rsync — comprehensive benchmark matrix (the "right way", per /running-the-gauntlet)

Authoritative spec for the true scoring harness. Obeys the BENCHMARK INTEGRITY STANDARD in
`atp_rq_beat_rsync_ledger.md` (only-vs-rsync, rsync-optimal, apples-to-apples, crypto-symmetric,
report cv + peak/avg RSS + feedback_rounds). Gauntlet Pillar-(a): reproducible, multi-rep,
machine-readable JSONL + scorecard, identical framework cost both engines.

## Current results

[`atp_rq_beat_rsync_ledger.md`](atp_rq_beat_rsync_ledger.md) is the single
source of truth for current benchmark-cell status. The current banked record is:
the 56-row rate-capped nocrypto sweep reached a board-level win in MATRIX-212
and MATRIX-231; the encrypted board was measured 25/25 in MATRIX-216 and its
lossy sub-board reached all-wins in MATRIX-221; MATRIX-230 closed the remaining
decode-integrity asterisk by classifying the observed RaptorQ rank deficiency as
`InsufficientRank`; MATRIX-232 records the honest clean-large, duty-cycle-bound
ceiling; MATRIX-233 bounds the tree-perfect gap at roughly 1.3-1.6x; and the
latest ledger entry is MATRIX-235 (2026-07-10). Consult the ledger and its
attached run artifacts rather than copying these summaries into scorecards.

**Historical lessons that shaped the harness and the work:**
1. ★ A pre-harness, uncapped June run once produced 50M/3%/50ms at 123s with a
   SHA miss. That result is superseded by the rate-capped MATRIX-212/MATRIX-231
   board and the MATRIX-230 integrity closure; it is not a current failing cell.
   Its durable lesson remains: source retransmit alone was insufficient under
   that regime, FEC repair must take over when it stops converging, and ATP must
   fail closed rather than commit mismatched or incomplete data.
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
| wan | 300 mbit | 45 ms ± 2 each end (90 ms RTT) | 0 | limit 20000 pkts; clean long pipe (2026-09-02: QUIC 53 % of link, ≈ rsync-ssh; RQ 87 %) |
| wanloss | 300 mbit | 45 ms ± 2 each end (90 ms RTT) | 0.01% | limit 20000 pkts; the residual loss of a real path (2026-09-02: QUIC lost only 8 % vs `wan` — loss sensitivity refuted at 1e-4) |
| wanqueue | 300 mbit | 45 ms ± 2 each end (90 ms RTT) | 0 | limit 1000 pkts (netem default): shallow real-NIC queue; tests whether sender bursts tail-drop (the Hetzner sender showed 13762 UDP SndbufErrors after the cross-machine runs) |
Apply netem on BOTH veth ends (symmetric), so `delay` is one-way and the RTT is twice it. Use `netem ... rate <r>` (or tbf) for the cap.

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

Profile, stable case ID, git HEAD, full verified binary/archive SHA-256 digests,
producer workflow run/attempt, SHA success, stream count, and both auth postures
participate in resume matching. Default artifact names are profile-specific,
and explicit result files containing another or missing profile are rejected.
Failed and stale attempts remain available in append-only results; the current
plan requires exactly one fully accepted row for each current
case/git/artifact identity and rejects malformed successful rows. These rows
must never enter `score_matrix.py`.

This profile proves only that an identical pre-seeded single file negotiates
`AlreadyInSync` over authenticated framed control, both endpoints close
successfully, payload counters remain zero, and the destination remains
unchanged. Recorded wall time and wire bytes are diagnostic only. It does not
prove zero total wire traffic, throughput or bandwidth improvement, rsync
superiority/inferiority, changed-chunk reuse, `DeltaChunks`, tree/rename
behavior, lossy-link resilience, broad transport correctness, release
readiness, broad workspace health, reproducible builds, or privileged-execution
safety.

Real execute-mode evidence for this profile must use the commit-bound ATP packet
produced by the `commit-bound-atp-binary` GitHub Actions job for the checkout's
exact `main` HEAD. The packet contains a run-unique x86_64 GNU release archive,
an outer checksum, a byte-identical standalone copy of the archive's embedded
provenance, and an offline GitHub SLSA attestation bundle. Before creating an
output directory, generating a workload, changing namespaces/netem, or starting
a cell, `matrix_bench.sh` must fail closed unless all of the following bind to
the current checkout and passed executable:

- the outer archive checksum and signed GitHub attestation, including exact
  repository, signer workflow, `refs/heads/main`, source SHA, and hosted-runner
  posture;
- the exact three regular archive members, authoritative embedded provenance,
  clean source SHA/tree, locked build command, Cargo.lock digest, explicit
  `x86_64-unknown-linux-gnu` target, Linux/X64 producer, and ELF64 x86-64 ABI;
- the inner checksum, recorded binary size/digest/version, and the passed
  executable's bytes, group/world-nonwritable permissions, and successful
  `--version` probe;
- the exact canonical `run_matrix_cell.sh` command and checked-in bytes of both
  matrix scripts at the same source commit.

Dry-run planning remains artifact-free. Checksum or filename matching without
the signed archive attestation is not admissible execution evidence. The
producer manifest explicitly makes no performance, matrix-execution, broad
workspace-health, release-readiness, runtime-correctness, reproducible-build,
consumer-verification, or privileged-execution-safety claim.

## Output
- `JSONL`: one row per (workload, regime, method, rep): all metrics above + explicit
  `cell_profile`, stable `case_id`, `auth_posture`,
  `delta_control_auth_posture`, netem params, and git HEAD. Authenticated-delta
  rows additionally carry the full verified binary/archive SHA-256 digests and
  producer workflow run/attempt.
  Acceptance rows additionally require `delta_mode_observed`,
  `delta_acceptance_ok`, exact sender/receiver payload and symbol counters,
  `control_wire_bytes`, `payload_file_identity_unchanged`, and
  `performance_claim:false`. (artifacts/ is gitignored → write under a tracked
  path or attach to ledger.)
  ATP-over-QUIC rows additionally carry `quic_limiter`: the sender's `limiter`
  block verbatim (see "Sender limiter block" below), `null` for binaries that
  predate it.
- `score_matrix.py`: JSONL → per-cell median + cv + atp/rsync wall & RSS ratios + per-regime geomean
  + a markdown scorecard. Missing/mismatched current QUIC auth postures are quarantined before
  median grouping. Headline = atp-vs-rsync ONLY.

### Sender limiter block (`limiter` in the QUIC `atp_send` JSON)

`atp send --transport quic` adds an additive `limiter` object to its `atp_send`
JSON line (and one `[atp] progress quic_limiter ...` stderr line). It comes from
`transport_quic::QuicSendLimiterReport` and says WHY a cell was slow instead of
leaving it to throughput × RTT arithmetic (br-asupersync-bi2462.2). Consumers
that ignore it keep parsing the report unchanged.

| key | meaning |
|---|---|
| `stalls.<reason>.count` / `.micros` | how often and for how long the sender waited behind each gate: `pacing` (byte/token pacer deadlines and the AIMD retry-after), `cwnd` (bytes in flight reached the QUIC congestion window), `stream_credit` (receiver's `MAX_STREAM_DATA` below the admission minimum), `unacked_guard` (ATP's in-flight admission cap: BtlBw × RTprop, 16 MiB ceiling), `send_queue` (source-stream queue over its cap, drained before more data was admitted), `receiver_window` (datagram-tier NeedMore credit), `other` (a blocked flush with cwnd and credit both available) |
| `total_stall_micros`, `dominant_stall`, `dominant_stall_micros`, `dominant_stall_share_pct` | the sum, the longest-held reason (null when nothing stalled), and its integer share of the wall time |
| `peak_bytes_in_flight`, `peak_congestion_window_bytes`, `min_congestion_window_bytes`, `final_congestion_window_bytes`, `final_ssthresh_bytes`, `slow_start_exited`, `transport_samples` | QUIC recovery state sampled at every stall and at the end (`final_ssthresh_bytes` is null while recovery never left slow start) |
| `min_rtt_micros`, `smoothed_rtt_micros`, `pto_count` | the transport's RTT estimator and PTO backoff at the end — in the ATP data plane's synthetic event-count clock units (one tick per packet plus pacer sleeps), NOT wall time; read them as relative, never as milliseconds |
| `path_rtprop_micros`, `path_bottleneck_bytes_per_s` | the wall-clock path figures: minimum send→ACK flight time and the max-filtered delivery rate from the source-stream delivery sampler (RTprop falls back to the handshake RTT sample before the first ACK) |
| `min_unacked_admission_cap_bytes`, `peak_stream_unacked_bytes` | the lowest in-flight admission cap the source-stream gate enforced and the highest sent-but-unacked byte count it saw (the bulk data is transport-untracked, so `peak_bytes_in_flight` stays 0 on this path) |
| `stream_window_requests`, `final_stream_send_window_bytes` | STREAM_DATA_BLOCKED frames the sender sent to ask for a larger source-stream window (only while credit-bound and loss-clean), and the peer's `MAX_STREAM_DATA` limit at the end — against the 2 MiB HelloAck window this shows whether the window grew (A4) |
| `loss_timeouts`, `lost_packets`, `lost_bytes`, `retransmit_batches`, `retransmitted_stream_bytes` | application-data loss timeouts that declared loss, what they declared, and source-stream retransmission volume |
| `unacked_admission_cap_bytes`, `min_stream_send_credit_bytes` | the admission cap in force at the end and the lowest stream credit the admission gate saw |
| `udp_send_errors`, `socket_buffers.{requested,applied}_{send,recv}_bytes` | UDP send-batch failures (ENOBUFS on a real NIC behind a shallow qdisc) and what the kernel actually granted (Linux clamps to `net.core.wmem_max` / `rmem_max`) |

Stall durations are attributed per wait-loop iteration from the loop's own
elapsed clock, so their sum never exceeds the wall time of the loops that
recorded them. Connection-level `MAX_DATA` credit is not tracked by the native
stack and has no entry.

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
