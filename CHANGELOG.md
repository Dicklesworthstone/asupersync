# Changelog

All notable changes to [Asupersync](https://github.com/Dicklesworthstone/asupersync) are documented here.

Asupersync is a spec-first, cancel-correct, capability-secure async runtime for Rust.

**Format notes:**

- Versions with a **Release** badge have published GitHub Releases. Plain git tags are milestone markers without release artifacts.
- Commit links point to representative commits, not exhaustive lists.
- Organized by landed capabilities within each version, not by diff order.

Scope window: current Unreleased work through 2026-07-05, reconstructed from git history, beads, benchmark ledgers, and live repo artifacts; latest published GitHub Release/tag baseline is `v0.3.4`.

## Version Timeline

- **Unreleased**: post-`v0.3.4` ATP, proof-lane, runtime, and skill-refresh work.
- **v0.3.5 workspace version marker**: internal package/version update on 2026-06-18; no `v0.3.5` git tag or GitHub Release existed when this changelog was refreshed.
- **v0.3.4 Release**: latest published GitHub Release/tag baseline, dated 2026-06-07.
- **v0.3.3 Pre-release**: superseded by `v0.3.4`.
- **v0.3.2 Release** and older entries: retained release-history sections below.

---

## [Unreleased]

### ATP clean-matrix, transport security, and proof-lane consolidation

> Late-June and July work moved ATP from individual architecture wins toward
> matrix-governed benchmark evidence. The bar is now explicit: tuned rsync
> baseline, release `atp`, crypto-symmetric cells, fail-closed SHA/tamper
> checks, rate-capped links, and whole-matrix evidence before claiming a win.
> Stale cells, compile-only checks, or `sha_ok` without timing/bytes evidence do
> not count.

- **ATP-over-QUIC/H3 foundation and native TLS posture.** The transport lane
  now includes ATP QUIC integration, ATP-over-H3/WebTransport adapters, native
  QUIC frame codecs, handshake state, packet protection, real UDP transfer
  paths, and fail-closed X.509/server-name/replay/anti-amplification tests.
  Direct native QUIC/TLS relies on QUIC AEAD authentication; non-direct or
  cross-trust RaptorQ paths still need explicit symbol-auth posture.
  Representative commits include
  [`b45516d70`](https://github.com/Dicklesworthstone/asupersync/commit/b45516d70),
  [`bb20b0fa9`](https://github.com/Dicklesworthstone/asupersync/commit/bb20b0fa9),
  [`651748218`](https://github.com/Dicklesworthstone/asupersync/commit/651748218),
  [`e1a681d80`](https://github.com/Dicklesworthstone/asupersync/commit/e1a681d80),
  [`159113a1f`](https://github.com/Dicklesworthstone/asupersync/commit/159113a1f),
  [`e7e1d8e8`](https://github.com/Dicklesworthstone/asupersync/commit/e7e1d8e8),
  [`4078161f`](https://github.com/Dicklesworthstone/asupersync/commit/4078161f),
  [`1442724ff`](https://github.com/Dicklesworthstone/asupersync/commit/1442724ff),
  and [`ca63bd03e`](https://github.com/Dicklesworthstone/asupersync/commit/ca63bd03e).
- **Reliable clean-source stream and auth/encrypted repair path.** The
  benchmark lane landed authenticated control-source frames, clean encrypted
  source-stream routing, drain/flush fixes, good-link reliable stream admission,
  ack-clocked QUIC datagram pacing, repair-spray pacing, and E802 block-size
  rounding fixes. These are tracked through the matrix harnesses rather than as
  isolated unit claims.
  ([`d7a82fd44`](https://github.com/Dicklesworthstone/asupersync/commit/d7a82fd44),
  [`116e51adf`](https://github.com/Dicklesworthstone/asupersync/commit/116e51adf),
  [`d880f5fb4`](https://github.com/Dicklesworthstone/asupersync/commit/d880f5fb4),
  [`69c9c14be`](https://github.com/Dicklesworthstone/asupersync/commit/69c9c14be),
  [`da53c8e9a`](https://github.com/Dicklesworthstone/asupersync/commit/da53c8e9a),
  [`ace3358d5`](https://github.com/Dicklesworthstone/asupersync/commit/ace3358d5),
  [`0dd7aa708`](https://github.com/Dicklesworthstone/asupersync/commit/0dd7aa708),
  `br-asupersync-8sxwj0`, `br-asupersync-5r1mh8`,
  `br-asupersync-uw1cc2`)
- **Encrypted QUIC receiver/sender overhaul and retransmit coalescing.** The
  July 3 MATRIX-205/206 work replaced the encrypted QUIC receive pump with
  zero-copy frame decode, in-place AEAD unprotect, ACK fast paths,
  inc-hash-on-receive, bounded sender queues, release-on-ACK retention,
  delivery-clocked source-stream pacing, and coalesced retransmit frames.
  Current evidence records the first encrypted mild-loss win (`50M/good`),
  `5G/perfect/encrypted` correctness unblocked, and a large receiver RSS drop,
  while keeping the no-claim boundary explicit: `500M/perfect/encrypted` still
  loses to tuned rsync, `50M/bad/encrypted` still needs a rate-climb/cliff
  recovery mechanism, absolute-schedule pacing was re-refuted, and 5G encrypted
  peak RSS remains follow-up work.
  ([`773a655ef`](https://github.com/Dicklesworthstone/asupersync/commit/773a655ef),
  [`1b480bcab`](https://github.com/Dicklesworthstone/asupersync/commit/1b480bcab),
  `br-asupersync-uw1cc2`, `br-asupersync-oh6gm2`,
  `br-asupersync-xnlyss`)
- **RQ 500M/broken convergence, decode-integrity correction, and scoped win.**
  MATRIX-207/208/209 moved `500M/broken/nocrypto` from timeout, to
  fail-closed convergence, to sha-ok parity, and finally to a banked scoped
  win. The stack includes arrival-evidence pacing loss, rank-stall congestion
  gated by arrival corroboration, lower round-0 FEC overhead, sparse residual
  source requests, shard-absolute FEC seed read-back from shared staging, and
  double-buffered encode-ahead for the paced RQ spray. Current ledger evidence
  supports only this matrix-cell claim: atp median 564.77s, sha-ok 3/3 plus a
  confirming fourth rep, versus tuned rsync median 574.46s. The residual
  `asupersync-c54to7` decode-integrity bead remains open for rare
  redundancy-recovered `InconsistentEquations`; do not read this as an
  encrypted, tree, cross-trust symbol-auth, or whole-matrix win.
  ([`6bfdf6c54`](https://github.com/Dicklesworthstone/asupersync/commit/6bfdf6c54),
  [`a6b797fc9`](https://github.com/Dicklesworthstone/asupersync/commit/a6b797fc9),
  [`814809e5`](https://github.com/Dicklesworthstone/asupersync/commit/814809e5),
  [`acfccb30`](https://github.com/Dicklesworthstone/asupersync/commit/acfccb30),
  `br-asupersync-c54to7`)
- **ATP follow-ups after the banked RQ win remain proof-gated.** MATRIX-210
  raised encrypted QUIC recovery drain caps conservatively (`FAST` 4->8,
  PTO 64->256), and MATRIX-211 landed a one-shot packed-member commit batch on
  the blocking I/O pool for a future `tree_small` A/B. These are implementation
  landings, not standalone benchmark wins: `br-asupersync-oh6gm2` remains open
  for encrypted rate-climb/cliff recovery, `br-asupersync-xnlyss` records the
  5G encrypted receiver RSS profile, and the packed-member path still needs a
  quiet-box matrix proof before any perf claim is banked.
  ([`dc99cad8`](https://github.com/Dicklesworthstone/asupersync/commit/dc99cad8),
  [`3dd3f141`](https://github.com/Dicklesworthstone/asupersync/commit/3dd3f141),
  `br-asupersync-oh6gm2`, `br-asupersync-xnlyss`)
- **Large-object clean wins against tuned rsync.** Incremental hash-on-receive,
  fragment hash overlap, protocol-v3 `ObjectComplete` hash trailers, and
  same-filesystem commit rename cut tail work on large clean transfers. Matrix
  evidence recorded 500M and 5G clean wins in nocrypto+auth cells while keeping
  explicit no-regress and no-claim boundaries for remaining harder lanes.
  ([`faa93d808`](https://github.com/Dicklesworthstone/asupersync/commit/faa93d808),
  [`463a4cfae`](https://github.com/Dicklesworthstone/asupersync/commit/463a4cfae),
  [`81c44d28e`](https://github.com/Dicklesworthstone/asupersync/commit/81c44d28e),
  [`bae50415d`](https://github.com/Dicklesworthstone/asupersync/commit/bae50415d),
  `br-asupersync-2eb4k2`, `br-asupersync-sze9ym`)
- **Delta/resync and bonding groundwork.** Byte-precise subchunk planning,
  mixed-subchunk tests, wire apply reports, compact repeated-chunk framing, and
  manifest-framing reductions landed for delta resync and netns sidecar work.
  The known delta resync hang remains an active blocker rather than a completed
  claim.
  ([`70d8fa001`](https://github.com/Dicklesworthstone/asupersync/commit/70d8fa001),
  [`bec7a27d1`](https://github.com/Dicklesworthstone/asupersync/commit/bec7a27d1),
  [`989331e78`](https://github.com/Dicklesworthstone/asupersync/commit/989331e78),
  [`cbbe37474`](https://github.com/Dicklesworthstone/asupersync/commit/cbbe37474),
  [`8983b7364`](https://github.com/Dicklesworthstone/asupersync/commit/8983b7364),
  `br-asupersync-v0jeoc`, `br-asupersync-cu4zww`,
  `br-asupersync-2qas9c`)
- **RaptorQ hardening and fail-closed decode posture.** The RaptorQ lane now has
  deterministic proof traces, decode verification guards, wrong-width symbol
  rejection, tamper proof witnesses, rank-profile evidence, and data-loss bug
  fixes. Treat it as a proof-carrying subsystem with explicit authentication
  posture, not just an encoder/decoder API.
  ([`ac69a713c`](https://github.com/Dicklesworthstone/asupersync/commit/ac69a713c),
  [`727e21eb7`](https://github.com/Dicklesworthstone/asupersync/commit/727e21eb7),
  [`11a08727b`](https://github.com/Dicklesworthstone/asupersync/commit/11a08727b),
  [`0ac5c3e7c`](https://github.com/Dicklesworthstone/asupersync/commit/0ac5c3e7c),
  [`aa0959143`](https://github.com/Dicklesworthstone/asupersync/commit/aa0959143),
  [`cb44e3cc4`](https://github.com/Dicklesworthstone/asupersync/commit/cb44e3cc4))
- **Proof lanes as first-class source of truth.** Remote `rch` proof commands,
  proof-lane manifests, proof status snapshots, validation-frontier signoff, and
  resource-envelope contracts now govern many documentation/runtime claims.
  Update scripts, artifacts, manifest lanes, and contract tests together.
  ([`1cc389141`](https://github.com/Dicklesworthstone/asupersync/commit/1cc389141),
  [`92e801726`](https://github.com/Dicklesworthstone/asupersync/commit/92e801726),
  [`fd911e707`](https://github.com/Dicklesworthstone/asupersync/commit/fd911e707),
  [`b63bd24cf`](https://github.com/Dicklesworthstone/asupersync/commit/b63bd24cf),
  [`29fb46d10`](https://github.com/Dicklesworthstone/asupersync/commit/29fb46d10))
- **Browser/service/runtime expansion.** Browser Edition added readiness,
  package-integrity, consumer-compatibility, WASM rebuild, native-only cfg, and
  RCH-in-CI gates. Service surfaces also advanced across production H2
  listeners, web middleware layering, fluent HTTP client requests, database
  transaction obligations, and gRPC call-scoped backpressure/cancel coupling.
  Runtime work added spawn/mailbox improvements, platform reactor defaults,
  shared fallback timers, scheduler CPU metrics, and churn gates.
  ([`0f58ff593`](https://github.com/Dicklesworthstone/asupersync/commit/0f58ff593),
  [`186a71303`](https://github.com/Dicklesworthstone/asupersync/commit/186a71303),
  [`057a8d8c0`](https://github.com/Dicklesworthstone/asupersync/commit/057a8d8c0),
  [`2ac589d68`](https://github.com/Dicklesworthstone/asupersync/commit/2ac589d68),
  [`6a79f24b6`](https://github.com/Dicklesworthstone/asupersync/commit/6a79f24b6),
  [`4c772a47c`](https://github.com/Dicklesworthstone/asupersync/commit/4c772a47c),
  [`88ef4e0da`](https://github.com/Dicklesworthstone/asupersync/commit/88ef4e0da),
  [`12c926ef8`](https://github.com/Dicklesworthstone/asupersync/commit/12c926ef8),
  [`326082b0f`](https://github.com/Dicklesworthstone/asupersync/commit/326082b0f),
  [`09868a489`](https://github.com/Dicklesworthstone/asupersync/commit/09868a489))

### Runtime scheduler/timer CPU efficiency (`runtime-cpu-overhaul`)

> Live profiling of a heavy consumer (a terminal-multiplexer GUI) localized
> 25–65% CPU to the asupersync runtime even while the application itself was
> wait-bound. This work added the measurement substrate, fixed the one real
> defect it surfaced, and recorded the refuted hypotheses so they are not
> re-attempted. (`br-asupersync-runtime-cpu-overhaul-5vt09v`)

- **Runtime instrumentation counters** behind a new, zero-cost `runtime-metrics`
  feature. `runtime::metrics::snapshot()` exposes timer-thread spawns,
  `sched_yield` calls, worker spins/parks/unparks, and the live timer population
  (registered/fired/cancelled plus a derived `active_timers` gauge). Every
  `record_*` helper inlines to a no-op and `snapshot()` returns all-zero when the
  feature is off, so release builds pay nothing.
  ([`12c926ef8`](https://github.com/Dicklesworthstone/asupersync/commit/12c926ef8),
  `br-asupersync-runtime-cpu-overhaul-5vt09v.1`)
- **Scheduler CPU/churn benchmark and recorded baseline**
  (`benches/scheduler_cpu_churn.rs`,
  `artifacts/scheduler_cpu_churn/baseline.json`): an M-sweep idle+load harness
  that mimics the profiled scheduler shape, reads the counters, and measures
  process CPU, OS-thread high-water, and wakeup-latency p50/p99/p999. A committed
  regression gate (`scripts/run_scheduler_cpu_churn_validation.sh`) fails on
  idle busy-spin, idle-CPU, or thread-per-`sleep` churn regressions.
  ([`12c926ef8`](https://github.com/Dicklesworthstone/asupersync/commit/12c926ef8),
  [`cae8c1540`](https://github.com/Dicklesworthstone/asupersync/commit/cae8c1540),
  `br-asupersync-runtime-cpu-overhaul-5vt09v.2`, `.6.1`)
- **Shared process-global fallback timer** (`time::sleep`): a `Sleep` polled with
  no installed timer driver (`Cx::current().timer_driver()` is `None`) used to
  spawn one OS thread per `Sleep` to drive its deadline — the thread-per-`sleep`
  churn the profile caught (~37/sec) for sleeps driven off the runtime's worker
  threads. It now registers with a single process-lifetime pump thread that
  shares the standard wall-clock timer wheel; a per-`Sleep` thread is kept only
  for custom logical clocks. Behavior-preserving — the default `Cx`-driver path
  is unchanged. As defense-in-depth, taking the fallback now emits a **one-time
  WARN** (via `tracing_compat`) naming the missing timer driver, so a
  mis-configured consumer surfaces in logs instead of churning silently — the
  fallback stays a valid path (no panic), matching the `br-asupersync-9nn568`
  no-driver-warn idiom.
  ([`b67dec457`](https://github.com/Dicklesworthstone/asupersync/commit/b67dec457),
  `br-asupersync-runtime-cpu-overhaul-5vt09v.3`, `.3.5`)
- **`RuntimeBuilder::enable_time()`** convenience: a discoverable, tokio-shaped
  opt-in that installs a wall-clock timer driver unless one was already provided
  via `with_timer_driver` (idempotent, order-independent). `build()` already
  installs a wall-clock driver by default, so this is a clarity/migration aid
  that gives consumers a named method to reach for — and that the off-driver
  fallback warn above points at — rather than a behavior change.
  (`br-asupersync-runtime-cpu-overhaul-5vt09v.3.1`)
- **Empirical findings recorded (no code shipped):** the benchmark proved the
  default multi-threaded runtime is healthy — `timer_threads_spawned == 0`, 0%
  idle CPU, and zero idle `sched_yield` — so the profiled pathologies are
  usage-specific, not default-runtime defects. Replacing the load-path
  `sched_yield` with a userspace spin (Lever 2) was **bench-refuted and
  reverted**: `yield_now` cooperatively deschedules the worker and throttles the
  backoff loop, whereas spinning keeps it hot — a deterministic ~2.7× increase in
  spin-loop iterations, i.e. more CPU, not less, on a multi-worker
  intermittent-work load. The park clock-polling reduction (Lever 3) was found
  already addressed (the multi-lane park reads the clock once per cycle; the
  single-thread worker parks on a constant timeout).
  (`br-asupersync-runtime-cpu-overhaul-5vt09v.4`, `.5`)

## v0.3.5 workspace version marker -- 2026-06-18

> Dependency-refresh and release-train patch for Rust workspace crates and
> Browser Edition packages.
>
> Internal package-version marker: no `v0.3.5` git tag or GitHub Release was
> present when this changelog was refreshed on 2026-07-04. Until that tag exists,
> compare Unreleased work from `v0.3.4`.

### Release highlights

- Synchronized publishable Rust crates, Browser Edition package manifests, and
  local workspace path dependencies on version 0.3.5.
- Raised remaining non-compatible dependency requirements for the conformance,
  fuzz, SQLite, OpenTelemetry, Redis, SQLx, RaptorQ, and Browser Edition tool
  surfaces so validation resolves against current upstream releases.
- Kept compatible patch/minor dependency resolution in the ignored local
  `Cargo.lock`, preserving the library crate's no-committed-lock policy.
- Updated the public README dependency snippets from 0.3.4 to 0.3.5.

## [v0.3.3] -- 2026-06-01

> 1,991 commits since v0.3.2 (2026-05-20 -> 2026-06-01) | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.3.2...v0.3.3)
>
> Patch release focused on completing the mock-code-finder cleanup push,
> hardening Windows/no-default build surfaces, and repairing the release
> publishing path so crates.io and Browser Edition package releases can run from
> a coherent workspace version.

### Release highlights

- Replaced remaining placeholder/mock-coded test and runtime surfaces with
  deterministic contract-backed behavior across conformance, messaging,
  observability, runtime/lab, and protocol lanes.
- Hardened Windows compilation paths, including no-default CLI binaries and
  capability-safe detached contexts for command-line proof surfaces.
- Synchronized publishable Rust workspace crates and Browser Edition package
  manifests on version 0.3.3 for a coherent release train.
- Repaired the GitHub publish workflow so release cargo jobs use `rch` when it
  is available and fall back to the hosted runner when `rch` is absent, instead
  of failing before crates.io dry-run/package validation.
- Expanded crates.io dry-run coverage so root crates are checked up front and
  every dependent crate is checked immediately before its ordered publish, after
  newly bumped dependencies are visible on crates.io.

## [v0.3.2] -- 2026-05-20 (Release)

> 3,657 commits since v0.3.1 (2026-04-22 → 2026-05-20) | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.3.1...v0.3.2)
>
> Triaged-issue fixes shipped in this release: Windows HTTPS connect path returning `Ok` then failing with `WSAENOTCONN (10057)` (#35, `bc7d3dec`); `Runtime::block_on` not installing an ambient `Cx`, causing `TcpListener::accept` to busy-poll instead of waiting on the reactor (#41, `73dfaaad`); and heuristic `module_desync` epoch-consistency logs demoted from `error!` to `debug!` so normal task-table epoch advances no longer spam errors (#42, `357df7f5`).

### Release theme

A two-week, multi-agent push focused on three things at once: closing
the **Reality-Check Wave 2 / swarm-v2** program (autonomic live control
loop, signed profile bundles, and a 64-core / 256GiB capacity envelope
proof), driving the **mock-code-finder** sweep into every subsystem
(replacing placeholder/mock implementations and broad clippy
suppressions with real semantics and contract artifacts), and a heavy
**runtime/protocol perf and correctness pass** across MPSC, mutex,
HPACK, transport router, scheduler hot paths, HTTP/3 QPACK, and
RaptorQ. Test surface grew with 90+ structure-aware fuzz targets and
a wave of differential / golden / metamorphic suites. Dozens of new
smoke-artifact lanes landed under hidden roots
(`.<name>-smoke-artifacts/`) and dedicated `scripts/run_*_smoke.sh`
runners; the matching `*_contract` integration tests pin them to
deterministic invariants.

### Reality-Check Wave 2 — swarm-v2 autonomic control loop

The headline workstream. Closed as `asupersync-d87ytw` (`[swarm-v2]
Autonomic live control loop and proof certificates`) on 2026-05-05
together with all 15 sub-beads `d87ytw.1`..`d87ytw.15` and the
`reality-check-wave2` siblings (`6qju7t`, `j1dwk6`, `ta56mp`,
`4a3ghz`).

- **Massive-swarm responsiveness program** ([`f660601c8`](https://github.com/Dicklesworthstone/asupersync/commit/f660601c8), [`b832d7fff`](https://github.com/Dicklesworthstone/asupersync/commit/b832d7fff), `br-asupersync-ul9jhr`)
- **64-core / 256GiB massive-swarm capacity envelope proof** with proof-carrying capacity certificates ([`a44863be5`](https://github.com/Dicklesworthstone/asupersync/commit/a44863be5), [`7e56ccdd5`](https://github.com/Dicklesworthstone/asupersync/commit/7e56ccdd5), [`1e0a3abb8`](https://github.com/Dicklesworthstone/asupersync/commit/1e0a3abb8), `br-asupersync-j1dwk6`, `tdgqjy`)
- **Compositional latency-budget certificates** and **mean-field swarm capacity planner** (`asupersync-d87ytw.2`, `d87ytw.3`)
- **Signed profile bundles** with manifests, shadow-run gates, rollback receipts, and true cryptographic signatures ([`66d6d2c1d`](https://github.com/Dicklesworthstone/asupersync/commit/66d6d2c1d), [`f6768f4b2`](https://github.com/Dicklesworthstone/asupersync/commit/f6768f4b2), [`9da861091`](https://github.com/Dicklesworthstone/asupersync/commit/9da861091), `br-asupersync-4buhgd`, `gk0cg3`, `spbsig`, `d87ytw.4`, `d87ytw.7`)
- **Explainable host profile planner** and dry-run runtime config bundles with arena-temperature policy ([`d5fc7b639`](https://github.com/Dicklesworthstone/asupersync/commit/d5fc7b639), [`bc671cd74`](https://github.com/Dicklesworthstone/asupersync/commit/bc671cd74), [`a81c62a8b`](https://github.com/Dicklesworthstone/asupersync/commit/a81c62a8b), `br-asupersync-c1qfr9`)
- **Adaptive batch sizing** for cancel and inject burst handling (`br-asupersync-crtx9h`)
- **Hot-cold arena tiers** and optional large-page cold evidence slabs ([`90d8eda39`](https://github.com/Dicklesworthstone/asupersync/commit/90d8eda39), [`360842bdd`](https://github.com/Dicklesworthstone/asupersync/commit/360842bdd), [`c896ea729`](https://github.com/Dicklesworthstone/asupersync/commit/c896ea729), `br-asupersync-hhlhjv`)
- **NUMA-local arena shard placement** and remote-touch accounting with deterministic locality planner ([`dd7dfdc79`](https://github.com/Dicklesworthstone/asupersync/commit/dd7dfdc79), `br-asupersync-nxd9xm`)
- **NUMA-aware worker cohorts** + local-first stealing (`br-asupersync-3ld2ri`)
- **Cohort-aware admission steering** and remote-spill budget (`br-asupersync-j1980r`)
- **Tail-risk-aware admission control** for overload periods (`br-asupersync-g0aumf`)
- **Overload brownout mode** for optional runtime surfaces, with OTLP trace shedding folded into the brownout-aware observability policy ([`717395913`](https://github.com/Dicklesworthstone/asupersync/commit/717395913), [`75afc4dac`](https://github.com/Dicklesworthstone/asupersync/commit/75afc4dac), [`bc2252817`](https://github.com/Dicklesworthstone/asupersync/commit/bc2252817), `br-asupersync-m1k0pz`, `xnqgmd`, `d87ytw.8`)
- **Read-biased snapshot substrate** for governor and observability hot paths (`br-asupersync-l0q0rs`)
- **Bounded-load distributed routing** for hot-node avoidance (`br-asupersync-lgj5tz`)
- **Contention-adaptive combiner path** for injection hot spots (`br-asupersync-g0kwgh`)
- **Self-tuning trace storage profiles** for 256GiB-class hosts (`br-asupersync-yaj7g6`, `d87ytw.9`)
- **Wake-to-run telemetry** + offline autotuner feedback loop and scheduler evidence artifact schema (`br-asupersync-99if94`, `1l8m9y`)
- **Controller interference matrix** + timescale-separation proof harness; **controller interference digital twin** (`br-asupersync-b4guhs`, `d87ytw.6`)
- **Controller snapshot ledger** for adaptive swarm policies; **controller provenance dashboard** ([`8ac2cc60a`](https://github.com/Dicklesworthstone/asupersync/commit/8ac2cc60a), `br-asupersync-ccgxc3`, `d87ytw.14`)
- **Live tail-causal attribution emitters**, **wait-cause remediation reports**, **session-typed hot-path obligation proofs**, **NUMA-and-capacity certificate merger**, **rch proof-queue workload feedback** (`asupersync-d87ytw.5`/`.10`/`.11`/`.12`/`.13`)
- **Final control-loop signoff audit** ([`a829a677f`](https://github.com/Dicklesworthstone/asupersync/commit/a829a677f), `asupersync-d87ytw.15`)
- **Real agent-swarm workload bridge and replay pack** (parent + sub-beads `qn8i0p` and `qn8i0p.1..8`): coordination workload artifact schema, redacted Agent-Mail/Beads/rch collector, runtime workload corpus expansion, lab replay/minimization hooks, capacity/profile planner ingest, privacy/redaction/trust boundary proofs, one-command smoke runner, final signoff
- **Restart-budget metamorphic oracle** alignment for the supervision storm-monitor regression ([`896e5fcbe`](https://github.com/Dicklesworthstone/asupersync/commit/896e5fcbe), [`95f93ee33`](https://github.com/Dicklesworthstone/asupersync/commit/95f93ee33), `br-asupersync-ta56mp`, `4a3ghz`)
- **Unified capability evidence registry** + proof manifest ([`68b1127cc`](https://github.com/Dicklesworthstone/asupersync/commit/68b1127cc), `br-asupersync-6qju7t`)

The program also added **22+ smoke-artifact lanes** with paired
`scripts/run_*_smoke.sh` runners and `tests/*_contract.rs`
integration tests pinning each lane to deterministic invariants:
adaptive-batch-sizing, blocking-pool-affinity, capacity-envelope-planner,
cohort-admission-steering, compile-frontier-movement,
decision-plane-validation, governor-state-snapshot,
host-profile-planner, hot-cold-arena-tiers,
jetstream-publish-backpressure, massive-swarm-signoff,
numa-arena-locality, otlp-audit-inventory, otlp-brownout-shedding,
overload-brownout, read-biased-region-snapshot,
resource-monitor-platform-gap, runtime-capacity-hints,
signed-profile-bundle, tail-risk-admission, task-record-pool,
trace-storage-profile. Smoke-artifact roots are gitignored by
contract ([`4874ddca9`](https://github.com/Dicklesworthstone/asupersync/commit/4874ddca9), `br-asupersync-9o35bs`).

### Mock-Code-Finder sweep

178 commits prefixed `[mock-code-finder][...]` and 70+ matching closed
beads. The campaign systematically removed broad clippy `#[allow(...)]`
suppressions and replaced placeholder/mock implementations with real
behavior across the repo. Top-touched subsystems: WASM (33 commits),
HTTP/2 (14), HTTP/3 (8), tokio compat, sync, scheduler, combinator,
otel/diagnostics/oracle, pool, lab-live, contract, websocket, trace,
time, recovery, raptorq, quic, notify, lab, kernel, kafka, doctor,
codec, channel, cancel, broadcast, frankenlab, refinement,
leak-checker, gen-server, gf256, golden, type, region, mutex, h1,
hpack, redis, fabric, rate-limit, fs/process/signal,
runtime/control-seam, rwlock, snapshot, semantic-risk.

Real production gaps closed under that banner included:

- **Kafka silent message loss when the `kafka` feature was off** —
  `KafkaProducer::send` was writing to a stub broker on production
  builds without `kafka` (which is not a default feature). Closed as
  CRITICAL.
- **HTTP/2 GOAWAY / PRIORITY / PING / PUSH_PROMISE / DATA END_STREAM
  conformance simulations** replaced with real state-machine and
  SETTINGS-driven assertions; **ENABLE_PUSH** wired to real
  `PUSH_PROMISE` behavior.
- **OTEL placeholders** replaced with real snapshots: histogram /
  metric aggregator extraction, resource / log severity / trace+span
  ID / batching simulations, W3C baggage HTTP extraction and
  injection, tail-based sampling scope, span-semantics success rate.
- **PostgreSQL real `COPY FROM` client API** + protocol state machine
  ([`fabea56fc`](https://github.com/Dicklesworthstone/asupersync/commit/fabea56fc) and related).
- **HTTP/1.1 RFC 9112 request-target validation** suite — six tests
  that previously passed vacuously when codec validation was missing.
- **RaptorQ differential** scaffolding that compared against
  hardcoded `Ok(vec![0x42; 1024])` mocks, plus the Gaussian
  elimination test placeholder, replaced with real round-trip and
  spec-derived assertions.
- **Storm-monitor** default-alignment regression fixed ([`95f93ee33`](https://github.com/Dicklesworthstone/asupersync/commit/95f93ee33)).
- **HTTP/3 conformance harness re-enabled** with 29 sub-suites and
  `static-mut` state replaced with `OnceLock<Mutex>` ([`73d7f63ce`](https://github.com/Dicklesworthstone/asupersync/commit/73d7f63ce)).
- **Hardcoded H3 mock implementations** replaced with real
  functionality ([`1bbfc2168`](https://github.com/Dicklesworthstone/asupersync/commit/1bbfc2168), `br-asupersync-bs9nbz`).

### Concurrency correctness

Real production bugs uncovered while landing the swarm-v2 program:

- **`src/channel/mpsc.rs`** — `try_send` was returning `Full` whenever
  *any* waiter was queued, even with available capacity (`bd
  asupersync-m02s6r`). Reverted to a true capacity check.
- **`src/channel/mpsc.rs`** — `SendPermit::send` was dropping the
  failure mode silently on disconnect; rewrote to surface via
  `Outcome` ([`b75a998f5`](https://github.com/Dicklesworthstone/asupersync/commit/b75a998f5), `br-asupersync-l7t66t`).
- **`src/channel/watch.rs`** — `send_modify` deadlocked because the
  user closure ran under the write lock; closure now executes outside
  the lock window ([`3a6ad1ea8`](https://github.com/Dicklesworthstone/asupersync/commit/3a6ad1ea8), `br-asupersync-0x7fdb`).
- **`src/runtime/io_driver.rs`** — `on_event` callbacks could deadlock
  against the driver's own state lock; ordering fixed ([`99043ae8e`](https://github.com/Dicklesworthstone/asupersync/commit/99043ae8e)).
- **`src/lab/runtime.rs`** — lock-ordering inversion repaired by
  hoisting `cx_inner.read()` out of the `scheduler.lock()` scope
  ([`dc69ed4e8`](https://github.com/Dicklesworthstone/asupersync/commit/dc69ed4e8), `br-asupersync-iwqn3q`).
- **`src/runtime/scheduler/three_lane.rs`** — the steal path was
  evicting tasks whose arena records had been concurrently removed;
  changed to preserve, then steal, then update accounting ([`df763583c`](https://github.com/Dicklesworthstone/asupersync/commit/df763583c), [`dc7123c78`](https://github.com/Dicklesworthstone/asupersync/commit/dc7123c78), `br-asupersync-uguhr2`).
- **`src/runtime/state.rs`** — region close not waking *all* waiters;
  fixed to broadcast ([`f257fd1c4`](https://github.com/Dicklesworthstone/asupersync/commit/f257fd1c4), `asupersync-novvgd`).
- **`src/record/region.rs`** — `IN_REGION_WITH_CALL` panic safety via
  `ReentryGuard` RAII ([`813131f08`](https://github.com/Dicklesworthstone/asupersync/commit/813131f08), `asupersync-b3998e`); `heap_with` /
  `rref_with` reentrant deadlock prevention ([`c5d08813b`](https://github.com/Dicklesworthstone/asupersync/commit/c5d08813b), `asupersync-xtxr28`).
- **`src/runtime/state.rs`** — region epoch advance on obligation
  reservation; obligation pending-counter underflow promoted from
  `debug_assert + saturating_sub` to release-mode panic ([`e3071bc80`](https://github.com/Dicklesworthstone/asupersync/commit/e3071bc80), [`25803feec`](https://github.com/Dicklesworthstone/asupersync/commit/25803feec)).
- **`src/sync/notify.rs`** — `notify_one` waking same waker repeatedly
  via baton drift; corrected baton passing across drop and `notified`
  paths.
- **`src/runtime/scheduler/three_lane.rs`** — `seen_io_tokens` bound
  added so the per-worker scratch set cannot grow without bound across
  long-lived workers ([`3d6bb2104`](https://github.com/Dicklesworthstone/asupersync/commit/3d6bb2104), `br-asupersync-414j0b`).

### HTTP / protocol correctness

- **HTTP/3 QPACK**: enforce max field-section-size ([`2830f0fa4`](https://github.com/Dicklesworthstone/asupersync/commit/2830f0fa4), `asupersync-ifn7kw`); decoded-header count cap for DoS protection ([`fe8dcdc16`](https://github.com/Dicklesworthstone/asupersync/commit/fe8dcdc16), `asupersync-9bvfe5`); dynamic-table base-relative indexing fixed ([`5159c0758`](https://github.com/Dicklesworthstone/asupersync/commit/5159c0758), [`5c77c9340`](https://github.com/Dicklesworthstone/asupersync/commit/5c77c9340), [`e565f9252`](https://github.com/Dicklesworthstone/asupersync/commit/e565f9252)); QPACK documented as static-only and the runtime status reconciled across README tables ([`4ead428b5`](https://github.com/Dicklesworthstone/asupersync/commit/4ead428b5), [`15da98895`](https://github.com/Dicklesworthstone/asupersync/commit/15da98895)).
- **HTTP/3 frame**: varint encoding fixed ([`b61b51396`](https://github.com/Dicklesworthstone/asupersync/commit/b61b51396), [`4a1ebb6aa`](https://github.com/Dicklesworthstone/asupersync/commit/4a1ebb6aa), `br-asupersync-e48gp6`); 29-sub-suite RFC 9114 conformance harness re-enabled ([`73d7f63ce`](https://github.com/Dicklesworthstone/asupersync/commit/73d7f63ce)); `H3UniStreamType::decode` widened to `pub` ([`5fafb3fff`](https://github.com/Dicklesworthstone/asupersync/commit/5fafb3fff)).
- **HTTP/1.1 codec**: forbidden trailers per RFC 9110 §6.5.1 rejected ([`4c3a2cdca`](https://github.com/Dicklesworthstone/asupersync/commit/4c3a2cdca), `br-asupersync-135g0e`); leading-sign in Content-Length and chunk-size rejected ([`52eac7c26`](https://github.com/Dicklesworthstone/asupersync/commit/52eac7c26)); bare-CR scan bound to head region ([`322a1df11`](https://github.com/Dicklesworthstone/asupersync/commit/322a1df11), `br-asupersync-2ovm8z`).
- **HTTP/2 stream**: `StreamStore::ensure_slot` gap capped to prevent memory-DoS ([`db46975e5`](https://github.com/Dicklesworthstone/asupersync/commit/db46975e5), `br-asupersync-jq82r4`); HTTP/2 SETTINGS frame differential test vs `h2` reference ([`4c0048590`](https://github.com/Dicklesworthstone/asupersync/commit/4c0048590)); H2 stream conformance coverage tightened ([`6d13b2151`](https://github.com/Dicklesworthstone/asupersync/commit/6d13b2151), `br-asupersync-h8pga6`).
- **HPACK**: O(1) `DynamicTable` find via side-index ([`46b2d1646`](https://github.com/Dicklesworthstone/asupersync/commit/46b2d1646), `br-asupersync-4pshog`); `Arc<str>` dynamic-table entries plus 4-bit-stride Huffman state table ([`8e3353e44`](https://github.com/Dicklesworthstone/asupersync/commit/8e3353e44)); UTF-8-validate-on-borrow + wasted-clone cleanup ([`e32fd747a`](https://github.com/Dicklesworthstone/asupersync/commit/e32fd747a)); HPACK golden vectors landed ([`c0c07ae6a`](https://github.com/Dicklesworthstone/asupersync/commit/c0c07ae6a)).
- **WebSocket**: receive `Cx` threaded through read-refill polling so cancellation interrupts before transport bytes are consumed ([`192e41654`](https://github.com/Dicklesworthstone/asupersync/commit/192e41654)); frame encoder close-payload validation ([`f553cfcc9`](https://github.com/Dicklesworthstone/asupersync/commit/f553cfcc9), `asupersync-xc1r82`); wire-byte golden snapshot ([`696b2caa3`](https://github.com/Dicklesworthstone/asupersync/commit/696b2caa3)); trailing-bytes mock-code suppressions removed ([`636f94e13`](https://github.com/Dicklesworthstone/asupersync/commit/636f94e13)).
- **gRPC**: trailer timeout harness repaired ([`adc594f26`](https://github.com/Dicklesworthstone/asupersync/commit/adc594f26)); transport timeouts mapped to `DEADLINE_EXCEEDED` ([`b5729089a`](https://github.com/Dicklesworthstone/asupersync/commit/b5729089a), `br-asupersync-p8rju5`); conformance modules revived for grpc_deadline / grpc_health / grpc_status ([`6704791c4`](https://github.com/Dicklesworthstone/asupersync/commit/6704791c4), [`54970da04`](https://github.com/Dicklesworthstone/asupersync/commit/54970da04), `br-asupersync-pfvsch`); initial-window backpressure differential vs grpc-go ([`809e09080`](https://github.com/Dicklesworthstone/asupersync/commit/809e09080)).
- **TLS**: `--features tls -D warnings` cleared ([`a78f535a0`](https://github.com/Dicklesworthstone/asupersync/commit/a78f535a0), `br-asupersync-s0nwli`); ClientHello harness hardened ([`6a8f21a01`](https://github.com/Dicklesworthstone/asupersync/commit/6a8f21a01), `br-asupersync-cuyzmt`); record_conformance post-handshake plaintext-injection cases inverted with `u16::try_from` and tautological asserts replaced ([`9c061e13f`](https://github.com/Dicklesworthstone/asupersync/commit/9c061e13f), [`f222ed94f`](https://github.com/Dicklesworthstone/asupersync/commit/f222ed94f), [`5da6a1632`](https://github.com/Dicklesworthstone/asupersync/commit/5da6a1632)); cryptographic boundary test module ([`aced1f44e`](https://github.com/Dicklesworthstone/asupersync/commit/aced1f44e), `br-asupersync-9fjvs3`); cert-pinning fuzzer ([`2c87c7d1b`](https://github.com/Dicklesworthstone/asupersync/commit/2c87c7d1b), `br-asupersync-t374gm`).
- **DNS**: reject CNAME / MX / SRV RDATA with trailing bytes after the embedded DNS name ([`981b595be`](https://github.com/Dicklesworthstone/asupersync/commit/981b595be)); golden encoder include_bytes paths corrected ([`78eaad0ce`](https://github.com/Dicklesworthstone/asupersync/commit/78eaad0ce), `br-asupersync-knpltd`).
- **Web layer**: compression honors `identity;q=0`; ETags content-derived; error rewrites strip stale headers; health JSON includes top-level detail; nextjs bootstrap invalidates runtime scope on failure ([`676707e1e`](https://github.com/Dicklesworthstone/asupersync/commit/676707e1e)).
- **QUIC**: native QUIC RFC 9000 conformance test suite ([`f1d99ac9d`](https://github.com/Dicklesworthstone/asupersync/commit/f1d99ac9d), `br-asupersync-3mgtqf`); H3 varint frame fuzzer ([`98976fdd1`](https://github.com/Dicklesworthstone/asupersync/commit/98976fdd1), `br-asupersync-0eas0f`); tls_conformance_harness `arb_crypto_sequence` repair ([`3b4c99784`](https://github.com/Dicklesworthstone/asupersync/commit/3b4c99784), `br-asupersync-0pfh9h`).

### Database and messaging

- **MySQL** wire-protocol conformance test suite ([`c2f02422e`](https://github.com/Dicklesworthstone/asupersync/commit/c2f02422e), `asupersync-jysouz`); MariaDB OK_Packet status flags differential ([`c421dfd86`](https://github.com/Dicklesworthstone/asupersync/commit/c421dfd86)); `ResultSet` structure-aware fuzzer ([`b6f10c40a`](https://github.com/Dicklesworthstone/asupersync/commit/b6f10c40a)); MySQL row-stream clippy frontier cleared and explicit `AuthSwitch` coverage timed ([`234fc871a`](https://github.com/Dicklesworthstone/asupersync/commit/234fc871a), [`1cbc303e7`](https://github.com/Dicklesworthstone/asupersync/commit/1cbc303e7), `br-asupersync-m84ex4`, `f9o478`).
- **PostgreSQL** wire parser seam hardening ([`5e9532a44`](https://github.com/Dicklesworthstone/asupersync/commit/5e9532a44)); `CopyData` / `CopyDone` wire format differential conformance ([`eb3d2a164`](https://github.com/Dicklesworthstone/asupersync/commit/eb3d2a164)); real `COPY FROM` client API + extended-query / logical-replication coverage.
- **Database pool** real-server URL safety gates ([`6a7499ff0`](https://github.com/Dicklesworthstone/asupersync/commit/6a7499ff0)); E2E pool-reconnection integration test ([`cc5cdd286`](https://github.com/Dicklesworthstone/asupersync/commit/cc5cdd286), `asupersync-na35bj`).
- **Kafka**: real-broker test harness fix ([`31287df27`](https://github.com/Dicklesworthstone/asupersync/commit/31287df27), `br-asupersync-ygotyp`); committed offsets retained across resubscribe ([`f97d2eaa0`](https://github.com/Dicklesworthstone/asupersync/commit/f97d2eaa0)); compile-blocker rebalance test API repaired ([`c12c415a1`](https://github.com/Dicklesworthstone/asupersync/commit/c12c415a1), `br-asupersync-b0irdm`); `ProduceResponse` parser fuzzer ([`3af44c682`](https://github.com/Dicklesworthstone/asupersync/commit/3af44c682)); record-batch integration repaired ([`fabea56fc`](https://github.com/Dicklesworthstone/asupersync/commit/fabea56fc)).
- **Redis**: RESP3 Push frames accepted in `RedisPubSub::parse_event` ([`8228cf70f`](https://github.com/Dicklesworthstone/asupersync/commit/8228cf70f)); RESP3 SUBSCRIBE pattern routing differential vs `redis-rs` ([`0256200bc`](https://github.com/Dicklesworthstone/asupersync/commit/0256200bc)); RESP3 buffering and `RESP3 pubsub` decoder structure-aware fuzzer ([`25c72e989`](https://github.com/Dicklesworthstone/asupersync/commit/25c72e989), [`e7a705c01`](https://github.com/Dicklesworthstone/asupersync/commit/e7a705c01)).
- **JetStream**: `ConsumerInfo`, `StreamInfo`, `PullSubscribeOpts`, API-response, error-response, and publish-backpressure structure-aware fuzzers ([`db038ab3f`](https://github.com/Dicklesworthstone/asupersync/commit/db038ab3f), [`5ae936ea4`](https://github.com/Dicklesworthstone/asupersync/commit/5ae936ea4), [`cabb82adc`](https://github.com/Dicklesworthstone/asupersync/commit/cabb82adc), [`7cfa88d8b`](https://github.com/Dicklesworthstone/asupersync/commit/7cfa88d8b)).
- **SQLite**: `PRAGMA` serialization structure-aware fuzzer ([`85975767d`](https://github.com/Dicklesworthstone/asupersync/commit/85975767d)).

### RaptorQ erasure coding

- **RFC 6330 LtTuple expansion** inlined into `repair_symbol_into` ([`e4e7e7e0a`](https://github.com/Dicklesworthstone/asupersync/commit/e4e7e7e0a)); FEC-Payload-ID emission benchmark ([`43adfe0b8`](https://github.com/Dicklesworthstone/asupersync/commit/43adfe0b8)).
- **Decode rejects overflowed repair ESIs** instead of panicking in `decode_block` ([`br-asupersync-fm6ys2`](https://github.com/Dicklesworthstone/asupersync/commit/7ba972514), regression test included).
- **GF(256) SIMD vs scalar-reference equivalence fuzzer** ([`4982c3c93`](https://github.com/Dicklesworthstone/asupersync/commit/4982c3c93), `br-asupersync-uc6d7d`).
- **Canonical encode / decode round-trip golden snapshot** ([`894629272`](https://github.com/Dicklesworthstone/asupersync/commit/894629272), `br-asupersync-c12bcb`); RFC 6330 §6 high-loss recovery differential test ([`4aa26704c`](https://github.com/Dicklesworthstone/asupersync/commit/4aa26704c)); RFC 6330 §6 encode-decode round-trip differential ([`7a8c67d35`](https://github.com/Dicklesworthstone/asupersync/commit/7a8c67d35)).
- **Decoder progressive-symbol-arrival cancel-storm fuzzer** ([`1dbb986e4`](https://github.com/Dicklesworthstone/asupersync/commit/1dbb986e4)); decoder symbol-corruption fuzzer ([`324bfe08d`](https://github.com/Dicklesworthstone/asupersync/commit/324bfe08d)); `N_max` boundary fuzzer ([`cff637262`](https://github.com/Dicklesworthstone/asupersync/commit/cff637262)); decoding pipeline `feed()` structure-aware target ([`a6567e0a5`](https://github.com/Dicklesworthstone/asupersync/commit/a6567e0a5)); multi-block coverage ([`8d3d2157a`](https://github.com/Dicklesworthstone/asupersync/commit/8d3d2157a), `br-asupersync-lc0anl`).

### Runtime performance

A continuous-improvement pass; many fixes are bead-traced. Highlights:

- **MPSC O(N) → O(1) slab-based lookups** ([`0ae255739`](https://github.com/Dicklesworthstone/asupersync/commit/0ae255739)); MPSC `try_send` single-lock fast path ([`cdb033b3c`](https://github.com/Dicklesworthstone/asupersync/commit/cdb033b3c), `br-lej99f`); MPSC waiter scans removed.
- **Mutex** O(1) waiter cleanup via slab-backed intrusive linked list ([`f49630a8e`](https://github.com/Dicklesworthstone/asupersync/commit/f49630a8e), `br-asupersync-wlf0xh`, `vgw2yw`).
- **Semaphore** waiter scans removed ([`321132d36`](https://github.com/Dicklesworthstone/asupersync/commit/321132d36), `br-asupersync-8qlc7a`); static description on hot path ([`31b85ecb9`](https://github.com/Dicklesworthstone/asupersync/commit/31b85ecb9)).
- **Three-lane scheduler** `next_task` hot dispatch lock acquisitions optimized; `self.local.lock()` coalesced in next_task hot path ([`f2f2484a5`](https://github.com/Dicklesworthstone/asupersync/commit/f2f2484a5), [`82c0f8a1d`](https://github.com/Dicklesworthstone/asupersync/commit/82c0f8a1d), `br-asupersync-fvixmw`).
- **Local queue** O(1) dedup `HashSet` + lock-free `cached_len` atomic ([`4a14e7844`](https://github.com/Dicklesworthstone/asupersync/commit/4a14e7844), `br-asupersync-5oll2p`, `pvbwxm`).
- **TaskRecord object pool** eliminating ~35% allocation hot-spots ([`579894f8e`](https://github.com/Dicklesworthstone/asupersync/commit/579894f8e)).
- **Transport router** hot-path alloc removal + `DispatchResult` inline capacity ([`c26ee7fb5`](https://github.com/Dicklesworthstone/asupersync/commit/c26ee7fb5), `br-asupersync-klff8q`, `dv32fs`); hash-based `select_n` with consistent hashing ([`71f868f0a`](https://github.com/Dicklesworthstone/asupersync/commit/71f868f0a)).
- **OTLP trace exporter** lock-free `ArrayQueue` ([`3e6a436da`](https://github.com/Dicklesworthstone/asupersync/commit/3e6a436da), [`e2cc810c3`](https://github.com/Dicklesworthstone/asupersync/commit/e2cc810c3)).
- **Distributed assignment** O(K²) `Vec::contains` → O(K log K) `BTreeSet` ([`9a5dfd056`](https://github.com/Dicklesworthstone/asupersync/commit/9a5dfd056), `br-asupersync-45xcbm`).
- **Lyapunov governor** O(1) snapshot via incremental obligation counters ([`adadea72a`](https://github.com/Dicklesworthstone/asupersync/commit/adadea72a), [`f844f5555`](https://github.com/Dicklesworthstone/asupersync/commit/f844f5555), `br-asupersync-xxcss5`).
- **`Cx`** fast-cancel atomic check before write-lock in `checkpoint` ([`2f62175c0`](https://github.com/Dicklesworthstone/asupersync/commit/2f62175c0), `br-is2xg0`); hot-path `Cx::current().is_some*()` migrated to zero-Arc-clone helpers ([`b18f6d3b8`](https://github.com/Dicklesworthstone/asupersync/commit/b18f6d3b8), `br-asupersync-xqt7dj`); `cx/registry` `format!` removed from hot reservation path ([`570d755ec`](https://github.com/Dicklesworthstone/asupersync/commit/570d755ec)).
- **`time::wheel`** redundant `current_time()` call eliminated in `register` path ([`505b91af3`](https://github.com/Dicklesworthstone/asupersync/commit/505b91af3), [`33e34c78c`](https://github.com/Dicklesworthstone/asupersync/commit/33e34c78c), `br-asupersync-ifq7c5`).
- **`runtime/state`** `live_task_count` delegated to `TaskTable`'s O(1) phase-counts sum ([`0ba45c264`](https://github.com/Dicklesworthstone/asupersync/commit/0ba45c264), `br-afv6z4`).
- **`scheduler/worker`** `seen_io_tokens` bounded + cache-waker amortization ([`3d6bb2104`](https://github.com/Dicklesworthstone/asupersync/commit/3d6bb2104), `br-asupersync-414j0b`, `jkb17z`).
- **`observability/cancellation_debt_monitor`** parking_lot + bounded pending map ([`ecbb95c85`](https://github.com/Dicklesworthstone/asupersync/commit/ecbb95c85), `br-asupersync-37sffr`, `i40ap4`).
- **`panic_isolation`** `PANIC_COUNTER` `fetch_add` SeqCst → Relaxed ([`88850ba3e`](https://github.com/Dicklesworthstone/asupersync/commit/88850ba3e), `br-asupersync-h0pfb4`).
- **Hot-path Vec storage** migrated to `SmallVec` inline buffers across runtime ([`8fc1e0d38`](https://github.com/Dicklesworthstone/asupersync/commit/8fc1e0d38)).
- **Arena pre-sizing** optimization ([`9c5183f42`](https://github.com/Dicklesworthstone/asupersync/commit/9c5183f42), `br-asupersync-y4lcl9`).
- **gRPC codec** zero-copy identity frame + sized-Vec gzip ([`d3841aa5c`](https://github.com/Dicklesworthstone/asupersync/commit/d3841aa5c)); H1 zero-copy body via `BytesMut::into_vec` ([`482935ac4`](https://github.com/Dicklesworthstone/asupersync/commit/482935ac4)); H2 stream `StreamStore` flat-Vec replaces `DetHashMap` on hot path ([`eb26cfa67`](https://github.com/Dicklesworthstone/asupersync/commit/eb26cfa67)).

### Test infrastructure expansion

- **165 `feat:` commits, 90+ structure-aware fuzz targets** added across H1, H2, H3, RaptorQ, JetStream, Kafka, Redis, MySQL, SQLite, codecs, intrusive heap, macaroon attenuation, finalizer stack, and task-cancel witness serialization.
- **Differential conformance suites**: HTTP/2 SETTINGS frame vs `h2`; `LengthDelimitedCodec`; gRPC initial-window backpressure vs `grpc-go`; PostgreSQL `CopyData` / `CopyDone`; RESP3 SUBSCRIBE pattern vs `redis-rs`; MySQL vs MariaDB OK_Packet; Bytes shared-slice semantics ([`32b3c56fc`](https://github.com/Dicklesworthstone/asupersync/commit/32b3c56fc), `br-asupersync-6uckg1`); RFC 6330 §6 RaptorQ.
- **Golden snapshot suites**: Plan IR rewrites ([`0a37eb422`](https://github.com/Dicklesworthstone/asupersync/commit/0a37eb422), `br-asupersync-8tajyi`); Plan DAG rewrite-rule ([`0e6066426`](https://github.com/Dicklesworthstone/asupersync/commit/0e6066426)); HPACK ([`c0c07ae6a`](https://github.com/Dicklesworthstone/asupersync/commit/c0c07ae6a), `br-asupersync-l432ti`); WebSocket wire-byte ([`696b2caa3`](https://github.com/Dicklesworthstone/asupersync/commit/696b2caa3), `br-asupersync-z95cah`); trace canonicalizer Foata normal form ([`14fa0df4b`](https://github.com/Dicklesworthstone/asupersync/commit/14fa0df4b)); trace event serialization ([`a5258618c`](https://github.com/Dicklesworthstone/asupersync/commit/a5258618c), `br-asupersync-la3t6w`); h1 request-line + h2 control-frame goldens ([`504ae1fe6`](https://github.com/Dicklesworthstone/asupersync/commit/504ae1fe6)); Plan DAG / analysis / certificate insta baselines ([`e66cf1c97`](https://github.com/Dicklesworthstone/asupersync/commit/e66cf1c97)); obligation ledger goldens ([`e56cdfe69`](https://github.com/Dicklesworthstone/asupersync/commit/e56cdfe69), `asupersync-a2tueg`); symbol_cancel protocol lifecycle golden ([`f00395737`](https://github.com/Dicklesworthstone/asupersync/commit/f00395737)).
- **Metamorphic suites**: `OnceCell` init-then-get equivalence ([`4eb5b01b3`](https://github.com/Dicklesworthstone/asupersync/commit/4eb5b01b3)); three-lane scheduler priority-promotion idempotence ([`e9875ffce`](https://github.com/Dicklesworthstone/asupersync/commit/e9875ffce)); semaphore fairness and cancel-release invariants ([`249093cbe`](https://github.com/Dicklesworthstone/asupersync/commit/249093cbe), `br-asupersync-668nd3`); MPSC FIFO ([`99e3eead4`](https://github.com/Dicklesworthstone/asupersync/commit/99e3eead4)); broadcast MR3 dropped-receiver recovery range pinned to actual sent values ([`9a83b6d44`](https://github.com/Dicklesworthstone/asupersync/commit/9a83b6d44), `br-asupersync-w7g55u`).
- **Cryptographic boundary tests** module ([`aced1f44e`](https://github.com/Dicklesworthstone/asupersync/commit/aced1f44e), `br-asupersync-9fjvs3`).
- **Bytes** shared-slice conformance suite ([`32b3c56fc`](https://github.com/Dicklesworthstone/asupersync/commit/32b3c56fc), `br-asupersync-6uckg1`).
- **HPACK RFC 7541 edge-case + adversarial decoder fuzz targets** ([`5571df6c1`](https://github.com/Dicklesworthstone/asupersync/commit/5571df6c1)).

### Refactoring and code quality

A 2026-04-25 sweep centralized constructor and default behavior across
the runtime, transport, codec, lab, observability, plan, RaptorQ, and
HTTP subsystems via `derive Default` / shared constructor helpers /
test-setup helper reuse. Representative commits: scheduler default
delegations ([`8e5e98783`](https://github.com/Dicklesworthstone/asupersync/commit/8e5e98783), [`ac5dba397`](https://github.com/Dicklesworthstone/asupersync/commit/ac5dba397), [`326685465`](https://github.com/Dicklesworthstone/asupersync/commit/326685465), [`1ecafa20d`](https://github.com/Dicklesworthstone/asupersync/commit/1ecafa20d)), HPACK default
constructors ([`c23a26b5a`](https://github.com/Dicklesworthstone/asupersync/commit/c23a26b5a)), gRPC web frame default ([`6facb4e79`](https://github.com/Dicklesworthstone/asupersync/commit/6facb4e79)), TLS empty
constructors ([`43baf627a`](https://github.com/Dicklesworthstone/asupersync/commit/43baf627a)), CRDT counter constructors ([`0d852e83b`](https://github.com/Dicklesworthstone/asupersync/commit/0d852e83b)),
Lamport clock default ([`b5a0b9e82`](https://github.com/Dicklesworthstone/asupersync/commit/b5a0b9e82)), Conformal calibration defaults
([`366ab1ab1`](https://github.com/Dicklesworthstone/asupersync/commit/366ab1ab1)).

### Observability

- **Cancellation visualizer** namespaced DOT node IDs per trace, escaped labels, overflow-safe duration averages, real throughput accumulator ([`711c97178`](https://github.com/Dicklesworthstone/asupersync/commit/711c97178)).
- **Cancellation analyzer** bottleneck threshold compares fractions instead of percentage points; preserves zero-throughput samples; insufficient-data on empty input ([`edd1f81cc`](https://github.com/Dicklesworthstone/asupersync/commit/edd1f81cc)).
- **`panic_isolation`** runtime lifecycle instrumentation in `CapturingMetrics` ([`bb3afb75f`](https://github.com/Dicklesworthstone/asupersync/commit/bb3afb75f)).
- **OTEL** placeholder histograms / metric aggregator extraction / W3C baggage HTTP extraction / tail-based sampling scope all replaced with real implementations under the mock-code-finder banner.

### Documentation and repository hygiene

A 2026-05-05 cleanup sweep:

- Root `.md` planning / analysis / fuzz-companion / per-subsystem audit files relocated under `docs/{plans,analysis,fuzz,audits}/` ([`56b3de9aa`](https://github.com/Dicklesworthstone/asupersync/commit/56b3de9aa), [`33b6c7ac6`](https://github.com/Dicklesworthstone/asupersync/commit/33b6c7ac6), [`79d5f5139`](https://github.com/Dicklesworthstone/asupersync/commit/79d5f5139), [`800c8a2a9`](https://github.com/Dicklesworthstone/asupersync/commit/800c8a2a9), [`e82f1ee76`](https://github.com/Dicklesworthstone/asupersync/commit/e82f1ee76)).
- Raw modes-of-reasoning per-mode swarm outputs removed ([`a5f3d5692`](https://github.com/Dicklesworthstone/asupersync/commit/a5f3d5692)); tracked ephemeral scan / fix-script / test-binary detritus removed ([`e04a0e708`](https://github.com/Dicklesworthstone/asupersync/commit/e04a0e708)).
- `.gitignore` expanded for root scratch and smoke-artifact accumulation ([`d31e2515a`](https://github.com/Dicklesworthstone/asupersync/commit/d31e2515a), [`4874ddca9`](https://github.com/Dicklesworthstone/asupersync/commit/4874ddca9)).
- Phase 6 reality check added ([`0f192ae63`](https://github.com/Dicklesworthstone/asupersync/commit/0f192ae63), `br-asupersync-ao9m8l`); HTTP/3 implementation status aligned across all README tables ([`15da98895`](https://github.com/Dicklesworthstone/asupersync/commit/15da98895), [`9a577aa7a`](https://github.com/Dicklesworthstone/asupersync/commit/9a577aa7a)).

### Audit campaign

The fresh-eyes / bug-audit campaign continued. Apr-24 / Apr-25 batches
recorded multiple SOUND verdicts, including the cryptographic boundary
test module ([`6d6009c17`](https://github.com/Dicklesworthstone/asupersync/commit/6d6009c17)), lab-network and lab-meta runners
([`3549ad058`](https://github.com/Dicklesworthstone/asupersync/commit/3549ad058)), and the smallvec optimization pass ([`6a28e1a48`](https://github.com/Dicklesworthstone/asupersync/commit/6a28e1a48), `br-asupersync-ms7qud`). The audit index ledger now exceeds 1450 records.

### Beads / workstream evidence

1,726 beads closed since v0.3.1. Beyond the swarm-v2 program above:

- **`asupersync-d87ytw` (parent epic)** + sub-beads `.1`–`.15` — autonomic live control loop and proof certificates (closed 2026-05-05).
- **`asupersync-qn8i0p` (parent)** + sub-beads `.1`–`.8` — real coordination-workload bridge and replay pack.
- **`asupersync-6qju7t`** — unified capability evidence registry and proof manifest.
- **`asupersync-j1dwk6`** — 64-core / 256GiB massive-swarm capacity envelope proof.
- **`asupersync-ul9jhr`** — massive-swarm responsiveness program.
- **`asupersync-wqsael`** — final massive-swarm signoff matrix and operator evidence audit.
- Workstream-specific cleanups: `m84ex4` (mysql clippy), `mmddg3` (runtime config clippy), `pfweja` (three_lane clippy), `vdhei0` (blocking_pool clippy), `xmp8am` (low-risk clippy frontier), `ikol9e` (W3C trace-context generalization), `jm7y3y` (`OnceCell` future_not_send policy), `9o35bs` (smoke-artifact gitignore contract), `5005zl` (E2E conformance helper compile bead).

### Verification

- `cargo check --workspace --all-targets` continues to pass.
- The lib-test frontier work (`br-asupersync-0b0fxk`, `d367a0`,
  `dhrd5p`, `ejzzih`, `hxk1pe`, `i1vce6`, `nuday6`, `oim3yn`, `wfbfg3`,
  `zb9g03`) repaired the residual cross-surface compile drift that
  blocked scheduler / observability / shared-main proof paths under
  `--features test-internals -D warnings`.
- The 22+ `tests/*_smoke_contract.rs` contract tests pin
  reality-check Wave 2 invariants; their generated artifacts live
  under hidden `.<name>-smoke-artifacts/` roots and are gitignored by
  contract.

---

## [v0.3.1](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.3.1) -- 2026-04-21 (Release)

> Hours after v0.3.0 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.3.0...v0.3.1)

### Release theme

Patch release carrying the output of a deep-dive post-v0.3.0 test-suite
hardening pass: **25 real production-code bugs fixed** (most of them
pre-existing, surfaced by the recently-expanded metamorphic test
suite), plus a large batch of test-harness drift fixes that unblock
the library's `cargo test --workspace --lib` path.

### Production bugs fixed

Concurrency correctness (highest severity):

- **`src/runtime/reactor/epoll.rs`** — SIGABRT `IO Safety violation: owned file descriptor already closed`. The test `modify_failure_preserves_bookkeeping_when_poller_fd_closed` was calling `libc::close(poller_fd)` on a descriptor still owned by `Poller::epoll_fd: OwnedFd`. Under parallel `cargo test --workspace --lib` (~200 threads), any concurrent fd allocation could grab that freed number and wrap it in its own `OwnedFd`; the test's subsequent `dup2(saved_poller_fd, poller_fd)` would then silently close the foreign owner's fd, and rust-std would abort the whole process when that foreign `OwnedFd` dropped. Replaced `libc::close(poller_fd)` with `dup2(replacement_fd, poller_fd)` so `poller_fd` is a continuously-valid descriptor throughout the test.
- **`src/runtime/reactor/epoll.rs`** — also added early `EBADF` rejection for `raw_fd < 0` (otherwise the stdlib `fd != -1` debug assertion trips) and a `ReactorState::orphaned` tombstone set so `deregister` is idempotent after `EBADF`/`ENOENT` reaped bookkeeping in `modify`.
- **`src/observability/runtime_integration.rs`** — parking_lot RwLock self-deadlock in `on_task_cancel_completed` and `on_region_closed`. The pattern `if let Some(x) = self.task_traces.write().remove(&id) { ... self.task_traces.read() ... }` extended the `RwLockWriteGuard`'s lifetime into the `if let` body, where the subsequent `.read()` deadlocked on the same non-reentrant lock. Extracted the `write().remove(...)` into a `let` binding so the write guard drops first.
- **`src/service/discover.rs`** — DNS Condvar coalesce observability (from the deep-dive; already in v0.3.0).
- **`src/runtime/epoch_gc.rs`** — `process_safe_epochs` broke on the first unsafe item in the queue, leaving safe items behind it unreclaimed. `try_advance_and_cleanup` / `force_advance_and_cleanup` passed `new_epoch - 1` as the safe boundary instead of `new_epoch`, so items tagged with the just-retired epoch were never reclaimed.
- **`src/runtime/epoch_tracking.rs`** — `GlobalEpochCounter::try_advance` had "simplified: always try to advance" stubbed in place of the rate limiting the docstring promised. Restored CAS-based rate limiting with a shared Instant origin. `DeferredCleanupQueue::execute_safe_cleanups` used `<=` instead of strict `<` on the safe-epoch comparison — violated the pinning invariant.

HTTP protocol correctness / security:

- **`src/http/h1/codec.rs`** — missing bare-CR scan (RFC 9112 §2.2 request-smuggling vector; accepted `\r` without `\n` in the request head) and no printable-ASCII validation on the request target (raw NUL, SOH, DEL, non-ASCII were accepted). Both closed.
- **`src/http/h3_native.rs`** — RFC 9297 DATAGRAM frame decode treated a truncated payload as a streaming short-read (`UnexpectedEof`) instead of peer misbehavior (`InvalidFrame`). Now emits distinct errors for varint vs payload-length truncation.
- **`src/http/h3_native.rs`** — `can_send_early_data` used `saturating_add` and clamped past `u64::MAX`, silently returning `true` for over-budget 0-RTT sends. Fixed to `checked_add` + treat `None` as over-budget.

WebSocket protocol correctness:

- **`src/net/websocket/handshake.rs::selected_protocol`** — violated RFC 6455 §4.2.2 by iterating the server's list rather than the client's offered order (server is required to honor client preference). Also silently returned `None` instead of `ProtocolMismatch` when client offers did not match a non-empty supported set. Both fixed.

Observability correctness:

- **`src/observability/diagnostics.rs::find_leaked_obligations`** — flagged obligations held by Completed tasks as leaks, producing false positives (Completed holders tear their obligations down via the normal scope-exit path). Now skips Completed holders.
- **`src/observability/obligation_tracker.rs`** — `find_potential_leaks` / `summary()` used strict `>` on age, which made the documented "immediate leak detection" config (`leak_age_threshold = Duration::ZERO`) a no-op. Changed to `>=`.
- **`src/lab/oracle/channel_atomicity.rs`** — same `>` → `>=` contract fix for `max_reservation_age_seconds = 0` meaning "immediate leak detection".

Channel correctness:

- **`src/channel/atomicity_test.rs::CancellationInjector::should_cancel`** — bit-shift bug: `(state >> 16) as f64 / u32::MAX as f64` produced values up to 2^48, so `random < probability` was almost never true for any probability in (0, 1). Masked to u32 after shift; added fast-paths for probability ∈ {0, 1}.
- **`src/channel/broadcast.rs`** — ring-buffer overrun when a single sender burst exceeded capacity. Interleaved drain with send so the fast receiver never falls behind the retention window.

Combinator correctness:

- **`src/combinator/bulkhead.rs`** — utilization boundary off-by-one: metric said "at 80% or above" but assertion used strict `>`. Changed to `>=` (8/10 is exactly representable in f64 and should match).

Cancel / progress-certificate correctness:

- **`src/cancel/progress_certificate.rs`** — `EvidenceEntry.bound` field is contractually a probability (docstring: "upper tail probability") but production was writing raw step magnitudes and run-lengths into it. Downstream verifiers that compared `.bound > 0.05` were generating false "bound not tight" alerts. Fixed all seven construction sites to emit probabilities; moved the metric data to the `.description` string.

RaptorQ correctness:

- **`src/raptorq/systematic.rs::rfc_repair_equation`** — `checked_add(padding_delta).expect(...)` panicked at the `u32::MAX` ESI boundary. RFC 6330 tuple derivation requires deterministic wrapping. Fixed to `wrapping_add`.
- **`src/raptorq/linalg.rs`** — Gaussian solvers preferentially reported `Inconsistent` when both `Singular` and `Inconsistent` conditions were present, obscuring the correct failure classification. Restricted the inconsistency scan to the single pivot-aligned row via a new `first_inconsistent_row_at` helper; downstream contradictions now surface only after full forward elimination.
- **`src/raptorq/decoder.rs::inactivate_and_solve_with_proof`** — recorded inactivations into the elimination trace AFTER fallible validation, so fail-closed paths left the proof trace empty even though the decoder had attempted inactivations. Split intent from commit: trace records unconditionally, state mutations are deferred until validation succeeds.

Plus miscellaneous prod fixes to `obligation::saga::compensation`, `lab::oracle::*` counts/threshold contracts, an `fs::uring` unused-import that was tripping `deny(unused_imports)`, and a `three_lane.rs` missing `let mut`.

### Test-harness hygiene

Most of the 110 originally-failing tests were test drift rather than production bugs — stale golden values, snapshot rotations, API signature drift, ratio/threshold constants that grew past old hardcoded expectations:

- **`tests/metamorphic_region_close_ordering.rs`** — fixed `cancel_order` semantic gap (tests didn't actually trigger cancel).
- **`src/sync/mutex_metamorphic.rs::mr2_cancel_non_poisoning`** — `drop(try_result)` before async relock so the guard doesn't hold the mutex across `block_on`.
- **`src/sync/barrier_metamorphic.rs::execute_barrier_scenario`** — `LabConfig::with_auto_advance()` + `run_with_auto_advance()` so virtual time advances through sleeps.
- Multiple `lab::oracle::*` tests — oracle count constants 17 → 24 as new oracles landed; `fail_fast_mode` return-type handling; seed-agnostic scenarios switched to real seeds.
- **`src/raptorq/rfc6330.rs`** — regenerated `GOLDEN_TUPLE_VECTORS` against a Python reference implementing RFC 6330 §5.3.5 byte-for-byte (the previous constants predated an RFC conformance fix in the production implementation).
- **`src/raptorq/metamorphic_tests.rs`** — switched default test fixture to `symbol_size = 16` with `repair_overhead = 4.0` so fixtures stay within the RFC 6330 K' ≥ 10 requirement.
- **`src/http/h2/frame_golden_tests.rs`** — five hex-literal typos in golden values (extra `f`, raw ASCII vs hex, stray `00` bytes, dropped digit).
- **`src/codec/tests/mod.rs`** — aligned test expectations with actual `BytesCodec` (empty decode returns `None`) and `LinesCodec` (strict `\n` delimiter; UTF-8 validated post-terminator) semantics.
- Various **insta snapshot regenerations** across diagnostics v3 schema, cli/doctor reports, decode-proof certificate, etc. — post-refactor cleanup.

### Known remaining failures

~85 tests in `runtime::scheduler`, `plan::fixtures`, `service::retry`, `supervision`, and misc modules continue to fail. These are tracked for a follow-up release; none block library consumers that don't touch those specific surfaces.

### Verification

- `cargo check --workspace --all-targets` on ts2 via rch: clean (exit 0, ~52s).
- `cargo test --workspace --lib`: **14,257 pass, 86 fail, 0 SIGABRT** (was 9,350 pass + 110 fail + abort in v0.3.0).

---

## [v0.3.0](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.3.0) -- 2026-04-21 (Release)

> 2500+ commits since v0.2.9 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.9...v0.3.0)

### Release theme

`v0.3.0` is the first release cut after a six-week high-throughput
multi-agent work sweep that landed hundreds of metamorphic relations,
golden snapshots, fuzz targets, and conformance fixtures across the
runtime, scheduler, obligation ledger, gRPC/HTTP/DNS stacks, RaptorQ,
FABRIC, and the observability surface. This bundles those additions
with a coordinated dependency refresh and a large compile-and-test
hygiene pass.

### Dependency refresh

Coordinated minor-version bumps against latest crates.io and nightly
1.97.0 (`66da6cae1`, 2026-04-20):

- **digest-0.11 wave:** `sha1` 0.10→0.11, `sha2` 0.10→0.11,
  `hmac` 0.12→0.13 — landed together because they all depend on
  `digest` 0.11.
- `hashbrown` 0.15 → 0.17 (skipped 0.16; MSRV 1.85).
- `rusqlite` 0.38 → 0.39 (bundled SQLite now 3.51.3).
- `lz4_flex` 0.12 → 0.13 across normal-deps and dev-deps.
- `signal-hook` 0.3 → 0.4 (non-wasm only).
- `rayon` 1.11 → 1.12 dev-dep.
- Relaxed `io-uring = "0.7.11"` pin to `"0.7"` so future patch
  bumps land automatically via `cargo update`.
- Additionally, `cargo update` refreshed a wide swath of semver-
  compatible patch versions across the dependency graph
  (clap/hyper/rustls/tokio-in-compat-shim/toml/tokio-macros/
  wasm-bindgen/web-sys/webpki-roots/zerocopy and several others).

Deferred:

- `prost` 0.13 → 0.14 — requires coordinated tonic 0.14 migration
  with the new `tonic-prost` + `tonic-prost-build` crate split and
  `Message` trait signature changes. Tracked for a follow-up.
- `time` 0.3.47 — actively blocked by an intentional pin
  (`>=0.3, <0.3.47`) in root `Cargo.toml`; not touching.

### Coordinated callsite updates

Required by the digest-0.11 wave and the sha2-0.11 `Array<u8, _>`
migration:

- Added `use hmac::KeyInit;` at three call sites
  (`src/cx/macaroon.rs`, `src/security/key.rs`, `src/security/tag.rs`)
  because `Hmac::new_from_slice` was moved to the `KeyInit` trait.
- `sha2::Sha256::finalize()` now returns `Array<u8, _>` (from
  hybrid-array) instead of `GenericArray<u8, _>`; the new type no
  longer impls `LowerHex`, so `format!("{digest:x}")` stops
  compiling. Replaced at three callsites
  (`tests/wasm_supply_chain_controls.rs::sha256_hex`,
  `tests/replay_e2e_suite.rs::trace_hash_hex`,
  `tests/conformance/raptorq_differential/src/fixture_loader.rs::calculate_hash`)
  with a manual `write!(&mut out, "{byte:02x}", ..)` loop so hex
  output is byte-identical to the prior `LowerHex` formatting.

### Concurrency bugs fixed as part of the test-gate

Three real production concurrency bugs were uncovered while getting
the test suite to green and are included in this release:

- **`src/observability/runtime_integration.rs`** —
  parking_lot RwLock self-deadlock. `on_task_cancel_completed` and
  `on_region_closed` used
  `if let Some(trace_id) = self.task_traces.write().remove(&id) { ... self.task_traces.read() ... }`;
  the `RwLockWriteGuard`'s lifetime was extended to the end of the
  `if let` block, where the subsequent `.read()` tried to re-acquire
  the same non-reentrant lock and deadlocked forever. Fixed by
  extracting the `write().remove(...)` result into a binding so the
  write guard drops at the end of that statement.
- **`src/service/discover.rs`** — DNS coalesce observability gap.
  The `Condvar`-based coalesce path (where followers park on a
  leader's inflight resolver instead of issuing duplicate requests)
  had no deterministic way for tests to confirm a follower had
  actually parked before the leader was released. Added
  `waiters: AtomicUsize` + `pub fn waiter_count()` to
  `DnsServiceDiscovery`; the five related tests now spin on
  `waiter_count()` until the follower is demonstrably parked, then
  release the leader. No scheduling behavior change on the coalesce
  contract itself.
- **`src/runtime/scheduler/three_lane.rs`** — one-line fix: inner
  `new_with_options` test at line 6526 needed `let mut scheduler`
  for the subsequent `take_workers()` call, which requires
  `&mut self`.

### Test-harness hygiene

- Refactored the three-lane scheduler test harnesses
  (`StarvationTestHarness`, `BudgetTestHarness`,
  `PromotionTestHarness`) to cache
  `workers: Vec<ThreeLaneWorker>` once in `new()` rather than
  calling the one-shot `take_workers()` per simulation pass. This
  also fixes a latent runtime bug in
  `mr_starvation_recovery_consistency` whose phase2 was silently
  dispatching zero tasks against an empty worker vector.
- `metamorphic_region_close_ordering::test_cancel_cascade_ordering`
  actually triggers cancellation now (via
  `state.cancel_request(root_region, &CancelReason::user("cascade"), None)`)
  and spawned tasks record their region_id into `cancel_order` on
  first-observed `Cx::is_cancel_requested()`. The test caller
  asserts membership and uniqueness on the recorded order.
- `mutex_metamorphic::mr2_cancel_non_poisoning` added the missing
  `drop(try_result)` before the subsequent `block_on(mutex.lock(..))`
  so the surviving guard doesn't keep the lock held across the
  async relock.
- `barrier_metamorphic::mr2_spurious_wakeup_preservation_property`
  switched its `execute_barrier_scenario` to
  `LabConfig::new(seed).with_auto_advance()` +
  `run_with_auto_advance()` so virtual time actually moves through
  sleeps.
- Ten-plus tests across the `golden_*` and `metamorphic_*` suites
  re-aligned with current API signatures (`inject_ready` /
  `inject_cancel` / `inject_timed` on `ThreeLaneScheduler`,
  `saturating_add_nanos` on `Time`, `create_task` /
  `cancel_request` / `create_child_region` on `RuntimeState`,
  `for_testing()` on `Cx`, `NavigationTopology` and
  `DoctorScenarioCoveragePackSmokeReport` field-set changes,
  `Output` vs `OutputWriter` rename in `src/cli/output`, etc.).
- `metamorphic_three_lane_fairness::metamorphic_adaptive_streak_convergence`
  is marked `#[ignore]`d with a reason: `LabScheduler` doesn't
  expose the EXP3 adaptive streak policy that only lives on the
  raw `ThreeLaneScheduler`.

### Scope of additions

This window landed (non-exhaustive, mined from commit history):

- Dozens of metamorphic relations across mpsc, mutex, rwlock,
  barrier, notify, Once, intrusive-heap, saga, obligation ledger,
  three-lane scheduler, transport aggregator, pool, region
  close/cascade, semaphore, race-loser drain, and io-driver.
- Dozens of golden snapshots covering CLI output formats,
  diagnostics forensic dump, doctor health report bundle,
  conformance manifest YAML, distributed snapshot, gRPC health
  responses, PostgreSQL query execution log, raptorq decode
  certificates, scheduler state dump, three-lane scheduler state,
  transport aggregator report format, web router dump, etc.
- Fuzz targets including DNS lookup/message decoder, HPACK
  decoder/round-trip, HTTP/1 and HTTP/2 pipelines, QUIC core
  protocol, TLS message parsing, Redis RESP, PostgreSQL wire
  protocol, Kafka wire protocol, RaptorQ codec frame splitter /
  symbol set / matrix ops / decoder state machine, websocket
  frames, channel state machine, and more.
- Conformance matrix expansion (manifest schema, doctor scenario
  coverage packs, stress/soak report format).
- Runtime and scheduler hardening (FIFO, reactor, epoch tracking,
  state correctness, cancel attribution, obligation replay
  identity).

### Verification

- `cargo check --workspace --all-targets` on ts2 via rch: green.
- Full `cargo test --workspace` — see release notes on the GitHub
  Release page for the complete pass summary; a handful of
  previously-hanging tests in `blocking_pool`, `observability`,
  `service::discover`, `mutex_metamorphic`, and
  `barrier_metamorphic` all pass now after the root-cause fixes
  listed above.

### Upgrade notes

Consumers on `0.2.x` crossing to `0.3.0` should expect the
coordinated hash/HMAC dependency wave (sha2 0.11 / hmac 0.13) to
require the `KeyInit` import fix at any callsite that used
`Hmac::new_from_slice`, and the `format!("{digest:x}")` → manual
hex-encode fix at any callsite that formatted a raw `finalize()`
output with the lowercase-hex formatter.

---

## [v0.2.9](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.9) -- 2026-03-21 (Release)

> 461 commits since v0.2.8 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.8...v0.2.9)

### Breaking changes

- **`ObjectParams.source_blocks` widened from `u8` to `u16`** ([`f7ae111f`](https://github.com/Dicklesworthstone/asupersync/commit/f7ae111f), [#30](https://github.com/Dicklesworthstone/asupersync/issues/30)). `u8` capped source blocks at 255; the protocol needs up to 256. The change applies to both the public field and the `ObjectParams::new(...)` constructor parameter. A sibling widening of `EncodingConfig::max_source_blocks` from `u8` to `u16` landed the same day in [`37f5b1b2`](https://github.com/Dicklesworthstone/asupersync/commit/37f5b1b2). Downstream consumers using caret constraints on `0.2.x` must update call sites to pass `u16`. Retroactively documented — this was the kind of source-breaking change that should have shipped in `0.3.0`; going forward, public signature width changes get a minor version bump.

### FABRIC Messaging Engine

The largest area of post-v0.2.8 development: a brokerless subject-oriented messaging system with session typing, obligation-backed delivery, and evidence-native decision planes.

- **Session projection engine** with duality verification for two-party protocols ([`3614ffd`](https://github.com/Dicklesworthstone/asupersync/commit/3614ffdb))
- **Semantic execution lane planner** for SubjectCell conversation families ([`85cebd4`](https://github.com/Dicklesworthstone/asupersync/commit/85cebd4f))
- **Deterministic protocol-scaffolding synthesis** for FABRIC sessions ([`0ff5530`](https://github.com/Dicklesworthstone/asupersync/commit/0ff55307))
- **SafetyEnvelope** for adaptive reliability tuning with runtime health evaluator ([`daf9c57`](https://github.com/Dicklesworthstone/asupersync/commit/daf9c572))
- **Fabric discovery sessions**, operator intent compiler, recoverable service capsules, IR monotone normalization ([`8fe3bb2`](https://github.com/Dicklesworthstone/asupersync/commit/8fe3bb25))
- **Full FABRIC IR compilation** with artifact registry, service/morphism/protocol/consumer compilation ([`670d072`](https://github.com/Dicklesworthstone/asupersync/commit/670d0723))
- **Adaptive consumer kernel** with overflow policy, decision audit, and pinned-client delivery ([`9f1d79b`](https://github.com/Dicklesworthstone/asupersync/commit/9f1d79b0))
- **Delta-CRDT metadata layer** for non-authoritative control surfaces ([`2d4561a`](https://github.com/Dicklesworthstone/asupersync/commit/2d4561af))
- **Bounded control-plane artifacts** for brokerless subject fabric ([`31d828e`](https://github.com/Dicklesworthstone/asupersync/commit/31d828e7))
- **Evidence-native data-plane decisions** and operator explain-plan expansion ([`920b531`](https://github.com/Dicklesworthstone/asupersync/commit/920b5315))
- **Delegated cursor partitions**, federation bridge runtime, multi-tenant namespace kernel ([`b69c261`](https://github.com/Dicklesworthstone/asupersync/commit/b69c2613))
- Certificate-carrying request/reply protocol with chunked reply obligations ([`a0cd1ad`](https://github.com/Dicklesworthstone/asupersync/commit/a0cd1ad6))
- Branch-addressable reality framework for cut-certified mobility ([`45859b0`](https://github.com/Dicklesworthstone/asupersync/commit/45859b00))
- Privacy-preserving metadata export with blinding and differential-privacy noise ([`c5878b6`](https://github.com/Dicklesworthstone/asupersync/commit/c5878b63))
- Obligation-backed consumer delivery with redelivery, dead-letter, and stats ([`b93be30`](https://github.com/Dicklesworthstone/asupersync/commit/b93be307))
- Shared fabric state registry with HMAC-SHA256 cell key hierarchy ([`2112b1f`](https://github.com/Dicklesworthstone/asupersync/commit/2112b1f6))
- Saga/Workflow obligation types re-exported from service module ([`017ba9e`](https://github.com/Dicklesworthstone/asupersync/commit/017ba9ef))
- Repair symbol binding, rebalance cut certification, cell epoch rebind ([`566728a`](https://github.com/Dicklesworthstone/asupersync/commit/566728a5))
- Semantic degradation policy for FABRIC lane overload decisions ([`393698e`](https://github.com/Dicklesworthstone/asupersync/commit/393698e1))
- Consistency topology and admission surface for FABRIC explain-plan ([`81f77c6`](https://github.com/Dicklesworthstone/asupersync/commit/81f77c6b))
- FABRIC control plane with system subjects and FrankenSuite advisories ([`848be23`](https://github.com/Dicklesworthstone/asupersync/commit/848be230))
- FABRIC compiler, explain-plan, IR cost model, and ShardedSublist ([`3b2ef97`](https://github.com/Dicklesworthstone/asupersync/commit/3b2ef972))
- Deterministic incident rehearsal framework for cut-certified mobility ([`68df80a`](https://github.com/Dicklesworthstone/asupersync/commit/68df80af))
- SublistLinkCache for per-link subject resolution hot cache ([`c3a3aaa`](https://github.com/Dicklesworthstone/asupersync/commit/c3a3aaa1))
- Quantitative obligation contracts (SLO-style) ([`e9b1c22`](https://github.com/Dicklesworthstone/asupersync/commit/e9b1c22f))
- EvidenceRecord advisory, typed filter, and evidence_id tracing ([`47d7f10`](https://github.com/Dicklesworthstone/asupersync/commit/47d7f10b))

### Transport and Networking

- **Rollback record**, dedup drain, and expiry-driven eviction in symbol aggregator ([`297cc5c`](https://github.com/Dicklesworthstone/asupersync/commit/297cc5c3))
- **Weight-aware select_n** for WeightedRoundRobin load balancing ([`3575ccf`](https://github.com/Dicklesworthstone/asupersync/commit/3575ccf8))
- Weighted round-robin select_n advances by 1 slot per selection, not by weight span ([`f76fcab`](https://github.com/Dicklesworthstone/asupersync/commit/f76fcab1))
- Weighted load balancer tracks active_backend_count, bounds-checks backend operations ([`2634deb`](https://github.com/Dicklesworthstone/asupersync/commit/2634deb5))
- Suppress spurious control traffic from cancel-ack and drain-request after shutdown ([`54bcaba`](https://github.com/Dicklesworthstone/asupersync/commit/54bcaba2))
- Prune_expired now includes default route TTL enforcement ([`a9fe79a`](https://github.com/Dicklesworthstone/asupersync/commit/a9fe79ae))
- Replace single-slot pending_symbol with FIFO staged queue in BufferedSink ([`1eedab5`](https://github.com/Dicklesworthstone/asupersync/commit/1eedab5f))

### Lab and Differential Testing

- **Differential artifact schemas** for retained divergence bundles ([`c372def`](https://github.com/Dicklesworthstone/asupersync/commit/c372deff))
- **Fuzz-to-scenario promotion** for differential regressions ([`5e583c6`](https://github.com/Dicklesworthstone/asupersync/commit/5e583c6e))
- **Evidence normalization** for lab-vs-live comparison ([`d865974`](https://github.com/Dicklesworthstone/asupersync/commit/d8659745))
- CaptureManifest field provenance and LiveWitnessCollector manifest tracking ([`e912340`](https://github.com/Dicklesworthstone/asupersync/commit/e9123408))
- Expand dual-run observable comparison to cover all semantic fields ([`a6c4b90`](https://github.com/Dicklesworthstone/asupersync/commit/a6c4b907))
- Divergence classification pipeline, fuzz-to-dual-run promotion, and divergence corpus registry ([`8e8f4a8`](https://github.com/Dicklesworthstone/asupersync/commit/8e8f4a83))
- Expand differential runner with 3 new scenarios, optional final policy ([`934a034`](https://github.com/Dicklesworthstone/asupersync/commit/934a034a))
- Validate obligation region ownership in snapshot restore ([`0e5de5a`](https://github.com/Dicklesworthstone/asupersync/commit/0e5de5a8))

### WASM and Browser

- **Browser runtime selection**, scope selection, and lane-health demotion/recovery coverage ([`2409c4b`](https://github.com/Dicklesworthstone/asupersync/commit/2409c4bc))
- **Lane-health retry window** coverage proving bounded retry budget before demotion ([`bdc84b7`](https://github.com/Dicklesworthstone/asupersync/commit/bdc84b74))
- Dedicated-worker matrix and execution-ladder diagnostics ([`7fb0c49`](https://github.com/Dicklesworthstone/asupersync/commit/7fb0c490))
- Shared-worker coordinator scaffolding with bounded attach, version handshake ([`f97de80`](https://github.com/Dicklesworthstone/asupersync/commit/f97de80a))
- Prerequisite-loss simulation in dedicated worker consumer test fixture ([`19f1250`](https://github.com/Dicklesworthstone/asupersync/commit/19f12505))
- Bounded service-worker broker API surface ([`45f8ff1`](https://github.com/Dicklesworthstone/asupersync/commit/45f8ff1a))

### Filesystem and I/O

- **BufReader::capacity()** accessor and safety doc comments for get_mut/into_inner ([`44459fe`](https://github.com/Dicklesworthstone/asupersync/commit/44459fe1))
- Correct 0o777 mode for io-uring create_dir, preserve file permissions in write_atomic ([`510fe8e`](https://github.com/Dicklesworthstone/asupersync/commit/510fe8e8))
- copy_buf tracks read_done state to flush correctly after EOF ([`1277755`](https://github.com/Dicklesworthstone/asupersync/commit/12777557))
- Peekable::size_hint returns (0, Some(0)) after cached exhaustion ([`5443ae6`](https://github.com/Dicklesworthstone/asupersync/commit/5443ae63))

### TLS and Security

- Fail closed on missing close_notify per RFC 8446 ([`602571e`](https://github.com/Dicklesworthstone/asupersync/commit/602571e8))
- Malformed grpc-timeout header fails closed instead of falling back to server default ([`e38a3b1`](https://github.com/Dicklesworthstone/asupersync/commit/e38a3b11))
- Improve certificate directory scanning robustness ([`8780cbc`](https://github.com/Dicklesworthstone/asupersync/commit/8780cbc6))

### Runtime and Concurrency Fixes

- Supervised restart leaves actor in Stopping state (deadlock) -- fixed ([`7812876`](https://github.com/Dicklesworthstone/asupersync/commit/78128769))
- Pending counter leak in Buffer when poll_ready errors ([`192c361`](https://github.com/Dicklesworthstone/asupersync/commit/192c361c))
- Buffer pending slot leak on panic in call() ([`1fad761`](https://github.com/Dicklesworthstone/asupersync/commit/1fad7614))
- Correct notify baton-passing when broadcast follows notify_one ([`fdc7a60`](https://github.com/Dicklesworthstone/asupersync/commit/fdc7a60e))
- Remove spurious baton passing when a notified waiter is dropped before poll ([`c10ca2a`](https://github.com/Dicklesworthstone/asupersync/commit/c10ca2aa))
- Adaptive hedge warmup threshold respects small configured windows ([`f11b4f0`](https://github.com/Dicklesworthstone/asupersync/commit/f11b4f01))
- Clock skew evidence for all skew types, prevent jitter zero-collapse at 1ns boundary ([`78fd305`](https://github.com/Dicklesworthstone/asupersync/commit/78fd3054))
- Enforce max_concurrent_streams for incoming remote-initiated H2 streams ([`0e27de0`](https://github.com/Dicklesworthstone/asupersync/commit/0e27de09))
- Preserve handler Content-Length in HEAD response per RFC 9110 ([`c10f4f9`](https://github.com/Dicklesworthstone/asupersync/commit/c10f4f9d))
- JoinHandle::is_finished detects dropped executor side ([`4ac0e5a`](https://github.com/Dicklesworthstone/asupersync/commit/4ac0e5a7))
- Process: close piped stdin before wait to prevent child deadlock ([`af8541e`](https://github.com/Dicklesworthstone/asupersync/commit/af8541e5))
- Kill_on_drop background reaping prevents zombie processes ([`81be156`](https://github.com/Dicklesworthstone/asupersync/commit/81be156d))
- Saga Drop panicking guard + circuit breaker Acquire ordering ([`79d25ca`](https://github.com/Dicklesworthstone/asupersync/commit/79d25caf))
- Server trigger_immediate runs pre-phase hook before advancing to ForceClosing ([`d0079ee`](https://github.com/Dicklesworthstone/asupersync/commit/d0079eeb))

### RaptorQ Erasure Coding

- Profile-pack v5 schema with decision_evidence_status tracking ([`69916e1`](https://github.com/Dicklesworthstone/asupersync/commit/69916e19))
- Conservative tie-breaker in decision contract, DRY test fixtures in gf256 ([`26beb1b`](https://github.com/Dicklesworthstone/asupersync/commit/26beb1ba))
- E2E script validates decision-metadata and override truthfulness ([`5379f3f`](https://github.com/Dicklesworthstone/asupersync/commit/5379f3f4))
- c==1 addmul fast path and SIMD threshold fix ([`2e4e327`](https://github.com/Dicklesworthstone/asupersync/commit/2e4e3272))
- SparseRow bounds check before zero fast-path ([`62bb40c`](https://github.com/Dicklesworthstone/asupersync/commit/62bb40c2))
- Stricter test log schema validation catches whitespace-only fields ([`ed80616`](https://github.com/Dicklesworthstone/asupersync/commit/ed806169))

### Comprehensive Audit Campaign

- ~130,000 lines audited across batches 391--415, all SOUND
- Representative batch: batch 415 covering service/concurrency_limit + timeout + rate_limit ([`b0c7aa3`](https://github.com/Dicklesworthstone/asupersync/commit/b0c7aa3b))
- Machine-searchable audit history expanded with 576 entries across 472 files ([`04b9d2a`](https://github.com/Dicklesworthstone/asupersync/commit/04b9d2af))

---

## [v0.2.8](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.8) -- 2026-03-15 (Release)

> 958 commits since v0.2.7 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.7...v0.2.8)

The largest release to date: 410+ bug fixes, 222 features, and audit coverage across 500+ files.

### Runtime Correctness and Safety

- **Fail-closed completion guards** added to all Future implementations (streams, I/O, sync, service) -- prevents silent misuse when polling after terminal state ([`a9e737d`](https://github.com/Dicklesworthstone/asupersync/commit/a9e737d8), [`c917822`](https://github.com/Dicklesworthstone/asupersync/commit/c917822d), [`c9069cc`](https://github.com/Dicklesworthstone/asupersync/commit/c9069cc2))
- **ThreeLaneLocalWaker** default_priority prevents priority inversion for cancelled local tasks ([`12d261d`](https://github.com/Dicklesworthstone/asupersync/commit/12d261db))
- **Actual cancel masking** in commit_section ([`85b1ac0`](https://github.com/Dicklesworthstone/asupersync/commit/85b1ac07))
- Deterministic waker drain, early lock drops, keepalive builder, mask optimization ([`0f0fe0a`](https://github.com/Dicklesworthstone/asupersync/commit/0f0fe0a6))
- Stale-entry skipping extended to all scheduler pop methods ([`ac4d2e9`](https://github.com/Dicklesworthstone/asupersync/commit/ac4d2e96))
- Task completion coerced to Cancelled when cancel is in-flight ([`bebe6b9`](https://github.com/Dicklesworthstone/asupersync/commit/bebe6b9b))
- Double-panic guards on all Drop-based leak detectors ([`44708b1`](https://github.com/Dicklesworthstone/asupersync/commit/44708b12))
- yield_now panics on repoll; timeout reset unconditional ([`596f351`](https://github.com/Dicklesworthstone/asupersync/commit/596f3518))
- Soften repoll guards from panic to error return across time, runtime, net ([`4a40627`](https://github.com/Dicklesworthstone/asupersync/commit/4a40627a))
- Join semantics with proper close handling ([`34fbc58`](https://github.com/Dicklesworthstone/asupersync/commit/34fbc581))

### Service Layer

- **Discover-driven topology updates** in LoadBalancer ([`765f9f3`](https://github.com/Dicklesworthstone/asupersync/commit/765f9f34))
- **Weighted strategy** polish with PolledAfterCompletion on LoadShed ([`fdca8d9`](https://github.com/Dicklesworthstone/asupersync/commit/fdca8d97))
- Unified NotReady error variant across all service middlewares ([`fbf95a7`](https://github.com/Dicklesworthstone/asupersync/commit/fbf95a7f))
- Readiness contracts and expanded filter, hedge, and timeout coverage ([`2e97eee`](https://github.com/Dicklesworthstone/asupersync/commit/2e97eeea))
- Buffer NotReady enforcement, OneshotError wrapper, LoadBalancer sync_backend_count ([`1d0505b`](https://github.com/Dicklesworthstone/asupersync/commit/1d0505b3))
- Correct readiness tracking in Filter/Reconnect, add RetryError wrapper ([`32cb86a`](https://github.com/Dicklesworthstone/asupersync/commit/32cb86a5))
- Stale DNS resolution prevented from clobbering newer state ([`1cb7314`](https://github.com/Dicklesworthstone/asupersync/commit/1cb73149))

### HTTP and Protocol Compliance

- **RFC 9110** identity encoding negotiation and HEAD response handling ([`662b127`](https://github.com/Dicklesworthstone/asupersync/commit/662b1271))
- **RFC 7540** reserved streams counted toward max_concurrent_streams ([`02bb14b`](https://github.com/Dicklesworthstone/asupersync/commit/02bb14bb))
- H2-reserved H3 settings rejected ([`518b400`](https://github.com/Dicklesworthstone/asupersync/commit/518b4008))
- Stateful streaming decompression, quality validation, and Expect: 100-continue refactoring ([`65b6677`](https://github.com/Dicklesworthstone/asupersync/commit/65b66771))
- CRLF injection sanitization in response headers, redirect Location, gRPC-web trailers ([`c178930`](https://github.com/Dicklesworthstone/asupersync/commit/c1789300), [`bdfc321`](https://github.com/Dicklesworthstone/asupersync/commit/bdfc3213), [`931150f`](https://github.com/Dicklesworthstone/asupersync/commit/931150f2))
- Tri-state Limited body distinguishes clean EOF from failure ([`2ed0aab`](https://github.com/Dicklesworthstone/asupersync/commit/2ed0aab4))
- Reference-count HealthReporters to prevent premature status clear ([`b96d51c`](https://github.com/Dicklesworthstone/asupersync/commit/b96d51c4))
- SSE: reject null bytes in last_event_id per SSE spec ([`6ae5703`](https://github.com/Dicklesworthstone/asupersync/commit/6ae57034))

### WASM and Browser

- **Real MessagePort and BroadcastChannel** bindings for browser reactor ([`c29a4c9`](https://github.com/Dicklesworthstone/asupersync/commit/c29a4c9b))
- **StreamAccounting** for BrowserReadable/WritableStream ([`119f217`](https://github.com/Dicklesworthstone/asupersync/commit/119f2174))
- Non-clobbering addEventListener-based message and error listeners ([`41ff324`](https://github.com/Dicklesworthstone/asupersync/commit/41ff3240))
- Service-worker broker descriptor and handoff parser validation ([`ddcfad6`](https://github.com/Dicklesworthstone/asupersync/commit/ddcfad65))

### Distributed and CRDT

- **Multi-block encoding** with per-block repair distribution ([`39f38b4`](https://github.com/Dicklesworthstone/asupersync/commit/39f38b45))
- **Quorum-aware recovery** completion and replica mutation guards ([`6985c9c`](https://github.com/Dicklesworthstone/asupersync/commit/6985c9c6))
- Close idempotent, reconcile replica loss across all degraded states ([`ad46fb2`](https://github.com/Dicklesworthstone/asupersync/commit/ad46fb27))
- ORSet tombstone tracking prevents removed values from reappearing on merge ([`7516adf`](https://github.com/Dicklesworthstone/asupersync/commit/7516adf7))
- GCounter saturating add, PNCounter widened to i128, checked ORSet seq ([`0673257`](https://github.com/Dicklesworthstone/asupersync/commit/0673257e))
- Reject trailing bytes in snapshot deserialization ([`99640c5`](https://github.com/Dicklesworthstone/asupersync/commit/99640c56))

### Sync Primitives

- OnceCell::set made non-blocking to prevent async deadlocks ([`a4985e7`](https://github.com/Dicklesworthstone/asupersync/commit/a4985e7f))
- Zero semaphore permits on close and handle pool close-while-create race ([`047c88a`](https://github.com/Dicklesworthstone/asupersync/commit/047c88a7))
- Lost notify_one baton when broadcast supersedes original waiter set ([`95c7de7`](https://github.com/Dicklesworthstone/asupersync/commit/95c7de7e))
- RwLock waiter state cleanup on cancellation and poison ([`3ae13c1`](https://github.com/Dicklesworthstone/asupersync/commit/3ae13c15))
- Atomic record_event replaces split next_seq/push_event to prevent sequence interleaving ([`da4facc`](https://github.com/Dicklesworthstone/asupersync/commit/da4facc8))

### Observability and Lab

- **Sync reactor chaos statistics** into LabRuntime aggregated stats ([`da489aa`](https://github.com/Dicklesworthstone/asupersync/commit/da489aa7))
- **Deadlocked health classification** from explicit trapped wait-cycle evidence ([`bd4b6b1`](https://github.com/Dicklesworthstone/asupersync/commit/bd4b6b1a))
- Task inspector falls back to logical state clock ([`d3c7744`](https://github.com/Dicklesworthstone/asupersync/commit/d3c7744d))
- Timer wheel synchronization to current clock before register/update/query paths ([`16eba13`](https://github.com/Dicklesworthstone/asupersync/commit/16eba13a))
- Trace writer drop flush ([`c6c8114`](https://github.com/Dicklesworthstone/asupersync/commit/c6c81145))
- Evict oldest incomplete traces when complete-trace eviction is insufficient ([`22aa925`](https://github.com/Dicklesworthstone/asupersync/commit/22aa925a))

### Database

- Cancel-aware result set draining and overflow-safe packet reads ([`f5e188d`](https://github.com/Dicklesworthstone/asupersync/commit/f5e188d1))
- DbPool mutex locks survive poisoned state ([`ba43ecc`](https://github.com/Dicklesworthstone/asupersync/commit/ba43ecc4))
- Return_connection reports whether connection was requeued ([`83f31ac`](https://github.com/Dicklesworthstone/asupersync/commit/83f31ac5))
- MySQL IPv6/timeout, QPACK static table and header validation ([`467831d`](https://github.com/Dicklesworthstone/asupersync/commit/467831d6))

### Audit Campaign

- **Over 500 files audited**, all SOUND, across batches 199--379
- 65,307 lines in batches 199--208 alone; 0 bugs remaining after fixes
- Audit coverage includes all major subsystems: runtime, scheduler, channels, net, HTTP, service, distributed, messaging

### Drop_unwrap_finder Utility

- New static analysis utility for finding potential unwrap panics in Drop impls ([`0c45351`](https://github.com/Dicklesworthstone/asupersync/commit/0c453514))

---

## [v0.2.7](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.7) -- 2026-03-03 (Tag)

> 412 commits since v0.2.6 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.6...v0.2.7)

### Web Framework

- **Session middleware** with pluggable backends ([`ff2c55b`](https://github.com/Dicklesworthstone/asupersync/commit/ff2c55be))
- **Static file serving** with ETag and caching ([`d6d012b`](https://github.com/Dicklesworthstone/asupersync/commit/d6d012bb))
- **Multipart form data** parser and RFC 7578 extractor ([`60e6c83`](https://github.com/Dicklesworthstone/asupersync/commit/60e6c83f), [`96292ef`](https://github.com/Dicklesworthstone/asupersync/commit/96292eff))
- **Health check endpoints** for Kubernetes-style probes ([`543587f`](https://github.com/Dicklesworthstone/asupersync/commit/543587f2))
- **Server-Sent Events (SSE)** support ([`5600b25`](https://github.com/Dicklesworthstone/asupersync/commit/5600b25d))
- **Cookie and CookieJar** extractors with header parsing ([`1e54bea`](https://github.com/Dicklesworthstone/asupersync/commit/1e54bea0))
- **CORS middleware** with configurable origin/method/header policies ([`4d9f63f`](https://github.com/Dicklesworthstone/asupersync/commit/4d9f63fa))
- **SecurityHeadersMiddleware** with configurable security policy ([`38bec9c`](https://github.com/Dicklesworthstone/asupersync/commit/38bec9cf))
- **Gzip/deflate compressors** and response compression middleware ([`79f746b`](https://github.com/Dicklesworthstone/asupersync/commit/79f746bf))
- 8 production middleware types for stack parity ([`13912ba`](https://github.com/Dicklesworthstone/asupersync/commit/13912ba8))
- RequestTraceMiddleware for request timing and trace propagation ([`beb1b0b`](https://github.com/Dicklesworthstone/asupersync/commit/beb1b0be))
- Full WebSocket implementation with module doc comment ([`7f0e222`](https://github.com/Dicklesworthstone/asupersync/commit/7f0e222f))
- WebSocket HTTP upgrade extractor ([`aa04fbd`](https://github.com/Dicklesworthstone/asupersync/commit/aa04fbd4))
- Form body size limit and comprehensive extractor tests ([`591d4fd`](https://github.com/Dicklesworthstone/asupersync/commit/591d4fd0))
- Content negotiation module ([`e806de9`](https://github.com/Dicklesworthstone/asupersync/commit/e806de91))
- TypeId-keyed typed state extraction in Extensions ([`d6d202a`](https://github.com/Dicklesworthstone/asupersync/commit/d6d202a4))

### Stream Combinators

- **Scan, peekable, throttle, debounce** combinators ([`2f7be8c`](https://github.com/Dicklesworthstone/asupersync/commit/2f7be8c4))

### Redis

- **Transaction (MULTI/EXEC)** and PubSub APIs ([`fad7cbb`](https://github.com/Dicklesworthstone/asupersync/commit/fad7cbb3))
- Pub/Sub types, PUBLISH, WATCH/UNWATCH, MULTI/EXEC, and PING ([`0d1383b`](https://github.com/Dicklesworthstone/asupersync/commit/0d1383b6))

### gRPC

- **Server reflection service** with descriptor registry ([`23f6f20`](https://github.com/Dicklesworthstone/asupersync/commit/23f6f207))
- **Compression encoding negotiation** on gRPC channel ([`7aedbe2`](https://github.com/Dicklesworthstone/asupersync/commit/7aedbe20))

### Tokio Compatibility Layer

- **Safe blocking bridge** with Cx context propagation ([`72557fa`](https://github.com/Dicklesworthstone/asupersync/commit/72557fae))
- Real I/O trait bridging and functional hyper executor/timer ([`6813e18`](https://github.com/Dicklesworthstone/asupersync/commit/6813e18f))
- Tokio-compat scaffolding, interop ranking, and migration framework ([`e23469a`](https://github.com/Dicklesworthstone/asupersync/commit/e23469a7))
- Replace thread-based sleep with native timer wheel delegation ([`6a58861`](https://github.com/Dicklesworthstone/asupersync/commit/6a58861a))
- Cancel-aware polling in Tower bridge replacing with_tokio_context ([`89e7c3c`](https://github.com/Dicklesworthstone/asupersync/commit/89e7c3c7))

### Database

- **MySQL client hardened** with result limits, URL parsing, abandoned tx drain ([`1a13be2`](https://github.com/Dicklesworthstone/asupersync/commit/1a13be2d))
- **SQLite connection defaults** and runtime configuration ([`6d1e2e1`](https://github.com/Dicklesworthstone/asupersync/commit/6d1e2e19))
- **PostgreSQL** type-safe parameter encoding, extended query protocol, prepared statements ([`3e2ad4f`](https://github.com/Dicklesworthstone/asupersync/commit/3e2ad4f4))

### I/O and Networking

- **RFC 8305 Happy Eyeballs v2** concurrent connection racing ([`60a8023`](https://github.com/Dicklesworthstone/asupersync/commit/60a80230))
- **AsyncSeekExt** trait ([`30993b6`](https://github.com/Dicklesworthstone/asupersync/commit/30993b6e))
- **ReaderStream and StreamReader** bridge adapters ([`e37a9d4`](https://github.com/Dicklesworthstone/asupersync/commit/e37a9d45))
- **Async Command/Child** methods for cooperative polling ([`4376aab`](https://github.com/Dicklesworthstone/asupersync/commit/4376aab5))
- Typed integer read/write methods on AsyncReadExt/AsyncWriteExt ([`40a6866`](https://github.com/Dicklesworthstone/asupersync/commit/40a68661), [`7b4ecdd`](https://github.com/Dicklesworthstone/asupersync/commit/7b4ecdd2))
- **Write_atomic** for durable file replacement via temp+rename ([`dd0573a`](https://github.com/Dicklesworthstone/asupersync/commit/dd0573ab))
- LinesCodec decode_eof, discard-and-recover for oversized lines ([`75b96ff`](https://github.com/Dicklesworthstone/asupersync/commit/75b96ffb))

### QUIC/HTTP3

- Native feature surfaces, deprecate compat wrappers ([`06df9b5`](https://github.com/Dicklesworthstone/asupersync/commit/06df9b52))
- QPACK field-section decode helpers with pseudo-header validation ([`a70436e`](https://github.com/Dicklesworthstone/asupersync/commit/a70436e5))
- 0-RTT/resumption and path migration lifecycle ([`556290c`](https://github.com/Dicklesworthstone/asupersync/commit/556290c9))
- Packet send-state guard and congestion recovery epoch fix ([`be7d9fb`](https://github.com/Dicklesworthstone/asupersync/commit/be7d9fb7))

### Kafka

- Deterministic producer/consumer lifecycle ([`e7a9204`](https://github.com/Dicklesworthstone/asupersync/commit/e7a92040))
- Messaging module gated behind kafka feature ([`c4705b7`](https://github.com/Dicklesworthstone/asupersync/commit/c4705b71))
- NATS graceful flush before shutdown, max_payload enforcement ([`16c4a88`](https://github.com/Dicklesworthstone/asupersync/commit/16c4a88f), [`1527fe9`](https://github.com/Dicklesworthstone/asupersync/commit/1527fe9b))

### WASM Supply Chain

- Supply-chain artifact bundle: SBOM, provenance, integrity manifest ([`37c0037`](https://github.com/Dicklesworthstone/asupersync/commit/37c00370))
- Flake governance framework with policy and checker ([`a48a751`](https://github.com/Dicklesworthstone/asupersync/commit/a48a751a))
- ABI compatibility policy and harness ([`335c905`](https://github.com/Dicklesworthstone/asupersync/commit/335c9051))
- Bundler/runtime compatibility matrix and test suite ([`7d54656`](https://github.com/Dicklesworthstone/asupersync/commit/7d54656d))
- DX error taxonomy, diagnostic enrichment, and IntelliSense quality contract ([`9b3c72b`](https://github.com/Dicklesworthstone/asupersync/commit/9b3c72b0))

### Semantic and Formal Verification

- TLA+ abstraction boundaries and runtime correspondence ([`28f7ca2`](https://github.com/Dicklesworthstone/asupersync/commit/28f7ca22))
- SEM-11 complete: enablement FAQ, maintainer playbook, audit cadence, retrospective ([`b4c57fa`](https://github.com/Dicklesworthstone/asupersync/commit/b4c57fa7))
- SEM-10.5 CI signal-quality gate with flake rate and runtime budget enforcement ([`fef0af4`](https://github.com/Dicklesworthstone/asupersync/commit/fef0af48))
- Residual risk register with bounded exceptions and GO/NO-GO rules ([`0f8d10e`](https://github.com/Dicklesworthstone/asupersync/commit/0f8d10ef))
- Failure-replay cookbook with triage tree and rerun shortcuts ([`c6beffb`](https://github.com/Dicklesworthstone/asupersync/commit/c6beffb6))

### Sync and Channel Fixes

- RwLock pre-grant drop safety extended to OwnedWriteFuture with cascading wakeup ([`94cc4ca`](https://github.com/Dicklesworthstone/asupersync/commit/94cc4cac))
- Watch channel Receiver::changed waker leak ([`5af621b`](https://github.com/Dicklesworthstone/asupersync/commit/5af621b6))
- Waiter ID overflow prevention, RwLock FIFO fairness ([`124a2c3`](https://github.com/Dicklesworthstone/asupersync/commit/124a2c3d))
- Receiver close returns Disconnected when channel empty instead of Empty ([`616d0b6`](https://github.com/Dicklesworthstone/asupersync/commit/616d0b6f))
- Broadcast receiver_count increment inside lock to prevent subscribe race ([`e9314df`](https://github.com/Dicklesworthstone/asupersync/commit/e9314df5))
- RwLock wake blocked readers when last queued writer is dropped ([`605e413`](https://github.com/Dicklesworthstone/asupersync/commit/605e413f))

### Lean Formal Proofs

- No-ambient-authority capability exclusion theorems ([`bd726ce`](https://github.com/Dicklesworthstone/asupersync/commit/bd726ce1))
- Global no-obligation-leak theorems ([`b60f38c`](https://github.com/Dicklesworthstone/asupersync/commit/b60f38c6))
- SingleOwner invariant proof ([`070ef00`](https://github.com/Dicklesworthstone/asupersync/commit/070ef003))
- Cancel-request idempotence theorems ([`447fcd8`](https://github.com/Dicklesworthstone/asupersync/commit/447fcd85))

### Performance

- Fused dual-slice GF(256) SIMD mul/addmul for AVX2 and NEON ([`58b27f4`](https://github.com/Dicklesworthstone/asupersync/commit/58b27f43))
- Always use dual-add fast path for c==1 in gf256_addmul_slices2 ([`b5b37fc`](https://github.com/Dicklesworthstone/asupersync/commit/b5b37fc3))
- AsyncReadVectored for TCP and Unix stream split halves ([`b3e8768`](https://github.com/Dicklesworthstone/asupersync/commit/b3e8768e))

### Doctor CLI

- Performance budget matrix and instrumentation gates ([`f638c35`](https://github.com/Dicklesworthstone/asupersync/commit/f638c35d))
- Visual regression harness and golden fixture suite ([`8367006`](https://github.com/Dicklesworthstone/asupersync/commit/8367006f))
- Guided remediation preview/apply pipeline with staged approval checkpoints ([`184fa87`](https://github.com/Dicklesworthstone/asupersync/commit/184fa87c))
- Post-remediation verification loop with trust scorecards ([`6ae61e4`](https://github.com/Dicklesworthstone/asupersync/commit/6ae61e4d))

---

## [v0.2.6](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.6) -- 2026-02-22 (Tag)

> 260 commits since v0.2.5 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.5...v0.2.6)

### RaptorQ Erasure Coding

- **Wavefront decode pipeline** for bounded assembly+peeling ([`e613664`](https://github.com/Dicklesworthstone/asupersync/commit/e6136648))
- **F8 wavefront pipeline closed** -- all G3 blockers resolved ([`42e2b6f`](https://github.com/Dicklesworthstone/asupersync/commit/42e2b6f2))
- Per-lane floor threshold for dual-addmul auto policy ([`4cfaada`](https://github.com/Dicklesworthstone/asupersync/commit/4cfaadad))
- Arc-wrap dense factor cache artifacts, flatten signature memory layout ([`0c26349`](https://github.com/Dicklesworthstone/asupersync/commit/0c263497))
- Raise addmul floor to 12KiB and add XOR fast path for tiny slices ([`b37eed8`](https://github.com/Dicklesworthstone/asupersync/commit/b37eed89))
- Iterator-based propagation in peel_from_queue ([`8ee3c9c`](https://github.com/Dicklesworthstone/asupersync/commit/8ee3c9c5))
- Dense-column mapping with adaptive DenseColIndexMap ([`b607315`](https://github.com/Dicklesworthstone/asupersync/commit/b607315c))

### HTTP/2 and Security

- **CVE-2023-44487 Rapid Reset** mitigated with RST_STREAM rate limiting ([`b47a7a5`](https://github.com/Dicklesworthstone/asupersync/commit/b47a7a5f))
- Chunked trailer size limit check reordered to avoid premature rejection ([`8754e3d`](https://github.com/Dicklesworthstone/asupersync/commit/8754e3dc))

### Networking

- **TCP accept storm** detection with exponential backoff ([`b187985`](https://github.com/Dicklesworthstone/asupersync/commit/b187985c))
- Exponential backoff for transient accept errors and fallback IO rewakes ([`ab42cfa`](https://github.com/Dicklesworthstone/asupersync/commit/ab42cfad))
- Fallback accept backoff moved to background thread ([`f6e567b`](https://github.com/Dicklesworthstone/asupersync/commit/f6e567b1))
- Region close notification so scope awaits child completion ([`834172e`](https://github.com/Dicklesworthstone/asupersync/commit/834172e1))

### Sync Primitives

- Exception safety improved in barrier/notify primitives ([`de7d4bc`](https://github.com/Dicklesworthstone/asupersync/commit/de7d4bc1))
- RwLockWriteGuard Sync bound tightened to require T: Send + Sync ([`0e74544`](https://github.com/Dicklesworthstone/asupersync/commit/0e745445))
- Require &mut self for oneshot Receiver::recv ([`6a081e2`](https://github.com/Dicklesworthstone/asupersync/commit/6a081e25))
- BlockingOneshotReceiver waker cleared on drop to prevent stale wake ([`118e356`](https://github.com/Dicklesworthstone/asupersync/commit/118e3566))
- Saturating_duration_since in pool eviction to prevent panic ([`925628a`](https://github.com/Dicklesworthstone/asupersync/commit/925628a9))
- Active waiter count incremented when notify waker slot re-filled ([`c2a1ab6`](https://github.com/Dicklesworthstone/asupersync/commit/c2a1ab6d))
- Lost-wakeup chain resolved in mutex and rwlock drop paths ([`698c425`](https://github.com/Dicklesworthstone/asupersync/commit/698c425e))

### Runtime

- Try_lock I/O leader pattern replaced with atomic CAS polling ([`d5ba8a2`](https://github.com/Dicklesworthstone/asupersync/commit/d5ba8a26))
- Panic safety added to blocking pool, shutdown check before wait ([`2ed0ba7`](https://github.com/Dicklesworthstone/asupersync/commit/2ed0ba7a))
- WebSocket close handshake timeout ([`0b473bc`](https://github.com/Dicklesworthstone/asupersync/commit/0b473bc8))
- Finished thread handle reaping + pool timeout cleanup ([`1fba0f9`](https://github.com/Dicklesworthstone/asupersync/commit/1fba0f9c))

### Performance

- Cache max duration as u64 nanoseconds to avoid repeated u128-to-u64 conversions ([`611acf6`](https://github.com/Dicklesworthstone/asupersync/commit/611acf63))
- Compare_exchange in Parker park/unpark ([`e2caecc`](https://github.com/Dicklesworthstone/asupersync/commit/e2caecc3))
- Fast-path empty wheel + purge storage on last cancel ([`70bf97e`](https://github.com/Dicklesworthstone/asupersync/commit/70bf97e6))
- Single-pass reservoir sampling in random load balancer ([`9198d51`](https://github.com/Dicklesworthstone/asupersync/commit/9198d516))
- Fast-path work stealing when queue has no local tasks ([`8b0ee3e`](https://github.com/Dicklesworthstone/asupersync/commit/8b0ee3e7))
- Stack-pin futures in scope race/select patterns ([`9035b20`](https://github.com/Dicklesworthstone/asupersync/commit/9035b204))
- Bounded concurrent sends in distributed distribute() ([`b582ebd`](https://github.com/Dicklesworthstone/asupersync/commit/b582ebd0))
- Bitmap-scan next-deadline via next_occupied_circular() ([`7e2bc5f`](https://github.com/Dicklesworthstone/asupersync/commit/7e2bc5f8))
- Reduce mutex hold time in TcpListener::register_interest ([`c42e9af`](https://github.com/Dicklesworthstone/asupersync/commit/c42e9af9))
- Cap stealer skip-list to inline capacity + full-scan wheel levels ([`465d82f`](https://github.com/Dicklesworthstone/asupersync/commit/465d82f8))

### Oracle and Testing

- **Refinement firewall** and temporal oracle hydration ([`c7c4a21`](https://github.com/Dicklesworthstone/asupersync/commit/c7c4a21c))
- Deterministic fault injection and lab scenario testing ([`766c2fb`](https://github.com/Dicklesworthstone/asupersync/commit/766c2fb0))
- Cumulative event count tracking for ring buffer eviction detection ([`fbf82e6`](https://github.com/Dicklesworthstone/asupersync/commit/fbf82608))
- Edge-case tests for snapshot OOM and timer wraparound ([`025324e`](https://github.com/Dicklesworthstone/asupersync/commit/025324e7))

### QPACK/HTTP3

- QPACK field section encode/decode for static-only mode ([`abfe6ad`](https://github.com/Dicklesworthstone/asupersync/commit/abfe6ad8))
- QPACK wire validation and interop fixture corpus ([`12f3c10`](https://github.com/Dicklesworthstone/asupersync/commit/12f3c108))

### Database

- Synchronous rollback, OOM cap, wrapping IDs fixed ([`c433946`](https://github.com/Dicklesworthstone/asupersync/commit/c4339464))

---

## [v0.2.5](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.5) -- 2026-02-18 (Release)

> 13 commits since v0.2.4 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.4...v0.2.5)

Workspace crate versions aligned to 0.2.5 for crates.io publication with MIT + OpenAI/Anthropic rider license metadata.

- **Deterministic artifact manifests** with replay verification and jq-based contract validation ([`b0c0fd1`](https://github.com/Dicklesworthstone/asupersync/commit/b0c0fd1c))
- **Coverage ratchet**, no-mock waiver expiry, and Track-D CI gates ([`19cfb06`](https://github.com/Dicklesworthstone/asupersync/commit/19cfb068))
- Preserve custom WebSocket close codes, persist load-shed state, tighten HTTP/1 parsing ([`21fb7c8`](https://github.com/Dicklesworthstone/asupersync/commit/21fb7c80))
- Tighten cast failure semantics and cancellation cleanup invariants ([`c5b1d75`](https://github.com/Dicklesworthstone/asupersync/commit/c5b1d758))
- Dense-factor reuse cache and broader decode stress benchmarks ([`c90f59f`](https://github.com/Dicklesworthstone/asupersync/commit/c90f59f6))
- Use BTreeMap for expected_loss_by_action payloads (publish fix) ([`0c8fd60`](https://github.com/Dicklesworthstone/asupersync/commit/0c8fd602))

---

## [v0.2.4](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.4) -- 2026-02-18 (Tag)

> 21 commits since v0.2.3 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.3...v0.2.4)

### Rust 2024 Edition Migration

- **Workspace migrated to Rust edition 2024** ([`db4ec3d`](https://github.com/Dicklesworthstone/asupersync/commit/db4ec3d8))
- Comprehensive rustfmt 2024 formatting applied across entire codebase ([`5cb48b4`](https://github.com/Dicklesworthstone/asupersync/commit/5cb48b40))
- Windows IOCP poller migrated from RawSocket to BorrowedSocket ([`29edc8f`](https://github.com/Dicklesworthstone/asupersync/commit/29edc8fe))

### Bug Fixes

- gRPC CallContext deadline expiry made boundary-inclusive and testable ([`0e36edd`](https://github.com/Dicklesworthstone/asupersync/commit/0e36edd3))
- TraceMonoid PartialEq guarded against fingerprint hash collisions ([`44072cb`](https://github.com/Dicklesworthstone/asupersync/commit/44072cb8))
- EndpointState made atomic; update_endpoint_state no-op fixed ([`fdc9cd1`](https://github.com/Dicklesworthstone/asupersync/commit/fdc9cd1a))
- Bridge sync pending accounting and CRDT obligation acquire idempotency ([`1f678ba`](https://github.com/Dicklesworthstone/asupersync/commit/1f678ba9))
- RFC 6455 close code validation on parse, tighten wire-sendable set ([`591bf57`](https://github.com/Dicklesworthstone/asupersync/commit/591bf574))
- Integer overflow prevention in Duration-to-u64 conversions and HPACK bitmask shifts ([`5b80ba6`](https://github.com/Dicklesworthstone/asupersync/commit/5b80ba69))
- Circuit breaker half_open_max_probes clamped to minimum of 1 ([`70c19da`](https://github.com/Dicklesworthstone/asupersync/commit/70c19dac))
- DummyCx stub in scope compile-fail test ([`b824e69`](https://github.com/Dicklesworthstone/asupersync/commit/b824e692))

### Performance

- Decoder scratch buffer reuse, HPACK prealloc, WatchStream mark_seen ([`9f0522e`](https://github.com/Dicklesworthstone/asupersync/commit/9f0522e0))
- Single-pass HTTP/1 header parsing and raptorq decoder retry snapshot/restore ([`33ce0f0`](https://github.com/Dicklesworthstone/asupersync/commit/33ce0f06))

---

## [v0.2.3](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.3) -- 2026-02-17 (Tag)

> 2 commits since v0.2.2 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.2...v0.2.3)

- Version bump release for tagged milestone
- Fix Windows reactor modify/delete socket source typing ([`63880c2`](https://github.com/Dicklesworthstone/asupersync/commit/63880c24))

---

## [v0.2.2](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.2) -- 2026-02-17 (Tag)

> 380 commits since v0.2.0 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.0...v0.2.2)

### Performance Overhaul: parking_lot Migration

- **Complete migration from std::sync to parking_lot** across the entire codebase -- channels, runtime, scheduler, sync primitives, actor, service, net, transport ([`3c1b335`](https://github.com/Dicklesworthstone/asupersync/commit/3c1b3356), [`067e030`](https://github.com/Dicklesworthstone/asupersync/commit/067e0306))
- Lock-free atomic counters replacing Mutex-guarded stats in channels, bulkhead, DNS, shutdown ([`c9d2ddb`](https://github.com/Dicklesworthstone/asupersync/commit/c9d2ddb3), [`e826391`](https://github.com/Dicklesworthstone/asupersync/commit/e8263919))
- BTreeMap/BTreeSet to HashMap/HashSet migration for hot paths ([`d421836`](https://github.com/Dicklesworthstone/asupersync/commit/d4218361), [`e25acf4`](https://github.com/Dicklesworthstone/asupersync/commit/e25acf4d))
- Then later reversed: HashMap/HashSet back to BTreeMap/BTreeSet for deterministic iteration in tests ([`ae922e6`](https://github.com/Dicklesworthstone/asupersync/commit/ae922e6d), [`e15df42`](https://github.com/Dicklesworthstone/asupersync/commit/e15df427))

### Performance: Hot-Path Optimizations

- Waker cloning eliminated via will_wake() guards across async subsystems ([`da99eb3`](https://github.com/Dicklesworthstone/asupersync/commit/da99eb32))
- CAS loops refined to compare_exchange_weak with match-arm retry ([`2056653`](https://github.com/Dicklesworthstone/asupersync/commit/2056653a))
- Pre-size collections and reduce heap churn across core subsystems ([`b4b053b`](https://github.com/Dicklesworthstone/asupersync/commit/b4b053be))
- Scheduler task dispatch reordering, metrics provider caching, inline waker hot paths ([`8a9330c`](https://github.com/Dicklesworthstone/asupersync/commit/8a9330c6))
- SmallVec in HTTP connection pool cleanup ([`97a1506`](https://github.com/Dicklesworthstone/asupersync/commit/97a1506d))
- Pre-allocate in-flight VecDeque with front-ready fast path in streams ([`aa571c0`](https://github.com/Dicklesworthstone/asupersync/commit/aa571c0f))
- Per-waiter Arc+Mutex eliminated in MPSC channel ([`5df3dad`](https://github.com/Dicklesworthstone/asupersync/commit/5df3dad3))
- Zero-copy response encoding and byte-level header parsing ([`9c4adfe`](https://github.com/Dicklesworthstone/asupersync/commit/9c4adfec))
- Lock-free timed_count, SmallVec steal, and 3-phase next_task ([`58ed379`](https://github.com/Dicklesworthstone/asupersync/commit/58ed3790))
- Stack pinning via std::pin::pin! replacing Box::pin in scopes ([`3967aa7`](https://github.com/Dicklesworthstone/asupersync/commit/3967aa7a))

### RaptorQ Erasure Coding

- **Block-Schur low-rank hard-regime branch** and dense column index acceleration ([`5aaaf82`](https://github.com/Dicklesworthstone/asupersync/commit/5aaaf82c))
- **Runtime decoder policy framework** with sparse elimination refinement ([`178824e`](https://github.com/Dicklesworthstone/asupersync/commit/178824ee))
- Sparse-first column ordering, hybrid elimination, chunked GF256 scalar kernels ([`1104918`](https://github.com/Dicklesworthstone/asupersync/commit/1104918a))
- Precompute GF(256) nibble multiplication tables as compile-time statics ([`8a5fd02`](https://github.com/Dicklesworthstone/asupersync/commit/8a5fd02b))
- Queue-based peeling, hard-regime elimination, input validation, output verification ([`62d79c4`](https://github.com/Dicklesworthstone/asupersync/commit/62d79c40))
- Detect inconsistent overdetermined systems in Gaussian elimination ([`04700e7`](https://github.com/Dicklesworthstone/asupersync/commit/04700e74))
- Binary search peeling removal ([`b015331`](https://github.com/Dicklesworthstone/asupersync/commit/b0153319))
- Cap symbol pool initial allocation to per-object demand ([`040006e`](https://github.com/Dicklesworthstone/asupersync/commit/040006e2))

### Reactor and I/O

- **Edge-triggered, priority, and HUP support** added to epoll reactor ([`65a47d7`](https://github.com/Dicklesworthstone/asupersync/commit/65a47d70))
- io_uring ETIME handling, Windows modify stale socket cleanup ([`c93cc6b`](https://github.com/Dicklesworthstone/asupersync/commit/c93cc6ba))
- io_uring modify() rollback semantics and stale-registration pruning ([`77ae6aa`](https://github.com/Dicklesworthstone/asupersync/commit/77ae6aa9))
- fd registration hardened against reuse and stale deregistration ([`66eff16`](https://github.com/Dicklesworthstone/asupersync/commit/66eff16a))
- Windows: duplicate socket guard, best-effort deregister, stale handle helper ([`2399d00`](https://github.com/Dicklesworthstone/asupersync/commit/2399d007))
- Colocate token and fd maps in EpollReactor, eliminate O(n) fd scan ([`363b898`](https://github.com/Dicklesworthstone/asupersync/commit/363b8982))

### Scheduler

- **Harden intrusive heap** against stale or corrupted heap indices ([`790bc44`](https://github.com/Dicklesworthstone/asupersync/commit/790bc44e))
- Harden local task safety, deadline dispatch, panic recovery, counter underflow protection ([`b07d13f`](https://github.com/Dicklesworthstone/asupersync/commit/b07d13fd))
- CAS for counter saturation, validate queue tags, recover from foreign-pinned waiters ([`aae1b2f`](https://github.com/Dicklesworthstone/asupersync/commit/aae1b2f9))
- Three liveness bugs resolved in work-stealing and shutdown paths ([`9fe7960`](https://github.com/Dicklesworthstone/asupersync/commit/9fe79606))
- Try_local_any_lane for single-lock multi-lane local dispatch ([`9125605`](https://github.com/Dicklesworthstone/asupersync/commit/91256053))
- Pop_any_lane_with_hint for single-call multi-lane dispatch ([`975763d`](https://github.com/Dicklesworthstone/asupersync/commit/975763df))
- Cancel_streak accounting corrected, Parker made poison-tolerant ([`9b2a812`](https://github.com/Dicklesworthstone/asupersync/commit/9b2a812b))
- No-progress detection for tasks that never checkpoint via logical time ([`cfbc3d3`](https://github.com/Dicklesworthstone/asupersync/commit/cfbc3d3c))
- ABBA deadlock prevented in Stealer::steal() lock ordering ([`9f00fae`](https://github.com/Dicklesworthstone/asupersync/commit/9f00faed))

### Formal Verification (Lean)

- **Close/cancel protocol totality proofs** with CI manifest schema validation ([`4b4d7c0`](https://github.com/Dicklesworthstone/asupersync/commit/4b4d7c0d))
- **10 canonical-form decomposition theorems** for state ladder types ([`ad10ca4`](https://github.com/Dicklesworthstone/asupersync/commit/ad10ca4c))
- Cross-entity liveness contract with composition validation tests ([`cd1f7e9`](https://github.com/Dicklesworthstone/asupersync/commit/cd1f7e97))
- Reliability hardening contract and closed-loop impact report ([`017d4ee`](https://github.com/Dicklesworthstone/asupersync/commit/017d4eef))
- Preservation helper prelude with canonical reusable theorems ([`31e7ee4`](https://github.com/Dicklesworthstone/asupersync/commit/31e7ee41))

### Distributed

- **DistributorTransport trait** for replica symbol dispatch ([`781acac`](https://github.com/Dicklesworthstone/asupersync/commit/781acac1))
- Full snapshot application in RegionBridge ([`42365b1`](https://github.com/Dicklesworthstone/asupersync/commit/42365b16))
- Region apply_distributed_snapshot and set_budget for bridge recovery ([`46986e1`](https://github.com/Dicklesworthstone/asupersync/commit/46986e13))
- Verified symbols can replace unverified; tolerate rejected symbols ([`18481eb`](https://github.com/Dicklesworthstone/asupersync/commit/18481ebd))
- ESI acceptance range widened for high-loss recovery scenarios ([`38c4e37`](https://github.com/Dicklesworthstone/asupersync/commit/38c4e37d))
- Recovery collector verified flag not trusted when verify_integrity is enabled ([`1472e42`](https://github.com/Dicklesworthstone/asupersync/commit/1472e425))

### Combinator and Service Layer

- **Async barrier rewrite** from synchronous Condvar to Future-based ([`1079a50`](https://github.com/Dicklesworthstone/asupersync/commit/1079a501))
- ConcurrencyLimit rewritten as async state machine ([`4282f82`](https://github.com/Dicklesworthstone/asupersync/commit/4282f82d))
- Circuit breaker CallGuard prevents probe permit leak on panic ([`21fb6d1`](https://github.com/Dicklesworthstone/asupersync/commit/21fb6d12))
- BulkheadPermit converted to RAII guard with Drop, fixes zombie queue capacity leak ([`81e80be`](https://github.com/Dicklesworthstone/asupersync/commit/81e80bea))
- Bulkhead cancel releases granted-but-unclaimed permits ([`08721816`](https://github.com/Dicklesworthstone/asupersync/commit/08721816))
- Lock ordering fixed in bulkhead, circuit breaker, and rate limiter ([`0dde97d`](https://github.com/Dicklesworthstone/asupersync/commit/0dde97db))
- RwLock metrics replaced with atomic counters on hot paths ([`335a6c8`](https://github.com/Dicklesworthstone/asupersync/commit/335a6c8a))
- RAII guards for connection slots and dispatch counters in transport ([`8feb047`](https://github.com/Dicklesworthstone/asupersync/commit/8feb0477))
- Drain pending queue after cancel returns a permit ([`698c425`](https://github.com/Dicklesworthstone/asupersync/commit/698c425e))

### Channel Correctness

- Broadcast channel recv protected from u64->usize truncation on 32-bit ([`3e6cb7d`](https://github.com/Dicklesworthstone/asupersync/commit/3e6cb7de))
- Cancellation-aware partition sends and fault buffer ownership safety ([`f889405`](https://github.com/Dicklesworthstone/asupersync/commit/f8894057))
- Flush errors propagated and undelivered messages requeued in fault channel ([`e2ce5dc`](https://github.com/Dicklesworthstone/asupersync/commit/e2ce5dca))
- Reorder buffer pre-allocation preserved across flushes ([`7ee583a`](https://github.com/Dicklesworthstone/asupersync/commit/7ee583a2))

### Supervision

- Configurable tolerance added to RestartStormMonitor ([`9225331`](https://github.com/Dicklesworthstone/asupersync/commit/92253312))

### Database

- MySQL auth nonce parsing and PostgreSQL error handling robustness ([`752e164`](https://github.com/Dicklesworthstone/asupersync/commit/752e164e))
- MySQL: disambiguate 0x00 data rows from OK terminators in DEPRECATE_EOF mode ([`cfd1792`](https://github.com/Dicklesworthstone/asupersync/commit/cfd17929))
- MySQL: use negotiated capabilities for result-set parsing ([`4197df9`](https://github.com/Dicklesworthstone/asupersync/commit/4197df9f))
- PostgreSQL: return Ok after successful SCRAM authentication ([`173ed90`](https://github.com/Dicklesworthstone/asupersync/commit/173ed903))
- PostgreSQL: drain to ReadyForQuery on ErrorResponse ([`a0b8a5f`](https://github.com/Dicklesworthstone/asupersync/commit/a0b8a5f2))

### HTTP/2 Protocol

- Skipped queued outbound DATA for reset/closed streams ([`e736975`](https://github.com/Dicklesworthstone/asupersync/commit/e7369754))
- Reject PUSH_PROMISE with promised stream ID 0 per RFC 7540 ([`b8546e4`](https://github.com/Dicklesworthstone/asupersync/commit/b8546e45))
- Wire role-aware settings into connection, reject server ENABLE_PUSH ([`9111259`](https://github.com/Dicklesworthstone/asupersync/commit/91112595))
- Enforce RFC 7540 idle stream connection errors ([`b434c29`](https://github.com/Dicklesworthstone/asupersync/commit/b434c291))
- RFC 7540/7541 conformance hardening and HPACK security fixes ([`995196e`](https://github.com/Dicklesworthstone/asupersync/commit/995196e2))
- CONTINUATION on closed streams and headers_complete corruption prevented ([`fa79c39`](https://github.com/Dicklesworthstone/asupersync/commit/fa79c392))

### Sync Primitives

- Cancellation-safe barrier, lost-wakeup prevention in Notify, wake-under-lock elimination in Semaphore ([`f4ed526`](https://github.com/Dicklesworthstone/asupersync/commit/f4ed5264))
- Broadcast-cancelled Notify waiter prevented from leaking stored token ([`686716c`](https://github.com/Dicklesworthstone/asupersync/commit/686716c6))
- Mutex baton-passing coverage and OnceCell::set() retry on cancelled initializer ([`b2406c6`](https://github.com/Dicklesworthstone/asupersync/commit/b2406c6b))
- OnceCell queued waker refreshed on re-poll in get_or_init ([`c5a2dd0`](https://github.com/Dicklesworthstone/asupersync/commit/c5a2dd0a))
- Pool return-waker notification, contended_mutex poison discrimination ([`ca438a3`](https://github.com/Dicklesworthstone/asupersync/commit/ca438a34))
- BarrierWaitFuture Drop impl and type-erased ConcurrencyLimit acquire future ([`d5b0b95`](https://github.com/Dicklesworthstone/asupersync/commit/d5b0b950))

### Determinism

- HashMap migrated to DetHashMap across determinism-sensitive paths ([`bf17982`](https://github.com/Dicklesworthstone/asupersync/commit/bf179823))
- DetHasher hardened for portable hashing with little-endian encoding ([`556b5d3`](https://github.com/Dicklesworthstone/asupersync/commit/556b5d33))

### Net

- Bind/reuseaddr/reuseport configuration before TcpSocket::connect ([`50fd1f2`](https://github.com/Dicklesworthstone/asupersync/commit/50fd1f27))
- UnixDatagram::bind prevented from deleting non-socket files ([`61bdbdd`](https://github.com/Dicklesworthstone/asupersync/commit/61bddbda))
- UnixListener::bind only removes stale socket files, refuses non-socket paths ([`8fd90c5`](https://github.com/Dicklesworthstone/asupersync/commit/8fd90c55))
- TCP and Unix split locks held across driver.register() to prevent EEXIST race ([`41de223`](https://github.com/Dicklesworthstone/asupersync/commit/41de2239))

### WebSocket

- Cancel-safety and pong encoding fixed in split halves ([`27ee9ce`](https://github.com/Dicklesworthstone/asupersync/commit/27ee9cea))
- Reserved close codes rejected and 1-byte close payloads per RFC 6455 ([`0eb5467`](https://github.com/Dicklesworthstone/asupersync/commit/0eb5467b))
- Frame codec hardened for RFC 6455: minimal encoding, MSB, close reason ([`178ecaf`](https://github.com/Dicklesworthstone/asupersync/commit/178ecafc))
- Server-selected subprotocol validated against client request per RFC 6455 ([`717ed35`](https://github.com/Dicklesworthstone/asupersync/commit/717ed35c))

### Test Coverage Expansion

- **Massive B10 test wave campaign** (waves 1--87): ~2,000+ new tests covering pure data-type invariants across every module
- Comprehensive E2E test suite for QUIC/H3 (72 scenarios) ([`d317506`](https://github.com/Dicklesworthstone/asupersync/commit/d3175068))
- Database: 109 unit tests for postgres, sqlite, and migration modules ([`fa7fab2`](https://github.com/Dicklesworthstone/asupersync/commit/fa7fab29))
- Cancellation protocol and race-drain conformance tests ([`99ee740`](https://github.com/Dicklesworthstone/asupersync/commit/99ee7409))

---

## [v0.2.0](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.0) -- 2026-02-15 (Tag)

> 396 commits since v0.1.1 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.1.1...v0.2.0)

Major version bump covering formal verification, deep audit, and RaptorQ decoder rewrite.

### Formal Verification (Lean 4)

- **Track-2 declaration-order stabilization** closed ([`ecc2921`](https://github.com/Dicklesworthstone/asupersync/commit/ecc29215))
- Obligation stability theorems registered and frontier tests hardened ([`96caeba`](https://github.com/Dicklesworthstone/asupersync/commit/96caeba8))
- Refinement map enriched with ownership, routing metadata, conformance tests ([`3c47575`](https://github.com/Dicklesworthstone/asupersync/commit/3c47575a))
- Lean proof-guided performance opportunity map ([`7cbb175`](https://github.com/Dicklesworthstone/asupersync/commit/7cbb1755), [`4cd59ec`](https://github.com/Dicklesworthstone/asupersync/commit/4cd59ec5))
- Track 2 burndown dashboard and CI verification profiles ([`cacb264`](https://github.com/Dicklesworthstone/asupersync/commit/cacb2648))
- Lean smoke gate job for pull requests ([`8800e82`](https://github.com/Dicklesworthstone/asupersync/commit/8800e82f))
- Proof-aware review workflow, artifact contract tests ([`68d09cc`](https://github.com/Dicklesworthstone/asupersync/commit/68d09cc1))

### RaptorQ Decoder

- **RFC 6330 tuple semantics** and repair equation generation ([`d8c37ad`](https://github.com/Dicklesworthstone/asupersync/commit/d8c37ad4))
- **RFC 6330 Table 2 lookup** replacing ad-hoc parameter derivation ([`5bf62fb`](https://github.com/Dicklesworthstone/asupersync/commit/5bf62fb7))
- **RFC 6330 golden vector conformance suite** ([`666d705`](https://github.com/Dicklesworthstone/asupersync/commit/666d705a))
- **Metamorphic property erasure-recovery** test battery ([`fe0d7de`](https://github.com/Dicklesworthstone/asupersync/commit/fe0d7dee))
- GF256 AVX2 and NEON SIMD intrinsics with feature-gated unsafe ([`4c51ee6`](https://github.com/Dicklesworthstone/asupersync/commit/4c51ee64))
- SIMD kernel dispatch infrastructure with AVX2/NEON scaffolds ([`47ed283`](https://github.com/Dicklesworthstone/asupersync/commit/47ed283a))
- Legacy soliton-based repair path removed, unified on RFC 6330 tuples ([`1c062a5`](https://github.com/Dicklesworthstone/asupersync/commit/1c062a50))
- Full pivoting in systematic constraint solver ([`a720f11`](https://github.com/Dicklesworthstone/asupersync/commit/a720f115))
- Minimum-degree row selection for constraint matrix pivoting ([`957c50b`](https://github.com/Dicklesworthstone/asupersync/commit/957c50b4))
- Deterministic D6 E2E scenario runner with profile support ([`da10a1a`](https://github.com/Dicklesworthstone/asupersync/commit/da10a1a0))
- Deterministic pivot tie-breaking tests and GF256 replay catalog ([`96dc92d`](https://github.com/Dicklesworthstone/asupersync/commit/96dc92d5))
- Canonical test log schema (D7) with failure context migration ([`49965c2`](https://github.com/Dicklesworthstone/asupersync/commit/49965c2e))
- SIMD intrinsics made opt-in for stable Rust compatibility ([`5a6a753`](https://github.com/Dicklesworthstone/asupersync/commit/5a6a753c))

### Runtime Correctness

- Macaroon discharge first-party caveats evaluated during verification ([`79fc52a`](https://github.com/Dicklesworthstone/asupersync/commit/79fc52af))
- Spurious cancel prevented when dropping ready JoinFuture ([`8834c12`](https://github.com/Dicklesworthstone/asupersync/commit/8834c12e))
- Scheduler collision slots collapsed when task generations drain ([`b202312`](https://github.com/Dicklesworthstone/asupersync/commit/b202312b))
- Blocking pool idle-thread retirement uses atomic CAS to prevent undershoot ([`441c7f5`](https://github.com/Dicklesworthstone/asupersync/commit/441c7f5c))
- Atomic saturating_decrement and polls_remaining consumption ([`467fcd3`](https://github.com/Dicklesworthstone/asupersync/commit/467fcd3b))
- Governor_interval=0 normalization and env config coverage expanded ([`38bd7e1`](https://github.com/Dicklesworthstone/asupersync/commit/38bd7e10))
- LeakEscalation threshold=0 clamped to 1 ([`a9442b5`](https://github.com/Dicklesworthstone/asupersync/commit/a9442b53))
- Region heap alloc made transactional w.r.t. stats ([`91f002b`](https://github.com/Dicklesworthstone/asupersync/commit/91f002b7))

### Channel and Sync

- Wake outside lock in broadcast and oneshot channels ([`a821183`](https://github.com/Dicklesworthstone/asupersync/commit/a8211831))
- Wake-under-lock deadlock prevented in mpsc sender cascade ([`c90c4ad`](https://github.com/Dicklesworthstone/asupersync/commit/c90c4ade))
- Integer-precision drift calculation and exhaustive waker cleanup on terminal paths ([`f0a7ce7`](https://github.com/Dicklesworthstone/asupersync/commit/f0a7ce7c))
- Double-panic abort prevented in mpsc and watch channel Drop impls ([`47d2c03`](https://github.com/Dicklesworthstone/asupersync/commit/47d2c03d), [`add13a3`](https://github.com/Dicklesworthstone/asupersync/commit/add13a3d))
- Waker lifecycle, permit semantics, and evidence emission fixes ([`5136714`](https://github.com/Dicklesworthstone/asupersync/commit/51367145))
- Waker-while-locked hazards eliminated in TCP and WebSocket split halves ([`6004fc3`](https://github.com/Dicklesworthstone/asupersync/commit/6004fc3f))

### Reactor

- events.len() corrected for kqueue, macOS kqueue, and Windows IOCP poll ([`775ffdf`](https://github.com/Dicklesworthstone/asupersync/commit/775ffdfb))
- epoll poll returns count of actually stored events ([`5d74e64`](https://github.com/Dicklesworthstone/asupersync/commit/5d74e642))
- Adapted to polling 3.11 Events API ([`b01c40c`](https://github.com/Dicklesworthstone/asupersync/commit/b01c40c4))
- io_uring fcntl pre-flight check for modify() early stale-fd pruning ([`4b87067`](https://github.com/Dicklesworthstone/asupersync/commit/4b870679))
- Poll_events mutex guard dropped before returning from EpollReactor::poll ([`5da8d49`](https://github.com/Dicklesworthstone/asupersync/commit/5da8d49d))

### Networking

- TCP split test guard drops and CombinedWaker for owned split halves ([`7a8d7cf`](https://github.com/Dicklesworthstone/asupersync/commit/7a8d7cf7))
- MX records sorted by RFC-priority order on construction ([`98b4ec2`](https://github.com/Dicklesworthstone/asupersync/commit/98b4ec24))
- Non-UTF8 Unix paths supported in io-uring path_to_cstring helpers ([`bc4cb65`](https://github.com/Dicklesworthstone/asupersync/commit/bc4cb65e))
- TCP/Unix split combined waiter interest on re-registration ([`b035ae6`](https://github.com/Dicklesworthstone/asupersync/commit/b035ae68), [`c841b9d`](https://github.com/Dicklesworthstone/asupersync/commit/c841b9da))

### H2 Protocol

- last_stream_id tracked for GOAWAY, CONTINUATION interleaving prevented ([`b94f07b`](https://github.com/Dicklesworthstone/asupersync/commit/b94f07bd))
- last_stream_id pollution on rejected HEADERS prevented ([`ed85b9b`](https://github.com/Dicklesworthstone/asupersync/commit/ed85b9bd))
- Zero-increment WINDOW_UPDATE on stream is stream error, not connection ([`1f65a18`](https://github.com/Dicklesworthstone/asupersync/commit/1f65a187))
- RFC 7540 error classification corrected for PRIORITY and WINDOW_UPDATE ([`2965fab`](https://github.com/Dicklesworthstone/asupersync/commit/2965fabf))

### Combinator

- Select polls both futures each tick so loser gets initialized ([`63525618`](https://github.com/Dicklesworthstone/asupersync/commit/63525618))
- join2 dual-cancellation strengthening and SelectAllDrain simultaneous-ready safety ([`520c561`](https://github.com/Dicklesworthstone/asupersync/commit/520c561e))
- Bracket catch panics from release future during Drop to prevent abort ([`49d6ac7`](https://github.com/Dicklesworthstone/asupersync/commit/49d6ac7c))
- Bracket drives release future to completion when dropped during Releasing phase ([`41c0e45`](https://github.com/Dicklesworthstone/asupersync/commit/41c0e45b))
- Saturating arithmetic strengthened in circuit breaker, scheduler, transport ([`357bebd`](https://github.com/Dicklesworthstone/asupersync/commit/357bebd3))
- Map_reduce edge cases hardened ([`2cb3dba`](https://github.com/Dicklesworthstone/asupersync/commit/2cb3dba2))

### Choreography

- Loop label scoping and Continue projection bugs fixed ([`3621d7a`](https://github.com/Dicklesworthstone/asupersync/commit/3621d7a6))
- first_active_participant traverses inert Seq/Par prefixes ([`271b6da`](https://github.com/Dicklesworthstone/asupersync/commit/271b6da0))
- Loop codegen break, duplicate participant detection ([`7d6a2d1`](https://github.com/Dicklesworthstone/asupersync/commit/7d6a2d17))
- Parallel knowledge-of-choice validation, compensation stubs, LabRuntime tests ([`a9d7e13`](https://github.com/Dicklesworthstone/asupersync/commit/a9d7e13f))

### Deep Audit Campaign

- Extensive deep audit of major subsystems, all confirmed SOUND
- Scheduler (worker, local_queue, global_injector), gen_server, blocking_pool, io_driver, bulkhead, channel subsystem, transport/aggregator, fs/uring, tcp/split, sharded_state, resource_accounting, time/driver, kafka ([`82a9d3f`](https://github.com/Dicklesworthstone/asupersync/commit/82a9d3f3), [`85cc3a1`](https://github.com/Dicklesworthstone/asupersync/commit/85cc3a15), [`f0133e3`](https://github.com/Dicklesworthstone/asupersync/commit/f0133e32))

### Performance Tuning

- #[inline] on hot-path cancel check, Cx clone, DetRng PRNG methods ([`0451e25`](https://github.com/Dicklesworthstone/asupersync/commit/0451e256), [`9e0f2e8`](https://github.com/Dicklesworthstone/asupersync/commit/9e0f2e8d))
- Atomic orderings relaxed, scheduler allocations eliminated, Cx clone consolidated ([`027821f`](https://github.com/Dicklesworthstone/asupersync/commit/027821f4))
- Scheduler skip cancel-lane rebuild when re-promotion priority is same or lower ([`316e7f7`](https://github.com/Dicklesworthstone/asupersync/commit/316e7f73))
- SmallVec for hot-path waker collections ([`aa3b61a`](https://github.com/Dicklesworthstone/asupersync/commit/aa3b61a4))

### CI

- Tag-triggered builds and owner-routing in Lean failure payloads ([`bf8a3c4`](https://github.com/Dicklesworthstone/asupersync/commit/bf8a3c44))
- Lean smoke gate, full gate, and bundle config in CI profiles ([`cb9cd9a`](https://github.com/Dicklesworthstone/asupersync/commit/cb9cd9aa))
- Nightly toolchain pinned to 2026-02-05 for reproducible builds ([`ef2540c`](https://github.com/Dicklesworthstone/asupersync/commit/ef2540c0))

### Dependencies

- polling 2.8 to 3.11, opentelemetry{,_sdk} 0.28 to 0.31 ([`0cef3b6`](https://github.com/Dicklesworthstone/asupersync/commit/0cef3b6b))
- rusqlite 0.33 to 0.38, rcgen 0.13 to 0.14, lz4_flex 0.11 to 0.12, toml 0.8 to 1.0, webpki-roots 0.26 to 1.0 ([`1f5733f`](https://github.com/Dicklesworthstone/asupersync/commit/1f5733f3), [`f2e5164`](https://github.com/Dicklesworthstone/asupersync/commit/f2e51646), [`d7ea4cf`](https://github.com/Dicklesworthstone/asupersync/commit/d7ea4cfe))

### Observability

- Lock-free resource accounting ([`4c68494`](https://github.com/Dicklesworthstone/asupersync/commit/4c68494b))
- Conformance test runner (cancellation protocol and race-drain) ([`99ee740`](https://github.com/Dicklesworthstone/asupersync/commit/99ee7409))
- 88 new trace event tests, 31 trace integrity tests, 24 trace recorder tests ([`6cdab62`](https://github.com/Dicklesworthstone/asupersync/commit/6cdab62a), [`aa8f0a4`](https://github.com/Dicklesworthstone/asupersync/commit/aa8f0a44), [`d0fe05d`](https://github.com/Dicklesworthstone/asupersync/commit/d0fe05db))

---

## [v0.1.1](https://github.com/Dicklesworthstone/asupersync/tag/v0.1.1) -- 2026-02-07 (Tag)

> 3 commits since v0.1.0 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.1.0...v0.1.1)

- Exclude `.out` files from crate package and fix match arm syntax ([`67f660c`](https://github.com/Dicklesworthstone/asupersync/commit/67f660cc))
- Add `.tmp/` to `.gitignore` ([`e8f03f1`](https://github.com/Dicklesworthstone/asupersync/commit/e8f03f18))

---

## [v0.1.0](https://github.com/Dicklesworthstone/asupersync/tag/v0.1.0) -- 2026-02-06 (Tag)

> ~1,650 commits | Initial public milestone

The initial tagged milestone establishing the core async runtime with structured concurrency, cancel-correctness, and capability security.

### Core Runtime

- **Structured concurrency** with region-based task ownership -- every spawned task belongs to a region that closes to quiescence ([`33335ea`](https://github.com/Dicklesworthstone/asupersync/commit/33335ea3))
- **Cancel-correct protocol**: cancellation is request, drain, finalize -- never silent data loss
- **Capability-secure effects**: all effects flow through explicit `Cx` context; no ambient authority
- **Four-valued Outcome**: `Ok`, `Err`, `Cancelled(reason)`, `Panicked(payload)` with severity lattice
- **Lab runtime**: deterministic testing with virtual time, deterministic scheduling, and trace replay
- **Test oracle module** for runtime invariant verification ([`dc03abd`](https://github.com/Dicklesworthstone/asupersync/commit/dc03abd8))

### Channels (Two-Phase Send)

- **MPSC channel** with reserve/commit pattern ([`73dab81`](https://github.com/Dicklesworthstone/asupersync/commit/73dab815))
- **Oneshot channel** with reserve/commit pattern ([`0f478cd`](https://github.com/Dicklesworthstone/asupersync/commit/0f478cd9))
- **Broadcast channel** with two-phase send and lagging receiver detection
- **Watch channel** with borrow-and-clone semantics

### Sync Primitives

- Two-phase sync primitives with guard obligations ([`cb7b1f1`](https://github.com/Dicklesworthstone/asupersync/commit/cb7b1f1c))
- Mutex, RwLock, Semaphore, Barrier, Notify, OnceCell -- all cancel-aware with `&Cx`

### Combinators

- **join_all**, **race_all** (N-way), **select** (2-way), **first_ok**, **pipeline**, **map_reduce** ([`945414a`](https://github.com/Dicklesworthstone/asupersync/commit/945414a6), [`d04745b`](https://github.com/Dicklesworthstone/asupersync/commit/d04745bc), [`34fe222`](https://github.com/Dicklesworthstone/asupersync/commit/34fe2220), [`d457794`](https://github.com/Dicklesworthstone/asupersync/commit/d457794c))
- **Bulkhead** combinator with queue timeout ([`180dc9e`](https://github.com/Dicklesworthstone/asupersync/commit/180dc9ea))
- **Circuit breaker** with half-open probing
- **Bracket** combinator: cancel-safe resource acquisition with Drop-based release ([`fdb20e7`](https://github.com/Dicklesworthstone/asupersync/commit/fdb20e76))

### Time

- Sleep and Timeout primitives with explicit time sources ([`1a58619`](https://github.com/Dicklesworthstone/asupersync/commit/1a586194))
- Timer wheel for efficient timeout management
- Works with virtual time in lab runtime for deterministic testing

### Scheduler

- EDF (Earliest Deadline First) scheduling with bug fixes ([`3787abb`](https://github.com/Dicklesworthstone/asupersync/commit/3787abbf))
- Three-lane priority scheduler
- Work-stealing with local queues and global injector

### I/O and Networking

- TCP, UDP, Unix stream/datagram support
- I/O conformance test suite (IO-001 through IO-007) ([`6a9a876`](https://github.com/Dicklesworthstone/asupersync/commit/6a9a876f))
- HTTP/1 and HTTP/2 codec and connection management
- TLS with ALPN negotiation

### Supervision (Spork/OTP Model)

- **GenServer** with init/terminate lifecycle and trace schema ([`c6a9068`](https://github.com/Dicklesworthstone/asupersync/commit/c6a90682))
- **Restart storm detection** via anytime-valid e-processes ([`500ac33`](https://github.com/Dicklesworthstone/asupersync/commit/500ac33c))
- **Conformal calibration** for health thresholds ([`b0ed01f`](https://github.com/Dicklesworthstone/asupersync/commit/b0ed01f9))
- **CrashPack**: golden snapshots, replay tests, artifact writer capability, versioned manifest ([`267153c`](https://github.com/Dicklesworthstone/asupersync/commit/267153cd), [`3ba14c7`](https://github.com/Dicklesworthstone/asupersync/commit/3ba14c75))
- **Link/Monitor system** with LinkedExit cancel kind and trap-exit policy ([`756d65d`](https://github.com/Dicklesworthstone/asupersync/commit/756d65db))
- NamePermit reserve/commit with linear obligations ([`13cbc6a`](https://github.com/Dicklesworthstone/asupersync/commit/13cbc6ae))
- Deterministic collision resolution for NameRegistry ([`77cd887`](https://github.com/Dicklesworthstone/asupersync/commit/77cd887e))
- AppSpec compiled to SupervisorSpec + Regions ([`50e566c`](https://github.com/Dicklesworthstone/asupersync/commit/50e566c9))

### RaptorQ (FEC)

- Core symbol types and encoding/decoding pipeline
- Benchmark baselines ([`74784392`](https://github.com/Dicklesworthstone/asupersync/commit/74784392))

### Formal Verification

- Determinism oracle ([`1b33dad`](https://github.com/Dicklesworthstone/asupersync/commit/1b33dad4))
- Divergent prefix minimizer ([`3d38c21`](https://github.com/Dicklesworthstone/asupersync/commit/3d38c21a))

### Documentation

- Comprehensive README with architecture diagrams, tokio mapping table, and quick examples
- Spork OTP mental model section ([`f26f319`](https://github.com/Dicklesworthstone/asupersync/commit/f26f319f))
- Networking, database, channels, and observability architecture sections ([`c367fd5`](https://github.com/Dicklesworthstone/asupersync/commit/c367fd54))

---

[Unreleased]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.4...HEAD
[v0.3.4]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.3...v0.3.4
[v0.3.3]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.9...v0.3.0
[v0.2.9]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.8...v0.2.9
[v0.2.8]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.7...v0.2.8
[v0.2.7]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.6...v0.2.7
[v0.2.6]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.5...v0.2.6
[v0.2.5]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.4...v0.2.5
[v0.2.4]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.0...v0.2.2
[v0.2.0]: https://github.com/Dicklesworthstone/asupersync/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/Dicklesworthstone/asupersync/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/Dicklesworthstone/asupersync/commits/v0.1.0
