# Asupersync Bridge Plan — reality check refreshed 2026-09-22

## September 22 assessment: validation debt now dominates delivery

**Verdict: the kernel's release-blocking native cancellation contract is green, and the entire
workspace compiles cleanly under default and all features. But implementation volume has outrun
execution by roughly an order of magnitude, and the September 15 instruction to restore trustworthy
execution first was not followed.** In the seven days after the September 15 refresh, 98,389 lines
were added to `src/` (the crate is now 2.27M lines of Rust plus 1.05M lines of tests). 61,060 of
those lines (62%) arrived in commits whose own messages say the code and tests were never compiled or
executed. 64% of non-tracker commits cite no bead. GitHub Actions is disabled at the repository level,
and one agent classified RCH itself as a no-deletion violation (`bi2462.81`), so much of the swarm had
no sanctioned validation path and kept landing source anyway. The heal commits made that code compile;
execution is a separate, still-missing step. When the never-run suites were finally executed (the
09-22 remote suites; the 09-22 root lib run), they came up red, and several of the reds are real
production defects, two of them already shipped in v0.5.0.

The vision itself has not moved backwards: Phase 0 (deterministic kernel) and Phase 1 (parallel
scheduler) are real; the core `Cx`/region/cancellation/obligation machinery works on the paths the
native contract exercises. What is missing is the same thing the last two refreshes found, now larger:
proof of the new surfaces, closure of the kernel's default-path gaps, and honest public documentation.
This refresh therefore puts an execution gate in front of all further feature work and converts every
concrete defect found into a bead.

### Assessment basis and limits

- Read AGENTS.md (1,439 lines) and README.md (2,626 lines) completely, the v4 design bible, the
  formal-semantics outline, and this plan's September 4 and September 15 sections.
- Ten read-only subsystem audits (kernel; scheduler/lab/replay/formal; combinators/supervision/AppSpec;
  network/server; data/IO/observability; distributed/remote; ATP/RaptorQ; Browser Edition;
  governance/CI/release/tracker; docs/examples/dependencies) traced implementation and tests against
  README/plan claims. Reports: `/data/tmp/rc_20260922/audit_*.md`. The root personally re-read the
  source at `8525d7055` for these claims: `race!`/`select!` loser cancellation; the remote silent-peer
  wait and uninterruptible close; the supervisor dependency `continue`; the `atp send` plaintext default;
  the browser glue/wasm export mismatch; process-wide signal registration; the gRPC `has_io()` predicate;
  the undeclared strict replay driver; the frozen `RuntimeState::now` in the scheduler reward; peer
  transport-parameter application (partially refuted, now R23d); orphaned source files; commit identity
  and "not compiled" counts; the Actions state; versions and releases; the proof-freshness time bomb.
  Everything else (for example the H2/H1/QUIC DoS paths, PostgreSQL/MySQL/Kafka/OTLP defects, DPOR and
  Lean vacuity, distributed ownership details) was verified by an auditor reading the cited code and is
  recorded with file:line in its bead. It still needs the bead's own old-red receipt before being
  treated as executed fact.
- Audit base: `8525d70554dd7cb7ab02ea16b461c5a6767e9e01` (main at session start). Main advanced
  during the session (runtime retirement-barrier fixes, HTTP/3 streaming bodies, replay capture); tip
  re-runs are labelled with their own SHA.
- All execution used `RCH_REQUIRE_REMOTE=1 rch exec --base <sha> --clean-overlay --no-overlay`:
  the exact committed tree, no working-tree overlay, no local fallback. Logs are retained under
  `/data/tmp/rc_20260922/lanes/`.

### Fresh execution evidence (pristine `8525d7055`, worker hz3)

| Lane | Result |
|---|---|
| Native parked-task cancellation contract (`--test runtime_abort_vs_cancel_semantics_audit`) | **42 passed, 0 failed, 0 ignored, 0 filtered**, exit 0 |
| `cargo check --all-targets --keep-going` (default features) | exit 0, 0 errors, **0 warnings** |
| `cargo check --all-targets --all-features --keep-going` | exit 0, 0 errors, **0 warnings** |
| `cargo test -p asupersync --lib --features test-internals` | 23,602 tests: **23,562 passed, 17 failed**, 23 ignored |
| `cargo run --example onramp_level0` | printed `hello from asupersync`, remote exit 0 (RCH then returned 102 = RCH-E309 artifact-retrieval timeout after success) |

The 17 lib failures classify as: one real runtime regression (retirement barrier installed after
inheritance overlay, fixed on main by `094bbe890`; a filtered re-run at `021cdecaf` confirms it passes, and
the native contract is 42/42 there too); three runtime test drifts;
one real native gRPC defect behind three failures (`cx.has_io()` checks a virtual IoCap native tasks
never carry, so native `connect_tcp`/`connect_tls` always refuse); one gRPC test bug (lossless
`grpc-timeout` unit); one stale QUIC test plus an encoder-validation gap; one resource-bracket
contract disagreement in never-run code; two never-root-caused worker-readiness failures; four RaptorQ
decoder golden-transcript mismatches in a module unchanged since 09-08 (root-cause required; no
reflexive regeneration); and ambient-authority inventory drift from new test threads.

(Feature-gated suite lanes F1-F5 and tip re-runs are recorded in the phase execution record below.)

### Systemic findings (these explain most of the product gaps below)

- **S1. No working validation path for much of the swarm.** GitHub Actions is disabled at the
  repository level (`actions/permissions` → `enabled:false`); the last run of any workflow was
  2026-09-07 and the `CI` workflow has zero successful runs in its history. README/AGENTS text that
  cites CI jobs (`lint-build`, `lean-build`, `tla-tlc`, real-server services, Phase-6 PR gates) describes
  gates that do not currently execute. `bi2462.81` (P0, blocked since 09-15) records one agent's position
  that RCH's own worker-cache pruning violates the no-deletion rule; the owner granted a local `-j2`
  exception to that agent only. Other agents ran RCH normally. This split is an owner decision, not an
  engineering one. The concrete mechanism: 157 of the 161 self-declared-uncompiled commits come from the
  `…@users.noreply.github.com` identity (commits created through GitHub's API/web by an agent with no
  compile path). They bypass `.githooks/pre-push` entirely, and with Actions disabled nothing else checks
  them. The suite-level `/data/projects/AGENTS.md` that RULE 0.5 cites does not exist.
- **S2. Source-only landing became normal.** 161 of 474 non-merge commits since 09-15 state that their
  code/tests were not compiled or executed; they carry 61,060 of 98,389 added `src/` lines (62%). Heal
  commits restored compilation (the pristine default and all-features checks are now clean), but most of
  the new feature-gated suites have no terminal run. First runs so far were mostly red (remote 0/8, 0/4,
  0/2, 0/4 on 09-22; seven lib failures in new modules), and two of the defects they exposed shipped in
  v0.5.0. Feature-gated tests have no `[[test]]` entry, so a default `cargo test` silently selects zero
  of them and passes.
- **S3. The work graph and the code stream decoupled.** 259 of 404 non-tracker commits since 09-15 cite no
  bead. Whole subsystems landed without any bead (`atpd-live` 7.6k lines, `cx::worker_readiness`
  2.6k, dynamic supervision/services ~4.5k, browser-core Rust executor). Meanwhile the beads that do
  describe this work were not updated: every distributed bead (`bi2462.10/.11/.12/.16/.48-.50/.77/.78`)
  still shows its 09-04 state despite ~60 commits; `bi2462.51/.57/.59` likewise. In-progress beads
  untouched for >30 days: 110 of 171. 408 of 635 unfinished beads are P0/P1, so priority no longer ranks.
- **S4. Proof artifacts that cannot fail.** 231 of 317 top-level `src/*.rs` files (~257k lines, 225 named
  `real_*_e2e_tests.rs`) are declared as a module nowhere and never compile; root hardening reports mark
  many of them passing. Further examples: the fail-closed production replay driver exists only as an
  undeclared file plus a `wiring.patch`; `run_raptorq_e2e.sh` records PASS for a scenario that selected zero
  tests; the TLC end-to-end test passes by printing SKIP when the jar is absent and two of its three
  invariants are vacuous; a libraptorq "differential" compares a fixture with itself; the ATP CLI journey
  test simulates the daemon with `cp`/`mv`; five of eight WebSocket RFC 6455 conformance submodules return
  `Ok(())`; `examples/macros_{basic,nested,race}.rs` use fake `Cx`/`Scope` types yet README cites them for
  loser drain.
- **S5. Public truth drifted in both directions.** The CHANGELOG labels v0.6.0 a published "Release"
  although it was never tagged, released or published (crates.io and GitHub latest = 0.5.0). README tells
  users `asupersync = "0.5.0"`, lists the pre-09-14 default feature set, and ships Rust samples that do not
  compile against current signatures (LabConfig builder methods, `join!` over `TaskHandle`, un-awaited
  async `BondedTransfer` calls, `cx.sleep_until`, a six-variant `CancelKind`). In the other direction it
  still says tree-level supervisor restart is pending (ManagedSupervisor exists) and that no Rust future is
  polled in wasm (a wasm32 executor exists in the core crate).
- **S6. Kernel promises still have default-path holes.** The checked obligation APIs admit before
  success, but the default APIs the README teaches (`reserve`, `acquire`) still post a Reserve and return
  the permit first; a later refusal only increments a counter, so the permit is untracked and the quota
  unenforced. Outside the entry macros, `block_on`, `Runtime` drop and `shutdown_timeout` still never
  cancel or drain the root region. `race!`/blocking `select!` spawn each prebuilt branch and discard the
  child `Cx`, so a branch written with the caller's `cx` (the natural style) never observes loser
  cancellation and the drain waits for natural completion or forever. These are exactly the headline
  guarantees (no orphans, losers drained, no obligation leaks) on the paths a first-time user takes.

### Phase 1 answers

1. **What works now, with fresh evidence:** the native parked-task cancellation contract (42/42); a clean
   compile of every target under default and all features with zero warnings; 23,562 of 23,602 lib tests;
   the `#[main]` on-ramp program. By code reading plus older receipts: executing pipeline/map-reduce,
   ManagedSupervisor live restart trees, quorum/first_ok loser drain, gRPC server streaming (its 20 lib tests
   passed in this run), RFC-exact RaptorQ encoding byte-matched against an independent crate to K=2048,
   canonical ATP frames, native ATP CLI transfer over TCP/RQ/QUIC loopback, the V3 mTLS remote service
   (08-31 two-host receipt), h2spec 147/147 on 09-06.
2. **What does not work or is not implemented:** the crosswalk rows marked PARTIAL/STUB/REGRESSED/
   UNPROVEN above, most sharply: loser cancellation for naturally written `race!`/`select!` branches;
   default-path obligation admission; root drain outside the entry macros; production schedule capture;
   native gRPC streaming connect; PostgreSQL server-side cancel; process-wide signal takeover; a coherent
   browser package; the tracked ATP SDK API and 13 CLI commands; AppSpec enforcement; bounded remote
   liveness; and every feature-gated suite that has never run.
3. **What blocks progress:** no sanctioned validation path for a large part of the swarm (S1/S2), a work
   graph no longer attached to the work (S3), proof artifacts that cannot fail (S4), and pending owner
   decisions (G1 validation path, R30 default transport, R31 `atpd-live`, R33 browser GA label, R35 0.5.1
   and compatibility policy, R36 orphan sources).
4. **Would finishing every open and in-progress bead close the gap? No.** Dozens of the defects found here
   had no bead (below). Several beads' acceptance requires GitHub Actions runs that current policy forbids
   (`aoovsx`, `gxv3dy`, `48ukyp`, `qoir1r`), so they cannot close as written. And nothing in the backlog
   addressed the validation path, the uncompiled-landing mechanism or the orphaned source.
5. **Vision goals with no covering bead before this refresh:** loser cancellation for caller-`cx` branches;
   retirement-barrier liveness after teardown; explicit-runtime root drain; the frozen production clock in
   the default scheduler reward; Poll/Wake emission for replay; vacuous formal theorems and TLC skips; H2/H1
   bounded waits; QUIC Retry and queue caps; native gRPC admission; PostgreSQL cancel; MySQL TLS/full auth;
   signal dispositions; zombie reaping; OTLP composition; remote silent-peer bounds and lease renewal;
   supervisor dependency fail-open; ATP plaintext default and legacy fake successes; `atpd-live`; browser
   glue/binary integrity and the Pages module; supply-chain lane drift; the Tokio carve-out in
   `benchmark-adapters`; 0.5.1 and the false 0.6.0 release label; the real 0.5.0 compatibility break; the
   proof-freshness time bomb; 231 orphaned source files; and a validation gate for API-created commits.

### Vision crosswalk: changes since September 15

Rows keep the September 4 numbering. Status words: WORKING_SCOPED (a real journey has a fresh receipt),
PARTIAL, STUB, UNPROVEN (code exists; no execution), REGRESSED, DOC_STALE (code ahead of docs).

| # | Goal | September 22 reality | Owner (existing / new) |
|---|---|---|---|
| 1 | Cooperative cancellation preserves typed results and cleanup | WORKING_SCOPED: 42/42 native contract at `8525d7055`. New risk: a `TaskHandle` that outlives its runtime can hang because teardown never opens the retirement barrier (auditor-reported, suspected). | native lane; NEW R16 |
| 2 | Root closure drains children/finalizers/obligations | PARTIAL: `#[main]` drains but discards the result and skips the drain on panic; `block_on`, `Runtime` drop and `shutdown_timeout` remain abort-by-drop; `spawn_with_cx` docs promise shutdown cancellation that never happens; `0sd3cp` acceptance (drain outcome in trace/report; handles observe `CancelReason::shutdown()`) not met. | NEW R17 |
| 3 | Stock permits obey obligation admission | PARTIAL, unchanged since 09-05: checked APIs correct; default APIs return untracked success on refusal. | `bi2462.28/.29` (revise) |
| 4 | Cleanup bounds inspectable for stock primitives | PARTIAL: `ResponsivenessRegistry` is a declared table (44 entries, finite ones hard-coded `polls: 1`), consulted by no primitive; its native conformance test has no receipt. | `bi2462.30/.31` |
| 5 | Pipeline/map-reduce execute structured work | PARTIAL: real executors, bounded and drained; `e2e_stream_pipeline` ran 20/21 at `8525d7055`. On the native multi-worker runtime a stage panic yields `Panicked` but also a stage error in the report, and a map error is still reported as `Cancelled` (`04jqgn`). | `bi2462.32/.33`, `04jqgn` |
| 6 | Region heap has a runtime consumer | PARTIAL, unchanged. | `bi2462.39-.41` |
| 7 | Scheduler scaling with fairness | PARTIAL: README's "slot within `limit+1` = 17 steps" is wrong under the default adaptive selector (limit reaches 64); the default-on UCB1 reward reads `RuntimeState::now`, which production never advances, so its deadline/age terms are inert. | NEW R18; sharding beads |
| 8 | Production failures replay in the lab | NOT DELIVERED: production emits no Poll/Wake events, so `ProductionSchedule::from_runtime_trace` yields zero steps; exhausted replay silently falls back; the strict driver is an undeclared file. New `io::replay_session*` code is I/O replay, not schedule capture. | `bi2462.8/.9` (revise); NEW R19 |
| 9 | DPOR explores distinct schedules | PARTIAL: lab forces Lamport clocks, so every cross-task conflicting pair is reported as a race; `estimated_classes` over-counts. | `vemwug`, `bi2462.44/.45`; NEW R19 |
| 10 | Formal claims match executable assumptions | PARTIAL: Lean has 189 theorems, 0 `sorry`, but some are vacuous (holder authority holds for any committer; propagation proves `n < n+1`); TLC e2e is vacuous for two invariants and false-green on skip; no CI job runs either. | NEW R20; `bi2462.37` |
| 11 | HTTP/body/WS/gRPC/H3 against independent peers | PARTIAL: h2spec 147/147 on 09-06 (receipts not retained; six H2 commits since). H2 has DoS/drain gaps (no preface timeout, unbounded `pump_writes`, detached handlers not cancelled on RST, unbounded shutdown wait); H1 streaming responses have no write timeout; native gRPC streaming connect refuses on every native call; gRPC client-/bidi-streaming unimplemented on real transports; QUIC has no Retry, so 16 spoofed Initials exhaust H3 handshake slots. | `bi2462.36`; NEW R21-R23 |
| 12 | Files, databases, telemetry for consumers | PARTIAL / REGRESSED: PostgreSQL cancellation of a query parked on the socket never sends CancelRequest (server keeps running it); MySQL has no TLS and no caching_sha2 full auth, and its KILL-on-drop can never run; Kafka teardown hangs in ~half of CI runs; OTLP `export` always errors so `MultiExporter` cannot compose it; production poll counts are always 0; one `ctrl_c()` call disables default termination for all signals process-wide. Real-server evidence ends 09-07. | NEW R24-R26; `bi2462.19` |
| 13 | Remote handles follow region ownership | PARTIAL: default `spawn_remote` is not region-owned; opt-in `run_remote` is, but a silent peer hangs region close (no deadline/keepalive; uninterruptible close) and the origin never renews leases (30 s default). v0.5.0 shipped two remote defects (V3 reply decode; `RemoteCap` lost across `open_child_region`), fixed on main, unreleased. | `bi2462.16`; NEW R27; NEW R35 patch release |
| 14 | Snapshot distribution survives failed peers | PARTIAL: first runs at `8525d7055`. `distribution_hedge_process` 2/2 and `symbol_service_native` 5/5; `symbol_durable_process` 6/7, where continuation restore fails with `HolderNotLive`. The acceptance scale (4 MiB, symbol loss) is still not met. | `bi2462.10`; G2.2 first execution |
| 15 | Membership drives discovery and revocation | PARTIAL: SWIM still an island; authenticated authority path opt-in and unexecuted. | `bi2462.11/.12` |
| 16 | Supervisor trees restart and escalate | WORKING_SCOPED: `supervision_regression` 6/6 at `8525d7055` (ManagedSupervisor public lab, native and SIGTERM journeys); DOC_STALE in README/rustdoc; new fail-open: a required Permanent child whose dependency is gone is silently never restarted and the report ends `Ok`; named children refused; AppSpec still uses the legacy non-restarting supervisor. | `bi2462.34/.35/.46`; NEW R29 |
| 17 | Secure ATP moves real files with bounded resources | PARTIAL: `atp send` defaults to plaintext unauthenticated TCP; RQ control transcript and NeedMore frames unauthenticated; `e880xo` (P0) has had no implementation since 06-15. | `e880xo`; NEW R30 |
| 18 | ATP SDK and CLI expose the promised workflows | STUB for the tracked API: legacy `AtpSession` methods still `NotImplemented`, the older `crate::atp::sdk` fakes success and its `verify_object` never reads content; a parallel native SDK plus `atpd-live` (~21k lines, no bead for `atpd-live`) moves data but has not executed since 09-19; 13 `asupersync atp` commands refuse with E701. | `bi2462.51-.74`; NEW R31 |
| 19 | ATP performance measured honestly | UNPROVEN/STALE: no re-measure since 09-04; `bi2462.4` closed without HyStart++/BDP credit or a WAN receipt; README quotes only the better WAN path; possible tree_small/bad regression (5.9 s → 32-41 s, different host, uninvestigated); scorecards do not bind the measured binary. | `bi2462.5`, `et48up`; NEW R32 |
| 20 | Browser users run, cancel, ship | REGRESSED packaging: committed JS glue calls wasm exports the committed binary lacks (callbacks throw); Pages workflow omits a newly imported module (next deploy breaks the demo); "GA" label contradicted by the artifact's own `RELEASE_CANDIDATE_NOT_GA_SIGNOFF` and 58-day-stale readiness rows; nothing on npm; no browser engine or browser-core compile in any gate; WebTransport datagram queues unbounded. A real wasm32 executor exists in the core crate but is neither exported nor run. | `94g51y`, `yxwno1`; NEW R33 |
| 21 | Dependency sovereignty loses no capability | STALLED (identical counts since 09-04); supply-chain contract lane red on HEAD (hash-pinned manifest drifted); undocumented `benchmark-adapters` Tokio edge inside core `src/`. | `ir2uf0`/`62jqi3`; NEW R34 |
| 22 | RABS consumes a sound substrate | PARTIAL: §44.1 done; 44.2/44.5 partial; 44.4 not started. | unchanged |
| 23 | Default/stable/feature/platform promises compile | Compile GREEN at `8525d7055` for default and all-features (first fresh evidence in weeks); stable, non-Linux and browser-core remain unproven; no CI. | `bi2462.19-.21`; S1 decision |
| 24 | Release consumers receive proved source | REGRESSED: v0.5.0 carries two remote defects fixed only on main; 0.6.0 is unpublished but documented as released; compatibility policy text covers 0.4.x only; 615 commits since v0.5.0. | `yqlhh7`; NEW R35 |
| 25 | Examples/docs/gates describe reachable behavior | PARTIAL, worse: non-compiling README samples; fake-type macro examples cited as proof; 231 never-compiled src files; feature table covers 26 of 64 features. | `bi2462.37/.38`; NEW R36 |
| 26 | Canonical ATP frames | WORKING_SCOPED (unit). | closed `.42/.43` |
| 27 | AppSpec enacts services and authority | STUB: metadata only; legacy supervisor. | `bi2462.46/.47` |
| 28 | Snapshot restore resumes supported work | PARTIAL, narrow, unexecuted. | `bi2462.48-.50` |
| 29 | Managed QUIC progresses on packets/deadlines | PARTIAL: `.75` closed; `.76` proof open; plus uncapped PATH_CHALLENGE/DATAGRAM queues and no Retry (row 11). | `bi2462.76`; NEW R23 |
| 30 | Remote admission protects peers | PARTIAL: opt-in executors ran 10/10 locally before HEAD; not integrated into `NativeRemoteRuntime`. | `bi2462.77/.78` |
| 31 | NEW: a validation path runs for every landed change | BROKEN (S1/S2). | NEW G1-G3 |
| 32 | NEW: every source file is compiled or deliberately archived | BROKEN: 231 orphan files. | NEW R36 |
| 33 | NEW: the tracker reflects the work | BROKEN (S3). | NEW G4 |

### Bridge order (supersedes the September 15 order where they conflict)

1. **Gate: one validation path for every agent (G1), then pay the execution debt (G2) before new
   feature families land.** New beadless subsystems are paused until their first terminal run exists.
   This is not ceremony: first runs of the September code found shipped defects.
2. **Fix the defects that break headline guarantees or ship to users:** `race!`/`select!` loser
   cancellation (R37), default-path obligation admission (`bi2462.28`), retirement-barrier liveness
   (R16), silent-peer remote hangs and lease renewal (R27), supervisor dependency fail-open (R29),
   process-wide signal takeover (R26a), PostgreSQL cancel (R24), native gRPC connect (R22a), browser
   package integrity (R33a/b), HTTP/2 and HTTP/1 slot/shutdown DoS (R21), QUIC queue caps and handshake
   exhaustion (R23a), ATP plaintext default and legacy fake successes (R30).
3. **Release hygiene:** decide and cut a 0.5.1 carrying the remote fixes, correct the false 0.6.0
   release claim, and state the compatibility boundary for 0.5/0.6 (R35).
4. **Make proof unable to lie:** zero-selection and vacuous-lane fixes, orphan-source disposition,
   README samples compiled as doctests (G3, R36, R38, R20).
5. **Then resume vision work** through the existing pairs (`bi2462.8` replay, `.10-.12` distributed,
   `.51-.74` ATP SDK/CLI, `.39-.41` heap, `.44-.50`), now with honest prerequisites (R19, R31).

### New work packages

Every implementation package names its independent proof; "done" means landed code plus a terminal
receipt with positive selected/passed counts and zero ignored/filtered for the named tests, bound to a
commit SHA. Public API changes stay additive unless the owner approves a break (AGENTS compatibility gate).

- **G1 — OWNER: authorize one validation path for all agents (P0 decision).** Decide whether RCH's
  worker-side cache pruning is acceptable under the no-deletion rule (then `bi2462.81` closes as
  "authorized"), or require the retained-artifact route `bi2462.81` describes. Decide whether GitHub
  Actions stays disabled; if so, README/AGENTS must stop citing CI jobs as enforcement and name the RCH
  lanes instead. Until decided, agents without a path must not land code (G3).
- **G2 — Execution-debt burn-down (P0 epic).** One child per area; each runs the exact targets with the
  features they require, records counts, files one bug per red, and treats a zero-test selection as a
  failure: G2.1 runtime/cx additions (resource bracket, worker readiness, dynamic supervision/services,
  `channel::ack`, JoinSet drain) including the seven lib failures in new modules; G2.2 distributed
  (remote_owned, symbol service, two-process distribution/durability, membership authority/owned/scoped/
  persistent, admission, continuation, PBFT); G2.3 ATP native SDK, `atp-live/1` profile and `atpd-live`
  subprocess suites; G2.4 network (gRPC native streams incl. TLS, H3 live UDP, H3 streaming bodies, h2spec
  rerun at HEAD); G2.5 I/O replay sessions and native journeys; G2.6 browser-core Rust (local executor,
  fetch client) plus wasm32 check; G2.7 data (OTLP sender change, SQLite additions) plus the full
  real-server suite at HEAD.
- **G3 — Make never-run code visible and unmergeable (P1).** Every file-level `#![cfg(feature=…)]` test gets
  a `[[test]] required-features` entry; a census test fails on any gated test file without one; the proof
  wrappers reject zero-selection; the pre-push hook refuses pushes whose touched feature-gated targets were
  not checked (via RCH) with an explicit, logged override. No new signoff artifacts.
- **G4 — Tracker truth reconciliation (P1).** Record landed-but-unrecorded work on its beads, attach
  receipts before closing shipped-unclosed beads, open follow-ups for false-closed beads with unmet
  acceptance, clear stale `blocked`/obsolete P0s, and re-rank: at most a few dozen P0/P1 should remain.

- **R16 — Retirement barrier never strands a join (P1 bug).** Teardown (`RuntimeInner::drop`, scheduler
  shutdown) must open or poison every pending barrier so a `TaskHandle` that outlives its runtime resolves
  `JoinError::Cancelled` as documented; add a census of completion paths that must open the barrier.
  Proof: native test that drops runtime A and joins its handle from runtime B under a timeout; a
  never-waking parked task variant; `try_join`/`is_finished` semantics documented.
- **R17 — Explicit runtime lifecycle drains the root region (P1).** Additive `Runtime` shutdown API that
  cancels and drains the root with a budget and returns a drain report; `#[main]` surfaces its drain result
  and drains on the panic path; `spawn_with_cx` docs corrected; `0sd3cp`'s unmet acceptance (drain outcome
  in trace/report, handles observe `CancelReason::shutdown()`) delivered or re-scoped with the owner.
- **R18 — Scheduler reward uses a real clock; fairness bound stated correctly (P1 bug + doc).** The
  Lyapunov snapshot must read the timer-driver time in production; add a test that the deadline/age terms
  move on the native runtime. Replace README's "limit+1 = 17 steps" with the adaptive worst case and add a
  native test measuring `max_cancel_streak` under the default selector.
- **R19 — Production schedule capture prerequisites for `bi2462.8` (P1).** R19a: opt-in production
  emission of Poll/Wake/CancelAck events with bounded overhead; R19b: declare and review the strict replay
  driver (`production_strict.rs` + `wiring.patch`), exhaustion fails closed; R19c: lab DPOR uses vector
  clocks with per-task identities, and `estimated_classes` becomes a true lower bound. Proofs: a
  multi-thread native capture replayed in the lab with an injected divergence caught; a truncated trace
  rejected; a counterexample for the class estimate.
- **R20 — Formal claims that can fail (P2).** Strengthen or reclassify the vacuous Lean theorems
  (`commit_holder_authority`, `cancel_propagation_bounded`, `cancel_protocol_terminates`) in the coverage
  inventory; make the TLC e2e check obligations and region close and fail (not SKIP) inside proof lanes.
- **R21 — HTTP/2 and HTTP/1 servers bound every wait (P1 bugs).** H2: preface timeout, bounded
  `pump_writes` with force-close race, handlers cancelled on RST, an in-flight admission cap, server-
  generated stream errors counted by the reset limiter, bounded shutdown join (N1-N3). H1: streaming
  response write timeout and bounded error-path flushes (N4-N5; `hw83se` was closed on an unmet fix).
  Proof: slow-reader, partial-preface, rapid-reset and shutdown-under-stall tests on real sockets.
- **R22 — gRPC native truth (P1/P2).** R22a: `NativeStreamEndpoint` admits on the real I/O driver
  capability, not the virtual `IoCap` (same predicate audit for ATP rendezvous); R22b: native
  client-streaming/bidi on real transports and hostname dialing; R22c: `Server::serve` probe is clearly
  labelled and the real serving entry point documented. Proof: native plaintext and TLS dial tests.
- **R23 — QUIC/H3 resource and protocol hardening (P1/P2).** R23a (P1): address validation/Retry for the
  managed endpoint, PATH_CHALLENGE and DATAGRAM caps, DATAGRAM rejected unless negotiated (N6, N10,
  N11); R23b (P2): managed key-update initiation and AES-GCM limit, received MAX_STREAMS honored, idle
  timeout in the UDP driver, client Retry handling, encoder-side parameter validation (N12-N15, N23);
  R23c (P2): one request's finalizer failure must not stop the H3 listener (N7).
- **R24 — PostgreSQL cancellation reaches the server (P1 bug, regression).** Send CancelRequest when a
  query parked on the socket is cancelled; real-server test asserts via `pg_stat_activity` that the backend
  stopped. Also TLS trust options (`sslrootcert`, verify-ca/full) and a handshake timeout (P2).
- **R25 — MySQL authentication, TLS and KILL (P2).** TLS and caching_sha2 full authentication so a cold
  MySQL 8 server works; fix the unsatisfiable KILL-on-drop predicate and bound its join.
- **R26 — Process, signal and observability correctness.** R26a (P1): register only requested signals and
  preserve default dispositions for the rest; R26b (P2): reap dropped still-running children; R26c (P1):
  root-cause the Kafka consumer teardown hang; R26d (P2): production poll counts and a correct
  `find_leaked_obligations`; R26e (P2): OTLP exporter composable in `MultiExporter`; R26f (P2): file poll
  traits and `write_atomic` never block a worker under a SPAWN-restricted context.
- **R27 — Remote liveness bounded by leases (P1, children of `bi2462.16`).** A silent peer after `Accepted`
  cannot hang region close: deadline/keepalive, interruptible close bounded by lease plus drain budget;
  origins renew leases automatically; the server echoes the clamped lease. Proof: a TLS listener that
  accepts then goes silent, driven by `run_remote` inside a closing parent region.
- **R29 — Supervision correctness (P1/P2).** Required dependents whose dependency is unavailable escalate
  or fail instead of being silently dropped (P1); managed supervisors support registered names (P2); lab and
  native agree on panic-path loser drain (P2); README/rustdoc describe ManagedSupervisor.
- **R30 — ATP secure and truthful defaults (P1).** Owner decision on the `atp send` default transport
  (authenticated default with explicit plaintext opt-in versus loud refusal off-loopback); remove fake
  successes and the tautological/false-failing `verify_object` in both legacy SDK surfaces; report
  cancellation as cancellation; fix the literal `./~/.atp` path. Compatibility-preserving where public.
- **R31 — `atpd-live` scope decision and SDK convergence (P1).** Decide whether `atpd-live` is a supported
  product, how it relates to `atpd` and SDK daemon delegation (`bi2462.61`), and whether the native SDK
  replaces the legacy `AtpSession` surface; record it before more parallel surfaces land.
- **R32 — ATP measurement honesty (P2).** Scorecards bind the measured binary SHA; investigate the
  tree_small/bad 5.9 s → 32-41 s result; README quotes both WAN paths; reopen `bi2462.4`'s unmet
  HyStart++/BDP/WAN acceptance as a follow-up.
- **R33 — Browser package integrity (P1).** R33a: rebuild and commit matching glue and wasm, plus a check
  that every glue import exists in the binary; R33b: Pages ships every module `index.js` imports; R33c:
  bounded WebTransport queues; R33d: demote the GA label to what the artifact supports (owner via
  `94g51y`); R33e: browser-core compiled in the validation lanes.
- **R34 — Supply-chain lane and Tokio carve-outs truthful (P2).** Refresh the fingerprint contract through
  its reviewed path; document or relocate the `benchmark-adapters` Tokio edge in core `src/`.
- **R35 — Release truth (P1).** Owner decision on a 0.5.1 patch carrying `7883e09ee`/`479d67ed6`; fix the
  CHANGELOG's false v0.6.0 release label, its empty `[Unreleased]` section and the README version lines
  (the git snippet `version = "0.5.0"` cannot resolve against 0.6.0 main); state the compatibility
  boundary policy for 0.5.x/0.6.x; correct README's "all four Phase 6 gates are live" and CI-job claims
  (16 flamegraph-triggering and 8 unsafe-touching commits since 09-15 produced no flamegraph or proof
  note).
- **R36 — Source and sample hygiene (P2).** Owner disposition for the 231 never-compiled `src/*.rs` files
  (wire, archive outside `src/`, or delete with permission); compile README Rust samples as doctests;
  rewrite the fake-type macro examples against the real API.
- **R37 — `race!`/`select!` losers observe cancellation (P1 bug).** Branches built on the caller's `cx`
  must be cancellable when they lose: additive closure form that hands each branch its child `Cx`, a
  migration note, and detection of the hazardous form; drain-correct `Cx`-level hedge; `timeout!`
  rustdoc corrected. Proof: native current-thread and multi-worker tests with a never-waking caller-cx
  `recv` loser and a long `sleep` loser, each under a wall-clock bound.
- **R39 — Find the real 0.5.0 compatibility break (P1, escaped-defect protocol).** The CHANGELOG blames
  `Outcome`'s conditional `Debug` for a downstream break, but that derive is identical at v0.4.3, so the
  true cause is unknown and an unapproved v0.4.3-surface break may be live in 0.5.0. Diff rustdoc JSON of
  v0.4.3, v0.4.11, v0.5.0 and HEAD; reproduce the consumer failure through the same public API; follow
  AGENTS' escaped-defect protocol (old-red/new-green receipt, census, gap analysis); add a public-surface
  diff lane (the root-export-name map alone cannot detect signature breaks) and repair the red
  `api_surface_map_contract`.
- **R40 — Proof-status freshness time bomb (P1, due 2026-09-23 00:00 UTC).** The two remaining `fresh`
  rows (dated 08-23) exceed the 30-day window tonight, failing `proof_status_snapshot_contract`; demoting
  them trips hard-coded `fresh-rch-pass` assertions in two other contracts (the `bi2462.80` trap, fixed
  only for the native row). Either rerun those lanes on RCH and record honest new receipts, or generalize
  the `.80` demotion fix. Also stop wall-clock-dependent contract tests from turning red by date alone.
- **R38 — Proof lanes that cannot report false green (P2).** `run_raptorq_e2e.sh` rejects zero-test
  scenarios; replace the self-comparing libraptorq differential; replace the `cp`/`mv` ATP journey test;
  fill or unregister hollow WebSocket/TLS/DNS conformance modules; root-cause the four RaptorQ decoder
  golden mismatches before any regeneration.


### Ambition pass 1: kill the test-blindness classes, not just the instances

The defects above were not random. Almost every one survived because the test suite has a structural
blind spot of one of six kinds. Fixing the instances without the classes guarantees recurrence, so each
class gets a mechanical detector and a replacement pattern.

| Class | Instances found on 09-22 | Detector (fails CI-equivalent lanes) | Replacement pattern |
|---|---|---|---|
| B1. Self-waking or caller-measured cancellation tests | `race!`/`select!` drain tests use `Cx::current()` losers; PostgreSQL cancel test measures only client wait time; `pc_03_wait_async_cancel_safe` never cancels | A census keyed by the `ResponsivenessRegistry` entries: every cancel-aware stock primitive must have at least one native test whose waiter is a never-waking parked future and whose assertion observes the *remote/owned side effect* (server backend stopped, waiter queue empty), not just the caller's return | Parked-state witness plus side-effect oracle; this also makes the registry consulted by tests instead of decorative |
| B2. Lab-only proof of native behavior | Panic-path loser drain (lab records a drain that never happened), the frozen production scheduler clock, schedule replay | A lab/native differential harness (new R45): each kernel scenario runs on LabRuntime, native current-thread and native multi-worker; outcome kinds and cleanup counts must agree | Metamorphic relation "same program, different runtime ⇒ same outcome class" |
| B3. Tests that are never selected | Every whole-file feature-gated suite without a `[[test]]` entry; 231 orphan `src/*.rs` files; the `run_raptorq_e2e.sh` 0-test PASS | G3 census plus zero-selection refusal plus the orphan census (R36a) | Registered required-features; ratchet on orphan count |
| B4. Tests that assert text instead of behavior | 274 of 397 contract tests never import the crate; README samples never compiled; hollow conformance modules | Freeze (holding: one contract added since 09-01) and compile README as doctests (R36b) | Behavior-first tests; meta tests excluded from any count used as evidence |
| B5. Goldens and oracles without a failure control | UCB1 "determinism golden" with no frozen values; vacuous Lean theorems; TLC invariants over traces with no obligations | Mutation controls (new R47): for kernel hot spots, a mutant must be killed by the named test before the test counts as proof | Mutation-backed acceptance on R16, R37, R29a, `bi2462.28`, R24, R26a |
| B6. Tests whose verdict depends on the calendar or host | Proof-status freshness contracts (R40); host-dependent benchmark deltas (R32) | "now" and host identity are explicit inputs; freshness is a separate named lane | Deterministic verdicts, with dated evidence judged by an explicit as-of input |

Added packages from this pass:
- **R45 — Lab/native differential harness for kernel semantics (P1).** A table of kernel scenarios (spawn/join,
  race/select with parked losers, quorum, hedge, pipeline, map-reduce, region close with finalizers and
  obligations, panic in winner/loser, cancel before first poll) run on all three runtimes with a comparison of
  terminal outcome kinds, cancellation attributions, finalizer counts and obligation conservation. Divergence
  is a failure. Seeds are logged; native runs repeat N times to expose schedule sensitivity.
- **R46 — Main watchdog as the CI substitute (P0).** Until G1 settles CI, an agent-run loop checks every new
  `main` commit on the authorized path (default check, all-features check, the native cancellation contract,
  and the targeted tests of the touched area), posts a receipt on the owning bead, and on red files a P0 bead
  naming the commit and author identity and pings Agent Mail. It is the only mechanism that also covers
  API-created commits.
- **R47 — Mutation-backed proof for kernel hot spots (P2).** Install `cargo-mutants` on a worker (dev tool,
  not a crate dependency) and run it restricted to `Cx::race_drained`, `Scope::race_all`, the obligation
  mailbox admission path, the retirement barrier, the ManagedSupervisor restart loop and the signal
  dispatcher, against their named tests. Surviving mutants become test gaps with beads.

Upgraded acceptance on existing packages from this pass: R16, R37, R29a, R24, R26a and `bi2462.28/.29` each
require one B1-style never-waking side-effect test and one B5 mutation kill; R19a/R19b require a B2
differential run once capture exists.


### Ambition pass 2: measurable exit, parallel tracks, islands and duplicate surfaces

**Exit criteria for this refresh.** R46 (the main watchdog) records each metric, and each has a number:
- Zero self-declared-uncompiled code commits on `main` for 7 consecutive days. At least 95% of `main` commits
  get a green watchdog receipt within 2 hours.
- All seven G2 areas have receipts; every red from them has a bead with a root-cause verdict.
- Every P1 defect in this refresh (R16, R17, R18a, R21a, R21b, R22a, R23a, R24, R26a, R26c, R27a, R27b, R29a,
  R30b, R33a, R33b, R37, R38b, R39, R40) is closed with old-red plus new-green receipts, or explicitly
  re-prioritized by the owner.
- P0 plus P1 unfinished beads fall to 60 or fewer; in-progress beads untouched for more than 30 days fall
  to 10 or fewer; the count of blocked beads with no blocking edge is 0.
- The orphan-source count never increases (ratchet), and the owner decision R36a is executed.
- Vision rows 1, 2, 3, 13, 16 and 20 reach WORKING_SCOPED with receipts.

**Parallel tracks for the swarm.** Each track has an internal order; tracks do not block each other except
where marked.
- T1 Validation: G1 → R46 → G3 → R33e/R38/R47. Everything else consumes its receipts.
- T2 Kernel: R37 → R37b → R36c; R16; R17; `bi2462.28` → `.29`; R29a → `bi2462.34/.35/.46`; R29c; R18a → R18b; R45.
- T3 Network: R22a (G2.4 old-red first); R21a; R21b; R23a → R23b/R23c; R41a-c.
- T4 Data and process: R26a; R24 → R24b; R26c (needs G2.7 services); R25; R26b/d/e/f.
- T5 Distributed: G2.2 → R27a → R27b → `bi2462.16`; `.10/.11/.77` receipts; R42; R43.
- T6 ATP: G2.3; R31 (owner) → `bi2462.51-.74` re-targeting; R30a (owner) and R30b; R32 → `bi2462.5`.
- T7 Browser: R33a → R33b; R33c; R33d (owner via `94g51y`).
- T8 Release and truth: R40 (due now); R39 → R35a; R35b; R34; R36a (owner) / R36b; R44; G4.

**Islands (new R48).** Four audits independently found public machinery with no runtime consumer: the lab
e-process monitor (created, never fed); conformal calibration unused by oracles; evidence ledger and sheaf
checks used only by tests; SWIM; PBFT; the region heap; the plan rewrite engine; the hardened ATP journal;
`MultiExporter`; `TaskInspector` poll counts; the session-typed remote protocol state machines. An island is
fine when labelled; it is a defect when the README describes it as working. R48 produces a census and a
verdict for each island: wire it, label it experimental, or retire it (with owner permission).

**Duplicate surfaces (new R49).** Parallel surfaces that must each be canonicalized or explicitly deprecated
(deprecation allowed, removal not without owner approval): two ATP SDK sessions (one refusing, one faking
success) plus the native SDK; `atpd` and `atpd-live`; three journal implementations; legacy
`CompiledSupervisor::spawn` and `ManagedSupervisor`; standalone `hedge()`, `Scope::hedge` and the proposed
Cx hedge; `Cx::race*` (drop) and `race_drained` (drain). R31 covers the ATP pieces; R49 covers the runtime
pieces and states the migration story for each pair in README.

**Release gates.** `yqlhh7` gets these concrete gates for the next release: an exact candidate SHA; the
native cancellation contract at that SHA; G2 receipts for any area touched since the last release; the
public-surface diff (R39) against the previous release; downstream canaries; CHANGELOG truth (R35b).


### Ambition pass 3: make the design bible's mathematics check the implementation

The v4 design bible already specifies the right mathematics: obligations as a Petri net/VASS (§8.7), schedules
up to Mazurkiewicz equivalence with optimal DPOR as the target (§3.2, §18), and small-step semantics as the
normative model (§19, `asupersync_v4_formal_semantics.md`). Today these are mostly descriptions or islands.
This pass turns each into a checker that runs against the real runtime, where it would have caught a defect
found on 09-22.

- **R51 — Obligation conservation as an online place invariant (P1).** Per region, maintain the P-invariant
  `reserved = committed + aborted + leaked + live` over the obligation mailbox *and* the runtime table,
  including queued admission credits and generation identity. Enforce it at every mailbox drain and at region
  close: always in lab, and in production behind a cheap debug/opt-in flag (atomic counters; benchmark-gated).
  A refused-after-success reservation (the `bi2462.28` default-path defect) violates the invariant at the
  first drain, so the defect class becomes self-reporting instead of silent. Proof: the invariant fires on
  the planted default-path refusal at 8525d7055 (old-red) and holds after the fix; a property test
  (proptest state machine) generates reserve/commit/abort/cancel/close interleavings on lab and native.
- **R52 — Model-based conformance to the operational semantics (P2).** Encode the normative rules (SPAWN,
  SCHEDULE, COMPLETE-*, CANCEL-REQUEST/ACKNOWLEDGE/DRAIN/FINALIZE, CLOSE-*, RESERVE/COMMIT/ABORT/LEAK) as a
  small pure Rust reference state machine. Replay LabRuntime traces, and native traces once R19a capture
  exists, through it in lockstep: any transition the model forbids is a refinement violation with the exact
  event. This is the practical bridge between the Lean-checked model and the Rust runtime that README
  explicitly says does not exist, and it replaces "the Lean model is proved" with "the runtime is checked
  against the model on every lab run". The model is test-only code; it must not become another island
  (it runs in the default lab test lane).
- **Optimal DPOR as the concrete target for R19c/`bi2462.44`.** Use source-set DPOR with wakeup trees
  (Abdulla, Aronis, Jonsson, Sagonas, 2014) over vector-clock happens-before with per-task identities.
  Validate against exhaustive enumeration of Mazurkiewicz classes on small programs, where each class must be
  explored exactly once. An early stop reports `incomplete`, never "exhaustive".
- **Resource-bounded protocol state (R21a/R23a acceptance upgrade).** Give each connection an explicit
  potential function Φ (buffered bytes + queued control frames + live handlers + pending handshakes) with a
  configured bound. Add a stateful fuzz harness (adversarial frame sequences: rapid reset, PING/PATH_CHALLENGE
  floods, window games, partial prefaces, spoofed Initials) whose oracle asserts `Φ ≤ bound` after every
  step and that shutdown completes. This proves the DoS fixes as a class, not per exploit.
- **Anytime-valid flake verdicts (R26c, NATS flake, any intermittent red).** Instead of "run it N times",
  decide "fixed" with a sequential e-value test (the runtime's own `eprocess` machinery). Accept at α = 0.01
  once the product of per-run likelihood ratios against the observed pre-fix hang rate exceeds 100; reject
  at the first hang. This makes the machinery dogfood itself and bounds the false-"fixed" rate.
- **Mutation score as the evidence weight (R47).** A test counts as proof of a kernel property only if it
  kills the relevant mutants (e.g. delete the barrier open on teardown; skip the RST handler cancel;
  `continue` → escalate). Record survivors as gaps.

None of these add a new public API or a new signoff artifact. Each runs in an existing test lane, and each
has a planted defect it must catch.


### Packages added during refinement (not listed above)

- **R41a-c (P2):** DNS in connect is uncancellable and `connect_timeout` spends its budget on the first
  address; WebSocket `ping_interval` is dead config, the handshake read is unbounded and an extension is
  echoed that cannot be implemented; `DesktopRuntimeProfile` installs `BrowserReactor` on native and reactor
  poll errors are swallowed.
- **R42 (P2):** PBFT src docs claim Byzantine-fault-tolerant safety while view change and checkpoints are
  missing and the deprecated `submit` returns a hardcoded result. **R43 (P3):** restart-durable remote
  idempotency. **R44 (P2):** AGENTS RULE 0.5 cites a file that does not exist.
- **R53 (P2):** data-layer batch (NATS lone-subscriber progress and flake, PostgreSQL LISTEN receive API,
  pool outcome mapping, ambient-`Cx` cancel wakers). **R54 (P2):** our RaptorQ decoder on reference packets
  at K ≥ 2048 in default builds, plus a full Table 2 check. **R55 (P2):** runtime-level `spawn_blocking` has no
  owning region. **R23d (P2):** verify the production handshake applies every peer transport parameter that
  the test-only `apply_peer_transport_parameters` handles.

### Phase execution record (September 22)

- Phase 1 (reality check): ten subsystem audits plus root verification of every high-severity claim, and
  eight pinned RCH lanes: the native contract at `8525d7055` (42/42) and at `021cdecaf` (42/42);
  default and all-features checks (clean, 0 warnings); the full lib suite (23,562/23,602, 17 failures
  classified); a filtered tip re-run (16 failures, the real runtime regression confirmed fixed); the on-ramp
  example (ran). The feature-gated suite lanes (tls/test-internals/http3/remote-service; default-feature
  integration; atp-cli; browser-core; rustfmt) were queued behind these and report into G2.
- First-execution lane F1 (pristine `8525d7055`; `tls,test-internals,http3,remote-service`;
  `--test-threads=1`; hz3). 116 tests ran across 14 of 17 targets: 110 passed, 6 failed, plus 1 hang.
  - Green on their first-ever run: `atp_live_stream` 22/22; `remote_owned_native` 11/11; remote
    queue/priority/admission 10/10; membership authority/owned/scoped 10/10; dynamic supervisor service
    2/2; two-process `distribution_hedge_process` 2/2; 22 of the remote lifecycle contract's 39 tests,
    including the cross-process CLI host and probe.
  - Red: `atp_native_sdk_transfer` 19/20, where the 09-22 writer's shutdown hits a 20 s QUIC handshake
    timeout; `membership_persistent_native` 1 failure, `AttemptTimeout` after a process restart;
    `quic_h3_live_udp` 11/15, where two failures are a test-harness executable-size bound and two are
    request deadlines not attributed to `CancelKind::Deadline`.
  - Hang: `remote_tls_listener_parent_cancellation_interrupts_stalled_handshake` sat at 0% CPU in a
    futex wait for more than 12 minutes, so the lane was cancelled; the targets it did not reach were
    re-queued.
  - A future-incompatibility lint (`recursion_depth_exceeding_limit`, "will become a hard error") fires
    in `symbol_service_native`.
  - Receipts are posted on G2.2/G2.3/G2.4 and R27a. The README's "execution of the new Rust
    regressions remains unverified" for NativeH3Listener is now answered: 11 of 15 green.
- First-execution lane F2 (pristine `8525d7055`, default features).
  - Green: `supervision_regression` 6/6; `dynamic_supervision_native` 2/2 and `resource_bracket_native` 4/4
    (both first runs); `atp_rq_symbol_auth_e2e_contract` 4/4; RaptorQ K=2048 encoder differential 1/1 and
    reference vectors 3/3.
  - Red: `e2e_stream_pipeline` 20/21 (native stage-panic attribution); `browser_ga_final_signoff_contract`
    6/8 and `wasm_supply_chain_controls` 5/10, both exactly as predicted by the browser audit.
- Remaining lanes (pristine `8525d7055`).
  - F1b: the remote lifecycle contract 38/38 with the hanging test skipped; `symbol_service_native` 5/5;
    `worker_readiness_native` 6/6; `symbol_durable_process` 6/7, where continuation restore fails with
    `Lease(Admission(HolderNotLive))`.
  - Contracts with as-of 2026-09-23: the proof-freshness time bomb, the red `api_surface_map_contract` and
    the red supply-chain fingerprint contract are all confirmed by execution.
  - `atpd_live_cli` 33/39: the headline multi-file commit fails on the first allowed send, and child stderr
    is not captured.
  - `asupersync-browser-core` lib 59/60, with one refusal-classification mismatch.
  - `cargo fmt --all --check` fails: 3,425 hunks in 187 files, concentrated in the source-only families.
  - Totals across F1, F1b, F2, the contract lane, F3 and F4: 368 tests ran, 342 passed, 26 failed, plus
    1 hang. Each failure has a receipt on its owning bead.
  - A peer had already landed the fix for R22a (`409a695d8`, citing `bi2462.104`) within 90 minutes of that
    bead's creation.
- Phase 2: this section, written in place.
- Phase 3a: 69 beads created under `bi2462` using the frozen generation instructions and only `br`. 24 existing
  beads received evidence comments (landed-but-unrecorded work, unmet acceptance, new prerequisites), and 27
  dependency/related edges were added.
- Phase 4: three ambition passes (test-blindness classes; exit metrics, tracks, islands, duplicate surfaces;
  online invariants, model-based conformance, optimal DPOR, resource-bounded protocol state, sequential flake
  verdicts, mutation-backed proof), then Phase 3a again: 7 more beads (R45-R49, R51, R52) and acceptance
  upgrades on 13 beads.
- Phase 5: five refinement passes. Pass 1 relaxed nine over-strict blocking edges so that execution-debt,
  watchdog and census work does not wait on owner decisions, added four beads for audit gaps that had been
  missed (R53-R55, R23d), and added scope and test-runner requirements to 25 beads. Pass 2 linked four overlaps
  with open beads (`eeexl1.11`, `eeexl1.10`, `qoir1r`, `43zovx`) instead of duplicating them. Pass 3 confirmed
  71 of the 80 new beads are dependency-ready and the other nine are blocked only by deliberate prerequisites.
  Pass 4 corrected R37's deliberate-failure control and attached the tip receipts. Pass 5 found no further
  bead changes (convergence).
- Validation: `br dep cycles` reports 0 active cycles; `bv --robot-insights --label reality-check-20260922`
  computed its cycle metric and found 0.
- Follow-through on 2026-09-23, under the owner's delegation of the open decisions:
  - R40 (`bi2462.140`): the two expiring rows were demoted to `rerun-required` because their lanes are
    red at HEAD (bi2462.136 drift). The two contracts that hard-coded `fresh-rch-pass` now accept any
    known status. The snapshot contract passes 22/22 after the expiry. A deliberate-failure control
    (demoted row, pristine tests) turns exactly the two edited tests red.
  - R36a (`bi2462.141`): option (d). Nothing moves or is deleted. A census in
    `tests/dormant_e2e_inventory_contract.rs` fails if the top-level orphan count rises above 230, and
    the `e2e_hardening_*` reports carry a banner saying that their checkmarks for orphan files are not
    test results. Wiring valuable orphans into real targets stays open on that bead.

### Created task index (September 22)

| Key | Bead | Type | Priority | Title |
|---|---|---|---|---|
| G1 | `asupersync-bi2462.85` | task | P0 | OWNER: authorize one validation path that every agent (including API-created commits) can use |
| G2 | `asupersync-bi2462.86` | epic | P0 | Execution-debt burn-down: first terminal run of every suite landed without execution since 2026-09-15 |
| G2.1 | `asupersync-bi2462.86.1` | task | P0 | Execution debt: runtime/cx additions (resource bracket, worker readiness, dynamic supervision, channel ack, Jo |
| G2.2 | `asupersync-bi2462.86.2` | task | P0 | Execution debt: distributed suites (remote_owned, symbol service, two-process distribution/durability, members |
| G2.3 | `asupersync-bi2462.86.3` | task | P0 | Execution debt: ATP native SDK, atp-live/1 profile and atpd-live subprocess suites |
| G2.4 | `asupersync-bi2462.86.4` | task | P1 | Execution debt: network suites (gRPC native streams incl. TLS, H3 live UDP, H3 streaming bodies, h2spec rerun  |
| G2.5 | `asupersync-bi2462.86.5` | task | P1 | Execution debt: I/O replay sessions (io::replay_session, replay_group, replay_group_session) and their native  |
| G2.6 | `asupersync-bi2462.86.6` | task | P1 | Execution debt: browser-core Rust (local executor, fetch client) and wasm32 build of the core crate |
| G2.7 | `asupersync-bi2462.86.7` | task | P1 | Execution debt: data layer (OTLP sender change, SQLite additions) and the full real-server suite at HEAD |
| G3 | `asupersync-bi2462.87` | task | P1 | Make never-run code visible and unmergeable: required-features registration census, zero-selection refusal, fe |
| G4 | `asupersync-bi2462.88` | task | P1 | Tracker truth reconciliation after the 2026-09-22 reality check (record landed work, fix false/stale states, r |
| R16 | `asupersync-bi2462.91` | bug | P1 | Retirement barrier can strand TaskHandle join forever when a runtime is torn down before the task completes |
| R17 | `asupersync-bi2462.92` | feature | P1 | Explicit Runtime lifecycle drains the root region; #[main] surfaces its drain result and drains on panic |
| R18a | `asupersync-bi2462.93` | bug | P1 | Default-on UCB1/Lyapunov scheduler reward reads RuntimeState::now, which production never advances |
| R18b | `asupersync-bi2462.94` | task | P2 | State the real cancel-preemption fairness bound under the default adaptive selector and measure it on native |
| R19a | `asupersync-bi2462.95` | feature | P1 | Opt-in production emission of Poll/Wake/CancelAck trace events so production schedules can be captured |
| R19b | `asupersync-bi2462.96` | task | P1 | Wire (or retire with owner approval) the fail-closed production replay driver; replay exhaustion must not sile |
| R19c | `asupersync-bi2462.97` | bug | P2 | DPOR race detection degenerate under the lab's forced Lamport clocks; estimated_classes over-counts |
| R20 | `asupersync-bi2462.98` | task | P2 | Formal claims that can fail: strengthen or reclassify vacuous Lean theorems; TLC e2e checks real invariants an |
| R21a | `asupersync-bi2462.102` | bug | P1 | HTTP/2 listener: unbounded preface read and pump_writes, handlers orphaned on RST (Rapid-Reset amplification), |
| R21b | `asupersync-bi2462.103` | bug | P1 | HTTP/1 streaming responses and buffered error-path flushes have no write timeout (slot pinned, shutdown join h |
| R22a | `asupersync-bi2462.104` | bug | P1 | Native gRPC streaming connect_tcp/connect_tls always refuse on the native runtime (wrong capability predicate  |
| R22b | `asupersync-bi2462.105` | feature | P2 | gRPC client-streaming and bidi on real transports; Channel dials hostnames |
| R22c | `asupersync-bi2462.106` | docs | P3 | grpc::Server::serve is a legacy probe that binds and returns Ok without serving; make the real serving entry p |
| R23a | `asupersync-bi2462.107` | bug | P1 | QUIC/H3 remote resource exhaustion: no Retry/address validation, uncapped PATH_CHALLENGE queue, un-negotiated  |
| R23b | `asupersync-bi2462.108` | bug | P2 | QUIC protocol correctness gaps: managed key update/AES-GCM limit, MAX_STREAMS ignored, UDP-driver idle timeout |
| R23c | `asupersync-bi2462.109` | bug | P2 | One request's finalizer/cleanup failure stops the whole NativeH3Listener for every peer |
| R23d | `asupersync-bi2462.157` | bug | P2 | QUIC: verify production applies every peer transport parameter that apply_peer_transport_parameters handles (D |
| R24 | `asupersync-bi2462.110` | bug | P1 | PostgreSQL: cancelling a query parked on the socket never sends CancelRequest (server keeps executing and hold |
| R24b | `asupersync-bi2462.111` | task | P2 | PostgreSQL TLS trust options (sslrootcert, verify-ca/verify-full) and a TLS handshake timeout |
| R25 | `asupersync-bi2462.112` | feature | P2 | MySQL: TLS, caching_sha2 full authentication (cold MySQL 8 login), working KILL-on-drop, less brittle SQL heur |
| R26a | `asupersync-bi2462.113` | bug | P1 | First ctrl_c()/signal() call installs handlers for all ten signals, disabling default termination process-wide |
| R26b | `asupersync-bi2462.114` | bug | P2 | Dropped still-running child processes without kill_on_drop become unreaped zombies; wait_async cancel path unt |
| R26c | `asupersync-bi2462.115` | bug | P1 | Kafka consumer teardown hangs in about half of CI runs after the test body passes |
| R26d | `asupersync-bi2462.116` | bug | P2 | Observability truth: production poll counts always 0; find_leaked_obligations reports healthy obligations and  |
| R26e | `asupersync-bi2462.117` | bug | P2 | OTLP exporters cannot compose in MultiExporter (export always errors); MultiExporter has no production caller |
| R26f | `asupersync-bi2462.118` | bug | P2 | File poll traits and write_atomic block an async worker when the Cx lacks SPAWN or no blocking pool exists |
| R27a | `asupersync-bi2462.122` | bug | P1 | Remote: a silent peer after Accepted hangs region close (no deadline/keepalive; uninterruptible RemoteHandle c |
| R27b | `asupersync-bi2462.123` | bug | P1 | Remote origins never renew leases; any native remote computation over 30 s ends LeaseExpired |
| R29a | `asupersync-bi2462.99` | bug | P1 | ManagedSupervisor silently never restarts a required child whose dependency is unavailable (report ends Ok) |
| R29b | `asupersync-bi2462.100` | feature | P2 | ManagedSupervisor supports registered (named) children |
| R29c | `asupersync-bi2462.101` | bug | P2 | Lab and native disagree on panic-path loser drain in Scope::race/race_all/hedge (lab records a drain that did  |
| R30a | `asupersync-bi2462.126` | task | P1 | ATP: decide and implement secure defaults (atp send defaults to plaintext unauthenticated TCP) |
| R30b | `asupersync-bi2462.127` | bug | P1 | ATP legacy SDK surfaces fake success and give false integrity verdicts (send_object no I/O, verify_object taut |
| R30c | `asupersync-bi2462.128` | bug | P2 | asupersync atp serve writes to a literal ./~/.atp/inbox (no tilde expansion) |
| R31 | `asupersync-bi2462.129` | task | P1 | ATP: decide the canonical SDK/daemon surface (legacy AtpSession vs native SDK vs atpd-live) before more parall |
| R32 | `asupersync-bi2462.130` | task | P2 | ATP measurement honesty: bind scorecards to the measured binary, investigate tree_small/bad 5.9s→32-41s, quote |
| R33a | `asupersync-bi2462.131` | bug | P1 | Browser: committed JS glue calls wasm exports the committed binary does not have (callbacks throw TypeError) |
| R33b | `asupersync-bi2462.132` | bug | P1 | Browser: Pages workflow does not ship webtransport-streams.js, which index.js now imports (next deploy breaks  |
| R33c | `asupersync-bi2462.133` | bug | P2 | Browser WebTransport datagram inbox and pending-write queues are unbounded |
| R33d | `asupersync-bi2462.134` | docs | P1 | Browser: the README "GA" label contradicts its own signoff artifact and 58-day-stale readiness rows; demote to |
| R33e | `asupersync-bi2462.135` | task | P2 | Browser: compile and test asupersync-browser-core and the wasm32 builds in the validation lanes |
| R34 | `asupersync-bi2462.136` | task | P2 | Supply-chain contract lane red on HEAD; undocumented Tokio edge in core src via benchmark-adapters |
| R35a | `asupersync-bi2462.137` | task | P1 | Release decision: publish a 0.5.1 carrying the remote defects fixed only on main (V3 reply decode, RemoteCap a |
| R35b | `asupersync-bi2462.138` | docs | P1 | Release truth: CHANGELOG labels unpublished v0.6.0 a "Release"; README version lines and the git snippet do no |
| R36a | `asupersync-bi2462.141` | task | P2 | OWNER: disposition for 231 never-compiled top-level src/*.rs files (~257k lines, 225 real_*_e2e_tests.rs) |
| R36b | `asupersync-bi2462.142` | task | P2 | Compile README Rust samples as doctests; fix the ones that do not compile against current signatures |
| R36c | `asupersync-bi2462.143` | task | P2 | Rewrite fake-type macro examples cited as proof (macros_basic/nested/race use fake Cx/Scope and drop futures u |
| R37 | `asupersync-bi2462.89` | bug | P1 | race!/select! losers built on the caller's cx never observe loser cancellation (drain hangs or stalls) |
| R37b | `asupersync-bi2462.90` | task | P2 | Drain-correct hedge usable from a real runtime task; timeout! rustdoc no longer claims drain |
| R38 | `asupersync-bi2462.144` | task | P2 | Proof lanes that cannot report false green (zero-test PASS, self-comparing differential, cp/mv journey, hollow |
| R38b | `asupersync-bi2462.145` | bug | P1 | RaptorQ decoder golden-transcript mismatches (4 lib tests) in a module unchanged since 09-08: root-cause befor |
| R39 | `asupersync-bi2462.139` | bug | P1 | Escaped defect: identify the real 0.5.0 public-API/behavior break (CHANGELOG blames an unchanged Outcome Debug |
| R40 | `asupersync-bi2462.140` | bug | P1 | Proof-status freshness time bomb: two fresh rows expire 2026-09-23 00:00 UTC; demotion trips hard-coded fresh- |
| R41a | `asupersync-bi2462.119` | bug | P2 | DNS in connect is uncancellable and untimed; connect_timeout spends its whole budget on the first address |
| R41b | `asupersync-bi2462.120` | bug | P2 | WebSocket ping_interval is dead config (30 s default never read); client handshake response read has no timeou |
| R41c | `asupersync-bi2462.121` | bug | P2 | Reactor fail-open: DesktopRuntimeProfile installs BrowserReactor on native (sockets park forever); reactor pol |
| R42 | `asupersync-bi2462.124` | docs | P2 | PBFT: src docs claim Byzantine-fault-tolerant safety; exported deprecated submit returns hardcoded "consensus  |
| R43 | `asupersync-bi2462.125` | feature | P3 | Restart-durable remote idempotency (dedup survives service restart) |
| R44 | `asupersync-bi2462.146` | docs | P2 | AGENTS.md RULE 0.5 cites /data/projects/AGENTS.md, which does not exist |
| R45 | `asupersync-bi2462.148` | task | P1 | Lab/native differential harness for kernel semantics (same program, three runtimes, same outcome class) |
| R46 | `asupersync-bi2462.147` | task | P0 | Main watchdog: every new main commit gets an authorized-path check and targeted tests; red files a P0 naming c |
| R47 | `asupersync-bi2462.149` | task | P2 | Mutation-backed proof for kernel hot spots (cargo-mutants restricted to named functions and their tests) |
| R48 | `asupersync-bi2462.150` | task | P2 | Island census: public machinery with no runtime consumer — wire, label experimental, or retire (with owner per |
| R49 | `asupersync-bi2462.151` | task | P2 | Canonicalize duplicate runtime surfaces (supervisor spawn vs managed, hedge variants, race vs race_drained) wi |
| R51 | `asupersync-bi2462.152` | feature | P1 | Obligation conservation as an online place invariant (reserved = committed + aborted + leaked + live) in lab a |
| R52 | `asupersync-bi2462.153` | task | P2 | Model-based conformance: executable reference model of the small-step semantics checked against lab (and captu |
| R53 | `asupersync-bi2462.154` | bug | P2 | Data-layer correctness batch: NATS Subscription::next socket reads, PostgreSQL LISTEN receive API, DB pool out |
| R54 | `asupersync-bi2462.155` | task | P2 | RaptorQ: prove our decoder on reference-encoder packets at K ≥ 2048 in default builds (and fix the gated/ignor |
| R55 | `asupersync-bi2462.156` | bug | P2 | Runtime-level spawn_blocking work has no owning region (outside structured concurrency) |

---

*The September 15 and September 4 sections below are retained as history. Where they conflict
with the September 22 section above, the September 22 section governs.*

## September 15 assessment: implementation ahead of validated delivery

**Verdict: substantial runtime implementation and a published 0.5.0 release;
the complete native, distributed, browser, and performance vision remains
partial. Current main is not established as release-ready by this assessment.**
The September 4 work packages below remain the implementation map, except where
this update corrects current state or execution policy. No GitHub Actions are
authorized: all release validation uses the user-required RCH/DSR route. Preserve
public APIs and behavior; neither pre-1.0 status nor an old plan authorizes breaks.

### Assessment basis and limits

- Read AGENTS.md (1,393 lines) and README.md (2,545 lines) completely, plus the
  complete core v4 plan. Revisited the existing bridge plan, formal posture,
  testing guidance, proof artifacts, selected implementation paths and existing
  task descriptions. This refresh is not a new exhaustive line-by-line audit of
  every auxiliary plan/specification or every runtime module. The broader
  September 4 archaeology is historical context, not fresh execution evidence.
- Source checkpoint: `c506c04d6b37c861fb794fa6ef44cdb49d60efbb`. Shared main also
  had uncommitted QUIC transport/UDP and audit-index changes. This is a moving
  shared tree, not an immutable tested candidate.
- Fresh anonymous GitHub/crates.io API checks: v0.5.0 is the latest release,
  published September 12; GitHub points at
  `78b64636e99fea4ea2d868096576021dd3b8e519` with 11 assets. crates.io reports
  0.5.0 unyanked. No open GitHub issues/PRs were returned. These metadata checks
  do not revalidate downloaded binaries, signatures, platform execution or all
  nine published crates. Recent fixes on main are not thereby shipped.
- Initial export census, corroborated by BV: 434 open, 153 in progress, 31
  blocked = 618 unfinished; 11,186 closed and 906 tombstones. There were 57
  non-closed bugs, including three P0s. Counts are not progress percentages.
  This refresh adds one bug and one prerequisite task, so those initial counts
  are intentionally not a claim about the final live tracker.
- CASS release search timed out after 20 seconds. Current source, tracker,
  existing bridge history and fresh registry metadata supply the assessment;
  no successful CASS retrieval is claimed.
- **No fresh Rust build, native test, application E2E, benchmark or Lean build
  ran in this refresh.** Installed RCH 2.0.0 (`3289f5e4e977`) still generates
  automatic scratch/cache deletion in `rch/src/transfer.rs:247` of the RCH
  project. That conflicts with the explicit no-deletion rule. This is an
  execution-policy blocker, not evidence that Asupersync failed compilation.
  No local Cargo fallback is authorized.

### Current vision-to-delivery crosswalk

Here IMPLEMENTED/UNPROVEN means real source exists but this refresh did not
execute the required current-source proof. PARTIAL means the promised workflow
still has a concrete implementation or integration gap. A narrower documented
boundary is not automatically a defect or completion of the broader goal.

| Goal | Current reality and remaining acceptance | Existing work |
|---|---|---|
| Owned tasks, cancellation, region drain | IMPLEMENTED/UNPROVEN at current main. Keep native parked cancellation, exact outcome, callback reentrancy, finalizer and obligation accounting tests first. Three P0 bug tasks remain nonterminal. | `909482`, `runtime-cancel-waker-outer-lock-118ayd`, `bi2462.28/.29`, bug campaign |
| Cancel-correct composition | Scoped pipeline and executing map-reduce now exist; the old "folds only" diagnosis is obsolete. Error attribution fixes and native/public journey proof remain. | `bi2462.32/.33`, `04jqgn` |
| Supervision | `ManagedSupervisor::run/spawn` executes a real region-owned controller; it is no longer correct to say no live controller exists. Native generation/finalizer/signal proof and broader dynamic integration remain separate. | `bi2462.34/.35`, OTP completeness |
| Region allocation | Generation-safe heap machinery is real; runtime-owned placement and workload benefit still require the existing design/implementation/test sequence. | `bi2462.39/.40/.41` |
| Production-to-lab replay | PARTIAL. Seed replay and trace tooling exist; full production capture, fail-closed replay exhaustion and exact alternative prefixes remain open. Default production adaptation versus fixed lab policy needs explicit trace coverage. | `bi2462.8/.9/.44/.45`, `ro6zzy`, `vemwug` |
| Formal guarantees | Six abstract core invariants are represented in Lean; this is not proof of all production Rust, adapters, protocols or arbitrary-future termination. | Existing formal/refinement lanes; `bi2462.37/.38` |
| Native network/server stack | Real reactor, HTTP and QUIC code exists. External H2 conformance, QUIC close/handshake/partial-send behavior and non-Linux execution are still material gates. | `bi2462.36/.76`, `kixe4i`, `nys7lr`, `x2r9zf`, `y1jsbw` |
| Data clients and telemetry | Real clients exist, but current service integration and sparse-feature consumer proof are not supplied by metadata contracts. Preserve typed SQLite diagnostics and bounded resource/cancellation behavior. | `bi2462.19`, `if3ji9`, `p1aa7g`, existing service tasks |
| Distributed ownership and recovery | mTLS named computation transport is a real scoped capability. Snapshot transport, membership generations, region-owned remote leases, per-peer admission and supported continuation restore remain separate unfinished work. | `bi2462.10/.11/.12/.16/.48-.50/.77/.78` |
| ATP native transfer | Real data plane; complete RQ control authentication, resync reliability, incremental efficiency and comparable encrypted/WAN benchmarks remain. Symbol authentication is not transcript authentication. | `e880xo`, `2qas9c`, `sizeku`, `bi2462.5` |
| ATP SDK/CLI | PARTIAL. SDK `send_object` constructs a local actor/handle without sending to a peer; `sync_tree` explicitly refuses. Native CLI transfer capability cannot establish SDK completion. | `bi2462.51-.74` |
| Browser Edition | JS/host-backed boundary and handle ledger exist. Package-integrity status does not establish a Rust-future executor, fresh browser-engine acceptance or npm delivery. Retained `asupersync-wasm` is explicitly a scaffold. | `94g51y`, `yxwno1`, browser storage/stream bugs |
| Platform/default/stable profiles | UNPROVEN as an aggregate. Workspace integration feature unification cannot stand in for independently resolved default production consumers; non-Linux failures require current reproduction. | `z2kt29`, `bi2462.19-.21`, `gxv3dy`, stable lane |
| Performance | UNPROVEN for recent fixes. Dated ATP comparisons include both wins and losses; new congestion/waker changes need paired measurements, not extrapolation. | `8ykza1`, scheduler performance work, `nys7lr`, `bi2462.5` |
| Shipped consumer compatibility | v0.5.0 is publicly listed. Main-only fixes, updated dependency versions and successful metadata checks do not prove downstream applications or a new release. | `nmg80j` consumer migration, `yqlhh7` release gate |

### Concrete new findings and coverage

1. **Expired evidence and an obstructed demotion path:** the snapshot has 37
   claim rows: 27 rerun-required, seven blocked, three labelled fresh. Its native
   cancellation row is dated August 12: 34 days old against a 30-day limit.
   `fresh_claim_evidence_has_a_bounded_structured_date` rejects that date, while
   `native_cancellation_receipt_is_attributed_only_to_its_focused_claim` requires
   the old fresh status and exact old job/count/durations. This is a static
   diagnosis of a deterministic stale-date failure, not an executed Rust RED.
   New bug `bi2462.80` separates historical provenance from current freshness;
   it must not fabricate a rerun, change the clock or discard the old receipt.
2. **Executable validation prerequisite lacked a bounded owner task:** the bug
   campaign already named the no-deletion-safe RCH requirement, but it was only
   a checklist item. New P0 task `bi2462.81` supplies installed-capability,
   lifecycle-retention and native-canary acceptance. It does not duplicate the
   runtime bugs or authorize changes to another agent's work.
3. **Older acceptance text points at forbidden Actions:** `yqlhh7` still names
   publish.yml/workflow_dispatch as the enforcement route. Its source/package/
   lock/profile/terminal-result predicate remains valuable, but must be executed
   by the authorized DSR/RCH release path. Correct this in the existing bead.
4. **Existing tasks cover the major product gaps:** preserve the SDK, replay,
   distributed, browser, heap and platform implementation/proof pairs. No new
   umbrella program is needed. This sampled crosswalk does not prove that every
   auxiliary aspiration has a bead; do not claim complete corpus coverage.

### Bridge order and review refinements

**First: restore trustworthy execution.** Resolve `bi2462.81`; repair honest
freshness handling under `.80`; rerun the native cancellation canary and smallest
prepared regressions on identified source. Code diagnosis can continue while
blocked, but another source-only fix is not a validation milestone. Keep one
coordinated remote build lane and retained first-failure logs.

**Second: close safety defects and consumer regressions.** Prioritize the three
P0s, callback-under-lock/panic fanout, admission bypass, unsent QUIC ownership and
database/browser cancellation or quota bugs. Lift compiler blockers needed to
test those repairs. Every hot-path change gets comparable pre/post measurements;
every affected public API gets an independent downstream canary. Do not close
the 52-consumer migration merely because manifests and lockfiles were updated.

**Third: complete integrated user journeys.** Reuse existing pairs to demonstrate
native root/supervisor drain; production failure capture and lab reproduction;
authenticated ATP SDK two-process transfer, interruption and resume; remote
region ownership under partition and lease expiry; then platform/browser lanes.
An absent-peer SDK test must not pass because a local handle was constructed.
Each journey records admitted work, terminal outcomes, byte/resource bounds and
cleanup, with deliberate negative controls and secrets redacted.

**Fourth: promote an exact candidate.** DSR and RCH only; bind source, lockfile,
toolchain, targets/features, actual package bytes, required native/service/
platform tests, compatibility and performance evidence before publication.
Reject missing, stale, skipped, zero-test, failed and mismatched evidence.
Published download/signature/checksum and consumer smoke checks follow upload.
A focused bug-fix release need not wait for every research extension, but cannot
claim unsupported capabilities or bypass required release gates.

Two deepening passes improved the plan: (1) replace isolated feature completion
with causal public-user journeys; (2) add fault composition at cancellation,
backpressure, authentication, generation replacement and lease boundaries.
Four refinement checks retained distinct concerns: implementation versus proof
coverage; API/wire and ownership preservation; unit/native/process negative
controls and performance comparability; acyclic dependencies and publication
provenance. These checks do not constitute an exhaustive review of all 618
unfinished tasks. Existing implementation/proof pairs remain intact; no feature
is closed by relabelling it, no arbitrary schedule/size target is invented, and
no document/test-count reduction substitutes for product progress.

The pre-update graph check reported zero active cycles; BV found 225 actionable
items and ranked scheduler sharding, SDK admission and production replay highest.
Those graph scores do not override the safety and validation prerequisites above.
The assessment/plan phase can be delivered now; the skill's fresh execution and
whole-project acceptance phases remain blocked or unfinished as stated.

## Current assessment and execution plan

**Verdict: substantial working runtime, incomplete end-to-end vision.** The
kernel, transports, and protocol clients contain real implementations. Recent
root draining, channel obligation registration, production trace projection,
platform repairs, and real-server CI wiring are substantive progress. They do
not establish complete production replay, distributed structured concurrency,
Browser Edition scheduling, universal cleanup bounds, or an aggregate green
release. Finishing the pre-existing backlog would still leave uncovered goals
and several incorrectly specified acceptance criteria.

This refresh governs execution. Sections 0–15 below preserve the September 1
baseline for comparison, **not executable marching orders**. In particular,
their deletion quotas, branch/PR examples, automatic dependency removals,
warning-only API breaks, default-state flip, and relabel-as-feature-completion
alternatives are superseded. No deletion, feature removal, public compatibility
break, or owner decision is authorized by this assessment. Work stays on shared
`main` with exact reservations. Existing passing implementations are retained.

### Evidence and scope

- Root read the complete AGENTS.md and README.md, core v4 plan, existing bridge
  plan, and testing guides. Three read-only archaeology lanes read the formal,
  distributed, browser/server/ATP, dependency, and RABS plans and specifications
  in full, then traced implementation and test call sites. RABS is a separate
  build-system design: its CAS, action cache, and build scheduler are not missing
  Asupersync runtime features. Authored plan/spec/design documents were included;
  deliberately stale fixtures are test inputs, not competing specifications.
- Initial source baseline: `4d1981015cd496b42e6dca90a98443ecc52343d4`.
  Shared `main` subsequently advanced to `b442149fcb6ee2e989e5fc02d7b814566e1d62fc`.
  Findings are static source observations unless a specific execution is cited.
  A source file, closed bead, compiled target, model test, admission receipt, and
  terminal native test are different evidence classes.
- Fresh strict-remote proof on the initial baseline: installed RCH supported
  `--base`, `--clean-overlay`, `--overlay-path`, and `--no-overlay`; the native
  `runtime_abort_vs_cancel_semantics_audit` executed on `hz3`, **34 passed,
  0 failed, 0 ignored, 0 filtered**, exit 0 at 2026-09-04 21:53:38 UTC.
  Log: `/tmp/asupersync-reality-native-20260904.log`. This proves the selected
  native parked-task cancellation contract, not subsequent commits or the whole
  runtime. The deliberate panic sentinel is an expected test input.
- Actual application runs on the same baseline also exited 0 remotely:
  `onramp_level0` printed `hello from asupersync` at 22:00:17 UTC;
  `onramp_level3` completed at 22:08:46 UTC. Logs are
  `/tmp/asupersync-reality-onramp0-20260904.log` and
  `/tmp/asupersync-reality-onramp3-20260904.log`. Level 3 currently injects a
  manual RuntimeState obligation and forces a closed region; it proves that
  illustrative assertion, not the new automatic-permit admission requirement.
- Inspected GitHub CI run `33908913396`, source
  `ead00ca8b4f3920e1802939a9204fd712f99ea34`,
  has actual failures, not merely a dispatch problem: Check/no-mock, lint,
  Linux/Windows tests, full Lean profile, and additional gates. `lake build` and
  TLC passed. Real-server logs show PostgreSQL, MySQL, Redis, NATS, and JetStream
  successes and the intended wrong-password refusal; Kafka times out without a
  terminal suite result. The success-filtered CI API returned zero runs. Later
  pending/cancelled runs are not evidence that these failures remain at HEAD or
  have been fixed. Reproduce each against the revision being promoted.
  At final refresh, CI `33925726681` on `583c44e51cb52c90afc967e4afe29571ca165d74`
  was pending; the separate parity-dashboard drift run `33925726676` had failed.
  The earlier `b442149f` CI run was canceled. None supplies an aggregate green
  result for the completed assessment or a release candidate.
- Shipped: crates.io `0.4.10`, published 2026-09-01 19:08:29 UTC, checksum
  `7e8b505d6aadb778c9c4b0ae174966641f11d578d253b7786f2407b17d5045ec`.
  The release-train bead records its source tag at `997e8d116ae864789f2cb47be90bfd4be5985c4f`.
  GitHub Releases still lists `v0.4.9` as latest. September 4 runtime changes are
  source progress, not a new published crate. Browser package integrity is not
  proof of a running Rust-future scheduler or a current browser-engine run.
- Initial `br` inventory: 11,103 closed, 376 open, 142 in progress, 31 blocked;
  549 unfinished. `bv` found 228 actionable. These are inventory counts, not a
  completion percentage. Deduplication searched the full titles/descriptions/
  notes/acceptance of unfinished issues and inspected relevant closed issues.

### Vision checklist and gap coverage

`PARTIAL` means meaningful implementation with remaining scope; `UNPROVEN`
means the stated claim lacks adequate execution evidence here; `STUB` means
the named public path deliberately refuses or does no requested work.
`WORKING_SCOPED` is reserved for an actual exercised journey. `NO_BEAD` records
coverage before this refresh and is resolved by the new tasks below.

| Goal and measuring stick | Reality and concrete remaining gap | Execution owner |
|---|---|---|
| 1. Cooperative cancellation preserves typed results and cleanup (README §§Cancellation; AGENTS native contract) | WORKING_SCOPED: fresh 34-case native audit; arbitrary non-cooperative code remains outside bounds | Keep native contract first in every runtime-changing lane |
| 2. Root closure drains children/finalizers/obligations (v4 §§6–9) | PARTIAL: explicit root drain and entry macros landed; `block_on`/explicit Runtime Drop retain compatibility; teardown timeout is not quiescence | Existing `0sd3cp` implementation retained; obligation and remote follow-through below |
| 3. Stock permits obey runtime obligation admission (v4 §8) | PARTIAL: channel gateway exists; it returns tickets before `create_obligation` can reject limits/closed regions; refused posts only increment a counter | NEW R1 admission + R1T tests; existing `cv5sqe`, `bi2462.15/.16/.17` |
| 4. Cleanup bounds are inspectable for stock primitives (v4 §7.6; README:249) | PARTIAL / NO_BEAD: no complete primitive responsiveness registry; fairness alone cannot bound arbitrary futures | NEW R2 bounds + R2T tests |
| 5. Pipeline/map-reduce execute structured work (v4 §12) | PARTIAL / NO_BEAD: modules reduce already-collected outcomes; no stage executor/backpressure or spawned map phase | NEW R3 execution + R3T tests; retain existing folds |
| 6. Region allocation has a real runtime consumer (v4 §10) | PARTIAL / NO_BEAD: generation-safe heap/RRef exist; observed heap allocations are examples/tests, not task placement | NEW R4 design, implementation, and lifetime/performance tests |
| 7. Scheduler scaling preserves fairness and cancellation (v4 §11) | PARTIAL / UNPROVEN: unified remains default; current scheduler work is benchmark-gated; a lab policy is not native parallel proof | `sched-hot-path-perf-bt4y5f`, `m9wsza`, their existing benchmark/test children |
| 8. Production failures replay locally (v4 §18) | PARTIAL: projection/driver landed; end-to-end production capture absent; exhausted replay falls back to normal scheduling | Strengthen `bi2462.8`, then `.9`; retain `.6/.7` work |
| 9. DPOR explores causally distinct schedules (v4 §18) | PARTIAL: clock merge exists; seed derivation does not force an exact alternative prefix or prove completeness | NEW R11/R11T; verify original `vemwug` scope separately; preserve `lab-dx-v2-n2v2fi.7` forensic journey |
| 10. Formal claims match executable assumptions (formal semantics §§6,8) | PARTIAL: Lean model/TLC lanes exist; fairness-only termination and exact lab-refinement wording overclaim | NEW R9 reconciliation; actual proof extension remains separate from wording |
| 11. HTTP/body/WS/gRPC/H3 work against independent peers (README network sections) | PARTIAL: real listeners and streaming paths exist; external h2spec result absent, several protocol/CI gates red | Existing `server-stack-hardening-eeexl1`; NEW R8 external HTTP/2 proof |
| 12. File/database clients and telemetry work for consumers (README IO/data) | PARTIAL: blocking/file/client/exporter implementations exist; five real service families ran successfully in inspected CI, Kafka did not terminate | `bi2462.19`, existing data/OTLP/Kafka children; no duplicate service harness |
| 13. Remote handles follow region ownership (v4 §8.4/§16) | PARTIAL: real mTLS named-computation transport; parent region does not yet own every remote lease/drain | Strengthen `bi2462.16`; preserve strict V1–V3 wire |
| 14. Snapshot distribution survives failed peers (v4 §16) | PARTIAL: encode/assign/recover model; only test-double DistributorTransport; sequential waits ignore timeout/concurrency knobs | Strengthen `bi2462.10`, native two-process faults and bounds |
| 15. Membership drives discovery and lease revocation (v4 §16) | PARTIAL: lease-reactor logic is called by manager sync; production orchestration and incarnation-aware rejoin remain | Correct `bi2462.11`, integrate in `.12` |
| 16. Supervisor trees restart and escalate (v4 §14/AppSpec) | PARTIAL / NO_BEAD prerequisite: per-actor loops exist; compiled tree driver missing; dynamic-child bead assumes a running supervisor | NEW R5 driver + R5T; then `dist-otp-completeness-8y37kz.2` |
| 17. Secure ATP moves real files with bounded resources (ATP architecture) | PARTIAL: native transfer exists; WAN performance, bounded memory, incremental/multi-donor behavior still have open acceptance | Existing `bi2462.5`, ATP data-plane/bonding/RaptorQ roots and children |
| 18. ATP SDK and CLI expose the promised workflows (ATP CLI/architecture) | STUB / NO_BEAD: closed SDK/CLI feature tasks coexist with explicit NotImplemented send/receive/resume/cancel/stream and sync/mirror/share/watch paths | NEW R6 SDK + R6T; R7 CLI + R7T; do not reopen the successful fake-success refusal fix |
| 19. ATP performance promises are measured and mathematically justified (ATP adaptive/matrix specs) | UNPROVEN in this audit: no fresh benchmark; adaptive regret example is vacuous at its given horizon; dynamic-reset claim lacks its stated theorem | Existing `j91wza`, `bi2462.5`, adaptive-control and benchmark children |
| 20. Browser users run, cancel, and ship supported workloads (browser plan/WASM) | PARTIAL: shipped ABI manages handles; it does not itself poll Rust futures; browser-engine/package publication freshness missing | Existing decision `94g51y` and publication `yxwno1`; retain feature goal until owner chooses |
| 21. Dependency sovereignty loses no capability (dependency plan/ADRs) | PARTIAL: KEEP/additive decisions and substantial owned components; old removal paragraphs conflict with current parity-gated DAG | `ir2uf0` and existing Rev-5 children; NEW R9 doc reconciliation |
| 22. RABS can consume a sound generic substrate (RABS master plan §44) | PARTIAL / external acceptance: ATP framing, managed QUIC, backpressure, timer regression matter; CAS/action/build ownership belongs to RABS | R10/R10T, R14/R14T, R15/R15T; retain existing nested-timer test; RABS owner runs adapter acceptance |
| 23. Default, stable, feature and platform promises compile independently (AGENTS profiles) | UNPROVEN as an aggregate; integration dev-dep cycle contaminates feature proof; platform CI still has failures | `z2kt29`, stable track, `bi2462.19/.20/.21` |
| 24. Release consumers receive the proved source (release checklist) | PARTIAL: package/source tag repair done; publish workflow depends only on planning, not aggregate behavioral/compatibility gates | Strengthen `yqlhh7` with next-release enforcement and packaged canaries |
| 25. Examples/docs/gates describe reachable behavior (README/testing/plan corpus) | PARTIAL / NO_BEAD for cross-document reconciliation: stale untracked-permit statements, infallible-send prose, unregistered supervision E2Es, strict-JSON/CBOR contradictions | NEW R9 + R9T; use existing docs/tests, no new dashboard |
| 26. Canonical ATP frames bind reproducible transcripts (ATP codec/RABS substrate) | REGRESSED contract / uncovered follow-up: extension HashMap is emitted unsorted and duplicate decoded IDs overwrite; closed `ovjee1` promised canonical/reject-duplicate behavior | NEW R10 fix + R10T; preserve public HashMap type |
| 27. AppSpec manifests enact services and resource authority (AppSpec compiler/reference docs) | PARTIAL / uncovered execution: compiler stores metadata, factories supply empty demo tasks; no actual route/budget/capability enforcement | NEW R12 runtime binding + R12T after live supervision |
| 28. Snapshot restore resumes supported work, not only metadata (snapshot-restore design) | PARTIAL / uncovered execution: proof sketch names absent restore API; suspended arbitrary Rust futures are not serializable | NEW R13 explicit supported-continuation design/implementation + R13T; reject unsupported futures |
| 29. Managed QUIC progresses on packets, deadlines and cancellation (RABS §44.5/QUIC design) | PARTIAL / NO_BEAD: serial receive/timer waits and 1ms polling; remaining duration is passed as an absolute Sleep deadline | NEW R14/R14T; retain engine/Initial-reroute work |
| 30. Remote admission protects peers and lifecycle control (RABS §44.4/v4 admission) | PARTIAL / NO_BEAD: global max-in-flight and coalesced control exist; generic per-peer byte/message/priority/async admission is missing | NEW R15/R15T, distinct from snapshot credit and region-lease tasks |

### Bridge work packages

Each package is a bounded feature or defect with a separate test companion when
it changes runtime behavior. IDs are recorded below after Phase 3a. No package
may close by deleting a promise or changing a test into a source-string check.
No source change is performed by this reality-check session.
Implementation closure means landed code and focused unit/compatibility evidence.
Its independent behavior-test companion runs afterward; the feature pair and
product parent require both. There is no reciprocal implementation-to-test edge.
Design tasks close only their reviewed design and concrete owned prerequisites.

- **R1 — Admit obligations before publishing success (P1, 3–5 days, high risk).**
  `obligation_mailbox.rs:252–278,384–410` mints/posts before admission;
  `state.rs:5018–5044` can reject region/holder/limit. Design a bounded,
  lock-order-safe admission permit or equivalent acknowledgement with rollback;
  retain pending-post credit until resolution, safe state-less Cx behavior, and
  existing channel signatures. Accepted tokens must always resolve exactly once;
  rejected admission must not silently become an untracked success. Explicitly
  settle cross-task holder transfer, late resolution, region close, zero permits,
  queue pressure and runtime teardown. Normal SendPermit drop aborts, it is not
  a planted leak. R1T drives native and lab limits 0/1/N, reserve-vs-close and
  cancel-vs-commit schedules with exact counts, reclamation and deadlock checks.
- **R2 — Publish justified responsiveness bounds (P2, 3–5 days, medium risk).**
  Inventory stock await/commit/mask surfaces with preconditions, unit (polls vs
  time), blocking/IO assumptions, budget composition and explicit unbounded cases.
  Connect real primitive implementations to those bounds; do not infer a time
  bound from scheduler fairness. R2T tests boundaries and deliberately withheld
  progress, including genuinely parked native cancellation and mask-depth cases.
- **R3 — Execute pipeline and map-reduce additively (P2, 4–7 days, medium risk).**
  Preserve fold APIs; add Scope-based execution with bounded interstage capacity,
  deterministic output ordering, four-way Outcome aggregation, loser cancellation
  and drain. No task detachment. R3T covers slow consumers, errors/panics/cancel at
  each stage, empty input, noncommutative reducers, exact cleanup, and a public
  consumer with queue high-water marks and reproducible failure logs.
- **R4 — Give the region heap a safe real consumer (P2, design before code).**
  First settle Pin/address stability, destructor ordering, escaped-handle refusal,
  generation reuse, finalizer/obligation relationships and task/region ownership.
  Keep the current allocator/default untouched. An additive opt-in implementation
  must actually place runtime-owned work/data in the heap, then prove quiescent
  reclamation through public APIs. Separate tests use drop counters, stale handles,
  cancellation, panic and failed admission; compare allocation counts and latency
  against the current path before any default proposal. No automatic unsafe waiver.
- **R5 — Run compiled supervisor trees (P1, 5–8 days, high risk).**
  Consume CompiledSupervisor plans in a region-owned live driver; preserve each
  child's restart policy, topology, intensity window, backoff, and parent escalation.
  Start with a complete bounded static-tree slice; publish which strategies are
  supported, retain unimplemented strategy tasks, and do not call dynamic child
  management complete. R5T covers child panic, sibling restart sets, escalation,
  cancellation during restart/backoff and stable child order in both lab and native
  runs. Dynamic supervision depends on this driver and its behavioral proof.
- **R6/R7 — Finish actual ATP SDK/CLI workflows (P2, decompose by operation).**
  SDK methods must delegate to the maintained native transfer engine through Cx,
  with authenticated transport, progress/backpressure, cancellation and resumable
  session ownership. CLI sync/mirror/share/watch must preserve their documented
  semantics and use that same engine. Mirror planning is read-only by default;
  destructive application requires the existing explicit operator policy. Retain
  the existing typed refusal for unsupported cases. Test companions exercise real
  two-process transfer, byte hashes, interruption/resume, wrong peer/auth, slow
  readers, finite retry budgets and no silent partial-file success. Per-operation
  implementation and tests are split into the following bounded pairs:
  R6A authenticated real-peer session admission (the current helper constructs
  both negotiators locally); R6B file/directory/object transfer with verified
  publication; R6C progress/terminal handle state; R6D streaming; R6E durable
  checkpoint/resume/cancel; R6F authenticated daemon IPC and restart reconciliation.
  Temporary queue emptiness is neither completion nor EOF. `is_complete` must not
  consume progress. Stream close waits for verified final acknowledgement before
  commit and drains its worker; a full queue applies backpressure. R6B/D/E depend
  on admitted sessions and corrected handle lifecycle, not socket reachability.
  R7A covers get/inbox/status/resume/cancel/serve and the existing send routes;
  R7B covers genuinely bidirectional sync/conflicts; R7C mirror plan/apply;
  R7D redeemable share/pairing with expiry/revocation; R7E watch with overflow
  recovery; R7F covers the remaining advertised seed/bench/diagnostic/config/proof
  commands by a complete command-to-handler inventory, reusing working handlers.
  Preserve `ProtocolError::NotImplemented`, `ASUP-E701`, validation precedence,
  exit codes, JSON schemas and old signatures on still-unavailable paths. Each
  operation's proof uses delayed progress/data, lost acknowledgement, wrong peer,
  stale checkpoint, destination conflict and cancel-at-commit where applicable.
- **R8 — Independent HTTP/2 conformance (P1, 2–4 days, proof-first).**
  Existing internal frame assertions and a blocked build did not execute h2spec.
  Pin an independent h2spec binary/version, start the real native H2 listener,
  run the required suite, retain exact failures and fix them in the owning code.
  Empty selection, listener startup failure or harness-only assertions cannot
  pass. Include a known-invalid listener/response negative control and cancellation/
  teardown evidence. This does not prove HTTP/3, browser behavior or all RFCs.
- **R9 — Reconcile the controlling docs with reachable examples (P1, 2–3 days).**
  Revise existing docs in place: permit registration versus no-Cx try paths;
  send-disconnect outcomes; root drain versus teardown; strict JSON V1–V3 versus
  aspirational CBOR; formal fairness/progress assumptions; WASM ledger scope;
  dependency KEEP/parity decisions; ATP mathematical assumptions. Register/fix or
  explicitly mark unreachable channel/signal supervision recipes; the signal
  sketch's Tokio sleep must not be wired into core. R9T compiles/runs the real
  examples with nonzero selection, validates advertised invocation paths, and
  plants a disconnect and missing-test selection. Text agreement alone is not
  behavioral proof. Keep unsupported goals visible and linked to implementation.

### Corrections to existing work, without duplicate feature epics

- `bi2462.8`: distinguish complete replay from an explicitly requested prefix;
  validate trace identity, coverage/gaps and terminal outcomes. Reject tail and
  interior truncation, extra unrecorded work and outcome drift. Do not silently
  switch to normal scheduling and report success. Capture from real production
  workers, then replay the same workload in the lab; handcrafted lab traces do
  not satisfy this acceptance. `.9` waits for this proof before widening claims.
- `bi2462.10`: preserve V1–V3 tags/fields/goldens. Prefer a versioned named
  snapshot computation within the existing envelope; any new transport message
  requires a deliberately versioned negotiated protocol. Honor ack_timeout,
  max_concurrent, hedging, quorum cancellation and parent Cx; a blocked first peer
  must not serialize every replica. Test two actual processes and failed peers.
- `bi2462.11`: MembershipLeaseManager already calls the reactor. Connect real
  discovery events, authenticate membership authority and reject stale incarnation
  replay. A revoked lease stays revoked; higher-incarnation rejoin requires fresh
  lease identity. `.12` composes transport/discovery/lease ownership only after
  their individual tests, then proves restart/partition/heal with public APIs.
- `bi2462.16`: bind remote spawn/lease/result/cancel to the owning region; never
  forge success from transport loss. Preserve JSON compatibility; documentation
  reconciliation is not a substitute for region-close/lease-expiry execution.
- `bi2462.19/.20/.21`: use actual CI failures and platform receipts, not the old
  no-runners premise. Kafka timed out in the inspected run. Required service tests
  must have terminal nonzero results; wrong-password rejection is expected evidence.
  Fix root causes on the selected revision, preserve old failures and first-attempt
  results, and distinguish quarantine/advisory jobs from enforced gates.
- `vemwug`: current source merges vector clocks, so do not implement that obsolete
  fix again. Audit the original synchronization coverage and its test receipt
  before deciding closure. NEW R11/R11T separately owns exact-prefix backtracking;
  it must not silently convert the old clock bug into a different algorithm task.
- `yqlhh7`: enforce release checklist before publishing, including v0.4.3 API/
  behavior comparison, independently resolved default/stable/feature canaries,
  packaged artifact/source/lockfile identity, native cancellation and required CI
  results. A green package dry-run is not a green runtime. Existing `pzpol4` tag
  repair stays closed; its expressly deferred workflow work remains here.
- `ir2uf0`/`62jqi3`: current Rev-5 is no-loss/parity-gated. KEEP and additive
  implementations are valid dispositions; do not automatically remove hex,
  base64, Kafka, SQLite, TOML, YAML, generic Protobuf, regex or CLI dependencies.
  Full generic/public interoperability remains a prerequisite to any cutover.

### Original-workstream coverage and completion rule

| September 1 items | Current disposition |
|---|---|
| A1–A3 | Preserve evidence-based tracker and ownership correction; remove count/one-epic quotas; retain unique ATP acceptance when linking roots |
| A4–A6 | R9/R9T plus existing proof freshness `iwwj4z` and release `yqlhh7`; no separate dashboard required |
| B1–B3 | Retain root drain and channel work; R1/R1T, `.15–.17`, R9; no new warning behavior under 0.4.x |
| B4 | R3/R3T plus existing cancel/drain combinator and plan-rewrite work; low-level drop semantics remain explicit |
| B5–B7 | Retain UCB1 fixes; replay `.8`; existing scheduler performance gates; R4 heap consumer |
| C1–C6 | `.19/.20/.21/.24`, `z2kt29`, `yqlhh7`; actual failed stages and skip refusal, not recreated harnesses |
| D1–D6 | Retain trace export, TLC and oracle improvements; `.8/.9`, corrected `vemwug`, existing adaptive-control/forensics work; R9 proof scope |
| F1–F6 | Existing server-stack implementation and tests; R8 independent H2; R9 current DNS/TLS/WS/H3 scope |
| G1–G6 | Existing file/data/telemetry work, `.19`, Rev-5 dependency tasks; no self-referential conformance promoted as interoperability |
| H1–H4 | `.10/.11/.12/.16`, R5/R5T, R9 strict wire reconciliation |
| I1–I5 | Existing WAN/bonding/RaptorQ proof tasks; R6/R7 implementations; no unapproved file/subcommand removal |
| E1–E5 | Existing browser owner decision and npm publication tasks; retain rebuild, engine CI and Rust IO reachability acceptance |
| J1–J6 | Correct misleading/stale consumers and ship useful proof; do not optimize LOC ratios or delete artifacts as a proxy for product progress |
| K1–K2 | Retain complete Rev-5 capability/parity DAG, strengthen doc joins; no automatic dependency exit |
| L1–L3 | Existing release hardening and canary tasks; no 0.5 default/API decision implied by this plan |

The finish line is a user journey at a named source/package revision with its
failure path, cleanup, compatibility and performance evidence. A documented
limitation is honest communication; it does not complete the original feature.
Unbounded external behavior must produce a scoped refusal/timeout with retained
ownership, not a fabricated bounded-completion claim. Implementation agents pick
up dependency-ready slices via `br ready`; this session supplies the revised plan
and executable backlog, not an assertion that those features have been built.

### Cross-component acceptance added by ambition pass 2

The following boundaries are feature work with companion tests, not additional
signoff metadata. No green component substitutes for a missing join:

- **R10:** serialize ATP extension entries in stable ID order without changing
  `FrameHeader.extensions: HashMap`; reject duplicate IDs under the existing
  canonical-frame contract. Test insertion-order permutations, malformed duplicate
  bytes, transcript equality, round trips and interoperability with old valid
  frames. Closed `ovjee1` is provenance for the promised behavior, not fresh proof.
- **R11:** extend the explorer with opt-in exact-prefix execution and an enabled
  alternative transition. Reuse ForcedSchedule and proven synchronization edges;
  preserve current seeded exploration. Compare explored equivalence classes to
  an exhaustive tiny-state oracle; report unsupported effects and search limits.
- **R12:** bind AppSpec factories to real capability/budget authority and route/
  trigger/service lifecycle, including nested groups through the managed supervisor.
  One real HTTP route, actor and trigger must produce outputs and refuse missing
  capabilities/expired budgets. Empty factories plus quiescence are not acceptance.
  Preserve the existing pure-data compiler and its honest unsupported cases.
- **R13:** specify a versioned workload factory/continuation codec for the finite
  set of supported restorable tasks; validate source/workload/state identity and
  restore resumed effects, outcomes and obligations. Reject arbitrary futures,
  stale generations and unsupported external effects. Metadata validation alone
  remains useful but is not continuation execution. The design is a prerequisite;
  no unsafe rehydration or universal crash-recovery guarantee is implied.
- **R14:** replace the managed QUIC fixed-poll/serial-wait loop with competition
  between actual socket readiness, due deadlines and cancellation. Preserve
  public Instant-taking APIs through a checked same-clock mapping; a relative
  duration is not an absolute runtime Time. Test nonzero epochs, overdue/earlier/
  removed timers, no lost wake, idle-to-burst transitions, saturated send/cancel
  and cross-connection fairness against the actual managed endpoint over UDP.
- **R15:** provide additive per-peer/global message, byte and waiter admission,
  cancellation-aware local reserve/commit, bounded retry-owned state and protected
  authenticated lifecycle-control capacity. Retain current max_in_flight and
  coalesced controls. Two independently controlled remote peers prove isolation,
  bounded memory and cancel/renew/drain progress under data saturation. No user
  priority can impersonate control authority; local commit is not remote
  exactly-once execution. Mixed legacy/admitted callers must either share the
  enforced envelope through a compatible internal path or use genuinely isolated
  transport/driver/queue domains with separately stated bounds. Excluding legacy
  buffers from a counter in the same unbounded queue is not isolation. Test mixed
  saturation and lifecycle controls while preserving existing default behavior.
  Shared remote.rs work requires exact reservations.

Snapshot transport receipts must bind object digest, attempt, replica and peer
authority; wrong-object/stale acknowledgements cannot satisfy quorum. Complete
production replay must prove outcomes and event coverage as well as poll order,
and preserve legacy prefix replay as an explicit compatibility mode. Membership
cannot promote unauthenticated UDP observations into TLS/capability authority.
The integration tests connect these exact boundaries rather than constructing
matching structs on both sides.

### Quantitative and proof discipline added by ambition pass 3

- Use obligation conservation as the R1 oracle: admitted reservations equal
  committed + aborted + explicitly leaked + still-live records; queued admission
  credits and generation identity must prevent an apparent zero during handoff.
  Rejected admission consumes neither capacity nor an accepted-token claim.
  Exercise the actual queue/state boundary with a finite state-machine model and
  native schedules; a model theorem alone does not prove the implementation.
- R11 compares Mazurkiewicz equivalence classes only for a declared finite
  transition system with sound dependency edges. Include a planted missing
  happens-before edge and a spurious independence edge. A search budget ending
  early is `incomplete`, not exhaustive success or a probabilistic guarantee.
- R2 composes only justified finite bounds and explicit environmental premises.
  An infinite cooperative loop is a counterexample to fairness-only termination;
  a thread stuck inside one poll is a counterexample to universal cleanup time.
  Formal docs must distinguish safety, conditional liveness and Rust refinement.
- The ATP adaptive-design regret expression yields about 324 loss units for
  T=200, where normalized cumulative loss is at most 200. That instance is a
  vacuous bound, not evidence of a few-percent overhead. A reset detector does
  not by itself establish the stated dynamic-regret theorem. Existing `j91wza`
  work must define loss/units, admissible process, change budget, tuning and
  finite-horizon comparator, then show paired real goodput/repair/latency/memory
  results. Retain current safe fallback if either assumptions or measurements fail.
- Performance remains a distinct acceptance dimension: reuse the maintained
  benchmark gates, hold payload/security/feature/hardware/worker count fixed,
  record raw before/after distributions and allocation/queue/byte high-water
  marks. Do not substitute a clean-link win for WAN/loss/multi-file behavior or
  silently relax the existing regression threshold. No fresh performance result
  was produced in this assessment. Heap/default/codec/SDK optimizations do not
  ship solely because their design sounds mathematically attractive.
- Release acceptance consumes the actual tested package and exact source/lockfile
  identity, not an independently regenerated lockfile or green metadata job.
  Reuse existing compatibility and consumer gates; test a deliberately mismatched
  package/source identity and a required-stage skip. No new release ceremony is
  needed beyond enforcing those existing conditions on the publishing path.

### Phase execution record

Phase 1 source/vision/coverage audit and Phase 2 bridge revision are complete.
Phase 3a created R1/R1T, R2/R2T, R3/R3T, R5/R5T, R8, R9/R9T as
`bi2462.28–.38`, using the frozen generation instructions and only `br` writes.
Ambition pass 1 expanded feature completion into full SDK/CLI operation pairs,
exposing session self-negotiation, destructive progress peeks, early EOF and
premature stream commit as prerequisites. It preserved the original eleven CLI
workflows and their routing/security modes instead of reducing the goal to send.
Further ambition/refinement and graph results are recorded as they execute.
Ambition pass 2 added canonical ATP transcript repair, exact-prefix DPOR,
AppSpec runtime enforcement and supported continuation restoration, with causal
cross-component proofs and explicit compatibility boundaries. Existing closed
schema/honesty work is preserved; missing execution is tracked separately.
Ambition pass 3 added conservation/generation oracles, exhaustive finite DPOR
comparison, conditional-liveness counterexamples, non-vacuous adaptive-FEC
acceptance and paired performance/package-identity gates. These are concrete
test obligations; no new theorem, benchmark win or release readiness is claimed.
Phase 3a regeneration created 36 more tasks, `bi2462.39–.74`: 47 new tasks
total at this checkpoint. Seventeen existing issues were revised with current
evidence/scope; conflicting original descriptions were retained as explicitly
historical context rather than discarded.
Refinement pass 1 reviewed every core work package and changed nine boundaries:
no denial-to-untracked fallback; complete stock wait inventory; bounded retained
ordered outputs; explicit task-placement ownership; late-generation fencing;
authenticated old/new codec compatibility; fresh-workload prefix reconstruction;
AppSpec authority/budget attenuation; coordinated snapshot cuts and single-owner
recovery. These are recorded in the affected beads' acceptance criteria.
Refinement pass 2 reviewed all 24 SDK/CLI tasks and actual graph edges. It split
implementation closure (code plus focused unit evidence) from feature-pair
completion (implementation plus independent behavior proof), avoiding procedural
cycles. It added missing real-engine/stream/command-proof prerequisites, bounded
optional progress, precise publication granularity, source-aware resume fencing,
complete delegated API/authority coverage, causal relay/mailbox tests, shared sync
semantics and persistent revocation. Unsupported command rows need named children
before the inventory can close; they do not pass the final product gate.
Refinement pass 3 found that generic transport epics did not own managed QUIC
wake/deadline correctness or generic per-peer remote admission. R14/R14T and
R15/R15T became `bi2462.75–.78`, bringing new tasks to **51**. It also corrected
four active dependency API/cutover instructions and strengthened the existing
release task: immutable dispatched candidate, tested lockfile/archive identity,
required terminal stage provenance, and refusal before any registry write.
Refinement pass 4 corrected five additional acceptance boundaries: documentation
implementation versus its later executable proof; stale acceptance fields in the
replay/distributed/CI children; gap roots waiting for their finishing children
without requiring parent closure first; positive selected/passed counts with
explicit failed/ignored/filtered counts; and mixed legacy/admitted remote credit
accounting. Governing compatibility/release requirements now lead the five
affected dependency/release descriptions, with contrary instructions retained
only as marked historical context. No feature was dropped to resolve a cycle.
Refinement pass 5 reread all 51 new tasks, 25 revised tasks, current AGENTS and
the governing plan. It found one acceptance-order deadlock despite a structurally
acyclic graph: Windows repair `.20` waited for aggregate CI `.19`, which now
requires Windows success. The edge is reversed: `.19` waits for `.20`, alongside
macOS `.21`. Windows repair starts from the selected revision's actual failure
and retains two successful native suite runs; it does not wait for a completed
aggregate. A sixth review is required because pass 5 made a substantive change.
Refinement pass 6 reached **no-change convergence**. It compared all 76 reviewed
tasks with pass 5, confirmed only the two Windows/aggregate records changed,
rechecked their actual prerequisite direction and found no further substantive
scope, acceptance or dependency correction. All three ambition passes, bead
generation/regeneration and six refinement passes are complete.

Final validation: `br dep cycles --json` found **zero active cycles**;
`bv --robot-insights --label reality-check-20260904` actually computed its cycle
metric and found **zero cycles**. Full-graph `bv` skips that metric above its
size threshold, so its empty cycle list is not used as proof. Final
`bv --robot-triage` reports 427 open, 142 in progress, 31 blocked: **600 unfinished**,
including the 51 new open tasks. Its actionable count is 206; `br ready` returns
27 under its own readiness/defer rules, including corrected Windows `.20`.
Twenty-five existing tasks had their scope, acceptance or prerequisites revised.
No existing issue changed status and no implementation gap was closed by this
assessment. All new dependency references resolve.

### Execution priorities after this assessment

1. Take the bounded, dependency-ready correctness repairs first: R1 obligation
   admission (`.28`), R10 canonical ATP extensions (`.42`) and R14 managed QUIC
   readiness/deadlines (`.75`), each with its independent behavior companion.
   Reserve exact paths; their readiness is not permission to cross peer ownership.
2. Complete the existing real capture/replay path (`.8/.9`) and live supervisor
   foundation (`.34/.35`). The latter unlocks actual dynamic supervision and
   AppSpec services; a computed restart plan is insufficient.
3. Progress SDK session/handle/transfer prerequisites into the operation-specific
   CLI journeys; retain the independent route, interruption, authority and
   restart tests. R15 admission and existing distributed `.10/.11/.16/.12`
   remain separate correctness joins rather than one generic transport epic.
4. Repair actual required CI/platform/service failures and rerun them on the
   candidate being promoted. Existing `yqlhh7` must enforce that candidate's
   compatibility, package and terminal proof identity before publication.
5. Use the existing Browser and dependency-scope decision tasks for genuine
   owner decisions. Continue compatible, useful work independently; KEEP/DEFER
   evidence and honest limitations do not erase unimplemented product goals.

### Created task index

All IDs below have prefix `asupersync-bi2462.`. Implementations include focused
unit tests; the paired proof task is independently required for product completion.

| Work package | Implementation/design | Independent proof |
|---|---|---|
| R1 obligation admission | 28 | 29 |
| R2 responsiveness bounds | 30 | 31 |
| R3 executing combinators | 32 | 33 |
| R5 live supervisor | 34 | 35 |
| R8 external h2spec | 36 (proof and discovered fixes) | 36 |
| R9 controlling docs/recipes | 37 | 38 |
| R4 safe runtime heap | 39 design, 40 implementation | 41 |
| R10 canonical ATP extensions | 42 | 43 |
| R11 exact-prefix DPOR | 44 | 45 |
| R12 AppSpec runtime bindings | 46 | 47 |
| R13 supported continuation restore | 48 design, 49 implementation | 50 |
| R6A real peer session | 51 | 52 |
| R6C progress/terminal lifecycle | 53 | 54 |
| R6B file/directory/object transfer | 55 | 56 |
| R6D streaming | 57 | 58 |
| R6E checkpoint/resume/cancel | 59 | 60 |
| R6F daemon IPC | 61 | 62 |
| R7A persistent control/routes | 63 | 64 |
| R7B bidirectional sync | 65 | 66 |
| R7C mirror plan/application | 67 | 68 |
| R7D share/pairing | 69 | 70 |
| R7E watch | 71 | 72 |
| R7F remaining command coverage | 73 | 74 |
| R14 managed QUIC wake/deadline | 75 | 76 |
| R15 protected peer admission | 77 | 78 |

---

## September 1 historical baseline (superseded execution instructions)

**Purpose.** This is the Phase 2 deliverable of the reality check run on
2026-09-01: a complete, granular plan to close every gap between what
README.md promises and what the code delivers, so that the README becomes
literally true and the project reaches its stated goals with the highest
quality, reliability, and performance. It is written so that Phase 3a can
turn it into beads without consulting any other document: every item carries
its own WHY (the observed gap with file:line evidence), WHAT (the change),
HOW (design constraints), ACCEPTANCE (a positive observable, a planted
negative, and a no-claim line), DEPENDS, SIZE, and RISK.

**How this plan was grounded.** Eleven read-only auditors covered every
README section with file:line citations; pristine-HEAD lanes ran on the rch
fleet; the tracker (12,506 beads) was analysed in full; crates.io, npm,
GitHub Pages, and CI were checked. The Phase 1 report is at
`/data/tmp/asupersync_reality_check_2026-09-01.md`. Beads already filed from
Phase 1 are referenced by id where an item maps to one.

**Binding rules for anyone executing this plan.**
- Real code + real tests in the same unit of work. No `todo!()`, no
  weakened assertions, no golden regeneration to force green, no
  fixtures/mocks presented as live proof. Every test names its planted
  negative and its no-claim line.
- No new process artifacts (contracts, ledgers, signoff packets, dashboards)
  unless the item names the feature they gate, their consumer, the observed
  defect class, and their deletion condition. Workstream J is a deletion
  workstream, not an authoring one.
- Additive public API only until a deliberate semver boundary; v0.4.3
  compatibility is a hard gate (AGENTS.md). Items that need a break say so
  and are parked behind the 0.5 boundary (Workstream L).
- Closure comes from an independent verifier citing green evidence bound to
  an exact revision. Beads whose owner has left are closed by the verifier
  or reopened with an incident comment, never by the author.
- Commit rate is not a KPI. Land coherent, verified units.

---

## 0. Ground truth at the start of this plan

Verified on pristine HEAD on 2026-09-01 (rch, clean overlay, remote required):

| Lane | Result |
|---|---|
| `onramp_level0`, `onramp_level3` | pass |
| `runtime_abort_vs_cancel_semantics_audit` | 34/34 |
| `e2e_web` | 40/40 behavioral rows; the one README-marker row fixed |
| `cargo check --all-targets` (default features) | clean except the lib-test target, healed in `b5dd9f8aa` |
| `cargo test --lib --features test-internals` (in-source unit tests) | 22,197 passed, 4 failed, 24 ignored (first full run in weeks) |

The four lib-test failures at HEAD `b5dd9f8aa`: two ambient-audit governance
drifts (`audit::ambient::tests::{known_findings_reference_real_code,
ambient_authority_does_not_regress}`), and two body-lifecycle tests in the
active server-stack area
(`http::h1::server::tests::streaming_server_refuses_actual_chunked_bytes_over_limit`,
`web::multipart::tests::streaming_multipart_refuses_metadata_before_body_ownership_and_observes_cancellation`).

Landed on 2026-09-01 during the follow-through (all with behavioral tests):
entry-macro runtime defaults (`#[main]` multi-thread + on-demand blocking
pool), `Runtime::task_inspector`/`Runtime::diagnostics` +
`Diagnostics::explain_cancellation`, executable `Scope::quorum` and
`Scope::first_ok`, MySQL `mysql_native_password` behind the existing opt-in,
`HttpClientBuilder::add_root_certificate` so the pooled client can do HTTPS
against a private root, README/WASM doc truth corrections, the lib-test
target heal, 15 lib clippy lints for the CI lint job.

Shipped reality: crates.io 0.4.10 (published 2026-09-01), 68 reverse
dependencies, about 30 sibling consumers on the development host, almost all
with `default-features = false`.

---

## 1. Program structure

Twelve workstreams, ordered by leverage. A and C are prerequisites for
trusting anything else. B, D, F, G are the product core. E, H, I are
decisions first, then work. J is deletion. K and L are governance of the
program itself.

| WS | Name | Why it comes where it does |
|---|---|---|
| A | Truth reset (tracker + docs) | Without it nobody can see what is undone |
| C | One green pipeline | Without it regressions are invisible |
| B | Kernel promises made structural | The README's headline guarantees |
| D | Lab and production converge | "Deterministic testing is default" |
| F | Server stack | Where most consumers live |
| G | Data and observability | Second-most used surfaces |
| H | Distributed and actors | Phase 4 of the roadmap |
| I | ATP and RaptorQ | The largest sub-project by LOC |
| E | Browser Edition | Decision-gated; wrong claims today |
| J | Governance diet | Reclaim effort; keep only gates that gate |
| K | Dependency Sovereignty decision | Half the backlog |
| L | Release train and semver boundary | Where breaks and tags live |

Dependency graph (coarse): A.1 -> everything (tracker legible); C.1 -> C.2..C.6
and every "green in CI" acceptance; B.1 -> B.4 (shutdown drain uses root
cancel); B.2 -> D.6 (obligations visible to oracles); D.2 -> D.3 (replay
needs the production scheduler in lab); E.1 decision -> E.2..E.5; K decision
-> J.3; L.1 -> every future release.

---

## 2. Workstream A: truth reset (tracker and docs)

### A.1 Close landed-but-open beads with evidence
- WHY: 161 of 177 in-progress beads have a landing commit on main; 113 carry a "shipped <hash>" comment; 98 belong to agents unseen for 45+ days. The tracker hygiene pass on 2026-09-01 closed only 2 under a strict protocol and classified 84 as SHIPPED_PARTIAL and 48 as "code on main, proof never ran" (BronzeHill's July 15 sync-primitive fixes). The full lib-test run at HEAD now provides that proof for the in-source tests.
- WHAT: for each of the 48 "proof never ran" beads, map the bead to the in-source tests its landing commit added (`git show --stat <hash>`), confirm those tests are in the 22,197 passing set of the 2026-09-01 lib-test run (or rerun the target), and close with reason "shipped at <hash>; <test names> green in lib-test run <log>". For the 84 SHIPPED_PARTIAL, split: close those whose remaining note is only "pending proof" once the proof exists; leave those with real remaining scope open but re-assign to nobody with a dated note.
- HOW: no closes without a test name and a run receipt; a close comment must cite both.
- ACCEPTANCE: in-progress count drops below 60; every remaining in-progress bead has an assignee active in the last 14 days or is unassigned with a dated "why still open" comment. Planted negative: a bead whose landing commit's tests are not in the passing set must not be closed by this pass.
- DEPENDS: none. SIZE: 1 day. RISK: low. BEAD: none yet (filed as part of Phase 3a).

### A.2 Blocked labels and orphan epics
- WHY: all 31 "blocked" beads have zero blocking edges (the 2026-08-10 DB recovery pruned 264 edges); 294 non-blocked beads have open blockers; `asupersync-ir2uf0` (Dependency Sovereignty root) has zero children; `asupersync-86fe9v` has all children closed but sits blocked under a signoff artifact that says `parent_close_allowed=false`.
- WHAT: for each blocked bead, either add the real blocking edge or flip to open with a note; parent the dep-plan phase epics under `ir2uf0` or delete the empty root (Workstream K decides); close `86fe9v` once its signoff artifact is either refreshed or retired (J.5).
- ACCEPTANCE: `bv --robot-alerts` shows zero blocked beads without an edge; no epic with zero children.
- DEPENDS: K.1 for the dep-plan epics. SIZE: half a day. RISK: low.

### A.3 Merge the three rsync-killer roots
- WHY: `rmk81s` (open), `arq-quic-epic-b0k8qo` (in progress, no assignee, 76 days), `317hxr` (open) are three competing roots for the same goal ("atp beats rsync"), each with its own done-criteria; bv flags the missing links.
- WHAT: one root with one done-criterion per tier (nocrypto, auth, encrypted), children re-parented, the other two closed as superseded with pointers.
- ACCEPTANCE: exactly one open epic titled with "rsync" and one dependency chain; the encrypted-tier criterion names the exact cell table it must win.
- DEPENDS: none. SIZE: half a day.

### A.4 README one-page truth block
- WHY: README is 189 KB with 36 lines over 600 characters; the Limitations and Roadmap tables are the closest thing to "what works" and they were wrong in six places until 2026-09-01. Newcomers and agents need one screen.
- WHAT: a "What works, what does not, what is next" block of at most 40 lines at the top of the Limitations section, regenerated from a checked list (not prose): each row = surface, status word (WORKING/PARTIAL/PREVIEW/NOT_STARTED), the single test or lane that proves it, and the bead if open. Keep the long no-claim prose below it.
- HOW: the block is checked by an existing contract test only if that test also fails when the named proof lane is red (otherwise it is ceremony; see J.1). Prefer a script that generates the block from a small JSON list committed next to the README and a test that the generated bytes match.
- ACCEPTANCE: block present; every WORKING row names a test file that exists and ran green in the latest CI run; a planted stale row (test file removed) fails the check.
- DEPENDS: C.1 (so "ran green in CI" is meaningful). SIZE: 1 day.

### A.5 Remaining README corrections
- WHY: after the 2026-09-01 doc batch, these remain wrong or stale: the FAQ "Is this production-ready?" still describes browser and RFC6455 coverage in older terms; the Documentation table lists `docs/api_audit.md` which is at "Version 0.1" from January and lists ~45 modules against 121 `pub mod` today; `docs/replay-debugging.md` claims "Production debugging: Yes" with a `regression_issue_123` placeholder; `docs/WASM.md` still contains the "cooperative scheduler" paragraph at lines 661-676 in older copies of the doc (corrected 2026-09-01 at the Runtime Model heading; re-check the whole file); TESTING.md lists 11 oracles where the code has 26 modules and contradicts itself on obligation_leak test counts (823 vs 754).
- WHAT: correct each; delete `docs/api_audit.md` content that is stale in favor of `artifacts/api_surface_map_v1.json` (or regenerate it from the map).
- ACCEPTANCE: a grep for `regression_issue_123` returns nothing; TESTING.md oracle list equals `ls src/lab/oracle`; api_audit is either regenerated with a date or reduced to a pointer.
- SIZE: half a day.

### A.6 CHANGELOG and version drift guard
- WHY: README said 0.4.9 while crates.io had 0.4.10; CHANGELOG dated v0.4.10 to 08-30 with no tag; the Version Timeline lacked the bullet until 2026-09-01.
- WHAT: a release-time check (part of L.1) that README's crates.io snippet, Cargo.toml version, the CHANGELOG timeline, and the git tag agree.
- ACCEPTANCE: running the check at HEAD passes; bumping Cargo.toml without the others fails it.
- DEPENDS: L.1. SIZE: hours.

---

## 3. Workstream B: kernel promises made structural

### B.1 Root region closes to quiescence on entry-future return
- BEAD: asupersync-gap-root-region-quiescence-0sd3cp (P1).
- WHY: `block_on` returns as soon as the main future completes (src/runtime/builder.rs ~3520-3535) and `RuntimeInner::drop` (~4862-4915) joins workers and drops state without cancelling or draining the root region; `shutdown_timeout` is a teardown bound only. Tasks that outlive `main` are abort-by-dropped: finalizers, cleanup budgets, and the request/drain/finalize protocol never run for them. This is the README's headline "no orphan tasks / cancellation is a protocol" not holding at the top of the tree.
- WHAT: (1) `Runtime::shutdown_with_drain(bound)`: request cancellation on the root region, drive the scheduler until the root region reports quiescence (no live tasks in unified state and dispatch table, no pending obligations, finalizers done) or the bound elapses, then perform today's teardown. (2) The entry macros call it after `block_on` returns with a default bound (2 s, configurable via a new `drain = "2s"` macro argument; `drain = "0"` restores drop). (3) `Runtime` drop for explicit `RuntimeBuilder` users is unchanged (compat) until the 0.5 boundary (L.3), where drain-by-default becomes the rule.
- HOW: reuse `cancel_request` on the root region and the existing `advance_region_state` machinery; the wait loop must yield the state lock between checks (never hold B across a park); non-cooperative tasks are dropped at the bound and their handles observe `CancelReason::shutdown()`; record `drain_completed`/`drain_timed_out` in trace and in the runtime's terminal report.
- ACCEPTANCE: native-runtime test: a task that checkpoints in a loop with a cleanup counter must have its cleanup run before the process reaches the end of `main` (counter == 1 observed after `main` returns through the macro); a planted non-cooperative task (never checkpoints) is dropped only after the bound elapses and the report says `drain_timed_out`; LabRuntime oracle shows no obligation leak in the cooperative case. No-claim: non-cooperative code is not bounded; LabRuntime semantics unchanged.
- DEPENDS: none. SIZE: 3-4 days. RISK: medium (shutdown paths are the most hardened code in the crate; every step needs the abort-vs-cancel contract green).

### B.2 Stock permits are runtime obligations
- BEAD: asupersync-gap-permits-as-obligations-cv5sqe (P1).
- WHY: mpsc/oneshot/broadcast `SendPermit`s and `SemaphorePermit`s never register an `ObligationKind` record (zero references in src/channel/{mpsc,oneshot,broadcast}.rs and src/sync/semaphore.rs); only session-tracked permits and `IoOp` do. The lab futurelock and leak oracles are blind to the most common permits, and the README says they are tracked.
- WHAT: when a permit is reserved through a `Cx` that carries runtime state, mint an obligation id from the existing arena and resolve it on send/abort/drop; a state-less `Cx` keeps today's untracked behaviour. Same for `Semaphore::acquire`. Public signatures unchanged.
- HOW: no allocation on the fast path (obligation ids are indices; the record lives in the existing table); the mpsc reserve/send benchmark rows in `methodology_baselines` must not regress beyond the gate; obligations resolved on the send path must not take the state lock inside the channel's own lock (lock order C after A/B).
- ACCEPTANCE: LabRuntime test: reserve an mpsc permit inside a task, complete the task without sending, and the obligation-leak oracle names the permit kind; a semaphore permit held across a task that stops being polled triggers futurelock; planted negative: a permit that is sent is never reported; baseline bench rows within the gate.
- DEPENDS: none. SIZE: 3 days. RISK: medium (hot path).

### B.3 `Outcome` misuse guard
- WHY: `mpsc::SendPermit::send` returns `Outcome<(), SendError<T>>` and `Outcome` has no `#[must_use]`, so the README's own `permit.send(i);` silently drops `Disconnected`.
- WHAT: `#[must_use]` on `SendPermit::send` (and the oneshot/broadcast equivalents), not on `Outcome` itself (which would warn in every consumer). Update the README examples to `let _ = permit.send(i);` where ignoring is intended, or to handle the outcome.
- ACCEPTANCE: a doc-test or UI test shows the warning fires for an ignored send; consumers using `default-features = false` compile without new warnings for other `Outcome` uses. No-claim: does not make loss impossible, only visible.
- SIZE: hours. RISK: low (warning only; a consumer with `deny(warnings)` and an ignored send would break, so note it in CHANGELOG).

### B.4 Executable pipeline and map_reduce, drain-correct hedge and timeout
- BEAD: asupersync-gap-loser-drop-combinators-1pupkj (P2) covers hedge/timeout.
- WHY: after 2026-09-01, quorum and first_ok execute (`Scope::quorum`, `Scope::first_ok`); pipeline and map_reduce are still folders only; `hedge()` (src/combinator/hedge.rs:19-21) and `time::timeout` (src/time/timeout_future.rs ~278-296) drop losers while docs claim drain; plan-execute race nodes drop (~781).
- WHAT: `Scope::pipeline(stages)` with bounded channels between stages and cancel/drain of downstream stages; `Scope::map_reduce(inputs, map, monoid)` spawning the map phase and folding; `hedge()` and plan-execute race nodes protocol-cancel and join losers when a spawn-capable `Cx` is available, else document drop explicitly; fix the src/combinator/timeout.rs header to describe what `time::timeout` does.
- ACCEPTANCE: tests mirroring the quorum/first_ok suite: losers' cleanup counters equal the loser count immediately after return; pipeline backpressure test proves a slow stage bounds the fast producer (queue depth never exceeds capacity); planted negative: a loser that ignores cancellation is reported after the bound rather than silently dropped.
- DEPENDS: none. SIZE: 3 days.

### B.5 UCB1 policy in lab replay and the ignored determinism golden
- BEAD: asupersync-gap-ucb1-lab-replay-my2vov (P2).
- WHY: README says the default-on discounted-UCB1 policy is "part of replay"; LabRuntime uses a fixed limit (src/lab/runtime.rs ~5221-5251); the only replay-determinism golden has been `#[ignore]` since 2026-04-22 (three_lane_tests.rs ~9737); the surviving test ignores its seed.
- WHAT: either carry adaptive policy state through the lab scheduler (D.2 makes this natural) or state in README that the policy is production-only; repair and un-ignore the golden or replace it with a same-seed-twice diff of the arm-choice trace.
- ACCEPTANCE: the golden runs (not ignored) in `cargo test --lib`; a one-line perturbation of the discount factor makes it fail.
- DEPENDS: D.2 preferred. SIZE: 1-2 days.

### B.6 State shape default
- WHY: README describes sharded state as the runtime's structure; the default is `StateShape::Unified` (src/runtime/config.rs ~2238); the flip is gated on the E1.3 perf dossier (bt4y5f.2.3, m9wsza, both stale).
- WHAT: finish the dossier (rerun the four lever benches with the Phase 6 gate) and flip the default, or keep Unified and reword README's "Sharded Runtime State" section to "available shape".
- ACCEPTANCE: either the default is Sharded with the bench gate green and the abort-vs-cancel contract green on both shapes, or README no longer implies sharding is the default.
- DEPENDS: C.1. SIZE: 2 days (bench time dominated).

### B.7 Region heap consumer or relabel
- WHY: `RegionHeap`/`RRef` is real and tested but nothing outside `src/types/rref.rs` tests allocates into it (`RegionRecord::heap_alloc` has no runtime caller).
- WHAT: decide: wire region-scoped allocation for task futures (a real design, several weeks) or mark the README section "implemented, not yet used by the runtime". Recommendation: relabel now, open a design bead for the wiring.
- ACCEPTANCE: README sentence matches; a bead exists with the design sketch.
- SIZE: hours (relabel).

---

## 4. Workstream C: one green pipeline

### C.1 `ci.yml` green on ubuntu
- WHY: the CI workflow has never had a green run. Last completed run: the lint job failed inside the lib (12 clippy errors, fixed 2026-09-01 in the working tree along with 3 newer ones and 4 in files outside the helper's scope), the Check job failed on rustfmt of a governance test (fixed), the Test job was killed at 7 minutes (runner shutdown mid-compile).
- WHAT: land the lint fixes; split the test job into shards (lib tests; integration tests by name prefix) each under the runner limit; cache the target directory; make the workflow required.
- ACCEPTANCE: three consecutive green runs on main; a planted failing test in a PR turns the run red.
- DEPENDS: none. SIZE: 2 days. BEAD: none yet.

### C.2 Non-Linux jobs
- BEAD: asupersync-gap-nonlinux-reactor-ci-gxv3dy (P1).
- WHY: Windows rustc crashed compiling the lib; macOS lib suite had 234 failures (net socket-option and GSO/sendmmsg "supported targets" rows, tls::acceptor, runtime); kqueue "conformance" runs a Linux-side model.
- WHAT: required `cargo check --lib` and `cargo test --lib` on macos-latest and windows-latest; triage the Windows crash (toolchain/target-feature) and gate Linux-only assertions with cfg.
- ACCEPTANCE: both jobs green three times; README platform matrix updated to the exact status.
- SIZE: 3-5 days. RISK: medium (unknown platform bugs).

### C.3 Real-server services in CI
- BEAD: asupersync-gap-real-server-ci-aoovsx (P1).
- WHY: no workflow sets REAL_POSTGRES_TESTS / REAL_MYSQL_TESTS / REAL_KAFKA_TESTS / REDIS_URL; NATS tests skip without a server; drift against real servers is undetectable.
- WHAT: a job with `services:` containers (postgres, mysql, redis, nats, redpanda) running those exact suites with the matching features.
- ACCEPTANCE: all five suites report nonzero tests and pass; a planted wrong password fails.
- SIZE: 2 days.

### C.4 Remote, chaos, and Lean lanes in CI
- BEAD: asupersync-gap-lean-tla-receipts-48ukyp (P2) for Lean.
- WHY: the 38-test remote-transport lifecycle suite runs only under a script outside CI; the server-stack chaos e2e (`examples/production_service.rs` + `scripts/run_server_stack_e2e.sh`) is in no workflow; `lake build` never runs in CI.
- WHAT: add the three as jobs (the Lean job caches the toolchain and uploads the build log).
- ACCEPTANCE: green jobs with artifacts; a planted `sorry` fails the Lean job.
- SIZE: 1-2 days.

### C.5 Fix the four lib-test failures at HEAD
- WHY: see section 0. Two are server-stack tests in FuchsiaSnow's active area (body-lifecycle diagnostics changed the error text and the chunked-limit accounting on 2026-09-01); two are ambient-audit drift (a KNOWN_FINDINGS line reference at metadata.rs:2546 and an insta inventory snapshot).
- WHAT: coordinate with the server-stack owner for the two behavioral tests; update the ambient-audit entry and accept the snapshot only after reviewing the diff (new TcpListener/TcpStream sites in h1/h2 listener and grpc client are real ambient-authority additions and must be justified or capability-routed).
- ACCEPTANCE: `cargo test --lib --features test-internals` fully green at HEAD.
- SIZE: 1 day.

### C.6 Stub and no-mock gates trusted again
- WHY: `check_no_mock_policy.py` and `scan_stubs.sh` are both red on false positives (a variable named `placeholder`, a gRPC status constructor, a doc comment); a `#[path = "mo\u{63}k.rs"]` escape hides "mock" from the scanner (src/transport/mod.rs:8).
- WHAT: rename the variable, allowlist the constructor by symbol not by substring, remove the unicode escape and register the test double honestly in the policy.
- ACCEPTANCE: both gates exit 0 at HEAD; a planted `todo!()` in src fails them.
- SIZE: hours.

---

## 5. Workstream D: lab and production converge

### D.1 Production trace export
- BEAD: asupersync-gap-prod-trace-export-ro6zzy (P1).
- WHY: "debug production issues locally" has no path: no public runtime trace export (`RuntimeState::trace_handle` is internal); `LabConfig::replay_trace(path)` is a metadata string; docs/replay-debugging.md example is a placeholder.
- WHAT: `RuntimeBuilder::trace_sink(sink)` and `Runtime::export_trace() -> Trace` writing the canonical event schema the lab records; a `LabRuntime::analyze_trace(trace)` entry that runs canonicalization, the DPOR race report, and crashpack assembly on an imported trace.
- ACCEPTANCE: e2e: production runtime with sink -> export -> lab analysis reports the same task/region events; docs example uses real APIs; planted negative: a truncated trace is rejected with a typed error.
- SIZE: 3 days.

### D.2 The production scheduler under lab control
- WHY: `LabScheduler` is a separate single-threaded model (src/lab/runtime.rs ~5234-5246); production is `ThreeLaneScheduler`. "Same seed, same behavior holds end-to-end, not just for a demo scheduler" is true only for the lab model. Lab-vs-live differential tests run the live side as `current_thread` only.
- WHAT: a deterministic driver mode for `ThreeLaneScheduler` (single OS thread, seeded tie-breaks, virtual time) usable by LabRuntime, so lab schedules exercise the production dispatch, steal, cancel-lane, and UCB1 code; keep `LabScheduler` as a policy until parity is proven, then retire it.
- ACCEPTANCE: the lab determinism suite passes with the three-lane driver; a deliberately injected nondeterministic tie-break makes the same-seed test fail; the lab-vs-live differential adds a multi-worker live side.
- DEPENDS: none hard; enables B.5 and D.3. SIZE: 2 weeks. RISK: high (core).

### D.3 Replay re-execution
- WHY: replay today is same-seed rerun plus diff; an exported production trace cannot be re-executed.
- WHAT: forced-schedule replay from a trace (`ForcedSchedule` receipts exist as lab-only; extend to imported traces) using D.2's driver.
- ACCEPTANCE: import a production trace of a real race, replay it in the lab, observe the same interleaving (event sequence equality) and the same outcome.
- DEPENDS: D.1, D.2. SIZE: 1 week.

### D.4 DPOR race detection stops over-reporting
- WHY: LabRuntime hardcodes `LogicalClockMode::Lamport` (src/lab/runtime.rs ~2075) while `dpor.rs:183-185` accepts only vector clocks as happens-before evidence, so every conflicting cross-task pair is a race; `from_trace` is O(n^2). Bead vemwug is blocked on a TraceEvent schema break.
- WHAT: vector clocks in LabRuntime (or Lamport-aware happens-before), the schema change behind a versioned trace format, and an O(n log n) race extraction.
- ACCEPTANCE: a trace with two independent tasks reports zero races; a real race is reported; explorer seed count for a known-race scenario drops (recorded before/after).
- DEPENDS: trace schema version (D.1). SIZE: 1 week.

### D.5 Inert statistical machinery: feed it or delete it
- WHY: `OracleSuite::report_and_observe` (e-process monitor) has zero callers; `ConformalCalibrator` is used by no oracle; `LabRunReport::export_tla` has zero callers and no exported trace has ever been fed to TLC; `check_sheaf_consistency` is uncalled outside its test. About 5.7k LOC of README-advertised machinery with no runtime consumer.
- WHAT: e-process: LabRuntime calls `report_and_observe` after each oracle evaluation and the explorer stops early when the e-process rejects (the actual README claim); conformal: calibrate the futurelock idle threshold from prior seeds (one real consumer); TLA+: one e2e that exports and runs TLC in CI (C.4); sheaf: wire into the saga runner's consistency check or delete the module and the README section.
- ACCEPTANCE: each mechanism has one production or lab call site with a test that fails when the mechanism is disabled; README table "Current status" column updated per mechanism.
- SIZE: 1 week.

### D.6 Oracle determinism in user builds
- WHY: four oracles stamp `SystemTime::now()` into `detected_at` unless `cfg(test)`/`deterministic-mode`, so violation records are not byte-stable in user builds; `VirtualTimerWheel` is advertised "in the hot path" but unwired (LabReactor uses a BinaryHeap).
- WHAT: stamp lab virtual time; either wire `VirtualTimerWheel` into LabReactor or delete the README sentence.
- ACCEPTANCE: two runs of the same seed produce byte-identical crashpacks in a plain release build.
- SIZE: 1-2 days.

---

## 6. Workstream F: server stack

### F.1 Per-request child region with body obligation
- BEAD: asupersync-server-stack-hardening-eeexl1.6.10 (P1, open, claimed 2026-09-01).
- WHY: handlers run under a clone of the connection Cx; the epic's headline "client disconnect -> 499 + DB cancel + obligation-clean region close" depends on a real request region.
- WHAT/ACCEPTANCE: as the bead states; the acceptance must include a real-socket test where the client disconnects mid-handler and the handler's DB-style obligation is aborted and the region closes clean.
- SIZE: 1 week (owner active).

### F.2 HTTPS client proof and H2 client
- WHY: the pooled `HttpClient` could not trust any root until 2026-09-01 (fixed: `add_root_certificate`); there is no general HTTP/2 client (gRPC owns a private channel); pooling is H1-client only.
- WHAT: (done) HTTPS through the pooled client with an installed root; (todo) HTTPS with the `tls-webpki-roots` feature against a public host in an opt-in network test; an `Http2Client` built on the gRPC channel's H2 framing with the same fluent API, or an explicit README line that H2 is server-only.
- ACCEPTANCE: HTTPS e2e green under `tls` and under `tls-webpki-roots`; H2 client fetches a body from the in-repo H2 listener with flow control exercised (body larger than the initial window).
- SIZE: 1 week for the H2 client.

### F.3 WebSocket production gaps
- BEADS: eeexl1.11 (blocked 79 days), it4lr2 (parser bug, in progress 6 weeks).
- WHAT: keepalive (ping/pong timers), permessage-deflate, write backpressure; land the parser fix with the RFC6455 registry green.
- ACCEPTANCE: autobahn-style fragmentation and close cases in the registry plus a keepalive timeout test and a backpressure test (slow reader bounds writer memory).
- SIZE: 1 week.

### F.4 gRPC server streaming over real H2 and the H2 recv-window bug
- BEADS: eeexl1.10 (stale), v1fa8y (in progress since 06-18).
- ACCEPTANCE: server-streaming call over a real socket delivers N messages with flow control; the recv-window regression test from v1fa8y passes.
- SIZE: 1 week.

### F.5 Multi-connection H3 listener
- BEAD: eeexl1.23 (filed 2026-09-01), after the cwnd fix (bi6url, landed ccb5af622).
- ACCEPTANCE: two concurrent QUIC clients complete requests against one listener; a third client's handshake failure does not affect the first two.
- SIZE: 1-2 weeks.

### F.6 DNS truth
- WHY: "async DNS with address-family selection" is a blocking std UDP query on a spawned thread with post-hoc family filtering; `tests/dns_real_upstream.rs` hits public resolvers with no env gate.
- WHAT: either a reactor-driven UDP resolver or a README sentence saying it is blocking-pool-backed; gate the upstream test behind an env var.
- SIZE: hours (docs + gate) or 1 week (async resolver).

---

## 7. Workstream G: data and observability

### G.1 `File` poll traits through the blocking pool
- BEAD: asupersync-gap-file-poll-blocks-executor-lop0ul (P2).
- ACCEPTANCE: on a current-thread runtime a large `BufReader<File>` read must not stall a second task's checkpoint counter.
- SIZE: 3 days.

### G.2 Inspector reachability (done) and poll accounting
- WHY: done 2026-09-01: `Runtime::task_inspector`/`diagnostics`, `explain_cancellation`. Finding while doing it: `TaskRecord::total_polls` is not advanced on the production dispatch path, so the inspector's `poll_count` is 0 in production.
- WHAT: either advance the counter on the hot path (one relaxed increment per poll; benchmark it) or document `poll_count` as lab-only in `TaskDetails`.
- ACCEPTANCE: inspector e2e asserts `poll_count >= 1` after the task ran (if advanced) and the baseline bench gate is green; or the doc states the limitation and the e2e keeps the flag-based liveness proof.
- SIZE: hours.

### G.3 OTLP exporter composable in `MultiExporter`
- WHY: `impl MetricsExporter for OtlpHttpExporter::export()` always returns Err (src/observability/otel.rs ~7134), so OTLP cannot join the composition the README describes.
- WHAT: an async `MetricsExporter` path or a blocking bridge that submits to the blocking pool with a bounded queue.
- ACCEPTANCE: a `MultiExporter` of in-memory + OTLP delivers to a loopback OTLP listener (the existing prost-decoding test pattern) and the in-memory exporter simultaneously.
- SIZE: 2 days.

### G.4 Real-server suites green and MySQL native auth (done)
- WHY: MySQL native auth landed 2026-09-01 behind the opt-in with KATs; real-server proof depends on C.3.
- ACCEPTANCE: C.3's job green; `tests/integration/mysql_real_server.rs` gains a native-password case against a server configured for it.
- SIZE: with C.3.

### G.5 Self-referential conformance suites
- WHY: `tests/nats_core_protocol.rs`, `tests/conformance/postgres_logical_replication.rs`, `postgres_extended_query.rs`, `tests/conformance/kafka_record_batch_v2/*` import nothing from the crate (about 4.3k LOC testing local reimplementations); PostgreSQL has no logical-replication implementation in src while README claims coverage.
- WHAT: point each suite at the crate's codec (or delete the suite and the README bullet); implement logical replication or remove the claim.
- ACCEPTANCE: each surviving suite has at least one `asupersync::` import and fails when the crate codec is sabotaged.
- SIZE: 2-3 days.

### G.6 Kafka: decide native vs rdkafka (see K)
- WHY: zero native wire code in src; 13 epics and 91 tasks open; ADR-009 says KEEP rdkafka.
- WHAT: K.1 decides; if native proceeds, the first deliverable is a real broker round-trip in C.3's job, not a plan.

---

## 8. Workstream H: distributed and actors

### H.1 Remote handles region-owned; leases as obligations
- BEAD: asupersync-gap-remote-handles-region-owned-udjmtx (P2).
- ACCEPTANCE: region close drains a running remote computation (cancel/terminal exchange observed) with no obligation leak; a never-answering remote is reported lease-expired at the bound.
- SIZE: 1 week.

### H.2 Snapshot distribution transport, SWIM wiring, PBFT stub
- BEAD: asupersync-gap-snapshot-transport-swim-pbft-e6drlx (P2).
- ACCEPTANCE: two-process snapshot distribute/recover with one peer down; SWIM-driven route refresh on loopback; PBFT unreachable from the default public API or marked experimental.
- SIZE: 2 weeks.

### H.3 Spork tree-level restart
- BEAD: asupersync-dist-otp-completeness-8y37kz.2 (blocked, stale owner).
- WHAT: the live restart loop over `CompiledSupervisor` plans (one-for-one first), with intensity/backoff, wired to actor failures.
- ACCEPTANCE: a supervised child that panics is restarted according to the compiled plan; exceeding intensity escalates to the parent; the minimal Spork example demonstrates a restart (today it uses `SupervisionStrategy::Stop`).
- SIZE: 1 week.

### H.4 Wire format decision (JSON vs CBOR)
- WHY: the design bible mandates canonical CBOR; the code ships strict JSON with goldens.
- WHAT: record the decision in asupersync_plan_v4.md (JSON kept, or CBOR at the 0.5 boundary).
- SIZE: hours.

---

## 9. Workstream I: ATP and RaptorQ

### I.1 Bench receipts in git and an honest encrypted-tier table
- BEAD: asupersync-gap-atp-bench-receipts-xwyrr2 (P2).
- ACCEPTANCE: `git ls-files artifacts/atp_bench_matrix` nonempty; ledger entry dated; README cell table equals the committed scorecard.
- SIZE: 1 day plus bench time.

### I.2 Cross-machine QUIC receipt
- WHY: no QUIC or bonded transfer has ever been recorded between two real hosts (only atp-tcp plaintext 2026-06-13).
- ACCEPTANCE: one dated Hetzner-to-Contabo QUIC transfer with SHA-256 verification committed under artifacts.
- SIZE: 1 day (fleet access exists).

### I.3 Encrypted tier beats rsync on clean links, or the claim is retired
- WHY: encrypted tier loses 50M/perfect 1.48x and tree_big/perfect 2.46x; the MATRIX-235 lever claims were never banked.
- WHAT: profile the encrypted sender duty cycle on a perfect link (the ledger's own diagnosis was sender-side), land the pipeline lever, re-run the matrix; if it still loses, the merged epic (A.3) states the loss explicitly and the "beats rsync" phrase is qualified to the tiers where it holds.
- ACCEPTANCE: committed scorecard; README/ledger match; the epic's done criterion is met or rewritten.
- SIZE: 1-2 weeks.

### I.4 RaptorQ K=2048 interop and independent vectors
- BEAD: asupersync-gap-raptorq-k2048-interop-creh6g (P2).
- ACCEPTANCE: the K=2048 encoder differential passes un-ignored; independent vectors for K in {10, 100, 1000, 2048, 10000}; a planted single-byte vector corruption fails.
- SIZE: 3 days.

### I.5 ATP dead code
- WHY: 3.7k LOC unreachable files (src/net/atp/bonding.rs shadowed, compress/, sink/, src/atp/{adaptive_raptorq,cas,telemetry}.rs), 1.2k LOC `cfg(any())` tombstones, 14 `atp` CLI subcommands returning not-implemented, 8 `doctor` subcommands emitting constant JSON.
- WHAT: with owner permission (AGENTS.md forbids agent-initiated deletion) wire or delete the unreachable files; remove tombstones; either implement or remove the placeholder CLI subcommands from the help text (a subcommand that cannot work must not be listed as available).
- ACCEPTANCE: no `.rs` file under src is unreachable from the module tree (a script enumerates and the count is zero); `atp --help` lists only working subcommands.
- SIZE: 2 days after permission.

---

## 10. Workstream E: Browser Edition

### E.1 Decision: real scheduler or ledger
- BEAD: asupersync-decision-browser-scheduler-or-ledger-94g51y (P1).
- WHY: the wasm ABI is a handle ledger (`task_spawn` takes no future); README was corrected on 2026-09-01; the served wasm is from 06-19 and predates security fixes; last browser-engine runs were March; npm publish never succeeded.
- WHAT: owner chooses (A) a wasm-side scheduler polling Rust futures via a microtask/MessageChannel pump with the single-threaded three-lane policy, or (B) keep the ledger and remove "runtime/scheduler" language from packages, docs, and the demo.
- SIZE: decision: hours; (A) 3-4 weeks; (B) 2 days.

### E.2 Rebuild and pin the wasm from HEAD
- ACCEPTANCE: `packages/browser-core/asupersync_bg.wasm` hash equals a reproducible build from HEAD; the GA signoff hash follows the build; Pages serves the new binary.
- SIZE: 1 day.

### E.3 Browser-engine tests in CI
- ACCEPTANCE: the existing Playwright fixtures run headless in a workflow on push; dedicated-worker, native-stream, react, next rows get their first recorded runs.
- SIZE: 2 days.

### E.4 npm publish
- BEAD: yxwno1 (blocked, P1).
- ACCEPTANCE: `@asupersync/browser` resolves on the registry or a dated manual publish receipt is committed.
- SIZE: 1 day.

### E.5 Fix or drop the Rust browser modules nobody reaches
- WHY: `src/io/browser_storage.rs` and `browser_stream.rs` are unreachable from the exported ABI; four open BrowserStorage bugs fix code no consumer can call.
- WHAT: after E.1, either export them through the ABI (A) or close the bugs as unreachable (B).
- SIZE: with E.1.

---

## 11. Workstream J: governance diet

### J.1 Freeze and audit contract tests
- WHY: 306 of 396 `*_contract.rs` files never import the crate; 521 of 1,431 test files never import asupersync; 44.5% of test LOC is meta; zero commits show a contract failure leading to a runtime fix.
- WHAT: freeze creation of new contract tests and artifact JSON; audit each existing contract test against the creation gate (consumer, feature gated, defect class, deletion condition) and delete those that fail it (with owner permission per AGENTS.md); keep the unsafe ledger and the no-stub discipline (the two with a record of catching real drift).
- ACCEPTANCE: test LOC that never touches the runtime falls below 20%; every surviving contract test names in its module doc the feature it gates.
- SIZE: 1 week (mostly deletion review).

### J.2 Proof snapshot replaced by CI receipts
- WHY: 27 of 37 proof claims are rerun-required; 41 of 64 lanes have no dated evidence; the snapshot's fresh rows expire on 2026-09-22.
- WHAT: generate the claim dashboard from CI job results (job name = lane id) instead of hand-maintained JSON; delete claims nobody re-runs.
- ACCEPTANCE: the dashboard is a build artifact of C.1, not a tracked JSON; README links to it.
- SIZE: 2 days after C.1.

### J.3 Retire obsolete program artifacts
- WHY: swarm-governor, proof-traffic, clean-overlay, memory-residency contracts and runbooks describe swarm process, not the runtime, and consume README space (three H2 sections are pure governance).
- WHAT: move their README sections to docs/proof/ with one index line in README; retire artifacts whose lanes never ran.
- ACCEPTANCE: README under 120 KB; no README H2 section whose only subject is agent process.
- SIZE: 1 day.

### J.4 Unsafe ledger regenerated in CI
- WHY: complete (40/40 files) but 574 commits stale with 18 stale locators.
- WHAT: regenerate on a clean tree in a CI job; fail on drift.
- ACCEPTANCE: contract green at HEAD; a planted unsafe block without a row fails.
- SIZE: hours.

### J.5 Signoff artifacts that block closure
- WHY: `86fe9v` is held blocked by `parent_close_allowed=false` in a signoff JSON nobody refreshes.
- WHAT: refresh or retire; closure decisions live in beads, not in JSON.
- SIZE: hours.

### J.6 `rch exec` strings in the shipped crate
- WHY: 49 src files embed the literal `rch exec` (the private build fleet) in doc/help strings shipped to consumers.
- WHAT: move operator hints to docs; keep the crate free of fleet-specific text.
- SIZE: half a day.

---

## 12. Workstream K: Dependency Sovereignty decision

### K.1 Decide the program against its ADRs
- BEAD: asupersync-decision-dependency-sovereignty-62jqi3 (P1).
- WHY: 217 of 565 open beads; all 12 ADRs terminal KEEP; 3 crates cut over, 4 owned-alongside, about 25 untouched; native Kafka has zero src code against 13 epics.
- OPTIONS: close as superseded; re-scope to cutovers with measured benefit (hex/base64 owned engines exist: remove the crates; decide sqlite/fsqlite); or keep the status quo.
- ACCEPTANCE: a decision comment on the bead; A.2 executes the parenting/closing that follows.

### K.2 If re-scoped: the two cheap cutovers
- WHAT: replace `hex` and `base64` crate usage (45 and 18 src files) with the owned codecs; measure binary size and compile time before/after.
- ACCEPTANCE: crates removed from Cargo.toml; all tests green; numbers recorded in the ADR.
- SIZE: 2 days.

---

## 13. Workstream L: release train and semver boundary

### L.1 Every release is a bead with receipts
- BEAD: asupersync-gap-release-train-pzpol4 (P1).
- WHAT: tag v0.4.10 on the published commit (verify with `cargo package --list` against the crates.io tarball); a release checklist bead template: compat comparison against v0.4.3, `cargo publish --dry-run`, tag, CHANGELOG bullet, downstream canary result; fix or retire publish.yml.
- ACCEPTANCE: `git tag -l v0.4.10` nonempty on the right commit; the next release uses the template.
- SIZE: 1 day.

### L.2 Downstream canary
- WHY: AGENTS.md requires an opted-in consumer canary; ~30 local consumers exist and most pin `default-features = false`.
- WHAT: a job that builds three representative consumers (one `default-features = false`, one with `proc-macros`, one with `tls`) against HEAD.
- ACCEPTANCE: job green; a planted public-API removal fails it.
- SIZE: 1 day.

### L.3 The 0.5 boundary list
- WHY: several truths need a break: drain-by-default on `Runtime` drop (B.1), `#[must_use]` on `Outcome` (B.3 wider form), CBOR (H.4), removal of the not-implemented CLI subcommands (I.5), retiring `LabScheduler` (D.2).
- WHAT: a single tracked list with migration notes; nothing on it ships in 0.4.x.
- SIZE: hours to start; maintained.

---

## 14. Milestones

| Milestone | Contents | Exit criterion |
|---|---|---|
| M1 Truth and green (2 weeks) | A.1-A.6, C.1, C.5, C.6, J.4, J.5, L.1 | CI green three times; tracker in-progress < 60; README one-page block present and checked |
| M2 Kernel promises (3 weeks) | B.1-B.4, G.2, G.3 | headline README guarantees each have a native-runtime test with a planted negative |
| M3 Lab/prod convergence (4 weeks) | D.1-D.6, B.5 | a production trace replays in the lab; DPOR reports zero races on independent tasks |
| M4 Platforms and data (2 weeks) | C.2, C.3, C.4, G.1, G.4, G.5 | non-Linux and real-server jobs green |
| M5 Server stack (3 weeks) | F.1-F.6 | request region real; HTTPS/H2 client; WS gaps closed; multi-connection H3 |
| M6 Distributed (3 weeks) | H.1-H.4 | remote work region-owned; snapshot distribution across two processes; tree restart |
| M7 ATP honesty (2 weeks) | I.1-I.5 | committed receipts; cross-machine QUIC; encrypted claim true or retired |
| M8 Browser (decision + 1-4 weeks) | E.1-E.5 | per decision |
| M9 Diet and decisions (1 week, parallel) | J.1-J.3, J.6, K.1-K.2, L.2, L.3 | meta test LOC < 20%; program decision recorded |

Total: roughly 20 engineer-weeks of product work plus decisions, with M1 and
M9 runnable by a small number of agents in parallel with M2.

---

## 15. Definition of done for the whole plan

The plan is done when every row of the Phase 1 vision checklist is WORKING
or carries an explicit PARTIAL/PREVIEW label in the README one-page block
with a named test, the CI workflow has been green for a month, the tracker's
open beads are all either actively owned or explicitly parked with a date,
and a fresh reality check by an auditor who has not read this plan finds no
README claim without a behavioral test behind it.
