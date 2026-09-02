# Asupersync Bridge Plan (Reality Check Phase 2), 2026-09-01

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
