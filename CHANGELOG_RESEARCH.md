# Changelog Research Notes

## 2026-07-01 Unreleased ATP / Skill-Refresh Pass

Scope: summarize material changes since the prior `asupersync-mega-skill`
creation point, with enough evidence to update both `CHANGELOG.md` and the
canonical skill in `/data/projects/je_private_skills_repo`.

Sources used:

- `AGENTS.md` and `README.md` in `/data/projects/asupersync`
- `CHANGELOG.md`
- `git log --since=2026-06-01 --oneline --decorate`
- `gh release list --limit 100`
- `br list --json`
- `br list --status closed --json`
- `cass status`
- focused `cass search ... --robot --limit ...` / `cass view ... --json`
- read-only subagent passes over current APIs, git/beads history,
  runtime semantics, and cass-mined session rules

High-confidence findings:

- The latest visible GitHub release is `v0.3.4` on 2026-06-07. The changelog
  also records a `v0.3.5` release-train entry dated 2026-06-18, but no matching
  local tag was visible during this pass.
- The current public runtime example is no longer the older
  `Cx::for_request()` bootstrap. The README shows `RuntimeBuilder`, `Runtime`,
  `RuntimeHandle::spawn`, ambient `Cx::current()`, and `Cx::spawn`.
  `Cx::for_request()` / `Cx::for_testing()` are test-internals gated.
- `tokio::spawn` should map to `Cx::spawn` or `Cx::spawn_in`.
  `Scope::spawn_registered` remains a lower-level boot/test path for callers
  that already hold `&mut RuntimeState`.
- The workspace now includes the root crate, `asupersync-macros`,
  `asupersync-browser-core`, `asupersync-tokio-compat`, `conformance`,
  `franken_kernel`, `franken_evidence`, `franken_decision`, `frankenlab`, and
  `drop_unwrap_finder`; `fuzz` and `asupersync-wasm` are excluded scaffolds.
- ATP evidence is matrix-governed. Claims must use the benchmark harnesses,
  tuned rsync baseline, release `atp`, crypto-symmetric cells, SHA/tamper
  checks, rate caps, and whole-matrix accounting.
- Late-June ATP work landed authenticated control-source stream paths,
  reliable encrypted clean-source stream handling, ack-clocked QUIC datagram
  pacing, repair-spray pacing, incremental hash-on-receive, protocol-v3
  `ObjectComplete` hash trailers, and commit-time same-filesystem renames.
- `br-asupersync-2eb4k2` records 500M clean wins against tuned rsync, and
  `br-asupersync-sze9ym` records 5G clean wins plus a commit-write reduction.
  Harder encrypted/QUIC and delta-resync blockers remain explicitly active.
- RaptorQ should be described as proof-carrying and fail-closed, with decode
  verification guards, symbol-auth posture, tamper witnesses, rank-profile
  evidence, and data-loss regression fixes.
- Proof-lane artifacts are first-class. `artifacts/proof_lane_manifest_v1.json`,
  `artifacts/proof_status_snapshot_v1.json`, validation-frontier artifacts,
  scripts, and contract tests must move together.
- Browser Edition has package/readiness/integrity gates and
  `asupersync-browser-core` is the canonical browser core; Rust browser runtime
  APIs remain explicit browser-lane surfaces, not a blanket server/edge story.
- Service surfaces have expanded materially across H2 listener/drain behavior,
  middleware layering, HTTP request builders, database transaction obligations,
  and gRPC call-scoped backpressure/cancel coupling.
- Runtime CPU work introduced `runtime-metrics`, scheduler churn evidence,
  shared process-global no-driver sleep fallback, a warn-once fallback path, and
  `RuntimeBuilder::enable_time()`.

No-claim boundaries to preserve:

- Do not claim ATP wins from compile-only evidence, stale matrix artifacts, or
  `sha_ok` without timing/bytes evidence.
- Do not present native QUIC/H3 as generic release-ready interoperability.
  Treat it as requirement-driven and verify exact protocol needs.
- Do not present Browser Edition as direct runtime support for SSR, edge, or
  Node-only contexts.
- Do not call Asupersync DPOR "optimal"; current source describes
  DPOR-style guided coverage with race/backtrack extraction.
- Do not use `Cx::for_request()` as a production teaching path.

## 2026-08-19 v0.4.4 to v0.4.8 Skill-Refresh Pass

Scope: reconcile the canonical `asupersync-mega-skill` against the complete
published change window from `v0.4.4` through `v0.4.8`, correcting the changelog
before using it as one of the skill's evidence sources.

Sources used:

- full `AGENTS.md`, `README.md`, `CHANGELOG.md`, and affected source modules
- `git log`, annotated tags, release-to-release diffs, and public-surface scans
- current Beads JSONL, including closed work and open/in-progress boundaries
- GitHub release and issue state
- focused CASS searches over migration, spawn, cancellation, browser, and
  messaging sessions; the lexical index was stale after 2026-08-02 and a safe
  rebuild attempt was refused with `index-busy`, so source, Git, and Beads are
  authoritative for the 2026-08-13 through 2026-08-18 window
- three read-only subagent passes over core/runtime APIs, stack/features, and
  release/Beads history

Release-window accounting:

- `v0.4.4..v0.4.8` contains 144 commits across 209 files (+19,305/-4,314).
- `v0.4.5` repaired native timer-parked cancellation and driverless Windows TCP
  connect, hardened Redis RESP3 parsing, added borrowed HTTP/1 request-head
  inspection, and shipped owned NKey codec/key substrate.
- `v0.4.6` added exact Lab dispatch capture/replay and deletion-only candidates,
  fixed command-before-time ordering and `Sleep` cleanup, and tightened HTTP/1
  parsing to exact RFC OWS and bounded ASCII framing rules.
- `v0.4.7` added bounded shutdown and additive typed checked joins, canonical
  bounded `ForcedSchedule` artifacts, authenticate-before-dedupe QUIC handling,
  independent byte/metadata reassembly caps, and ATP final-size validation.
- `v0.4.8` made local-spawn and local cancel routing verify runtime ownership and
  made `CurrentCxGuard` teardown identity-based rather than LIFO-only.

Compatibility conclusions:

- The v0.4.5-v0.4.8 public changes are additive; legacy `RuntimeHandle::spawn`,
  `JoinHandle<T>`, owned HTTP heads, and ordinary runtime drop remain available.
- Checked joins were deliberately added as `CheckedJoinHandle<T>` plus
  `spawn_checked` / `try_spawn_checked` rather than changing the established
  `JoinHandle<T>::Output` contract.
- `spawn_local` now fails closed with `LocalSchedulerUnavailable` when a foreign
  runtime context is active; it does not reroute a non-`Send` task to that
  runtime or silently turn it into a `Send` task.

Open/no-claim boundaries retained in the skill:

- Exact `ForcedSchedule` replay is shipped, but a complete failure classifier,
  minimizer, workload/action codec, and persisted downstream reproducer are not.
- Owned NKey primitives are shipped, but the first-party production identity
  cutover, generic transcript signer, and full retained-artifact E2E are not.
- Native QUIC/HTTP/3 remains feature-gated and requirement-driven; the hardening
  work is not blanket interoperability or performance proof.
- `messaging-fabric` remains an incomplete reserved surface; Redis, NATS,
  JetStream, and Kafka support must be described independently.
- Browser direct runtime remains main-thread/dedicated-worker only; service and
  shared workers are broker/coordinator surfaces, Rust browser runtime remains
  preview, and browser packages remain workspace-local rather than npm-published.
- Recorded vector-clock causality is not yet complete for every default-runtime
  producer edge, so race reports remain conservative rather than fully precise.

Changelog corrections made from this pass:

- corrected v0.4.8 local-spawn wording from implied rerouting to fail-closed
  runtime-identity rejection
- added synchronous admission closure to the bounded-shutdown description
- added the v0.4.7 canonical `ForcedSchedule` artifact codec and its no-claims
- added ATP duplicate-FIN/final-size validation
- made the shipped-versus-incomplete NKey boundary explicit
- normalized the v0.4.3 and v0.4.4 headings to their annotated tag dates

## 2026-08-20 v0.4.9 Canonical-Skill Reconciliation

Scope: refresh the canonical `asupersync-mega-skill` against the complete
`v0.4.8..v0.4.9` release delta, correcting the release record before using it
as one of the skill's evidence sources.

Sources used:

- full `AGENTS.md`, `README.md`, `CHANGELOG.md`, `TESTING_FOR_AGENTS.md`, the
  canonical skill, and the affected source, test, proof-artifact, and package
  manifests
- annotated tags, release-to-release git history, GitHub release/issue state,
  crates.io package state, and npm package lookups
- direct Beads JSONL comparison plus focused live issue inspection; tracker
  rows were treated as intent and evidence, not as authoritative shipped-state
  labels when they contradicted tagged source and release artifacts
- focused CASS searches over request-context creation, native cancellation,
  SQLite, compatibility, and prior skill work; the local checkpoint remained
  stale after 2026-08-02, and the one bounded rebuild attempt failed cleanly
  with an `index-busy` snapshot conflict, so CASS supplied hypotheses and
  historical rationale rather than current-state proof
- three read-only subagent passes over architecture/API deltas, git/release
  history, and Beads history

Release-window accounting:

- `v0.4.8..v0.4.9` contains 50 commits across 181 files
  (+21,059/-4,130).
- `main`, `origin/main`, `origin/master`, and the `v0.4.9` tag all resolved to
  `9eb0600e6` during this pass. GitHub publishes `v0.4.9`, and all nine Rust
  workspace crates are live and unyanked at `0.4.9` on crates.io.
- The browser package manifests are also versioned `0.4.9`, but the four
  `@asupersync/*` packages still returned npm 404 and remain workspace-local.
- The canonical skill's effective source cutoff was `eacfba37a`: it captured
  the first 40 commits after `v0.4.8` but preceded the final ten commits and
  therefore described shipped v0.4.9 work as unreleased current-main behavior.

Material v0.4.9 conclusions:

- Additive request-context and blocking-pool attachment APIs, bounded actor
  yielding, saturating restart backoff, finite owned OTLP metrics/traces/logs,
  SQLite cancellation ownership, checked SQL, transaction rollback completion,
  row metadata/strict REAL accessors, and protected-stdin ATP key transport are
  published v0.4.9 behavior rather than post-v0.4.8 previews.
- The largest skill and changelog omission was the additive structured SQLite
  diagnostic family: `SqliteOperation`, `SqliteErrorCategory`,
  `SqliteRetryDisposition`, `SqliteErrorDiagnostic`, `SqliteOperationError`,
  and separately named connection/transaction `*_diagnosed` methods. Existing
  `SqliteError` signatures remain intact; cancellation remains an outer
  `Outcome`; ordinary formatting and error chaining redact raw SQL, values,
  paths, and engine prose; explicit accessors expose legacy or engine details.
- The terminal SQLite P9 aggregate compares 47 common public-surface cases,
  records eight native-only cancellation cases, reports zero unexplained
  divergences, and keeps `rusqlite` plus `sqlparser`. It does not authorize a
  FrankenSQLite cutover or establish arbitrary-SQL, performance, cross-platform,
  browser-Wasm, or process-global-quiescence claims.
- OTLP A2-A5 are shipped, but the open frontier is A6-A11: transport responses,
  queue/retry/shutdown, shared privacy/cardinality, failure/fuzz coverage,
  aggregate dependency/cutover signoff, and maintained external SDK/provider
  coverage remain incomplete.
- `asupersync-909482` and `asupersync-2qas9c` remain unshipped P0 boundaries.
  In contrast, the protected-input ATP change and the exact-v0.4.4 downstream
  cancellation fixture shipped in v0.4.9.
- The public API artifact remains a lexical inventory (19 entry points, 120
  modules, 315 root exports), not proof that every listed module is a default
  production surface or that any item is behaviorally correct.

Evidence hierarchy and compatibility conclusions:

- Current tagged source and public signatures outrank stale tracker status;
  focused acceptance artifacts and terminal execution receipts establish only
  their declared guarantees; Beads and CASS provide rationale and discovery.
- A manifest row defines a proof command and no-claim boundary, a status
  snapshot records freshness/blockers, and only a terminal execution receipt
  proves that the command ran. Structural contract tests are not broad runtime
  or release proof.
- v0.4.9 preserves the hard v0.4.3 compatibility floor. Its public changes are
  additive, and the diagnosed SQLite family deliberately uses separately named
  APIs rather than changing established error types or method signatures.

Changelog corrections made from this pass:

- added the previously omitted structured SQLite diagnostic API family and its
  parser/transaction classification repair to the v0.4.9 SQLite section
- added structured SQLite diagnostics to the v0.4.9 additive-compatibility
  summary
- replaced the historical low-signal fuzz-target phrase "and more" with the
  concrete channel state-machine boundary
