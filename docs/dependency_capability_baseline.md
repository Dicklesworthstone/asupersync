# Dependency capability baseline

`artifacts/dependency_capability_baseline_v1.json` is the canonical executable
baseline for CAP A2. It turns the CAP A1 inventory into replayable incumbent
evidence while preserving every gap as an explicit blocker. It is not cutover evidence
and it does not claim that any proposed replacement is equivalent.

## No feature loss

Dependency sovereignty is an implementation objective, not permission to make
asupersync smaller as a product. Public APIs, generic extension points,
features, binaries, formats, wire protocols, platform behavior, diagnostics,
security policy, cancellation semantics, downstream integrations, and user
journeys stay available unless an explicit owner decision changes product
scope. A missing test is `UNKNOWN` or blocked; it never means unused.

Every one of the 50 stable capability IDs classifies six case classes:

- `positive`: accepted use and normal output;
- `empty_boundary`: empty, minimum, maximum, Unicode, binary, or other edge
  values;
- `malformed_error`: invalid input, public error mapping, and fail-closed
  behavior;
- `resource_limit`: size, memory, queue, disk, work, timeout, or topology
  bounds;
- `cancellation_cleanup`: interruption, drain, quiescence, and residual
  resources;
- `recovery`: retry, reuse, restart, rollback, or next-operation behavior.

A case is backed by a named evidence entry, typed as
`BLOCKED_EXTERNAL`, `BLOCKED_PLATFORM`, or `BLOCKED_OWNER`, or explicitly
`NOT_APPLICABLE` with a reason. Silent skips are forbidden. In particular,
zero tests is a failure for every cataloged Cargo test command.

## What parity means

The artifact separates properties that are often incorrectly collapsed into
“the tests passed”:

- `EXACT_BYTES` applies only to accepted wire, persisted, and stable operator
  bytes;
- `SEMANTIC` preserves the meaning of inputs and outputs without demanding
  accidental implementation bytes;
- `PUBLIC_COMPILE` protects downstream naming, traits, bounds, and feature
  combinations;
- `ERROR_CONTRACT` protects variants, context, stable diagnostics, and
  fail-closed behavior;
- `SECURITY_POLICY` protects trust, redaction, downgrade resistance, and secret
  lifecycle;
- `RESOURCE_ENVELOPE` protects bounded work, memory, handles, queues, and
  latency;
- `LIFECYCLE` protects cancellation, drain, cleanup, quiescence, restart, and
  rollback;
- `PLATFORM_MATRIX`, `SERVICE_INTEROP`, and `OPERATOR_UX` retain behavior that a
  host-only unit test cannot establish.

`EXECUTABLE_COMPLETE` means only that all six baseline case classes are
classified with current incumbent evidence or a justified non-applicability.
It does not mean the surface is exhaustive, a replacement has parity, or a
cutover is allowed.

## Standalone downstream consumer

The fixture at
`tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml` is its own
workspace. It does not inherit root dev-dependencies and never enables
`test-internals`. Its committed `Cargo.lock` and exact direct versions pin the
standalone resolver state. This catches both public API narrowing that an
in-workspace test could accidentally hide and unreviewed dependency drift.

Two profiles are required:

- `consumer-default` runs at least seven tests for the pinned lockfile, an
  arbitrary downstream Serde enum/map/binary type, a downstream-defined Prost
  message with repeated/map and oneof fields, a downstream-authored pending
  Stream, configuration and public errors, and Base64 protocol helpers.
- `consumer-full` runs at least nine tests and adds the public metrics exporter
  lifecycle, custom regex and automatic PII redaction, the Tower Service
  adapter, and feature-graph coverage for config and compression.

Representative types do not cap the accepted generic surface. They prove that
downstream-defined types still work; finite in-repo schemas never justify
replacing arbitrary Serde or Protobuf capability.

## Replay and logging

Run the focused scenarios through RCH:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh contract
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh consumer-default
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh consumer-full
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh catalog
```

The script writes a retained run directory under
`target/e2e-results/dependency-capability-baseline/<run_id>/`. The fail-closed
execution floors are 26 contract tests, seven default-consumer
tests, nine full-consumer tests, and one static catalog assertion. A successful
command below its lane's floor is reported as `FAIL`. Each run includes:

- `summary.json` with normalized outcome, executed test count, timing, cleanup,
  source drift, and redaction status;
- `events.ndjson` with stable run, scenario, and step IDs;
- per-step `stdout.log` and `stderr.log`;
- `provenance.json` with the actual source and baseline revisions, Rust/Cargo
  versions, exact shell-escaped command, fixture ID, per-file SHA-256 manifest
  plus aggregate fixture digest, features, target, host, execution tree, and
  RCH worker context. The runner accepts either GNU `sha256sum` or the
  macOS-provided `shasum -a 256`;
- `replay.sh` containing the exact deterministic replay command.

Canonical Cargo scenarios use RCH's clean committed-`HEAD` mode
(`--base HEAD --clean-overlay --no-overlay`), so unrelated shared-worktree dirt
is recorded by the controller but excluded from the execution tree. During
implementation, agents use explicit `--overlay-path` proof commands; the
retained runner is the post-commit replay surface.

The runner filters stdout and stderr before either stream reaches retained
files or the controller terminal. A deterministic canary self-test verifies
that filter on every run, and a post-write scan fails if the raw canary is
still present. It rejects zero-test Cargo success, rejects a successful
remote-required command whose RCH worker cannot be identified, and records the
complete generated-path inventory plus child-process cleanup. It does not use
a local Cargo fallback. External or platform prerequisites produce a typed
blocked receipt rather than a passing skip.

The later VER A2 aggregate owns
`scripts/run_all_e2e.sh --suite dependency-sovereignty`, injected runner
failure, aggregate service lifecycle, and cross-scenario log packaging. CAP A2
does not overclaim that future work.

## Hash-map hot-path static audit

`CAP-HASH-MAPS-STATIC-AUDIT-V1` records the bounded static audit for
`asupersync-d24mms.1` and now carries terminal receipt
`CAP-HASH-MAPS-TERMINAL-KEEP-V1`. It is
`TERMINAL_KEEP_SOURCE_PINNED`: thirteen source pins establish a complete
two-file production inventory at revision
`e531006885bc7df52c9d537cf8bff7528343829c`. No replacement or comparison
matrix ran, so its execution state is
`NO_REPLACEMENT_OR_BENCHMARK_MATRIX_EXECUTED_KEEP_TRIGGERED`.

The dependency owns three internal collection roles:

- `LocalQueueInner.presence` is a `HashSet<TaskId>` synchronized with owner
  push/pop and bounded work stealing. It uses default construction,
  `reserve`, `insert`, and `remove`; its collection order is not observed.
- `ReactorState.tokens` and `ReactorState.fds` are Linux/Android epoll maps.
  They use capacity construction, lookup, insertion, `Entry` mutation, and
  removal to preserve one-to-one token/descriptor registration and stale-fd
  cleanup. Their collection order is also not observed.

The APIs have an apparent `std::collections` analogue, but API shape is not
replacement proof for these hot paths. Source currently declares 40 local-
queue unit tests, 36 epoll unit tests, ten local-queue metamorphic test
attributes across seven `proptest!` blocks, five mock reactor conformance
tests, and two real-reactor E2E tests. None is a current candidate-versus-
incumbent execution receipt. `EVD-REACTOR-REGISTRATION` is adjacent lifecycle
evidence only, and the declared `reactor_registration_churn` scenario is not
implemented in the retained dependency-sovereignty runner.

The marginal ledger contains 52 `normal:hashbrown` profile/target rows across
thirteen feature profiles and four target triples, with zero, two, or four
marginal package versions depending on the cell. Its source commit is
`376c313540a58d2c8e6618cf40b4ac87ed36ec53`, not the observed revision, and
its unsafe exposure remains `unclassified-fail-closed`. It is useful graph
context, not fresh favorable cutover evidence.

Cutover still requires scheduler and reactor semantic execution, explicit
collision/hash-seed policy, deterministic replay, Linux/Android/macOS/Windows/
wasm profile coverage, Apple Silicon and high-core x86 p50/p95/p999 plus CPU,
allocation and RSS measurements, replayable redacted E2E receipts, and a fresh
classified marginal ledger. Only the inventory gate is `STATIC_COMPLETE`; the
other eight gates are `MISSING`.

The disposition is `KEEP_INCUMBENT` and `hashbrown_exit_allowed=false`. The
bead contract explicitly makes missing or inconclusive same-or-better evidence
a successful terminal KEEP outcome, so `tracker_closure_allowed=true` only
with disposition `CLOSE_AS_KEEP_INCUMBENT_ONLY`. The focused remote Rust
contract checks current source pins, the exact call-site and operation
inventory, registry and marginal-ledger joins, and this fail-closed closure
rule. It is not replacement, runtime-parity, benchmark, or platform evidence.
This packet does not authorize source, manifest, or lockfile edits, performance
claims, release readiness, or broad workspace-health claims.

## Host benchmark metadata static audit

`CAP-HOST-BENCH-METADATA-STATIC-AUDIT-V1` records the bounded static audit for
`asupersync-d24mms.2`. It is `STATIC_SOURCE_PINNED_NOT_EXECUTED`: eleven source
pins establish a complete two-of-two inventory at the observed revision, but
no compiler, test, benchmark, host probe, platform matrix, profile matrix, or
E2E scenario was run. Its execution state is therefore
`NO_PLATFORM_OR_PROFILE_MATRIX_EXECUTED`.

Both dependency call sites are in `BenchmarkEnvironment::collect()` behind the
`benchmark-adapters` feature:

- `whoami::distro()` populates `os_info`, degrading detection errors to the
  literal `unknown`;
- `num_cpus::get()` contributes the count in the nonempty
  `<count>x <ARCH>` `cpu_info` string.

The collected schema has six fields and reaches five production result
construction sites plus four unit-only sites. The existing
`tests/atp_benchmark_integration.rs` surface asserted none of `os_info`,
`cpu_info`, or `BenchmarkEnvironment` at the observed audit revision.
`EVD-HOST-TOPOLOGY` is useful adjacent default-profile evidence, but it does not
execute these call sites or compare candidate outputs. The declared
`host_benchmark_metadata` dependency-
sovereignty scenario is not implemented in the retained runner.

Cutover requires SAME-or-BETTER evidence across Linux, macOS, and Windows;
default-negative, `benchmark-adapters`, and benchmark-plus-Criterion profiles;
ordinary, affinity-restricted, quota-constrained, and metadata-error host
contexts; exact schema/operator output; fallback behavior; redaction; replay;
and a favorable marginal-ledger result. Only the source inventory gate is
`STATIC_COMPLETE`; the other seven gates are `MISSING`.

The disposition is `KEEP_INCUMBENT` for both dependencies and
`dependency_exit_allowed=false`. This packet does not authorize manifest,
lockfile, or behavior edits, tracker closure, performance claims, release
readiness, or broad workspace-health claims.

### Claim-time host-metadata source checkpoint

At claim base `706bde7ee34caa356ef675359b2e611dfae3e700`,
`tests/atp_benchmark_integration.rs` adds
`benchmark_environment_host_metadata_candidate_contract`. Its state is
`SOURCE_AUTHORED_NOT_EXECUTED`: no compiler, test, benchmark, host probe, Cargo,
RCH, or platform/profile lane was run.

The contract freezes the incumbent nonempty `os_info`, nonzero
`<count>x <ARCH>` `cpu_info`, and exact six-field serialized
`BenchmarkEnvironment` schema. It also names
`std::thread::available_parallelism()` and
`sysinfo::System::long_os_version()` with explicit `1` and `unknown` fallback
shapes. These candidate APIs are compile/smoke anchors only; their values are
not asserted equal to the incumbent because affinity, container/quota, error,
Linux, macOS, and Windows parity still requires the declared execution matrix.

The machine artifact retains its historical 415-line integration-source pin at
the observed audit revision. The fail-closed Rust contract separately pins the
current 467-line checkpoint so historical evidence is not silently rewritten.
Neither production dependency call changed, and no manifest, lockfile,
marginal-ledger, registry, cutover, or closure state was promoted.

## Claim-time tempfile profile checkpoint

`CAP-TEMP-ARTIFACTS-CLAIM-TIME-STATIC-CHECKPOINT-V1` is the bounded
claim-time checkpoint for `asupersync-d24mms.5` at base revision
`869664efc07f7be8a3e3803d48a786f76151a08d`. Its state is
`SOURCE_AUTHORED_NOT_EXECUTED`: no compiler, formatter, test, Cargo, RCH,
benchmark, service, platform, lifecycle, or E2E lane was run.

The July tracker premise is stale. The normal `tempfile` edge is required by
default-native ATP RaptorQ and QUIC pack-materialization paths, not only by the
`benchmark-adapters` and `test-internals` profiles. The source-authored contract
pins the following current resolution boundaries:

| Resolution profile | Current non-test consumer | Static consequence |
|---|---|---|
| default native library | `src/net/atp/transport_rq/mod.rs` owns four qualified `tempfile` references for pack materialization and lifetime retention | the unconditional native ATP module requires the normal edge |
| default native library | `src/net/atp/transport_quic/mod.rs` owns three pre-test-module qualified references for pack materialization and lifetime retention | the unconditional native ATP module requires the normal edge |
| `cli` | `src/bin/asupersync.rs` stages replay artifacts with `NamedTempFile::new_in` before its test module | CLI optionalization would require `dep:tempfile` in `cli` |
| `benchmark-adapters` | `src/atp/benchmark/suite.rs` owns a `TempDir` work directory | benchmark optionalization would require `dep:tempfile` in `benchmark-adapters` |
| `test-internals` | `src/test_logging.rs` exposes `TempDirFixture` when `test || test-internals` | test-internals optionalization would require `dep:tempfile` in `test-internals` |

The current repository `src/` census contains 80 Rust files and 278 qualified
`tempfile::` tokens. This is a drift detector, not a Cargo-built profile
classification: inline tests and dormant harnesses account for many tokens, so
the checkpoint does not claim zero `UNKNOWN`. The current `tests/` lexical
census contains 96 Rust files: the 94-file claim-base set, this static contract,
and the executable `tests/temp_artifact_lifecycle.rs` fixture. This demonstrates
why lexical presence is not dependency-resolution proof. The dev edge remains
necessary for broad integration and inline tests, the two current benchmark
files, and the test-only example fixture.

At the claim base, `Cargo.toml` still has separate normal and dev declarations
spelled `3.25`, while `Cargo.lock` resolves `3.27.0`. Those are pinned observed
facts, not future version requirements. No feature contains `dep:tempfile`.
Because the default native library already consumes the crate, wiring only the
original two proposed features would be incomplete. The decision is therefore
`KEEP_INCUMBENT` with `normal_dependency_optionalization_allowed=false`.

`Cargo.toml`, `Cargo.lock`, the marginal ledger, the capability registry, and
the canonical baseline artifact remain byte-for-byte unchanged. In particular,
the historical `NO_DEDICATED_RECEIPT` row remains unchanged at its own observed
revision; this newer source-authored checkpoint does not rewrite that snapshot
or masquerade as an execution receipt. The bead remains open for an exact
Cargo-built default/sparse/combined profile inventory, lifecycle and cleanup
evidence, platform coverage, canonical replay/redaction artifacts, and a
serialized manifest/lock/ledger decision only if every capability remains
SAME-or-BETTER.

The follow-up `temp_artifacts` scenario in
`scripts/run_dependency_sovereignty_e2e.sh` is the executable Linux tranche. It
combines the pinned normal-edge manifest/lock contract with Cargo-built default,
sparse `test-internals`, `benchmark-adapters`, and `cli` profiles, their relevant
combined profile, the dedicated
success/error/panic/cancellation/permission/retention/parallel lifecycle
fixture, and focused default ATP, CLI replay, test-logging, and benchmark
consumers. The first admitted lifecycle run exposed inherited group/other mode
bits on a remote worker. The production-owned benchmark, test-fixture, RQ-pack,
and QUIC-pack constructors now request Unix mode `0700`; the executable fixture
requests the same mode and verifies that the benchmark and test-fixture paths
do not expose group/other permissions. Its canonical replay command is
`RCH_REQUIRE_REMOTE=1 bash scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario temp_artifacts`.
This lane does not authorize optionalization: the default native consumers make
`KEEP_INCUMBENT` the no-loss result. It also does not claim macOS or Windows
execution, broad workspace health, performance improvement, or dependency exit.

## Visibility macro static audit

`CAP-VISIBILITY-MACRO-STATIC-AUDIT-V1` records the bounded static audit for
`asupersync-d24mms.7` and now carries terminal receipt
`CAP-VISIBILITY-MACRO-TERMINAL-KEEP-V1`. It is
`TERMINAL_KEEP_SOURCE_PINNED`: fourteen source pins establish the incumbent
feature, macro-crate, attribute, registry, runner, consumer, and
marginal-ledger topology at revision
`52b8b5368ca6c161ed4481fa91f94f0efe6d3c98`. No macro implementation or
comparison matrix ran, so its execution state is
`NO_MACRO_REPLACEMENT_OR_COMPILE_MATRIX_EXECUTED_KEEP_TRIGGERED`.

The current inventory is twelve identical `visibility::make(pub)` tokens
across four production files, correcting the tracker description's stale
ten-file count. Eleven attributes widen `pub(crate)` items only under
`test-internals`; one is attached to the already-public `CurrentCxGuard`.
Observed shapes are two associated const functions, eight associated
functions, one receiver method, and one struct. They include generic inherent
impls, multiline signatures, attributes both before and after `cfg_attr`, and
a function with target-conditioned body branches.

Static token equality is not expansion parity. There is no owned visibility
attribute in `asupersync-macros`, no visibility-specific unit or trybuild
fixture, and no privacy-off fixture. `EVD-PROC-MACROS` covers adjacent owned
macro surfaces only. The baseline declares `test_internals_consumer`, but the
retained runner implements only `contract`, `consumer-default`,
`consumer-full`, and `catalog`; the standalone consumer deliberately excludes
`test-internals`.

The sparse feature topology is also unresolved. `test-internals` currently
enables `dep:visibility` but not `dep:asupersync-macros`, while the macro crate
dev-depends on the root with default features disabled and `test-internals`
enabled. Rewiring that feature could change the package-cycle topology, so a
cycle-free sparse compile is a required receipt rather than a static
assumption.

The marginal ledger contains four older `normal:visibility` rows, all in the
`workspace-dev-build-audit` profile across Linux, macOS, Windows, and wasm.
Each reports one marginal package, no native code or build script, and one
proc macro, but the ledger source revision predates this audit and covers none
of the required sparse profiles. It is graph context, not cutover evidence.

Only the twelve-occurrence inventory gate is `STATIC_COMPLETE`; downstream
semantic classification, UI corpus, privacy-off behavior, sparse-feature and
cycle proof, hygiene/span/diagnostic parity, platform/profile compilation,
downstream replay, and fresh serialized ledger cutover are `MISSING`. The
disposition is `KEEP_INCUMBENT` and `visibility_exit_allowed=false`. This
bead's contract explicitly makes any sparse-feature or hygiene uncertainty a
successful terminal KEEP outcome. `tracker_closure_allowed=true` applies only
to `CLOSE_AS_KEEP_INCUMBENT_ONLY`; the cutover gate itself remains closed. The
focused remote Rust contract checks the current source pins, exact attribute
and item-shape inventory, feature and macro-cycle topology, registry and
marginal-ledger joins, and this fail-closed closure rule. It is not macro
expansion, hygiene, diagnostic, privacy, sparse-feature, package-cycle, or
downstream parity evidence. This packet does not authorize macro publication,
feature rewiring, source, manifest, or lockfile edits, release readiness, or
broad workspace-health claims.

## Slab consumer static audit

`CAP-TOKEN-SLAB-STATIC-AUDIT-V1` records the bounded static audit for
`asupersync-d24mms.8` and now carries terminal receipt
`CAP-TOKEN-SLAB-TERMINAL-KEEP-V1`. It is `TERMINAL_KEEP_SOURCE_PINNED`:
fourteen source pins revalidate the four external production consumers at
revision `3b7cc05c8e848017419312b77f02c9b1129598d5`. No owned collection or
comparison matrix ran, so its execution state is
`NO_REPLACEMENT_OR_CONSUMER_MATRIX_EXECUTED_KEEP_TRIGGERED`.

The tracker baseline remains exact and is not a scope cap:

- `service/rate_limit.rs` stores exhausted registrations behind slot-plus-id
  handles. Refund and refill can detach the whole slab before wake callbacks,
  and final waker destruction stays outside the bucket mutex.
- `sync/semaphore.rs` stores a doubly linked FIFO behind slot-plus-id handles.
  Middle/head removal, cancellation, close, panic, and drop must retain link,
  capacity, and exactly-once retirement semantics.
- `sync/waiter.rs` deliberately separates monotonic `WaiterId` identity from
  reusable slab indices. Vacancy, insertion, removal, direct indexing, and
  deferred waker handling all participate in its contract.
- `time/wheel.rs` stores a generation per slab index. Cancel and expiry must
  reject stale generations, remove activity exactly once, and purge or clear
  the remaining timer storage when empty.

The catalogued evidence does not bind to those consumers.
`EVD-TOKEN-SLAB` points only to `memory_tier_slab_pool_contract.rs`; that
fixture has zero external `slab::Slab` tokens and five `util::Arena` tokens.
It verifies memory-tier capacity planning for the separate arena abstraction.
The baseline's `EXECUTABLE_COMPLETE` classification may describe that fixture,
but it is not an external-slab candidate/differential receipt. The declared
`token_slab_churn` and `token_slab_cancel_cleanup` scenarios are absent from
both retained dependency-sovereignty and aggregate runners.

The four source files declare 40 rate-limit, 73 semaphore, eight waiter, and
48 timer-wheel tests. These are valuable incumbent behavior surfaces,
including stale-id, generation-mismatch, cancellation, FIFO, close, panic,
clear, purge, overflow, and reuse cases. They were not executed here and do
not compare an owned candidate.

The stale marginal ledger contains 52 `normal:slab` rows across thirteen
feature profiles and four targets. Twenty-five rows show no package-ID
reduction because slab remains transitively reachable; twenty-seven remove
one `slab@0.4.12` package. All rows classify the edge `SAFE-OWN` with no native
code, build script, or proc macro. That uneven, older graph opportunity does
not evaluate present consumer behavior, implementation risk, maintenance, or
performance.

Only the four-file call-site inventory is `STATIC_COMPLETE`; evidence binding,
owned-API differential behavior, stale-key safety, cancellation/panic/shutdown
quiescence, property/conformance coverage, real-consumer replay, platform and
profile compilation, performance/resource ratchets, and fresh serialized
ledger cutover are `MISSING`. The disposition is `KEEP_INCUMBENT` and
`slab_exit_allowed=false`. The bead explicitly says to proceed only on a
favorable trust and maintenance tradeoff and otherwise KEEP.
`tracker_closure_allowed=true` applies only to
`CLOSE_AS_KEEP_INCUMBENT_ONLY`; the cutover gate itself remains closed. The
focused remote Rust contract checks the current source pins, exact consumer
operation inventory, registry and marginal-ledger joins, misbound evidence
rejection, and this fail-closed closure rule. It is not candidate behavior,
stale-key safety, cancellation, lifecycle, performance, resource, platform,
or real-consumer replay evidence. This packet does not authorize slab removal,
owned collection publication, source, manifest, or lockfile edits, release
readiness, performance claims, or broad workspace-health claims.

## Phase-2 terminal readiness frontier

`CAP-PHASE2-TERMINAL-READINESS-STATIC-AUDIT-V1` records the bounded refreshed
frontier for `asupersync-d24mms.13` at revision
`376c313540a58d2c8e6618cf40b4ac87ed36ec53`. The result is
`BLOCKED_11_OF_13_PREREQUISITES_NOT_TERMINAL`: the scoped Phase-1 foundation
and Offline Tuner `env_logger` cutover are terminal-ready. The Offline Tuner
child was replayed; the Phase-2 aggregate and the other children were not.

This frontier distinguishes useful landed work from terminal proof. A baseline
capability row marked `EXECUTABLE_COMPLETE` means that the incumbent case
taxonomy is classified; it does not mean the corresponding replacement leaf or
campaign has passed its terminal contract. Likewise, a Git landing proves that
content exists on `main`, not that its focused or aggregate scenario is current
and replayable.

The exact prerequisite partition is:

| Prerequisite | Static state | Landed scope | Missing terminal scope |
|---|---|---|---|
| `asupersync-dep-p1-foundations-upksjk.4` | `FOUNDATION_SCOPED_PASS` | content-pinned Phase-1 foundation receipt | none for its scoped prerequisite role |
| `asupersync-d24mms.1` | `STATIC_KEEP_GATE_LANDED_BLOCKED` | hash-map inventory and KEEP gate | candidate execution, replay, platform, performance, and fresh ledger |
| `asupersync-d24mms.2` | `STATIC_KEEP_GATE_LANDED_BLOCKED` | host metadata inventory and KEEP gate | host contexts, profile/platform matrix, schema output, redaction, and replay |
| `asupersync-d24mms.3` | `EXECUTED_ROOT_EDGE_EXIT_READY` | 30-cell success matrix, five diagnostic failures, privacy improvement, canonical E2E, and root-edge removal | none for its scoped prerequisite role |
| `asupersync-d24mms.4` | `CHECKPOINT_LANDED_BLOCKED` | owned deterministic UTC formatter checkpoint | sparse graph, ledger, and broader DEP-ADR-011 evidence |
| `asupersync-d24mms.5` | `NO_DEDICATED_RECEIPT` | incumbent temporary-artifact baseline only | Cargo-built profile classification and fixture-preserving optionalization decision |
| `asupersync-d24mms.6.10` | `CAMPAIGN_PARTIAL_BLOCKED` | futures-lite A1 inventory | A2-A9 work and A10 terminal receipt |
| `asupersync-d24mms.7` | `STATIC_KEEP_GATE_LANDED_BLOCKED` | twelve-attribute visibility inventory and KEEP gate | owned macro and privacy-off/sparse-feature compile matrices |
| `asupersync-d24mms.8` | `STATIC_KEEP_GATE_LANDED_BLOCKED` | four-consumer slab inventory, evidence-binding defect, and KEEP gate | candidate differential, lifecycle, consumer replay, and performance evidence |
| `asupersync-d24mms.9.5` | `CAMPAIGN_PARTIAL_BLOCKED` | hex A1 inventory and A2 kernel checkpoint | migrations, independent parity, journeys, and A5 terminal receipt |
| `asupersync-d24mms.10.6` | `CAMPAIGN_PARTIAL_BLOCKED` | Base64 A1 inventory | owned engines, migrations, corpus, service matrix, and A6 terminal receipt |
| `asupersync-d24mms.11` | `CHECKPOINT_LANDED_BLOCKED` | bounded scanner plus declared artifact/reassembly route | admitted focused execution and retained replay artifacts |
| `asupersync-d24mms.12.5` | `CAMPAIGN_PARTIAL_BLOCKED` | dormant-E2E A1 inventory | restored journeys and A5 aggregate evidence |

The machine packet pins the exact 13 blocker edges and the 16 capability IDs
already mapped to the Phase-2 terminal in the capability registry. The current
`.beads/issues.jsonl` snapshot is used only for read-only topology. Its status
labels are stale for several landed commits, so Git ancestry and content-pinned
artifacts are the progress authority; the tracker is not completion authority
and was not written.

The state counts are one `FOUNDATION_SCOPED_PASS`, one
`EXECUTED_ROOT_EDGE_EXIT_READY`, four `STATIC_KEEP_GATE_LANDED_BLOCKED`, two
`CHECKPOINT_LANDED_BLOCKED`, four `CAMPAIGN_PARTIAL_BLOCKED`, and one
`NO_DEDICATED_RECEIPT`. Therefore
`phase2_terminal_signoff_allowed=false`, `dependency_exit_allowed=false`, and
`tracker_closure_allowed=false`. The required next state is
`ALL_13_PREREQUISITES_TERMINAL_AND_REPLAYED_WITH_ZERO_UNKNOWN`; any missing,
stale, unreplayed, or regressed row keeps the incumbents and blocks Phase-2
signoff.

The Offline Tuner child ran remote unit, real-binary integration, canonical
E2E, formatter, ledger-regeneration, and focused contract lanes. No Phase-2
aggregate, broad workspace, cross-platform, benchmark-performance, service,
model, fuzz, or release lane was executed for this frontier. The remaining
blocked rows authorize no source, manifest, lockfile, tracker, dependency,
release, performance, broad-health, or deletion action.

## High-risk boundaries

- SQLite uses the incumbent real-file/WAL corpus, but FrankenSQLite is
  currently a reverse dependency. It may be compared only from a neutral
  synthesized consumer or the downstream repository; adding it to asupersync
  would create a Cargo cycle.
- Kafka authentication fixtures are not a Kafka client. Produce/consume,
  transactions, groups, rebalance, coordinator, security, fault, and restart
  behavior stay blocked on pinned real brokers.
- X.509 incumbent tests do not authorize owning certificate validation or
  cryptography. rustls/webpki remains the delegated validator unless the
  complete security epic passes.
- Regex examples do not narrow the accepted regex language. Fixed scanners are
  not a substitute for arbitrary user patterns.
- Compression includes Brotli. DEFLATE evidence cannot silently remove it.
- Linux evidence does not stand in for macOS, Windows, BSD, browsers, kqueue,
  IOCP, control events, xattr variants, or host-introspection fields.
- Functional concurrency evidence does not establish performance. Apple
  Silicon and representative high-core-count Intel/AMD measurements remain
  separate acceptance gates.

## Generated summary

<!-- BEGIN GENERATED BASELINE SUMMARY -->
- Artifact: `dependency-capability-baseline-v1` (schema 1)
- Coverage: 50 capabilities; 40 evidence entries; 2 consumer profiles.
- States: BLOCKED_EXTERNAL=5, BLOCKED_PLATFORM=6, EXECUTABLE_COMPLETE=12, EXECUTABLE_PARTIAL_BLOCKING=27.

| Capability ID | Baseline state | Evidence | Blocked cases |
|---|---|---:|---:|
| `CAP-ATP-VERSION-SCANNER` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-AUTH-CREDENTIALS` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-BASE64-CODEC` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 1 |
| `CAP-BROWSER-RUNTIME` | BLOCKED_PLATFORM | 1 | 2 |
| `CAP-CACHE-LAYOUT` | BLOCKED_PLATFORM | 2 | 1 |
| `CAP-CLI-ASUPERSYNC` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 3 |
| `CAP-CLI-ATP` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-CLI-ATPD` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-CLI-OFFLINE-TUNER` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-CONCURRENT-QUEUES` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-CONFIG-TOML-JSON` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-DATABASE-WIRE` | BLOCKED_EXTERNAL | 2 | 2 |
| `CAP-DEPENDENCY-LEDGER` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-DIAGNOSTICS` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-DOWNSTREAM-CONSUMERS` | EXECUTABLE_COMPLETE | 3 | 0 |
| `CAP-FUTURES-STREAMS` | EXECUTABLE_COMPLETE | 2 | 0 |
| `CAP-HASH-MAPS` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-HEX-CODEC` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-HOST-BENCH-METADATA` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-HOST-INTROSPECTION` | BLOCKED_PLATFORM | 1 | 1 |
| `CAP-HTTP-COMPRESSION` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-KAFKA` | BLOCKED_EXTERNAL | 1 | 2 |
| `CAP-LAB-DETERMINISM` | EXECUTABLE_COMPLETE | 2 | 0 |
| `CAP-NATS-MESSAGING` | BLOCKED_EXTERNAL | 2 | 2 |
| `CAP-NKEY-AUTH` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 3 |
| `CAP-OTLP-ECOSYSTEM` | BLOCKED_EXTERNAL | 2 | 2 |
| `CAP-PERSISTED-TRACE-SNAPSHOT` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-POLLING-SOCKET` | BLOCKED_PLATFORM | 1 | 1 |
| `CAP-PROC-MACROS` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 1 |
| `CAP-PROTOBUF-GENERIC` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-PUBLIC-API-TOPOLOGY` | EXECUTABLE_PARTIAL_BLOCKING | 3 | 2 |
| `CAP-QUIC-HTTP3-ATP` | EXECUTABLE_PARTIAL_BLOCKING | 3 | 1 |
| `CAP-REAL-SERVICE-E2E` | BLOCKED_EXTERNAL | 5 | 3 |
| `CAP-REGEX-PRIVACY` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 3 |
| `CAP-SCENARIO-YAML-JSON` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 1 |
| `CAP-SERDE-GENERIC` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-SIGNALS` | BLOCKED_PLATFORM | 1 | 1 |
| `CAP-SIMD-RAPTORQ` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-SQLITE` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-STRUCTURED-CONCURRENCY` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-SYNC-LOCKS` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-TEMP-ARTIFACTS` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 2 |
| `CAP-TIME-UTC-RFC3339` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 1 |
| `CAP-TLS-X509` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-TOKEN-SLAB` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-TOWER-COMPAT` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 4 |
| `CAP-TRACE-LZ4` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-VERIFICATION-PROFILES` | EXECUTABLE_COMPLETE | 2 | 0 |
| `CAP-VISIBILITY-MACRO` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-XATTR` | BLOCKED_PLATFORM | 1 | 1 |
<!-- END GENERATED BASELINE SUMMARY -->

## No-claim boundary

This baseline does not prove replacement parity, broad workspace health,
release readiness, production correctness, performance improvement, live RCH
fleet availability, or permission to delete anything. Every cutover stays
serialized behind CAP A4, VER A1/A2, campaign-specific unit and no-mock E2E
evidence, graph/oracle/rollback disposition, security review, platform/service
matrices, and owner signoff.
