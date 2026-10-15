# Working Inside the Asupersync Repo

Rules from AGENTS.md for AI coding agents working in this codebase.

## Contents

- [Critical Rules](#critical-rules)
- [Backwards Compatibility](#backwards-compatibility-v043-hard-gate)
- [Editing and Compilation](#code-editing-discipline)
- [Testing](#testing)
- [Features and Dependencies](#feature-flags)
- [Multi-Agent and Session Closeout](#multi-agent-environment)
- [Documentation and Release Evidence](#key-documentation)
- [RCH, Migration, UBS, and Beads](#rch-remote-compilation-helper)
- [ATP Benchmark Discipline](#atp-benchmark-discipline)

## Critical Rules

1. **NEVER delete files** without express written permission. Even files you created.
2. **NEVER run destructive commands** (`git reset --hard`, `git clean -fd`, `rm -rf`) without explicit user authorization.
3. **Work only on `main`**. Do not create branches or worktrees. In the live
   Asupersync workflow, the legacy compatibility ref is mirrored only by the
   exact command in `AGENTS.md`; do not add branch-name references to docs or
   code.
4. **Rust 2024 edition**, nightly toolchain (`rust-toolchain.toml` pins
   `nightly-2026-07-05`).
5. **Cargo only** -- no other package manager.
6. **`#![deny(unsafe_code)]`** with per-module `#[allow(unsafe_code)]` where required.
7. **Backwards compatibility is a hard release gate.** Asupersync ships to
   downstream production consumers; see the section below.

## Backwards Compatibility (v0.4.3 Hard Gate)

Current workspace version is 0.4.9 (v0.4.0 -> v0.4.9 shipped 2026-08-07 ->
2026-08-20). For every `0.4.x` release, compatibility with the public API and
documented behavior of **v0.4.3** is a hard release gate (AGENTS.md
"Backwards Compatibility"):

- No removal/rename/visibility reduction/signature change of public items, and
  no documented-behavior change, without explicit written user approval for
  that exact break. Prefer additive APIs; deprecations must keep working
  through `0.4.x`.
- Before release: compare the public surface against v0.4.3 and compile
  representative downstream consumers; unexplained breaks hold the release.
- Downstream-reported regressions must be reduced to a permanent in-repo test
  using the same public API sequence (native runtime, not only `LabRuntime`,
  for scheduler/cancel/wakeup/protocol semantics); that focused lane becomes a
  permanent release blocker.
- **Escaped-defect protocol** (AGENTS.md): reproduce on the consumer's
  execution class, prove the formerly failing state was reached, assert exact
  result + cleanup invariants, keep an old-red/new-green receipt, audit the
  whole boundary with a census, wire the focused lane before broad fail-fast
  suites (rejecting zero/filtered/ignored-test output), run the downstream
  canary, and document the gap analysis. Weakening any of this needs explicit
  written user approval.
- Ignore any older repo text claiming Asupersync "has no users" or need not
  preserve compatibility -- the user has explicitly overridden it.
- The generic 0.x caveat in `src/lib.rs` is not permission for casual breaks;
  live `AGENTS.md` and the audited v0.4.3 floor are the governing policy.

## Forbidden Crates

Keep Tokio and Tokio-backed framework crates out of core `src/`: `tokio`,
`hyper`, `reqwest`, `axum`, `async-std`, `smol`, and crates that pull Tokio into
production core. Scoped exceptions live in `asupersync-tokio-compat/`,
conformance scaffolding, fuzz/bench/differential support, and explicitly
feature-gated adapter edges. `tower` can be an optional adapter surface; do not
turn it into the core runtime story.

## Code Editing Discipline

- **Never** run scripts that process/change code files. Make changes manually.
- **Never** create file variations (e.g., `mainV2.rs`, `main_improved.rs`).
- New files only for genuinely new functionality. Bar is very high.
- Revise existing code files in place.

## Compiler Checks (Mandatory After Code Changes)

```bash
rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_check_all_targets" cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_clippy_all_targets" cargo clippy --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_fmt_check" cargo fmt --check
```

Installed RCH may reject `cargo fmt --check` because formatting is not a
compilation command. If that happens, run the repository-accepted local,
read-only formatter check on the touched files and report that boundary
explicitly; do not represent the RCH refusal as formatter execution.

Those three commands use the **default** feature set only. Every
`required-features` target and every module behind `postgres`, `mysql`,
`sqlite`, `tls`, `kafka`, `quic`, `messaging-fabric`, `cli`, `io-uring`, or
`simd-intrinsics` is silently skipped by them. Before landing anything touching
a feature-gated surface, also run (per AGENTS.md; `--keep-going` is mandatory):

```bash
rch exec -- env CARGO_TARGET_DIR=... cargo check --all-targets --all-features --keep-going
rch exec -- env CARGO_TARGET_DIR=... cargo clippy --all-targets --all-features --keep-going -- -D warnings
```

Use a narrower command only when the user, bead, or proof-lane manifest
explicitly narrows the scope. Do not silently fall back to local builds when
remote `rch` proof is required; preserve the failing command and blocker
instead. Before selecting proof, read live `TESTING_FOR_AGENTS.md`, coordinate
before starting competing long-running proof jobs, and record the RCH build id,
target dir, artifact root, and dirty-tree state for any cited result.

Repo-internal proof is not the same thing as a downstream migration inventory;
for that, use `scripts/migration_readiness_planner.py` (see below).

## Testing

Many modules include inline `#[cfg(test)]` unit tests; integration, conformance,
and contract suites cover other surfaces. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

For concurrency-sensitive behavior, prefer deterministic lab-runtime tests.

### Native parked-task cancellation (release-blocking contract)

Cancellation changes to `Cx`, `TaskHandle`, scheduler wakeup, spawn wrappers,
or cancel-aware primitives MUST run the focused native lane
(`native-parked-task-cancellation` in the proof-lane manifest):

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --locked --test runtime_abort_vs_cancel_semantics_audit -- --nocapture
```

`scripts/run_proof_checks.sh` runs this as its **first required proof**, before
the broader rust-proof lanes (certificate verification, obligation formal
checks, lab oracle invariants, cancellation protocol, combinator laws, TLA+
export, trace canonicalization), the integration lanes (lease semantics, close
quiescence, refinement conformance), and the optional Lean build.
`tests/proof_lane_manifest_contract.rs` pins that ordering and the fail-closed
`RCH_REQUIRE_REMOTE=1` policy; the wrapper rejects local-fallback banners and
zero/filtered test output. Reordering, filtering, or skipping this lane is a
release-blocking regression. Never publish terminal join results through a
cancelled `Cx`; runtime `TaskHandle` producers use the capability-restricted
`TaskResultSender` (a raw oneshot replacement is a release-blocking regression).

FrankenGraphDB migrated its stale cancellation expectation, and v0.4.9 ships
the exact-v0.4.4 canary. Stale `asupersync-yqlhh7.1` tracker status is not
contrary evidence.

### Test Commands

```bash
T="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}"
rch exec -- env CARGO_TARGET_DIR="$T/rch_target_test_all" cargo test --features test-internals <filter>
rch exec -- env CARGO_TARGET_DIR="$T/rch_target_test_asupersync_macros" cargo test -p asupersync-macros
rch exec -- env CARGO_TARGET_DIR="$T/rch_target_test_asupersync_conformance" cargo test -p asupersync-conformance
rch exec -- env CARGO_TARGET_DIR="$T/rch_target_test_frankenlab" cargo test -p frankenlab
```

(`franken-kernel`, `franken-evidence`, and `franken-decision` have analogous
`-p` lanes.) Release/proof lanes stay fail-closed under `RCH_REQUIRE_REMOTE=1`.

### Test Categories

| Area | Focus |
|------|-------|
| `types/` | IDs, outcomes, budgets, policies, serialization round-trips |
| `record/` | Task/region/obligation record creation, state transitions |
| `runtime/` | Scheduler fairness, state management, region lifecycle |
| `cx/` | Capability context, scope API, structured concurrency contracts |
| `channel/` | Two-phase reserve/send, MPSC/oneshot, cancel-correctness |
| `sync/` | Mutex, RwLock, Semaphore, Pool, Barrier, OnceCell -- cancel-awareness |
| `combinator/` | Join, race, timeout, bulkhead, retry -- loser drain correctness |
| `cancel/` | Cancellation protocol, symbol cancel, drain/finalize lifecycle |
| `obligation/` | Permit/ack/lease commit/abort, no-leak invariant |
| `lab/` | Virtual time, deterministic scheduling, DPOR, oracles |
| `net/` + `io/` | Async I/O adapters, socket integration |
| `http/` | HTTP/1.1, HTTP/2 protocol correctness |
| `codec/` | Framing, encoding/decoding round-trips |
| `conformance/` | Cross-component conformance suite |
| `benches/` | Scheduler, timer wheel, reactor, cancel/drain, RaptorQ |

### E2E and Benchmarks

Do not copy a bare benchmark or `NO_PREFLIGHT=1` command from this skill. Read
live `AGENTS.md`, `TESTING_FOR_AGENTS.md`, the relevant proof-lane manifest row,
and the benchmark runbook first. Repository proof must use the exact required
RCH command and prerequisites. A downstream local benchmark may be useful
smoke evidence, but it is not repository release or performance proof.

## Feature Flags

This is a selected, non-exhaustive inventory. Read live `Cargo.toml` before
making a support, dependency-graph, or release claim.

| Flag | What |
|------|------|
| `proc-macros` | Default macros and entry attributes, plus `ProtoMessage` / `ProtoOneof`; `session_protocol!` is explicit-path-only |
| `nightly-outcome-try` | Default nightly `Outcome` ergonomics |
| `test-internals` | Opt-in test helpers -- NOT for production |
| `runtime-metrics` / `metrics` | Runtime counters and telemetry surfaces |
| `wasm-browser-*` | Canonical browser profiles |
| `real-service-e2e` + focused E2E flags | Environment-gated no-mock service proof lanes |
| `tls` / `tls-native-roots` / `tls-webpki-roots` | TLS via rustls |
| `sqlite` / `postgres` / `mysql` | Database clients |
| `quic` / `http3` / `atp-cli` | Feature-gated QUIC/H3/ATP surfaces; `atp-cli` implies TLS |
| `atpd-daemon` | Unpublished ATP daemon binary gate, outside default release checks |
| `kafka` | Kafka client integration via rdkafka |
| `messaging-fabric` | Feature-gated native FABRIC lane; external Redis, NATS/JetStream, and Kafka clients are separate surfaces |
| `compression` | HTTP response compression (gzip/deflate/Brotli) |
| `io-uring` | Linux io_uring reactor |
| `tower` | Tower Service adapter |
| `ci-cross-platform` | Cross-platform CI umbrella; excludes benchmark-only Tokio quarantine |
| `benchmark-adapters` / `criterion-benches` | Benchmark-only lanes; do not cite as core production graph proof |
| `lock-metrics` | ContendedMutex tracking |
| `loom-tests` | Loom verification |
| `simd-intrinsics` | AVX2/NEON GF(256) for RaptorQ |

Also classify `waker-profiling` and `runtime-metrics` as instrumentation;
`dependency-ledger`, `cancel-correctness-oracle`, and `lab-stack-traces` as
proof/internal; `fuzz` as a deliberate Tokio-carrying fuzz quarantine; and
`tokio-compat` as a marker whose actual wrappers live in the separate compat
crate. `metrics` is an optional native production feature and remains Tokio-free
on its normal dependency edge. `ci-cross-platform` is an umbrella, not proof
that every optional production surface was exercised.

## Output Style

- Core code should not write to stdout/stderr
- Use structured tracing via `Cx::trace` for observability
- Keep tests deterministic; avoid time-based logging outside lab runtime

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `thiserror` | Error derivation |
| `crossbeam-queue` | Lock-free queues |
| `parking_lot` | Fast sync primitives |
| `polling` | Portable epoll/kqueue/IOCP |
| `slab` | Pre-allocated storage |
| `smallvec` | Stack-allocated vectors |
| `pin-project` | Safe pin projections |
| `serde` + `serde_json` | Serialization |
| `socket2` | Low-level sockets |
| `rustls` | TLS (optional) |
| `rusqlite` | SQLite (optional) |
| `proptest` | Property testing (dev) |
| `criterion` | Benchmarks (dev) |
| `rayon` | Data parallelism for CPU-bound work (dev/bench only) |

## Dependency Policy

- Prefer `std`/`core` and small, focused crates
- No other executor/runtime in core
- New crates must preserve determinism in lab runtime
- No ambient globals

## Multi-Agent Environment

Other agents may be working on the project simultaneously. Treat their changes as your own -- never stash, revert, overwrite, or disturb their work.

Start repo-internal sessions by reading `AGENTS.md` and `README.md`, then use
Agent Mail reservations before editing. Reserve exact files/globs, tie
reservations and messages to the bead id when one exists, and avoid broad
claims.

## Session Completion Protocol

Classification, explanation, diagnosis, and review requests are read-only:
inspect evidence and report without changing Beads, files, Git history, or
remotes. Use the mutation sequence below only when the user authorized changes,
you actually own modified paths, and any relevant Bead is active.

1. File issues for genuinely remaining work only when tracker mutation is in
   scope.
2. Run quality gates appropriate to the files that actually changed.
3. Update only the owned issue state and evidence.
4. Pull/rebase when required by live repository state, sync owned Beads changes,
   and commit only path-limited owned changes.
5. Push `main`, then follow the live repository instructions for mirroring its
   legacy compatibility ref; do not create or work on a second branch.
6. Release reservations and hand off context. If push/rebase is blocked by peer
   state, report the exact command and blocker.

## Key Documentation

| File | Purpose |
|------|---------|
| `asupersync_plan_v4.md` | Design bible and core invariants |
| `asupersync_v4_formal_semantics.md` | Small-step operational semantics |
| `TESTING.md` | Comprehensive testing guide |
| `TESTING_FOR_AGENTS.md` | Current testing instructions for agents |
| `AGENTS.md` | AI agent guidelines (source of truth) |
| `README.md` | Project overview |
| `CHANGELOG.md` | Current release notes, Unreleased scope, and tag/release caveats |
| `artifacts/api_surface_map_v1.json` | Machine-readable public API map |
| `docs/error_codes/registry.json` | `ASUP-Exxx` runtime error-code registry (pinned by `tests/error_code_registry_contract.rs`) |
| `artifacts/proof_lane_manifest_v1.json` | Proof-lane source of truth |
| `artifacts/proof_status_snapshot_v1.json` | Current proof status snapshot |
| `artifacts/semantic_evidence_bundles_v1.json` / `artifacts/public_guarantee_semantic_evidence_bundles_v1.json` | Claim/evidence bundles for public guarantees |
| `artifacts/proof_evidence_debt_graph_contract_v1.json` | Proof debt graph contract |
| `artifacts/proof_lane_failure_repro_receipt_contract_v1.json` | Failure reproduction receipt contract |
| `artifacts/reservation_aware_fallback_work_finder_contract_v1.json` | Reservation-aware fallback work finder contract |
| `artifacts/swarm_proof_lane_planner_contract_v1.json` | Swarm proof-lane planner contract |
| `artifacts/migration_readiness_planner_signoff_v1.json` | Migration planner signoff and proof-status claim |
| `artifacts/phase6_methodology_gate_enforcement_contract_v1.json` | Direct-main vs PR/release-review gate contract |
| `artifacts/runtime_pressure_control_evidence_contract_v1.json` | Runtime pressure-control evidence contract |
| `artifacts/unsafe_boundary_ledger_v1.json` | Audited unsafe exceptions and no-claim boundaries |
| `artifacts/fourth_wave_governor_final_signoff_v1.json` | Scoped fourth-wave governor aggregate |
| `artifacts/artifact_governance_final_signoff_v1.json` | Scoped artifact-governance aggregate |
| `artifacts/memory_residency_replay_e2e_contract_v1.json` / `artifacts/memory_residency_operator_safety_contract_v1.json` | Experimental memory-residency replay and operator boundaries |
| `artifacts/clean_overlay_proof_orchestration_v1.json` / `artifacts/proof_traffic_final_signoff_v1.json` | Clean-overlay and proof-traffic orchestration contracts |
| `artifacts/dependency_supply_chain_policy_v1.json` / `artifacts/dependency_budget_contract_v1.json` | Dependency policy and graph-budget contracts |
| `artifacts/browser_ga_final_signoff_v1.json` | Scoped JS/TS browser GA packet |
| `docs/atp_bench_matrix_spec.md` | ATP benchmark acceptance contract |
| `docs/atp_rq_beat_rsync_ledger.md` | Append-only ATP benchmark evidence ledger and refuted-hypothesis history |
| `scripts/atp_bench/MATRIX.md` | ATP matrix operator runbook / command guide |

## RCH (Remote Compilation Helper)

`rch` offloads cargo builds to remote workers:

```bash
rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_build_release" cargo build --release
rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_test_all" cargo test --features test-internals
rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_clippy" cargo clippy
rch doctor       # health check
rch workers probe --all  # test connectivity
```

Add `RCH_REQUIRE_REMOTE=1` whenever the lane must fail closed on remote proof.

If unavailable, preserve the remote-proof failure instead of quietly proving a
different local command.

Admission refusal, exit 103, worker selection, a remote PID, or an RCH job that
never reaches terminal Cargo output proves no test result. Record it as zero
executed tests. For a green claim require terminal output at the exact commit,
positive named-sentinel counts, and zero failed/ignored/measured/filtered tests
where the lane contract requires those fields.

Do not key source or evidence authority to a checkout prefix. `/dp/...`,
`/data/projects/...`, and RCH content-addressed roots vary by host. Validate
repository identity and complete evidence, then emit a bounded blocked receipt
for incomplete mounts instead of creating worker-lottery behavior.

## Phase 6 / Release-Gate Artifacts

For hot-path, safety, release-review, or proof-policy work, read the current
README Phase 6 policy-gate section before choosing validation. Triggered gates
may require scoped `rch` benchmark output, golden checksums, flamegraphs, or
proof-note artifacts committed with the change. A green broad `check`/`clippy`
run is not a substitute for a triggered artifact gate.

Do not infer release status from `Cargo.toml` version alone. `CHANGELOG.md`
separates published GitHub Releases from plain tags and active Unreleased work;
verify tags, releases, Cargo/package metadata, and changelog together.

Use a three-layer proof model: the manifest defines a command, guarantee,
resource envelope, and explicit no-claims; the status snapshot records
freshness and blockers; only a terminal execution receipt proves the command
ran. A green structural contract proves only its declared schema/docs surface.

## Migration Readiness Planner

For downstream Rust migrations, the quick inventory script is only a fast grep /
`cargo tree` aid. The repo's richer read-only planner is
`scripts/migration_readiness_planner.py`; use it when the task is to decide
whether or how to migrate a real project. Map:

- `summary.final_verdict` to the migration/adoption lane,
- `proof_pack.proof_commands` to validation obligations,
- `semantic_map.recommendations` to concrete rewrite targets,
- `operator_report.phase_plan` to staged rollout and handoff.

The proof-lane manifest contains the planner signoff lane. Do not replace this
with ad hoc dependency search when the user asks for migration readiness.

## UBS (Ultimate Bug Scanner)

```bash
ubs file.rs                          # specific file
ubs $(git diff --name-only --cached) # staged files
ubs --ci --fail-on-warning .         # CI mode
```

Exit 0 = safe. Exit >0 = fix and re-run.

## Beads Issue Tracking

```bash
br ready              # show ready work
br list --status=open # all open
br show <id>          # issue details
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br sync --flush-only  # export (no git ops)
```

When tracker mutation was authorized and this session actually changed owned
Beads rows, run `br sync --flush-only` and stage only the owned tracker delta.
Do not mutate or stage `.beads/` for a read-only classification/review, and do
not stage unrelated peer tracker changes.

Beads is authoritative for tracker intent, dependencies, comments, and recorded
acceptance evidence, but not automatically for shipped status. Corroborate an
`open` or `in_progress` label against tagged source, release artifacts, and the
acceptance record; current rows such as the shipped runtime-handle context work
demonstrate that status can lag. Use CASS for prior rationale and working
hypotheses, never as a substitute for current source when its index is stale or
quarantined.

## ATP Benchmark Discipline

For ATP work, `scripts/atp_bench/run_matrix_cell.sh`,
`scripts/atp_bench/score_matrix.py`, `scripts/atp_bench/MATRIX.md`,
`docs/atp_bench_matrix_spec.md`, and `docs/atp_rq_beat_rsync_ledger.md` work
together, but they do not have the same authority. `MATRIX.md` is the operator
runbook; `docs/atp_rq_beat_rsync_ledger.md` is the append-only evidence ledger
for results, refuted hypotheses, and no-claim boundaries. Do not claim a win
unless the current matrix cell beats tuned rsync under the requested
crypto/auth/link conditions with SHA/tamper checks and timing/byte evidence.

Run sequence for serious ATP claims:

1. `bash scripts/atp_bench/selftest_matrix.sh` (harness sanity, no root).
2. Release `atp` binary for the exact feature tier (`--features atp-cli`).
3. `scripts/atp_bench/matrix_bench.sh` (resumable planner; `--execute` drives
   `run_matrix_cell.sh` per hermetic netns cell). Delta re-sync claims use
   `scripts/atp_bench/resync_bench.sh` instead.
4. `scripts/atp_bench/score_matrix.py` (`--fail-on-mismatch` is the harness's
   fail-closed scoring gate; no GitHub CI job runs it).
5. Ledger update in `docs/atp_rq_beat_rsync_ledger.md` and/or matrix artifact.

Stale cells are blockers unless the claim is explicitly scoped to the fresh cell.

A single fresh matrix cell can support only that scoped cell/regression claim.
Headline ATP claims such as "beats rsync" require whole-matrix evidence and must
report weak spots, stale cells, failures, and no-claim boundaries instead of
cherry-picking favorable cells.
