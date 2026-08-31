# Source Map

## Table of Contents

- [What Is Asupersync?](#what-is-asupersync)
- [Release and Live-HEAD Status](#release-and-live-head-status)
- [Core Types Quick Reference](#core-types-quick-reference)
- [Workspace Structure](#workspace-structure)
- [Module Map (`src/`)](#module-map-src)
- [Read In This Order](#read-in-this-order)
- [When You Need Tracker Context](#when-you-need-tracker-context)

## What Is Asupersync?

A spec-first, cancel-correct, capability-secure async runtime for Rust with
1,700+ tracked files under `src/`, including 1,400+ Rust files; the generated
API map currently lists 19 entry points, 120 modules, and 315 root exports.
That artifact is a lexical root-export inventory: it has no per-item support
class, includes cfg-gated test/legacy modules, and proves neither default
production availability nor runtime behavior. Refresh live counts from
`artifacts/api_surface_map_v1.json` and `git ls-files` at the declared
repository root before quoting them. Not a Tokio wrapper -- a broad
support-class-scoped replacement for Tokio stacks, with stronger
guarantees:

- **Structured concurrency**: every task owned by a region; region close = quiescence
- **Cancel-correctness**: cancellation is request -> drain -> finalize (not silent drop)
- **Two-phase effects**: reservation/commit APIs protect selected channel and
  effect boundaries from cancellation-window data loss
- **Capability security**: effects are gated by held `Cx` authority; ambient
  lookup can mirror an installed context but cannot mint authority
- **Deterministic testing**: `LabRuntime` with virtual time, DPOR, oracles, chaos injection
- **Obligation tracking**: permits/acks/leases must resolve by commit or abort;
  guard types may perform an explicit abort action on drop
- **Networking stack**: TCP, HTTP/1.1, HTTP/2, WebSocket, TLS, gRPC, DNS,
  feature-gated native QUIC/H3, and ATP transport lanes
- **Database clients**: SQLite, PostgreSQL (wire protocol), MySQL (wire protocol)
- **OTP-style supervision**: actors, GenServer, supervision trees, AppSpec, Spork
- **Proof and evidence lanes**: API surface maps, proof manifests, validation
  snapshots, and benchmark matrix artifacts are source-of-truth inputs

## Release and Live-HEAD Status

Last reconciled: 2026-08-21.

| Boundary | Current status | Authority |
|---|---|---|
| Published Rust release | v0.4.9 is the functional baseline | annotated tag, release registry, `Cargo.toml` |
| 0.4.x compatibility floor | v0.4.3 public API and documented behavior remain mandatory | live `AGENTS.md` compatibility policy |
| Unreleased `main` delta | Registered unary `ServiceHandler` implementations can route over native H2 through additive `ServiceHandlerFuture`, `call_unary`, `dispatch_registered_unary`, `dispatch_registered_unary_with_trailers`, `bind_registered_http2`, and `serve_http2`; legacy-shaped impl blocks need no new required trait item, while metadata-only dispatch and `Server::serve` retain their established fail-closed/probe roles | commit `3c73a334c`; `src/grpc/{service,server}.rs`; focused real-H2 and audit tests |
| Open correctness boundaries | Callback/waker execution under runtime-state locks (`asupersync-909482`) and ATP receive-watchdog acceptance (`asupersync-2qas9c`) remain unshipped until live tracker/source evidence says otherwise | live Beads plus focused source/proof |

This card is the canonical summary for current release, post-release, and
open-boundary state. Domain references may explain a boundary where it is
operationally necessary, but should route here for its current status instead
of independently maintaining volatile tracker labels. Refresh the card from
tagged source, the live tracker, registry state, and terminal receipts; CASS
supplies rationale, not current-state authority.

### Six Non-Negotiable Invariants

1. **Structured concurrency**: every task/fiber/actor owned by exactly one region
2. **Region close = quiescence**: no live children + all finalizers done
3. **Cancellation is a protocol**: request -> drain -> finalize (idempotent)
4. **Losers are drained**: races must cancel and fully drain losers
5. **No obligation leaks**: permits/acks/leases must resolve by commit or abort
6. **No ambient authority minting**: effects flow through held `Cx` capabilities;
   ambient lookup can only mirror an already-installed context

## Core Types Quick Reference

| Type | Purpose |
|------|---------|
| `Cx` | Capability context -- put `&Cx` first in effectful async APIs you control; v0.4.9 exposes additive embedder blocking-pool wiring; legacy and adapter surfaces may differ |
| `Scope` | Current-region handle and child-region API; ordinary spawning goes through `Cx::spawn` / `Cx::spawn_in` |
| `Outcome<T, E>` | Four-valued: `Ok`, `Err`, `Cancelled(reason)`, `Panicked(payload)` |
| `Budget` | Bounded cleanup: deadline, poll quota, cost quota, priority; meet takes `min` for deadline/quotas and `max` for priority |
| `Region` / `RegionId` | Structured concurrency scope -- owns tasks, closes to quiescence |
| `TaskId` | Identifier for spawned tasks |
| `ObligationId` | Identifier for a tracked permit/ack/lease whose state resolves by commit or abort |
| `CancelKind` | `User`, `Timeout`, `Deadline`, `PollQuota`, `CostBudget`, `FailFast`, `RaceLost`, `ParentCancelled`, `ResourceUnavailable`, `Shutdown`, `LinkedExit` |
| `LabRuntime` / `LabConfig` | Deterministic runtime with virtual time for testing |
| `ForcedSchedule` / `ForcedScheduleDecodeLimits` | Exact bounded Lab dispatch recording, canonical artifact decoding, and fail-closed replay (`lab::runtime`) |
| `RuntimeBuilder` | Construct production runtime: `current_thread()`, `low_latency()`, `high_throughput()` |
| `CheckedJoinHandle<T>` | Additive runtime-handle join path with typed `JoinError`; legacy `JoinHandle<T>` remains supported |
| `SqliteOperationError` / `SqliteErrorDiagnostic` | Opt-in, redaction-safe SQLite operation/category/retry/code diagnostics; established SQLite methods still return `SqliteError` |
| `AppSpec` | Application topology with supervision, registry, restart policy |

Severity lattice: `Ok < Err < Cancelled < Panicked`. Monotone aggregation.

## Workspace Structure

| Workspace member / package | Purpose |
|-------|---------|
| `asupersync` | Main runtime (1,700+ tracked files under `src/`, 120 API-map modules) |
| `asupersync-macros` | Proc macros: `scope!`, `spawn!`, `join!`, `join_all!`, `race!`, `select!`; entry attributes `#[main]`, `#[test]`, `#[lab_test]`; protobuf derives `ProtoMessage` / `ProtoOneof`; explicit-path-only `proc_macros::session_protocol!` |
| `asupersync-browser-core` | Canonical browser-runtime core for JS/TS packages |
| `asupersync-tokio-compat` | Quarantined interop bridge for stubborn Tokio-only dependencies |
| `conformance` / `asupersync-conformance` | Conformance test suite |
| `franken_kernel` / `franken-kernel` | FrankenSuite type substrate |
| `franken_evidence` / `franken-evidence` | Evidence ledger schema |
| `franken_decision` / `franken-decision` | Decision contract runtime |
| `frankenlab` | Deterministic testing harness |
| `drop_unwrap_finder` | Workspace diagnostic tool |

`fuzz` and `asupersync-wasm` may appear in the tree as excluded scaffolds; do
not treat them as canonical workspace members without checking `Cargo.toml`.
Minimal builds without `proc-macros` do not receive a functional fallback DSL:
`join!` and `race!` deliberately compile-error, while several other macros are
unavailable until the feature is restored.

## Module Map (src/)

| Module | What It Does |
|--------|--------------|
| `types/` | IDs, Outcome, Budget, CancelKind, Policy, WASM ABI |
| `record/` | TaskRecord, RegionRecord, ObligationRecord |
| `error/` / `error.rs` | Error kinds, typed runtime errors, and user-facing diagnostics |
| `config.rs` | Runtime and feature configuration plumbing |
| `prelude.rs` | Common public imports for downstream users |
| `runtime/` | Three-lane scheduler, sharded state, builder, config, reactor, blocking pool, timer, region heap |
| `cx/` | Cx, Scope, registry |
| `channel/` | MPSC, oneshot, broadcast, watch, session (two-phase) |
| `sync/` | Mutex, RwLock, Semaphore, Barrier, Notify, OnceCell, Pool, ContendedMutex |
| `combinator/` | join, race, timeout, quorum, hedge, circuit_breaker, bulkhead, retry, rate_limit, bracket, pipeline, map_reduce, first_ok, laws.rs |
| `cancel/` | Cancellation protocol, progress certificates (Freedman/Azuma) |
| `obligation/` | Permit/ack/lease tracking, e-process monitoring |
| `epoch.rs` | Epoch accounting and runtime reclamation support |
| `lab/` | LabRuntime, virtual time wheel, DPOR explorer, oracle suite, conformal, chaos, snapshots |
| `trace/` | Mazurkiewicz/Foata canonicalize, geodesic, DPOR, boundary (persistent homology), GF(2), sheaf, TLA+ export, crashpack |
| `time/` | Sleep, timeout, interval, timer wheel, driver |
| `io/` | Async I/O traits and adapters |
| `fs/` | Native filesystem surfaces, VFS helpers, and fs obligation integration |
| `process.rs` | Native process spawning and child lifecycle integration |
| `signal/` | Native signal handling surface |
| `net/` | TCP, UDP, Unix, DNS, WebSocket, native QUIC |
| `atp/` / `net/atp/` | ATP object transfer, RaptorQ transport, QUIC/H3 adapters, benchmarked matrix lanes |
| `http/` | HTTP/1.1, HTTP/2, `http::Client` / `HttpClient`, body, pool, compression |
| `tls/` | rustls TLS 1.2/1.3 |
| `bytes/` | Zero-copy `Bytes`, `BytesMut`, `BytesCursor`, `Buf`, `BufMut`, `Buf::copy_to_bytes` |
| `codec/` | Framing, encoding/decoding |
| `encoding.rs` / `decoding.rs` | Public encoding/decoding helpers around protocol and RaptorQ paths |
| `web/` | Router, extractors, middleware, request regions |
| `server/` | Native server helpers outside the higher-level web router |
| `service/` | ServiceBuilder, Tower adapter |
| `grpc/` | gRPC client/server, CallContext, descriptor-driven registered unary dispatch, native H2 serving |
| `database/` | SQLite (blocking pool), PostgreSQL (wire), MySQL (wire) |
| `messaging/` | Kafka, JetStream, Redis-stream style messaging adapters and durability/e2e surfaces |
| `stream/` | map, filter, merge, zip, fold, buffered, try_stream |
| `transport/` | Router, aggregator, sink (low-level delivery) |
| `session.rs` | Session/channel protocol surfaces and linear reply semantics |
| `future.rs` | Crate-private blocking poll/`block_on`-style implementation helper (`crate::util::future`); unavailable to downstream code and rejected on runtime worker threads |
| `bin/` | Binaries: `asupersync`, `atp`, `atpd`, dependency-ledger and RaptorQ/QUIC profile tools |
| `plan/` | DAG IR, rewrite engine, analysis lattices |
| `observability/` | LogEntry, metrics, TaskInspector, Diagnostics, spectral health, validated OTLP HTTP configuration, and finite owned metrics/trace/log mapping behind `metrics` |
| `console.rs` / `cli/` | Operator CLI and console diagnostics; `cli` is feature-gated and native-only |
| `audit/` | Audit/checking helpers used by proof and verification lanes |
| `adapter_certification.rs` | Adapter certification checks for interop boundaries |
| `conformance/` | In-crate conformance scaffolding and traceability helpers |
| `migration/` | Migration support code and compatibility boundary helpers |
| `monitor.rs` | Monitoring primitives and runtime health observation |
| `link.rs` | Link/lifecycle support used by actor, monitor, evidence, and process tests |
| `evidence.rs` / `evidence_sink.rs` | Evidence records and sinks used by proof/reporting lanes |
| `agent_swarm/` | Agent coordination and handoff mechanisms |
| `security/` | Security primitives, key material, symbol-auth, and capability-sensitive helpers |
| `tracing_compat.rs` | Optional tracing integration and compatibility shims |
| `raptorq/` | RFC 6330 fountain codes, GF(256), proof-carrying decode pipeline, symbol-auth posture |
| `distributed/` | Adaptive layouts, anti-entropy, assignment, runtime bridge, computation schemas, PBFT, SWIM/membership, consistent hashing, distribution/encoding/recovery, and snapshots |
| `remote.rs` | Named remote spawn, leases, idempotency, sagas |
| `actor.rs` | Bounded mailbox actors |
| `gen_server.rs` | Request/reply server (OTP GenServer) |
| `supervision.rs` | Supervision trees, restart policies |
| `spork.rs` | OTP-style layer on kernel |
| `app.rs` | AppSpec for application topology |
| `util/` | Internal utilities; inspect source before relying on public stability |

Read `src/lib.rs` cfgs before turning this table into a support claim. Portable
and default roots appear first; `cli` and `database` are feature-gated; ATP is
excluded on wasm; `fs`, `grpc`, `messaging`, `process`, `server`, and `signal`
are native-only; and several later root modules are proof/test harnesses rather
than default production surfaces.

## Read In This Order

Locate the checkout by repository identity, set its root as
`ASUPERSYNC_ROOT`, and interpret every path below relative to that root. Do not
assume `/dp`, `/data/projects`, an RCH checkout prefix, or any other deployment
path is authoritative.

### 1. Project posture

- `AGENTS.md`
- `README.md`
- `Cargo.toml`
- `src/lib.rs`
- `TESTING_FOR_AGENTS.md`
- `CHANGELOG.md` (v0.4.0-v0.4.9 sections)
- `CHANGELOG_RESEARCH.md` (evidence and no-claim notes for major refresh windows)
- `artifacts/api_surface_map_v1.json`

### 2. Integration entrypoints

- `docs/integration.md`
- `docs/macro-dsl.md`
- `src/runtime/mod.rs`
- `src/cx/mod.rs`

### 3. Native replacement surfaces

- `src/web/mod.rs`
- `src/service/mod.rs`
- `src/http/mod.rs`
- `src/grpc/mod.rs`
- `src/database/mod.rs`
- `src/actor.rs`
- `src/supervision.rs`
- `src/gen_server.rs`
- `src/observability/mod.rs`

### 4. Migration and interop docs

- `scripts/migration_readiness_planner.py`
- `artifacts/migration_readiness_planner_signoff_v1.json`
- `docs/tokio_migration_cookbooks.md`
- `asupersync-tokio-compat/src/runtime.rs` (live context bridge; it does not install a Tokio runtime)
- `docs/tokio_interop_support_matrix.md`
- `docs/tokio_compatibility_limitation_matrix.md`

### 5. Browser / WASM docs

- `docs/wasm_quickstart_migration.md`
- `docs/wasm_canonical_examples.md`
- `docs/wasm_react_reference_patterns.md`
- `docs/wasm_nextjs_template_cookbook.md`
- `docs/wasm_troubleshooting_compendium.md`
- `asupersync-browser-core/`

### 6. Proof lanes and ATP matrix work

- `artifacts/proof_lane_manifest_v1.json`
- `artifacts/proof_status_snapshot_v1.json`
- `artifacts/semantic_evidence_bundles_v1.json`
- `artifacts/public_guarantee_semantic_evidence_bundles_v1.json`
- `artifacts/proof_evidence_debt_graph_contract_v1.json`
- `artifacts/proof_lane_failure_repro_receipt_contract_v1.json`
- `artifacts/reservation_aware_fallback_work_finder_contract_v1.json`
- `artifacts/swarm_proof_lane_planner_contract_v1.json`
- `artifacts/validation_frontier_signoff_v1.json`
- `artifacts/unsafe_boundary_ledger_v1.json`
- `artifacts/fourth_wave_governor_final_signoff_v1.json`
- `artifacts/artifact_governance_final_signoff_v1.json`
- `artifacts/memory_residency_replay_e2e_contract_v1.json`
- `artifacts/memory_residency_operator_safety_contract_v1.json`
- `artifacts/clean_overlay_proof_orchestration_v1.json`
- `artifacts/proof_traffic_final_signoff_v1.json`
- `artifacts/dependency_supply_chain_policy_v1.json`
- `artifacts/dependency_budget_contract_v1.json`
- `artifacts/browser_ga_final_signoff_v1.json`
- `docs/atp_bench_matrix_spec.md`
- `docs/atp_rq_beat_rsync_ledger.md`
- `scripts/atp_bench/MATRIX.md`
- `scripts/atp_bench/run_matrix_cell.sh`
- `scripts/atp_bench/score_matrix.py`

### 7. Examples

- `examples/macros_basic.rs`
- `examples/macros_nested.rs`
- `examples/cancellation_injection.rs`
- `examples/chaos_testing.rs`
- `examples/spork_minimal_supervised_app.rs`
- `examples/prometheus_metrics.rs`

## When You Need Tracker Context

Use:

```bash
br list --json
br list --status closed --json
```

What to look for:

- open browser DX / QA / release beads
- closed Tokio-replacement and migration-cookbook programs
- active RaptorQ and Lean-coverage hardening work
- active ATP matrix lanes, transport no-claim boundaries, and proof-lane gates

Beads records intent, dependencies, comments, and acceptance evidence; it is not
an infallible shipped-state database. A row can remain `in_progress` after its
source or release artifact ships. CASS can recover rationale and failed
hypotheses, but its index can be stale or quarantined. Resolve current support
in this order: tagged source and public signatures; focused acceptance artifacts
plus terminal execution receipts; release/registry state; then Beads and CASS
for rationale. Record contradictions instead of silently choosing the older
label.
