# Source Map

## What Is Asupersync?

A spec-first, cancel-correct, capability-secure async runtime for Rust with
1,700+ tracked files under `src/`, including 1,100+ Rust files; the generated
API map currently lists 120 modules and 298 root exports. Refresh live counts
from `/data/projects/asupersync/artifacts/api_surface_map_v1.json` and
`git ls-files` before quoting them. Not a Tokio wrapper -- a broad
support-class-scoped replacement for native Asupersync designs, with stronger
guarantees:

- **Structured concurrency**: every task owned by a region; region close = quiescence
- **Cancel-correctness**: cancellation is request -> drain -> finalize (not silent drop)
- **Two-phase effects**: reserve/commit prevents data loss on cancellation
- **Capability security**: all effects flow through explicit `Cx`; no ambient authority
- **Deterministic testing**: `LabRuntime` with virtual time, DPOR, oracles, chaos injection
- **Obligation tracking**: permits/acks/leases must be committed or aborted (linear resources)
- **Networking stack**: TCP, HTTP/1.1, HTTP/2, WebSocket, TLS, gRPC, DNS,
  feature-gated native QUIC/H3, and ATP transport lanes
- **Database clients**: SQLite, PostgreSQL (wire protocol), MySQL (wire protocol)
- **OTP-style supervision**: actors, GenServer, supervision trees, AppSpec, Spork
- **Proof and evidence lanes**: API surface maps, proof manifests, validation
  snapshots, and benchmark matrix artifacts are source-of-truth inputs

### Six Non-Negotiable Invariants

1. **Structured concurrency**: every task/fiber/actor owned by exactly one region
2. **Region close = quiescence**: no live children + all finalizers done
3. **Cancellation is a protocol**: request -> drain -> finalize (idempotent)
4. **Losers are drained**: races must cancel and fully drain losers
5. **No obligation leaks**: permits/acks/leases must be committed or aborted
6. **No ambient authority**: effects flow through `Cx` and explicit capabilities

## Core Types Quick Reference

| Type | Purpose |
|------|---------|
| `Cx` | Capability context -- first param to all async ops, no ambient authority |
| `Scope` | Current-region handle and child-region API; ordinary spawning goes through `Cx::spawn` / `Cx::spawn_in` |
| `Outcome<T, E>` | Four-valued: `Ok`, `Err`, `Cancelled(reason)`, `Panicked(payload)` |
| `Budget` | Bounded cleanup: deadline, poll_quota, cost_quota, priority. Semiring: meet = tighter wins |
| `Region` / `RegionId` | Structured concurrency scope -- owns tasks, closes to quiescence |
| `TaskId` | Identifier for spawned tasks |
| `ObligationId` | Tracked permit/ack/lease -- must be committed or aborted |
| `CancelKind` | User, Timeout, FailFast, RaceLost, ParentCancelled, Shutdown |
| `LabRuntime` / `LabConfig` | Deterministic runtime with virtual time for testing |
| `RuntimeBuilder` | Construct production runtime: `current_thread()`, `low_latency()`, `high_throughput()` |
| `AppSpec` | Application topology with supervision, registry, restart policy |

Severity lattice: `Ok < Err < Cancelled < Panicked`. Monotone aggregation.

## Workspace Structure

| Workspace member / package | Purpose |
|-------|---------|
| `asupersync` | Main runtime (1,700+ tracked files under `src/`, 120 API-map modules) |
| `asupersync-macros` | Proc macros: `scope!`, `spawn!`, `join!`, `join_all!`, `race!` |
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
| `sync/` | Mutex, RwLock, Semaphore, Barrier, Notify, OnceLock, Pool, ContendedMutex |
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
| `grpc/` | gRPC client/server, CallContext |
| `database/` | SQLite (blocking pool), PostgreSQL (wire), MySQL (wire) |
| `messaging/` | Kafka, JetStream, Redis-stream style messaging adapters and durability/e2e surfaces |
| `stream/` | map, filter, merge, zip, fold, buffered, try_stream |
| `transport/` | Router, aggregator, sink (low-level delivery) |
| `session.rs` | Session/channel protocol surfaces and linear reply semantics |
| `plan/` | DAG IR, rewrite engine, analysis lattices |
| `observability/` | LogEntry, metrics, TaskInspector, Diagnostics, spectral health |
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
| `distributed/` | Consistent hashing, snapshots |
| `remote.rs` | Named remote spawn, leases, idempotency, sagas |
| `actor.rs` | Bounded mailbox actors |
| `gen_server.rs` | Request/reply server (OTP GenServer) |
| `supervision.rs` | Supervision trees, restart policies |
| `spork.rs` | OTP-style layer on kernel |
| `app.rs` | AppSpec for application topology |
| `util/` | Internal utilities; inspect source before relying on public stability |

## Read In This Order

### 1. Project posture

- `/data/projects/asupersync/AGENTS.md`
- `/data/projects/asupersync/README.md`
- `/data/projects/asupersync/Cargo.toml`
- `/data/projects/asupersync/src/lib.rs`
- `/data/projects/asupersync/TESTING_FOR_AGENTS.md`
- `/data/projects/asupersync/artifacts/api_surface_map_v1.json`

### 2. Integration entrypoints

- `/data/projects/asupersync/docs/integration.md`
- `/data/projects/asupersync/docs/macro-dsl.md`
- `/data/projects/asupersync/src/runtime/mod.rs`
- `/data/projects/asupersync/src/cx/mod.rs`

### 3. Native replacement surfaces

- `/data/projects/asupersync/src/web/mod.rs`
- `/data/projects/asupersync/src/service/mod.rs`
- `/data/projects/asupersync/src/http/mod.rs`
- `/data/projects/asupersync/src/grpc/mod.rs`
- `/data/projects/asupersync/src/database/mod.rs`
- `/data/projects/asupersync/src/actor.rs`
- `/data/projects/asupersync/src/supervision.rs`
- `/data/projects/asupersync/src/gen_server.rs`
- `/data/projects/asupersync/src/observability/mod.rs`

### 4. Migration and interop docs

- `/data/projects/asupersync/scripts/migration_readiness_planner.py`
- `/data/projects/asupersync/artifacts/migration_readiness_planner_signoff_v1.json`
- `/data/projects/asupersync/docs/tokio_migration_cookbooks.md`
- `/data/projects/asupersync/docs/tokio_adapter_boundary_architecture.md`
- `/data/projects/asupersync/docs/tokio_interop_support_matrix.md`
- `/data/projects/asupersync/docs/tokio_compatibility_limitation_matrix.md`

### 5. Browser / WASM docs

- `/data/projects/asupersync/docs/wasm_quickstart_migration.md`
- `/data/projects/asupersync/docs/wasm_canonical_examples.md`
- `/data/projects/asupersync/docs/wasm_react_reference_patterns.md`
- `/data/projects/asupersync/docs/wasm_nextjs_template_cookbook.md`
- `/data/projects/asupersync/docs/wasm_troubleshooting_compendium.md`
- `/data/projects/asupersync/asupersync-browser-core/`

### 6. Proof lanes and ATP matrix work

- `/data/projects/asupersync/artifacts/proof_lane_manifest_v1.json`
- `/data/projects/asupersync/artifacts/proof_status_snapshot_v1.json`
- `/data/projects/asupersync/artifacts/semantic_evidence_bundles_v1.json`
- `/data/projects/asupersync/artifacts/public_guarantee_semantic_evidence_bundles_v1.json`
- `/data/projects/asupersync/artifacts/proof_evidence_debt_graph_contract_v1.json`
- `/data/projects/asupersync/artifacts/proof_lane_failure_repro_receipt_contract_v1.json`
- `/data/projects/asupersync/artifacts/reservation_aware_fallback_work_finder_contract_v1.json`
- `/data/projects/asupersync/artifacts/swarm_proof_lane_planner_contract_v1.json`
- `/data/projects/asupersync/artifacts/validation_frontier_signoff_v1.json`
- `/data/projects/asupersync/docs/atp_bench_matrix_spec.md`
- `/data/projects/asupersync/docs/atp_rq_beat_rsync_ledger.md`
- `/data/projects/asupersync/scripts/atp_bench/MATRIX.md`
- `/data/projects/asupersync/scripts/atp_bench/run_matrix_cell.sh`
- `/data/projects/asupersync/scripts/atp_bench/score_matrix.py`

### 7. Examples

- `/data/projects/asupersync/examples/macros_basic.rs`
- `/data/projects/asupersync/examples/macros_nested.rs`
- `/data/projects/asupersync/examples/cancellation_injection.rs`
- `/data/projects/asupersync/examples/chaos_testing.rs`
- `/data/projects/asupersync/examples/spork_minimal_supervised_app.rs`
- `/data/projects/asupersync/examples/prometheus_metrics.rs`

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
