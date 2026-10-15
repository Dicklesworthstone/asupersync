# Adapter Performance and Correctness Budgets

**Bead**: `asupersync-2oh2u.7.8` ([T7.8])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Author**: SapphireHill (claude-code / opus-4.6)
**Date**: 2026-03-04
**Dependencies**: `asupersync-2oh2u.7.5` (body_bridge), `asupersync-2oh2u.7.7` (conformance suites)
**Purpose**: Define and enforce measurable performance budgets, correctness gates, and
behavioral contracts for every adapter in `asupersync-tokio-compat`, replacing the
deferred `NF28` placeholders with concrete thresholds.

---

## 1. Scope

This document governs the six adapter modules in `asupersync-tokio-compat/`:

| Module | Adapter Direction | Feature Gate |
|--------|------------------|--------------|
| `hyper_bridge` | asupersync→hyper v1 (Executor, Timer, Sleep) | `hyper-bridge` |
| `body_bridge` | bidirectional HTTP body (IntoHttpBody, collect_body) | `hyper-bridge` |
| `tower_bridge` | bidirectional Service (FromTower, IntoTower) | `tower-bridge` |
| `io` | bidirectional I/O (TokioIo, AsupersyncIo) | always |
| `cancel` | CancelAware future wrapper | always |
| `blocking` | sync/async boundary (block_on_sync, with_cx_sync) | always |

---

## 2. NF28 Concrete Thresholds (Replacing Deferred Placeholders)

These replace the previously deferred entries in `docs/tokio_nonfunctional_closure_criteria.md` § NF28.

### 2.1 Adapter Call Overhead

| ID | Metric | Hard Ceiling | Soft Target | Rationale |
|----|--------|-------------|-------------|-----------|
| NF28.1 | Tower Service adapter dispatch overhead (per call) | < 500 ns | < 200 ns | Must not regress vs. direct tower::Service call. |
| NF28.1a | Tower FromTower::call overhead | < 500 ns | < 200 ns | Includes Cx check + forwarding. |
| NF28.1b | Tower IntoTower::call overhead | < 500 ns | < 200 ns | Includes Cx check + forwarding. |
| NF28.2 | Hyper executor spawn overhead (over direct spawn) | < 1 us | < 500 ns | Spawn delegation must be near-transparent. |
| NF28.2a | Hyper timer sleep overhead (over direct timer) | < 500 ns | < 200 ns | Timer shim wraps existing timer. |
| NF28.3 | Body bridge full-body round-trip (512 B payload) | < 2 us | < 1 us | Single-frame bodies must be cheap. |
| NF28.3a | Body bridge collect_body overhead (1 KB payload) | < 5 us | < 2 us | Collection is inherently a copy. |
| NF28.3b | Body bridge collect_body_limited overhead (1 KB) | < 6 us | < 3 us | Size check adds ~1 compare per frame. |
| NF28.4 | I/O adapter poll_read/poll_write overhead | < 500 ns | < 200 ns | Per-poll cost for ready I/O. |
| NF28.4a | I/O TokioIo wrap/unwrap | 0 ns (compile-time) | — | Newtype projection, no runtime cost. |
| NF28.4b | I/O AsupersyncIo wrap/unwrap | 0 ns (compile-time) | — | Newtype projection, no runtime cost. |
| NF28.5 | CancelAware per-poll overhead (BestEffort mode) | < 100 ns | < 50 ns | Single atomic load on fast path. |
| NF28.5a | CancelAware per-poll overhead (Strict mode) | < 200 ns | < 100 ns | Atomic load + state check. |
| NF28.5b | CancelAware per-poll overhead (TimeoutFallback) | < 500 ns | < 200 ns | May arm timeout on first cancel. |
| NF28.6 | Blocking bridge thread spawn overhead | < 100 us | < 50 us | Thread pool spawn + Cx propagation. |
| NF28.6a | Blocking bridge Cx propagation overhead | < 1 us | < 500 ns | set_current + RAII guard. |

### 2.2 Throughput

| ID | Metric | Hard Ceiling | Soft Target | Rationale |
|----|--------|-------------|-------------|-----------|
| NF28.7 | Tower adapter throughput (noop service) | > 2M calls/sec | > 5M calls/sec | Must not bottleneck hot service paths. |
| NF28.8 | Body bridge throughput (64-byte frames) | > 1M frames/sec | > 3M frames/sec | gRPC streaming requires high frame rate. |
| NF28.9 | I/O adapter throughput (loopback, 4 KB reads) | > 1 GB/s | > 2 GB/s | Matches NF06 I/O budget. |
| NF28.10 | CancelAware throughput (fast future, BestEffort) | > 5M completions/sec | > 10M/sec | Wrapper must not be a bottleneck. |

### 2.3 Memory

| ID | Metric | Hard Ceiling | Soft Target | Rationale |
|----|--------|-------------|-------------|-----------|
| NF28.11 | Per-TokioIo wrapper memory | 0 bytes extra | — | Newtype projection. |
| NF28.12 | Per-AsupersyncIo wrapper memory | 0 bytes extra | — | Newtype projection. |
| NF28.13 | Per-IntoHttpBody<()> (full, no trailers) | < 64 bytes | < 48 bytes | Bytes + Option<Bytes> + Option<HeaderMap>. |
| NF28.14 | Per-CancelAware future overhead | < 128 bytes | < 64 bytes | AtomicBool + mode enum + state. |
| NF28.15 | Per-GrpcServiceAdapter wrapper | 0 bytes extra | — | Newtype projection. |
| NF28.16 | Per-FromTower/IntoTower wrapper | 0 bytes extra | — | Newtype projection. |
| NF28.17 | Blocking bridge per-call heap allocs | < 3 | 1 | Thread pool task + Cx clone. |

### 2.4 Cancellation Correctness

| ID | Metric | Hard Ceiling | Soft Target | Rationale |
|----|--------|-------------|-------------|-----------|
| NF28.18 | Cancel propagation to CancelAware (p99) | < 100 us | < 10 us | Single atomic store + wakeup. |
| NF28.19 | CancelAware drops inner future on Strict cancel | 100% | — | Structural guarantee. |
| NF28.20 | CancelAware TimeoutFallback grace period accuracy | +/- 10 ms | +/- 1 ms | Timer precision. |
| NF28.21 | BlockingOutcome captures panic (no propagation) | 100% | — | Structural guarantee (std::panic::catch_unwind). |
| NF28.22 | Cx guard restored on panic unwind | 100% | — | RAII drop guarantee. |

### 2.5 No-Regression Gate

| ID | Metric | Warning | Hard-Fail | Rationale |
|----|--------|---------|-----------|-----------|
| NF28.NR | Interop adapter overhead regression | +8% | +15% | Aligns with PB-11 from T8.7 policy. |

---

## 3. Startup and Shutdown Behavior Contracts

### 3.1 Startup

| Contract ID | Module | Behavior | Budget |
|-------------|--------|----------|--------|
| SU-01 | hyper_bridge | `AsupersyncExecutor::with_spawn_fn()` binds spawn closure | < 100 ns |
| SU-02 | hyper_bridge | `AsupersyncTimer::new()` binds time source | < 100 ns |
| SU-03 | body_bridge | `IntoHttpBody::full()` / `empty()` / `streaming()` are `const fn` | 0 ns (compile-time) |
| SU-04 | tower_bridge | `FromTower::new()` / `IntoTower::new()` wrap inner service | < 100 ns |
| SU-05 | io | `TokioIo::new()` / `AsupersyncIo::new()` newtype wrap | 0 ns (compile-time) |
| SU-06 | cancel | `CancelAware::new()` wraps future + mode + flag | < 100 ns |
| SU-07 | blocking | Pool initialization (first call to `block_on_sync`) | < 10 ms |

### 3.2 Shutdown / Cleanup

| Contract ID | Module | Behavior | Budget |
|-------------|--------|----------|--------|
| SD-01 | cancel | CancelAware drops inner future on cancel completion | Immediate (synchronous drop) |
| SD-02 | blocking | Blocking thread Cx guard restored on completion or panic | Immediate (RAII drop) |
| SD-03 | body_bridge | IntoHttpBody stream yields None after all frames consumed | 0 polls after terminal |
| SD-04 | io | TokioIo/AsupersyncIo Drop releases nothing (no owned FD) | Immediate |
| SD-05 | tower_bridge | FromTower/IntoTower Drop delegates to inner service | Immediate |
| SD-06 | hyper_bridge | Spawned tasks are region-owned; region close collects them | Per NF02.1 (< 5 us) |

### 3.3 Graceful Drain

| Contract ID | Behavior | Budget |
|-------------|----------|--------|
| GD-01 | Inflight CancelAware futures complete or drain within grace period | `fallback_timeout` (default 30s) |
| GD-02 | Inflight blocking tasks complete within pool shutdown timeout | Platform default |
| GD-03 | Body streams terminate (yield None) when underlying transport closes | < 1 poll after close |

---

## 4. Invariant Enforcement Gates

These gates are hard-fail; any violation blocks T7.8 closure.

| Gate ID | Invariant | Enforcement Method | Pass Criterion |
|---------|-----------|--------------------|----------------|
| IG-01 | INV-1 (no ambient authority) | Compile-time: all entry points require Cx or have no runtime cost | No thread-local sniffing in adapter code |
| IG-02 | INV-2 (structured concurrency) | AsupersyncExecutor routes spawn to region | All spawned tasks are region-owned |
| IG-03 | INV-3 (cancellation protocol) | CancelAware wrapper on every adapter future | Cancel request → drain → finalize |
| IG-04 | INV-4 (no obligation leaks) | Region close collects all adapter-spawned tasks | Zero leaks in 1M cycles |
| IG-05 | INV-5 (outcome severity lattice) | BlockingOutcome {Ok, Cancelled, Panicked} | Never coerced to Result |
| IG-06 | RULE-1 (no Tokio in core) | No `tokio::runtime::Runtime` / `#[tokio::main]` / `#[tokio::test]` | Static scan |
| IG-07 | RULE-2 (adapters in separate crate) | All adapter code in `asupersync-tokio-compat/` | Path check |

---

## 5. Quality Gate Integration

### 5.1 Budget Rows Binding to T8.7 Policy

T7.8 budgets bind to `PB-11` from `docs/tokio_track_performance_regression_budgets.md`:

| PB Row | Track | Metric | Warning | Hard-Fail |
|--------|-------|--------|---------|-----------|
| PB-11 | T7 | latency_p95_ms | +8% | +15% |

### 5.2 Alarm Binding

| Alarm | Condition | Effect |
|-------|-----------|--------|
| AL-01 | Any NF28.* hard ceiling exceeded | Hard-fail promotion |
| AL-02 | 2+ NF28.* soft targets missed in one run | Waiver required |
| AL-09 | Invariant gate (IG-01..07) violation | Hard-fail promotion |

### 5.3 Required Artifacts

Every T7.8 evaluation run MUST produce:

- `artifacts/tokio_adapter_performance_budgets_manifest.json`
- `artifacts/tokio_adapter_performance_budgets_report.md`

---

## 6. Adapter-Specific Correctness Contracts

### 6.1 CancelAware Contracts

| Contract | Description | Test Pattern |
|----------|-------------|--------------|
| CC-01 | BestEffort: cancel request does not discard result if already Ready | Poll to completion after cancel |
| CC-02 | Strict: cancel request discards result, returns Cancelled | Poll after cancel, verify CancellationIgnored or Cancelled |
| CC-03 | TimeoutFallback: grace period elapsed → future dropped | Arm cancel, wait > fallback_timeout, verify drop |
| CC-04 | Cancel request is idempotent | Multiple cancel calls, same outcome |
| CC-05 | Inner future dropped on CancelAware drop | Drop without polling to completion, verify inner drop |

### 6.2 Blocking Bridge Contracts

| Contract | Description | Test Pattern |
|----------|-------------|--------------|
| BC-01 | Cx propagated to blocking thread | Check Cx::current() inside blocking closure |
| BC-02 | Panic captured as Panicked outcome | panic!() in closure → BlockingOutcome::Panicked |
| BC-03 | Cx guard restored after panic | Verify Cx::current() after panicking closure completes |
| BC-04 | Cancellation check on completion | cancel_requested during execution → Cancelled outcome |

### 6.3 Body Bridge Contracts

| Contract | Description | Test Pattern |
|----------|-------------|--------------|
| BB-01 | Full body: single DATA frame then None | poll_frame × 2 |
| BB-02 | Empty body: is_end_stream() == true | Immediate check |
| BB-03 | Trailers: DATA frame then TRAILERS frame then None | poll_frame × 3 |
| BB-04 | Empty body + trailers: skip DATA, TRAILERS then None | poll_frame × 2 |
| BB-05 | size_hint accurate for full bodies | Compare with payload length |
| BB-06 | collect_body_limited: rejects oversize | body > limit → TooLarge |
| BB-07 | collect_body_limited: accepts within limit | body <= limit → Ok |

### 6.4 Tower Bridge Contracts

| Contract | Description | Test Pattern |
|----------|-------------|--------------|
| TC-01 | FromTower preserves poll_ready semantics | Ready/NotReady propagation |
| TC-02 | IntoTower preserves call semantics | Request/Response roundtrip |
| TC-03 | Error types preserved through adapter | Service::Error unchanged |

### 6.5 I/O Bridge Contracts

| Contract | Description | Test Pattern |
|----------|-------------|--------------|
| IC-01 | TokioIo implements hyper v1 Read/Write | Trait bound check |
| IC-02 | AsupersyncIo implements asupersync Read/Write | Trait bound check |
| IC-03 | poll_read cancel-safe (partial data preserved) | Cancel mid-read, verify buffered data |
| IC-04 | read_exact NOT cancel-safe (documented) | Documentation check |

### 6.6 Hyper Bridge Contracts

| Contract | Description | Test Pattern |
|----------|-------------|--------------|
| HC-01 | AsupersyncExecutor implements hyper::rt::Executor | Trait bound check |
| HC-02 | AsupersyncTimer implements hyper::rt::Timer | Trait bound check |
| HC-03 | AsupersyncSleep implements hyper::rt::Sleep | Trait bound check |
| HC-04 | Spawned tasks route to current region | Region ownership verification |

---

## 7. Measurement Methodology

### 7.1 Benchmark Requirements

Benchmarks for NF28 metrics MUST follow the measurement framework from
`docs/tokio_nonfunctional_closure_criteria.md` § 1.3:

- 4+ logical cores, 8+ GB RAM
- Release profile with LTO enabled
- Three warmup iterations discarded
- Median of five measurement runs reported

### 7.2 Benchmark Suite Mapping

| Benchmark File | NF28 Metrics Covered |
|---------------|---------------------|
| `benches/interop_tower.rs` | NF28.1, NF28.1a, NF28.1b, NF28.7 |
| `benches/interop_hyper.rs` | NF28.2, NF28.2a |
| `benches/interop_body.rs` | NF28.3, NF28.3a, NF28.3b, NF28.8 |
| `benches/interop_io.rs` | NF28.4, NF28.9 |
| `benches/interop_cancel.rs` | NF28.5, NF28.5a, NF28.5b, NF28.10, NF28.18 |
| `benches/interop_blocking.rs` | NF28.6, NF28.6a |

Status: All benchmark files need creation (tracked by downstream beads).

### 7.3 Contract Test File

`tests/tokio_adapter_performance_budgets.rs` validates:
- Budget document schema completeness
- Threshold presence for all NF28 rows
- Startup/shutdown contract coverage
- Invariant gate enforcement
- Adapter-specific correctness contract mapping

---

## 8. Downstream Binding

| Downstream Bead | Binding |
|-----------------|---------|
| `asupersync-2oh2u.7.9` | Support matrix consumes budget thresholds for capability claims |
| `asupersync-2oh2u.7.10` | Exhaustive unit tests implement contracts from § 6 |
| `asupersync-2oh2u.10.7` | T8.7 regression policy consumes PB-11 budgets from this doc |
| `asupersync-2oh2u.10.12` | Cross-track logging gate consumes artifact schema |

---

## 9. Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-03-04 | SapphireHill | Initial creation; fills NF28 deferred thresholds |
