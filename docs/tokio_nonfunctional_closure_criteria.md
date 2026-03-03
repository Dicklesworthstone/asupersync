# Non-Functional Closure Criteria for Tokio Replacement

**Bead**: `asupersync-2oh2u.1.2.3` ([T1.2.b])
**Author**: SapphireHill (claude-code / opus-4.6)
**Date**: 2026-03-03
**Dependency**: T1.2.a (functional parity contracts), T1.1.c (risk register)
**Purpose**: Measurable non-functional thresholds per capability domain for
replacement closure. Each criterion has explicit rationale tied to production
migration risk.
**T1.2 synthesis**: consolidated domain sign-off matrix is tracked in
`docs/tokio_functional_parity_contract.md` section "Domain Definition-of-Done
Synthesis (T1.2 Parent)".

---

## 1. Measurement Framework

### 1.1 Performance Budget Categories

| Category | Metric | Tool |
|----------|--------|------|
| Throughput (T) | ops/sec, messages/sec, bytes/sec | Criterion benchmarks |
| Latency (L) | p50, p99, p999 in microseconds | Criterion + lab traces |
| Memory (M) | peak RSS, per-unit overhead, allocation rate | `dhat`, `jemalloc_ctl` |
| CPU (C) | user-time per operation, idle utilization | `perf stat`, criterion |
| Stability (S) | correctness under faults, recovery time | Property tests, fault injection |
| No-Regression (NR) | maximum allowed regression vs. baseline | `critcmp` |

### 1.2 Threshold Interpretation

- **Hard ceiling**: MUST NOT exceed; blocks closure
- **Soft target**: SHOULD meet; documented exception allowed with rationale
- **Baseline**: current measured value; regressions block CI

### 1.3 Comparison Methodology

All comparisons are Asupersync vs. equivalent Tokio-ecosystem operation under
identical hardware, concurrency level, and workload shape. Benchmarks MUST
run on dedicated CI hardware (no shared runners) for reproducibility.

Measurement conditions:
- 4+ logical cores, 8+ GB RAM
- Release profile (`--release`) with LTO enabled
- Three warmup iterations discarded before measurement
- Median of five measurement runs reported

### 1.4 Regression Policy

| Condition | Action |
|-----------|--------|
| Regression > 20% on any metric | **Hard fail**: CI blocks merge |
| Regression > 5% on any metric | **Soft warning**: annotated in PR |
| Improvement > 10% on any metric | **Baseline update**: automatic |

### 1.5 Exemption Policy

Domains at maturity M0-M1 (Planned/Parked) receive placeholder thresholds
marked `[DEFERRED]`. These MUST be replaced with real thresholds before the
domain can claim closure.

---

## 2. Per-Domain Non-Functional Criteria

### NF01 — Core Runtime (F01)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF01.1 | Task spawn latency (p99) | < 5 us | < 2 us | Tokio spawn is ~1-2 us. Must not regress for migration. |
| NF01.2 | Task spawn throughput | > 2M/sec (8 cores) | > 5M/sec | Production services spawn millions of tasks. |
| NF01.3 | Worker thread wake latency | < 50 us | < 10 us | Affects tail latency for idle-then-burst patterns. |
| NF01.4 | Memory per idle task | < 512 bytes | < 256 bytes | 100K concurrent tasks must fit in ~50MB overhead. |
| NF01.5 | Shutdown quiescence time | < 5s (10K tasks) | < 1s | Migration must not worsen graceful shutdown. |
| NF01.6 | Idle runtime CPU utilization | < 1% of one core | < 0.1% | No busy-wait when no tasks are queued. |
| NF01.7 | Spawn throughput NR gate | <= 10% regression | — | Hard fail on CI. |

### NF02 — Structured Concurrency (F02)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF02.1 | Region open/close overhead | < 5 us | < 2 us | Region lifecycle must be near-free. |
| NF02.2 | Cancellation propagation latency (1000-task tree, p99) | < 200 us | < 100 us | Fast propagation prevents livelock. |
| NF02.3 | Per-region memory overhead (empty) | < 256 bytes | < 128 bytes | Must scale to many nested regions. |
| NF02.4 | Checkpoint throughput (unmasked, per-thread) | > 10M checks/sec | > 50M checks/sec | Hot-path operation must be cheap. |
| NF02.5 | Region quiescence guarantee | 100% tasks reach terminal | — | Structural, not probabilistic. |
| NF02.6 | Cancellation propagation NR gate | <= 10% regression | — | |

### NF03 — Channels (F03)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF03.1 | mpsc send/recv round-trip (p99) | < 2 us | < 500 ns | Hot path in most async applications. |
| NF03.2 | mpsc throughput (SPSC, bounded cap=64) | > 5M msg/sec | > 10M msg/sec | Must match tokio::sync::mpsc. |
| NF03.3 | Unbounded mpsc throughput (SPSC) | > 8M msg/sec | > 15M msg/sec | No backpressure overhead. |
| NF03.4 | Broadcast fan-out latency (1K receivers) | < 100 us | < 20 us | Event broadcasting is common pattern. |
| NF03.5 | Memory per channel (bounded, cap=32) | < 1 KB | < 512 bytes | Many channels active simultaneously. |
| NF03.6 | Per-message allocation (bounded, steady state) | 0 heap allocs | — | Pre-allocated ring buffer. |
| NF03.7 | Channel throughput NR gate | <= 10% regression | — | |

### NF04 — Sync Primitives (F04)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF04.1 | Mutex uncontended lock/unlock | < 100 ns | < 50 ns | Must not bottleneck hot-path resource access. |
| NF04.2 | RwLock read-side contention (8 readers) | < 500 ns/op | < 200 ns/op | Read-heavy workloads dominate database caches. |
| NF04.3 | Semaphore acquire/release (uncontended) | < 100 ns | < 50 ns | Connection pool gates use semaphore. |
| NF04.4 | Notify wake latency | < 1 us | < 200 ns | Condition variable equivalent. |
| NF04.5 | Per-waiter memory overhead | < 128 bytes | < 64 bytes | Bounded waiter bookkeeping. |
| NF04.6 | No reader/writer starvation (RwLock) | 100% of waiters eventually wake | — | Liveness guarantee. |
| NF04.7 | Uncontended lock NR gate | <= 15% regression | — | |

### NF05 — Time / Timers (F05)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF05.1 | sleep() registration overhead | < 500 ns | < 200 ns | Every timeout/deadline creates a timer entry. |
| NF05.2 | Timer wheel tick processing (10K timers) | < 100 us | < 20 us | Must not stall runtime poll loop. |
| NF05.3 | Timer accuracy | < 1 ms error at 100ms granularity | < 100 us | Deadline-sensitive operations require accuracy. |
| NF05.4 | Concurrent timers capacity | >= 100K active, no degradation | >= 500K | Production server patterns. |
| NF05.5 | Per-timer memory overhead | < 64 bytes | < 48 bytes | Compact timer entries. |
| NF05.6 | Timer throughput NR gate | <= 10% regression | — | |

### NF06 — Async I/O (F06)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF06.1 | Read throughput (64KB buffers, loopback) | > 1 GB/s | > 2 GB/s | Must not be I/O adapter bottleneck. |
| NF06.2 | Write throughput (64KB buffers, loopback) | > 1 GB/s | > 2 GB/s | |
| NF06.3 | AsyncRead/Write poll overhead (ready I/O) | < 500 ns | < 200 ns | |
| NF06.4 | I/O throughput NR gate | <= 10% regression | — | |

### NF07 — Codec / Framing (F07)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF07.1 | Lines codec throughput | > 200K lines/sec (avg 80B) | > 500K | |
| NF07.2 | Length-delimited codec throughput | > 500K frames/sec (128B) | > 1M | |
| NF07.3 | Codec buffer allocation (steady state) | Amortized 0 alloc/frame | — | Reuse internal BytesMut. |
| NF07.4 | Codec throughput NR gate | <= 10% regression | — | |

### NF08 — Byte Buffers (F08)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF08.1 | Bytes clone throughput | > 20M clones/sec | > 50M | Ref-counted, no memcpy. |
| NF08.2 | BytesMut extend throughput | > 1 GB/s | > 2 GB/s | |
| NF08.3 | Bytes per-instance overhead | < 32 bytes | < 24 bytes | Compact representation. |
| NF08.4 | Buffer throughput NR gate | <= 10% regression | — | |

### NF09 — Reactor (F09)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF09.1 | Events processed per poll cycle | > 50K events/cycle | > 100K | High-throughput server patterns. |
| NF09.2 | Poll-to-waker dispatch latency | p50 < 10 us, p99 < 50 us | < 5 us | Reactor must not bottleneck waking. |
| NF09.3 | Reactor idle CPU | < 1% of one core | < 0.5% | epoll_wait/kevent should sleep. |
| NF09.4 | io_uring submission latency | < 2 us | < 500 ns | Must justify io_uring complexity. |
| NF09.5 | Reactor poll overhead (idle) | < 1 us | < 200 ns | |
| NF09.6 | Zero stale events under fd churn | 0 stale dispatches | — | Generation-based token correctness. |
| NF09.7 | Reactor throughput NR gate | <= 10% regression | — | |

### NF10 — TCP/UDP/Unix (F10)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF10.1 | TCP echo throughput (1KB msg) | > 100K msg/sec | > 500K | Basic networking benchmark. |
| NF10.2 | TCP connection accept rate | > 20K accepts/sec | > 50K | Server scalability. |
| NF10.3 | TCP connect latency (loopback) | p50 < 200 us, p99 < 1 ms | < 100 us | |
| NF10.4 | UDP send/recv round-trip | < 50 us | < 10 us | Low-latency messaging protocols. |
| NF10.5 | Connection cleanup on peer reset | FD and memory freed < 1s | < 100 ms | |
| NF10.6 | Network throughput NR gate | <= 10% regression | — | |

### NF11 — DNS (F11)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF11.1 | Cached resolution latency | p50 < 5 us | < 1 us | Cache hit near-instant. |
| NF11.2 | Resolution throughput (cached) | > 500K lookups/sec | > 1M | |
| NF11.3 | Uncached resolution timeout | Configurable, default <= 5s | <= 3s | |
| NF11.4 | DNS NR gate | <= 15% regression | — | |

### NF12 — TLS (F12)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF12.1 | TLS 1.3 handshake latency (RSA 2048) | < 10 ms | < 5 ms | Connection establishment bottleneck. |
| NF12.2 | TLS throughput (AES-128-GCM) | > 500 MB/sec | > 1 GB/sec | Must not bottleneck data transfer. |
| NF12.3 | Memory per TLS session | < 64 KB | < 32 KB | Many concurrent TLS connections. |
| NF12.4 | Handshake failure handling | Connection dropped < 1s, FD freed | < 100 ms | |
| NF12.5 | TLS throughput NR gate | <= 10% regression | — | |

### NF13 — WebSocket (F13)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF13.1 | Message throughput (text, 128B) | > 100K msg/sec per connection | > 200K | |
| NF13.2 | Handshake upgrade latency | p50 < 1 ms | < 500 us | |
| NF13.3 | Per-connection WebSocket state | < 8 KB | < 4 KB | |
| NF13.4 | Clean close under cancellation | Close frame sent before FD release | — | Protocol compliance. |
| NF13.5 | WebSocket throughput NR gate | <= 10% regression | — | |

### NF14 — HTTP/1+2 (F14)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF14.1 | HTTP/1.1 req/res round-trip (keep-alive) | < 100 us | < 30 us | Basic web serving. |
| NF14.2 | HTTP/2 stream throughput (100 streams) | > 50K req/sec | > 200K | Multiplexed workloads. |
| NF14.3 | HPACK compression ratio (typical headers) | > 50% | > 60% | Bandwidth efficiency. |
| NF14.4 | Per-HTTP/2-stream memory (idle) | < 4 KB | < 2 KB | |
| NF14.5 | Server graceful shutdown (HTTP/2) | Inflight streams complete, GOAWAY sent | — | |
| NF14.6 | HTTP throughput NR gate | <= 10% regression | — | |

### NF15 — QUIC + HTTP/3 (F15) `[DEFERRED]`

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF15.1 | QUIC handshake latency (0-RTT) | `[DEFERRED]` | — | Define after feature exposure. |
| NF15.2 | QUIC stream throughput | `[DEFERRED]` | — | |
| NF15.3 | Loss recovery correctness (RFC 9002) | `[DEFERRED]` | — | |
| NF15.4 | QUIC regression gate | `[DEFERRED]` | — | |

### NF16 — Web Framework (F16)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF16.1 | Router dispatch latency (100 routes) | < 5 us | < 1 us | Per-request overhead. |
| NF16.2 | JSON extraction overhead (1KB body) | < 10 us | < 3 us | Common request pattern. |
| NF16.3 | Middleware chain overhead (5 layers) | < 5 us | < 1 us | Production middleware stacks. |
| NF16.4 | Max sustained req/sec (hello world, 8 cores) | > 200K | > 500K | Framework benchmark floor. |
| NF16.5 | Per-request allocation | < 5 heap allocs (routing + extraction) | < 2 | |
| NF16.6 | Web framework throughput NR gate | <= 10% regression | — | |

### NF17 — gRPC (F17)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF17.1 | Unary RPC round-trip (loopback) | < 500 us | < 100 us | Microservice communication. |
| NF17.2 | Streaming throughput | > 100K msg/sec | > 500K | Data pipeline patterns. |
| NF17.3 | Protobuf encode/decode overhead (1KB) | < 5 us | < 1 us | Serialization cost. |
| NF17.4 | Stream cancellation cleanup | Resources freed < 100 ms | < 10 ms | |
| NF17.5 | gRPC throughput NR gate | <= 10% regression | — | |

### NF18 — Database (F18)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF18.1 | PostgreSQL simple query round-trip | < 1 ms (LAN) | < 500 us | Driver overhead vs. wire time. |
| NF18.2 | Connection pool checkout (uncontended) | < 10 us | < 1 us | Per-request pool access. |
| NF18.3 | Prepared statement cache hit ratio | > 99% (steady state) | > 99.9% | Avoid repeated parse. |
| NF18.4 | Pool recovery after server restart | Within configured timeout | < 5s | |
| NF18.5 | Database throughput NR gate | <= 15% regression | — | |

### NF19 — Messaging (F19)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF19.1 | Redis GET/SET round-trip | < 500 us (LAN) | < 200 us | Cache access latency. |
| NF19.2 | NATS publish throughput | > 100K msg/sec | > 500K | Event streaming. |
| NF19.3 | Kafka produce throughput | > 50K msg/sec | > 200K | Log ingestion. |
| NF19.4 | Consumer reconnect after broker restart | < 10s | < 5s | No message loss on reconnect. |
| NF19.5 | Messaging throughput NR gate | <= 15% regression | — | |

### NF20 — Service/Middleware (F20)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF20.1 | Middleware chain overhead per layer | < 100 ns | < 50 ns | Must not introduce visible latency. |
| NF20.2 | Service call throughput (passthrough) | > 5M calls/sec | > 10M | |
| NF20.3 | Circuit breaker check overhead | < 100 ns | < 30 ns | Per-call fast path. |
| NF20.4 | Rate limiter check overhead | < 200 ns | < 50 ns | Per-request gate. |
| NF20.5 | Service throughput NR gate | <= 10% regression | — | |

### NF21 — Filesystem (F21)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF21.1 | File read throughput (sequential, 1MB, SSD) | > 500 MB/s | > 1 GB/s | Must not be slower than blocking I/O. |
| NF21.2 | Directory listing throughput | > 5K entries/sec | > 10K | readdir performance. |
| NF21.3 | File open + close round-trip | < 1 ms | < 500 us | Common filesystem pattern. |
| NF21.4 | Cancel-safe file I/O | FD closed, partial writes visible only if flushed | — | |
| NF21.5 | Filesystem throughput NR gate | <= 15% regression | — | |

### NF22 — Process (F22)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF22.1 | Process spawn latency | p50 < 10 ms | < 5 ms | Fork/exec overhead. |
| NF22.2 | Stdio pipe throughput | > 50 MB/s | > 100 MB/s | Must not bottleneck child I/O. |
| NF22.3 | Kill-and-wait correctness | Exit status returned < 1s of kill | < 100 ms | |
| NF22.4 | Process spawn NR gate | <= 15% regression | — | |

### NF23 — Signals (F23)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF23.1 | Signal delivery latency | p99 < 50 ms from OS signal to handler | < 10 ms | |
| NF23.2 | Multiple signals coalesced correctly | Latest signal delivered, none lost | — | |
| NF23.3 | Signal latency NR gate | <= 20% regression | — | |

### NF24 — Streams (F24)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF24.1 | Stream adapter throughput (map/filter) | > 2M items/sec per adapter | > 5M | |
| NF24.2 | Per-stream-adapter allocation (steady state) | 0 heap allocs per item | — | |
| NF24.3 | Stream throughput NR gate | <= 10% regression | — | |

### NF25 — Observability (F25)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF25.1 | Span creation/close (disabled) | < 500 ns | < 200 ns | Disabled tracing must be near-free. |
| NF25.2 | Span creation/close (enabled) | < 5 us | < 2 us | |
| NF25.3 | Event emission throughput (enabled subscriber) | > 500K events/sec | > 1M | |
| NF25.4 | CPU overhead (tracing disabled) | < 1% vs. no-tracing build | < 0.5% | |
| NF25.5 | Observability overhead NR gate | <= 15% regression | — | |

### NF26 — Lab / Testing (F26)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF26.1 | Schedule permutation throughput | > 5K permutations/sec (100-task) | > 10K | DPOR exploration speed. |
| NF26.2 | Virtual time advance overhead | < 500 ns per tick | < 100 ns | Must not bottleneck simulation. |
| NF26.3 | Determinism guarantee | 100% identical outcomes for same seed | — | Structural guarantee. |
| NF26.4 | Lab throughput NR gate | <= 10% regression | — | |

### NF27 — Combinators (F27)

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF27.1 | Combinator chain throughput (5-deep) | > 1M evaluations/sec | > 2M | |
| NF27.2 | Per-combinator allocation (steady state) | 0 heap allocs | — | |
| NF27.3 | Retry with 3 attempts overhead (excluding waits) | < 1 us | < 200 ns | Retry bookkeeping cost. |
| NF27.4 | Combinator throughput NR gate | <= 10% regression | — | |

### NF28 — Interop (F28) `[DEFERRED]`

| # | Metric | Hard Ceiling | Soft Target | Rationale |
|---|--------|-------------|-------------|-----------|
| NF28.1 | Tokio Handle shim overhead | `[DEFERRED]` | — | Define after compatibility crate. |
| NF28.2 | Tower adapter throughput | `[DEFERRED]` | — | |
| NF28.3 | Shim correctness under cancellation | `[DEFERRED]` | — | |
| NF28.4 | Interop overhead NR gate | `[DEFERRED]` | — | |

---

## 3. Reliability / Stability Criteria

| # | Criterion | Threshold | Rationale |
|---|-----------|-----------|-----------|
| RS01 | Zero data loss under cancel | 0 events lost in 1M cancel cycles | Two-phase commit contract |
| RS02 | No obligation leaks | 0 leaks in 1M region-close cycles | Structural invariant |
| RS03 | No deadlocks under contention | 0 deadlocks in 10M lock-acquire cycles | Lock ordering enforcement |
| RS04 | No use-after-free (Miri clean) | 0 UB findings | Safe Rust guarantee |
| RS05 | Deterministic replay consistency | 100% trace match across 10K replays | LabRuntime contract |
| RS06 | Graceful degradation under OOM | No panic; controlled shedding | Production resilience |
| RS07 | No wakeup storms | < 2x expected wakeups under contention | Efficiency under load |

---

## 4. Resource Budget Constraints

| Resource | Per-Connection | Per-Task | Global (idle) |
|----------|---------------|----------|---------------|
| Memory | < 16 KB | < 512 B | < 10 MB |
| File descriptors | 1 socket + 1 timer | 0 | < 100 |
| Threads | 0 (async) | 0 (async) | core_count + blocking_pool |
| Allocations per request | < 20 | < 5 | N/A |

---

## 5. CI Integration

### 5.1 Regression Detection

All NF metrics MUST be tracked in CI with automatic regression alerts:

```
# Example CI gate
cargo bench --bench <suite> -- --save-baseline current
critcmp baseline current --threshold 10%
# Fail if any metric regresses >10% from baseline
```

### 5.2 Benchmark Suites Required

| Suite | Domains Covered | Status |
|-------|----------------|--------|
| `benches/spawn.rs` | NF01-NF02 (runtime, concurrency) | Needs creation |
| `benches/channel.rs` | NF03 (channels) | Needs creation |
| `benches/sync.rs` | NF04 (sync primitives) | Needs creation |
| `benches/timer.rs` | NF05 (time/timers) | Needs creation |
| `benches/io.rs` | NF06-NF09 (I/O, codec, bytes, reactor) | Needs creation |
| `benches/net.rs` | NF10-NF12 (TCP/UDP, DNS, TLS) | Needs creation |
| `benches/http.rs` | NF13-NF14 (WebSocket, HTTP) | Needs creation |
| `benches/web.rs` | NF16-NF17 (web framework, gRPC) | Needs creation |
| `benches/data.rs` | NF18-NF19 (database, messaging) | Needs creation |
| `benches/service.rs` | NF20 (service/middleware) | Needs creation |
| `benches/os.rs` | NF21-NF23 (fs, process, signals) | Needs creation |
| `benches/combinator.rs` | NF24, NF27 (streams, combinators) | Needs creation |
| `benches/observability.rs` | NF25 (observability) | Needs creation |
| `benches/lab.rs` | NF26 (lab/testing) | Needs creation |
| `benches/global_budget.rs` | Cross-domain (resource budgets) | Needs creation |

### 5.3 Verification Mapping

Each NF domain maps to a test file for contract validation:

| Domain | Test File | Purpose |
|--------|-----------|---------|
| NF01-NF28 | `tests/tokio_nonfunctional_closure_criteria.rs` | Schema + threshold validation |
| RS01-RS07 | `tests/tokio_nonfunctional_closure_criteria.rs` | Reliability contract validation |
| Cross-domain | `tests/tokio_nonfunctional_closure_criteria.rs` | Resource budget validation |

---

## 6. Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-03-03 | SapphireHill | Initial criteria (v1.0) |
| 2026-03-03 | SapphireHill | v2.0: expanded to all 28 domains, added structured concurrency, codecs, reactor, DNS, WebSocket, fs, process, signals, streams, observability, lab, interop. Added regression policy, exemption policy, verification mapping. |
| 2026-03-03 | DustySnow | Added explicit pointer to consolidated T1.2 domain DoD synthesis matrix for closure gating. |
