# Runtime Tail-Latency Taxonomy Contract

Bead: `asupersync-1508v.1.4`

## Purpose

This contract defines the canonical tail-latency decomposition vocabulary for Asupersync. It gives later runtime-ascension work one stable language for queueing, service, I/O or network, retry, synchronization, allocator or cache, and explicit unknown contribution instead of free-form prose.

The contract is intentionally split into:

1. A code-backed source of truth in `src/observability/diagnostics.rs`
2. A versioned artifact in `artifacts/runtime_tail_latency_taxonomy_v1.json`
3. Invariant tests in `tests/runtime_tail_latency_taxonomy_contract.rs`

## Canonical Equation

The canonical equation is:

`tail_latency_ns = queueing_ns + service_ns + io_or_network_ns + retries_ns + synchronization_ns + allocator_or_cache_ns + unknown_ns`

Two rules matter:

1. Direct-duration fields and proxy signals are not interchangeable.
2. If a term cannot yet be directly measured, the residual latency must remain visible in `tail.unknown.unmeasured_ns`.

## Required Core Log Fields

Every runtime or test emitter that claims this contract must understand the compact always-on core:

| Key | Unit | Meaning |
| --- | --- | --- |
| `tail.contract_version` | `schema_id` | Versioned taxonomy identifier |
| `tail.total_latency_ns` | `ns` | Observed end-to-end tail latency |
| `tail.queueing.ready_queue_depth` | `count` | Runnable backlog proxy |
| `tail.service.poll_count` | `count` | Service-demand proxy |
| `tail.io_or_network.events_received` | `count` | Reactor/network pressure proxy |
| `tail.retries.total_delay_ns` | `ns` | Direct retry/backoff delay |
| `tail.synchronization.lock_wait_ns` | `ns` | Direct lock-contention delay |
| `tail.allocator_or_cache.live_allocations` | `count` | Allocator/cache pressure proxy |
| `tail.unknown.unmeasured_ns` | `ns` | Explicit residual bucket |

## Term Mapping

### Queueing

- Direct duration key: `tail.queueing.ns`
- Attribution key: `tail.queueing.attribution_state`
- Core producers:
  - `asupersync::obligation::lyapunov::StateSnapshot::ready_queue_depth` in `src/obligation/lyapunov.rs`
  - `asupersync::obligation::lyapunov::StateSnapshot::draining_regions` in `src/obligation/lyapunov.rs`
- Extended producers:
  - `asupersync::combinator::bulkhead::BulkheadMetrics::queue_depth` in `src/combinator/bulkhead.rs`
  - `asupersync::sync::pool::PoolStats::waiters` in `src/sync/pool.rs`

### Service

- Direct duration key: `tail.service.ns`
- Attribution key: `tail.service.attribution_state`
- Core producers:
  - `asupersync::runtime::state::TaskSnapshot::poll_count` in `src/runtime/state.rs`
  - `asupersync::observability::resource_accounting::ResourceAccountingSnapshot::poll_quota_consumed` in `src/observability/resource_accounting.rs`
- Extended producer:
  - `asupersync::observability::resource_accounting::ResourceAccountingSnapshot::cost_quota_consumed` in `src/observability/resource_accounting.rs`

### I/O Or Network

- Direct duration key: `tail.io_or_network.ns`
- Attribution key: `tail.io_or_network.attribution_state`
- Core producer:
  - `asupersync::runtime::io_driver::IoStats::events_received` in `src/runtime/io_driver.rs`
- Extended producers:
  - `asupersync::runtime::io_driver::IoStats::polls` in `src/runtime/io_driver.rs`
  - `asupersync::runtime::io_driver::IoStats::wakers_dispatched` in `src/runtime/io_driver.rs`

### Retries

- Direct duration key: `tail.retries.ns`
- Attribution key: `tail.retries.attribution_state`
- Core producer:
  - `asupersync::combinator::retry::RetryState::total_delay` in `src/combinator/retry.rs`
- Extended producers:
  - `asupersync::combinator::rate_limit::RateLimitMetrics::total_wait_time` in `src/combinator/rate_limit.rs`
  - `asupersync::combinator::circuit_breaker::CircuitBreakerMetrics::total_rejected` in `src/combinator/circuit_breaker.rs`

### Synchronization

- Direct duration key: `tail.synchronization.ns`
- Attribution key: `tail.synchronization.attribution_state`
- Core producers:
  - `asupersync::sync::contended_mutex::LockMetricsSnapshot::wait_ns` in `src/sync/contended_mutex.rs`
  - `asupersync::observability::resource_accounting::ResourceAccountingSnapshot::obligations_pending` in `src/observability/resource_accounting.rs`
- Extended producers:
  - `asupersync::sync::contended_mutex::LockMetricsSnapshot::hold_ns` in `src/sync/contended_mutex.rs`
  - `asupersync::sync::pool::PoolStats::total_wait_time` in `src/sync/pool.rs`

### Allocator Or Cache

- Direct duration key: `tail.allocator_or_cache.ns`
- Attribution key: `tail.allocator_or_cache.attribution_state`
- Core producer:
  - `asupersync::runtime::region_heap::HeapStats::live` in `src/runtime/region_heap.rs`
- Extended producers:
  - `asupersync::runtime::region_heap::HeapStats::bytes_live` in `src/runtime/region_heap.rs`
  - `asupersync::observability::resource_accounting::ResourceAccountingSnapshot::heap_bytes_peak` in `src/observability/resource_accounting.rs`

### Unknown

- Direct duration key: `tail.unknown.unmeasured_ns`
- Attribution key: `tail.unknown.attribution_state`
- Required policy:
  - if a direct-duration field is unavailable for any term, the missing portion must remain visible here
  - missing attribution must never silently collapse to zero

## Unknown Bucket Policy

The unknown bucket is mandatory whenever attribution is incomplete. It exists to preserve evidence quality:

1. Missing measurement is not the same thing as zero latency.
2. Controllers and future optimization tracks must be able to distinguish measured improvement from measurement blind spots.
3. Replay and forensics tools should treat a large unknown bucket as an investigation target, not as clean health.

## Sampling Policy

The contract requires the following sampling discipline:

1. Always emit the compact core fields for any tail-latency event.
2. Extended fields may be replay-only or forensic-only, but must retain the stable keys defined by this contract.
3. When a term is only represented by proxies, preserve the proxy fields and keep the residual duration in the unknown bucket.

## Compact Tail Causal Emitters

Bead `asupersync-d87ytw.5` adds the first runtime-facing compact emitter for this taxonomy:

- `TailLatencyEmitterConfig`
- `TailLatencyCompactSample`
- `TailLatencyCompactEvent`
- `emit_tail_latency_compact_event`

The emitter is disabled by default. Enabled core emission produces a deterministic event row with:

- `scenario_id`
- `event_id`
- `taxonomy_version`
- `fields`
- `attribution_states`
- `missing_producers`
- `unknown_unmeasured_ns`
- `overhead_estimate_bytes`

The compact core mirrors the required log field table exactly. It includes `tail.contract_version`, `tail.total_latency_ns`, ready queue depth, poll count, I/O events received, retry delay, lock wait, live allocations, and the unknown residual bucket.

Missing producers fail closed without dropping the row. The numeric field remains present with value `0`, the key is listed in `missing_producers`, the term attribution state becomes `missing_producer`, and the residual stays visible in `tail.unknown.unmeasured_ns`. Proxy fields never reduce the unknown bucket; only measured direct durations do. If measured direct durations exceed `tail.total_latency_ns`, emission returns an error instead of saturating silently.

Extended allocator byte pressure is gated with `TailLatencyEmitterConfig::with_extended_allocator_bytes_live()`. It is replay/forensics-only until a later bead proves a live low-overhead producer.

## Compact Emitter Smoke Runner

The deterministic runner is `scripts/run_tail_causal_attribution_emitters_smoke.sh`.

It exercises:

1. A complete compact row with all producers present.
2. A missing-producer row that preserves residual unknown latency.
3. The default disabled path, which emits no row.

Every execute-mode run logs scenario id, event id, taxonomy version, compact fields, residual unknown, overhead estimate, artifact path, and replay command in a JSON report. The runner routes the Rust proof through `rch` and writes a report artifact under the selected output root.

## Validation

The invariant suite for this contract lives in `tests/runtime_tail_latency_taxonomy_contract.rs`.

Focused reproduction:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tail_latency_taxonomy cargo test -p asupersync --test runtime_tail_latency_taxonomy_contract --features test-internals -- --nocapture
```

Smoke reproduction:

```bash
bash scripts/run_tail_causal_attribution_emitters_smoke.sh --execute --output-root target/tail-causal-attribution-smoke
```

The validation checks:

1. The doc section structure stays stable.
2. The artifact stays aligned to the code-backed contract.
3. Producer file paths continue to exist.
4. Term and required-field inventories stay stable across edits.
5. Compact emitter rows preserve schema keys, unknown residuals, disabled-mode behavior, deterministic serialization, and low-overhead feature gating.

## Cross-References

- `src/observability/diagnostics.rs`
- `artifacts/runtime_tail_latency_taxonomy_v1.json`
- `tests/runtime_tail_latency_taxonomy_contract.rs`
- `scripts/run_tail_causal_attribution_emitters_smoke.sh`
- `src/runtime/scheduler/decision_contract.rs`
- `src/obligation/lyapunov.rs`
- `src/observability/resource_accounting.rs`
