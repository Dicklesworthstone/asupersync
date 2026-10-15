# Kernel Fast Path Prototype Contract

Bead: `asupersync-1508v.4.5`

## Purpose

This contract defines the prototype surface for shard-local dispatch, wake coalescing, and steal-path improvements behind a reversible fallback seam. The prototype must be selectable versus the incumbent path, show measurable wins on representative workloads, and preserve determinism, single-owner rules, and structured cleanup semantics.

## Contract Artifacts

1. Canonical artifact: `artifacts/kernel_fast_path_prototype_v1.json`
2. Comparator-smoke runner: `scripts/run_kernel_fast_path_prototype_smoke.sh`
3. Invariant suite: `tests/kernel_fast_path_prototype_contract.rs`

## Prototype Surfaces

### P1: Shard-Local LIFO Dispatch

The current `LocalQueue` uses a `Mutex<IntrusiveStack>` for push/pop. The prototype introduces a sharded fast path that keeps the owner-thread push/pop lock-free via a thread-local batch buffer, falling back to the shared stack only on steal or overflow.

| Aspect | Incumbent | Prototype |
|--------|-----------|-----------|
| Owner push | `Mutex<IntrusiveStack>` lock | Thread-local batch buffer (lock-free) |
| Owner pop | `Mutex<IntrusiveStack>` lock | Thread-local batch drain (lock-free) |
| Steal | Lock + FIFO scan | Lock + FIFO scan (unchanged) |
| Overflow | N/A | Flush batch to shared stack |
| Batch size | N/A | Configurable (default 8) |

### P2: Wake Coalescing

The current `WakerState` uses `Mutex<HashSet<TaskId>>` for dedup. The prototype adds a fixed-size bloom filter front-end that absorbs high-frequency duplicate wakes without acquiring the lock, falling back to the HashSet when the bloom saturates.

| Aspect | Incumbent | Prototype |
|--------|-----------|-----------|
| Dedup structure | `Mutex<HashSet<TaskId>>` | Bloom filter + `Mutex<HashSet<TaskId>>` |
| Hot-path lock | Always acquired | Skipped if bloom says "already woken" |
| False positive | None | Bounded by bloom parameters |
| Drain | `HashSet::drain()` | Clear bloom + `HashSet::drain()` |

### P3: Adaptive Steal Lookahead

The current steal path uses Power of Two Choices with a linear fallback. The prototype adds adaptive lookahead that adjusts the number of candidates based on recent steal success rate, reducing contention when queues are mostly balanced.

| Aspect | Incumbent | Prototype |
|--------|-----------|-----------|
| Candidate selection | 2 random + linear fallback | 2-4 adaptive + truncated fallback |
| Adaptation signal | None | Exponential moving average of steal success |
| Contention reduction | Fixed | Proportional to balance |

## Fallback Seam Contract

All prototype paths MUST be gated behind a `FastPathConfig` that defaults to the incumbent behavior. The seam is:

```rust
pub struct FastPathConfig {
    pub shard_local_dispatch: bool,     // default: false
    pub wake_coalescing: bool,          // default: false
    pub adaptive_steal: bool,           // default: false
    pub batch_size: usize,              // default: 8
    pub bloom_bits: usize,              // default: 256
    pub steal_ema_alpha: f64,           // default: 0.1
}
```

When any prototype flag is false, the code path MUST be identical to the pre-prototype behavior. This is enforced by invariant tests.

## Benchmark Dimensions

### B1: Owner Push/Pop Throughput

- Messages per second for local push/pop cycles
- Measured with 1, 2, 4, 8 workers
- Batch vs non-batch comparison

### B2: Wake Dedup Throughput

- Wakes per second under varying duplicate rates (0%, 50%, 90%, 99%)
- Lock acquisition count reduction
- False positive rate at each duplicate level

### B3: Steal Latency Distribution

- p50, p95, p99 steal latency in nanoseconds
- Steal success rate under balanced vs imbalanced load
- Contention cycles saved by adaptive lookahead

### B4: End-to-End Task Throughput

- Tasks completed per second under mixed workload
- Comparison: all-incumbent vs all-prototype vs selective
- Tail latency (p99, p999) regression check

## Structured Logging Contract

Prototype benchmark logs MUST include:

- `prototype_surface`: Which prototype (P1/P2/P3)
- `fast_path_active`: Whether prototype path was used
- `worker_count`: Number of workers
- `batch_size`: Configured batch size (P1)
- `bloom_bits`: Bloom filter size (P2)
- `steal_ema_alpha`: EMA alpha for steal adaptation (P3)
- `throughput_ops_sec`: Operations per second
- `p50_ns`, `p95_ns`, `p99_ns`: Latency percentiles in nanoseconds
- `lock_acquisitions`: Lock acquisition count
- `false_positive_rate`: Bloom false positive rate (P2)
- `steal_success_rate`: Steal success fraction (P3)
- `verdict`: `advance`, `hold`, or `reject`

## Comparator-Smoke Runner

Canonical runner: `scripts/run_kernel_fast_path_prototype_smoke.sh`

The runner reads `artifacts/kernel_fast_path_prototype_v1.json`, supports deterministic dry-run or execute modes, and emits:

1. Per-scenario manifests with schema `kernel-fast-path-prototype-smoke-bundle-v1`
2. Aggregate run report with schema `kernel-fast-path-prototype-smoke-run-report-v1`

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa042 cargo test --test kernel_fast_path_prototype_contract -- --nocapture
```

## Cross-References

- `src/runtime/scheduler/local_queue.rs` -- Local queue (incumbent)
- `src/runtime/scheduler/stealing.rs` -- Work stealing (incumbent)
- `src/runtime/scheduler/global_injector.rs` -- Global injector
- `src/runtime/scheduler/intrusive.rs` -- Intrusive stack
- `src/runtime/waker.rs` -- Waker dedup (incumbent)
- `artifacts/kernel_fast_path_substrate_comparison_v1.json` -- Substrate comparison (AA-04.1)
- `artifacts/kernel_fast_path_prototype_v1.json`
- `scripts/run_kernel_fast_path_prototype_smoke.sh`
- `tests/kernel_fast_path_prototype_contract.rs`
