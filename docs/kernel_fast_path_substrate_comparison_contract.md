# Kernel Fast Path Substrate Comparison Contract

Bead: `asupersync-1508v.4.4`

## Purpose

This contract defines the evaluation framework for comparing the current kernel substrate (Mutex-protected intrusive stacks, `HashSet` waker dedup, `SegQueue`/`BinaryHeap` global injection) against wait-free and progress-bounded alternatives. Every candidate is evaluated on throughput, tail latency, memory footprint, determinism impact, and safety/proof cost.

## Contract Artifacts

1. Canonical artifact: `artifacts/kernel_fast_path_substrate_comparison_v1.json`
2. Comparator-smoke runner: `scripts/run_kernel_fast_path_substrate_smoke.sh`
3. Invariant suite: `tests/kernel_fast_path_substrate_comparison_contract.rs`

## Current Substrate Inventory

### Local Queue (`src/runtime/scheduler/local_queue.rs`)

- **Structure**: Mutex-protected intrusive stack via `IntrusiveStack`
- **Owner access**: LIFO push/pop (cache-hot)
- **Thief access**: FIFO steal with bounded lookahead (cap 8)
- **Locking**: `ContendedMutex` (pointer-ordered dual-lock for stealing)
- **Allocation**: Zero allocation on hot path (arena-backed `TaskRecord`)

### Work Stealing (`src/runtime/scheduler/stealing.rs`)

- **Algorithm**: Power of Two Choices (Mitzenmacher 2001)
- **Fallback**: Linear scan after two-choice failure
- **Determinism**: Uses `DetRng` for reproducible steal ordering

### Global Injector (`src/runtime/scheduler/global_injector.rs`)

- **Ready lane**: Lock-free `SegQueue` (crossbeam)
- **Timed lane**: Mutex-protected `BinaryHeap` (EDF)
- **Cancel lane**: Lock-free `SegQueue`

### Waker Dedup (`src/runtime/waker.rs`)

- **Structure**: `Mutex<HashSet<TaskId>>`
- **Dedup**: O(1) insert, drain on poll
- **Wake source**: Attributed (Timer, IO, Explicit, Unknown)

## Candidate Matrix

### Candidate 1: Wait-Free SPSC Ring (Local Queue)

Replace Mutex-protected intrusive stack with a bounded SPSC ring buffer for the owner path, keeping a separate MPSC channel for steals.

| Dimension | Expected Impact |
|-----------|----------------|
| Throughput | +10-20% on owner push/pop |
| p99 latency | Eliminates lock contention tail |
| Memory | Fixed ring size vs dynamic stack |
| Determinism | Identical (FIFO/LIFO semantics preserved) |
| Safety | Requires `unsafe` for wait-free ring |

### Candidate 2: Chase-Lev Deque (Local Queue + Stealing)

Replace intrusive stack + dual-lock steal with a Chase-Lev work-stealing deque.

| Dimension | Expected Impact |
|-----------|----------------|
| Throughput | +15-30% steal throughput |
| p99 latency | Lock-free steal eliminates contention spikes |
| Memory | Per-slot overhead instead of intrusive links |
| Determinism | Requires deterministic steal ordering shim |
| Safety | Well-studied unsafe (crossbeam-deque reference) |

### Candidate 3: Sharded Waker Bitmap (Waker Dedup)

Replace `Mutex<HashSet>` with a fixed-size atomic bitmap (one bit per task slot).

| Dimension | Expected Impact |
|-----------|----------------|
| Throughput | +50-100% on wake hot path |
| p99 latency | No lock contention |
| Memory | O(max_tasks / 8) bytes |
| Determinism | Identical (set semantics preserved) |
| Safety | Safe (atomic bit ops only) |

### Candidate 4: Bounded-Progress Timed Lane (Global Injector)

Replace `Mutex<BinaryHeap>` with a timing wheel or calendar queue for the timed lane.

| Dimension | Expected Impact |
|-----------|----------------|
| Throughput | +20-40% for deadline-heavy workloads |
| p99 latency | O(1) insert/extract vs O(log n) |
| Memory | Pre-allocated wheel slots |
| Determinism | Identical (EDF ordering preserved) |
| Safety | Safe implementation possible |

## Evaluation Methodology

### Microbenchmark Suite

Each candidate is benchmarked on:

1. **Push throughput**: Single-producer sequential push rate
2. **Pop throughput**: Single-consumer sequential pop rate
3. **Steal throughput**: Cross-thread steal rate under contention
4. **Mixed workload**: Realistic push/pop/steal ratio (70/20/10)
5. **Wake throughput**: Wake dedup rate under concurrent wakers

### Tail Latency Profile

For each candidate:

- p50, p95, p99, p999 latency per operation
- Contention spike frequency (>2x p99 events per 1M ops)
- Maximum observed latency

### Memory Footprint

- Per-task overhead (bytes)
- Peak allocation during benchmark
- Steady-state working set size

### Evaluation Criteria

Candidates are evaluated using the AA-01.3 EV scoring model:

- **Impact** (0.35): Throughput and latency improvement on representative workloads
- **Confidence** (0.20): Quality of benchmark evidence
- **Effort** (0.15): Implementation complexity and review burden
- **Adoption friction** (0.15): Migration risk and fallback seam complexity
- **User-visible benefit** (0.15): Observable improvement in application-level benchmarks

### Decision Rules

1. A candidate MUST beat the baseline by >10% on at least one key metric
2. A candidate MUST NOT regress any metric by >5%
3. Candidates requiring `unsafe` MUST include proof sketch or reference implementation
4. The winning candidate MUST be gated behind a fallback seam (AA-04.2)

## Adoption Wedge Contract

The selected candidate (if any) ships behind a conservative fallback seam:

1. Feature flag: `RuntimeConfig::fast_path_substrate` (default: current baseline)
2. Fallback: automatic revert to baseline on any regression signal
3. Structured logging: benchmark deltas emitted at startup when experimental path active

## Structured Logging Contract

Benchmark logs MUST include:

- `candidate_id`: Which substrate candidate
- `benchmark_id`: Microbenchmark or workload identifier
- `throughput_ops_sec`: Operations per second
- `p50_ns`, `p95_ns`, `p99_ns`, `p999_ns`: Latency percentiles in nanoseconds
- `memory_bytes`: Memory footprint
- `determinism_impact`: `none`, `shim_required`, or `broken`
- `verdict`: `win`, `lose`, `tie`, or `inconclusive`

## Comparator-Smoke Runner

Canonical runner: `scripts/run_kernel_fast_path_substrate_smoke.sh`

The runner reads `artifacts/kernel_fast_path_substrate_comparison_v1.json`, supports deterministic dry-run or execute modes, and emits:

1. Per-scenario manifests with schema `kernel-fast-path-substrate-smoke-bundle-v1`
2. Aggregate run report with schema `kernel-fast-path-substrate-smoke-run-report-v1`

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa041 cargo test --test kernel_fast_path_substrate_comparison_contract -- --nocapture
```

## Cross-References

- `src/runtime/scheduler/local_queue.rs` -- Current local queue
- `src/runtime/scheduler/stealing.rs` -- Work stealing
- `src/runtime/scheduler/global_injector.rs` -- Global injection queue
- `src/runtime/waker.rs` -- Waker dedup
- `src/runtime/scheduler/intrusive.rs` -- Intrusive stack
- `artifacts/runtime_control_seam_inventory_v1.json` -- Control seam inventory (AA-01.3)
- `artifacts/kernel_fast_path_substrate_comparison_v1.json`
- `scripts/run_kernel_fast_path_substrate_smoke.sh`
- `tests/kernel_fast_path_substrate_comparison_contract.rs`
