# Benchmarking Guide

## Overview

Asupersync uses [Criterion.rs](https://crates.io/crates/criterion) for statistical benchmarking and a custom golden output framework for behavioral equivalence verification.

## Quick Start

```bash
# Run all benchmarks (saves to target/criterion/)
cargo bench

# Run specific benchmark suite
cargo bench --bench phase0_baseline
cargo bench --bench scheduler_benchmark
cargo bench --bench protocol_benchmark
cargo bench --bench timer_wheel
cargo bench --bench tracing_overhead
cargo bench --bench reactor_benchmark

# Save a named baseline for comparison
cargo bench -- --save-baseline initial --noplot

# Compare against a baseline
cargo bench -- --baseline initial --noplot
```

## Benchmark Suites

### phase0_baseline

Core type operations and runtime primitives.

| Group | What It Measures | Target |
|-------|------------------|--------|
| `outcome/*` | Severity comparison, join/race aggregation | < 5ns |
| `budget/*` | Creation, deadline, semiring combination | < 10ns |
| `cancel_reason/*` | Creation, strengthen | < 5ns |
| `arena/*` | Insert, get, remove, iteration | < 50ns single op |
| `runtime_state/*` | Region creation, quiescence check, cancel | < 500ns |
| `combinator/*` | join2, race2, timeout config | < 10ns |
| `lab_runtime/*` | LabRuntime creation, time query | < 1us create |
| `throughput/*` | Batch region/arena/budget operations | > 50M elem/s |
| `time/*` | Time arithmetic (from_nanos, duration_since) | < 1ns |
| `raptorq/pipeline/*` | Send/receive pipeline (64KB-1MB) | > 100 MiB/s |

### scheduler_benchmark

Scheduling primitives and work stealing.

| Group | What It Measures | Target |
|-------|------------------|--------|
| `local_queue/*` | Per-worker LIFO queue | < 50ns push/pop |
| `global_queue/*` | Cross-thread injection queue | < 100ns (lock-free) |
| `priority/*` | Three-lane scheduler (cancel/timed/ready) | < 200ns schedule/pop |
| `lane_priority/*` | Lane ordering correctness | < 500ns |
| `work_stealing/*` | Batch theft between workers | < 500ns for 8-task |
| `throughput/*` | High-throughput scheduling workload | > 4M elem/s |
| `parker/*` | Thread park/unpark latency | < 500ns unpark-park |

## Profiling Cookbook

This section provides copy-paste commands for CPU, allocation, and syscall
profiling. Use deterministic inputs and fixed seeds where the benchmark/test
supports them, and record the command + baseline in the isomorphism template.

### CPU Profiling (flamegraph)

Requires `cargo-flamegraph` and `perf` on Linux.

```bash
# Install once
cargo install flamegraph

# Scheduler hot path (release build with frame pointers)
RUSTFLAGS="-C force-frame-pointers=yes" \
cargo flamegraph --bench scheduler_benchmark -- --bench

# Cancellation/combinator path
RUSTFLAGS="-C force-frame-pointers=yes" \
cargo flamegraph --bench protocol_benchmark -- --bench

# Trace/DPOR path
RUSTFLAGS="-C force-frame-pointers=yes" \
cargo flamegraph --bench tracing_overhead -- --bench
```

Notes:
- Keep the workload deterministic (fixed seeds) to make deltas meaningful.
- Always capture the exact command and git SHA in your perf notes.

### Allocation Profiling (heap/alloc)

Preferred path uses the built-in census script:

```bash
# Default: heaptrack + phase0_baseline
./scripts/alloc_census.sh

# Scheduler benchmark with explicit tool
./scripts/alloc_census.sh --tool heaptrack --cmd "cargo bench --bench scheduler_benchmark"
```

Alternative manual tools:

```bash
# heaptrack (Linux)
heaptrack ./target/release/deps/scheduler_benchmark-*

# valgrind massif (portable but slow)
valgrind --tool=massif ./target/release/deps/scheduler_benchmark-*

# jemalloc DHAT (if enabled)
MALLOC_CONF="prof:true,prof_active:true,lg_prof_sample:19" \
./target/release/deps/scheduler_benchmark-*
```

Notes:
- Use release builds to avoid debug noise.
- Compare allocation counts before/after and record % change.

### Syscall Profiling (strace)

```bash
# High-level syscall counts + time spent
strace -f -c -o /tmp/asupersync_syscalls.txt \
  cargo bench --bench scheduler_benchmark

# Inspect the summary
cat /tmp/asupersync_syscalls.txt
```

Notes:
- `-f` follows child threads.
- Keep the same benchmark configuration when comparing deltas.

### Perf Notes Checklist

Always attach:
- Command(s) executed (verbatim)
- Baseline comparison (mean/p95/p99 if available)
- Allocation delta (% change)
- Isomorphism proof (see template below)

## Golden Output Tests

Golden output tests verify that the runtime's observable behavior has not changed.

```bash
# Run golden output verification
cargo test --test golden_outputs

# First-time recording (prints checksums to stderr)
cargo test --test golden_outputs -- --nocapture
```

### How It Works

1. Each test runs a deterministic workload with fixed inputs
2. Outputs are hashed to a u64 checksum via `DefaultHasher`
3. Checksums are compared against hardcoded expected values
4. Mismatch means behavior changed — intentional changes require updating the expected values

### Covered Workloads

| Test | What It Verifies |
|------|------------------|
| `golden_outcome_severity_lattice` | Severity enum ordering (Ok < Err < Cancelled < Panicked) |
| `golden_budget_combine_semiring` | Budget combination picks tighter constraints |
| `golden_cancel_reason_strengthen` | Strengthen picks more severe cancel reason |
| `golden_arena_insert_remove_cycle` | Arena insert/remove/reinsert produces correct values |
| `golden_runtime_state_region_lifecycle` | Region create/cancel state transitions |
| `golden_lab_runtime_deterministic_scheduling` | Same seed produces same execution |
| `golden_join_outcome_aggregation` | join2 worst-wins aggregation matrix |
| `golden_race_outcome_aggregation` | race2 winner selection |
| `golden_time_arithmetic` | Time type arithmetic stability |

### Updating Golden Values

After an intentional behavioral change:

1. Run `cargo test --test golden_outputs -- --nocapture 2>&1 | grep "GOLDEN MISMATCH"`
2. Verify the change is expected
3. Set the expected value in `FIRST_RUN_SENTINEL` mode (set to `0`) to record new values
4. Update with recorded values
5. Document why behavior changed in the commit message

## Isomorphism Proof Template (required for perf changes)

Any performance-focused change must include a **proof-of-equivalence** block.
This is the policy gate to ensure speedups do not silently change semantics.

Where to include it:
- PR description (preferred), or
- an appended section in the relevant benchmark PR notes

### Template

```
Isomorphism Proof (required)

Change summary:
- What changed and why it should be behavior-preserving.

Semantic invariants (check all):
- [ ] Outcomes unchanged (Ok/Err/Cancelled/Panicked)
- [ ] Cancellation protocol unchanged (request -> drain -> finalize)
- [ ] No task leaks / obligation leaks
- [ ] Losers drained after races
- [ ] Region close implies quiescence

Determinism + ordering:
- RNG: seed source unchanged / updated (explain)
- Tie-breaks: unchanged / updated (explain)
- Floating point: ordering + rounding unchanged / updated (explain)
- Iteration order: deterministic and stable

Trace equivalence:
- Trace equivalence class unchanged or justified (describe)
- Schedule certificate consistency checked (if applicable)

Golden outputs:
- `cargo test --test golden_outputs` run? [yes/no]
- Any checksum changes? [no / yes -> list + rationale]

Perf evidence:
- Benchmarks run (commands + baseline)
- p50/p95/p99 deltas (attach numbers)
```

### Policy

- A perf PR without this template is considered incomplete.
- If golden outputs change, the PR must explain why behavior changed and why it is acceptable.
- If determinism-related behavior changes (RNG, ordering, tie-breaks), the PR must document it explicitly.

## Baseline Capture

```bash
# Print baseline JSON to stdout (requires jq)
./scripts/capture_baseline.sh

# Save to baselines/ with timestamp + latest symlink
./scripts/capture_baseline.sh --save baselines/
```

Reads `target/criterion/*/new/estimates.json` and produces a single JSON with `{name, mean_ns, median_ns, std_dev_ns}` per benchmark. Baselines are saved as `baselines/baseline_<timestamp>.json` and `baselines/baseline_latest.json`.

The baseline JSON also includes `p95_ns` and `p99_ns`, computed from `sample.json`
as per-iteration latencies.

## Allocation Census

Use the allocation census script to capture allocation-heavy hot paths without
modifying code or outputs.

```bash
# Default: heaptrack + phase0_baseline
./scripts/alloc_census.sh

# Explicit tool + benchmark
./scripts/alloc_census.sh --tool valgrind --cmd "cargo bench --bench scheduler_benchmark"

# Optional flamegraph capture (requires cargo-flamegraph)
./scripts/alloc_census.sh --flamegraph
```

The script writes a report JSON to `baselines/alloc_census/` with the raw tool
artifacts and summaries. Example schema:

```json
{
  "generated_at": "2026-02-03T03:21:00Z",
  "tool": "heaptrack",
  "command": "cargo bench --bench phase0_baseline",
  "artifacts": {
    "raw": "baselines/alloc_census/heaptrack_20260203_032100.1234.gz",
    "summary": "baselines/alloc_census/heaptrack_20260203_032100.txt",
    "flamegraph": "baselines/alloc_census/flamegraph_20260203_032100.svg"
  }
}
```

Notes:
- `heaptrack` and `valgrind` are optional system tools; install as needed.
- `cargo-flamegraph` integration is best-effort and only runs for `cargo ...` commands.
- Keep inputs deterministic (fixed seeds) when comparing allocation deltas.

### Scheduler Hot-Path Allocation Audit (bd-1p8g)

Measurement attempt (valgrind/massif):

- Wrapping `cargo bench` via `alloc_census.sh` did not emit a Massif output file.
- Running Massif directly on the bench binary succeeded:

```bash
valgrind --tool=massif \
  --massif-out-file=/tmp/alloc_census/massif_direct.out \
  target/release/deps/scheduler_benchmark-<hash> \
  --warm-up-time 1 --measurement-time 5 --sample-size 10

ms_print /tmp/alloc_census/massif_direct.out
```

Observed summary:

- Peak heap usage ~ **571 KB** (Massif graph peak).
- Massif attribution is dominated by Criterion harness overhead (reporting/template data).
- Scheduler hot-path allocations are present but below Massif’s default threshold.

Static allocation census (code review):

- `src/runtime/scheduler/local_queue.rs`: `VecDeque<TaskId>` grows dynamically on push; `Stealer::steal_batch` allocates a new `Vec<TaskId>` per call.
- `src/runtime/scheduler/global_queue.rs`: `SegQueue` allocates segments as it grows.
- `src/runtime/scheduler/global_injector.rs`: `SegQueue` for cancel/ready lanes and `BinaryHeap` for timed lane; timed lane `BinaryHeap` grows dynamically on push.
- `src/runtime/scheduler/priority.rs`: `BinaryHeap` lanes and `HashSet` dedup grow dynamically; scratch `Vec` buffers allocate on first growth.
- `src/runtime/waker.rs`: `Vec<TaskId>` in `WakerState` grows and uses linear `contains` checks.

### Arena / Slab Plan (Zero-Alloc Scheduler Path)

Goal: eliminate per-poll allocations and reduce allocation volume by ≥90% in
scheduler benchmarks while preserving determinism.

Phase 1 (Immediate, low-risk):

- Replace `Stealer::steal_batch`’s per-call `Vec` allocation with a reusable
  buffer owned by the stealer or worker.
- Pre-size `BinaryHeap` and `HashSet` lanes using capacity hints derived from
  `RuntimeConfig` (e.g., `global_queue_limit`, worker count).
- Convert `WakerState`’s `Vec<TaskId>` to a reusable buffer with `clear()` reuse
  to avoid repeated allocations.

Phase 2 (Arena-backed task nodes):

- Introduce a scheduler-local slab for task nodes keyed by `TaskId` arena index.
- Store per-task scheduling metadata (lane, links, flags) in the slab.
- Replace dedup `HashSet` with a deterministic index-based flag vector.

Phase 3 (Intrusive queues):

- Replace `SegQueue`/`VecDeque` with intrusive queues storing slab indices,
  eliminating heap allocation per enqueue.
- Provide bounded ring buffers and explicit free lists to keep capacity stable.

Phase 4 (Bench + regression gate):

- Add allocation counters around scheduler lanes.
- Wire allocation checks into `benches/scheduler_benchmark.rs` and compare
  against a stored baseline (≤10% of current allocations).

Capacity guidance (initial sizing):

- Local queue: `worker_threads * 2 * steal_batch_size`
- Global lanes: `global_queue_limit` (or bounded fallback)
- Timed lane: `max_in_flight_timers` (from `TimerDriver` or config)

## CI Integration

Recommended CI workflow:

```yaml
- cargo test --test golden_outputs  # behavioral equivalence
- cargo bench                        # run benchmarks
- ./scripts/capture_baseline.sh --save baselines/  # archive baseline
```

The conformance bench runner (`conformance/src/bench/`) also supports regression checking with configurable thresholds (default: 10% mean, 15% p95, 25% p99, 10% allocation count).

### Regression Gates (benchmarks)

CI should compare the current benchmark run against `baselines/baseline_latest.json` and fail on
threshold regressions:

- mean: 1.10x
- p95: 1.15x
- p99: 1.25x

This is enforced in `.github/workflows/benchmarks.yml` using the baseline JSON produced by
`scripts/capture_baseline.sh`.

## Measurement Methodology

- **Statistical rigor**: Criterion collects 100 samples (50 for throughput) with warmup
- **Deterministic inputs**: All benchmarks use fixed seeds for reproducibility
- **Black-box optimization**: `criterion::black_box` prevents dead-code elimination
- **Throughput tracking**: Elements/sec and bytes/sec for batch operations
- **Outlier detection**: Criterion flags statistical outliers automatically
- **No system-dependent behavior**: Golden tests use virtual time and deterministic scheduling
