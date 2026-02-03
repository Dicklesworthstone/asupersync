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

## CI Integration

The benchmark CI workflow (`.github/workflows/benchmarks.yml`) runs on PRs and saves baselines for regression detection. See the workflow file for details.

## Measurement Methodology

- **Statistical rigor**: Criterion collects 100 samples (50 for throughput) with warmup
- **Deterministic inputs**: All benchmarks use fixed seeds for reproducibility
- **Black-box optimization**: `criterion::black_box` prevents dead-code elimination
- **Throughput tracking**: Elements/sec and bytes/sec for batch operations
- **Outlier detection**: Criterion flags statistical outliers automatically
- **No system-dependent behavior**: Golden tests use virtual time and deterministic scheduling
