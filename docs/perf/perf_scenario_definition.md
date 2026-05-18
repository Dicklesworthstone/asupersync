# Performance Profiling Scenario - Round 2 Post-yvmiat

**Scenario**: Runtime scheduler, context, and channel performance optimization
**Workload**: artifacts/runtime_workload_corpus_v1.json (AA01-WL-CPU-001 primary target)
**Metric**: CPU hotspots with >5% impact evidence via samply profiling
**Success Criteria**: Ranked hotspot table with concrete evidence, ship measurable wins only

**Target Directories**:
- src/runtime/scheduler/ (wake path, scheduling primitives)  
- src/cx/ (capability context building)
- src/channel/ (two-phase reserve/send operations)

**Previous Context**: yvmiat optimization delivered 71.8% → ~20% improvement in schedule_local_push
**This Round**: Find next >5% targets with hard profiling evidence

**Budget**: 60 minutes ship-or-surface
**Evidence Standard**: samply flame graphs + quantified impact per function

## NUMA Ready-Queue Sharding Scenario (asupersync-c8thc8.7)

**Purpose**: Decide whether ready-queue ingress/drain work needs NUMA-aware
partitioning for 64+ logical CPU hosts before any scheduler rewrite.

**Control Surface**: `benches/scheduler_benchmark.rs`

**Primary Lanes**:
- `scheduler/global_ready_contention/inject_ready_then_drain/{1,8,32,64}`
- `scheduler/three_lane_decision/global_ready_burst/{64,512}`
- `scheduler/three_lane_decision/fast_ready_uncontended`
- `scheduler/three_lane_decision/fast_ready_local_peek_contended`
- `scheduler/adaptive_cancel_streak/cancel_ready_mixed/{2,4,8,16}`
- `scheduler/adaptive_cancel_streak/ready_stall_depth/{2,4,8}`

**Required Metrics**:
- Throughput interval for each ready-ingress and ready-drain lane.
- p50/p95/p99/p999 latency derived from Criterion samples.
- Fairness signal from cancel/ready mixed and ready-stall-depth lanes.
- Cancellation/drain overhead from the existing cancel/drain bench surfaces
  before claiming scheduler-wide improvement.
- Evidence-capture overhead from ready-burst evidence on/off cases.

**Remote-only Commands**:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_numa_ready_queue_global CARGO_INCREMENTAL=0 CARGO_PROFILE_BENCH_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo bench -p asupersync --bench scheduler_benchmark -- scheduler/global_ready_contention
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_numa_ready_queue_three_lane CARGO_INCREMENTAL=0 CARGO_PROFILE_BENCH_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo bench -p asupersync --bench scheduler_benchmark -- scheduler/three_lane_decision
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_numa_ready_queue_cancel_ready CARGO_INCREMENTAL=0 CARGO_PROFILE_BENCH_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo bench -p asupersync --bench scheduler_benchmark -- scheduler/adaptive_cancel_streak
```

**Receipt Requirements**:
- Capture git SHA, rch worker id, host logical CPU count, RAM, kernel, rustc,
  cargo, command line, and Criterion sample count.
- Compare only same-host before/after runs. Cross-host data may seed a hunch,
  but it is not release evidence.
- Link the receipt beside the existing baseline pattern at
  `tests/artifacts/perf/asupersync-h6pjqb/scheduler_p999_latency_receipt_v1.json`.

**Ship Gate**:
- Ship a NUMA-ready-queue prototype only after at least one ready-ingress or
  ready-drain lane improves on same-host data.
- Block if p95/p99/p999 latency, cancel/ready fairness, cancellation/drain, or
  evidence-capture overhead regresses materially.
- If the data points to local-priority lock contention instead of ingress queue
  placement, file the next bead against that narrower bottleneck.
