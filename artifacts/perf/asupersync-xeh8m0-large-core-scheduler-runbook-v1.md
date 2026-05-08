# asupersync-xeh8m0.3 Large-Core Scheduler Evidence Runbook

This runbook defines the measurement lane for `asupersync-xeh8m0.3`. It is a source-only setup artifact: it does not claim a speedup and it does not change scheduler code.

## Scenario

- Scenario id: `xeh8m0-three-lane-decision-large-core-baseline`
- Benchmark surface: `benches/scheduler_benchmark.rs`
- Criterion group/filter: `scheduler/three_lane_decision`
- Host class: at least 64 logical CPUs and 256 GiB RAM
- Comparison rule: compare only runs from the same rch worker or record `verdict=no_win`

The selected benchmark group covers:

- `fast_ready_uncontended`
- `fast_ready_local_peek_contended`
- `global_ready_burst/64`
- `global_ready_burst/512`
- `global_ready_burst_evidence_off`
- `global_ready_burst_evidence_on`

## Required Command

Run the benchmark through `rch`:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_xeh8m0_scheduler_evidence CARGO_INCREMENTAL=0 RUSTFLAGS='-C debuginfo=1 -C force-frame-pointers=yes' cargo bench -p asupersync --bench scheduler_benchmark -- scheduler/three_lane_decision
```

The JSON artifact contract must parse:

```bash
jq empty artifacts/perf/asupersync-xeh8m0-large-core-scheduler-evidence-v1.json
```

## Required Receipt

Write the baseline receipt here:

`tests/artifacts/perf/asupersync-xeh8m0.3/three_lane_decision_baseline_v1.json`

The receipt must include:

- `git_sha`
- `timestamp_utc`
- `hostname_or_rch_worker`
- `logical_cpu_count`
- `ram_gib`
- `kernel`
- `rustc_version`
- `cargo_version`
- `benchmark_command`
- `criterion_filter`
- `p50`
- `p95`
- `p999`
- `elements_per_second`
- `sample_count`
- `verdict`

Use `verdict=no_win` when the available worker cannot satisfy the host class or when variance prevents a defensible conclusion. Do not claim a scheduler speedup from a missing or cross-host baseline.

## Closeout Gate

The bead is not complete until the closeout lists:

- The exact rch command run.
- The rch worker identity and host fingerprint.
- The receipt path.
- The p50/p95/p999 and throughput values.
- Whether the evidence supports, rejects, or cannot evaluate the performance hypothesis.

Do not update README support claims or change scheduler code until a measured receipt exists.
