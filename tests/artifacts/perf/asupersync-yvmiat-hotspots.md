# asupersync-yvmiat Hotspot Table Attempt

## Scenario

- Bead: `asupersync-yvmiat`
- Target: scheduler/runtime profiling pass
- Workload surface: `benches/scheduler_benchmark.rs`
- Criterion filter: `scheduler/global_ready_contention`
- Command:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_yvmiat_flame cargo flamegraph --package asupersync --bench scheduler_benchmark --features test-internals -o artifacts/flamegraphs/main-asupersync-yvmiat.svg -- scheduler/global_ready_contention
```

## Result

No ranked hotspot table was produced. The benchmark build completed, but the profiler could not sample on the remote worker.

| Rank | Location | Metric | Value | Category | Evidence |
|------|----------|--------|-------|----------|----------|
| 1 | blocked before sampling | perf access | `perf_event_paranoid=4` | profiler-permission | `tests/artifacts/perf/asupersync-yvmiat-profile-notes.md` |

## Blocker

`cargo flamegraph` reached the sampling phase and failed with:

```text
Access to performance monitoring and observability operations is limited.
perf_event_paranoid setting is 4
failed to sample program, exited with code: Some(255)
```

The run also warned that bench debuginfo is disabled:

```text
profiling without debuginfo
```

## Next Profiler Lane

This bead should remain open until one of these is true:

1. A worker/profile environment with `perf_event_paranoid <= 1` or `CAP_PERFMON` is available.
2. A non-perf sampler such as `samply` is installed and can profile the workload.
3. The benchmark is run under an approved profiling profile with debug symbols enabled, for example `CARGO_PROFILE_BENCH_DEBUG=true`.

No optimization should land from this artifact alone because it contains blocker evidence, not ranked hot-path evidence.
