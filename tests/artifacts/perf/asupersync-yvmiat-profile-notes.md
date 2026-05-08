# asupersync-yvmiat Profiling Notes

## Intent

`asupersync-yvmiat` requires ranked profiling evidence before any scheduler/runtime optimization. The earlier bead text explicitly rejects code-inspection-only micro-optimizations unless a profile identifies a top-5 hotspot.

## Coordination State

- `asupersync-aj7lx3.5` was claimed by another agent, so this session stayed off that proof-status surface.
- `.beads/issues.jsonl` and `.beads/beads.db` were reserved by another agent during this preflight, so this session did not claim or update the tracker.
- Reserved by CopperSpring:
  - `tests/artifacts/perf/asupersync-yvmiat-hotspots.md`
  - `tests/artifacts/perf/asupersync-yvmiat-fingerprint.json`
  - `tests/artifacts/perf/asupersync-yvmiat-profile-notes.md`
  - `artifacts/flamegraphs/main-asupersync-yvmiat.svg`

## Tool Availability

- `samply`: missing locally.
- `cargo-flamegraph`: available locally.
- `perf`: available locally.
- `rch`: available, status degraded but with healthy workers and an empty queue before the run.

## Remote Flamegraph Attempt

Command:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_yvmiat_flame cargo flamegraph --package asupersync --bench scheduler_benchmark --features test-internals -o artifacts/flamegraphs/main-asupersync-yvmiat.svg -- scheduler/global_ready_contention
```

Outcome:

- Remote worker: `vmi1153651`
- Build result: benchmark profile finished building in 4m27s.
- Sampling result: failed before samples were collected.
- Output artifact: `artifacts/flamegraphs/main-asupersync-yvmiat.svg` was not created.

Relevant output:

```text
Finished `bench` profile [optimized] target(s) in 4m 27s

WARNING: profiling without debuginfo. Enable symbol information by adding the following lines to Cargo.toml:

[profile.bench]
debug = true

Or set this environment variable:

CARGO_PROFILE_BENCH_DEBUG=true

Missing support for build id in kernel mmap events.
Disable this warning with --no-buildid-mmap
Error:
Access to performance monitoring and observability operations is limited.
...
perf_event_paranoid setting is 4
...
failed to sample program, exited with code: Some(255)
```

## Decision

Do not optimize yet. The acceptance gate needs a real ranked hotspot table. This run only proves the current remote `perf` lane is blocked by profiler permissions and missing bench debuginfo.

## Concrete Unblock Options

1. Run the same command on a worker with `perf_event_paranoid <= 1` or `CAP_PERFMON`.
2. Install/use `samply` or another non-perf sampler that can run in the approved environment.
3. Add an approved profiling build profile or env override for debuginfo before rerunning:

```bash
CARGO_PROFILE_BENCH_DEBUG=true
```

Any future optimization closeout should cite a new artifact with at least five ranked rows, not this blocker note.
