# Per-structure cache alignment experiment

This runbook owns the evidence for `asupersync-0h6myr.6` and
`CAP-CACHE-LAYOUT`. The machine-readable authority is
`artifacts/cache_padded_alignment_experiment_v1.json`.

## Scope

The experiment compares 64-byte and 128-byte alignment for representative
access patterns. It does not change `CachePadded<T>`, any production structure,
or the public `CACHE_LINE_SIZE` constant. A result may recommend a
structure-specific follow-up bead, but it cannot authorize a global alignment
change.

The inventory covers:

- the two advisory counters in `GlobalFifoQueue`;
- the twelve independently padded fields in `ReadyCombiner`;
- the timed-lane counter/deadline pair in `GlobalInjector`;
- the `WorkerCoordinator` wake index;
- the eight `SpawnIdAllocator` shards;
- the per-thread pin vector in `SafePointDetector`;
- the sixteen submit/complete shards in `LabIoCap`; and
- the related manual 64-byte layout in contended-mutex metrics.

The last row is inventory-only because its private mixed atomic, mutex, vector,
and padding layout is not represented by the synthetic atomic-cell probe.

## Benchmark contract

`benches/lab_iocap_contention.rs` retains its production `LabIoCap` workloads
and adds a bounded receipt named `cache-alignment-bounded-v1`.

The independent-hot-counter workload represents per-worker or per-shard
writes. The snapshot-scan workload represents cold aggregation over padded
arrays. Each measured row records throughput, p50, p95, p99, p999, a
per-thread fairness ratio, entry count, worker count, and elapsed time.
Write percentiles are per-operation values normalized from fixed
256-operation chunks. Scan percentiles are per-entry values normalized from
one complete scan. Layout rows record the one-entry and 8/16/64-entry
footprints. Core counts beyond the admitted host's available parallelism are
explicit no-claims.

The default probe runs 65,536 operations per writer in 256-operation chunks
and caps scaling at 64 workers. `ASUP_CACHE_ALIGNMENT_OPS` may select a larger
bounded profile, but every receipt must record the actual value.

## Host and topology provenance

Every admitted platform row must record:

- remote worker identity;
- architecture and CPU vendor/model;
- online logical CPUs, cores, sockets, NUMA nodes, and any visible
  cluster/CCX topology;
- operating system and kernel;
- benchmark profile and source commit;
- process RSS when available; and
- cache-reference/cache-miss counters when the host permits them.

Unavailable counters are `NO_CLAIM`; permission failure is not a zero count.
An unexecuted Apple Silicon or second-x86-vendor cell remains an explicit
no-claim.

## Interpretation

The 128-byte cell doubles the footprint of each small padded atomic. A
throughput improvement on one host is insufficient by itself: tail latency,
fairness, core scaling, scan density, and memory cost must all be considered
for the exact structure.

Terminal outcomes are:

- `ADOPT_PER_STRUCTURE`: create a separate implementation bead naming the
  exact structure and rollback gate;
- `KEEP`: retain 64 bytes for the measured structures; or
- `DEFER`: evidence is incomplete or materially mixed.

There is no `ADOPT_GLOBAL` outcome.

## Recorded result

The admitted cell ran on RCH worker `hz1`: an 8-vCPU AMD EPYC-Milan VM with
4 cores/8 threads, one socket, one NUMA node, 32 MiB L3, roughly 30.6 GiB RAM,
and Linux 7.0.

The first bounded run was mixed: the 128-byte write cell ranged from 0.95x to
1.12x the 64-byte throughput at 1/2/4 workers, then fell to 0.51x at 8 workers.
The hardware-counter rerun did not reproduce that large drop; its 8-worker
ratio was 0.98x. Its scan ratios ranged from 0.92x to 1.01x. The counter run
recorded 37,051,507 cache references, 10,000,119 cache misses, and 19,900 KiB
maximum RSS. In every layout row, 128-byte cells used exactly twice the memory.

The terminal verdict is `DEFER`. The same-host max-core result is not stable
enough for adoption, and the Apple Silicon, second-x86-vendor, and 16/32/64-core
cells are unexecuted no-claims. No implementation bead is authorized.

## Verification

All Cargo commands are remote-only clean-overlay runs. The focused sequence is:

1. check and lint the existing `lab_iocap_contention` benchmark;
2. execute the bounded benchmark on each available admitted host;
3. validate the machine artifact with
   `cache_padded_alignment_experiment_contract`; and
4. run the repository all-target check and Clippy frontiers.

Formatting uses standalone `rustfmt`; JSON syntax uses `jq empty`; whitespace
uses `git diff --check`.

## Rollback and no-claim boundary

This bead adds evidence and benchmark instrumentation only. Rolling it back
means reverting those evidence surfaces; there is no production layout rollback.
The artifact does not prove broad workspace health, scheduler correctness,
release readiness, cache-miss improvement, Apple Silicon behavior, or a global
128-byte policy.
