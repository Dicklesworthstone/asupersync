# Safe queue experiment and terminal decision

<!-- BEGIN CROSSBEAM QUEUE SAFE EXPERIMENT -->

This is the operator-readable companion to
`artifacts/crossbeam_queue_safe_experiment_v1.json` for
`asupersync-0h6myr.2` and `CAP-CONCURRENT-QUEUES`.

The terminal decision is `KEEP_INCUMBENT`. The experiment changes no queue
behavior, does not remove `crossbeam-queue`, and does not authorize a cutover
bead. It corrects the exporter benchmark to compare the safe mutex-backed
prototype with the actual production `BoundedExportQueue`, and it removes
fixed-rate wording that the repository had not proved.

## Claim-time surface correction

The bead's original description included `channel/mpsc` as an `ArrayQueue`
surface. Current source does not. That channel uses
`parking_lot::Mutex<ChannelInner<T>>` with `VecDeque<T>` and explains why queue,
reserved capacity, waiter removal, commit, cancellation, and wake state must
linearize together. It is therefore excluded rather than counted as a
crossbeam surface.

Five production modules directly use the dependency:

| Surface | Primitive | Current role |
| --- | --- | --- |
| scheduler global FIFO | `SegQueue` | native unbounded MPMC FIFO; wasm already uses a mutexed `VecDeque` |
| blocking pool | `SegQueue` | global and cohort task queues |
| epoch GC | `SegQueue` | deferred cleanup work |
| epoch tracking | `SegQueue` | deferred cleanup entries |
| OTLP exporter | `ArrayQueue` | bounded FIFO with atomic drop-oldest replacement |

## Why the old benchmark was not gate evidence

The committed benchmark claimed its purpose was to verify a fixed `10x+`
improvement, but it did not instantiate the production queue. It carried a
hand-written approximation with a manual pop/push overflow path and a separate
length counter, while production now uses `ArrayQueue::force_push`. It also
increased total work with producer count.

A clean-`HEAD` replay completed successfully, but the approximation was slower
than the mutex at every 1/2/4/8/16-producer cell. That contradicts the old
unqualified purpose statement; it says nothing reliable about the current
production queue.

## Corrected method

The corrected benchmark uses:

- the public production `BoundedExportQueue`;
- a safe `parking_lot::Mutex<VecDeque<T>>` prototype;
- capacity 1,000 and identical drop-oldest/FIFO operations;
- 65,536 total enqueues per cell, independent of producer count;
- a 64-byte payload and one dequeue attempt per ten enqueues;
- 1, 8, 32, and 64 producer threads;
- Criterion's configured ten-sample run.

The timed region includes queue construction, payload allocation, and producer
thread spawn/join as well as queue operations. The comparison is therefore a
synthetic production-queue contention workload, neither a pure queue
operation-cost measurement nor an end-to-end exporter service run.

The RCH worker had 16 logical CPUs / 8 physical cores on one AMD Ryzen 7 5800X
socket, one NUMA node, 65,729,736 KiB of memory, Linux
6.17.0-8-generic, and rustc 1.99.0-nightly
(`dc3f85158`, LLVM 22.1.8). The 32- and 64-producer rows are oversubscribed;
they are not 32- or 64-core claims.

| Producers | Safe 95% time interval | Incumbent 95% time interval | Safe point-time delta | Candidate result |
| ---: | ---: | ---: | ---: | --- |
| 1 | 0.839-0.868 ms | 0.841-0.855 ms | +0.58% | interval-overlap tie |
| 8 | 5.269-5.315 ms | 5.789-5.819 ms | -8.70% | win |
| 32 | 7.635-8.112 ms | 6.415-8.140 ms | +8.62% | interval-overlap tie |
| 64 | 9.186-9.606 ms | 6.658-8.455 ms | +24.64% | regression |

These are Criterion whole-workload slope estimates. Lower time is better; the
point delta is `(safe / incumbent - 1)`. They are not per-operation latency
quantiles.

## Result and stop rule

The machine artifact records the final estimate intervals. The decisive
`OTLP-64-PRODUCERS` row has the safe prototype's entire 95% time interval above
the incumbent's entire interval. Because the gate requires the safe candidate
to win or tie every required axis, one separated regression makes the candidate
ineligible. Continuing the expensive scheduler, channel-tail, allocation,
residency, Apple Silicon, and physical 32/64-core matrix cannot turn this
candidate into a passing cutover.

This is a terminal `KEEP`, not a claim that the incumbent wins every workload.
The safe prototype was competitive in lower producer-count cells, which is
useful evidence for a future differently scoped design, but it does not
override the failed conjunctive gate.

## Focused verification

Use clean-overlay remote compilation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path .gitignore \
  --overlay-path src/observability/otlp_trace_exporter.rs \
  --overlay-path benches/otlp_queue_contention.rs \
  --overlay-path artifacts/crossbeam_queue_safe_experiment_v1.json \
  --overlay-path docs/crossbeam_queue_safe_experiment.md \
  --overlay-path tests/crossbeam_queue_safe_experiment_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_crossbeam_queue_safe_contract" \
  cargo test -p asupersync \
  --test crossbeam_queue_safe_experiment_contract -- --nocapture
```

No local Cargo fallback is approved.

## No-claim boundary

This experiment does not prove p50/p95/p99/p999 operation latency, fairness,
starvation, cancellation or shutdown latency, allocation count, RSS, physical
32/64-core scaling, Apple Silicon performance, scheduler/blocking-pool/epoch
performance, broad workspace health, release readiness, or general
no-regression. It authorizes no dependency removal, queue cutover, new unsafe
code, hand-written lock-free primitive, deletion, destructive cleanup, peer
build cancellation, branch, or worktree.

<!-- END CROSSBEAM QUEUE SAFE EXPERIMENT -->
