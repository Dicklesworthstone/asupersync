# Performance And Scheduling Mental Model

Treat Asupersync as a runtime you can reason about, not a black-box executor.

The highest leverage performance gains usually come from making your workload
cooperate with the runtime model:

- lane-aware scheduling,
- structured ownership,
- bounded cancellation pressure,
- low-contention state design,
- explicit blocking boundaries.

## The Core Scheduler Model

The runtime uses a three-lane scheduler:

- cancel lane
- timed lane
- ready lane

Priority is explicit:

- cancel work outranks timed work,
- timed work outranks ordinary ready work,
- fairness is bounded rather than wishful.

What this means for downstream code:

- cancellation-heavy systems can remain responsive if code checkpoints and
  cleanup is bounded,
- deadline-driven work benefits from explicit time/budget discipline,
- "ready" work should not assume it can monopolize the worker.

## What Cooperates With The Runtime

Good performance/correctness shapes:

- long loops call `cx.checkpoint()`
- CPU-heavy loops chunk work into bounded pieces
- blocking work is isolated to blocking pools or other explicit boundaries
- `!Send` local tasks stay truly local and short
- speculative or hedged branches get tight budgets
- hot shared state is sharded or single-owned instead of globally locked

Good question to ask:

- if this task were cancelled or deprioritized here, would it release pressure
  quickly and predictably?

## What Fights The Runtime

Bad shapes:

- huge compute loops with no checkpoints
- wide masked sections
- many tiny tasks contending on one hot global mutex
- open-coded fire-and-forget background work
- blocking syscalls in core async paths
- treating cancellation as rare and therefore not performance-sensitive

These problems show up as fairness drift, deadline misses, lock contention,
stalled drains, and bad shutdown tails.

## Runtime Presets Are Architectural Choices

Choose the starting preset based on workload:

| Workload | Good Starting Point |
|---------|---------------------|
| CLI, simple daemon, deterministic-first app | `RuntimeBuilder::current_thread()` |
| request/response service | `RuntimeBuilder::low_latency()` |
| queue-heavy or throughput-heavy service | `RuntimeBuilder::high_throughput()` |

Then tune only if measurements justify it.

The repo already exposes knobs for:

- worker and blocking pool sizing
- poll budget / scheduling batch controls
- cancel-streak behavior and adaptive governance
- root-region limits
- deadline monitoring
- logical clock mode
- observability and leak response

Use those knobs after you understand the workload shape, not before.

## Locking And Sharded State

Asupersync's own runtime state is sharded for a reason. Copy that lesson.

Canonical shard order in the runtime:

- `E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations)`

What downstream integrators should learn from that:

- separate hot-path mutation domains when possible,
- keep lock acquisition order deterministic when multiple locks are needed,
- do not introduce a "god mutex" around unrelated state,
- use `ContendedMutex` where you need evidence about wait/hold time.

If you must lock multiple structures, define an order and document it.

## Locality Matters

The runtime distinguishes local `!Send` work and stealable `Send` work.

Downstream implication:

- pin truly local stateful work to a local owner when that helps locality,
- do not force everything into cross-worker sharing,
- do not create fake locality for work that is actually parallel and migratable.

The point is to align ownership and movement cost.

## Cancellation Pressure Is Part Of Performance

Asupersync treats cancellation/drain as hot-path behavior, not rare cleanup.

Practical implications:

- short cleanup paths matter for tail latency,
- loser-drain semantics in races are not optional bookkeeping,
- supervision and shutdown behavior affect scheduler pressure directly,
- speculative work should be budgeted so cancel storms remain bounded.

If shutdown or fail-fast is important in your service, benchmark and test the
drain path, not only the success path.

## Blocking Pool Discipline

Use explicit blocking boundaries for:

- file-heavy native work
- legacy drivers
- CPU-bound sync libraries
- niche system integration that is not yet exposed natively

Rules:

- keep the blocking surface narrow,
- own the handoff explicitly,
- measure whether blocking threads expand or retire sensibly,
- do not casually let blocking work seep into request code.

## Diagnostics To Use While Tuning

High-value operator surfaces:

- deadline monitor
- `TaskInspector`
- blocked-task explanations
- obligation leak diagnostics
- lock metrics via `ContendedMutex`
- progress certificates and drain phase labels
- fairness counters such as yield/cancel streak telemetry

Use these before guessing.

## Tuning Strategy

1. Pick the right ownership model.
2. Remove hot shared-state bottlenecks.
3. Add checkpoints and bound cleanup.
4. Isolate blocking work.
5. Only then tune runtime knobs.

If the architecture is wrong, builder tuning will not save it.

## Practical Workload Heuristics

### HTTP/gRPC server

- prefer `low_latency()`
- keep request handlers narrow-capability and short
- push long-lived subsystems into `AppSpec` or actors
- use `ServiceBuilder` for request-path backpressure instead of bespoke control

### Queue/worker pipeline

- prefer `high_throughput()`
- batch where possible
- use `bulkhead`, `rate_limit`, and pools explicitly
- keep cancellation checkpoints in long loops

### Deterministic test or forensic harness

- prefer `current_thread()` or `LabRuntime`
- turn on strict diagnostics
- make trace/replay artifacts part of normal investigation

## Anti-Patterns

- tuning cancel streaks before adding checkpoints
- creating thousands of tiny tasks around one global lock
- running CPU-bound code inline because "it is still async"
- using masked sections to suppress cancellation churn instead of fixing cleanup
- treating fairness issues as mysterious when counters and diagnostics exist

## Read Next

- `RUNTIME-CONTROLS.md`
- `OBSERVABILITY-FORENSICS.md`
- `TESTING-FORENSICS.md`
- `PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md`
