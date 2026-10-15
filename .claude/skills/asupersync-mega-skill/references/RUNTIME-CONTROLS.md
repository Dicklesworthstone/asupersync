# Runtime Controls That Actually Matter

Asupersync exposes runtime controls that are worth using on purpose. Do not leave them as mysterious defaults if the workload is serious.

## Table of Contents

- [Pick A Runtime Shape Intentionally](#pick-a-runtime-shape-intentionally)
- [The Knobs Worth Learning](#the-knobs-worth-learning)
- [Mint Production Request Contexts](#mint-production-request-contexts)
- [Wire A Caller-Owned Blocking Pool In Embedders](#wire-a-caller-owned-blocking-pool-in-embedders)
- [Enter The Owning Worker For Local Tasks](#enter-the-owning-worker-for-local-tasks)
- [Bounded Teardown And Checked Runtime Tasks](#bounded-teardown-and-checked-runtime-tasks)
- [Ambient `Cx` Guard Discipline](#ambient-cx-guard-discipline)
- [Runtime Control Guidance](#runtime-control-guidance)
- [Configuration Layering](#configuration-layering)
- [Tuning Rules](#tuning-rules)
- [Diagnostics Surfaces](#diagnostics-surfaces)
- [Practical Operator Posture](#practical-operator-posture)
- [Source Map](#source-map)

## Pick A Runtime Shape Intentionally

Use the preset that matches the workload, then tune from there:

- `RuntimeBuilder::current_thread()`
  Good for CLI tools, single-tenant workers, test harnesses, and simple services where determinism and simplicity matter more than throughput.
- `RuntimeBuilder::multi_thread()`
  The plain default: deterministic, host-independent worker count (4). Use `ambient_default_worker_threads()` explicitly if you want host-scaled parallelism.
- `RuntimeBuilder::low_latency()`
  Good for request/response APIs, latency-sensitive gateways, and systems where deadline responsiveness matters (steal batch 4, poll budget 32).
- `RuntimeBuilder::high_throughput()`
  Good for queue-heavy servers, fan-out workers, and high-concurrency services that benefit from more batching (2x default workers, steal batch 32).

Do not start from `high_throughput()` just because it sounds bigger. Tail behavior and shutdown behavior matter more than peak throughput in many systems.

## The Knobs Worth Learning

| Goal | Knobs | Advice |
|------|-------|--------|
| Bound sync bridges and blocking work | `blocking_threads(min, max)`, `blocking_affinity_profile(...)` | Essential when SQLite, filesystem, process, or legacy sync code is in the stack. |
| Tune cooperative scheduling | `poll_budget(...)`, `steal_batch_size(...)` | Change only after measurement; these affect fairness and latency. |
| Improve shutdown/cancel-heavy behavior | `cancel_lane_max_streak(...)`, `enable_adaptive_cancel_streak(...)` (default on), `adaptive_cancel_streak_epoch_steps(...)`, `enable_governor(...)`, `governor_interval(...)` | Worth using when cancellations are frequent or cleanup pressure is high. |
| Reduce state-lock contention | `with_sharded_state(true)` | Opt-in sharded backing state (default stays `Unified`); dispatch runs on shard A and obligations resolve on shard C. |
| Route spawns off the state lock | `spawn_admission(SpawnAdmissionMode::Mailbox)` | Lock-free spawn mailbox; default is `Direct` (synchronous under the state lock). |
| Topology-aware steal ordering | `worker_cohorts(...)`, `scheduler_placement_mode(...)` | Deterministic cohort-first victim ordering (`LocalityFirst`/`LatencyFirst`/`ThroughputFirst`); no host probing — you supply the mapping. |
| Pre-size and tier runtime memory | `capacity_hints(...)`, `expected_concurrent_tasks(...)`, `arena_temperature_policy(...)`, `trace_storage_profile(...)` | Deterministic capacity/memory-tier policies; policy-only, no scheduling-semantics change. |
| Bound root-level fan-out | `root_region_limits(...)` | Use for admission control on the app root; do not confuse this with per-handler concurrency limits. |
| Attach logs and metrics | `observability(...)`, `metrics(...)` | Treat these as first-class runtime wiring, not an afterthought. |
| Install a wall-clock timer driver explicitly | `enable_time()` | Discoverable migration aid; `build()` already installs the default driver, but this is useful when fixing no-driver sleep fallbacks. |
| Detect deadline trouble early | `deadline_monitoring(...)` | Especially valuable for APIs, pipelines, and long-running workflows. |
| Preserve causal context in traces | `logical_clock_mode(...)` | Useful when work crosses regions, nodes, or replay/debug boundaries. |
| Keep cancel provenance bounded | `cancel_attribution_config(...)` | Important in deep call graphs or high fan-out cancellation trees. |
| Decide how hard leaks should fail | `obligation_leak_response(...)` | Prefer explicit policy over accidental silence. |

## Mint Production Request Contexts

Use `Runtime::request_cx_with_budget(budget)` when the owner of the runtime
starts a request or operation. Published v0.4.9 also provides the additive
`RuntimeHandle::request_cx_with_budget(budget)` and
`RuntimeHandle::try_request_cx_with_budget(budget)` paths for components that
hold only a cloned handle. The fallible handle method returns
`SpawnError::RuntimeUnavailable` if a weak handle outlives the runtime; the
infallible wrapper panics in that case.

These APIs mint a runtime-backed `Cx` with the configured budget, root region,
drivers, entropy, tracing, spawn gateway, and pending-spawn accounting. Do not
replace them with `Cx::for_testing()` / `Cx::for_request()`, or with a helper
task spawned only to obtain `Cx::current()`. Downstream projects need v0.4.9 or
a source revision containing commit `04a4914af` for the handle-scoped methods.

## Wire A Caller-Owned Blocking Pool In Embedders

A host that polls Asupersync futures without owning a complete `Runtime` can
still provide bounded blocking execution in v0.4.9:

```rust
let cx = cx.with_blocking_pool_handle(Some(pool.handle()));
let _guard = cx.set_current();
```

`Cx::with_blocking_pool_handle` is a consuming, additive wiring method. The
caller must already own a public `BlockingPoolHandle`; passing `None` detaches
an existing handle. Once installed, ambient and `Cx` blocking calls dispatch
through that pool. Without a carried pool, both forms run the closure inline on
the polling thread; only free `runtime::spawn_blocking` with no ambient `Cx`
uses the bounded dedicated-thread fallback. The method does not install a
scheduler, create a runtime, or make `spawn_local` available. Downstream code
needs v0.4.9 or a source revision containing commit `a4b16b4e0` before using it.

## Enter The Owning Worker For Local Tasks

`Cx::spawn_local` requires the worker-local lane owned by the same runtime. A
direct `Runtime::block_on`, an entry-macro body, `run_test`, or
`run_test_with_cx` does not by itself install that lane; attempting local spawn
there can return `SpawnError::LocalSchedulerUnavailable` (ASUP-E004). Attaching
a blocking-pool handle does not change this.

For a `!Send` local-task test or embedder path, enter a real scheduler worker
through `runtime.block_on(runtime.handle().spawn(async { ... }))`, obtain
`Cx::current()` inside that worker future, and call `spawn_local` there. Create
the non-`Send` guard or state inside the local future rather than moving it
through the outer `Send` worker future. In cancellation regressions, use a
oneshot/atomic witness to prove the local task reached the intended parked state
before aborting it, then assert both the exact join result and cleanup state.
Do not substitute `LabRuntime` when the reported contract is native worker
wakeup or abort delivery.

## Bounded Teardown And Checked Runtime Tasks

Use structured application shutdown first:

1. stop external admissions,
2. request cancellation and join owned regions/tasks,
3. drain protocol and cleanup obligations,
4. consume the runtime with `shutdown_timeout(bound)` as the final liveness fuse.

Calling `shutdown_timeout` (and therefore zero-bound `shutdown_background`)
synchronously closes every runtime-owned spawn gateway and blocking-pool
admission. Fallible spawn methods on retained `RuntimeHandle`s and runtime-backed
`Cx`s then reject new task, blocking, and local-task spawns with
`SpawnError::RuntimeUnavailable`; the established convenience wrappers retain
their documented panic/`None` behavior, and a retained blocking-pool
handle returns a cancelled task. An already-admitted spawn publication may
finish before scheduler shutdown is signalled. These internal gates do not stop
external listener/service admission, which is why step 1 remains
application-owned.

`Runtime::shutdown_timeout` returns `true` only when final teardown completes
within the bound. `false` means the bound expired or detached-reaper creation
failed; runtime state may remain alive, potentially until process exit, but its
runtime-owned admissions remain closed. It does not force-kill a thread or a
future that illegally blocks inside `poll`.
`shutdown_background` performs no wait and is for explicitly accepted
process-liveness tradeoffs, not normal graceful shutdown.

For runtime-level task observation:

- `try_spawn_checked` returns admission failure instead of panicking and yields
  `CheckedJoinHandle<T>` with `Result<T, JoinError>` output,
- `spawn_checked` has the same typed join but panics if admission is unavailable,
- legacy `RuntimeHandle::spawn` / `JoinHandle<T>` remains functional with its
  established v0.4.3 panic-propagating output,
- region-owned application tasks should still prefer `Cx::spawn` and
  `TaskHandle::join(&Cx)`.

## Ambient `Cx` Guard Discipline

Prefer explicit `&Cx` propagation. `CurrentCxGuard` owns a thread-local ambient
frame and deliberately remains `!Send`; do not hold it across a migration point
or move it to another thread. v0.4.8 made same-thread out-of-order teardown
identity-safe: each guard removes the exact frame it installed rather than
blindly popping the current top. That repair prevents nested capability
restrictions from being removed by the wrong guard; it does not turn ambient
context into cross-thread authority.

## Runtime Control Guidance

### Deadline Monitoring

Use `deadline_monitoring(...)` for services where "stuck but not dead" is a real failure mode.

High-value facts from the repo:

- Warnings are logical-time aware and still work when logical time stalls.
- Warnings are deduplicated per task until removal.
- The warning can include the most recent checkpoint message.

Practical advice:

- add meaningful checkpoint messages in long phases,
- enable deadline monitoring for operator-facing services,
- treat repeated warnings as a design signal, not just a log event.

### Logical Clock Mode

Use logical clocks when causal ordering matters in traces or distributed workflows.

- Keep the default posture for simple single-node systems.
- Reach for explicit logical clock configuration when correlating work across nodes, regions, or replay artifacts.
- If the project already uses distributed tracing or cross-node replay, choose the mode deliberately instead of inheriting whatever default happens to exist.

Relevant sources:

- `src/runtime/builder.rs`
- `src/runtime/config.rs`
- `src/trace/distributed/vclock.rs`

### Cancel Attribution

`CancelAttributionConfig` exists because deep cause chains are useful until they become an unbounded memory tax.

Use it when:

- cancellation crosses many layers,
- you need root-cause lineage in diagnostics,
- you expect fan-out trees or cascading shutdowns.

Practical rule:

- preserve enough cause depth to debug,
- cap it aggressively enough that cancellation storms stay cheap,
- document truncation expectations in operational runbooks.

### Root Region Limits

`root_region_limits(...)` is an architectural guardrail, not just a tuning footnote.

Use it for:

- multi-tenant runtimes,
- agent platforms,
- server processes that should not admit unbounded child regions,
- anything with user-controlled fan-out.

Do not use it as a substitute for:

- service-layer rate limiting,
- queue-level backpressure,
- handler-local concurrency isolation.

Those belong in `service::*`, combinators like `bulkhead`, or explicit application policy.

### Leak Policy

Asupersync makes leak handling explicit via `ObligationLeakResponse`.

Use a deliberate policy (the shipped default is `Panic` — "no obligation
leaks" is a fail-fast runtime invariant; tests/labs opt into softer modes):

- `Panic` (default) fails fast with diagnostic details.
- `Log` is a practical production starting point when crashing is unacceptable.
- `Recover` aborts the leaked obligation (best-effort cleanup) and continues.
- `Silent` should be rare and intentional.

The repo also supports threshold-based escalation via `LeakEscalation` in runtime config. Use that when you want "warn first, then hard-fail if it repeats."

## Configuration Layering

Asupersync already supports configuration precedence. Use it.

Recommended pattern:

1. Put stable environment-independent defaults in code.
2. Load TOML when the deployment benefits from explicit ops-managed config.
3. Apply env overrides for 12-factor deployment.
4. Keep programmatic overrides for the final, highest-priority decisions.

Relevant APIs:

- `RuntimeBuilder::from_toml(...)` / `from_toml_str(...)` and
  `from_json(...)` / `from_json_str(...)` (a versioned JSON envelope over the
  same typed scheduler/blocking layer) with the `config-file` feature
- `RuntimeBuilder::with_env_overrides()`

The current file-config schema carries scheduler and blocking-pool settings,
not credentials. Do not treat it as a secret store or infer a generic
secret-redaction guarantee from its canonical JSON encoder.

## Tuning Rules

- Change one scheduling knob at a time and measure.
- Pair tuning work with metrics or bench evidence.
- Do not disable adaptive cancel behavior without a measured reason (it is
  enabled by default at HEAD).
- Do not use `global_queue_limit` as fake task shedding. The runtime preserves ownership semantics; if you need real admission policy, build it at the service/app layer.
- Browser-specific knobs like `browser_ready_handoff_limit(...)` and worker offload belong only in the browser/wasm lane.

## Diagnostics Surfaces

Do not reduce observability to plain logs.

High-value surfaces:

- `ObservabilityConfig` for log/trace/metric policy
- `LogCollector` for structured entries
- metrics exporters including OTLP-capable paths
- `TaskInspector` for live blocked-state and held-obligation visibility
- `Diagnostics` for structured root-cause explanations
- `CancellationExplanation` for cancel lineage
- `TaskBlockedExplanation` for stalled-task diagnosis
- `ObligationLeak` for linear-resource failures
- spectral health diagnostics for wait-graph degradation
- `runtime::metrics::snapshot()` scheduler CPU/churn counters (feature
  `runtime-metrics`, off by default)
- runtime pressure evidence: `RuntimePressureSnapshot` / `RuntimePressureVerdict`
  from the resource monitor (`src/runtime/resource_monitor.rs`)
- opt-in memory-residency policy/accounting: schema-versioned recommendation
  and accounting snapshots (recommendation-only, mutates nothing; additive
  `/debug/memory-residency` debug endpoint) in `src/runtime/memory_residency.rs`

Relevant paths:

- `src/observability/mod.rs`
- `src/observability/diagnostics.rs`
- `src/observability/task_inspector.rs`
- `src/observability/spectral_health.rs`
- `src/runtime/resource_monitor.rs`
- `src/runtime/memory_residency.rs`

## Practical Operator Posture

- Enable structured observability from the start instead of backfilling string logs later.
- Use `deadline_monitoring(...)` plus meaningful checkpoint messages in long-running tasks.
- Reach for `TaskInspector` and structured diagnostics before adding speculative debug prints.
- Preserve seeds, trace fingerprints, and replay commands for concurrency failures.
- Choose logical clock mode deliberately before distributed rollout.
- Alert on `shutdown_timeout(false)`; never record it as successful cleanup.

## Source Map

- `src/runtime/builder.rs`
- `src/runtime/config.rs`
- `src/runtime/deadline_monitor.rs`
- `src/runtime/scheduler/three_lane.rs`
- `README.md`
