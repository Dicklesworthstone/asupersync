# Runtime Controls That Actually Matter

Asupersync exposes runtime controls that are worth using on purpose. Do not leave them as mysterious defaults if the workload is serious.

## Pick A Runtime Shape Intentionally

Use the preset that matches the workload, then tune from there:

- `RuntimeBuilder::current_thread()`
  Good for CLI tools, single-tenant workers, test harnesses, and simple services where determinism and simplicity matter more than throughput.
- `RuntimeBuilder::low_latency()`
  Good for request/response APIs, latency-sensitive gateways, and systems where deadline responsiveness matters.
- `RuntimeBuilder::high_throughput()`
  Good for queue-heavy servers, fan-out workers, and high-concurrency services that benefit from more batching.

Do not start from `high_throughput()` just because it sounds bigger. Tail behavior and shutdown behavior matter more than peak throughput in many systems.

## The Knobs Worth Learning

| Goal | Knobs | Advice |
|------|-------|--------|
| Bound sync bridges and blocking work | `blocking_threads(min, max)` | Essential when SQLite, filesystem, process, or legacy sync code is in the stack. |
| Tune cooperative scheduling | `poll_budget(...)`, `steal_batch_size(...)` | Change only after measurement; these affect fairness and latency. |
| Improve shutdown/cancel-heavy behavior | `cancel_lane_max_streak(...)`, `enable_adaptive_cancel_streak(...)`, `enable_governor(...)`, `governor_interval(...)` | Worth using when cancellations are frequent or cleanup pressure is high. |
| Bound root-level fan-out | `root_region_limits(...)` | Use for admission control on the app root; do not confuse this with per-handler concurrency limits. |
| Attach logs and metrics | `observability(...)`, `metrics(...)` | Treat these as first-class runtime wiring, not an afterthought. |
| Install a wall-clock timer driver explicitly | `enable_time()` | Discoverable migration aid; `build()` already installs the default driver, but this is useful when fixing no-driver sleep fallbacks. |
| Detect deadline trouble early | `deadline_monitoring(...)` | Especially valuable for APIs, pipelines, and long-running workflows. |
| Preserve causal context in traces | `logical_clock_mode(...)` | Useful when work crosses regions, nodes, or replay/debug boundaries. |
| Keep cancel provenance bounded | `cancel_attribution_config(...)` | Important in deep call graphs or high fan-out cancellation trees. |
| Decide how hard leaks should fail | `obligation_leak_response(...)` | Prefer explicit policy over accidental silence. |

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

Use a deliberate policy:

- `Log` is a practical production starting point.
- `Panic` is appropriate in lab/CI when leaks should fail fast.
- `Recover` is for cases where the runtime should abort the leaked obligation path and continue.
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

- `RuntimeBuilder::from_toml(...)` / `from_toml_str(...)` with the
  `config-file` feature
- `RuntimeBuilder::with_env_overrides()`

## Tuning Rules

- Change one scheduling knob at a time and measure.
- Pair tuning work with metrics or bench evidence.
- Do not disable adaptive cancel behavior without a measured reason.
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

Relevant paths:

- `src/observability/mod.rs`
- `src/observability/diagnostics.rs`
- `src/observability/task_inspector.rs`
- `src/observability/spectral_health.rs`

## Practical Operator Posture

- Enable structured observability from the start instead of backfilling string logs later.
- Use `deadline_monitoring(...)` plus meaningful checkpoint messages in long-running tasks.
- Reach for `TaskInspector` and structured diagnostics before adding speculative debug prints.
- Preserve seeds, trace fingerprints, and replay commands for concurrency failures.
- Choose logical clock mode deliberately before distributed rollout.

## Source Map

- `src/runtime/builder.rs`
- `src/runtime/config.rs`
- `src/runtime/deadline_monitor.rs`
- `src/runtime/scheduler/three_lane.rs`
- `README.md`
