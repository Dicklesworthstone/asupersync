# Observability And Failure Forensics

Asupersync's operator story is stronger than "export a few traces." Use it.

## Table of Contents

- [Three Layers To Understand](#three-layers-to-understand)
- [Runtime Observability Support Classes](#runtime-observability-support-classes)
- [Current Owned OTLP Mapping And Transport Boundary](#current-owned-otlp-mapping-and-transport-boundary)
- [Runtime Observability Surfaces](#runtime-observability-surfaces)
- [Progress Certificates And Drain Phases](#progress-certificates-and-drain-phases)
- [Task And Wait-Graph Diagnostics](#task-and-wait-graph-diagnostics)
- [Futurelock, Crashpacks, And Replay](#futurelock-crashpacks-and-replay)
- [Evidence Ledger](#evidence-ledger)
- [Practical Posture](#practical-posture)

## Three Layers To Understand

| Layer | Purpose |
|-------|---------|
| trace / replay | deterministic event history and replay artifacts |
| observability | structured logs, metrics, task and resource views |
| diagnostics | human-readable explanations for blocked, leaked, or cancelled work |

Do not collapse these into one vague "logging" concept.

## Runtime Observability Support Classes

Do not describe every observability type as one uniformly available production
export stack:

| Support class | Available surface | Boundary |
|---------------|-------------------|----------|
| always-on core | `LogEntry`, `LogCollector`, in-process `Metrics` / `NoOpMetrics`, `TaskInspector`, `Diagnostics`, cancellation and spectral-health diagnostics | Structured capture and inspection; no claim of external collector delivery |
| `metrics` feature | `observability::otel` SDK bridges, validated OTLP HTTP configuration/export, and finite owned metrics, trace, and log mapping | Native-only feature-gated integration; verify the chosen signal, transport, and collector lane |
| `tracing-integration` feature | `tracing` compatibility and span/log integration | Optional compatibility layer; disabled paths compile to no-op shims |
| explicit unsupported boundary | OTLP tail-based sampling reports `OtlpTailSamplingSupportClass::ExplicitlyUnsupported` | No production deferred trace-completion sampler yet |
| test-only harness | `OtelTransportMode`, `OtelExporterConfig`, and `OtelMetricsExporter` inside `src/observability/metrics.rs`'s `#[cfg(test)]` module | Deterministic capture/failure simulation only; not downstream configuration or evidence of network delivery |

The similarly named production exporters live under feature-gated
`src/observability/otel.rs`; never teach the test-only `OtelTransportMode` as a
public transport selector.

### Current Owned OTLP Mapping And Transport Boundary

Published v0.4.9 has an additive native OTLP path re-exported only under
`cfg(all(feature = "metrics", not(target_arch = "wasm32")))`:

- `OtlpHttpConfigBuilder::build` produces an immutable validated
  `OtlpHttpConfig`; endpoint, retry, TLS, authentication-header, and resource
  limits fail closed through stable `OtlpConfigError` codes, without ambient
  environment reads inside core configuration;
- authentication values and endpoint path/query material are redacted from
  `Debug`, authenticated endpoints require HTTPS, and the HTTP transport never
  follows redirects or uses a cookie store;
- `OwnedOtlpMetrics` implements the runtime `MetricsProvider` and emits bounded
  cumulative metrics batches with explicit timestamps and reset epochs;
- `OwnedOtlpTraces` validates borrowed span/event/link collections, lineage,
  identifiers, timestamps, attributes, and byte budgets before cloning or
  sending; and
- `OwnedOtlpLogs` does the same for finite structured log bodies and batches.

`OtlpHttpExporter::{send_owned_metrics, send_owned_traces, send_owned_logs}`
validates and encodes each complete collection before the first write, sends
requests sequentially inside the caller's `Cx`, and does not create a detached
exporter task. These capabilities ship in v0.4.9. The owned protobuf encoder is
crate-private; downstream consumers use the higher-level owned types. The owned
trace lineage guarantee is local parentage within one trace; links do not
establish arbitrary cross-trace structured-concurrency lineage.

Keep the evidence boundary exact. The ordinary executable integration lane
uses a handwritten loopback HTTP listener and independently decodes the wire
bytes. A pinned official OpenTelemetry Collector fixture exists, sends all
three owned signals, and reads the Collector's file output, but its test is
explicitly `#[ignore]` because it downloads and runs an external service.
Therefore only terminal output from the exact `metrics,test-internals` focused
cases proves mapper, limit, and loopback-wire behavior; default workspace totals
may compile the file while executing none of those feature-gated cases. The
focused cases still do not prove that the official Collector test actually ran.
Cite collector acceptance only with terminal output from that explicit
ignored-test lane.

Tracker status is also scoped: the A2-A5 configuration, owned metrics, owned
trace, and owned log tranches ship in v0.4.9. A6-A11 remain open: response and
transport semantics; queue/retry/shutdown; shared privacy/cardinality policy;
the multi-signal failure/fuzz matrix; aggregate dependency/no-Tokio and
cutover-or-keep signoff; and maintained official SDK/provider ecosystem
coverage. Do not turn the configuration plus three owned-signal tranche
closures into a claim that the entire OTLP program is complete. Re-check the
live Beads graph and release tag before repeating this status later.

## Runtime Observability Surfaces

High-value user-facing surfaces include:

- `ObservabilityConfig`
- `LogCollector`
- in-process metrics plus feature-gated exporter / OTLP integration
- `TaskInspector`
- `Diagnostics`
- `CancellationExplanation`
- `TaskBlockedExplanation`
- `ObligationLeak`

Use them when the question is "what is the system doing right now?" rather than
"can I replay this exact failure?"

Relevant paths:

- `src/observability/mod.rs`
- `src/observability/diagnostics.rs`
- `src/observability/task_inspector.rs`

## Progress Certificates And Drain Phases

Asupersync does not reduce shutdown to "wait and hope."

The runtime tracks cancellation drain progress (`ProgressCertificate`) with
explicit phase labels:

- `warmup`
- `rapid_drain`
- `slow_tail`
- `stalled`
- `quiescent`

Use this to distinguish:

- expected cleanup tail,
- true shutdown wedge,
- causal chain depth problems,
- resource/obligation leaks.

Read the certificate's claims carefully (wording changed in the v0.4.x line):

- The selected public concentration envelope equals the Azuma candidate; at the
  current same-history horizon both candidate tails are algebraically `1` and
  are NOT evidence of convergence.
- `converging` is a separate empirical status over the complete accepted finite
  non-negative observation history — not a future-drift, termination, or
  probability guarantee.
- Incomplete or invalid telemetry fails closed: the remaining-step estimate is
  suppressed and the phase reports `warmup` until reset.

Relevant paths:

- `README.md` ("Range-Bounded Drain Certificates")
- `src/cancel/progress_certificate.rs`

## Task And Wait-Graph Diagnostics

Before adding more logs, ask the runtime:

- which task is blocked,
- what it is waiting on,
- which obligations it still holds,
- whether cancellation has propagated,
- whether the wait graph is degrading structurally.

This is what `TaskInspector`, `TaskBlockedExplanation`, `CancellationExplanation`,
and spectral health diagnostics are for. Spectral early-warning severity is a
`none / watch / warning / critical` ladder over wait-graph connectivity trends.

Relevant paths:

- `src/observability/task_inspector.rs`
- `src/observability/diagnostics.rs`
- `src/observability/spectral_health.rs`

## Futurelock, Crashpacks, And Replay

Use this when a concurrency failure matters:

1. keep the seed,
2. keep the trace fingerprint,
3. keep the crashpack / replay pointer,
4. keep the oracle failures,
5. keep the reproduction command.

This turns "it wedged once in CI" into a reusable debugging asset.

Relevant paths:

- `src/lab/runtime.rs`
- `src/trace/crashpack.rs`
- `TESTING.md` / `TESTING_FOR_AGENTS.md`

## Evidence Ledger

Some failures are subtle enough that raw traces are not enough. Asupersync can
also produce structured evidence-ledger output for invariant failures.

Use it when:

- the failure is probabilistic-looking but deterministic under replay,
- there are competing explanations for a leak or stall,
- you need machine- and human-readable justification for why the runtime thinks an invariant failed.

Relevant path:

- `src/lab/oracle/evidence.rs`

## Practical Posture

For a serious service:

- enable structured observability,
- preserve replay artifacts for concurrency failures,
- use task inspector and diagnostics before speculative debug printing,
- use progress certificates to interpret drain behavior,
- treat futurelock and obligation-leak signals as design bugs, not random noise.
