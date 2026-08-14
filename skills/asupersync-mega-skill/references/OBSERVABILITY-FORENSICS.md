# Observability And Failure Forensics

Asupersync's operator story is stronger than "export a few traces." Use it.

## Three Layers To Understand

| Layer | Purpose |
|-------|---------|
| trace / replay | deterministic event history and replay artifacts |
| observability | structured logs, metrics, task and resource views |
| diagnostics | human-readable explanations for blocked, leaked, or cancelled work |

Do not collapse these into one vague "logging" concept.

## Runtime Observability Surfaces

High-value user-facing surfaces include:

- `ObservabilityConfig`
- `LogCollector`
- metrics exporters / OTLP integration
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
