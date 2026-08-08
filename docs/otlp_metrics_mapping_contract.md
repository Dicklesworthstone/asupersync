# OTLP metrics mapping contract

<!-- BEGIN OTLP METRICS MAPPING CONTRACT -->

Bead: `asupersync-5z2scg.2.3`

Canonical artifact: `artifacts/otlp_metrics_mapping_contract_v1.json`

Claim revision: `f3ccd58d8d9b740ad07b4f2197d56d70ad049125`

Status: static A3 contract authored; production adapter implementation,
executable contract validation, deterministic LabRuntime replay, and real
collector evidence remain pending (`UNRUN_STATIC_ONLY`). The bead stays open.

## Outcome

This tranche reviews three OTLP-relevant metrics surfaces that must not be
conflated:

1. `OtelMetrics` records 23 fixed runtime instruments into a caller-supplied
   OpenTelemetry `Meter`. The embedder's provider owns collection, aggregation,
   temporality, timestamps, histogram boundaries, exemplars, and export.
2. `Metrics` is the dependency-free dynamic registry. It retains counters,
   gauges, explicit-bound histograms, and bounded-sample summaries.
3. `otlp_proto` contains finite crate-private owned OTLP metric and collector
   messages. No production adapter currently connects either producer surface
   to those messages.

That list is not the complete repository-wide metrics census. The A3 artifact
freezes this reviewed subset, records each required future owned-adapter mapping,
and keeps unresolved producer limits and descriptor decisions as closure blockers.
Fields named `owned_*` are requirements, not descriptions of
the current external `MeterProvider` output or a complete adapter design.

This distinction corrects three overstatements in the earlier frozen inventory:

- production metrics are not Asupersync-enforced cumulative-only; only the
  test/fuzz generated-message builder hard-codes cumulative temporality;
- the standalone bounded snapshot queue drops the oldest batch, not the newest;
  and
- the cited A3 integration receipt is partial evidence, not proof of owned
  mapping, reset behavior, boundary cardinality, deterministic replay, or a
  real collector.

## Fixed `OtelMetrics` instrument census

`OtelMetrics` constructs exactly 23 instruments: three observable gauges,
13 counters, and seven histograms. None calls `with_unit`; every current
application-level descriptor unit is therefore empty even when its description
states that values are seconds.

| Instrument | Kind | Attributes | Sampling selector | Required owned data |
|---|---|---|---|---|
| `asupersync.tasks.active` | observable `u64` gauge | none | none | gauge integer |
| `asupersync.regions.active` | observable `u64` gauge | none | none | gauge integer |
| `asupersync.obligations.active` | observable `u64` gauge | none | none | gauge integer |
| `asupersync.tasks.spawned` | `u64` counter | none | none | cumulative monotonic sum |
| `asupersync.tasks.completed` | `u64` counter | `outcome` | none | cumulative monotonic sum |
| `asupersync.regions.created` | `u64` counter | none | none | cumulative monotonic sum |
| `asupersync.regions.closed` | `u64` counter | none | none | cumulative monotonic sum |
| `asupersync.cancellations` | `u64` counter | `kind` | none | cumulative monotonic sum |
| `asupersync.deadlines.set` | `u64` counter | none | none | cumulative monotonic sum |
| `asupersync.deadlines.exceeded` | `u64` counter | none | none | cumulative monotonic sum |
| `asupersync.deadline.warnings_total` | `u64` counter | `reason`, `task_type` | none | cumulative monotonic sum |
| `asupersync.deadline.violations_total` | `u64` counter | `task_type` | none | cumulative monotonic sum |
| `asupersync.task.stuck_detected_total` | `u64` counter | `task_type` | none | cumulative monotonic sum |
| `asupersync.obligations.created` | `u64` counter | none | none | cumulative monotonic sum |
| `asupersync.obligations.discharged` | `u64` counter | none | none | cumulative monotonic sum |
| `asupersync.obligations.leaked` | `u64` counter | none | none | cumulative monotonic sum |
| `asupersync.tasks.duration` | `f64` histogram | `outcome` | its own name | cumulative explicit histogram |
| `asupersync.regions.lifetime` | `f64` histogram | none | its own name | cumulative explicit histogram |
| `asupersync.cancellation.drain_duration` | `f64` histogram | none | its own name | cumulative explicit histogram |
| `asupersync.deadline.remaining_seconds` | `f64` histogram | `task_type` | its own name | cumulative explicit histogram |
| `asupersync.checkpoint.interval_seconds` | `f64` histogram | `task_type` | its own name | cumulative explicit histogram |
| `asupersync.scheduler.poll_time` | `f64` histogram | none | shared `asupersync.scheduler` | cumulative explicit histogram |
| `asupersync.scheduler.tasks_polled` | `f64` histogram | none | shared `asupersync.scheduler` | cumulative explicit histogram |

The exact descriptions, semantic units, callbacks, and mapping variants live in
the JSON artifact. Descriptions remain byte-for-byte incumbent values. An owned
parity cutover must emit an empty `Metric.unit`; introducing `s`, `1`, or
another nonempty unit is a deliberate descriptor version requiring separate
golden and collector evidence.

The explicit integration-test census currently names only the 20 synchronous
counters and histograms. The three observable gauges exist in the constructor
but are not named in that expected list.

`MetricsProvider::record_panic` is another retained callback but not one of the
23 instruments: `OtelMetrics` inherits the trait's no-op default. A3 cannot close
until a versioned counter mapping lands or the unsupported behavior is retained
explicitly.

## Additional retained surfaces still requiring census

The fixed 23-row table is complete only for `OtelMetrics`. It is not “every
metric in Asupersync.” At least three additional families remain:

- `runtime::metrics` exposes eight process-global monotonic counters plus the
  derived `active_timers` gauge under `runtime-metrics`; it also exposes a reset
  operation for the counters.
- The dynamic `Metrics` registry has in-tree producers including the pressure
  governor and RaptorQ pipeline. Representative names include
  `pressure_overall_scaled`, `pressure_governor_decision_latency_ns`,
  `swarm_coordination_latency_seconds`, `raptorq.symbols_sent`, and
  `raptorq.auth_rejected`.
- Direct `Counter`, `Gauge`, and `Histogram` users include the release-proof
  aggregator, ATP QUIC per-connection metrics, and network-truth metrics.

Those examples are deliberately not presented as exhaustive. Completing that
producer/name census and mapping its reset, dynamic-name, descriptor, and range
semantics is an A3 closure blocker.

## Dynamic registry mapping

The default-feature `Metrics` registry is also retained:

| Registry kind | Available fidelity | Required owned mapping | Current gap |
|---|---|---|---|
| Counter | exact `u64` value | cumulative monotonic `Sum` | owned integer is `i64`; epoch state is absent |
| Gauge | exact `i64` value | `Gauge` integer | adapter absent |
| Histogram | sorted bounds, per-bucket counts including `+Inf`, count, sum | cumulative explicit `Histogram` | public `MetricsSnapshot` drops bounds and bucket counts |
| Summary | exact count and sum; last 4,096 finite observations for quantiles | `Summary` | no snapshot row or canonical quantile set |

The registry defaults to 10,000 distinct names per kind. Zero means unlimited.
A fresh name beyond the cap is routed to
`asupersync_metric_cardinality_overflow`, and the rejection counter advances.
Because the sentinel is insertable in addition to the configured ordinary-name
budget, a capped map may contain the cap plus the sentinel.

## Required owned message shape

The future production route is:

```text
ExportMetricsServiceRequest
  -> ResourceMetrics
    -> ScopeMetrics
      -> Metric
        -> Gauge | Sum | Histogram | Summary
          -> bounded data points
```

Counters use `Sum`, `Cumulative`, `is_monotonic = true`, and an integer point.
Gauges use an integer point with no start timestamp. Histograms use cumulative
explicit buckets whose count vector has exactly one more item than the strictly
increasing bound vector and whose checked bucket sum equals `count`. The exact
bound vectors for the seven fixed histograms remain unselected. Summaries remain
blocked until the producer owns a canonical quantile set. Asupersync has no
explicit owned exemplar producer; the current embedder SDK may still attach
exemplars under its own provider policy. A future owned policy path leaves
exemplars, exponential histograms, and metric metadata empty until explicit
producers and policies land.

Descriptor identity is name, kind, description, and unit. Stream identity adds
the canonical post-filter attribute vector. One `Metric` groups the distinct
attribute-stream points for one descriptor. Empty names, duplicate exact
streams, same-name descriptor conflicts, and duplicate point identities are
refused before model construction. Coalescing is forbidden until an explicit
associative aggregation contract and goldens exist. Metrics are ordered by
descriptor identity and points by their canonical attribute vectors. No model
or wire bytes are returned when producer mapping fails.

## Temporality, timestamps, and reset

Current production policy is `EMBEDDER_OWNED_NOT_ENFORCED_BY_ASUPERSYNC`.
The required owned policy is cumulative-only for sums and histograms. Delta is
forbidden until previous-value state, reset detection, and dedicated goldens
exist.

Within one stream and attribute set:

- `time_unix_nano` is nonzero and never moves backwards;
- gauge `start_time_unix_nano` is absent;
- cumulative start time is one stable, nonzero accumulation-epoch timestamp;
- reset or aggregation-state recreation rotates that start time and restarts
  the cumulative value or every histogram field together; and
- reset is never represented as a negative delta.

The generated-message fixture does not prove that policy. It derives a fresh
start timestamp from every `batch_sequence`, presenting every changed sequence
as a new accumulation epoch. The existing monotonicity audit also misses two
numeric boundaries: `Counter::add` can wrap its `AtomicU64`, and the fixture's
`cast_signed()` produces a negative point above `i64::MAX`.

The owned adapter therefore refuses a counter or observable gauge above
`i64::MAX` before model construction. Wrapping and lossy floating-point
conversion are forbidden. It also refuses nonfinite observations, bounds, sums,
min/max, quantiles, and quantile values. Dynamic `Summary` accepts negative
finite observations while the owned Summary quantile model rejects negative
values, so that mapping remains blocked. Time and epoch authority must be
explicit inputs; synthetic batch arithmetic and an ambient wall clock are not
production authority.

## Attributes, cardinality, and sampling

The canonical operation order is filter, redact, sort, then construct the
model. Sorting uses UTF-8 key bytes followed by encoded value bytes. Duplicate
or empty keys are refused; empty string values are preserved unless the caller's
privacy policy explicitly removes the field.

Current fixed domains include `outcome`, `kind`, `task_type`, and `reason`.
`task_type` is restricted to 64 bytes and the documented safe character set;
invalid values become `<invalid>`. `reason` is a static string but still needs
the owned value-byte admission check.

`OtelMetrics` defaults are 1,000 label combinations per tracker-visible metric,
4,096 tracker-visible names, `Drop`, no dropped keys, and no sampling. Only the
eight label-bearing fixed call sites enter the tracker; the other 15 fixed
instruments do not consume name slots. Zero has intentionally different
meanings: `max_cardinality = 0` sends every fresh label set to overflow handling,
while `max_metrics = 0` disables the name limit. At zero cardinality, `Drop`
omits, `Aggregate` retries and is normally still refused, while `Warn` records
beyond the zero cap.

Overflow behavior is exact, including its shortcomings:

- `Drop` counts one overflow and omits the point.
- `Aggregate` changes every retained value to `other` and retries. Because the
  retry happens after the set is full, a new all-`other` series is normally
  refused. It succeeds only if that exact series was admitted earlier.
- `Warn` logs and records beyond both caps. This is explicitly unbounded and
  cannot be inherited by a bounded owned adapter.

Sampling uses one atomic 100-slot sequence shared across selected metrics. The
threshold is `floor(sample_rate * 100)`, giving one-percent downward
quantization. Selectors use substring matching; an empty selector list reaches
every sampled call. `NaN` survives the current clamp and casts to threshold zero;
owned mode must reject it at configuration time. Histogram sampling occurs
before sanitization and cardinality admission, so a sampled-out point consumes
no tracker slot. A completion counter can still advance while its duration
histogram is sampled out, and both scheduler histograms share one decision.
There is no reweighting. Concurrent callback order can change which observations
are retained, so deterministic replay remains an executable acceptance
requirement.

## Snapshot queue and finite limits

`MetricsSnapshot` has unbounded entry and label vectors, no batch-byte cap, and
no message cap. `BoundedExportQueue` is a separate utility, not part of the
production `Meter` route. Its capacity is caller-supplied; overload drops the
oldest batch and preserves FIFO among survivors. Capacity zero has effective
depth one: the first enqueue reports shedding but increments no drop counter
because there was no prior item. A dequeued batch that fails export is neither
requeued nor counted as shed.

The private owned model has useful semantic limits and default wire-envelope
values, but they are not producer or production proof:

| Limit | Value |
|---|---:|
| Default wire message envelope | 4 MiB, caller-configurable up to the protobuf ceiling |
| Hard protobuf message ceiling | 2,147,483,647 bytes |
| Hard total owned strings/bytes payload | 4 MiB |
| Total repeated items | 65,536 |
| Resource groups per request | 64 |
| Scopes per resource group | 128 |
| Metrics per scope | 4,096 |
| Points per metric | 1,000 |
| Attributes per owner | 128 |
| Exemplars per point | 128 |
| Histogram bucket counts | 4,096 |
| Histogram explicit bounds | 4,095 |
| Summary quantiles | 1,024 |
| Metric name / description / unit | 1,024 / 4,096 / 256 bytes |
| Attribute key / value | 1,024 / 4,096 bytes |

`ProtoMessage` encode/decode accepts caller-supplied `ProtobufWireLimits`, so the
4 MiB message and 16 MiB work values are defaults rather than immutable schema
caps. The semantic owned-payload and collection caps remain hard. The codec
rejects limit violations without returning a partial fresh model.

Exact producer points-per-metric, metrics-per-batch, batch-byte, queue-depth,
overload, fixed-histogram-bound, and summary-quantile choices are still
unselected. They must be finite and at most the applicable owned semantic and
caller wire envelopes. A3 cannot close and an adapter cannot land until those
values and split/refusal behavior are versioned and covered by goldens.

## Evidence required before closure

The artifact's golden matrix is the authoritative checklist. At minimum it
requires:

- an exact 23-instrument descriptor and mapping census;
- an exhaustive retained surface, producer, public-name, descriptor, reset,
  and numeric-domain census beyond the reviewed three-family baseline;
- same-epoch cumulative continuity and explicit reset rotation;
- exact `i64::MAX` mapping plus refusal at `i64::MAX + 1`;
- empty, boundary, maximum, reset, and malformed histogram cases;
- gauge and cumulative timestamp rules;
- byte-identical attribute ordering with duplicate and empty-key refusals;
- empty-name and duplicate/conflicting dynamic stream identity refusals;
- N and N+1 cardinality cases for every overflow and zero policy;
- distinct zero-cardinality outcomes for `Drop`, `Aggregate`, and `Warn`;
- negative Summary incompatibility plus finite-number and overflow boundaries;
- sampling quantization, NaN refusal, selector, admission-order, and shared-sequence cases;
- exact producer limits, overload/split behavior, all seven fixed histogram
  bound vectors, and canonical Summary quantiles at zero, limit, and
  limit-plus-one boundaries;
- a versioned panic-callback counter mapping or an explicit retained unsupported
  disposition;
- refusal of unbounded `Warn` in owned mode;
- deterministic LabRuntime replay with identical bytes and sampling decisions;
  and
- a no-mock collector case for counters, gauges, histograms, reset, attributes,
  and cardinality boundaries.

This tranche authored only the static artifact, documentation, and its Rust
contract source. None of those executable cases ran.

## No-claim boundary

This packet does not implement an owned production adapter, alter production
behavior, or prove compilation, formatting, tests, deterministic replay,
collector interoperability, feature-matrix health, or broad workspace health.
It does not claim that an arbitrary embedder `MeterProvider` selects the future
owned policies. It does not treat the generated-message helper or JSON-only
golden as production protobuf evidence. It does not authorize dependency
removal, API removal, cutover, release readiness, local execution fallback, or
tracker closure.

<!-- END OTLP METRICS MAPPING CONTRACT -->
