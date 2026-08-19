# OTLP metrics mapping contract

<!-- BEGIN OTLP METRICS MAPPING CONTRACT -->

Bead: `asupersync-5z2scg.2.3`

Canonical artifact: `artifacts/otlp_metrics_mapping_contract_v1.json`

Claim revision: `f3ccd58d8d9b740ad07b4f2197d56d70ad049125`

Status: additive fixed-provider implementation complete. Focused execution is
`FOCUSED_RCH_GREEN`, including byte-identical deterministic LabRuntime replay
and a digest-pinned official `otelcol-contrib` v0.157.0 acceptance case. A fast
loopback receiver remains only a wire/decode smoke test.

## Outcome

This tranche reviews three OTLP-relevant metrics surfaces that must not be
conflated:

1. `OtelMetrics` records 23 fixed runtime instruments into a caller-supplied
   OpenTelemetry `Meter`. The embedder's provider owns collection, aggregation,
   temporality, timestamps, histogram boundaries, exemplars, and export.
2. `Metrics` is the dependency-free dynamic registry. It retains counters,
   gauges, explicit-bound histograms, and bounded-sample summaries.
3. `OwnedOtlpMetrics` implements all 23 fixed `MetricsProvider` instruments on
   top of the finite crate-owned `otlp_proto` messages. It owns cumulative
   epochs, exact histogram bounds, deterministic order, and finite request
   envelopes. `OtlpHttpExporter::send_owned_metrics` exports under a caller
   `Cx` without changing the established `OtelMetrics` bridge.

The fixed provider intentionally does not ingest the dynamic `Metrics` registry
or arbitrary direct instruments. Those surfaces remain documented no-claims,
not hidden inputs to the closed 23-instrument mapping. Fields named `owned_*`
describe the additive native provider; they do not describe the current
external `MeterProvider` output.

This distinction corrects three overstatements in the earlier frozen inventory:

- production metrics are not Asupersync-enforced cumulative-only; only the
  test/fuzz generated-message builder hard-codes cumulative temporality;
- the standalone bounded snapshot queue drops the oldest batch, not the newest;
  and
- the cited A3 integration receipt is partial evidence, not proof of owned
  mapping, reset behavior, boundary cardinality, deterministic replay, or a
  real collector. The executable tranche below supplies that missing case for
  the additive owned provider only.

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
the JSON artifact. Descriptions remain byte-for-byte incumbent values. The
additive owned provider emits `1` for counts and `s` for durations. The existing
external bridge still emits its established empty application-level units, so
this is not a cutover or a breaking descriptor change.

The owned-provider unit census executes callbacks for all 23 instruments,
including the three observable gauges, and checks the sorted emitted names.

`MetricsProvider::record_panic` is another retained panic-callback but not one of
the 23 instruments. Its no-op behavior is retained explicitly. A future panic
counter must be additive and versioned; the unsupported callback is not silently
misrepresented as an exported metric.

## Additional retained surfaces outside the fixed provider

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

Those examples are deliberately not presented as exhaustive. They are not
accepted inputs to `OwnedOtlpMetrics`; a future dynamic adapter must define its
own descriptor identity, reset, summary, and range semantics.

## Dynamic registry mapping

The default-feature `Metrics` registry is also retained:

| Registry kind | Available fidelity | Required owned mapping | Current gap |
|---|---|---|---|
| Counter | exact `u64` value | cumulative monotonic `Sum` | not wired to the fixed provider |
| Gauge | exact `i64` value | `Gauge` integer | not wired to the fixed provider |
| Histogram | sorted bounds, per-bucket counts including `+Inf`, count, sum | cumulative explicit `Histogram` | public `MetricsSnapshot` drops bounds and bucket counts |
| Summary | exact count and sum; last 4,096 finite observations for quantiles | `Summary` | no snapshot row or canonical quantile set |

The registry defaults to 10,000 distinct names per kind. Zero means unlimited.
A fresh name beyond the cap is routed to
`asupersync_metric_cardinality_overflow`, and the rejection counter advances.
Because the sentinel is insertable in addition to the configured ordinary-name
budget, a capped map may contain the cap plus the sentinel.

## Owned message shape

The native fixed-provider route is:

```text
ExportMetricsServiceRequest
  -> ResourceMetrics
    -> ScopeMetrics
      -> Metric
        -> Gauge | Sum | Histogram
          -> bounded data points
```

Counters use `Sum`, `Cumulative`, `is_monotonic = true`, and an integer point.
Gauges use an integer point with no start timestamp. Histograms use cumulative
explicit buckets whose count vector has exactly one more item than the strictly
increasing bound vector and whose checked bucket sum equals `count`. The five
duration histograms use `[0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1, 10,
60]`; deadline remaining uses `[0, 0.001, 0.01, 0.1, 1, 5, 30, 60, 300]`; and
tasks polled uses `[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]`. The fixed
provider emits no Summary, exemplar, exponential histogram, or metric metadata
until an explicit producer and versioned contract exist.

The provider has a closed descriptor set. One `Metric` groups distinct canonical
attribute-stream points for one fixed descriptor. Metrics are ordered by name
and points by their sorted attribute vectors. Duplicate or empty attribute keys
are refused before model construction. No model or wire bytes are returned when
producer mapping or encoding fails.

## Temporality, timestamps, and reset

The retained external bridge remains
`EMBEDDER_OWNED_NOT_ENFORCED_BY_ASUPERSYNC`. The additive owned provider is
cumulative-only for sums and histograms. Delta is unsupported.

Within one stream and attribute set:

- `time_unix_nano` is nonzero and never moves backwards;
- gauge `start_time_unix_nano` is absent;
- cumulative start time is one stable, nonzero accumulation-epoch timestamp;
- reset or aggregation-state recreation rotates that start time and restarts
  the cumulative value or every histogram field together; and
- reset is never represented as a negative delta.

The generated-message fixture does not prove that policy. The executable owned
provider instead receives epoch and point timestamps explicitly, rejects
backwards time, and rotates the epoch only through `reset`.

The owned provider maps `i64::MAX` exactly and refuses `i64::MAX + 1` before
model construction. Wrapping and lossy floating-point
conversion are forbidden. Scheduler task counts above the exactly representable
`f64` integer range are likewise refused. The owned schema rejects nonfinite
observations, bounds, sums, min/max, quantiles, and quantile values. Time and
epoch authority are explicit inputs; the provider never reads an ambient wall
clock.

## Attributes, cardinality, and sampling

The canonical operation order is filter, redact, sort, then construct the
model. Sorting uses UTF-8 key bytes followed by encoded value bytes. Duplicate
or empty keys are refused; empty string values are preserved unless the caller's
privacy policy explicitly removes the field.

The owned provider preserves empty values, refuses duplicate or empty keys, and
checks the 128-attribute, 1,024-byte key, 4,096-byte value, and aggregate owned-
byte limits before cloning caller-owned resource strings. It sorts resource and
point attributes before model construction. Current fixed domains include
`outcome`, `kind`, `task_type`, and `reason`.
`task_type` is restricted to 64 bytes and the documented safe character set;
invalid values become `<invalid>`. An oversized static `reason` is counted and
omitted before cloning, because the callback cannot return a mapping error.

`OtelMetrics` defaults are 1,000 label combinations per tracker-visible metric,
4,096 tracker-visible names, `Drop`, no dropped keys, and no sampling. Only the
eight label-bearing fixed call sites enter the tracker; the other 15 fixed
instruments do not consume name slots. Zero has intentionally different
meanings: `max_cardinality = 0` sends every fresh label set to overflow handling,
while `max_metrics = 0` disables the name limit. At zero cardinality, `Drop`
omits, `Aggregate` retries and is normally still refused, while `Warn` records
beyond the zero cap.

Those strategies describe the retained external bridge. Its overflow behavior
is exact, including its shortcomings:

- `Drop` counts one overflow and omits the point.
- `Aggregate` changes every retained value to `other` and retries. Because the
  retry happens after the set is full, a new all-`other` series is normally
  refused. It succeeds only if that exact series was admitted earlier.
- `Warn` logs and records beyond both caps. This is explicitly unbounded and
  cannot be inherited by a bounded owned adapter.

`OwnedOtlpMetrics` has none of those bypass modes. It accepts a finite point cap
from 1 through 1,000, omits a fresh stream at N+1, and increments
`rejected_updates`. Zero or out-of-range configuration is rejected.

Sampling uses one atomic 100-slot sequence shared across selected metrics. The
threshold is `floor(sample_rate * 100)`, giving one-percent downward
quantization. Selectors use substring matching; an empty selector list reaches
every sampled call. `NaN` survives the current clamp and casts to threshold zero;
owned mode must reject it at configuration time. Histogram sampling occurs
before sanitization and cardinality admission, so a sampled-out point consumes
no tracker slot. A completion counter can still advance while its duration
histogram is sampled out, and both scheduler histograms share one decision.
There is no reweighting. `OwnedOtlpMetrics` does not sample; the focused
LabRuntime test proves byte-identical output for the same deterministic schedule.

## Snapshot queue and finite limits

`MetricsSnapshot` has unbounded entry and label vectors, no batch-byte cap, and
no message cap. `BoundedExportQueue` is a separate utility, not part of the
production `Meter` route. Its capacity is caller-supplied; overload drops the
oldest batch and preserves FIFO among survivors. Capacity zero has effective
depth one: the first enqueue reports shedding but increments no drop counter
because there was no prior item. A dequeued batch that fails export is neither
requeued nor counted as shed.

The private owned model has semantic limits and default wire-envelope values:

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

`OwnedOtlpMetricsConfig` defaults to 1,000 points per metric, 256 metrics per
request, and 4,194,304 encoded bytes per request. The accepted ranges are
1..=1,000, 1..=4,096, and 1..=4,194,304 respectively. Collections split
deterministically at metric boundaries. The provider has no implicit queue, so
queue depth and queue overload are not applicable. Mapping and encoding of all
batches complete before `send_owned_metrics` performs the first network write.
Any mapping or encoding refusal returns no request byte vector.

## Executable evidence

The focused A3 lanes exercise:

- the exact sorted 23-instrument census and the three OTLP metric variants;
- cumulative epochs, explicit reset, nondecreasing timestamps, exact integer
  conversion, histogram shape, finite numeric validation, and typed refusals;
- canonical attributes, empty-value preservation, finite N/N+1 cardinality,
  deterministic metric splitting, and byte-envelope rejection;
- byte-identical deterministic LabRuntime replay; and
- `send_owned_metrics` against a loopback HTTP wire receiver, followed by
  generated-schema decoding and semantic assertions; and
- an ignored real-service E2E that downloads the SHA-256-pinned official
  `otelcol-contrib` v0.157.0 Linux distribution, sends two cumulative/reset
  requests, and independently parses its file-exporter JSON output.

The owned unit matrix runs through RCH with
`metrics,tracing-integration,test-internals`; the integration and real-service
targets use `metrics,test-internals`. The artifact records
`FOCUSED_RCH_GREEN`. These are executable evidence for this fixed provider, not
a substitute for a later broad release gate.

## No-claim boundary

The implemented provider covers the fixed 23-instrument `MetricsProvider`
surface, not the dynamic `Metrics` registry or arbitrary direct instruments.
Focused RCH evidence proves only the cited unit, LabRuntime, loopback wire smoke,
and pinned official `otelcol-contrib` v0.157.0 case. It does not claim that an
arbitrary embedder `MeterProvider` selects the owned policies, prove other
Collector versions, or prove the full feature matrix, broad workspace health,
performance, or release readiness. It does not authorize dependency removal,
API removal, cutover, or local execution fallback.

<!-- END OTLP METRICS MAPPING CONTRACT -->
