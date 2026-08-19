# OpenTelemetry structured-concurrency traces

This document describes the tracing surfaces that are implemented today. It is
not a promise of automatic runtime instrumentation, a performance claim, or a
tail-sampling design.

## Contents

- [Current surfaces](#current-surfaces)
- [Owned finite trace mapper](#owned-finite-trace-mapper)
- [Structured-concurrency lineage](#structured-concurrency-lineage)
- [Sampling and limits](#sampling-and-limits)
- [Export ownership](#export-ownership)
- [Compatibility](#compatibility)
- [Verification](#verification)
- [Explicit non-claims](#explicit-non-claims)

## Current surfaces

The `metrics` feature exposes two separate trace-building routes:

1. `SpanStorage` is a manually driven OpenTelemetry SDK bridge. Callers create,
   update, materialize, and end its region/task/operation/cancellation spans.
   Asupersync does not install it into `RuntimeBuilder`, and the runtime does not
   automatically call it for every scheduler transition.
2. `OwnedOtlpTraces` is a finite mapper backed by Asupersync's crate-owned OTLP
   protobuf model. It accepts borrowed span records, validates the complete
   sampled collection, produces deterministic OTLP request bytes, and can send
   them through `OtlpHttpExporter` under a caller-owned `Cx`.

The older `OtlpSpan`, `SpanBatch`, and `TraceExporter` APIs remain available.
The owned mapper is additive and does not change their signatures or behavior.

## Owned finite trace mapper

Create a validated mapper and borrowed span inputs:

```rust
use asupersync::observability::{
    OtlpTraceSpanInput, OtlpTraceStatus, OwnedOtlpStatusCode,
    OwnedOtlpTraceConfig, OwnedOtlpTraces,
};

let traces = OwnedOtlpTraces::try_new(OwnedOtlpTraceConfig::new())?;
let trace_id = [0x11; 16];
let root_id = [0x21; 8];
let child_id = [0x22; 8];

let root = OtlpTraceSpanInput::new(
    trace_id,
    root_id,
    "region.root",
    1_000,
    5_000,
);
let child = OtlpTraceSpanInput::new(
    trace_id,
    child_id,
    "task.worker",
    2_000,
    4_000,
)
.with_parent_span_id(root_id)
.with_status(OtlpTraceStatus::new(
    OwnedOtlpStatusCode::Ok,
    "completed",
));

let collection = traces.collect(
    &[child, root],
    &[("service.name", "example")],
)?;
assert_eq!(collection.sampled_spans(), 2);
```

All IDs and timestamps are explicit. The mapper does not read an ambient clock
or generate random identifiers. Each `OtlpTraceSpanInput` may carry:

- a 16-byte nonzero trace ID and 8-byte nonzero span ID;
- an optional 8-byte parent span ID;
- span name, kind, start/end timestamps, W3C tracestate, and trace flags;
- bounded string attributes and producer-supplied dropped-attribute count;
- bounded timestamped events and dropped-event count;
- bounded links, including link tracestate/flags/remote-context metadata;
- an optional OTLP status and diagnostic message;
- optional local/remote context metadata encoded in OTLP flags.

The public input fields are private and configured through builders. This keeps
the new API additive: future metadata can be added without making existing
exhaustive struct literals fail to compile.

## Structured-concurrency lineage

For sampled spans in the same collection, a parent ID is a local lineage edge
when `(trace_id, parent_span_id)` identifies another sampled span. The mapper:

- rejects duplicate `(trace_id, span_id)` pairs;
- rejects cycles and self-parenting;
- requires every local parent timestamp interval to enclose its child;
- emits local parents before descendants even when input is shuffled;
- orders unrelated roots deterministically by trace ID, timestamps, and span ID;
- accepts an absent parent as an external/distributed parent rather than
  inventing a local span.

Callers choose the semantic span names and attributes. A useful convention is:

| Runtime event | Span name | Typical attributes |
| --- | --- | --- |
| Region lifecycle | `region.root` or `region.child` | entity/region IDs, outcome |
| Task lifecycle | `task.worker` | task/region IDs, outcome |
| Cancellable operation | `operation.read` | operation kind, resource class |
| Cancellation/drain | `cancel.drain` | cancel kind, initiator, outcome |

These names are conventions, not automatic runtime hooks.

## Sampling and limits

The sampled bit is the low bit of `trace_flags`. Unsampled inputs are counted
and discarded before resource validation or owned request allocation. This is
head sampling: the producer decides sampling before calling the mapper. There is
no tail sampler in this path.

`OwnedOtlpTraceConfig` validates an immutable finite envelope. Defaults are:

| Limit | Default |
| --- | ---: |
| Sampled spans per collection | 4,096 |
| Sampled spans per request | 256 |
| Events per span | 128 |
| Links per span | 128 |
| Attributes per resource/span/event/link | 128 |
| Span or event name | 1,024 bytes |
| W3C tracestate | 512 bytes |
| Owned caller string bytes per collection | 4 MiB |
| Encoded request bytes | 4 MiB |

Finite count, byte, identifier, timestamp, attribute, and lineage validation is
performed before cloning caller strings. Malformed W3C tracestate is rejected
during owned protobuf encoding, before the mapper returns or the exporter
writes a byte. All failures use a value-redacted `OwnedOtlpTraceError`, and
complete mapping of every request finishes before network output begins.

Events are ordered by timestamp and name. Links and attributes are likewise
canonicalized before encoding. With equivalent inputs, repeated Lab runs and
different input ordering produce byte-identical request bodies.

## Export ownership

`OtlpHttpExporter::send_owned_traces` maps first and then sends each request
sequentially:

```rust
let cx = /* caller-owned Cx */;
exporter.send_owned_traces(&cx, &traces, &[root, child]).await?;
```

The method uses the same validated endpoint, TLS/auth, timeout, retry, and
compression policy as owned metrics. It does not spawn a background exporter
task. Cancellation and budget ownership therefore remain with the supplied
`Cx`; an all-unsampled collection performs no network request.

## Compatibility

This work adds new APIs under the existing opt-in `metrics` feature. It does
not remove, rename, or change the public signature of the v0.4.3 trace-export
surfaces. Existing SDK-based instrumentation and legacy trace exporters keep
working. Applications may adopt the owned mapper one producer at a time.

The crate-owned protobuf module is intentionally private. Public callers build
borrowed inputs and receive request bytes through `OwnedOtlpTraceCollection`,
so protobuf implementation details can evolve without exporting a second OTLP
schema API.

## Verification

Focused mapper and native wire tests:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_otlp_trace_a4" \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --lib --features metrics,test-internals \
  owned_otlp_trace_tests -- --nocapture

RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_otlp_trace_golden" \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --test otlp_metrics_request_golden \
  --features metrics,test-internals -- --nocapture
```

The ignored real-service test downloads a pinned Linux OpenTelemetry Collector
archive, verifies its SHA-256 digest, sends both metrics and traces, and reads
the collector's file-exporter output:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_otlp_collector" \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --test otlp_metrics_request_golden \
  --features metrics,test-internals \
  owned_metrics_external_otel_collector_accepts_and_exports_request \
  -- --ignored --exact --nocapture
```

## Explicit non-claims

- The runtime does not automatically emit a span for every region, task,
  operation, cancellation, or obligation transition.
- `RuntimeBuilder` does not install `SpanStorage` or `OwnedOtlpTraces`.
- The owned mapper implements producer-selected head sampling, not tail
  sampling.
- No benchmark result or fixed overhead percentage is claimed here.
- Collector acceptance proves the emitted OTLP/HTTP trace request is accepted
  by the pinned fixture. It does not prove compatibility with every collector,
  backend, deployment policy, TLS setup, or sampling pipeline.
- Enabling `metrics` is not zero-cost. With the feature disabled, these owned
  trace types and exporter methods are not compiled.
