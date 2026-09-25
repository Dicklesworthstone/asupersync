# Composing OTLP exports with synchronous exporters

On native builds with `metrics`, `OtlpHttpExporter` and
`OtlpLogsHttpExporter` implement their synchronous exporter traits by admitting
snapshots to a bounded queue. They can participate in `MultiExporter` and
`MultiLogsExporter`. Admission performs no network I/O and starts no task.

An `Ok(())` from `export` means the snapshot was admitted. Collector delivery
requires an explicit async consumer. Clones share the queue; each batch captures
its destination, TLS policy, retry policy, credentials and resource attributes
at admission, so changing another clone's configuration cannot redirect it.

## Collect and deliver a finite snapshot

`observability::metrics::Metrics::export_snapshot()` collects current counters,
gauges and histogram totals into the legacy `MetricsSnapshot` representation.
It allocates at collection time. Updates through acquired counter/gauge handles
remain atomic operations. Histogram totals are internally coherent; different
instruments are sampled independently. Summaries and explicit histogram buckets
cannot be represented by this legacy snapshot. Use `OwnedOtlpMetrics` when those
richer runtime metrics and an explicit accumulation epoch are required.

```rust,ignore
use asupersync::observability::otel::{
    MetricsExporter, MultiExporter, OtlpHttpExporter, StdoutExporter,
};

let otlp = OtlpHttpExporter::try_new("http://127.0.0.1:4318/v1/metrics")?;
let exporters = MultiExporter::new(vec![
    Box::new(StdoutExporter::new()),
    Box::new(otlp.clone()),
]);
let snapshot = registry.export_snapshot();
exporters.export(&snapshot)?;
// Supply the Unix-nanosecond timestamp from the application's clock authority.
otlp.flush_queued(&cx, collection_time_unix_nano).await?;
exporters.flush()?;
```

`flush_queued` owns one consumer and delivers only the finite prefix present
when it starts. Later admissions remain queued. The caller supplies the timestamp
assigned to legacy metrics, since `MetricsSnapshot` has no timestamp field. All
metrics in that flush receive the supplied timestamp; applications requiring
distinct collection times should flush each collection or use the owned mapper.
Histogram totals are encoded as a single unbounded bucket without inventing
distribution detail. Counters exceeding OTLP's signed integer range, non-finite
histogram sums, duplicate streams, and invalid attributes are refused.

For logs, use `otlp_logs.flush_queued(&cx).await?`; existing record timestamps
are retained. The established async `export_async` and `send_otlp_protobuf`
paths remain available and bypass the admission queue.

## A caller-owned continuous sender

Run `otlp.run_queued(&cx, unix_nanosecond_clock).await` inside a task owned by the
application's region. For logs, call `otlp_logs.run_queued(&cx).await`.
Notification wakes an idle sender when a snapshot arrives. Explicit cancellation
and the Cx deadline also wake an idle sender. No runtime or detached sender is
created by these APIs. A second concurrent consumer returns `consumer_busy`.

Stop producers before graceful shutdown, stop/join the continuous consumer, then
use `flush_queued` with the caller's still-valid cleanup context to drain the
remaining finite queue. Cancellation before dequeue leaves the batch queued.
Cancellation or dropping a delivery future after dequeue retires that attempt
as failed: the collector may already have accepted its bytes. Such a batch is
never automatically requeued. Existing bounded HTTP retries apply within one
attempt, and collector partial rejection remains a terminal error.

## Admission and completion accounting

Each queue admits at most **64 batches** and **8 MiB of snapshot/configuration
string bytes**, including the in-flight batch. New snapshots are refused when
either limit is reached; existing accepted snapshots are preserved. A batch is
limited to 4096 points/records, with finite metric-name and attribute limits.
Container overhead, protobuf encoding and HTTP transport allocations are
additional; encoded requests are limited to 4 MiB. These are queue limits, not
a bound on application allocations or concurrent direct async calls.

`queue_stats()` reports pending and retained batches, retained string bytes,
successful deliveries, failed/abandoned attempts and consumer ownership.
Synchronous `flush()` checks these counters. It returns an error while any batch
is pending/in flight or if any admitted attempt has failed. Failure history is
retained for the queue lifetime; later successful deliveries do not erase it.
This avoids reporting accepted-but-undelivered telemetry as flushed.

The native regression target is `otlp_queued_native` with
`metrics,test-internals`; unit queue/mapping tests are under
`observability::otel::queued::tests`. The native collector fixture decodes the
wire payload with the OpenTelemetry reference protobuf model. It is a protocol
fixture, not a deployed collector compatibility result.
