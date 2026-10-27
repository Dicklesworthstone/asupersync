# Deadline Monitoring (Adaptive Thresholds)

## Overview
The deadline monitor scans live tasks and emits warnings when tasks are approaching
or exceeding expected durations, and when they stop making progress.

Native runtimes also send task-completion observations to the monitor. This lets
adaptive thresholds learn from tasks that finish between scans and records
remaining time and deadline overruns even when the task never appeared in a
scan. Enable it with `RuntimeBuilder::deadline_monitoring`; disabled monitoring
does not allocate completion observations or inspect task labels at completion.

## Adaptive Threshold Algorithm
When `adaptive_enabled` is set, the monitor computes a per-task-type warning
threshold from historical durations:

1. **Group by task type** (set via `Cx::set_task_type("...")`).
2. **Record duration on completion** (logical time: `now - created_at`).
3. **Compute percentile** using the existing rounded zero-based rank:
   - `index = round(clamp(p, 0, 1) * (N - 1))`
   - Select the sorted sample at that index.
4. **Warn when elapsed >= threshold**.

If there are fewer than `min_samples` for a task type, the monitor uses
`fallback_threshold` (clamped to the task's total deadline when present).

When adaptive mode is disabled, the monitor uses the legacy logic:
`remaining <= warning_threshold_fraction * total_deadline`.

Each type keeps at most `max_history` samples, with storage allocated as samples
arrive. At most `MAX_ADAPTIVE_TASK_TYPES` (256) types are retained. Admitting a
new type at that limit evicts the oldest admitted type; later observations for
the evicted type start a new history and use the fallback until `min_samples`
is reached again. Histories are not accumulated while adaptive mode is disabled.

## Task Type Labeling
Adaptive thresholds are keyed by task type. If no task type is set, the monitor
uses `"default"`.

Recommended usage:

```rust
async fn handler(cx: &Cx) {
    cx.set_task_type("http.request");
    // ... work ...
}
```

## Metrics Emitted

- `asupersync.deadline.warnings_total`
- `asupersync.deadline.violations_total`
- `asupersync.deadline.remaining_seconds` (remaining at completion)
- `asupersync.checkpoint.interval_seconds`
- `asupersync.task.stuck_detected_total`

Task types are attached as labels where supported by the metrics backend.

## Native Delivery and Shutdown

Native completion captures owned task facts before the task record is recycled.
The monitor receives them through a queue bounded by
`MAX_QUEUED_DEADLINE_COMPLETIONS` (4,096). Each observation retains its completion
timestamp and admitted deadline, including when cancellation has replaced the
task context's budget with its separate cleanup budget. A shared receipt keeps
a deadline violation from being counted twice when completion races a scan,
when a scan has already forgotten the task, or when its task-table slot is reused.

Queue overflow drops the newest diagnostic observation and increments a counter;
it does not reject task work. Use `Runtime::deadline_monitor_stats()` to inspect
accepted, processed, queued, overflowed, and post-shutdown rejected observations.
Nonzero `dropped_completions` means adaptive histories and completion metrics are
incomplete. The method returns `None` if native monitoring is disabled or its
host thread could not start.

Warning and metric callbacks run on the monitor thread after runtime and queue
locks are released. Native monitoring contains each callback panic independently,
increments `callback_panics`, and continues processing other callbacks and
accepted observations. Standalone `DeadlineMonitor` users retain the existing
direct-callback behavior.

Runtime teardown keeps monitoring active until workers stop and stopped tasks
are retired, then seals the queue and drains every accepted observation before
joining the monitor thread. This does not require waiting for a long scan
interval to expire. `shutdown_drained` still reports region quiescence separately;
it does not stop the monitor or synchronously flush its observations.

Native scans omit terminal tasks and tasks without a deadline before copying
checkpoint histories. Histories for monitored tasks are still copied while
holding their task-table lock. The lab monitor retains its existing explicit
completion feed and time-source behavior.

## Tuning Tips
- Start with `warning_percentile = 0.9` and `min_samples = 10`.
- Use a conservative `fallback_threshold` to avoid noisy alerts.
- If your task mix is large, label with coarse-grained types to avoid
  high-cardinality metrics.
