# Deadline Monitoring (Adaptive Thresholds)

## Overview
The deadline monitor scans live tasks and emits warnings when tasks are approaching
or exceeding expected durations, and when they stop making progress.

## Adaptive Threshold Algorithm
When `adaptive_enabled` is set, the monitor computes a per-task-type warning
threshold from historical durations:

1. **Group by task type** (set via `Cx::set_task_type("...")`).
2. **Record duration on completion** (logical time: `now - created_at`).
3. **Compute percentile** using a nearest-rank rule:
   - `rank = ceil(p * N)`, `index = max(rank - 1, 0)`
   - This ensures at least `p` of samples are <= threshold.
4. **Warn when elapsed >= threshold**.

If there are fewer than `min_samples` for a task type, the monitor uses
`fallback_threshold` (clamped to the task's total deadline when present).

When adaptive mode is disabled, the monitor uses the legacy logic:
`remaining <= warning_threshold_fraction * total_deadline`.

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

## Tuning Tips
- Start with `warning_percentile = 0.9` and `min_samples = 10`.
- Use a conservative `fallback_threshold` to avoid noisy alerts.
- If your task mix is large, label with coarse-grained types to avoid
  high-cardinality metrics.
