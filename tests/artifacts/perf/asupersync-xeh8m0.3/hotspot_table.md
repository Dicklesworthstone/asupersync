# asupersync-xeh8m0.3 Hotspot Table

No ranked hotspots are claimed for this receipt.

| Rank | Location | Metric | Value | Category | Evidence |
|------|----------|--------|-------|----------|----------|

## Verdict

The required rch-routed `scheduler/three_lane_decision` Criterion lane failed before measurements with `remote_exit=101`.

First blocker: `src/sync/lock_ordering.rs:56:12` reported `error: struct LockInfo is never constructed`.

Because Criterion did not run, this artifact records `verdict=no_win` and leaves p50, p95, p999, throughput, sample count, and run seed unset in the JSON receipt. No scheduler speedup, baseline latency, or hotspot ranking is supported by this run.
