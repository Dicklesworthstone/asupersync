# asupersync-xeh8m0.3 Hotspot Table

No ranked hotspots are claimed for this receipt.

| Rank | Location | Metric | Value | Category | Evidence |
|------|----------|--------|-------|----------|----------|

## Verdict

The required rch-routed `scheduler/three_lane_decision` Criterion lane failed with `remote_exit=101`.

The latest attempt got past the earlier `src/sync/lock_ordering.rs:56:12` dead-code compile frontier and reported partial Criterion estimates for `fast_ready_uncontended` and `fast_ready_local_peek_contended`, then failed during `scheduler/three_lane_decision/global_ready_burst/64` warmup.

Current blocker: `os-thread-local-0.1.3/src/lib.rs:76:9` reported `assertion left == right failed; left: 11; right: 0`.

Because the full scenario did not complete, this artifact records `verdict=no_win` and leaves p50, p95, p999, throughput, sample count, and run seed unset in the JSON receipt. No scheduler speedup, complete baseline latency, or hotspot ranking is supported by this run.
