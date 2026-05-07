# Transport Frontier Feasibility Harness and Benchmark Contract

Bead: `asupersync-1508v.8.4`

Validation-prep extension: `asupersync-1508v.8.7`

## Purpose

This contract defines the feasibility harness, workload vocabulary, and benchmark schema for transport-frontier experiments. Every transport experiment (multipath, coded transport, receiver-driven RPC) must share deterministic workloads, comparable metrics, and structured benchmark logs before prototype work begins.

## Contract Artifacts

1. Canonical artifact: `artifacts/transport_frontier_benchmark_v1.json`
2. Comparator-smoke runner: `scripts/run_transport_frontier_benchmark_smoke.sh`
3. Invariant suite: `tests/transport_frontier_benchmark_contract.rs`

## Current Transport Substrate

### Core Abstractions

| Component | File | Role |
|-----------|------|------|
| `SymbolSink` / `SymbolStream` | `src/transport/sink.rs`, `stream.rs` | Async send/recv traits |
| `MultipathAggregator` | `src/transport/aggregator.rs` | Path selection, dedup, reordering |
| `SymbolRouter` / `SymbolDispatcher` | `src/transport/router.rs` | Routing table, load balancing |
| `SimNetwork` | `src/transport/mock.rs` | Deterministic network simulation |

### Simulation Capabilities

The `SimNetwork` provides deterministic, reproducible network simulation with:

- Configurable per-link latency, loss rate, reorder probability
- Deterministic RNG for reproducible failure injection
- In-memory channels with backpressure

## Benchmark Dimensions

### D1: RTT Tail Latency

- p50, p95, p99, p999 round-trip latency per message
- Measured under load: idle, 50%, 80%, 95% utilization
- Head-of-line blocking impact quantified per transport variant

### D2: Goodput Under Loss

- Effective throughput as a function of link loss rate (0%, 1%, 5%, 10%)
- Coded transport recovery overhead (bandwidth tax)
- Retransmission amplification factor

### D3: Fairness

- Jain's fairness index across concurrent flows
- Starvation detection: any flow below 10% of fair share
- Priority inversion exposure

### D4: CPU Per Packet

- CPU cycles per processed message (encode/decode/route)
- Cache miss rate on hot path
- Amortization effectiveness (batching gains)

### D5: Failure Handling

- Recovery time after path failure (time to reroute)
- Handoff latency during path migration
- Overload behavior: backpressure correctness, no data loss

### D6: Operator Visibility

- Structured log field completeness per experiment
- Metric granularity (per-path, per-flow, aggregate)
- Downgrade decision observability

## Workload Vocabulary

### Transport Workloads

| Workload ID | Description | Pattern |
|-------------|-------------|---------|
| TW-BURST | Burst loss recovery | 1000 msgs, 5% burst loss |
| TW-REORDER | Packet reordering | 1000 msgs, 10% reorder |
| TW-HANDOFF | Path migration | Active flow, primary path fails |
| TW-OVERLOAD | Backpressure | Sender rate 2x receiver capacity |
| TW-MULTIPATH | Multi-path aggregation | 3 paths, varying quality |
| TW-FAIRNESS | Concurrent flows | 10 flows, shared bottleneck |

## Experiment Catalog

### Experiment 1: Receiver-Driven Low-Latency RPC

Grant-based flow control where the receiver paces the sender.

- **Hypothesis**: Reduces tail latency by eliminating sender-side congestion control delay
- **Key metrics**: D1 (RTT), D3 (fairness), D4 (CPU)

### Experiment 2: Multipath Transport

Simultaneous use of multiple network paths with coded redundancy.

- **Hypothesis**: Improves goodput under partial failures
- **Key metrics**: D2 (goodput), D5 (failure handling)

### Experiment 3: Coded Transport (FEC/RLNC)

Forward error correction or random linear network coding for loss recovery without retransmission.

- **Hypothesis**: Trades bandwidth for latency (eliminates retransmission RTTs)
- **Key metrics**: D1 (RTT), D2 (goodput), D4 (CPU)

## Structured Logging Contract

Benchmark logs MUST include:

- `experiment_id`: Which transport experiment
- `workload_id`: Workload from the vocabulary
- `benchmark_correlation_id`: Stable correlation ID linking the decision to a replayable benchmark run
- `path_count`: Number of active paths
- `experimental_gate_id`: Explicit preview gate state for the transport decision
- `path_policy_id`: Requested transport path-selection policy
- `effective_path_policy_id`: Effective path-selection policy after conservative fallback
- `requested_path_count`: Requested path count for bounded policies, if any
- `selected_path_count`: Number of paths actually selected by the policy
- `fallback_path_count`: Number of conservative fallback paths retained for replay/debug analysis
- `selected_path_ids`: Stable comma-separated selected path IDs in decision order
- `fallback_path_ids`: Stable comma-separated fallback path IDs in decision order
- `fallback_policy_id`: Conservative fallback policy when the requested policy cannot be honored exactly
- `path_downgrade_reason`: Stable downgrade code emitted by the low-level path selector
- `downgrade_reason`: Stable downgrade code such as `no-primary-path` or `requested-paths-unavailable`
- `coding_policy_id`: Requested coded-transport policy
- `effective_coding_policy_id`: Effective coded-transport policy after conservative fallback
- `loss_rate_pct`: Configured loss rate
- `throughput_msgs_sec`: Messages per second
- `p50_us`, `p95_us`, `p99_us`, `p999_us`: Latency percentiles in microseconds
- `cpu_cycles_per_msg`: CPU cost per message
- `fairness_index`: Jain's fairness index
- `recovery_time_ms`: Time to recover from failure
- `verdict`: `advance`, `hold`, or `reject`

## Comparator-Smoke Runner

Canonical runner: `scripts/run_transport_frontier_benchmark_smoke.sh`

The runner reads `artifacts/transport_frontier_benchmark_v1.json`, supports deterministic per-scenario and whole-suite dry-run or execute modes, and emits:

1. Per-scenario manifests with schema `transport-frontier-benchmark-smoke-bundle-v1`
2. Aggregate run report with schema `transport-frontier-benchmark-smoke-run-report-v1`
3. Whole-suite summary with schema `transport-frontier-benchmark-smoke-suite-summary-v1` when invoked with `--all`

Supported invocations:

- `bash ./scripts/run_transport_frontier_benchmark_smoke.sh --scenario <ID> --dry-run`
- `bash ./scripts/run_transport_frontier_benchmark_smoke.sh --scenario <ID> --execute`
- `bash ./scripts/run_transport_frontier_benchmark_smoke.sh --all --dry-run`
- `bash ./scripts/run_transport_frontier_benchmark_smoke.sh --all --execute`

Deterministic runner controls:

- `AA08_RUN_ID`: override the generated run identifier for deterministic dry-run/contract tests
- `AA08_TIMESTAMP`: override the manifest timestamp for deterministic dry-run/contract tests
- `AA08_FINISHED_AT`: override the execute-mode completion timestamp when exact report or suite-summary content matters
- `AA08_OUTPUT_ROOT`: redirect artifacts away from the default `target/transport-frontier-benchmark-smoke`

Required bundle fields:

- `schema`, `scenario_id`, `description`, `workload_id`, `validation_surface`
- `focus_dimension_ids`, `run_id`, `mode`, `command`, `timestamp`
- `artifact_path`, `runner_script`, `bundle_manifest_path`
- `planned_run_log_path`, `planned_run_report_path`, `rch_routed`

Required report fields:

- `schema`, `scenario_id`, `description`, `workload_id`, `validation_surface`
- `focus_dimension_ids`, `run_id`, `mode`, `command`
- `artifact_path`, `runner_script`, `bundle_manifest_path`
- `run_log_path`, `run_report_path`, `output_dir`, `rch_routed`
- `started_at`, `finished_at`, `exit_code`

In dry-run mode, the runner still materializes `run_report.json` as a deterministic placeholder report with `mode=dry-run` and `exit_code=0`, so the contract surface stays structurally identical between planning and execute runs.

Required suite-summary fields:

- `schema`, `run_id`, `mode`, `artifact_path`, `runner_script`
- `output_dir`, `summary_path`, `started_at`, `finished_at`, `status`
- `scenario_count`, `scenario_ids`, `all_rch_routed`, `suite_exit_code`, `scenarios`

Required suite-summary scenario entry fields:

- `scenario_id`, `description`, `workload_id`, `validation_surface`
- `focus_dimension_ids`, `command`, `output_dir`, `bundle_manifest_path`
- `run_log_path`, `run_report_path`, `status`, `exit_code`, `rch_routed`

When `--all` is used, the runner writes the suite summary to:

- `target/transport-frontier-benchmark-smoke/<run_id>/summary.json`

In `--all --dry-run`, the summary is a deterministic planning artifact with `status=planned` and `suite_exit_code=null`.
In `--all --execute`, the summary records per-scenario pass/fail status and the first non-zero suite exit code, while still retaining report pointers for every scenario that ran.

Validation-prep smoke slices now include:

- fairness flow-balance coverage
- handoff/fallback metadata coverage
- overload rejection visibility
- deterministic operator-visibility bundle generation

## Validation

Focused invariant test command (routed through `rch`):

```bash
${RCH_BIN:-rch} exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_transport_frontier_contract cargo test -p asupersync --test transport_frontier_benchmark_contract --features test-internals -- --nocapture
```

## Cross-References

- `src/transport/mod.rs` -- Transport module
- `src/transport/aggregator.rs` -- Multipath aggregation
- `src/transport/router.rs` -- Routing and dispatch
- `src/transport/mock.rs` -- Deterministic network simulation
- `src/transport/sink.rs` -- Symbol sink trait
- `src/transport/stream.rs` -- Symbol stream trait
- `artifacts/runtime_control_seam_inventory_v1.json` -- Control seam inventory (AA-01.3)
- `artifacts/transport_frontier_benchmark_v1.json`
- `scripts/run_transport_frontier_benchmark_smoke.sh`
- `tests/transport_frontier_benchmark_contract.rs`
