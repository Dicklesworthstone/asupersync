# Transport Frontier Feasibility Harness and Benchmark Contract

Bead: `asupersync-1508v.8.4`

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
- `path_count`: Number of active paths
- `loss_rate_pct`: Configured loss rate
- `throughput_msgs_sec`: Messages per second
- `p50_us`, `p95_us`, `p99_us`, `p999_us`: Latency percentiles in microseconds
- `cpu_cycles_per_msg`: CPU cost per message
- `fairness_index`: Jain's fairness index
- `recovery_time_ms`: Time to recover from failure
- `verdict`: `advance`, `hold`, or `reject`

## Comparator-Smoke Runner

Canonical runner: `scripts/run_transport_frontier_benchmark_smoke.sh`

The runner reads `artifacts/transport_frontier_benchmark_v1.json`, supports deterministic dry-run or execute modes, and emits:

1. Per-scenario manifests with schema `transport-frontier-benchmark-smoke-bundle-v1`
2. Aggregate run report with schema `transport-frontier-benchmark-smoke-run-report-v1`

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa081 cargo test --test transport_frontier_benchmark_contract -- --nocapture
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
