# External Validation and Comparative Benchmark/Evidence Packs

**Bead**: `asupersync-2oh2u.11.7` ([T9.7])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Date**: 2026-03-04
**Purpose**: Run external validation campaigns and publish comparative evidence
packs that reproduce parity, reliability, and operability claims under realistic
workloads and failure conditions.

---

## 1. Scope

This contract governs external validation methodology, benchmark design,
evidence pack structure, and publication requirements for demonstrating
Tokio-replacement readiness to independent reviewers.

Prerequisites:
- `asupersync-2oh2u.11.10` (T9.10: migration lab KPIs)
- `asupersync-2oh2u.10.13` (T8.13: golden log corpus)
- `asupersync-2oh2u.10.12` (T8.12: cross-track e2e logging gates)
- `asupersync-2oh2u.11.5` (T9.5: release channels)
- `asupersync-2oh2u.11.4` (T9.4: reference applications)
- `asupersync-2oh2u.10.10` (T8.10: incident-response playbooks)

Downstream:
- `asupersync-2oh2u.11.8` (T9.8: replacement claim RFC)
- `asupersync-2oh2u.11.12` (T9.12: operator enablement pack)

---

## 2. Validation Campaign Design

### 2.1 Campaign Types

| Campaign ID | Name | Scope | Duration | Description |
|------------|------|-------|----------|-------------|
| VC-01 | Functional Parity | Per-track | 1 day | Verify API-level parity against tokio equivalents |
| VC-02 | Performance Baseline | Per-track | 2 days | Benchmark latency/throughput vs tokio baseline |
| VC-03 | Reliability Soak | Multi-track | 7 days | Sustained load with fault injection |
| VC-04 | Migration Friction | Per-track | 1 day | Measure migration effort via lab protocol |
| VC-05 | Operability Drill | Multi-track | 1 day | Incident response drill with measurement |
| VC-06 | Ecosystem Interop | T7 focus | 2 days | Third-party crate compatibility verification |

### 2.2 Comparison Methodology

Each campaign compares asupersync against tokio using:

| Metric | Measurement | Baseline Source |
|--------|------------|-----------------|
| Latency (p50, p99) | Histogram | tokio equivalent benchmark |
| Throughput (ops/sec) | Counter | tokio equivalent benchmark |
| Memory usage (RSS) | Peak/steady | tokio equivalent under same load |
| Error rate | Ratio | tokio equivalent under same faults |
| Startup time | Duration | tokio equivalent cold start |
| Cancellation correctness | Pass/fail | asupersync-specific (no tokio baseline) |

---

## 3. Benchmark Suite

### 3.1 Per-Track Benchmarks

| Benchmark ID | Track | Workload | Metric Focus |
|-------------|-------|----------|-------------|
| BM-01 | T2 (I/O) | TCP echo with 10K concurrent connections | Latency p99, throughput |
| BM-02 | T2 (I/O) | Codec encode/decode with 1MB frames | Throughput, memory |
| BM-03 | T3 (FS) | File read/write 10K files, 1MB each | Throughput, FD count |
| BM-04 | T3 (Process) | Spawn/wait 1K child processes | Latency, zombie cleanup |
| BM-05 | T4 (QUIC) | QUIC handshake + 100 streams | Latency, connection setup |
| BM-06 | T4 (H3) | HTTP/3 request/response 10K requests | Throughput, memory |
| BM-07 | T5 (Web) | HTTP routing + middleware chain | Latency p99, throughput |
| BM-08 | T5 (gRPC) | Unary + streaming RPC 10K calls | Latency, message rate |
| BM-09 | T6 (DB) | Connection pool acquire/release 10K ops | Latency p99, pool utilization |
| BM-10 | T6 (Messaging) | Kafka produce/consume 100K messages | Throughput, ordering |
| BM-11 | T7 (Interop) | tokio-compat bridge overhead | Latency overhead, memory |
| BM-12 | Multi-track | Full-stack web+db+messaging | End-to-end latency |

### 3.2 Benchmark Execution Protocol

1. **Environment**: Dedicated bare-metal or VM with fixed CPU/memory
2. **Warmup**: 30-second warmup period, results discarded
3. **Measurement**: 5-minute steady-state measurement window
4. **Repetitions**: Minimum 3 runs; report median and percentiles
5. **Correlation**: Each run tagged with unique correlation ID
6. **Artifacts**: Raw data, histogram plots, structured log traces

---

## 4. Evidence Pack Structure

### 4.1 Pack Layout

```text
evidence-packs/
├── manifest.json              # Pack metadata and index
├── campaigns/
│   ├── vc-01-functional/      # Per-campaign results
│   │   ├── results.json       # Machine-readable outcomes
│   │   ├── narrative.md       # Human-readable analysis
│   │   └── artifacts/         # Raw data, logs, traces
│   ├── vc-02-performance/
│   └── ...
├── benchmarks/
│   ├── bm-01-tcp-echo/
│   │   ├── asupersync.json    # asupersync results
│   │   ├── tokio-baseline.json # tokio baseline
│   │   ├── comparison.json    # Delta analysis
│   │   └── histogram.svg      # Visual comparison
│   └── ...
├── compatibility/
│   ├── deltas.json            # Compatibility delta summary
│   └── gap-analysis.md        # Gap analysis with remediation
└── summary/
    ├── executive-summary.md   # High-level findings
    └── readiness-verdict.json # GO/NO_GO recommendation
```

### 4.2 Pack Manifest Schema

```json
{
  "schema_version": "evidence-pack-v1",
  "pack_id": "EP-20260304-001",
  "created_at": "2026-03-04T12:00:00Z",
  "asupersync_version": "0.2.8",
  "tokio_baseline_version": "1.43.0",
  "campaigns": ["VC-01", "VC-02", "VC-03"],
  "benchmarks": ["BM-01", "BM-02"],
  "tracks_covered": ["T2", "T3", "T4", "T5", "T6", "T7"],
  "verdict": "GO",
  "correlation_id": "ep-20260304-abc123",
  "reproducibility": {
    "git_sha": "abc123",
    "rust_version": "1.85.0",
    "os": "Linux 6.17",
    "cpu": "AMD EPYC 7763",
    "memory_gb": 64
  }
}
```

---

## 5. Result Analysis Framework

### 5.1 Comparison Verdicts

| Verdict | Condition | Action |
|---------|-----------|--------|
| BETTER | asupersync outperforms tokio by > 5% | Highlight as advantage |
| EQUIVALENT | Within ±5% of tokio | Parity confirmed |
| ACCEPTABLE | 5–20% slower than tokio | Document with rationale |
| REGRESSION | > 20% slower than tokio | Requires remediation bead |
| INCOMPATIBLE | Behavioral difference detected | Requires compatibility fix |

### 5.2 Compatibility Delta Schema

```json
{
  "schema_version": "compatibility-delta-v1",
  "track": "T5",
  "delta_id": "CD-T5-001",
  "category": "behavioral",
  "description": "gRPC-web trailing metadata order differs",
  "severity": "Low",
  "impact": "No user-visible impact in standard configurations",
  "remediation": "Normalize metadata ordering in adapter layer",
  "owner": "Track T5 lead",
  "follow_up_bead": "asupersync-2oh2u.X.Y"
}
```

---

## 6. Publication Requirements

### 6.1 Reproducibility

| Requirement ID | Description |
|---------------|-------------|
| PR-01 | All benchmark code committed to repository |
| PR-02 | Environment specification documented (hardware, OS, Rust version) |
| PR-03 | Exact command sequences for reproduction provided |
| PR-04 | Raw data artifacts preserved with correlation IDs |
| PR-05 | Git SHA of tested code recorded in manifest |

### 6.2 Independent Review

| Requirement ID | Description |
|---------------|-------------|
| IR-01 | Evidence pack self-contained (no external dependencies for review) |
| IR-02 | Narrative summary accessible to non-experts |
| IR-03 | Structured results machine-parseable for automated review |
| IR-04 | Compatibility deltas explicitly list user-visible differences |
| IR-05 | Remediation plans for all REGRESSION and INCOMPATIBLE findings |

---

## 7. Quality Gates

| Gate ID | Name | Condition | Evidence |
|---------|------|-----------|----------|
| EV-01 | Campaign types complete | All 6 VC-xx campaigns defined | This document §2.1 |
| EV-02 | Benchmark suite complete | All 12 BM-xx benchmarks defined | This document §3.1 |
| EV-03 | Evidence pack structure defined | Layout and manifest schema specified | This document §4 |
| EV-04 | Comparison verdicts defined | BETTER through INCOMPATIBLE with actions | This document §5.1 |
| EV-05 | Reproducibility requirements met | PR-01..PR-05 | This document §6.1 |
| EV-06 | Independent review requirements met | IR-01..IR-05 | This document §6.2 |
| EV-07 | Compatibility delta schema defined | Machine-readable delta format | This document §5.2 |
| EV-08 | All tracks covered | T2-T7 in benchmark suite | This document §3.1 |

---

## 8. Evidence Links

| Artifact | Reference |
|----------|-----------|
| Migration lab KPI contract | `docs/tokio_migration_lab_kpi_contract.md` |
| Golden log corpus | `docs/tokio_golden_log_corpus_contract.md` |
| Cross-track logging gates | `docs/tokio_cross_track_e2e_logging_gate_contract.md` |
| Release channels | `docs/tokio_release_channels_stabilization_policy.md` |
| Reference applications | `docs/tokio_reference_applications_templates.md` |
| Incident-response playbooks | `docs/tokio_incident_response_rollback_playbooks.md` |
| Replacement roadmap | `docs/tokio_replacement_roadmap.md` |

---

## 9. CI Integration

Validation:
```bash
cargo test --test tokio_external_validation_benchmark_enforcement
rch exec 'cargo test --test tokio_external_validation_benchmark_enforcement'
```

---

## Appendix A: Cross-References

| Bead | Relationship | Description |
|------|-------------|-------------|
| `asupersync-2oh2u.11.10` | Prerequisite | Migration lab KPIs |
| `asupersync-2oh2u.10.13` | Prerequisite | Golden log corpus |
| `asupersync-2oh2u.10.12` | Prerequisite | Cross-track e2e logging gates |
| `asupersync-2oh2u.11.5` | Prerequisite | Release channels |
| `asupersync-2oh2u.11.4` | Prerequisite | Reference applications |
| `asupersync-2oh2u.10.10` | Prerequisite | Incident-response playbooks |
| `asupersync-2oh2u.11.8` | Downstream | Replacement claim RFC |
| `asupersync-2oh2u.11.12` | Downstream | Operator enablement pack |
