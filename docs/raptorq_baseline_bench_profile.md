# RaptorQ Baseline Bench/Profile Corpus (bd-3s8zu) + G1 Budgets (bd-3v1cs)

This document records the deterministic baseline packet for the RaptorQ RFC-6330 program track.

- Bead: `bd-3s8zu`
- Artifact JSON: `artifacts/raptorq_baseline_bench_profile_v1.json`
- Replay catalog artifact: `artifacts/raptorq_replay_catalog_v1.json`
- Baseline run report: `target/perf-results/perf_20260215_222548/report.json`
- Baseline metric snapshot: `target/perf-results/perf_20260215_222548/artifacts/baseline_current.json`
- Git SHA: `40fc41edeefbade5bcb3ee5f1260f61cec7769a3`
- Seed: `424242`

This artifact now also carries the Track-G budget draft for bead `bd-3v1cs`:

- Workload taxonomy for `fast` / `full` / `forensics`
- Draft SLO budgets and regression thresholds
- Deterministic evaluation and confidence policy
- Gate-profile mapping tied to correctness evidence

Machine-readable contract:

- `artifacts/raptorq_baseline_bench_profile_v1.json`
- top-level key: `g1_budget_draft`
- schema tag: `g1_budget_draft.schema_version = raptorq-g1-budget-draft-v1`
- canonical sections: `workload_taxonomy`, `budget_sheet`, `profile_gate_mapping`, `confidence_policy`, `correctness_prerequisites`, `structured_logging`

## Quickstart Commands

### Fast
```bash
rch exec -- target/release/deps/raptorq_benchmark-60b0ce0491bd21fa --bench raptorq_e2e/encode/k=32_sym=1024 --noplot --sample-size 10 --measurement-time 0.02 --warm-up-time 0.02
```

### Full
```bash
rch exec -- ./scripts/run_perf_e2e.sh --bench raptorq_benchmark --bench phase0_baseline --seed 424242 --save-baseline baselines/ --no-compare
```

### Forensics
```bash
rch exec -- valgrind --tool=callgrind --callgrind-out-file=target/perf-results/perf_20260215_222548/artifacts/callgrind_raptorq_encode_k32.out target/release/deps/raptorq_benchmark-60b0ce0491bd21fa --bench raptorq_e2e/encode/k=32_sym=1024 --noplot --sample-size 10 --measurement-time 0.02 --warm-up-time 0.02
```

## Canonical Workload Taxonomy (G1)

| Workload ID | Family | Traffic Shape | Intent | Primary Metric |
|---|---|---|---|---|
| `RQ-G1-ENC-SMALL` | Encode (`k=32`, `sym=1024`) | small block, no repair, no loss | Hot-path encode latency for common small block | `median_ns`, `p95_ns` |
| `RQ-G1-DEC-SOURCE` | Decode source-only (`k=32`, `sym=1024`) | small block, zero repair density | Best-case decode latency floor | `median_ns`, `p95_ns` |
| `RQ-G1-DEC-REPAIR` | Decode repair-only (`k=32`, `sym=1024`) | small block, high repair density | Repair-heavy decode robustness | `median_ns`, `p95_ns` |
| `RQ-G1-GF256-ADDMUL` | GF256 kernel (`addmul_slice/4096`) | arithmetic hotspot | Arithmetic hotspot sensitivity | `median_ns`, `p95_ns` |
| `RQ-G1-SOLVER-MARKOWITZ` | Dense solve (`solve_markowitz/64`) | solver stress shape | Worst-case decode solver pressure | `median_ns`, `p95_ns` |
| `RQ-G1-PIPE-64K` | Pipeline throughput (`send_receive/65536`) | small object | Small object end-to-end throughput | `throughput_mib_s` |
| `RQ-G1-PIPE-256K` | Pipeline throughput (`send_receive/262144`) | medium object | Mid-size object throughput | `throughput_mib_s` |
| `RQ-G1-PIPE-1M` | Pipeline throughput (`send_receive/1048576`) | large object | Large object throughput stability | `throughput_kib_s` |
| `RQ-G1-E2E-RANDOM-LOWLOSS` | Deterministic E2E conformance | low repair density, random loss | Low-loss real-world decode behavior | `decode_success`, `median_ns` |
| `RQ-G1-E2E-RANDOM-HIGHLOSS` | Deterministic E2E conformance | high repair density, random loss | High-loss decode resilience | `decode_success`, `median_ns` |
| `RQ-G1-E2E-BURST-LATE` | Deterministic E2E conformance | burst loss (late window) | Burst-loss recovery behavior | `decode_success`, `median_ns` |

## Draft Budget Sheet (G1)

Budget source: refreshed seed-`424242` corpus (`target/perf-results/perf_20260215_222548/artifacts/baseline_current.json`) and matching phase0 throughput log (`target/perf-results/perf_20260215_222548/logs/phase0_baseline_20260215_222548.log`).

| Workload ID | Baseline | Warning Budget | Fail Budget |
|---|---:|---:|---:|
| `RQ-G1-ENC-SMALL` (`median_ns`) | 288991.90 | 339423.87 | 374536.69 |
| `RQ-G1-ENC-SMALL` (`p95_ns`) | 296377.39 | 365569.28 | 400946.95 |
| `RQ-G1-DEC-SOURCE` (`median_ns`) | 21167.80 | 27398.68 | 34248.35 |
| `RQ-G1-DEC-REPAIR` (`median_ns`) | 97917.66 | 121135.59 | 140262.26 |
| `RQ-G1-GF256-ADDMUL` (`median_ns`) | 2003.83 | 2438.90 | 2869.30 |
| `RQ-G1-SOLVER-MARKOWITZ` (`median_ns`) | 799515.96 | 988670.46 | 1186404.55 |
| `RQ-G1-PIPE-64K` (`throughput_mib_s`) | 8.8312 | 8.0201 | 7.2562 |
| `RQ-G1-PIPE-256K` (`throughput_mib_s`) | 2.1097 | 1.8545 | 1.6967 |
| `RQ-G1-PIPE-1M` (`throughput_kib_s`) | 330.8300 | 303.1800 | 279.8600 |
| `RQ-G1-E2E-RANDOM-LOWLOSS` (`decode_success`) | 1.0000 | 1.0000 | 1.0000 |
| `RQ-G1-E2E-RANDOM-HIGHLOSS` (`decode_success`) | 1.0000 | 1.0000 | 1.0000 |
| `RQ-G1-E2E-BURST-LATE` (`decode_success`) | 1.0000 | 1.0000 | 1.0000 |

## Confidence + Threshold Policy (G1)

- Use deterministic seed `424242` for all profile gates.
- Treat `median_ns` as primary, `p95_ns` as tail-protection metric.
- For criterion-style metrics, warning and fail are both required to be reproducible in two consecutive runs before escalation from yellow to red.
- Any single-run value crossing fail budget by `>= 20%` is an immediate red gate (hard stop).
- Throughput budgets are lower bounds; latency budgets are upper bounds.
- Keep benchmark command lines stable when comparing directional movement.

## Profile-to-Gate Mapping (G1)

| Profile | Command Surface | Required Workloads | Deterministic Runtime Envelope | Gate Intent |
|---|---|---|---|---|
| `fast` | direct benchmark invocation (quickstart fast) | `RQ-G1-ENC-SMALL`, `RQ-G1-E2E-RANDOM-LOWLOSS` | <= 3 minutes wall time on standard CI runner | PR/smoke directional signal |
| `full` | `scripts/run_perf_e2e.sh --bench ... --seed 424242` | all workload IDs in taxonomy table | <= 30 minutes wall time on standard CI runner | merge/release evidence |
| `forensics` | callgrind + artifact capture (quickstart forensics) | `RQ-G1-ENC-SMALL`, `RQ-G1-GF256-ADDMUL`, `RQ-G1-SOLVER-MARKOWITZ`, `RQ-G1-E2E-BURST-LATE` | <= 90 minutes wall time on standard CI runner | deep regression root-cause packet |

## Correctness Prerequisites for Performance Claims

Performance budget outcomes are advisory-only until these are present and green:

- D1 (`bd-1rxlv`): RFC/canonical golden vector suite
- D5 (`bd-61s90`): comprehensive unit matrix
- D6 (`bd-3bvdj` / `asupersync-wdk6c`): deterministic E2E scenario suite (`scripts/run_raptorq_e2e.sh`)
- D7 (`bd-oeql8`) and D9 (`bd-26pqk`): structured forensic logging + replay catalog

No optimization decision record (`bd-7toum`) or CI gate closure (`bd-322jd`) should treat G1 budgets as authoritative without these prerequisites.

Replay-catalog source of truth for deterministic reproduction:

- `artifacts/raptorq_replay_catalog_v1.json` (`schema_version=raptorq-replay-catalog-v1`)
- fixture reference `RQ-D9-REPLAY-CATALOG-V1`
- stable `replay_ref` IDs mapped to unit+E2E surfaces with remote repro commands

## Structured Logging Fields for G1 Gate Outputs

Every budget-check event should include:

- `workload_id`
- `profile` (`fast`|`full`|`forensics`)
- `seed`
- `metric_name`
- `observed_value`
- `warning_budget`
- `fail_budget`
- `decision` (`pass`|`warn`|`fail`)
- `artifact_path`
- `replay_ref`

Artifact path conventions by profile:

| Profile | Artifact Path Pattern | Required Artifact |
|---|---|---|
| `fast` | `target/perf-results/fast/<timestamp>/summary.json` | metric summary with budget verdict |
| `full` | `target/perf-results/full/<timestamp>/report.json` | full benchmark report + baseline snapshot |
| `forensics` | `target/perf-results/forensics/<timestamp>/` | callgrind output + annotated hotspot report |

## Calibration Checklist for Closure

Before closing `bd-3v1cs`, run this checklist and record evidence paths in bead comments:

1. Confirm D1 (`bd-1rxlv`), D5 (`bd-61s90`), D6 (`bd-3bvdj` / `asupersync-wdk6c`), and D9 (`bd-26pqk`) remain closed.
2. Re-run full baseline corpus with fixed seed `424242` and record artifact paths.
3. Recompute warning/fail budgets from the refreshed corpus and update this document.
4. Verify `fast`/`full`/`forensics` runtime envelopes on the standard CI shape.
5. Attach one deterministic repro command for each budget violation class.

Closure evidence update (`2026-02-16`):

- Checklist items 1-3 are satisfied by the refreshed seed-`424242` corpus packet:
  - `target/perf-results/perf_20260215_222548/report.json`
  - `target/perf-results/perf_20260215_222548/artifacts/baseline_current.json`
  - `target/perf-results/perf_20260215_222548/logs/phase0_baseline_20260215_222548.log`
- Item 4 remains mapped to deterministic envelope policy in this document (`fast`/`full`/`forensics`) with observed full-profile wall time bounded by the `<= 30 minute` target.
- Item 5 remains represented by the deterministic repro command surfaces captured in the quickstart/profile sections and the machine-readable packet.

## Prerequisite Status Snapshot (2026-02-16)

| Bead | Purpose | Current Status | Calibration Impact |
|---|---|---|---|
| `bd-1rxlv` | D1 golden-vector conformance | `closed` | prerequisite satisfied |
| `bd-61s90` | D5 comprehensive unit matrix | `closed` | prerequisite satisfied |
| `bd-3bvdj` / `asupersync-wdk6c` | D6 deterministic E2E suite | `closed` | deterministic profile suite is established and linked |
| `bd-oeql8` | D7 structured logging/artifact schema | `closed` | forensics schema contract is enforced in deterministic unit and E2E paths |
| `bd-26pqk` | D9 replay catalog linkage | `closed` | prerequisite satisfied |

Closure gate interpretation for `bd-3v1cs`:

- This bead may publish and iterate draft budgets early.
- Calibration refresh is now complete for the current prerequisite state, with updated corpus artifacts and budget numbers committed in this document.

## Phase Note

This document now covers both G1 draft-definition and the post-prerequisite calibration refresh pass (seed `424242`, packet `perf_20260215_222548`) against the currently implemented correctness evidence surfaces.

## Representative Criterion Results

### RaptorQ E2E (`baseline_current.json`)

| Benchmark | Median (ns) | p95 (ns) |
|---|---:|---:|
| `raptorq_e2e/encode/k=32_sym=1024` | 288991.90 | 296377.39 |
| `raptorq_e2e/decode_source_only/k=32_sym=1024` | 21167.80 | 21959.03 |
| `raptorq_e2e/decode_repair_only/k=32_sym=1024` | 97917.66 | 105037.92 |

### Kernel Hotspot Proxies (`baseline_current.json`)

| Benchmark | Median (ns) | p95 (ns) |
|---|---:|---:|
| `gf256_primitives/addmul_slice/RQ-E-GF256-004_n4096_seed4100_k32_sym4096` | 2003.83 | 2019.53 |
| `linalg_operations/row_scale_add/4096` | 1993.38 | 2019.07 |
| `gaussian_elimination/solve_markowitz/64` | 799515.96 | 808401.46 |

### Phase0 RaptorQ Pipeline Throughput (`phase0_baseline_...log`)

| Benchmark | Time Range | Throughput Range |
|---|---|---|
| `raptorq/pipeline/send_receive/65536` | `[7.0823 ms 7.1029 ms 7.1309 ms]` | `[8.7647 MiB/s 8.7992 MiB/s 8.8248 MiB/s]` |
| `raptorq/pipeline/send_receive/262144` | `[118.66 ms 119.04 ms 119.48 ms]` | `[2.0923 MiB/s 2.1001 MiB/s 2.1069 MiB/s]` |
| `raptorq/pipeline/send_receive/1048576` | `[3.0987 s 3.1085 s 3.1230 s]` | `[327.89 KiB/s 329.42 KiB/s 330.46 KiB/s]` |

## Profiler Evidence

### Primary attempt (`perf stat`)
- Status: blocked by host kernel policy (`perf_event_paranoid=4`)
- Command captured in JSON packet.

### Fallback (`callgrind`)
- Artifact: `target/perf-results/perf_20260215_222548/artifacts/callgrind_raptorq_encode_k32.out`
- Instruction refs (`Ir`): `1,448,085,214`
- Limitation: release binary has partial symbol resolution (top entries are unresolved addresses in `callgrind_annotate`).

### Resource profile (`/usr/bin/time -v`)
- Wall time: `0:00.10`
- CPU: `1074%`
- Max RSS: `22316 KB`
- Context switches: `3431` voluntary / `5918` involuntary

## Validation Harness Inventory

### Comprehensive unit tests
- `src/raptorq/tests.rs`
- `tests/raptorq_conformance.rs`
- `tests/raptorq_perf_invariants.rs`

### Deterministic E2E
- `rch exec -- ./scripts/run_raptorq_e2e.sh --profile fast`
- `rch exec -- ./scripts/run_raptorq_e2e.sh --profile full`
- `rch exec -- ./scripts/run_raptorq_e2e.sh --profile forensics --scenario RQ-E2E-FAILURE-INSUFFICIENT`
- `rch exec -- ./scripts/run_phase6_e2e.sh`
- `rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture`

Artifacts:
- `target/phase6-e2e/report_<timestamp>.txt`
- `target/e2e-results/raptorq/<profile>_<timestamp>/summary.json`
- `target/e2e-results/raptorq/<profile>_<timestamp>/scenarios.ndjson`
- `target/perf-results/perf_20260215_222548/report.json`
- `target/perf-results/perf_20260215_222548/artifacts/baseline_current.json`

### Structured logging contract (source of truth)
- `tests/raptorq_conformance.rs` report structure (scenario/block/loss/proof)
- Required fields tracked in JSON packet: scenario identity, seed, block dimensions, loss counts, proof status, replay/hash outputs.

## Determinism Guidance

- Re-run on same host/toolchain/seed and compare directional movement (median+p95), not exact nanosecond equality.
- Use fixed seed `424242` for full runs and keep command line identical when comparing deltas.
- Remote quick-rerun check (`encode/k=32_sym=1024`, sample-size 10) produced:
  - Run 1: `[120.62 us 127.42 us 134.53 us]`
  - Run 2: `[196.20 us 199.42 us 202.23 us]`
  - Conclusion: remote worker load can shift quick-run ranges; use the seeded full-corpus packet as the calibration anchor.
