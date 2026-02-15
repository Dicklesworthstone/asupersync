# RaptorQ Baseline Bench/Profile Corpus (bd-3s8zu) + G1 Budgets (bd-3v1cs)

This document records the deterministic baseline packet for the RaptorQ RFC-6330 program track.

- Bead: `bd-3s8zu`
- Artifact JSON: `artifacts/raptorq_baseline_bench_profile_v1.json`
- Replay catalog artifact: `artifacts/raptorq_replay_catalog_v1.json`
- Baseline run report: `target/perf-results/perf_20260214_143734/report.json`
- Baseline metric snapshot: `target/perf-results/perf_20260214_143734/artifacts/baseline_current.json`
- Git SHA: `621e54283fef7b81101ad8af8b0aab2444279551`
- Seed: `424242`

This artifact now also carries the Track-G budget draft for bead `bd-3v1cs`:

- Workload taxonomy for `fast` / `full` / `forensics`
- Draft SLO budgets and regression thresholds
- Deterministic evaluation and confidence policy
- Gate-profile mapping tied to correctness evidence

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
rch exec -- valgrind --tool=callgrind --callgrind-out-file=target/perf-results/perf_20260214_143734/artifacts/callgrind_raptorq_encode_k32.out target/release/deps/raptorq_benchmark-60b0ce0491bd21fa --bench raptorq_e2e/encode/k=32_sym=1024 --noplot --sample-size 10 --measurement-time 0.02 --warm-up-time 0.02
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

Budget source: `baseline_current.json` and phase0 throughput logs listed above. Values below are draft guardrails for CI profile wiring and should be recalibrated after D1/D5/D6 evidence is fully green.

| Workload ID | Baseline | Warning Budget | Fail Budget |
|---|---:|---:|---:|
| `RQ-G1-ENC-SMALL` (`median_ns`) | 123455.74 | 145000.00 | 160000.00 |
| `RQ-G1-ENC-SMALL` (`p95_ns`) | 125662.90 | 155000.00 | 170000.00 |
| `RQ-G1-DEC-SOURCE` (`median_ns`) | 18542.03 | 24000.00 | 30000.00 |
| `RQ-G1-DEC-REPAIR` (`median_ns`) | 76791.45 | 95000.00 | 110000.00 |
| `RQ-G1-GF256-ADDMUL` (`median_ns`) | 698.37 | 850.00 | 1000.00 |
| `RQ-G1-SOLVER-MARKOWITZ` (`median_ns`) | 606508.43 | 750000.00 | 900000.00 |
| `RQ-G1-PIPE-64K` (`throughput_mib_s`) | 11.5620 | 10.5000 | 9.5000 |
| `RQ-G1-PIPE-256K` (`throughput_mib_s`) | 2.6734 | 2.3500 | 2.1500 |
| `RQ-G1-PIPE-1M` (`throughput_kib_s`) | 354.6400 | 325.0000 | 300.0000 |
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
- D6 (`bd-3bvdj`): deterministic E2E scenario suite
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

1. Confirm D1 (`bd-1rxlv`), D5 (`bd-61s90`), and D6 (`bd-3bvdj`) are green in CI.
2. Re-run full baseline corpus with fixed seed `424242` and record artifact paths.
3. Recompute warning/fail budgets from the refreshed corpus and update this document.
4. Verify `fast`/`full`/`forensics` runtime envelopes on the standard CI shape.
5. Attach one deterministic repro command for each budget violation class.

## Prerequisite Status Snapshot (2026-02-15)

| Bead | Purpose | Current Status | Calibration Impact |
|---|---|---|---|
| `bd-1rxlv` | D1 golden-vector conformance | `closed` | prerequisite satisfied |
| `bd-61s90` | D5 comprehensive unit matrix | `open` | unit-coverage evidence still partial for closure |
| `bd-3bvdj` | D6 deterministic E2E suite | `open` | E2E profile coverage not fully closed |
| `bd-oeql8` | D7 structured logging/artifact schema | `open` | forensics schema contract still pending closure |
| `bd-26pqk` | D9 replay catalog linkage | `open` | replay catalog delivered but bead not closed yet |

Closure gate interpretation for `bd-3v1cs`:

- This bead may publish and iterate draft budgets early.
- Final closure requires a post-D5/D6/D7/D9 calibration pass with refreshed corpus artifacts and updated budget numbers committed in this document.

## Phase Note

This document satisfies the G1 draft-definition phase (workload taxonomy + budget scaffolding + gate mapping). Final bead closure requires calibration refresh against fully implemented golden-vector correctness evidence and stabilized baseline corpus runs.

## Representative Criterion Results

### RaptorQ E2E (`baseline_current.json`)

| Benchmark | Median (ns) | p95 (ns) |
|---|---:|---:|
| `raptorq_e2e/encode/k=32_sym=1024` | 123455.74 | 125662.90 |
| `raptorq_e2e/decode_source_only/k=32_sym=1024` | 18542.03 | 18995.61 |
| `raptorq_e2e/decode_repair_only/k=32_sym=1024` | 76791.45 | 81979.41 |

### Kernel Hotspot Proxies (`baseline_current.json`)

| Benchmark | Median (ns) | p95 (ns) |
|---|---:|---:|
| `gf256_primitives/addmul_slice/4096` | 698.37 | 797.90 |
| `linalg_operations/row_scale_add/4096` | 717.42 | 1246.28 |
| `gaussian_elimination/solve_markowitz/64` | 606508.43 | 610781.32 |

### Phase0 RaptorQ Pipeline Throughput (`phase0_baseline_...log`)

| Benchmark | Time Range | Throughput Range |
|---|---|---|
| `raptorq/pipeline/send_receive/65536` | `[5.3824 ms 5.4056 ms 5.4248 ms]` | `[11.521 MiB/s 11.562 MiB/s 11.612 MiB/s]` |
| `raptorq/pipeline/send_receive/262144` | `[92.222 ms 93.515 ms 94.862 ms]` | `[2.6354 MiB/s 2.6734 MiB/s 2.7108 MiB/s]` |
| `raptorq/pipeline/send_receive/1048576` | `[2.8780 s 2.8874 s 2.8992 s]` | `[353.20 KiB/s 354.64 KiB/s 355.80 KiB/s]` |

## Profiler Evidence

### Primary attempt (`perf stat`)
- Status: blocked by host kernel policy (`perf_event_paranoid=4`)
- Command captured in JSON packet.

### Fallback (`callgrind`)
- Artifact: `target/perf-results/perf_20260214_143734/artifacts/callgrind_raptorq_encode_k32.out`
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
- `rch exec -- ./scripts/run_phase6_e2e.sh`
- `rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture`

Artifacts:
- `target/phase6-e2e/report_<timestamp>.txt`
- `target/perf-results/perf_20260214_143734/report.json`
- `target/perf-results/perf_20260214_143734/artifacts/baseline_current.json`

### Structured logging contract (source of truth)
- `tests/raptorq_conformance.rs` report structure (scenario/block/loss/proof)
- Required fields tracked in JSON packet: scenario identity, seed, block dimensions, loss counts, proof status, replay/hash outputs.

## Determinism Guidance

- Re-run on same host/toolchain/seed and compare directional movement (median+p95), not exact nanosecond equality.
- Use fixed seed `424242` for full runs and keep command line identical when comparing deltas.
- Same-host fast rerun check (`encode/k=32_sym=1024`, sample-size 10) produced:
  - Run 1: `[326.64 us 328.41 us 330.75 us]`
  - Run 2: `[328.09 us 329.94 us 332.57 us]`
  - Conclusion: median stayed near `~329 us`, so directional conclusions were stable.
