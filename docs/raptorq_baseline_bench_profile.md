# RaptorQ Baseline Bench/Profile Corpus (bd-3s8zu)

This document records the deterministic baseline packet for the RaptorQ RFC-6330 program track.

- Bead: `bd-3s8zu`
- Artifact JSON: `artifacts/raptorq_baseline_bench_profile_v1.json`
- Baseline run report: `target/perf-results/perf_20260214_143734/report.json`
- Baseline metric snapshot: `target/perf-results/perf_20260214_143734/artifacts/baseline_current.json`
- Git SHA: `621e54283fef7b81101ad8af8b0aab2444279551`
- Seed: `424242`

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
