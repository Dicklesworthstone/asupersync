# RaptorQ E5 Profile-Pack Benchmark Summary (2026-02-22)

Bead: `asupersync-36m6p.1`  
Parent: `asupersync-36m6p`

## Command Bundle (rch-only)

```bash
rch exec -- env ASUPERSYNC_GF256_DUAL_POLICY=auto ASUPERSYNC_GF256_PROFILE_PACK=auto \
  CARGO_TARGET_DIR=/tmp/rch-e5-qd cargo bench --features criterion-benches --bench raptorq_benchmark -- gf256_dual_policy \
  --sample-size 10 --warm-up-time 0.05 --measurement-time 0.08 \
  > artifacts/e5_profile_pack_auto_capture.log 2>&1

rch exec -- env ASUPERSYNC_GF256_DUAL_POLICY=sequential ASUPERSYNC_GF256_PROFILE_PACK=auto \
  CARGO_TARGET_DIR=/tmp/rch-e5-qd cargo bench --features criterion-benches --bench raptorq_benchmark -- gf256_dual_policy \
  --sample-size 10 --warm-up-time 0.05 --measurement-time 0.08 \
  > artifacts/e5_profile_pack_sequential_capture.log 2>&1

rch exec -- env ASUPERSYNC_GF256_DUAL_POLICY=fused ASUPERSYNC_GF256_PROFILE_PACK=auto \
  CARGO_TARGET_DIR=/tmp/rch-e5-qd cargo bench --features criterion-benches --bench raptorq_benchmark -- gf256_dual_policy \
  --sample-size 10 --warm-up-time 0.05 --measurement-time 0.08 \
  > artifacts/e5_profile_pack_fused_capture.log 2>&1
```

## Policy Snapshot (from probe JSON in each capture)

- `kernel = Scalar`
- `architecture_class = generic-scalar`
- `profile_pack = scalar-conservative-v1`
- `profile_fallback_reason = none`
- `replay_pointer = replay:rq-e-gf256-profile-pack-v1`
- `mul_window = [usize::MAX, 0]` and `addmul_window = [usize::MAX, 0]` in profile metadata

Implication: with `mode=Auto`, policy decisions are sequential by design on this host/build shape.

## Midpoint Throughput Delta Summary

Metric definition: midpoint GiB/s from Criterion `thrpt` line for `*_auto` vs `*_sequential_baseline` within the same run.

| Mode | Scenarios | Avg mul delta | Avg addmul delta |
|---|---:|---:|---:|
| `Auto` | 6 | `+5.76%` | `+2.55%` |
| `Sequential` | 6 | `-5.56%` | `+5.13%` |
| `Fused` | 6 | `+0.40%` | `+8.52%` |

Selected scenario examples:

- `RQ-E-GF256-DUAL-001` (`a=4096,b=4096`): fused `mul -5.60%`, fused `addmul +31.34%`
- `RQ-E-GF256-DUAL-004` (`a=12288,b=12288`): fused `mul +23.78%`, fused `addmul +0.66%`
- `RQ-E-GF256-DUAL-006` (`a=16384,b=16384`): fused `mul -2.14%`, fused `addmul -1.73%`

## Assessment

1. This evidence confirms deterministic policy wiring and mode forcing (`Auto`, `Sequential`, `Fused`) with stable schema metadata.
2. On this run shape, profile-pack behavior is scalar-only (`scalar-conservative-v1`), so architecture-profile-pack uplift claims remain unproven for SIMD paths.
3. Throughput deltas are mixed by scenario; no stable, materially positive fused uplift appears across all six dual-policy scenarios.

## Recommended Next Evidence Step for E5 Closure

Run the same command bundle on a build/worker shape where `simd-intrinsics` kernels are active, then compare:

- auto profile-pack vs sequential baseline
- forced fused vs sequential baseline
- p95/p99 stability for representative scenario families

without changing scenario seeds or benchmark matrix.
