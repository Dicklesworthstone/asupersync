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

Budget source: `baseline_current.json` and phase0 throughput logs listed above. Values below are draft guardrails for CI profile wiring and should be recalibrated with a refreshed post-D7 corpus.

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
- D6 (`bd-3bvdj` / `asupersync-wdk6c`): deterministic E2E scenario suite (`scripts/run_raptorq_e2e.sh`)
- D7 (`bd-oeql8`) and D9 (`bd-26pqk`): structured forensic logging + replay catalog

Optimization decision records for `bd-7toum` now live at:

- `artifacts/raptorq_optimization_decision_records_v1.json`
- `docs/raptorq_optimization_decision_records.md`

These records are still phased: treat G1 budgets as non-authoritative until those cards include final measured evidence and rollback-rehearsal outcomes for all in-scope runtime levers, and CI gate closure (`bd-322jd`) is complete.

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

### E4 Dual-Policy Probe Logging (`asupersync-348uw`)

Track-E dual-lane policy probes are emitted from `benches/raptorq_benchmark.rs` under benchmark group `gf256_dual_policy`:

```bash
rch exec -- cargo bench --bench raptorq_benchmark -- gf256_dual_policy
```

Probe log schema:

- `schema_version = raptorq-track-e-dual-policy-probe-v5`
- `manifest_schema_version`, `profile_schema_version`
- `scenario_id`, `seed`
- `kernel`, `architecture_class`, `active_profile_architecture_class`
- `target_arch`, `target_os`, `target_env`, `target_endian`, `target_pointer_width_bits`
- `mode`, `profile_pack`, `profile_fallback_reason`
- `rejected_profile_packs` lists every non-selected pack id for the active profile selection
- `profile_catalog_count`, `tuning_candidate_catalog_count`
- `tuning_corpus_id`
- `profile_pack_env_requested`
- `mul_min_total_env_override`, `mul_max_total_env_override`
- `addmul_min_total_env_override`, `addmul_max_total_env_override`, `addmul_min_lane_env_override`
- `max_lane_ratio_env_override`
- `selected_tuning_candidate_id`, `rejected_tuning_candidate_ids`
- `command_bundle` keeps the manifest-side `gf256_primitives` comparator bundle distinct from the probe `repro_command`
- `replay_pointer`
- `lane_len_a`, `lane_len_b`, `total_len`, `lane_ratio`
- `mul_window_min`, `mul_window_max`
- `addmul_window_min`, `addmul_window_max`, `addmul_min_lane`
- `max_lane_ratio`
- `mul_decision`, `mul_decision_reason`
- `addmul_decision`, `addmul_decision_reason`
- `decision_artifact_id`, `decision_role`
- `decision_evidence_status`
- `selected_candidate_summary`, `rejected_candidate_set_summary`
- `selected_mul_delta_vs_baseline_pct`
- `selected_addmul_delta_vs_baseline_pct`
- `selected_targeted_addmul_average_delta_pct`
- `artifact_path`, `repro_command`

Override truthfulness rule:

- if forced mode or numeric `ASUPERSYNC_GF256_*` window overrides mutate the live contract, the manifest/probe surface must fail closed instead of pretending the run still matches the catalog default
- override runs therefore scrub canonical selection provenance to `selected_tuning_candidate_id = manual-env-override-unbacked`,
  `decision_role = runtime_override_not_canonical_profile_selection`,
  `decision_artifact_id = manual_env_override_unbacked`,
  `decision_evidence_status = runtime-override-unbacked`,
  `replay_pointer = replay:rq-e-gf256-profile-pack-env-override-v1`
  and an override-specific `command_bundle` placeholder:
  `rch exec -- env <captured ASUPERSYNC_GF256_* override fields> cargo bench --bench raptorq_benchmark -- gf256_primitives`
  that tells operators to replay from the emitted override fields

Coverage intent:

- balanced lanes below/at/above fused windows
- asymmetric lanes near and beyond ratio threshold
- deterministic evidence for when auto policy selects fused vs sequential dual kernels

Command-surface split:

- Comparator/rollback bundle: manifest-level `command_bundle` in the profile-pack
  snapshot remains anchored to `rch exec -- cargo bench --bench raptorq_benchmark -- gf256_primitives`.
- Probe-specific bundle: the dual-policy log `repro_command` remains anchored to
  `rch exec -- cargo bench --bench raptorq_benchmark -- gf256_dual_policy`.

Current default policy note (profile-pack schema v5):

- `x86-avx2-balanced-v1` is split-biased for `mul_slices2` (`mul_window_min > mul_window_max`), so auto mode keeps dual-mul on the sequential path by default.
- `addmul_slices2` uses the bounded fused window (`24576..32768`, lane floor `8192`) from the 2026-03-04 deterministic corpus refresh, preserving balanced-lane gains while filtering asymmetric/small-lane regressions.
- Schema v5 is additive over v4: the profile-pack and dual-policy log surfaces now carry explicit `decision_evidence_status`, while the replay pointer remains `replay:rq-e-gf256-profile-pack-v3` because the tuned window/corpus contract itself did not change.
- The live manifest/log surface now carries the same decision anchor as the checked-in Track-E artifact:
  `decision_artifact_id = simd_policy_ablation_2026_03_04`,
  `decision_role = canonical_current_x86_default_contract`,
  `decision_evidence_status = canonical`,
  selected-candidate summary `material addmul auto uplift on balanced large-lane scenarios while mul auto remained near neutral`,
  and rejected-candidate-set summary `candidate mul windows improved addmul but regressed mul auto, so default rollout keeps mul auto disabled`.
- `aarch64-neon-balanced-v1` is intentionally surfaced as provisional rather than silently peer-equivalent to the x86 contract:
  `decision_artifact_id = pending_same_target_profile_ablation`,
  `decision_role = catalog_bootstrap_pending_same_target_ablation`,
  and `decision_evidence_status = pending-same-target-ablation`
  until same-target NEON ablation evidence lands.

### E5 Profile-Pack Capture (`asupersync-36m6p.1`, 2026-02-22)

Deterministic evidence packet for profile-pack behavior and dual-policy throughput deltas:

- `artifacts/raptorq_e5_profile_pack_benchmark_summary.md`
- `artifacts/e5_profile_pack_auto_capture.log`
- `artifacts/e5_profile_pack_sequential_capture.log`
- `artifacts/e5_profile_pack_fused_capture.log`

Capture command bundle (rch-only):

```bash
rch exec -- env ASUPERSYNC_GF256_DUAL_POLICY=auto ASUPERSYNC_GF256_PROFILE_PACK=auto \
  CARGO_TARGET_DIR=/tmp/rch-e5-qd cargo bench --bench raptorq_benchmark -- gf256_dual_policy \
  --sample-size 10 --warm-up-time 0.05 --measurement-time 0.08 \
  > artifacts/e5_profile_pack_auto_capture.log 2>&1

rch exec -- env ASUPERSYNC_GF256_DUAL_POLICY=sequential ASUPERSYNC_GF256_PROFILE_PACK=auto \
  CARGO_TARGET_DIR=/tmp/rch-e5-qd cargo bench --bench raptorq_benchmark -- gf256_dual_policy \
  --sample-size 10 --warm-up-time 0.05 --measurement-time 0.08 \
  > artifacts/e5_profile_pack_sequential_capture.log 2>&1

rch exec -- env ASUPERSYNC_GF256_DUAL_POLICY=fused ASUPERSYNC_GF256_PROFILE_PACK=auto \
  CARGO_TARGET_DIR=/tmp/rch-e5-qd cargo bench --bench raptorq_benchmark -- gf256_dual_policy \
  --sample-size 10 --warm-up-time 0.05 --measurement-time 0.08 \
  > artifacts/e5_profile_pack_fused_capture.log 2>&1
```

Observed host/profile snapshot in all three runs:

- `kernel = Scalar`
- `architecture_class = generic-scalar`
- `profile_pack = scalar-conservative-v1`
- `replay_pointer = replay:rq-e-gf256-profile-pack-v2`
- Historical note: this 2026-02-22 packet predates the later profile-pack
  schema/policy refresh. Current defaults and test contracts are anchored to
  `replay:rq-e-gf256-profile-pack-v3`.

Track-E/E5 interpretation: this packet validates deterministic profile-pack policy wiring and mode forcing, but does not yet prove SIMD-profile-pack material uplift because the active kernel path was scalar on these runs.

The benchmark artifact now marks the embedded scalar snapshot the same way,
instead of leaving that role implicit:

- `policy_snapshot_rq_e_gf256_005.snapshot_role = historical_pre_refresh_scalar_policy_wiring_reference`
- `policy_snapshot_rq_e_gf256_005.status = historical_reference_only`
- `policy_snapshot_rq_e_gf256_005.superseded_by_decision_packet = simd_policy_ablation_2026_03_04`
- `policy_snapshot_rq_e_gf256_005.replay_pointer = replay:rq-e-gf256-profile-pack-v1`

That packet is preserved for provenance only. It is not the current default
contract; the canonical current x86 default contract remains
`simd_policy_ablation_2026_03_04`.

### E5 SIMD A/B Ablation (`asupersync-36m6p`, 2026-03-02)

Follow-up same-session SIMD ablations were run via `rch` on `RQ-E-GF256-DUAL-006` (`lane_a=16384`, `lane_b=16384`) to reduce cross-worker noise:

```bash
rch exec -- bash -lc 'set -euo pipefail; COMMON="cargo bench --bench raptorq_benchmark --features simd-intrinsics -- RQ-E-GF256-DUAL-006 --sample-size 40 --warm-up-time 0.15 --measurement-time 0.18"; export CARGO_TARGET_DIR=/tmp/rch-e5-samesession; ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto $COMMON; ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL=24576 ASUPERSYNC_GF256_DUAL_ADDMUL_MAX_TOTAL=32768 ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_LANE=12288 $COMMON'

rch exec -- bash -lc 'set -euo pipefail; COMMON="cargo bench --bench raptorq_benchmark --features simd-intrinsics -- RQ-E-GF256-DUAL-006 --sample-size 40 --warm-up-time 0.15 --measurement-time 0.18"; export CARGO_TARGET_DIR=/tmp/rch-e5-samesession2; ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto $COMMON; ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto ASUPERSYNC_GF256_DUAL_MUL_MIN_TOTAL=32768 ASUPERSYNC_GF256_DUAL_MUL_MAX_TOTAL=32768 $COMMON'
```

Recorded in `artifacts/raptorq_track_e_gf256_bench_v1.json` under `simd_policy_ablation_2026_03_02`:

- Large balanced addmul window candidate (`addmul_total=24576..32768`, `addmul_min_lane=12288`) showed no meaningful `addmul_slices2_auto` uplift (`+0.1438%`, `p=0.82`) and regressed `mul_slices2_auto` (`+2.1554%` median).
- Mul-only window candidate (`mul_total=32768`) regressed `mul_slices2_auto` (`+0.6484%`, `p=0.02`) on the same scenario.

This 2026-03-02 packet is now explicitly a historical comparator, not the
current default contract. The artifact marks that machine-checkably via
`simd_policy_ablation_2026_03_02.decision.decision_artifact_id = simd_policy_ablation_2026_03_02`,
`simd_policy_ablation_2026_03_02.decision.decision_evidence_status = historical-reference`,
`simd_policy_ablation_2026_03_02.decision.supersession.status = superseded`
and
`simd_policy_ablation_2026_03_02.decision.supersession.superseded_by = simd_policy_ablation_2026_03_04`.

Updated decision after broader corpus (`simd_policy_ablation_2026_03_04`):

This default-selection result is recorded in
`artifacts/raptorq_track_e_gf256_bench_v1.json` under
`simd_policy_ablation_2026_03_04.decision` and is the canonical E5 artifact for
the current x86 auto-window contract.

The artifact now also pins the decision identity and maturity directly:
`simd_policy_ablation_2026_03_04.decision.decision_artifact_id = simd_policy_ablation_2026_03_04`,
`simd_policy_ablation_2026_03_04.decision.decision_role = canonical_current_x86_default_contract`
`simd_policy_ablation_2026_03_04.decision.decision_evidence_status = canonical`
and
`simd_policy_ablation_2026_03_04.decision.supersedes = ["simd_policy_ablation_2026_03_02"]`.

- Keep `mul` auto window disabled by default on x86 (`mul_min_total > mul_max_total`).
- Move x86 `addmul` auto window to `24576..32768` total bytes with `addmul_min_lane=8192`.
- Rationale: same-target deterministic corpus over `RQ-E-GF256-DUAL-*` showed strongest repeatable uplift in balanced high-throughput lanes (`DUAL-004/005/006`), with targeted `addmul_slices2_auto` median deltas of `-6.1424%`, `-14.4411%`, and `-6.3938%` versus baseline (`avg -8.9924%`).

Command bundle for the 2026-03-04 corpus:

```bash
rch exec -- bash -lc 'set -euo pipefail; export CARGO_TARGET_DIR=/tmp/rch-e5-20260304-dual; \
  ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto \
  cargo bench --bench raptorq_benchmark --features simd-intrinsics -- RQ-E-GF256-DUAL \
  --sample-size 20 --warm-up-time 0.1 --measurement-time 0.12'

rch exec -- bash -lc 'set -euo pipefail; export CARGO_TARGET_DIR=/tmp/rch-e5-20260304-dual; \
  ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto \
  ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL=24576 ASUPERSYNC_GF256_DUAL_ADDMUL_MAX_TOTAL=32768 \
  ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_LANE=8192 \
  cargo bench --bench raptorq_benchmark --features simd-intrinsics -- RQ-E-GF256-DUAL \
  --sample-size 20 --warm-up-time 0.1 --measurement-time 0.12'

rch exec -- bash -lc 'set -euo pipefail; export CARGO_TARGET_DIR=/tmp/rch-e5-20260304-dual; \
  ASUPERSYNC_GF256_PROFILE_PACK=auto ASUPERSYNC_GF256_DUAL_POLICY=auto \
  ASUPERSYNC_GF256_DUAL_MUL_MIN_TOTAL=24576 ASUPERSYNC_GF256_DUAL_MUL_MAX_TOTAL=30720 \
  ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL=24576 ASUPERSYNC_GF256_DUAL_ADDMUL_MAX_TOTAL=30720 \
  ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_LANE=8192 \
  cargo bench --bench raptorq_benchmark --features simd-intrinsics -- RQ-E-GF256-DUAL \
  --sample-size 20 --warm-up-time 0.1 --measurement-time 0.12'
```

### E5 High-Confidence Tail Closure Check (`asupersync-36m6p`, 2026-03-05)

`artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json` now exposes a
structured `closure_assessment` block so the Track-E closure state is machine
checkable rather than inferred from prose alone.

- `closure_assessment.ready_for_e5_closure = false`
- `closure_assessment.acceptance_criterion_4_status = not_met`
- `closure_assessment.material_uplift_demonstrated = false`
- `closure_assessment.overall_tail_direction_vs_baseline = regressed`
- `closure_assessment.operation_tail_pattern_vs_baseline = mixed`
- `closure_assessment.scope_sufficiency = insufficient`

Why this remains open:

- overall proxy auto tails are still above baseline on the narrowed
  high-confidence corpus (`p95/p99 = 9.3392 us` vs `9.0743 us`)
- operation-level proxy tails are mixed: `mul_slices2_fused`,
  `mul_slices2_sequential`, and `addmul_slices2_sequential` remain above
  baseline, while `addmul_slices2_fused` improves versus baseline
- the packet still covers only one closure-critical scenario, so it cannot
  substitute for the broader SIMD-active corpus required for AC#4 closure

Interpretation: this high-confidence packet is now a negative-evidence guardrail
against premature E5 closure. It proves the current narrowed corpus is not
enough to claim material uplift and therefore keeps `closure_assessment` in the
not-ready state until a broader SIMD-active multi-scenario refresh lands.

Contract note: `artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json` is
intentionally a narrowed single-scenario guardrail packet. Any broader
multi-scenario high-confidence refresh must publish a new artifact/schema
version rather than silently mutating this `highconf_v1` contract in place.

Scope boundary note: both `artifacts/raptorq_track_e_gf256_p95p99_v1.json`
and `artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json` intentionally
exclude `addmul_slices2_c1_auto` / `addmul_slices2_c1_sequential` from their
percentile-scored `operation_scope`. The `c==1` addmul fast path reuses
dual-add semantics and is covered separately by deterministic bench validation
via `addmul_slices2_c1_bit_exact` plus the dedicated benchmark IDs above.

### E5 Broader Multi-Scenario Guardrail Packets (`asupersync-36m6p`, 2026-03-21)

`artifacts/raptorq_track_e_gf256_multiscenario_refresh_v2.json` remains the
historical short-window directional packet for the seven-scenario
`RQ-E-GF256-DUAL-*` corpus already anchored in
`artifacts/raptorq_track_e_gf256_bench_v1.json` under
`simd_policy_ablation_2026_03_04`.

- `schema_version = raptorq-track-e-gf256-multiscenario-refresh-v2`
- `evidence_role = broader_multiscenario_directional_refresh`
- `scope_contract = same_target_multi_scenario_directional_corpus`
- `confidence_contract = short_window_directional_not_closure_grade`
- selected candidate remains `candidate_addmul_window_only`

`artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json` is now the
current broader longer-window negative-guardrail packet for the eight-scenario
`RQ-E-GF256-DUAL-001..008` corpus.

- `schema_version = raptorq-track-e-gf256-multiscenario-refresh-v3`
- `evidence_role = broader_multiscenario_longer_window_guardrail`
- `scope_contract = same_target_multi_scenario_longer_window_corpus`
- `confidence_contract = longer_window_interval_proxy_negative_guardrail`
- `successor_policy = requires_new_artifact_version_for_raw_sample_positive_retest_or_profile_contract_change`
- scenario scope widens to `RQ-E-GF256-DUAL-001..008`
- selected candidate remains `candidate_addmul_window_only`
- canonical current x86 default contract remains:
  - `mul_window = unchanged: disabled (mul_min_total > mul_max_total)`
  - `addmul_window = 24576..32768 total bytes`
  - `addmul_min_lane = 8192`

Interpretation: these broader packets complement rather than replace
`highconf_v1`. The narrowed guardrail still owns the live closure-status check
(`ready_for_e5_closure = false`). `multiscenario_refresh_v2` preserves the
historical short-window directional read, while `multiscenario_refresh_v3`
keeps the current broader longer-window negative result machine-checkable:
overall broader-corpus percentile proxies still regress under auto, so the
broader packet remains a guardrail rather than closure-grade proof.

Closure consequence:

- `artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json` remains the
  narrowed negative-evidence guardrail for the current not-ready state
- `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v2.json` remains the
  historical broader directional packet
- `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json` is the
  current broader longer-window negative guardrail and still keeps
  `ready_for_e5_closure = false`
- a future closure attempt still needs raw-sample or materially better broader
  evidence and must publish a new artifact/schema version rather than mutating
  any checked-in packet in place

## Calibration Checklist for Closure

Before closing `bd-3v1cs`, run this checklist and record evidence paths in bead comments:

1. Confirm D1 (`bd-1rxlv`), D5 (`bd-61s90`), D6 (`bd-3bvdj` / `asupersync-wdk6c`), and D9 (`bd-26pqk`) remain closed.
2. Re-run full baseline corpus with fixed seed `424242` and record artifact paths.
3. Recompute warning/fail budgets from the refreshed corpus and update this document.
4. Verify `fast`/`full`/`forensics` runtime envelopes on the standard CI shape.
5. Attach one deterministic repro command for each budget violation class.

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
- Final closure requires a calibration refresh with updated corpus artifacts and budget numbers committed in this document.

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
- `rch exec -- ./scripts/run_raptorq_e2e.sh --profile fast`
- `rch exec -- ./scripts/run_raptorq_e2e.sh --profile full`
- `rch exec -- ./scripts/run_raptorq_e2e.sh --profile forensics --scenario RQ-E2E-FAILURE-INSUFFICIENT`
- `rch exec -- ./scripts/run_phase6_e2e.sh`
- `rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture`

Artifacts:
- `target/phase6-e2e/report_<timestamp>.txt`
- `target/e2e-results/raptorq/<profile>_<timestamp>/summary.json`
- `target/e2e-results/raptorq/<profile>_<timestamp>/scenarios.ndjson`
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
