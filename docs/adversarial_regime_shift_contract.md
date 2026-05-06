# Adversarial Regime-Shift Synthesizer Contract

Bead: `asupersync-1508v.6.7`

## Purpose

This contract defines a deterministic, budgeted search that synthesizes worst-case workloads and regime shifts from replay traces, control models, and invariants. Generated challenge cases feed back into the corpus used by the rest of the ascension program, making the runtime adversarially self-hardening.

## Contract Artifacts

1. Canonical artifact: `artifacts/adversarial_regime_shift_v1.json`
2. Smoke runner: `scripts/run_adversarial_regime_shift_smoke.sh`
3. Invariant suite: `tests/adversarial_regime_shift_contract.rs`

## Search Objectives

| Objective | Target Invariant | Severity |
|-----------|-----------------|----------|
| OBJ-TAIL-SLO-BREACH | p99 latency <= 500us | critical |
| OBJ-FAIRNESS-DRIFT | fairness_ratio >= 0.3 | critical |
| OBJ-AUTHORITY-EDGE | no invalid state transitions | high |
| OBJ-RECOVERY-EDGE | fallback clears after recovery | high |
| OBJ-WAKE-LOSS | lost_wakeup_count == 0 | critical |
| OBJ-OBLIGATION-LEAK | obligation_leak_count == 0 | critical |
| OBJ-DIAGNOSABILITY-LOSS | log_field_coverage >= 0.9 | medium |

Each objective specifies mutation axes (what to vary), a target invariant (what to violate), and severity (how urgently a violation must be addressed).

## Mutation Model

Mutations are deterministic: given a seed derived from `workload_id + objective_id + mutation_round`, all mutations are reproducible. The search operates under explicit budgets:

- Max mutations per run: 1000
- Max wall-clock time: 300 seconds
- Max workloads promoted: 50

Mutation axes include arrival rate, cancel fraction/timing, burst size, rollback timing, park/wake interleaving, bloom saturation pressure, region close timing, and others.

## Challenge Corpus Feedback

Promoted challenge cases must satisfy:

1. Reproducible (deterministic replay succeeds)
2. Minimized (no redundant mutation axes)
3. Targeted (specific objective with measurable violation)
4. Documented (human-readable rationale)

Promoted cases feed into: comparator tables, composition validation, CI regression suite, and closure artifacts.

## Structured Logging Contract

Synthesis logs MUST include: `search_run_id`, `objective_id`, `mutation_round`, `mutation_vector`, `seed`, `violation_detected`, `violation_value`, `violation_threshold`, `workload_id`, `challenge_id`, `promoted`, `minimization_rounds`, `wall_clock_ms`, `budget_remaining`.

## Comparator-Smoke Runner

```bash
bash ./scripts/run_adversarial_regime_shift_smoke.sh --list
bash ./scripts/run_adversarial_regime_shift_smoke.sh --execute
```

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_adversarial_regime_shift cargo test -p asupersync --test adversarial_regime_shift_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/adversarial_regime_shift_v1.json`
- `artifacts/runtime_workload_corpus_v1.json` -- Source replay corpus
- `artifacts/digital_twin_v1.json` -- Twin stages for simulation
- `artifacts/runtime_control_seam_inventory_v1.json` -- Seam IDs
- `artifacts/bounded_controller_synthesis_v1.json` -- Controller domains
- `artifacts/replay_minimization_validation_contract_v1.json` -- Minimization
