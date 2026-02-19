# RaptorQ Comprehensive Unit Test Matrix (bd-61s90)

Scope: deterministic unit-test inventory for RaptorQ encoder/decoder/solver/GF256 surfaces, plus explicit linkage to deterministic E2E scenarios.

## Scenario IDs

Canonical deterministic scenario IDs used in this matrix:

- `RQ-U-HAPPY-SYSTEMATIC` (happy path, systematic/source-heavy decode)
- `RQ-U-HAPPY-REPAIR` (happy path, repair-driven decode)
- `RQ-U-BOUNDARY-TINY` (k=1, k=2, tiny symbol)
- `RQ-U-BOUNDARY-LARGE` (large k / large symbol)
- `RQ-U-ERROR-INSUFFICIENT` (insufficient symbol failure)
- `RQ-U-ERROR-SIZE-MISMATCH` (symbol size mismatch failure)
- `RQ-U-ADVERSARIAL-LOSS` (random/burst/adversarial loss)
- `RQ-U-DETERMINISM-SEED` (same-seed reproducibility)
- `RQ-U-DETERMINISM-PROOF` (proof replay/hash determinism)
- `RQ-U-LINALG-RANK` (solver rank/pivot behavior)
- `RQ-U-GF256-ALGEBRA` (field arithmetic invariants)

Deterministic E2E scenario IDs from `tests/raptorq_conformance.rs:1310`:

- `RQ-E2E-SYSTEMATIC-ONLY`
- `RQ-E2E-TYPICAL-RANDOM-LOSS`
- `RQ-E2E-BURST-LOSS-LATE`
- `RQ-E2E-INSUFFICIENT-SYMBOLS`

## Unit Coverage Matrix

| Module Family | Happy Path Coverage | Boundary Coverage | Adversarial/Error Coverage | Determinism Evidence | E2E Linkage | Structured Replay/Log Field Coverage | Status |
|---|---|---|---|---|---|---|---|
| Sender/Receiver builders + pipeline API | `src/raptorq/tests.rs:101`, `src/raptorq/tests.rs:268`, `src/raptorq/tests.rs:379` | empty payload + custom/default config: `src/raptorq/tests.rs:344`, `src/raptorq/tests.rs:320`, `src/raptorq/tests.rs:331` | oversized + cancellation + insufficient symbols: `src/raptorq/tests.rs:194`, `src/raptorq/tests.rs:226`, `src/raptorq/tests.rs:315` | deterministic emit/signing behavior covered via send-symbol paths | `RQ-E2E-SYSTEMATIC-ONLY`, `RQ-E2E-INSUFFICIENT-SYMBOLS` | builder-path unit failures emit schema-aligned context (`scenario_id`, `seed`, `parameter_set`, `replay_ref`) and map to D9 replay IDs | strong |
| Systematic parameter lookup + tuple/degree semantics | `src/raptorq/systematic.rs:1148`, `src/raptorq/systematic.rs:1159`, `tests/raptorq_conformance.rs:597` | k-small/large + overhead bounds: `src/raptorq/systematic.rs:1122`, `src/raptorq/systematic.rs:1135`, `tests/raptorq_conformance.rs:617` | distribution/edge handling: `src/raptorq/systematic.rs:1171`, `src/raptorq/systematic.rs:1250`, `tests/raptorq_conformance.rs:541` | same-seed deterministic checks: `src/raptorq/systematic.rs:1204`, `tests/raptorq_conformance.rs:573` | `RQ-E2E-SYSTEMATIC-ONLY`, `RQ-E2E-TYPICAL-RANDOM-LOSS` | systematic conformance/property/drop/fuzz vectors now emit schema-aligned context and resolve to D9 replay IDs | strong |
| Decoder equation reconstruction + decode semantics | roundtrip no-loss/repair-only: `tests/raptorq_conformance.rs:101`, `tests/raptorq_conformance.rs:155`, `src/raptorq/tests.rs:604` | tiny/large symbol, k=1/2: `tests/raptorq_conformance.rs:276`, `tests/raptorq_conformance.rs:293`, `src/raptorq/tests.rs:1080`, `src/raptorq/tests.rs:1337` | insufficient + size mismatch + random loss: `tests/raptorq_conformance.rs:374`, `tests/raptorq_conformance.rs:397`, `tests/raptorq_conformance.rs:469`, `src/raptorq/tests.rs:1276`, `src/raptorq/tests.rs:1301` | deterministic decode equality: `tests/raptorq_conformance.rs:217`, `tests/raptorq_conformance.rs:243` | all four E2E scenarios | structured report fields available in E2E suite (`tests/raptorq_conformance.rs:1181`) | strong |
| Solver/Linalg (pivot/rank/gaussian behavior) | gaussian solve sanity: `src/raptorq/linalg.rs:1056`, `src/raptorq/linalg.rs:1072` | empty rhs + 3x3/64-scale paths: `src/raptorq/linalg.rs:1109`, `src/raptorq/linalg.rs:1176`, perf invariants dense paths `tests/raptorq_perf_invariants.rs:732` | singular matrix + stats/pivot constraints: `src/raptorq/linalg.rs:1094`, `tests/raptorq_perf_invariants.rs:392`, `tests/raptorq_perf_invariants.rs:825` | deterministic stats/proof checks: `tests/raptorq_perf_invariants.rs:425`, `tests/raptorq_perf_invariants.rs:506` | `RQ-E2E-TYPICAL-RANDOM-LOSS`, `RQ-E2E-BURST-LOSS-LATE`, `RQ-E2E-INSUFFICIENT-SYMBOLS` | structured logging sentinel present (`tests/raptorq_perf_invariants.rs:667`) | strong |
| GF256 primitives + algebraic laws | algebra basics: `src/raptorq/gf256.rs:518`, `src/raptorq/gf256.rs:536`, `tests/raptorq_conformance.rs:636` | power/inverse edge behavior: `src/raptorq/gf256.rs:624`, `src/raptorq/gf256.rs:562` | distributive/associative/large input checks: `src/raptorq/gf256.rs:579`, `src/raptorq/gf256.rs:600`, `src/raptorq/gf256.rs:728` | deterministic table/roundtrip checks: `src/raptorq/gf256.rs:489`, `src/raptorq/gf256.rs:500` | indirectly exercised by all E2E scenarios | core-law, SIMD/scalar, nibble-table, dispatch, and dual-policy unit checks emit schema-aligned failure context and resolve to D9 replay IDs (`replay:rq-u-gf256-core-laws-v1`, `replay:rq-u-gf256-simd-scalar-equivalence-v1`, `replay:rq-u-gf256-nibble-table-v1`, `replay:rq-u-gf256-dual-policy-v1`) | strong |
| Proof/replay integrity | proof replay + hash determinism: `src/raptorq/proof.rs:687`, `src/raptorq/proof.rs:710`, `tests/raptorq_perf_invariants.rs:570` | mismatch detection boundary: `src/raptorq/proof.rs:754` | failure-path replay checks: `tests/raptorq_perf_invariants.rs:538` | deterministic content hash + replay passes | `RQ-E2E-SYSTEMATIC-ONLY`, `RQ-E2E-INSUFFICIENT-SYMBOLS` | structured proof metadata reported in E2E report JSON (`tests/raptorq_conformance.rs:1203`) | strong |

## Unit ↔ E2E Traceability

| Unit Scenario ID | Unit Sentinel Examples | Linked Deterministic E2E Scenario(s) |
|---|---|---|
| `RQ-U-HAPPY-SYSTEMATIC` | `tests/raptorq_conformance.rs:101`, `src/raptorq/tests.rs:217` | `RQ-E2E-SYSTEMATIC-ONLY` |
| `RQ-U-HAPPY-REPAIR` | `tests/raptorq_conformance.rs:155`, `src/raptorq/tests.rs:1243` | `RQ-E2E-TYPICAL-RANDOM-LOSS`, `RQ-E2E-BURST-LOSS-LATE` |
| `RQ-U-BOUNDARY-TINY` | `tests/raptorq_conformance.rs:276`, `tests/raptorq_conformance.rs:293`, `src/raptorq/tests.rs:1080` | `RQ-E2E-SYSTEMATIC-ONLY` |
| `RQ-U-BOUNDARY-LARGE` | `tests/raptorq_conformance.rs:348`, `src/raptorq/tests.rs:1167`, `src/raptorq/tests.rs:1337` | `RQ-E2E-TYPICAL-RANDOM-LOSS` |
| `RQ-U-ERROR-INSUFFICIENT` | `tests/raptorq_conformance.rs:374`, `src/raptorq/tests.rs:1276` | `RQ-E2E-INSUFFICIENT-SYMBOLS` |
| `RQ-U-ERROR-SIZE-MISMATCH` | `tests/raptorq_conformance.rs:397`, `src/raptorq/tests.rs:1301` | `RQ-E2E-INSUFFICIENT-SYMBOLS` (error-path schema parity) |
| `RQ-U-ADVERSARIAL-LOSS` | `tests/raptorq_conformance.rs:469`, `tests/raptorq_perf_invariants.rs:732` | `RQ-E2E-TYPICAL-RANDOM-LOSS`, `RQ-E2E-BURST-LOSS-LATE` |
| `RQ-U-DETERMINISM-SEED` | `tests/raptorq_conformance.rs:188`, `tests/raptorq_conformance.rs:573`, `src/raptorq/tests.rs:773` | all E2E scenarios (deterministic double-run contract) |
| `RQ-U-DETERMINISM-PROOF` | `tests/raptorq_perf_invariants.rs:506`, `tests/raptorq_perf_invariants.rs:570` | all E2E scenarios via `e2e_pipeline_reports_are_deterministic` |

## G1 Workload Linkage

The G1 workload taxonomy in `docs/raptorq_baseline_bench_profile.md` maps to matrix/e2e coverage as follows:

| G1 Workload ID | Deterministic Evidence Anchor |
|---|---|
| `RQ-G1-ENC-SMALL` | `tests/raptorq_conformance.rs:101`, `tests/raptorq_conformance.rs:188` |
| `RQ-G1-DEC-SOURCE` | `tests/raptorq_conformance.rs:101`, `tests/raptorq_conformance.rs:217` |
| `RQ-G1-DEC-REPAIR` | `tests/raptorq_conformance.rs:155`, `tests/raptorq_conformance.rs:469` |
| `RQ-G1-E2E-RANDOM-LOWLOSS` | `RQ-E2E-TYPICAL-RANDOM-LOSS` scenario run + deterministic report equality check |
| `RQ-G1-E2E-RANDOM-HIGHLOSS` | `tests/raptorq_perf_invariants.rs:732` adversarial-loss profile + E2E random-loss replay |
| `RQ-G1-E2E-BURST-LATE` | `RQ-E2E-BURST-LOSS-LATE` scenario run + deterministic report equality check |

## Structured Failure Logging Contract (D5-facing)

Current structured failure/logging anchors:

- `tests/raptorq_perf_invariants.rs:667` (`seed_sweep_structured_logging`)
- `tests/raptorq_conformance.rs:1181` report JSON includes scenario/block/loss/outcome/proof fields
- deterministic report equality assertion at `tests/raptorq_conformance.rs:1277`
- unit edge-case structured failure context helper and scenario-tagged assertions in `src/raptorq/tests.rs` (`failure_context`, happy/boundary decode success paths, `insufficient_symbols_error`, `symbol_size_mismatch_error`, `large_block_bounded`)

Required unit failure fields (for matrix governance):

- `scenario_id`
- `seed`
- `parameter_set` (`k`, `symbol_size`, overhead/repair profile)
- `replay_ref` (stable replay case ID)

Status:

- structured fields are fully present in deterministic E2E report flow
- unit-level structured context is present for edge-case paths, builder-path send/receive tests, systematic conformance/property/drop/fuzz vectors, and GF256 unit families included in this matrix; broader suite-wide replay-id propagation remains a D9 follow-up

## Replay Catalog (D9)

Canonical replay catalog artifact: `artifacts/raptorq_replay_catalog_v1.json`.

- Schema version: `raptorq-replay-catalog-v1`
- Fixture reference: `RQ-D9-REPLAY-CATALOG-V1`
- Stable replay IDs are tracked for both success and failure scenarios.
- Every catalog entry links:
  - at least one comprehensive unit test
  - at least one deterministic E2E script
  - a remote repro command (`rch exec -- ...`)

Profile tags represented in catalog entries:

- `fast`
- `full`
- `forensics`

## Deterministic E2E Script Suite (D6)

Deterministic scenario runner for D6:

- Script: `scripts/run_raptorq_e2e.sh`
- Machine-parseable artifacts:
  - `target/e2e-results/raptorq/<profile>_<timestamp>/summary.json`
  - `target/e2e-results/raptorq/<profile>_<timestamp>/scenarios.ndjson`
- Scenario records include:
  - `scenario_id`
  - `profile`
  - `category` (`happy`|`boundary`|`failure`|`composite`)
  - `replay_ref`
  - `unit_sentinel`
  - `assertion_id`
  - `run_id`
  - `seed`
  - `parameter_set`
  - `phase_markers`
  - `artifact_path`
  - `repro_command`

Profile coverage in the script suite:

- `fast`: happy smoke + tiny boundary + insufficient-symbol failure + deterministic report contract
- `full`: complete happy/boundary/failure matrix + deterministic report contract
- `forensics`: heavy-loss/hard-failure surfaces + deterministic report contract

## G6 Validation Report + Failure Triage Playbook

### Canonical one-command wrapper

```bash
# Fast smoke (recommended first pass)
NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile fast --bundle

# Full validation
NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile full --bundle

# Forensics validation
NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile forensics --bundle
```

Expected runtime guidance (with `rch` available; highly workload-dependent):

| Profile | Typical Runtime | Intended Use |
|---|---|---|
| `fast` | ~6-12 min | PR smoke gate and local confidence loop |
| `full` | ~12-25 min | pre-merge validation and deeper scenario coverage |
| `forensics` | ~18-35 min | incident triage, hard-loss/failure investigation |

### Human-friendly validation report template

Use this template for CI summaries, issue comments, or handoff notes.

```markdown
# RaptorQ Validation Report

- run_id: <profile_timestamp>
- profile: <fast|full|forensics>
- overall_status: <pass|fail|validation_failed>
- user_impact_summary: <one sentence: who is affected and how severe>

## Suite Summary
| Suite | Result | Notes |
|---|---|---|
| bundle-unit | <pass/fail/na> | stage_id=<...> |
| bundle-perf-smoke | <pass/fail/na> | stage_id=<...> |
| deterministic-e2e | <pass/fail> | passed=<n>, failed=<n> |
| conformance-path | <pass/fail> | scenario classes covered: happy/boundary/failure/composite |

## Artifacts
- summary: `target/e2e-results/raptorq/<run>/summary.json`
- scenarios: `target/e2e-results/raptorq/<run>/scenarios.ndjson`
- bundle stages: `target/e2e-results/raptorq/<run>/validation_stages.ndjson` (if bundled)
- failing scenario logs: `target/e2e-results/raptorq/<run>/<SCENARIO_ID>.log`

## Repro Commands
- full rerun: `NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile <profile> --bundle`
- focused rerun: `NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile <profile> --scenario <SCENARIO_ID> --bundle`
- CI gate replay: `rch exec -- cargo test --test ci_regression_gates -- --nocapture`

## First-response triage decision
- suspected class: <config|loss envelope|decode policy|kernel dispatch|cache/regime|infrastructure>
- first response action: <single action taken>
- next owner / follow-up bead: <id>
```

### Failure signature map (first-response)

| Signature | Likely Root-cause Class | First Response |
|---|---|---|
| `summary.status=validation_failed` with `failed_stage_id=unit-*` | deterministic unit regression | run failing stage `repro_command` from `validation_stages.ndjson`, then inspect `src/raptorq/tests.rs` and linked sentinel |
| `summary.status=validation_failed` with `failed_stage_id=bench-*` | perf-smoke tooling or kernel-path regression | run stage `repro_command`, inspect bench output for `profile_pack`, `mode`, fallback labels |
| scenario line has `status=fail` and `category=failure` but expected happy/boundary case failed | decode correctness regression | replay scenario `repro_command`, inspect scenario `seed`, `parameter_set`, `replay_ref` |
| repeated `policy_mode=conservative_baseline` under dense/high-loss runs | policy/feature extraction drift (F5/F6) | inspect `policy_*` and `regime_*` fields in decode stats; verify budget/fallback reasons |
| `factor_cache_hits=0` across repeated identical decodes | cache-key mismatch or disabled reuse (F7) | inspect `factor_cache_last_reason`, `factor_cache_last_reuse_eligible`, `factor_cache_last_key` |
| `hard_regime_fallbacks` spikes with `hard_regime_branch=block_schur_low_rank` | hard-regime branch instability (C5/C6/F8) | inspect `hard_regime_conservative_fallback_reason` and dense-core stats before tuning |

### Structured logging keys + replay lookup

Primary keys for triage:

- `summary.json`: `status`, `profile`, `validation_bundle`, `validation_stage_log`, `scenario_log`
- `scenarios.ndjson`: `scenario_id`, `category`, `status`, `seed`, `parameter_set`, `replay_ref`, `unit_sentinel`, `repro_command`, `artifact_path`
- `validation_stages.ndjson`: `stage_id`, `status`, `exit_code`, `duration_ms`, `artifact_path`, `repro_command`
- unit/e2e schema anchors: `src/raptorq/test_log_schema.rs` (`raptorq-unit-log-v1`, `raptorq-e2e-log-v1`)

Replay lookup workflow:

```bash
RUN_DIR=target/e2e-results/raptorq/<profile_timestamp>

# 1) list failing scenarios
jq -c 'select(.status=="fail") | {scenario_id, replay_ref, repro_command}' "$RUN_DIR/scenarios.ndjson"

# 2) resolve replay reference into D9 catalog metadata
REPLAY_REF="$(jq -r 'select(.status=="fail") | .replay_ref' "$RUN_DIR/scenarios.ndjson" | head -n1)"
jq -c --arg replay "$REPLAY_REF" '.entries[] | select(.replay_ref==$replay)' artifacts/raptorq_replay_catalog_v1.json
```

### Runtime-optimization diagnostics (E4/E5/C5/C6/F5/F6/F7/F8)

Use these signal keys during triage, especially when CI gate logs (`tests/ci_regression_gates.rs`) flag regressions.

| Lever | Primary Signal Keys | Interpretation |
|---|---|---|
| `E4` / `E5` | `profile_pack`, `architecture_class`, `profile_fallback_reason`, `mode` | verifies deterministic GF256 dispatch and fallback behavior |
| `C5` | `hard_regime_activated`, `hard_regime_branch`, `hard_regime_fallbacks` | verifies hard-regime activation and branch stability |
| `C6` | `dense_core_rows`, `dense_core_cols`, `gauss_ops`, `peeling_fallback_reason` | verifies dense-core path engagement under loss pressure |
| `F5` | `policy_mode`, `policy_reason`, `policy_baseline_loss`, `policy_high_support_loss`, `policy_block_schur_loss` | explains policy selection and expected-loss tradeoff |
| `F6` | `regime_state`, `regime_score`, `regime_retune_count`, `regime_rollback_count`, `regime_replay_ref` | verifies regime-shift detector dynamics and replayability |
| `F7` | `factor_cache_hits`, `factor_cache_misses`, `factor_cache_entries`, `factor_cache_capacity`, `factor_cache_last_reason` | verifies factor-cache effectiveness and boundedness |
| `F8` | combined view of `policy_*`, `hard_regime_*`, `factor_cache_*`, `regime_*` | verifies cross-lever composition and fallback safety |

## Gaps and Follow-ups

Open gaps identified during matrix pass:

1. D5 matrix rows are now `strong`; replay-log hygiene maintenance continues for D9-linked surfaces as suites evolve.
2. End-to-end structured-forensics evolution (beyond this unit matrix scope) remains tracked through D6 artifact maintenance.

Mapped follow-up beads:

- `bd-26pqk` (seed/fixture replay catalog)
- `bd-oeql8` (structured test logging schema)
- `bd-3bvdj` / `asupersync-wdk6c` (deterministic E2E scenario suite alignment)

## D5 Closure Gate

The D5 bead can close only when all of the following are true:

1. Every `partial` row in the Unit Coverage Matrix is upgraded to `strong` with concrete file+line evidence.
2. Every required unit failure path emits schema-aligned context fields:
   - `scenario_id`
   - `seed`
   - `parameter_set`
   - `replay_ref`
3. Every `replay_ref` referenced by unit failures resolves to an entry in `artifacts/raptorq_replay_catalog_v1.json`.
4. Unit↔E2E linkage remains canonical and deterministic (`RQ-E2E-*` IDs), with at least one deterministic E2E counterpart per unit scenario family.
5. Closure note includes reproducible `rch exec -- ...` commands and artifact paths used for final validation.

### Status Snapshot (2026-02-16)

| Bead | Scope | Current Status | Note for D5 Closure |
|---|---|---|---|
| `bd-61s90` | D5 comprehensive unit matrix | `closed` | matrix contract is accepted; continue maintenance as coverage evolves |
| `bd-26pqk` | D9 replay catalog | `closed` | replay catalog linkage is closed and remains a required reference |
| `bd-oeql8` | D7 structured logging schema | `closed` | schema contract enforcement is in place for deterministic unit + E2E paths |
| `bd-3bvdj` / `asupersync-wdk6c` | D6 deterministic E2E suite | `closed` | deterministic profile/scenario runner is in place and linked to unit families |

## Repro Commands

```bash
# Unit-heavy pass (focused)
rch exec -- cargo test --lib raptorq -- --nocapture

# Deterministic conformance scenario suite
rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture

# Deterministic D6 profile suite (staged unit + perf-smoke + E2E)
rch exec -- ./scripts/run_raptorq_e2e.sh --profile full --bundle

# Focused failure reproduction with stable replay linkage
rch exec -- ./scripts/run_raptorq_e2e.sh --profile forensics --scenario RQ-E2E-FAILURE-INSUFFICIENT --bundle

# Structured logging sentinel in perf invariants
rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture

# Replay catalog schema/linkage validation
rch exec -- cargo test --test raptorq_perf_invariants replay_catalog_schema_and_linkage -- --nocapture
```
