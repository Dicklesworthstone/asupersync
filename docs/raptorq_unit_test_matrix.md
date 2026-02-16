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
- unit-level structured context is present for edge-case paths, builder-path send/receive tests, systematic conformance/property/drop/fuzz vectors, and GF256 unit families included in this matrix; broader suite-wide replay-id propagation remains a D7/D9 follow-up

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
  - `repro_cmd`

Profile coverage in the script suite:

- `fast`: happy smoke + tiny boundary + insufficient-symbol failure + deterministic report contract
- `full`: complete happy/boundary/failure matrix + deterministic report contract
- `forensics`: heavy-loss/hard-failure surfaces + deterministic report contract

## Gaps and Follow-ups

Open gaps identified during matrix pass:

1. D5 matrix rows are now `strong`; remaining replay/logging standardization work continues in D7/D9 for non-D5 suites.
2. End-to-end structured-forensics evolution (beyond this unit matrix scope) remains tracked in D7 and D6.

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
| `bd-oeql8` | D7 structured logging schema | `open` | schema contract enforcement still needed across all required suites |
| `bd-3bvdj` / `asupersync-wdk6c` | D6 deterministic E2E suite | `closed` | deterministic profile/scenario runner is in place and linked to unit families |

## Repro Commands

```bash
# Unit-heavy pass (focused)
rch exec -- cargo test --lib raptorq -- --nocapture

# Deterministic conformance scenario suite
rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture

# Deterministic D6 profile suite (happy + boundary + failure)
rch exec -- ./scripts/run_raptorq_e2e.sh --profile full

# Focused failure reproduction with stable replay linkage
rch exec -- ./scripts/run_raptorq_e2e.sh --profile forensics --scenario RQ-E2E-FAILURE-INSUFFICIENT

# Structured logging sentinel in perf invariants
rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture

# Replay catalog schema/linkage validation
rch exec -- cargo test --test raptorq_perf_invariants replay_catalog_schema_and_linkage -- --nocapture
```
