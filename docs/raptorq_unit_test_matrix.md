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
| Sender/Receiver builders + pipeline API | `src/raptorq/tests.rs:91`, `src/raptorq/tests.rs:217`, `src/raptorq/tests.rs:307` | empty payload + custom/default config: `src/raptorq/tests.rs:283`, `src/raptorq/tests.rs:293`, `src/raptorq/tests.rs:307` | oversized + cancellation + insufficient symbols: `src/raptorq/tests.rs:157`, `src/raptorq/tests.rs:178`, `src/raptorq/tests.rs:264` | deterministic emit/signing behavior covered via send-symbol paths | `RQ-E2E-systematic_only`, `RQ-E2E-insufficient_symbols` | failure messages present; replay-id field enforcement delegated to conformance/perf invariants suites | partial |
| Systematic parameter lookup + tuple/degree semantics | `src/raptorq/systematic.rs:1148`, `src/raptorq/systematic.rs:1159`, `tests/raptorq_conformance.rs:597` | k-small/large + overhead bounds: `src/raptorq/systematic.rs:1122`, `src/raptorq/systematic.rs:1135`, `tests/raptorq_conformance.rs:617` | distribution/edge handling: `src/raptorq/systematic.rs:1171`, `src/raptorq/systematic.rs:1250`, `tests/raptorq_conformance.rs:541` | same-seed deterministic checks: `src/raptorq/systematic.rs:1204`, `tests/raptorq_conformance.rs:573` | `RQ-E2E-systematic_only`, `RQ-E2E-typical_random_loss` | deterministic seeds asserted; replay-id mapping to D9 catalog pending | partial |
| Decoder equation reconstruction + decode semantics | roundtrip no-loss/repair-only: `tests/raptorq_conformance.rs:101`, `tests/raptorq_conformance.rs:155`, `src/raptorq/tests.rs:604` | tiny/large symbol, k=1/2: `tests/raptorq_conformance.rs:276`, `tests/raptorq_conformance.rs:293`, `src/raptorq/tests.rs:1080`, `src/raptorq/tests.rs:1337` | insufficient + size mismatch + random loss: `tests/raptorq_conformance.rs:374`, `tests/raptorq_conformance.rs:397`, `tests/raptorq_conformance.rs:469`, `src/raptorq/tests.rs:1276`, `src/raptorq/tests.rs:1301` | deterministic decode equality: `tests/raptorq_conformance.rs:217`, `tests/raptorq_conformance.rs:243` | all four E2E scenarios | structured report fields available in E2E suite (`tests/raptorq_conformance.rs:1181`) | strong |
| Solver/Linalg (pivot/rank/gaussian behavior) | gaussian solve sanity: `src/raptorq/linalg.rs:1056`, `src/raptorq/linalg.rs:1072` | empty rhs + 3x3/64-scale paths: `src/raptorq/linalg.rs:1109`, `src/raptorq/linalg.rs:1176`, perf invariants dense paths `tests/raptorq_perf_invariants.rs:732` | singular matrix + stats/pivot constraints: `src/raptorq/linalg.rs:1094`, `tests/raptorq_perf_invariants.rs:392`, `tests/raptorq_perf_invariants.rs:825` | deterministic stats/proof checks: `tests/raptorq_perf_invariants.rs:425`, `tests/raptorq_perf_invariants.rs:506` | `RQ-E2E-typical_random_loss`, `RQ-E2E-burst_loss_late`, `RQ-E2E-insufficient_symbols` | structured logging sentinel present (`tests/raptorq_perf_invariants.rs:667`) | strong |
| GF256 primitives + algebraic laws | algebra basics: `src/raptorq/gf256.rs:518`, `src/raptorq/gf256.rs:536`, `tests/raptorq_conformance.rs:636` | power/inverse edge behavior: `src/raptorq/gf256.rs:624`, `src/raptorq/gf256.rs:562` | distributive/associative/large input checks: `src/raptorq/gf256.rs:579`, `src/raptorq/gf256.rs:600`, `src/raptorq/gf256.rs:728` | deterministic table/roundtrip checks: `src/raptorq/gf256.rs:489`, `src/raptorq/gf256.rs:500` | indirectly exercised by all E2E scenarios | deterministic; replay-id binding for pure unit GF tests pending D9 | partial |
| Proof/replay integrity | proof replay + hash determinism: `src/raptorq/proof.rs:687`, `src/raptorq/proof.rs:710`, `tests/raptorq_perf_invariants.rs:570` | mismatch detection boundary: `src/raptorq/proof.rs:754` | failure-path replay checks: `tests/raptorq_perf_invariants.rs:538` | deterministic content hash + replay passes | `RQ-E2E-systematic_only`, `RQ-E2E-insufficient_symbols` | structured proof metadata reported in E2E report JSON (`tests/raptorq_conformance.rs:1203`) | strong |

## Unit ↔ E2E Traceability

| Unit Scenario ID | Unit Sentinel Examples | Linked Deterministic E2E Scenario(s) |
|---|---|---|
| `RQ-U-HAPPY-SYSTEMATIC` | `tests/raptorq_conformance.rs:101`, `src/raptorq/tests.rs:217` | `RQ-E2E-systematic_only` |
| `RQ-U-HAPPY-REPAIR` | `tests/raptorq_conformance.rs:155`, `src/raptorq/tests.rs:1243` | `RQ-E2E-typical_random_loss`, `RQ-E2E-burst_loss_late` |
| `RQ-U-BOUNDARY-TINY` | `tests/raptorq_conformance.rs:276`, `tests/raptorq_conformance.rs:293`, `src/raptorq/tests.rs:1080` | `RQ-E2E-systematic_only` |
| `RQ-U-BOUNDARY-LARGE` | `tests/raptorq_conformance.rs:348`, `src/raptorq/tests.rs:1167`, `src/raptorq/tests.rs:1337` | `RQ-E2E-typical_random_loss` |
| `RQ-U-ERROR-INSUFFICIENT` | `tests/raptorq_conformance.rs:374`, `src/raptorq/tests.rs:1276` | `RQ-E2E-insufficient_symbols` |
| `RQ-U-ERROR-SIZE-MISMATCH` | `tests/raptorq_conformance.rs:397`, `src/raptorq/tests.rs:1301` | `RQ-E2E-insufficient_symbols` (error-path schema parity) |
| `RQ-U-ADVERSARIAL-LOSS` | `tests/raptorq_conformance.rs:469`, `tests/raptorq_perf_invariants.rs:732` | `RQ-E2E-typical_random_loss`, `RQ-E2E-burst_loss_late` |
| `RQ-U-DETERMINISM-SEED` | `tests/raptorq_conformance.rs:188`, `tests/raptorq_conformance.rs:573`, `src/raptorq/tests.rs:773` | all E2E scenarios (deterministic double-run contract) |
| `RQ-U-DETERMINISM-PROOF` | `tests/raptorq_perf_invariants.rs:506`, `tests/raptorq_perf_invariants.rs:570` | all E2E scenarios via `e2e_pipeline_reports_are_deterministic` |

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
- unit-level structured context is present for key edge-case success+failure paths; full suite-wide replay-id propagation remains **partial** pending D7/D9 integration

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

## Gaps and Follow-ups

Open gaps identified during matrix pass:

1. Unit suites do not yet consistently emit explicit `replay_ref` IDs on every failure path.
2. Some pure GF256 and builder-path tests rely on assertion text without schema-aligned key/value context.

Mapped follow-up beads:

- `bd-26pqk` (seed/fixture replay catalog)
- `bd-oeql8` (structured test logging schema)
- `bd-3bvdj` (deterministic E2E scenario suite alignment)

## Repro Commands

```bash
# Unit-heavy pass (focused)
rch exec -- cargo test --lib raptorq -- --nocapture

# Deterministic conformance scenario suite
rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture

# Structured logging sentinel in perf invariants
rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture

# Replay catalog schema/linkage validation
rch exec -- cargo test --test raptorq_perf_invariants replay_catalog_schema_and_linkage -- --nocapture
```
