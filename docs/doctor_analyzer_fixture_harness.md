# doctor Analyzer Fixture Harness

## Scope

This harness defines deterministic fixture-pack validation for doctor Track 2
analyzers:

- workspace scanner
- evidence ingestion
- invariant analyzer
- lock-contention analyzer

Canonical assets:

- `tests/fixtures/doctor_analyzer_harness/fixtures.json`
- `tests/doctor_analyzer_fixture_harness.rs`

## Goals

1. Deterministic fixture loading.
2. Deterministic analyzer execution across repeated runs.
3. Oracle checks with actionable mismatch diagnostics.
4. Structured per-fixture logs with run/scenario/repro provenance.
5. Clear authoring workflow for promoting new fixtures.

## Fixture Pack Schema

`fixtures.json` is the single source of fixture metadata.

Fields:

- `schema_version`: `doctor-analyzer-fixture-pack-v1`
- `fixtures[]`:
  - `fixture_id`
  - `description`
  - `family`: `scanner | invariant | lock_contention | ingestion`
  - `workspace_root` (for scanner/invariant/lock fixtures)
  - `artifact_profile` (for ingestion fixtures)
  - `expectation`:
    - minimum thresholds (`min_*`)
    - optional warning token checks
    - `repro_command`

## Determinism Rules

1. Fixture list order must be stable in source control.
2. Harness output logs are sorted by `fixture_id`.
3. Repeated run equality is required (`first_run == second_run`).
4. Structured event ordering from lock-contention analyzer must validate against
   `doctor-logging-v1`.

## Running the Harness

Use CLI feature-enabled test execution:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_analyzer_docs cargo test -p asupersync --features cli --test doctor_analyzer_fixture_harness -- --nocapture
```

## Promotion Workflow

1. Add or update fixture metadata in `fixtures.json`.
2. If new corpus inputs are required, add them under `tests/fixtures/...`.
3. Run the harness command above.
4. For failures, inspect structured fixture logs in test output:
   - `fixture_id`
   - `diagnostics`
   - `repro_command`
5. Only promote when all fixtures report `status = pass` deterministically.
