# Semantic Evidence Bundle (SEM-09.2)

This document defines the SEM-09.2 normalized evidence bundle and its build
workflow.

## Purpose

`scripts/build_semantic_evidence_bundle.sh` assembles one deterministic JSON
artifact that joins:

1. SEM-12 unified runner output (`verification_report.json`)
2. SEM-09 readiness gate declarations (`docs/semantic_readiness_gates.md`)
3. SEM-12 rule matrix traceability (`docs/semantic_verification_matrix.md`)

The bundle is designed for SEM-09.3 gate evaluation and for reproducible
handoff between agents.

SEM-09.4 (`docs/semantic_residual_risk_register.md`) consumes this bundle to
maintain the bounded residual-risk register and objective GO/NO-GO decisions.

## Command

```bash
bash scripts/build_semantic_evidence_bundle.sh \
  --report target/semantic-verification/verification_report.json \
  --output target/semantic-readiness/evidence_bundle.json
```

Optional strict mode:

```bash
bash scripts/build_semantic_evidence_bundle.sh --strict
```

In `--strict`, the command exits non-zero when `missing_evidence` is non-empty.

## Output Contract

Schema version:

- `semantic-evidence-bundle-v1`

Top-level fields:

- `schema_version`
- `generated_at`
- `status` (`pass` or `needs_attention`)
- `inputs`
- `runner`
- `readiness_gates`
- `traceability`
- `missing_evidence`
- `missing_evidence_by_owner`
- `deterministic_rerun`

## Missing Evidence Ownership

Missing evidence entries are explicitly mapped to owner beads:

- Matrix `UT/PT/OC` gaps -> `asupersync-3cddg.12.5`
- Matrix `E2E` gaps -> `asupersync-3cddg.12.6`
- Matrix `LOG` gaps -> `asupersync-3cddg.12.7`
- Matrix `DOC` gaps -> `asupersync-3cddg.12.2`
- Matrix `CI` gaps -> `asupersync-3cddg.12.9`
- Runner suite failures:
  - `docs` -> `asupersync-3cddg.12.2`
  - `golden` -> `asupersync-3cddg.12.8`
  - `lean_validation` / `lean_build` -> `asupersync-3cddg.12.3`
  - `tla_validation` / `tla_check` -> `asupersync-3cddg.12.4`
  - `logging_schema` -> `asupersync-3cddg.12.7`
  - `coverage_gate` -> `asupersync-3cddg.12.14`
- Missing profile-required artifacts -> `asupersync-3cddg.12.11`

## Deterministic Rerun Support

The bundle carries reproducible command pointers:

1. Runner rerun command (`run_semantic_verification.sh --profile ... --json`)
2. Bundle regeneration command (`build_semantic_evidence_bundle.sh --report ...`)

This keeps SEM-09.3 readiness evaluation reproducible across CI and local runs.

## Public Guarantee Bundles

`artifacts/public_guarantee_semantic_evidence_bundles_v1.json` defines the
`public-guarantee-semantic-evidence-bundles-v1` layer for user-facing runtime
guarantees. It is a mapping artifact, not a fresh proof receipt. Each bundle
pairs one public claim with semantic sources, manifest proof lanes, fixtures,
conformance rows, freshness policy, failure-mode examples, README linking
rules, and explicit no-claim boundaries.

The required public guarantee IDs are:

- `no-orphan-tasks`
- `race-loser-drain`
- `no-obligation-leaks`
- `cancel-safe-send`
- `deterministic-replay`
- `default-production-no-tokio`

Fresh proof still requires the exact manifest lane to run through
remote-required RCH, or an approved cache hit under
`artifacts/proof_status_snapshot_v1.json`. `rerun-required`,
`stale-evidence`, `blocked`, `no-win`, and `unsupported` are fail-closed states;
they are not proof shortcuts.
