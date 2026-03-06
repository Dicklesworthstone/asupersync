# CI Proof Gates Contract

Bead: `asupersync-1508v.10.5`

## Purpose

This contract defines the hard CI gates that make the ascension program operationally real: proof/artifact consistency, calibration drift alarms, tail regression budgets, obligation leak detection, revocation integrity, and progressive-delivery readiness computation from explicit evidence.

## Contract Artifacts

1. Canonical artifact: `artifacts/ci_proof_gates_v1.json`
2. Smoke runner: `scripts/run_ci_proof_gates_smoke.sh`
3. Invariant suite: `tests/ci_proof_gates_contract.rs`

## Gate Definitions

| Gate | Severity | Purpose |
|------|----------|---------|
| CG-ARTIFACT-BUNDLE | blocking | Artifact existence and version validation |
| CG-CLAIM-EVIDENCE-COVERAGE | blocking | Every claim has evidence |
| CG-CALIBRATION-DRIFT | blocking | Controller calibration stability |
| CG-TAIL-REGRESSION | blocking | Tail latency within budget |
| CG-OBLIGATION-LEAK | blocking | No obligation leaks |
| CG-REVOCATION-INTEGRITY | blocking | Revoked tokens stay denied |
| CG-VALIDATION-PACK-COVERAGE | warning | Track validation packs pass |
| CG-COMPOSITION-ELIGIBILITY | warning | Cross-track compatibility |
| CG-STRUCTURED-LOG-SCHEMA | warning | Log field completeness |
| CG-REPRODUCIBILITY | blocking | All failures reproducible |

## Readiness Computation

| Dimension | Weight |
|-----------|--------|
| RD-PROOF-COVERAGE | 0.25 |
| RD-CALIBRATION-STABILITY | 0.20 |
| RD-TAIL-BUDGET | 0.20 |
| RD-VALIDATION-PACK | 0.15 |
| RD-OBLIGATION-SAFETY | 0.10 |
| RD-REPRODUCIBILITY | 0.10 |

### Verdicts

- **GO**: score >= 0.90
- **CONDITIONAL_GO**: score >= 0.75
- **NO_GO**: score < 0.75

## Actionability

Every gate failure emits an exact rerun command for reproduction.

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa102 cargo test --test ci_proof_gates_contract -- --nocapture
```

## Cross-References

- `artifacts/ci_proof_gates_v1.json`
- `artifacts/claim_evidence_graph_v1.json` -- Claim/evidence graph
- `artifacts/capability_token_model_v1.json` -- Revocation integrity
- `artifacts/crash_recovery_validation_v1.json` -- Reproducibility
