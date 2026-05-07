# CI Proof Gates Contract

Bead: `asupersync-1508v.10.5`

## Purpose

This contract defines the hard CI gates that make the ascension program operationally real: proof/artifact consistency, calibration drift alarms, tail regression budgets, obligation leak detection, revocation integrity, and progressive-delivery readiness computation from explicit evidence.

## Contract Artifacts

1. Canonical artifact: `artifacts/ci_proof_gates_v1.json`
2. Smoke runner: `scripts/run_ci_proof_gates_smoke.sh`
3. Invariant suite: `tests/ci_proof_gates_contract.rs`

## SLO Policy Proof Loop

The SLO policy lane is a direct-main operator gate for service-objective policy changes. It does not replace the broad Phase 6 gates; it gives SLO bundle edits their own deterministic contract:

1. Canonical artifact: `artifacts/slo_policy_bundle_contract_v1.json`
2. Runtime API and exported constants: `src/types/slo_policy.rs`, `SLO_POLICY_BUNDLE_SCHEMA_VERSION`, `SLO_POLICY_COMPILER_SCHEMA_VERSION`, `SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION`
3. JSON validators: `validate_slo_policy_bundle_json` and `validate_slo_proof_report_json`
4. Invariant suite: `tests/slo_policy_bundle_contract.rs`
5. Operator script: `scripts/validate_slo_policy_bundle.sh`

The artifact records the bundle schema, compiler schema `slo-budget-admission-compiler-v1`, LabRuntime replay contract `slo-lab-replay-contract-v1`, and proof-report schema `slo-proof-report-v1`. Operators should read those as one chain: bundle input, compiled Budget/admission decision, replay evidence, and final proof-report gate.

Proof reports intentionally preserve separate outcomes instead of collapsing them into success:

| Status | Gate meaning |
|--------|--------------|
| `pass` | Accepted and counted as full success |
| `degraded` | Accepted only when issue-free; records brownout/degradation evidence |
| `no_win` | Accepted only when issue-free and accompanied by a no-win receipt |
| `fail` | Rejected |
| `blocked` | Rejected |
| `unsupported` | Rejected |
| `stale_evidence` | Rejected and treated as stale profile evidence |

Malformed reports, missing `rch exec` commands, stale profile hashes, missing no-win receipts, redaction failures, secret-like material, unsupported schema versions, and missing required fields fail closed. The proof-report JSONL rows emitted by `scripts/validate_slo_policy_bundle.sh` include `proof_report_status`, `proof_report_success`, `gate_accepted`, `proof_report_issue_kinds`, `proof_commands_count`, and `no_win_receipt`.

Direct-main SLO doc or policy changes should run the gate through `rch exec --`:

```bash
rch exec -- bash scripts/validate_slo_policy_bundle.sh --output-root target/slo-policy-bundle --run-id asupersync-bgtplc.5
```

The Rust contract for the artifact, exported APIs, README section, and this operator doc is:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_slo_policy_docs CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture
```

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
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_ci_proof_gates cargo test -p asupersync --test ci_proof_gates_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/ci_proof_gates_v1.json`
- `artifacts/claim_evidence_graph_v1.json` -- Claim/evidence graph
- `artifacts/capability_token_model_v1.json` -- Revocation integrity
- `artifacts/crash_recovery_validation_v1.json` -- Reproducibility
