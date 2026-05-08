# CI Proof Gates Contract

Bead: `asupersync-1508v.10.5`

## Purpose

This contract defines the hard CI gates that make the ascension program operationally real: proof/artifact consistency, calibration drift alarms, tail regression budgets, obligation leak detection, revocation integrity, and progressive-delivery readiness computation from explicit evidence.

## Contract Artifacts

1. Canonical artifact: `artifacts/ci_proof_gates_v1.json`
2. Smoke runner: `scripts/run_ci_proof_gates_smoke.sh`
3. Invariant suite: `tests/ci_proof_gates_contract.rs`

## SLO Policy Proof Loop

The SLO-to-runtime lane is a direct-main operator gate for service-objective policy changes. It covers the explicit SLO application/admission seam: compile the bundle, apply the compiled policy at runtime, replay deterministic enforcement evidence, and run the proof script. It does not replace the broad Phase 6 gates and does not claim blanket production enforcement outside that seam.

1. Canonical artifact: `artifacts/slo_policy_bundle_contract_v1.json`
2. Runtime API and exported constants: `src/types/slo_policy.rs`, `SLO_POLICY_BUNDLE_SCHEMA_VERSION`, `SLO_POLICY_COMPILER_SCHEMA_VERSION`, `SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION`, `SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION`
3. JSON validators: `validate_slo_policy_bundle_json`, `validate_slo_proof_report_json`, and `validate_slo_runtime_policy_application_json`
4. Invariant suite: `tests/slo_policy_bundle_contract.rs`
5. Operator script: `scripts/validate_slo_policy_bundle.sh`

The artifact records the bundle schema, compiler schema `slo-budget-admission-compiler-v1`, runtime application schema `slo-runtime-policy-application-v1`, LabRuntime replay contract `slo-lab-replay-contract-v1`, proof-report schema `slo-proof-report-v1`, and runtime enforcement report schema `slo-runtime-enforcement-proof-report-v1`. Operators should read those as one chain: bundle input, compiled Budget/admission decision, runtime application contract, replay evidence, final proof-report gate, and runtime enforcement report.

Runtime enforcement rows preserve separate outcomes before the proof-report gate:

| Status | Runtime meaning |
|--------|-----------------|
| `pass` | Admitted runtime work completed under the compiled policy |
| `degraded` | Optional work browned out before the objective was violated |
| `no_win` | No-win fallback receipt selected |
| `blocked` | Rejected or blocked at the runtime boundary |
| `stale_evidence` | Rejected for stale profile hash or evidence mismatch |
| `unsupported` | Unsupported optional work or runtime lane |
| `malformed` | Malformed runtime enforcement row or report |

Runtime enforcement JSONL rows emitted by `scripts/validate_slo_policy_bundle.sh` include `runtime_enforcement_status`, `runtime_admission_status`, `lab_replay_status`, admitted and rejected work counts, optional work browned out, cleanup deadline misses, `fallback_reason`, `issue_kinds`, `proof_command`, `proof_command_source`, and `redaction_policy_id`.

Proof reports still preserve separate outcomes instead of collapsing them into success:

| Status | Gate meaning |
|--------|--------------|
| `pass` | Accepted and counted as full success |
| `degraded` | Accepted only when issue-free; records brownout/degradation evidence |
| `no_win` | Accepted only when issue-free and accompanied by a no-win receipt |
| `fail` | Rejected |
| `blocked` | Rejected |
| `unsupported` | Rejected |
| `stale_evidence` | Rejected and treated as stale profile evidence |

Malformed reports, missing `rch exec` commands, stale profile hashes, missing no-win receipts, redaction failures, secret-like material, unsupported schema versions, missing required fields, and local `rch` fallback markers checked with `--check-rch-log` fail closed. The proof-report JSONL rows emitted by `scripts/validate_slo_policy_bundle.sh` include `proof_report_status`, `proof_report_success`, `gate_accepted`, `proof_report_issue_kinds`, `proof_commands_count`, and `no_win_receipt`.

Direct-main SLO doc or policy changes should run the gate through `rch exec --`:

```bash
rch exec -- bash scripts/validate_slo_policy_bundle.sh --output-root target/slo-policy-bundle --run-id asupersync-w5n9qp.5
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

## Validation Frontier Ledger

Broad proof commands stop for two very different reasons: the owned slice failed locally, or shared-main/coordination debt blocked a broader lane before it reached the owned slice. The canonical schema for recording that distinction is `artifacts/validation_frontier_ledger_schema_v1.json`, and the contract/parser-fixture verifier is `tests/validation_frontier_ledger_contract.rs`.

Ledger rows are meant to be pasted into bead close reasons and Agent Mail updates instead of claiming broad green proof from a proxy command. Each row records:

1. The intended proof or coordination command.
2. The touched files that motivated the attempt.
3. The normalized decision: `pass`, `blocked-external`, or `failed-local`.
4. The first failing crate or coordination surface, target, file, line, and error class.
5. The likely owner or bead when known.
6. The narrower supplemental proof that still covered the local change.

Close reasons should cite the frontier row directly. The minimum paste-ready shape is:

- `blocked-external` or `failed-local`
- intended command
- first blocker file and line
- error class plus short summary
- supplemental proof command

Example:

```text
blocked-external: intended `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_ci_proof_gates_docs cargo test --test combinator_select_fairness_determinism_audit -- --nocapture`; stopped at `src/sync/semaphore.rs:37` (`rustc_compile_error`, unused imports); supplemental proof `rch exec -- rustfmt --edition 2024 --check tests/combinator_select_fairness_determinism_audit.rs`.
```

Validation for the ledger contract is also `rch`-scoped:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_validation_frontier_ledger cargo test -p asupersync --test validation_frontier_ledger_contract -- --nocapture
```

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_ci_proof_gates cargo test -p asupersync --test ci_proof_gates_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/ci_proof_gates_v1.json`
- `artifacts/validation_frontier_ledger_schema_v1.json` -- Broad-proof blocker schema and closeout citation format
- `artifacts/claim_evidence_graph_v1.json` -- Claim/evidence graph
- `artifacts/capability_token_model_v1.json` -- Revocation integrity
- `artifacts/crash_recovery_validation_v1.json` -- Reproducibility
