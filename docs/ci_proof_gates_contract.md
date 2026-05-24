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

1. The proof lane id, intended proof or coordination command, target commit, and exit status.
2. The touched files that motivated the attempt plus affected files found in the output.
3. The shared-main dirty-tree summary, including whether peer dirt overlapped the touched files.
4. The RCH admission result, worker when admitted, and whether `RCH_REQUIRE_REMOTE=1` refused local fallback.
5. The normalized decision: `pass`, `blocked-external`, or `failed-local`.
6. The first failing crate or coordination surface, target, file, line, and error class.
7. Error buckets grouped by file, module, stable rustc/clippy/RCH code, likely commit/bead, and owner.
8. The narrower supplemental proof that still covered the local change.

Close reasons should cite the frontier row directly. The minimum paste-ready shape is:

- `blocked-external` or `failed-local`
- intended command
- first blocker file and line
- error class plus short summary
- RCH admission and exit status
- dirty-tree overlap state
- supplemental proof command

Example:

```text
blocked-external: intended `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_ci_proof_gates_docs cargo test --test combinator_select_fairness_determinism_audit -- --nocapture`; stopped at `src/sync/semaphore.rs:37` (`rustc_compile_error`, unused imports); supplemental proof `rch exec -- rustfmt --edition 2024 --check tests/combinator_select_fairness_determinism_audit.rs`.
```

Validation for the ledger contract is also `rch`-scoped:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_validation_frontier_ledger cargo test -p asupersync --test validation_frontier_ledger_contract -- --nocapture
```

## Proof-Lane Status Dashboard

The live proof dashboard is `artifacts/proof_status_snapshot_v1.json`, checked
by `tests/proof_status_snapshot_contract.rs`. It is a derived status view over
`artifacts/proof_lane_manifest_v1.json` plus the validation-frontier ledger; it
must not invent proof commands or broaden a lane beyond the manifest's
`covers` / `explicit_not_covered` text.

Update the dashboard as one atomic proof-status change:

1. Add or update the lane in `artifacts/proof_lane_manifest_v1.json` and keep
   its guarantee mapping bidirectional.
2. Add or update the claim row in `artifacts/proof_status_snapshot_v1.json`.
   `proof_commands` must be copied from the referenced manifest lanes.
3. Keep `green` for dependency/formal/artifact lanes that are not merely broad
   compile/test/lint/doc frontiers. Use `yellow_frontier` for broad validation
   frontiers, `yellow_scoped` for quarantined or intentionally scoped lanes, and
   `red_blocked_external` only with an exact validation-frontier fixture.
4. For a red row, preserve the fixture id, command, decision, error class,
   first-failure file/line, summary, and supplemental proof command. Stale
   blocker summaries are rejected by the contract test.
5. Keep README and AGENTS claim markers present; marker drift is a dashboard
   failure, not a reason to loosen the test.

The focused proof for dashboard/manifest consistency is:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_status_snapshot cargo test -p asupersync --test proof_status_snapshot_contract -- --nocapture
```

## Capability And Ambient-Effect Gate

The no-ambient-authority lane is anchored in `src/audit/ambient.rs`. It scans production `src/` Rust files for direct wall-clock time, OS randomness, filesystem/network construction, runtime environment access, stdout/stderr macros, and thread-spawn patterns that bypass `Cx` or explicit capability providers.

The scanner deliberately separates three classes of code:

1. Production runtime modules, where ambient effects are violations unless routed through a provider or documented in `KNOWN_FINDINGS`.
2. Provider modules such as `src/fs/`, `src/util/entropy.rs`, `src/time/driver.rs`, `src/runtime/blocking_pool.rs`, and `src/web/debug.rs`, where the module is the explicit capability boundary.
3. Test/fuzz/compat surfaces, including inline `#[cfg(test)]` modules and top-level `src/*_tests.rs`, `*_conformance_tests.rs`, `*_metamorphic_tests.rs`, and `*_e2e_tests.rs` harnesses, where ambient output, environment, and host fixtures are allowed as test instrumentation.

Future allowlist updates must be narrow. If a production runtime file needs a new ambient effect, prefer moving the effect behind an existing capability provider. If the effect is intentionally a provider boundary, add or update the exact provider/test carve-out, add a `KNOWN_FINDINGS` entry when the usage should remain visible in the catalog, and update scanner tests so one allowed carve-out and one rejected production pattern prove the invariant still holds.

The focused proof lane for this gate is:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_ambient_authority cargo test -p asupersync --lib audit::ambient -- --nocapture
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
- `src/audit/ambient.rs` -- Production ambient-effect scanner and capability carve-outs
