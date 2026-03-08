# Browser Troubleshooting Compendium and Diagnostics Cookbook (WASM-15)

Contract ID: `wasm-browser-troubleshooting-cookbook-v1`  
Legacy bead lineage: `asupersync-umelq.16.4`  
Current bead: `asupersync-3qv04.9.4`  
Follow-on bead: `asupersync-3qv04.8.6.3`  
Parent track: `asupersync-3qv04.9`  
Adjacent QA/failure-triage bead: `asupersync-3qv04.8.6`

## Purpose

Provide deterministic symptom-to-action playbooks for common Browser Edition
failures so operators can move from incident to replayable evidence without
ad-hoc debugging.

Each recipe includes:

1. symptom pattern,
2. likely root cause,
3. deterministic command bundle,
4. expected evidence artifacts,
5. escalation pointer if the gate remains red.

All cargo-heavy commands stay on `rch exec -- ...`.

## Fast Triage Ladder

Run these in order before deep investigation:

```bash
mkdir -p artifacts/troubleshooting

python3 scripts/run_browser_onboarding_checks.py --scenario all \
  | tee artifacts/troubleshooting/onboarding_all.log

bash ./scripts/run_all_e2e.sh --suite wasm-qa-evidence-smoke \
  | tee artifacts/troubleshooting/wasm_qa_evidence_smoke.log

bash ./scripts/run_all_e2e.sh --verify-matrix \
  | tee artifacts/troubleshooting/e2e_verify_matrix.log

python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json \
  | tee artifacts/troubleshooting/dependency_policy.log

rch exec -- cargo test --test e2e_log_quality_schema -- --nocapture \
  | tee artifacts/troubleshooting/log_quality_schema.log
```

If all four pass, move to targeted recipes below.

## Artifact Map

Use this table first when you know a command failed but do not know where the
evidence landed.

| Workflow | Canonical command | Primary artifacts |
|---|---|---|
| Onboarding smoke and framework readiness | `python3 scripts/run_browser_onboarding_checks.py --scenario all` | `artifacts/onboarding/{vanilla,react,next}.ndjson`, `artifacts/onboarding/{vanilla,react,next}.summary.json` |
| Browser Edition onboarding + QA smoke lane | `python3 scripts/run_browser_onboarding_checks.py --scenario all --dry-run --out-dir artifacts/onboarding && bash ./scripts/run_all_e2e.sh --suite wasm-qa-evidence-smoke` | `artifacts/onboarding/{vanilla,react,next}.summary.json`, `target/wasm-qa-evidence-smoke/<run>/<scenario>/{bundle_manifest.json,run_report.json,run.log,events.ndjson}`, `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json` |
| WASM dependency/profile audit | `python3 scripts/check_wasm_dependency_policy.py --policy .github/wasm_dependency_policy.json` | `artifacts/wasm_dependency_audit_summary.json`, `artifacts/wasm_dependency_audit_log.ndjson` |
| WASM flake governance | `python3 scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json` | `artifacts/wasm_flake_governance_report.json`, `artifacts/wasm_flake_governance_events.ndjson` |
| E2E orchestration matrix | `bash ./scripts/run_all_e2e.sh --verify-matrix` | `target/e2e-results/orchestrator_<timestamp>/report.json`, `artifact_manifest.json`, `artifact_manifest.ndjson`, `replay_verification.json`, `artifact_lifecycle_policy.json` |
| Packaged bootstrap/load/reload harness | `bash ./scripts/test_wasm_packaged_bootstrap_e2e.sh` | `target/e2e-results/wasm_packaged_bootstrap/e2e-runs/<scenario>/<run>/summary.json`, `run-metadata.json`, `log.jsonl`, `steps.ndjson`, `perf-summary.json`, `artifacts/wasm_packaged_bootstrap_perf_summary.json` |
| React packaged-consumer validation | `bash ./scripts/validate_react_consumer.sh` | `target/e2e-results/react_consumer/<timestamp>/consumer_build.log`, `target/e2e-results/react_consumer/<timestamp>/summary.json` |
| Package shape / `npm pack` smoke | `bash ./scripts/validate_npm_pack_smoke.sh` | terminal validation output plus package artifact presence under `packages/browser-core/` |
| Browser-core artifact staging | `PATH=/usr/bin:$PATH corepack pnpm run build` | `packages/browser-core/asupersync.js`, `packages/browser-core/asupersync.d.ts`, `packages/browser-core/asupersync_bg.wasm`, `packages/browser-core/abi-metadata.json`, `packages/browser-core/debug-metadata.json` |

## Recipe Matrix

| Symptom | Likely Cause | Run | Expected Evidence |
|---|---|---|---|
| wasm32 compile fails with forbidden-surface errors | Invalid profile/feature mix (`cli`, `tls`, `sqlite`, `postgres`, `mysql`, `kafka`, etc.) or native-only leakage into the browser closure | `rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-dev` | compile output references wasm guardrails in `src/lib.rs`; supporting audit artifacts: `artifacts/wasm_dependency_audit_summary.json`, `artifacts/wasm_dependency_audit_log.ndjson` |
| `ASUPERSYNC_*_UNSUPPORTED_RUNTIME` thrown during init/bootstrap | direct runtime attempted in Node, SSR, Next server/edge, or another environment outside the shipped browser support boundary | `rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture` | contract test output proves package-specific unsupported-runtime codes, support reasons, and guidance strings; use `docs/integration.md` support matrix to choose the correct bridge-only fallback |
| packaged consumer validation says required Browser Edition artifacts are missing | `packages/browser-core/` wasm artifacts or higher-level package `dist/` outputs were not built/staged before running consumer validation | `PATH=/usr/bin:$PATH corepack pnpm run build && bash ./scripts/validate_react_consumer.sh` | built artifacts appear under `packages/browser-core/`; consumer evidence appears at `target/e2e-results/react_consumer/<timestamp>/consumer_build.log` and `summary.json` |
| `npm pack --dry-run` or package-shape validation fails | manifest/export-map/files-array drift, missing staged browser-core artifacts, or resolver policy drift | `bash ./scripts/validate_npm_pack_smoke.sh` | terminal output names the failing manifest field or missing artifact; warnings reference `packages/browser-core/*` and tell you whether `build:wasm` must run first |
| Browser Edition onboarding + QA smoke CI lane red | onboarding command bundle drift, smoke-scenario command drift, or mismatch between `.github/workflows/ci.yml` and `.github/ci_matrix_policy.json` for lane `wasm-browser-qa-smoke` | `python3 scripts/run_browser_onboarding_checks.py --scenario all --dry-run --out-dir artifacts/onboarding && bash ./scripts/run_all_e2e.sh --suite wasm-qa-evidence-smoke` | onboarding summaries under `artifacts/onboarding/`; per-scenario smoke bundles under `target/wasm-qa-evidence-smoke/<run>/<scenario>/`; suite summary under `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json`; CI lane id `wasm-browser-qa-smoke` |
| `run_all_e2e --verify-matrix` fails on redaction/retention/lifecycle policy | invalid `ARTIFACT_REDACTION_MODE`, retention settings, or suite matrix drift | `bash ./scripts/run_all_e2e.sh --verify-matrix` | orchestrator report bundle under `target/e2e-results/orchestrator_<timestamp>/`; inspect `report.json`, `artifact_manifest.json`, `replay_verification.json`, and `artifact_lifecycle_policy.json` |
| log-quality gate failure | missing required summary fields, low score under threshold, or doc/workflow drift against the schema contract | `rch exec -- cargo test --test e2e_log_quality_schema -- --nocapture` | `e2e_log_quality_schema` pinpoints missing/invalid contract tokens; pair it with the latest orchestrator `report.json` when the failure originated from an E2E run |
| bundler compatibility lane red | bundler matrix drift, docs/workflow mismatch, or package staging gap | `rch exec -- cargo test --test wasm_bundler_compatibility -- --nocapture` | pass/fail tied to matrix contract; artifact pointers include `artifacts/wasm_bundler_compatibility_summary.json` and `artifacts/wasm_bundler_compatibility_test.log` |
| replay/forensics lane red | flake governance drift, missing quarantine/forensics metadata, or stale incident playbook linkage | `python3 scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json` | report + events files: `artifacts/wasm_flake_governance_report.json`, `artifacts/wasm_flake_governance_events.ndjson`; cross-check `artifacts/wasm_flake_quarantine_manifest.json` when flakes are quarantined |
| packaged bootstrap/load/reload harness fails | browser-core artifact mismatch, bootstrap state-machine drift, reload/remount regression, or shutdown leak | `bash ./scripts/test_wasm_packaged_bootstrap_e2e.sh` | packaged bootstrap bundle under `target/e2e-results/wasm_packaged_bootstrap/e2e-runs/<scenario>/<run>/`; inspect `summary.json`, `run-metadata.json`, `log.jsonl`, `steps.ndjson`, and `perf-summary.json` |
| obligation/quiescence failures in browser lifecycle tests | cancel/drain sequencing regression or missing lifecycle cleanup path | `rch exec -- cargo test --test obligation_wasm_parity wasm_full_browser_lifecycle_simulation -- --nocapture` | deterministic failure points to lifecycle phase and obligation invariant breach; if reproduced through onboarding, also inspect `artifacts/onboarding/react.obligation_lifecycle.log` |

## Deep-Dive Playbooks

### A. Profile and Dependency Closure

Use when wasm32 checks fail or native-only features appear in browser closure.

```bash
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json

rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-dev

rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-deterministic
```

Evidence to capture:

- `artifacts/wasm_dependency_audit_summary.json`
- `artifacts/wasm_dependency_audit_log.ndjson`
- wasm32 check logs for each profile
- exact feature flags used in the failing command

### B. Unsupported Runtime and Compatibility Boundary Failures

Use when `@asupersync/browser`, `@asupersync/react`, or `@asupersync/next`
throws an unsupported-runtime error during bootstrap.

```bash
rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture
```

Evidence to capture:

- package-specific error code:
  - `ASUPERSYNC_BROWSER_UNSUPPORTED_RUNTIME`
  - `ASUPERSYNC_REACT_UNSUPPORTED_RUNTIME`
  - `ASUPERSYNC_NEXT_UNSUPPORTED_RUNTIME`
- `diagnostics.reason` (`missing_global_this`, `missing_browser_dom`,
  `missing_webassembly`, or `supported`)
- capability snapshot (`hasWindow`, `hasDocument`, `hasWebAssembly`,
  `hasAbortController`, `hasFetch`, `hasWebSocket`)
- Next target (`client`, `server`, `edge`) if the failure came through
  `@asupersync/next`

Expected operator action:

- keep `@asupersync/browser` direct runtime creation in a real browser
  main-thread entrypoint
- keep `@asupersync/react` direct runtime usage inside client-rendered React
  trees only
- keep `@asupersync/next` server and edge code on bridge-only adapters and move
  runtime creation into a client component or browser-only module
- do not treat browser-worker, Node.js, or SSR contexts as implicitly supported
  direct-runtime lanes unless the support matrix and package guards are promoted
  together

### C. Package Artifact and Consumer Build Failures

Use when package validators complain about missing wasm outputs, missing `dist/`
trees, or broken local consumer installs.

```bash
PATH=/usr/bin:$PATH corepack pnpm run build
bash ./scripts/validate_react_consumer.sh
bash ./scripts/validate_npm_pack_smoke.sh
```

Evidence to capture:

- built browser-core artifacts under `packages/browser-core/`
- `target/e2e-results/react_consumer/<timestamp>/consumer_build.log`
- `target/e2e-results/react_consumer/<timestamp>/summary.json`
- terminal output from `scripts/validate_npm_pack_smoke.sh` naming the exact
  missing field, export-map entry, or artifact

### D. Onboarding Runner Drift

Use when the documented first-success flows fail or when you want the fastest
symptom-to-artifact sweep across vanilla, React, and Next lanes.

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario all
```

Evidence to capture:

- `artifacts/onboarding/vanilla.ndjson`
- `artifacts/onboarding/react.ndjson`
- `artifacts/onboarding/next.ndjson`
- `artifacts/onboarding/vanilla.summary.json`
- `artifacts/onboarding/react.summary.json`
- `artifacts/onboarding/next.summary.json`

Each summary includes ordered correlation IDs and the failing step IDs; use
those before opening individual harness logs.

### E. Browser Edition Onboarding + QA Smoke Lane Failures

Use when the CI smoke lane is red, when `run_all_e2e.sh --suite
wasm-qa-evidence-smoke` fails locally, or when the onboarding bundle and smoke
bundle disagree about whether Browser Edition is healthy.

```bash
python3 scripts/run_browser_onboarding_checks.py \
  --scenario all --dry-run --out-dir artifacts/onboarding

bash ./scripts/run_wasm_qa_evidence_smoke.sh --all --execute

bash ./scripts/run_all_e2e.sh --suite wasm-qa-evidence-smoke
```

Evidence to capture:

- `artifacts/onboarding/vanilla.summary.json`
- `artifacts/onboarding/react.summary.json`
- `artifacts/onboarding/next.summary.json`
- latest `target/wasm-qa-evidence-smoke/<run>/<scenario>/bundle_manifest.json`
- latest `target/wasm-qa-evidence-smoke/<run>/<scenario>/run_report.json`
- latest `target/wasm-qa-evidence-smoke/<run>/<scenario>/events.ndjson`
- latest `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json`
- CI lane id `wasm-browser-qa-smoke` plus the step names
  `Browser Edition onboarding command bundle smoke` and
  `WASM QA smoke runner (dry-run bundle contract)` when the red failure came
  from GitHub Actions

Interpretation order:

1. If onboarding fails first, treat that as the primary user-facing regression
   and use the per-framework summaries before the smoke bundles.
2. If onboarding passes but the smoke suite fails, open the failing
   `bundle_manifest.json` and `run_report.json` first; they point to the exact
   scenario command, evidence ID, and retained artifact paths.
3. If the local suite passes but CI is red, compare `.github/workflows/ci.yml`
   and `.github/ci_matrix_policy.json` for drift in the `wasm-browser-qa-smoke`
   lane contract before changing runner logic.

### F. Replay, Matrix, and Incident Forensics

Use when behavior is flaky across runs or incident triage lacks reproducible
logs.

```bash
bash ./scripts/run_all_e2e.sh --verify-matrix
bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics
python3 scripts/check_wasm_flake_governance.py \
  --policy .github/wasm_flake_governance_policy.json
```

Evidence to capture:

- latest `target/e2e-results/orchestrator_<timestamp>/report.json`
- latest `target/e2e-results/orchestrator_<timestamp>/artifact_manifest.json`
- latest `target/e2e-results/orchestrator_<timestamp>/replay_verification.json`
- `artifacts/wasm_flake_governance_report.json`
- `artifacts/wasm_flake_governance_events.ndjson`
- replay command, trace pointer, and scenario ID from the emitted suite summary

### G. Log Contract Violations

Use when diagnostics are present but not machine-parseable or policy-compliant.

```bash
rch exec -- cargo test --test e2e_log_quality_schema -- --nocapture
```

Evidence to capture:

- exact failing test names
- missing contract token/field from assertion output
- the newest relevant `report.json` or onboarding `*.summary.json`
- updated doc/workflow references if contract drift is intentional

### H. Lifecycle, Quiescence, and Packaged Bootstrap Failures

Use when a browser lifecycle or shutdown path leaks work, skips loser drain, or
fails to reach quiescence.

```bash
rch exec -- cargo test --test obligation_wasm_parity \
  wasm_full_browser_lifecycle_simulation -- --nocapture

bash ./scripts/test_wasm_packaged_bootstrap_e2e.sh
```

Evidence to capture:

- failing lifecycle phase from the Rust test output
- latest packaged bootstrap `summary.json`
- latest packaged bootstrap `steps.ndjson`
- latest packaged bootstrap `perf-summary.json`
- any exported `artifacts/wasm_packaged_bootstrap_perf_summary.json`

## Escalation Rules

Escalate immediately if any condition holds:

1. a failure is non-reproducible under a fixed command/seed,
2. evidence artifacts are missing or non-parseable,
3. a workaround requires disabling redaction or quality gates,
4. a package/runtime support claim conflicts with `docs/integration.md`.

Escalation route:

1. Post findings in Agent Mail with thread id matching the active bead.
2. Include the exact command, failure text, and artifact pointers.
3. Keep mitigation proposals explicit; no hidden policy bypasses.
4. If the issue spans packaging plus runtime semantics, attach both the package
   evidence (`packages/browser-core/*`, consumer logs) and the runtime evidence
   (`artifacts/onboarding/*`, `target/e2e-results/*`).

## Cross-References

- `docs/integration.md` (Browser Documentation IA + guardrails)
- `docs/wasm_dx_error_taxonomy.md` (package error codes, recoverability, and guidance contract)
- `docs/wasm_quickstart_migration.md` (onboarding/release-channel flow)
- `docs/wasm_qa_evidence_matrix_contract.md` (smoke runner contract and artifact bundle schema)
- `docs/wasm_bundler_compatibility_matrix.md` (bundler contract and CI lane)
- `docs/wasm_flake_governance_and_forensics.md` (incident governance)
- `docs/doctor_logging_contract.md` (redaction and log-quality contracts)
