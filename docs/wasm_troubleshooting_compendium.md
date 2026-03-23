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

If all five pass, move to targeted recipes below.

## Artifact Map

Use this table first when you know a command failed but do not know where the
evidence landed.

| Workflow | Canonical command | Primary artifacts |
|---|---|---|
| Onboarding smoke and framework readiness | `python3 scripts/run_browser_onboarding_checks.py --scenario all` | `artifacts/onboarding/{vanilla,worker,react,next}.ndjson`, `artifacts/onboarding/{vanilla,worker,react,next}.summary.json` |
| Vanilla packaged-consumer validation | `PATH=/usr/bin:$PATH bash scripts/validate_vite_vanilla_consumer.sh` | `target/e2e-results/vite_vanilla_consumer/<timestamp>/consumer_build.log`, `target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json` |
| Browser Edition onboarding + QA smoke lane | `python3 scripts/run_browser_onboarding_checks.py --scenario all --dry-run --out-dir artifacts/onboarding && bash ./scripts/run_all_e2e.sh --suite wasm-qa-evidence-smoke` | `artifacts/onboarding/{vanilla,worker,react,next}.summary.json`, `target/wasm-qa-evidence-smoke/<run>/<scenario>/{bundle_manifest.json,run_report.json,run.log,events.ndjson}`, `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json` |
| WASM dependency/profile audit | `python3 scripts/check_wasm_dependency_policy.py --policy .github/wasm_dependency_policy.json` | `artifacts/wasm_dependency_audit_summary.json`, `artifacts/wasm_dependency_audit_log.ndjson` |
| WASM flake governance | `python3 scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json` | `artifacts/wasm_flake_governance_report.json`, `artifacts/wasm_flake_governance_events.ndjson` |
| E2E orchestration matrix | `bash ./scripts/run_all_e2e.sh --verify-matrix` | `target/e2e-results/orchestrator_<timestamp>/report.json`, `artifact_manifest.json`, `artifact_manifest.ndjson`, `replay_verification.json`, `artifact_lifecycle_policy.json` |
| Packaged bootstrap/load/reload harness | `bash ./scripts/test_wasm_packaged_bootstrap_e2e.sh` | `target/e2e-results/wasm_packaged_bootstrap/e2e-runs/<scenario>/<run>/summary.json`, `run-metadata.json`, `log.jsonl`, `steps.ndjson`, `perf-summary.json`, `artifacts/wasm_packaged_bootstrap_perf_summary.json` |
| React packaged-consumer validation | `bash ./scripts/validate_react_consumer.sh` | `target/e2e-results/react_consumer/<timestamp>/consumer_build.log`, `target/e2e-results/react_consumer/<timestamp>/summary.json` |
| Dedicated-worker packaged-consumer validation | `PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh` | `target/e2e-results/dedicated_worker_consumer/<timestamp>/consumer_build.log`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json`; the summary bundle preserves `scenario_inventory` plus artifact pointers under `artifacts` and includes `worker_storage_roundtrip_marker`, `worker_artifact_export_marker`, `worker_artifact_download_guard_marker`, `worker_artifact_quota_guard_marker`, and `worker_artifact_cleanup_marker` |
| Package shape / `npm pack` smoke | `bash ./scripts/validate_npm_pack_smoke.sh` | terminal validation output plus package artifact presence under `packages/browser-core/` |
| Browser-core artifact staging | `PATH=/usr/bin:$PATH corepack pnpm run build` | `packages/browser-core/asupersync.js`, `packages/browser-core/asupersync.d.ts`, `packages/browser-core/asupersync_bg.wasm`, `packages/browser-core/abi-metadata.json`, `packages/browser-core/debug-metadata.json` |

## Recipe Matrix

| Symptom | Likely Cause | Run | Expected Evidence |
|---|---|---|---|
| wasm32 compile fails with forbidden-surface errors | Invalid profile/feature mix (`cli`, `tls`, `sqlite`, `postgres`, `mysql`, `kafka`, etc.) or native-only leakage into the browser closure | `rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-dev` | compile output references wasm guardrails in `src/lib.rs`; supporting audit artifacts: `artifacts/wasm_dependency_audit_summary.json`, `artifacts/wasm_dependency_audit_log.ndjson` |
| `ASUPERSYNC_*_UNSUPPORTED_RUNTIME` thrown during init/bootstrap | direct runtime attempted in Node, SSR, Next server/edge, or another environment outside the shipped browser support boundary | `rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture` | contract test output proves package-specific unsupported-runtime codes, support reasons, and guidance strings; use `docs/integration.md` support matrix to choose the correct bridge-only fallback |
| WebTransport reports unsupported/runtime-denied or session/datagram setup fails | browser/runtime lacks `globalThis.WebTransport`, runtime is not a valid HTTPS/HTTP3 target, or the browser rejects datagram readiness for this endpoint | `rch exec -- cargo test --test wasm_js_exports_coverage_contract webtransport -- --nocapture`<br>`rch exec -- cargo test --test wasm_browser_feasibility_matrix web_transport_docs_name_fetch_and_websocket_fallbacks -- --exact` | contract output proves the exported WebTransport diagnostics and cleanup markers remain intact; the matrix contract proves docs still tell operators to fall back to `WebSocket` or `fetch` when WebTransport is unavailable or rejected |
| `MessageChannel` / `MessagePort` / `BroadcastChannel` expected as public Browser Edition APIs, but nothing is exported | these browser-native messaging surfaces are explicit host-capability/reactor substrate today, not shipped JS/TS SDK entrypoints | `rch exec -- cargo test --test wasm_browser_feasibility_matrix messaging_surfaces_remain_public_sdk_unshipped_but_explicitly_documented -- --exact`<br>`rch exec -- cargo test browser_reactor_message_port --lib -- --nocapture`<br>`rch exec -- cargo test browser_reactor_broadcast_channel --lib -- --nocapture` | the matrix contract proves the docs still classify the messaging boundary and name the supported fallbacks; the focused reactor tests prove MessagePort/BroadcastChannel validation paths remain covered even though the public SDK intentionally withholds those APIs |
| `ASUPERSYNC_BROWSER_STORAGE_OPERATION_FAILED`, `ASUPERSYNC_BROWSER_ARTIFACT_OPERATION_FAILED`, or `ASUPERSYNC_BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED` surfaces during browser persistence flows | blocked IndexedDB upgrade/open, quota pressure, corrupt artifact index state, or a worker/non-DOM runtime attempting direct download instead of export handoff | `rch exec -- cargo test --test wasm_js_exports_coverage_contract browser_src_index_exposes_storage_and_artifact_diagnostics -- --nocapture`<br>`PATH=/usr/bin:$PATH bash scripts/validate_vite_vanilla_consumer.sh`<br>`PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh` | contract output proves the exported codes/reasons/guidance stay in sync; bundle summaries under `target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, and `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json` confirm the maintained fixtures still exercise storage/artifact bundle markers while preserving dedicated-worker `scenario_inventory` plus artifact pointers under `artifacts` |
| packaged consumer validation says required Browser Edition artifacts are missing | `packages/browser-core/` wasm artifacts or higher-level package `dist/` outputs were not built/staged before running consumer validation | `PATH=/usr/bin:$PATH corepack pnpm run build && bash ./scripts/validate_react_consumer.sh` | built artifacts appear under `packages/browser-core/`; consumer evidence appears at `target/e2e-results/react_consumer/<timestamp>/consumer_build.log` and `summary.json` |
| dedicated-worker onboarding or bootstrap validation fails | dedicated-worker runtime guard drift, worker fetch-host regression, coordination protocol drift, or a stale packaged consumer fixture | `python3 scripts/run_browser_onboarding_checks.py --scenario worker` | `artifacts/onboarding/worker.ndjson`, `artifacts/onboarding/worker.summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/consumer_build.log`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json`; confirm the summary still preserves `scenario_inventory` plus artifact pointers under `artifacts` |
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
PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh
```

Evidence to capture:

- package-specific error code:
  - `ASUPERSYNC_BROWSER_UNSUPPORTED_RUNTIME`
  - `ASUPERSYNC_REACT_UNSUPPORTED_RUNTIME`
  - `ASUPERSYNC_NEXT_UNSUPPORTED_RUNTIME`
- `diagnostics.reason` (`missing_global_this`,
  `service_worker_not_yet_shipped`, `shared_worker_not_yet_shipped`,
  `unsupported_runtime_context`, `missing_webassembly`, or `supported`)
- capability snapshot (`hasWindow`, `hasDocument`, `hasWebAssembly`,
  `hasAbortController`, `hasFetch`, `hasWebSocket`)
- Next target (`client`, `server`, `edge`) if the failure came through
  `@asupersync/next`

Expected operator action:

- keep `@asupersync/browser` direct runtime creation in a real browser
  main-thread entrypoint or a dedicated worker bootstrap module
- when the failure is worker-specific, rerun
  `PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh`
  plus `rch exec -- cargo test --lib worker_channel::tests::coordinator_ -- --nocapture`
  to separate package/bootstrap breakage from coordination protocol drift
- keep `@asupersync/react` direct runtime usage inside client-rendered React
  trees only
- keep `@asupersync/next` server and edge code on bridge-only adapters and move
  runtime creation into a client component or browser-only module
- do not treat service-worker/shared-worker, Node.js, or SSR contexts as
  implicitly supported direct-runtime lanes unless the support matrix and
  package guards are promoted together

### C. Package Artifact and Consumer Build Failures

Use when package validators complain about missing wasm outputs, missing `dist/`
trees, or broken local consumer installs.

```bash
PATH=/usr/bin:$PATH corepack pnpm run build
bash ./scripts/validate_react_consumer.sh
PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh
bash ./scripts/validate_npm_pack_smoke.sh
```

Evidence to capture:

- built browser-core artifacts under `packages/browser-core/`
- `target/e2e-results/react_consumer/<timestamp>/consumer_build.log`
- `target/e2e-results/react_consumer/<timestamp>/summary.json`
- `target/e2e-results/dedicated_worker_consumer/<timestamp>/consumer_build.log`
- `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`
- `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json`
- the dedicated-worker summary bundle preserves `scenario_inventory` plus
  artifact pointers under `artifacts` for release-governance review
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
- `artifacts/onboarding/worker.ndjson`
- `artifacts/onboarding/react.ndjson`
- `artifacts/onboarding/next.ndjson`
- `artifacts/onboarding/vanilla.summary.json`
- `artifacts/onboarding/worker.summary.json`
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

### H. Durable Storage and Artifact Flow Failures

Use when browser-safe persistence regresses, when dedicated-worker export
handoff stops matching the package contract, or when operators report storage
quota/blocked-open/download-boundary failures.

```bash
rch exec -- cargo test --test wasm_js_exports_coverage_contract browser_src_index_exposes_storage_and_artifact_diagnostics -- --nocapture
rch exec -- cargo test --test wasm_browser_feasibility_matrix dedicated_worker_storage_ -- --nocapture
PATH=/usr/bin:$PATH bash scripts/validate_vite_vanilla_consumer.sh
PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh
```

Evidence to capture:

- `target/e2e-results/vite_vanilla_consumer/<timestamp>/consumer_build.log`
- `target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json`
- `target/e2e-results/dedicated_worker_consumer/<timestamp>/consumer_build.log`
- `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`
- `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json`
- `artifacts/onboarding/worker.summary.json` if the failure came through the onboarding runner
- dedicated-worker summary metadata:
  - `scenario_inventory`
  - `artifacts` (artifact pointers)
- dedicated-worker summary markers:
  - `worker_storage_roundtrip_marker`
  - `worker_artifact_export_marker`
  - `worker_artifact_download_guard_marker`
  - `worker_artifact_quota_guard_marker`
  - `worker_artifact_cleanup_marker`
- exact error code and reason:
  - `ASUPERSYNC_BROWSER_STORAGE_OPERATION_FAILED`
  - `ASUPERSYNC_BROWSER_ARTIFACT_OPERATION_FAILED`
  - `ASUPERSYNC_BROWSER_ARTIFACT_DOWNLOAD_UNSUPPORTED`
  - `quota_exceeded`
  - `corrupt_index`
  - `download_unavailable`

Interpretation order:

1. If the source contract test fails, fix the exported codes/guidance or cleanup API markers in `packages/browser/src/index.ts` first.
2. If the contract test passes but a consumer validator fails, inspect the summary JSON to see whether the drift is in the vanilla main-thread bundle markers or the dedicated-worker export-handoff markers.
3. If only the worker lane fails, treat direct-download behavior as suspect first; worker contexts must export bytes/blob payloads and hand them to a browser main-thread UI instead of calling `downloadArchive()` directly.
4. Cross-check `docs/WASM.md` and `docs/wasm_canonical_examples.md` before widening support claims or changing the operator guidance text.
5. Treat `blocked_upgrade` as live IndexedDB contention, not a retry loop, and treat `quota_exceeded` as an explicit retention/cleanup failure that must be resolved before persisting more artifacts.

Relevant surface reminder:

- `BrowserStorage` owns the durable IndexedDB/localStorage keys.
- `BrowserArtifactStore` sits on top of that storage layer; use
  `exportArchive()` or `exportArtifact()` in workers and reserve direct
  `downloadArchive()` / `downloadArtifact()` calls for browser main-thread DOM
  runtimes only.

### I. Lifecycle, Quiescence, and Packaged Bootstrap Failures

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

### J. Host-Capability Boundary Confusion

Use when Browser Edition users conflate dedicated-worker direct-runtime support
with browser-native messaging support, or when WebTransport is treated as an
ambient transport instead of a guarded capability lane.

```bash
rch exec -- cargo test --test wasm_browser_feasibility_matrix \
  web_transport_docs_name_fetch_and_websocket_fallbacks -- --exact

rch exec -- cargo test --test wasm_browser_feasibility_matrix \
  messaging_surfaces_remain_public_sdk_unshipped_but_explicitly_documented -- --exact

rch exec -- cargo test browser_reactor_message_port --lib -- --nocapture
rch exec -- cargo test browser_reactor_broadcast_channel --lib -- --nocapture
```

Evidence to capture:

- exact unsupported/denied WebTransport diagnostic and URL/runtime context
- proof that docs still say `WebSocket` / `fetch` is the fallback when
  WebTransport is unavailable or rejected
- proof that docs still classify `MessageChannel`, `MessagePort`, and
  `BroadcastChannel` as substrate-only from the public SDK perspective
- the focused reactor test output for MessagePort/BroadcastChannel validation
  paths

Expected operator action:

1. If the goal is direct off-main-thread Browser Edition execution, bootstrap
   the runtime inside a dedicated worker instead of looking for a
   `MessagePort` or `BroadcastChannel` API in `@asupersync/browser`.
2. If the goal is same-origin app coordination, keep
   `MessageChannel` / `MessagePort` / `BroadcastChannel` at the application
   boundary and pass serialized data into Asupersync-owned scopes/tasks.
3. If the hop crosses into server, edge, Node, or another non-browser
   boundary, route through explicit bridge-only adapters instead of widening
   the browser direct-runtime contract.
4. If WebTransport is unavailable or handshake/datagram setup fails, fall back
   to `WebSocket` or `fetch` unless and until the deployment/runtime satisfies
   the guarded prerequisites.

### K. Optional-Lane Rollout, Demotion, and No-Go Policy

Use when the question is not "which command failed?" but "is this advanced lane
allowed to widen exposure at all?"

Read the latest ladder decision tuple first:

1. `support_class`
2. `reason_code`
3. `fallback_lane_id`
4. `lane_health_status`
5. `lane_health_failure_count`
6. `lane_health_retry_budget_remaining`
7. `lane_health_cooldown_until_ms`
8. `lane_health_last_trigger`
9. `demoted_lane_id`
10. `repro_command`
11. `policy_schema_version`

Then compare the surface against its ceiling in
`docs/wasm_release_channel_strategy.md`.

Deterministic command bundle:

```bash
python3 scripts/check_wasm_worker_offload_policy.py \
  --policy .github/wasm_worker_offload_policy.json

python3 scripts/check_wasm_benchmark_corpus.py \
  --policy .github/wasm_benchmark_corpus.json

python3 scripts/check_perf_regression.py \
  --budgets .github/wasm_perf_budgets.json \
  --profile core-min

rch exec -- ./scripts/run_perf_e2e.sh \
  --bench phase0_baseline \
  --bench scheduler_benchmark \
  --seed 42 \
  --metric p95_ns

rch exec -- bash ./scripts/run_nightly_stress_soak.sh \
  --ci \
  --suites cancellation_stress,scheduler_fairness \
  --timeout 3600

rch exec -- cargo test --test wasm_browser_feasibility_matrix -- --nocapture
rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture
```

Required evidence to capture:

- `artifacts/wasm_worker_offload_summary.json`
- `artifacts/wasm_benchmark_corpus_summary.json`
- `artifacts/wasm_perf_regression_report.json`
- `artifacts/wasm_perf_gate_events.ndjson`
- `target/nightly-stress/<run_id>/trend_report.json`
- `target/nightly-stress/<run_id>/run_manifest.json`
- the latest lane log or diagnostic blob containing `support_class`,
  `reason_code`, `fallback_lane_id`, `lane_health_status`,
  `lane_health_failure_count`, `lane_health_retry_budget_remaining`,
  `lane_health_last_trigger`, `demoted_lane_id`, and `repro_command`

Decision table:

| Surface family | Truthful ceiling today | Green-light conditions | Mandatory no-go / demotion trigger |
|---|---|---|---|
| Dedicated-worker direct runtime | may reach `stable` | `support_class=direct_runtime_supported`, `reason_code=supported`, lane health is healthy, and worker artifacts are green in the same window | any worker-only lane-health demotion, missing worker onboarding/consumer evidence, or a regression that forces fallback to the browser main thread |
| `WebTransport` datagrams | `guarded canary-only` | HTTPS/HTTP3 prerequisites hold, diagnostics remain healthy, and docs/tests still point to `WebSocket` / `fetch` as the fallback | `candidate_prerequisite_missing`, `downgrade_to_websocket_or_fetch`, handshake/datagram rejection, or missing fallback guidance |
| Rust-authored browser path | `preview_only` | maintained fixture evidence is green and the public Rust-callable builder lane actually exists | any attempt to present the lane as public/stable while it remains repository-maintained only |
| Browser-native messaging (`MessageChannel`, `MessagePort`, `BroadcastChannel`) | `preview_only` | public SDK exports and explicit API contract tests exist | any claim that the shipped Browser Edition SDK already exports these surfaces as stable runtime lanes |
| `SharedArrayBuffer` / worker offload / parallel executor lanes | `nightly-only` | cross-origin isolation is proven, worker-offload policy is green, replay and perf artifacts are green, and nightly stress/soak trends are clean | `shared_array_buffer_requires_cross_origin_isolation`, any replay drift, any perf regression, any stress/soak regression, or any lane-health demotion |

Interpretation order:

1. If the surface asks for a label above its ceiling (`preview_only`,
   `guarded canary-only`, or `nightly-only`), stop: that is already `NO_GO`.
2. If `support_class` is `bridge_only` or `unsupported`, publish the fallback
   or fail-closed path as the supported behavior. Do not widen exposure.
3. If `reason_code` is `candidate_prerequisite_missing`,
   `candidate_lane_unhealthy`, or `demote_due_to_lane_health`, keep the lane
   in its lowered state until a fresh green evidence bundle exists.
4. If the lane is performance- or chaos-sensitive, require both
   `artifacts/wasm_perf_regression_report.json` and
   `target/nightly-stress/<run_id>/trend_report.json` before retrying.
5. If the lane reaches users only through a downgrade
   (`downgrade_to_websocket_or_fetch`,
   `downgrade_to_export_bytes_for_download`, bridge-only targets), describe the
   downgraded path as the actual supported product behavior.

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
- `docs/WASM.md` (authoritative Browser Edition support matrix)
- `docs/wasm_canonical_examples.md` (maintained browser example and validator bundle contract)
- `docs/wasm_dx_error_taxonomy.md` (package error codes, recoverability, and guidance contract)
- `docs/wasm_quickstart_migration.md` (onboarding/release-channel flow)
- `docs/wasm_qa_evidence_matrix_contract.md` (smoke runner contract and artifact bundle schema)
- `docs/wasm_bundler_compatibility_matrix.md` (bundler contract and CI lane)
- `docs/wasm_flake_governance_and_forensics.md` (incident governance)
- `docs/doctor_logging_contract.md` (redaction and log-quality contracts)
