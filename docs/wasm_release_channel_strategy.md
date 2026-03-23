# WASM Release Channel Strategy

Contract ID: `wasm-release-channel-strategy-v1`  
Bead: `asupersync-umelq.15.3`  
Depends on: `asupersync-umelq.15.1`

## Purpose

Define a deterministic promotion and demotion workflow for Browser Edition
artifacts across three channels:

1. `nightly` (fast feedback, highest churn),
2. `canary` (limited-risk pre-stable validation),
3. `stable` (production channel with strict release gates).

This policy is intentionally gate-driven: no channel promotion is valid unless
all required checks and artifact contracts pass.

## Channel Contract

| Channel | Optimization profile | Intended use | Promotion source |
|---|---|---|---|
| `nightly` | `wasm-browser-dev` | Daily integration and rapid iteration | n/a |
| `canary` | `wasm-browser-canary` | Limited rollout and early regression detection | `nightly` |
| `stable` | `wasm-browser-release` | Production release lane | `canary` |

Profile definitions are sourced from:

- `.github/wasm_optimization_policy.json`
- `scripts/check_wasm_optimization_policy.py`

## Required Promotion Gates

Promotion requires all gates below to pass in the same decision window.

### Gate 1: Profile and optimization policy validity

```bash
python3 scripts/check_wasm_optimization_policy.py \
  --policy .github/wasm_optimization_policy.json
```

Required artifact:

- `artifacts/wasm_optimization_pipeline_summary.json`

### Gate 2: Dependency provenance and forbidden-crate audit

```bash
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json
```

Required artifacts:

- `artifacts/wasm_dependency_audit_summary.json`
- `artifacts/wasm_dependency_audit_log.ndjson`

### Gate 3: Security release gate (with dependency checks enabled)

```bash
python3 scripts/check_security_release_gate.py \
  --policy .github/security_release_policy.json \
  --check-deps \
  --dep-policy .github/wasm_dependency_policy.json
```

Required artifacts:

- `artifacts/security_release_gate_report.json`
- `artifacts/security_release_gate_events.ndjson`

### Gate 4: Browser profile build checks (cargo-heavy, offloaded)

```bash
rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-dev

rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-prod

rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-deterministic
```

### Gate 5: Deterministic scenario evidence and replayability

Run deterministic onboarding and scenario validation before promotion:

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario all
```

At minimum, promotion evidence must include:

1. command bundle used for each gate,
2. produced artifacts and paths,
3. replay command pointers for any non-pass diagnostics.

### Gate 6: Packaged release artifact and consumer-build evidence

Pilot and GA promotion for `asupersync-3qv04.7.3` is not satisfied by policy
documents alone. Release confidence must be derived from real packages, real
consumer builds, and real behavioral evidence from the current candidate.

Required package-release artifacts:

- `artifacts/npm/package_release_validation.json`
- `artifacts/npm/package_pack_dry_run_summary.json`
- `artifacts/npm/publish_outcome.json`

The Gate 6 package-validation command bundle must also prove that the candidate
ran the full Browser Edition package gate, not a symbolic placeholder. The
accepted evidence is either `corepack pnpm run validate` from the root workspace
or direct command provenance showing both `bash scripts/validate_package_build.sh`
and `bash scripts/validate_npm_pack_smoke.sh` for the same candidate window.
A lone generic `validate` label without both underlying validators is
insufficient for promotion.

Required consumer-build and smoke artifacts:

- `artifacts/onboarding/vanilla.summary.json`
- `artifacts/onboarding/react.summary.json`
- `artifacts/onboarding/next.summary.json`
- `target/wasm-qa-evidence-smoke/<run>/<scenario>/bundle_manifest.json`
- `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json`

Missing any Gate 6 artifact is a release-blocking failure even if the policy,
security, and dependency gates are otherwise green.

## VNext Surface Promotion Ceilings

The Browser Edition channel decision does not automatically promote every new
browser-facing surface. Each vNext surface must carry its own promotion ceiling
that matches the live support bucket in `docs/WASM.md`.

| Surface | Support bucket in `docs/WASM.md` | Promotion ceiling before extra closure | Minimum promotion evidence | Default demotion / rollback |
|---|---|---|---|---|
| `Dedicated Web Worker` direct-runtime lane | `Direct-runtime supported` | may reach `stable` only when worker-specific evidence is green in the reviewed candidate window | `artifacts/onboarding/worker.summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json`, `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh`; the reviewed candidate must preserve the dedicated-worker `scenario_inventory` plus artifact pointers under `artifacts` in the summary bundle | demote the worker lane from `stable` to `canary`; keep the browser main-thread runtime as the stable fallback |
| `IndexedDB` durable storage + `BrowserArtifactStore` | `Direct-runtime supported` | may reach `stable` only when storage/artifact diagnostics, export flows, and fixture evidence are green | `target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `PATH=/usr/bin:$PATH bash scripts/validate_vite_vanilla_consumer.sh`, `PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh` | demote durable storage/artifact claims to `canary` and remove any durable-persistence promise rather than silently substituting ambient persistence |
| Rust-authored browser path | `Direct-runtime feasible but not yet shipped` | `preview_only`; no `stable` promotion while the lane is still repository-maintained rather than a public Rust-callable browser builder | `PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh`, `target/e2e-results/rust_browser_consumer/<timestamp>/summary.json`, `target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json`, `tests/wasm_rust_browser_example_contract.rs`, `docs/wasm_quickstart_migration.md` | downgrade to `architecturally feasible only` and remove any public/stable claim if the fixture, docs, or browser-run evidence regresses |
| `WebTransport` datagrams | `Guarded direct-runtime support` | `guarded canary-only` unless the HTTPS/HTTP3 prerequisites and fallback evidence stay green | `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `docs/WASM.md`, `docs/wasm_troubleshooting_compendium.md` | demote to `preview_only` and require `WebSocket` / `fetch` fallback guidance in release notes |
| Service-worker bounded broker registration + durable handoff | `Guarded package-level support on service-worker hosts` | `guarded canary-only`; never `stable` while the host itself remains a fail-closed direct-runtime denial and while broker lifecycle evidence is still contract-grade rather than broad runtime-grade | `docs/wasm_service_worker_broker_contract.md`, `tests/wasm_service_worker_broker_contract.rs`, `docs/WASM.md`, `packages/browser/src/index.ts`; every candidate must preserve explicit broker registration, durable handoff, and downgrade diagnostics without widening the host claim | demote to `preview_only`, keep `service_worker_not_yet_shipped` / `service_worker_direct_runtime_not_shipped` as the public truth, and require dedicated-worker or browser main-thread fallback guidance in release notes |
| Shared-worker bounded coordinator attach + downgrade | `Guarded package-level support from browser main-thread or dedicated-worker callers` | `guarded canary-only`; never `stable` while SharedWorker direct runtime remains fail-closed and while attach/handshake/loss evidence is still bounded-coordinator-only | `docs/wasm_shared_worker_tenancy_lifecycle_contract.md`, `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `docs/WASM.md`, `packages/browser/src/index.ts`; every candidate must preserve explicit coordinator attach, version handshake, and downgrade semantics | demote to `preview_only`, keep `shared_worker_direct_runtime_not_shipped` as the public truth, and require dedicated-worker or browser main-thread fallback guidance in release notes |
| Browser-native messaging (`MessageChannel`, `MessagePort`, `BroadcastChannel`) | `Direct-runtime feasible but not yet shipped as public Browser Edition APIs` | `preview_only`; no `stable` promotion while the public SDK intentionally does not export them | `docs/wasm_api_surface_census.md`, `docs/WASM.md`, public API contract tests once the SDK exports land | revert to application-boundary-only guidance and remove any public Browser Edition support claim |
| `SharedArrayBuffer` / worker offload / parallel executor lanes | `Guarded optional, not shipped` | `nightly-only` or explicitly marked preview experiments; never default `stable` | closure of `asupersync-2jhnk.2`, `asupersync-2jhnk.3`, `asupersync-2jhnk.4`, and `asupersync-2jhnk.5`, plus cross-origin-isolation, replay, chaos, and performance evidence | disable the lane immediately and demote `canary -> nightly`; preserve the single-threaded browser runtime as the only supported default |

## Optional-Lane Operator Decision Law

The table above defines ceilings. This section defines the operator law for
whether a lane is actually eligible to widen exposure inside that ceiling.

Every optional-lane decision record must capture these fields from the latest
diagnostic or ladder log:

- `support_class`
- `reason_code`
- `fallback_lane_id`
- `lane_health_status`
- `lane_health_failure_count`
- `lane_health_retry_budget_remaining`
- `lane_health_cooldown_until_ms`
- `lane_health_last_trigger`
- `demoted_lane_id`
- `repro_command`
- `policy_schema_version`

Interpret the latest tuple with this state machine:

| Observed tuple | Allowed external label | Required operator action |
|---|---|---|
| `support_class=direct_runtime_supported`, `reason_code=supported`, `lane_health_status=healthy` | may follow the surface ceiling from the vNext table | verify the surface-specific artifacts are green in the same decision window before widening exposure |
| `support_class=direct_runtime_supported`, `reason_code=candidate_prerequisite_missing` | hold at `preview_only`, `guarded canary-only`, or `nightly-only` | publish the missing prerequisite, keep fallback guidance explicit, and block promotion until the next green evidence window |
| any `candidate_lane_unhealthy` or `demote_due_to_lane_health` result | demote one level below the requested channel; never claim `stable` during the unhealthy window | treat the lane as failed over, preserve the fallback path, and require fresh replay/perf/support evidence before retrying |
| `support_class=bridge_only` with `downgrade_to_server_bridge`, `downgrade_to_edge_bridge`, `downgrade_to_websocket_or_fetch`, or `downgrade_to_export_bytes_for_download` | `bridge_only` or the named fallback only | release notes and diagnostics must describe the downgrade as the supported path, not as degraded direct-runtime parity |
| any `policy_denial` or `unsupported` reason (`service_worker_direct_runtime_not_shipped`, `shared_worker_direct_runtime_not_shipped`, `shared_array_buffer_requires_cross_origin_isolation`, `unsupported_runtime_context`) | keep the lane disabled, `preview_only`, or `nightly-only` per the vNext table | treat the request as `NO_GO` for wider rollout and keep the fail-closed or downgraded path in place |

Mandatory evidence bundle before promoting or re-enabling an optional lane:

1. the latest ladder log with `support_class`, `reason_code`,
   `fallback_lane_id`, `lane_health_status`, `lane_health_failure_count`,
   `lane_health_retry_budget_remaining`, `lane_health_last_trigger`,
   `demoted_lane_id`, and `repro_command`,
2. `python3 scripts/check_wasm_worker_offload_policy.py --policy .github/wasm_worker_offload_policy.json`
   producing `artifacts/wasm_worker_offload_summary.json`,
3. `python3 scripts/check_wasm_benchmark_corpus.py --policy .github/wasm_benchmark_corpus.json`
   producing `artifacts/wasm_benchmark_corpus_summary.json`,
4. `python3 scripts/check_perf_regression.py --budgets .github/wasm_perf_budgets.json --profile core-min`
   producing `artifacts/wasm_perf_regression_report.json` and
   `artifacts/wasm_perf_gate_events.ndjson`,
5. `rch exec -- ./scripts/run_perf_e2e.sh --bench phase0_baseline --bench scheduler_benchmark --seed 42 --metric p95_ns`
   or the surface-specific benchmark corpus repro command for the candidate,
6. `rch exec -- bash ./scripts/run_nightly_stress_soak.sh --ci --suites cancellation_stress,scheduler_fairness --timeout 3600`
   with `target/nightly-stress/<run_id>/trend_report.json`,
7. the surface-specific artifacts from the vNext table plus
   `docs/WASM.md` and `docs/wasm_troubleshooting_compendium.md`.

Automatic `NO_GO` triggers for optional lanes:

1. a surface asks for a label above its ceiling (`preview_only`,
   `guarded canary-only`, or `nightly-only`),
2. `lane_health_status` is not healthy or retry budget is exhausted,
3. cross-origin isolation is missing for any `SharedArrayBuffer` or worker
   offload lane,
4. fallback guidance is missing for `WebTransport`, worker artifact export, or
   any bridge-only downgrade,
5. any replay, performance, benchmark-corpus, or nightly stress artifact is
   missing, stale, or not attributable to the reviewed candidate.

## Promotion Rules

`nightly -> canary` promotion requires:

1. all required gates pass,
2. no critical/high unresolved findings in security release gate report,
3. dependency policy transitions are active and non-expired,
4. package validation and pack dry-run artifacts exist for the candidate, with
   command provenance tying the candidate to both
   `bash scripts/validate_package_build.sh` and
   `bash scripts/validate_npm_pack_smoke.sh`,
5. onboarding and QA smoke artifacts exist for the same decision window.

`canary -> stable` promotion requires:

1. all required gates pass on canary artifact set,
2. no blocked release criteria in security report (`gate_status != fail`),
3. artifact provenance present and reproducible for optimization, dependency,
   and security summaries,
4. no unresolved deterministic replay failures from the selected promotion run,
5. package validation, pack dry-run, and publish outcome artifacts are
   reproducible for the current candidate, and the package-validation provenance
   must still show both `bash scripts/validate_package_build.sh` and
   `bash scripts/validate_npm_pack_smoke.sh`,
6. consumer-build onboarding summaries and QA smoke bundle/summary artifacts
   are reproducible for the current candidate.

No vNext surface may be promoted above the ceiling declared in
`docs/WASM.md` and the table above. A `stable` Browser Edition release may
ship with `preview_only`, `guarded canary-only`, `bridge-only`, or
`impossible` surfaces still present in the documentation, but release notes and
support diagnostics must keep those labels explicit rather than implying that
every browser-facing surface inherited `stable` by package association.

## Demotion and Rollback Policy

Demotion is mandatory when one of these triggers occurs post-publish:

1. any release-blocking security criterion fails,
2. dependency policy check fails due to forbidden crate hit or expired
   conditional transition,
3. deterministic replay checks for mandatory scenarios fail in two consecutive
   release-gate runs,
4. required promotion artifacts are missing or non-reproducible,
5. package validation or pack dry-run artifacts are missing, stale, do not
   match the candidate being promoted, or do not prove both
   `bash scripts/validate_package_build.sh` and
   `bash scripts/validate_npm_pack_smoke.sh`,
6. consumer-build onboarding or QA smoke artifacts are missing, stale, or not
   reproducible for the candidate being promoted.
7. any vNext surface is described above its documented ceiling
   (`preview_only`, `guarded canary-only`, `nightly-only`, `bridge-only`, or
   `impossible`) or loses the artifact bundle listed in the vNext promotion
   table.

Demotion actions:

1. `stable -> canary` immediately on trigger detection.
2. If canary also violates a blocking trigger, `canary -> nightly`.
3. Record demotion event with trigger id, artifact pointers, and replay command.
4. Open/attach a remediation bead before any re-promotion attempt.

## Operator Runbook (Deterministic Order)

1. Run optimization policy check.
2. Run dependency policy check.
3. Run security gate with `--check-deps`.
4. Run `rch` offloaded wasm profile checks.
5. Run deterministic onboarding/scenario validation.
6. Confirm package validation, pack dry-run, and publish outcome artifacts for
   the candidate are present and non-empty, and that the command bundle still
   captures `corepack pnpm run validate` or both
   `bash scripts/validate_package_build.sh` and
   `bash scripts/validate_npm_pack_smoke.sh`.
7. Confirm onboarding summaries plus QA smoke bundle/summary artifacts for the
   same candidate are present and non-empty.
8. For any optional lane, attach the latest decision tuple
   (`support_class`, `reason_code`, `fallback_lane_id`, lane-health fields,
   and `repro_command`) plus the optional-lane evidence bundle before
   widening exposure.
9. Publish promotion decision with command + artifact pointers.

## Traceability and Audit Fields

Promotion or demotion decisions must capture:

1. channel transition (`from`, `to`),
2. decision timestamp (UTC),
3. command bundle (exact commands),
4. artifact paths and hashes where available,
5. blocking criterion IDs (if demoted),
6. owning bead ID for remediation.

## Workflow Contract + Package Assumptions

The canonical automation entrypoint for this contract is:

- `.github/workflows/publish.yml`
- `docs/wasm_release_rollback_incident_playbook.md` (operational rollback + incident procedure)

Release automation for this workflow is tied to:

- contract id: `wasm-release-channel-strategy-v1`
- active bead scope: `asupersync-umelq.15.2`

Policy wiring expectations:

1. WASM release gates produce a traceability artifact linking this contract
   to security release-block criteria in `.github/security_release_policy.json`
   (for example `SEC-BLOCK-01`, `SEC-BLOCK-06`, and `SEC-BLOCK-07`).
2. Required gate report artifacts are retained alongside release artifacts:
   - `artifacts/wasm_optimization_pipeline_summary.json`
   - `artifacts/wasm_dependency_audit_summary.json`
   - `artifacts/security_release_gate_report.json`
3. npm release assumptions are explicit and artifactized:
   - package discovery glob: `packages/*/package.json`
   - discovered package path list: `artifacts/npm/package_json_paths.txt`
   - assumptions artifact: `artifacts/npm/npm_release_assumptions.json`
   - package validation artifact: `artifacts/npm/package_release_validation.json`
   - pack dry-run evidence artifact: `artifacts/npm/package_pack_dry_run_summary.json`
   - publish outcome artifact: `artifacts/npm/publish_outcome.json`
   - rollback outcome artifact (when rollback mode is used): `artifacts/npm/rollback_outcome.json`
4. Missing package manifests are a hard release-blocking failure. Missing package manifests or missing built package outputs are hard release-blocking failures. The exact required package set from
   `.github/wasm_typescript_package_policy.json` must be discovered, built via
   `corepack pnpm run build`, validated with
   `bash scripts/validate_package_build.sh`, and pack-smoke checked with
   `bash scripts/validate_npm_pack_smoke.sh`, and evidenced with
   `npm pack --json --dry-run` before any npm publish can proceed.
5. Consumer-build and behavioral evidence are artifactized alongside the
   package-release bundle:
   - `artifacts/onboarding/vanilla.summary.json`
   - `artifacts/onboarding/react.summary.json`
   - `artifacts/onboarding/next.summary.json`
   - `target/wasm-qa-evidence-smoke/<run>/<scenario>/bundle_manifest.json`
   - `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json`
6. Rollback mode requires both target version and operator reason; the executed
   dist-tag commands must be captured in release artifacts.

Incident response and rollback operational requirements are defined in:

- `docs/wasm_release_rollback_incident_playbook.md`

That playbook is enforced by CI certification artifacts:

- `artifacts/wasm_release_rollback_playbook_summary.json`
- `artifacts/wasm_release_rollback_playbook_test.log`

## Non-Negotiable Constraints

1. No channel promotion can bypass dependency or security gates.
2. No channel promotion can proceed with unresolved critical findings.
3. Cargo-heavy validation in this workflow must be executed through `rch`.
4. This policy does not weaken runtime invariants: structured concurrency,
   cancellation protocol, loser-drain behavior, obligation closure, and explicit
   capability boundaries remain mandatory.
