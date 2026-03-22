# WASM GA Readiness Review Board and Go/No-Go Checklist

**Bead**: `asupersync-umelq.17.4`  
**Contract ID**: `wasm-ga-readiness-review-board-checklist-v1`  
**Program**: `asupersync-umelq.17` (WASM-16 Pilot Program, GA Readiness, and Launch Governance)

## Purpose

Define a deterministic, fail-closed GA decision process for Browser Edition
promotion. The review board consumes upstream evidence artifacts, applies
objective thresholds, records waiver rationale when allowed, and emits a
machine-readable decision packet.

This checklist is operational policy, not narrative guidance.

## Prerequisite Beads and Evidence Inputs

This checklist is blocked until the following dependencies have executable
evidence available:

| Bead | Scope | Required Evidence |
|---|---|---|
| `asupersync-umelq.17.2` | pilot telemetry and SLO contract | `docs/wasm_pilot_observability_contract.md`, `artifacts/pilot/pilot_observability_summary.json` |
| `asupersync-umelq.15.5` | release rollback and incident response | `docs/wasm_release_rollback_incident_playbook.md`, `artifacts/wasm_release_rollback_playbook_summary.json` |
| `asupersync-umelq.14.5` | security release blocking criteria | `scripts/check_security_release_gate.py`, `artifacts/security_release_gate_report.json` |
| `asupersync-umelq.13.5` | continuous performance regression gates | `.github/wasm_perf_budgets.json`, `artifacts/wasm_perf_regression_report.json` |
| `asupersync-umelq.16.5` | rationale index and design traceability | `docs/wasm_rationale_index.md`, `tests/wasm_rationale_index.rs` |
| `asupersync-umelq.12.5` | incident forensics and replay workflow | `docs/replay-debugging.md`, replay artifact pointer in decision packet |
| `asupersync-umelq.18.10` | nightly stress/soak and flake-burndown | `docs/nightly_stress_soak_automation.md`, `target/nightly-stress/<run_id>/trend_report.json` |

## Browser Edition Release Mapping

The current Browser Edition release-promotion bead is `asupersync-3qv04.7.3`.
This checklist remains the board-level fail-closed decision surface, but the
packet is incomplete unless it also points to the live Browser Edition release
evidence below.
That Browser Edition evidence must satisfy Gate 6 package-release and
consumer-build artifacts from `docs/wasm_release_channel_strategy.md`, not
just higher-level policy approval text.
For the package-validation portion of Gate 6, the board must reject any packet
that cannot show `corepack pnpm run validate` or both
`bash scripts/validate_package_build.sh` and
`bash scripts/validate_npm_pack_smoke.sh` for the reviewed candidate.

| Browser Bead | Scope | Required Artifact-Backed Evidence |
|---|---|---|
| `asupersync-3qv04.6.5` | packaged ABI compatibility upgrade/downgrade matrix | `docs/wasm_abi_compatibility_policy.md`, `artifacts/wasm_abi_contract_summary.json`, `artifacts/wasm_abi_contract_events.ndjson`, `tests/wasm_packaged_abi_compatibility_matrix.rs` |
| `asupersync-3qv04.6.6` | packaged browser-behavior E2E baseline | `docs/wasm_packaged_bootstrap_harness_contract.md`, `docs/wasm_packaged_cancellation_harness_contract.md`, `artifacts/wasm_packaged_bootstrap_harness_v1.json`, `artifacts/wasm_packaged_cancellation_harness_v1.json` |
| `asupersync-3qv04.6.7` | aggregate bundle-size, startup-latency, and memory budget enforcement | `.github/wasm_perf_budgets.json`, `artifacts/wasm_budget_summary.json`, `artifacts/wasm_perf_regression_report.json` |
| `asupersync-3qv04.6.7.1` | bundle-size budgets and regression gates | `docs/wasm_bundle_size_budget.md`, `artifacts/wasm_bundle_size_budget_v1.json`, `tests/wasm_bundle_size_budget_contract.rs` |
| `asupersync-3qv04.6.7.2` | packaged startup/bootstrap latency budgets | `docs/wasm_packaged_bootstrap_harness_contract.md`, `artifacts/wasm_packaged_bootstrap_perf_summary.json`, `artifacts/wasm_packaged_bootstrap_harness_v1.json` |
| `asupersync-3qv04.6.7.3` | packaged steady-state, shutdown, and cancellation budgets | `docs/wasm_packaged_cancellation_harness_contract.md`, `artifacts/wasm_packaged_cancellation_perf_summary.json`, `artifacts/wasm_packaged_cancellation_harness_v1.json` |
| `asupersync-3qv04.6.8` | package-manager and module-resolution compatibility matrix | `docs/wasm_bundler_compatibility_matrix.md`, `docs/wasm_typescript_package_topology.md`, `artifacts/wasm_typescript_package_summary.json`, `artifacts/wasm_typescript_package_log.ndjson` |
| `asupersync-3qv04.7.1` | real package publish workflow and pack validation | `.github/workflows/publish.yml`, `artifacts/npm/package_release_validation.json`, `artifacts/npm/package_pack_dry_run_summary.json`, `artifacts/npm/publish_outcome.json` |
| `asupersync-3qv04.7.2` | shipped-output SBOM, provenance, and integrity | `docs/wasm_browser_sbom_v1.json`, `docs/wasm_browser_provenance_attestation_v1.json`, `docs/wasm_browser_artifact_integrity_manifest_v1.json` |
| `asupersync-3qv04.8.6` | deterministic onboarding and QA smoke entrypoints | `artifacts/onboarding/vanilla.summary.json`, `artifacts/onboarding/react.summary.json`, `artifacts/onboarding/next.summary.json`, `artifacts/onboarding/worker.summary.json`, `target/wasm-qa-evidence-smoke/<run>/<scenario>/bundle_manifest.json`, `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json` |
| `asupersync-3qv04.9.1` | install and quickstart paths | `docs/wasm_quickstart_migration.md`, `docs/integration.md` |
| `asupersync-3qv04.9.2` | environment support and compatibility guidance | `docs/wasm_bundler_compatibility_matrix.md`, `docs/wasm_release_channel_strategy.md` |
| `asupersync-3qv04.9.3` | maintained example surfaces from validated fixtures | `docs/wasm_canonical_examples.md`, `target/e2e-results/rust_browser_consumer/<timestamp>/summary.json`, `target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json` |
| `asupersync-3qv04.9.4` / `asupersync-3qv04.9.5` | troubleshooting plus API or version guidance | `docs/wasm_troubleshooting_compendium.md`, `docs/wasm_api_surface_census.md` |

Missing any Browser Edition artifact above is a hard-blocking gap for
`asupersync-3qv04.7.3` even if the older governance-program packet is
otherwise complete.

## VNext Surface Review Rows

The board must review the post-v1 browser surfaces individually. None of the
rows below inherit `stable` by association with the baseline Browser Edition
package release.

| Review Row | Surface | Ceiling / support rule | Minimum evidence before approval | Hard-blocking when... |
|---|---|---|---|---|
| `VT-DW-01` | `Dedicated Web Worker` direct-runtime lane | may reach `stable` only when the worker lane is still `Direct-runtime supported` in `docs/WASM.md` and the worker evidence bundle is green | `artifacts/onboarding/worker.summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json`, `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`; the reviewed candidate must preserve dedicated-worker `scenario_inventory` and `artifacts` pointers | the packet claims stable worker support without those artifacts |
| `VT-STORAGE-01` | `IndexedDB` durable storage + `BrowserArtifactStore` | may reach `stable` only when blocked-upgrade/quota/export diagnostics and maintained fixture evidence remain green | `target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json`, `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`, `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs` | durable browser persistence is claimed without artifact-backed storage/export evidence |
| `VT-RUST-01` | Rust-authored browser path | `preview_only` until the lane stops being merely `Direct-runtime feasible but not yet shipped` | `PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh`, `target/e2e-results/rust_browser_consumer/<timestamp>/summary.json`, `target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json`, `tests/wasm_rust_browser_example_contract.rs`, `docs/wasm_quickstart_migration.md` | the packet presents the Rust browser path as stable/public without the fixture evidence bundle |
| `VT-WT-01` | `WebTransport` guarded lane | `guarded canary-only` until prerequisites and fallback evidence remain green | `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `docs/WASM.md`, `docs/wasm_troubleshooting_compendium.md` | WebTransport is claimed above its guarded ceiling or without explicit fallback guidance |
| `VT-SW-BROKER-01` | Service-worker bounded broker registration + durable handoff | `guarded canary-only`; never `stable` while the direct runtime still returns `service_worker_not_yet_shipped` / `service_worker_direct_runtime_not_shipped` | `docs/wasm_service_worker_broker_contract.md`, `tests/wasm_service_worker_broker_contract.rs`, `docs/WASM.md`, `packages/browser/src/index.ts` | the packet claims service-worker broker support above `guarded canary-only` or omits the bounded broker downgrade truth |
| `VT-SHARED-01` | Shared-worker bounded coordinator attach + downgrade | `guarded canary-only`; never `stable` while SharedWorker direct runtime remains `shared_worker_direct_runtime_not_shipped` | `docs/wasm_shared_worker_tenancy_lifecycle_contract.md`, `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `docs/WASM.md`, `packages/browser/src/index.ts` | the packet claims shared-worker coordinator support above `guarded canary-only` or omits the fail-closed downgrade truth |
| `VT-MSG-01` | `MessageChannel`, `MessagePort`, `BroadcastChannel` | `preview_only` while the Browser Edition public SDK intentionally does not export them | `docs/wasm_api_surface_census.md`, `docs/WASM.md`, public API contract tests once exported | the packet turns application-boundary-only messaging into a public/stable Browser Edition promise |
| `VT-SAB-01` | `SharedArrayBuffer` / worker offload / parallel executor lanes | `nightly-only` or preview; never default `stable` while `asupersync-2jhnk.*` remains open | `asupersync-2jhnk.2`, `asupersync-2jhnk.3`, `asupersync-2jhnk.4`, `asupersync-2jhnk.5`, plus replay/chaos/perf evidence | the packet claims SAB/offload as GA/stable without cross-origin-isolation and closure evidence |

## Mandatory Evidence Fields

Every gate row in the review packet must define all fields below.

| Field | Description |
|---|---|
| `gate_id` | Stable identifier (`GA-GATE-xx`) |
| `source_bead` | Upstream bead ID |
| `artifact_path` | Relative artifact path |
| `generated_at_utc` | Evidence generation timestamp |
| `repro_command` | Deterministic rerun command |
| `threshold_rule` | Objective pass criterion |
| `observed_value` | Measured result |
| `gate_status` | `pass` / `fail` / `waived` |
| `owner_role` | Responsible sign-off role |
| `log_pointer` | Structured log artifact |
| `trace_pointer` | Replay trace pointer when applicable |
| `waiver_reason` | Mandatory when status is `waived` |
| `waiver_approver` | Mandatory when status is `waived` |
| `unresolved_risk_ids` | Residual risks linked by ID |

## Sign-Off Roles and Quorum

Required roles:

1. Review Board Chair
2. Runtime Semantics Lead
3. Security Lead
4. Performance Lead
5. Observability Lead
6. Release Operations Lead
7. Support Readiness Lead

Minimum quorum:

- Review Board Chair plus 5 of 6 remaining roles.
- Runtime Semantics Lead, Security Lead, and Release Operations Lead are
  mandatory participants and cannot be absent.

## Objective Gate Model

### Hard-Blocking Gates

The following conditions are always release-blocking:

1. Missing mandatory evidence field on any gate row.
2. Any upstream blocker artifact missing or unreadable.
3. `security_release_gate_report.json` indicates release-blocking finding.
4. `wasm_perf_regression_report.json` indicates budget violation.
5. Pilot observability summary indicates `status = fail`.
6. Stress/soak trend report indicates `regression_detected = true`.
7. Rollback playbook certification missing or failing.
8. Any vNext surface row is missing or is claimed above its documented
   ceiling (`preview_only`, `guarded canary-only`, `nightly-only`,
   `bridge-only`, or `impossible`).

### Aggregate Decision Rule

Decision status is computed with fail-closed logic:

- `NO_GO` if any hard-blocking gate triggers.
- `NO_GO` if quorum is not satisfied.
- `NO_GO` if unresolved critical risk remains open.
- `GO` only when all gates pass or are validly waived and aggregate score is
  `>= 0.90`.

## Waiver Policy

Waivers are allowed only for non-critical gates.

Waiver requirements:

1. `waiver_reason` is concrete and evidence-linked.
2. `waiver_approver` is the Review Board Chair plus one mandatory role lead.
3. Waiver expiry timestamp is defined.
4. Follow-up bead ID is recorded.

Waivers are forbidden for:

- security blockers,
- missing rollback controls,
- missing deterministic replay pointers,
- unresolved critical risks.

## Deterministic Review Rehearsal

Primary contract test:

```bash
rch exec -- cargo test -p asupersync --test wasm_ga_readiness_review_board_checklist -- --nocapture
```

Replay-focused preflight:

```bash
rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture
python3 scripts/check_security_release_gate.py --policy .github/security_release_policy.json
python3 scripts/check_perf_regression.py --budgets .github/wasm_perf_budgets.json --profile core-min
```

Evidence synchronization expectation:

- artifacts used in the board packet must be generated from the same CI run or
  from explicitly version-pinned artifacts with matching commit SHA.

## Decision Packet Schema

The board must emit:

- `artifacts/wasm_ga_readiness_decision_packet.json`
- `artifacts/wasm_ga_readiness_review_board_test.log`

Packet contract:

```json
{
  "schema_version": "wasm-ga-readiness-decision-packet-v1",
  "bead": "asupersync-umelq.17.4",
  "decision_status": "GO | NO_GO",
  "aggregate_score": 0.0,
  "quorum_satisfied": true,
  "gate_rows": [],
  "signoffs": [],
  "waivers": [],
  "residual_risks": [],
  "replay_bundle": {
    "repro_command": "",
    "trace_pointer": ""
  }
}
```

## CI Certification Contract

`.github/workflows/ci.yml` must include a review-board certification step that:

1. Runs `wasm_ga_readiness_review_board_checklist` test target.
2. Emits `artifacts/wasm_ga_readiness_review_board_summary.json`.
3. Uploads a dedicated artifact bundle for audit and rerun linkage.

## Cross-References

- `docs/wasm_pilot_observability_contract.md`
- `docs/wasm_release_rollback_incident_playbook.md`
- `docs/wasm_rationale_index.md`
- `docs/nightly_stress_soak_automation.md`
- `docs/replay-debugging.md`
