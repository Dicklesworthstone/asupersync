# WASM GA Go/No-Go Evidence Packet

Contract ID: `wasm-ga-go-no-go-evidence-packet-v1`  
Bead: `asupersync-umelq.17.4`  
Parent: `asupersync-umelq.17`  
Depends on: `asupersync-umelq.15.5`, `asupersync-umelq.13.5`, `asupersync-umelq.14.5`, `asupersync-umelq.12.5`, `asupersync-umelq.16.5`, `asupersync-umelq.17.2`, `asupersync-umelq.18.10`

## Purpose

Define a deterministic evidence packet that the GA review board uses to decide
`GO` or `NO_GO` for Browser Edition launch. The packet is designed to:

1. force complete evidence for semantics, perf, security, release, docs, and support,
2. make threshold/waiver/sign-off rules explicit and auditable,
3. fail closed when release-blocking evidence is missing or unverified.

## Decision Policy

### Hard decision states

- `GO`: all mandatory criteria pass, no unresolved release-blocking risks.
- `CONDITIONAL_GO`: only if waivers are policy-valid and none are release-blocking.
- `NO_GO`: any release-blocking criterion fails or evidence is missing/unverifiable.

## Browser Edition Release Artifact Set

The current Browser Edition pilot or GA promotion bead is `asupersync-3qv04.7.3`.
This packet must therefore bind the board decision to the live Browser Edition
artifact lineage rather than relying on policy-only governance text.
The packet is also incomplete unless Gate 6 package-release and consumer-build
evidence from `docs/wasm_release_channel_strategy.md` is present for the same
candidate.
That Gate 6 package evidence must carry command provenance for the real Browser
Edition package gate: `corepack pnpm run validate` or both
`bash scripts/validate_package_build.sh` and
`bash scripts/validate_npm_pack_smoke.sh`.

Required release-lineage references:

1. `asupersync-3qv04.6.5` with `docs/wasm_abi_compatibility_policy.md`,
   `artifacts/wasm_abi_contract_summary.json`,
   `artifacts/wasm_abi_contract_events.ndjson`, and
   `tests/wasm_packaged_abi_compatibility_matrix.rs`.
2. `asupersync-3qv04.6.6` with
   `docs/wasm_packaged_bootstrap_harness_contract.md`,
   `docs/wasm_packaged_cancellation_harness_contract.md`,
   `artifacts/wasm_packaged_bootstrap_harness_v1.json`, and
   `artifacts/wasm_packaged_cancellation_harness_v1.json`.
3. `asupersync-3qv04.6.7` with `.github/wasm_perf_budgets.json`,
   `artifacts/wasm_budget_summary.json`, and
   `artifacts/wasm_perf_regression_report.json`.
4. `asupersync-3qv04.6.7.1` with `docs/wasm_bundle_size_budget.md`,
   `artifacts/wasm_bundle_size_budget_v1.json`, and
   `tests/wasm_bundle_size_budget_contract.rs`.
5. `asupersync-3qv04.6.7.2` with
   `docs/wasm_packaged_bootstrap_harness_contract.md`,
   `artifacts/wasm_packaged_bootstrap_perf_summary.json`, and
   `artifacts/wasm_packaged_bootstrap_harness_v1.json`.
6. `asupersync-3qv04.6.7.3` with
   `docs/wasm_packaged_cancellation_harness_contract.md`,
   `artifacts/wasm_packaged_cancellation_perf_summary.json`, and
   `artifacts/wasm_packaged_cancellation_harness_v1.json`.
7. `asupersync-3qv04.6.8` with `docs/wasm_bundler_compatibility_matrix.md`,
   `docs/wasm_typescript_package_topology.md`,
   `artifacts/wasm_typescript_package_summary.json`, and
   `artifacts/wasm_typescript_package_log.ndjson`.
8. `asupersync-3qv04.7.1` with `.github/workflows/publish.yml`,
   `artifacts/npm/package_release_validation.json`,
   `artifacts/npm/package_pack_dry_run_summary.json`, and
   `artifacts/npm/publish_outcome.json`.
9. `asupersync-3qv04.7.2` with `docs/wasm_browser_sbom_v1.json`,
   `docs/wasm_browser_provenance_attestation_v1.json`, and
   `docs/wasm_browser_artifact_integrity_manifest_v1.json`.
10. `asupersync-3qv04.8.6` with
    `artifacts/onboarding/vanilla.summary.json`,
    `artifacts/onboarding/react.summary.json`,
    `artifacts/onboarding/next.summary.json`,
    `target/wasm-qa-evidence-smoke/<run>/<scenario>/bundle_manifest.json`, and
    `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json`.
11. `asupersync-3qv04.9.1`, `asupersync-3qv04.9.2`, `asupersync-3qv04.9.3`,
   `asupersync-3qv04.9.4`, and `asupersync-3qv04.9.5` with
   `docs/wasm_quickstart_migration.md`,
   `docs/wasm_bundler_compatibility_matrix.md`,
   `docs/wasm_canonical_examples.md`,
   `docs/wasm_troubleshooting_compendium.md`, and
   `docs/wasm_api_surface_census.md`.

Any release packet that omits these Browser Edition artifact references is
incomplete for `asupersync-3qv04.7.3` and must be treated as `NO_GO`.

### Mandatory threshold policy

These thresholds are minimums, not targets:

1. Security release gate status must be `pass` with zero unmitigated blocking criteria.
2. Continuous perf regression lane must be green for required browser workload suites.
3. Deterministic replay artifacts must exist for every required incident/flake scenario class.
4. Unit and E2E validation for launch-governance controls must pass.
5. Structured logging quality gates must report no schema-breaking violations.

## Required Evidence Fields

The packet must include all fields below:

1. `packet_schema_version`
2. `generated_at_utc`
3. `bead_id`
4. `contract_id`
5. `decision_state` (`GO|CONDITIONAL_GO|NO_GO`)
6. `board_review_id`
7. `board_signoff_window_utc`
8. `release_candidate_version`
9. `release_channel_target`
10. `gate_results` (per-gate status and evidence pointers)
11. `threshold_evaluation` (threshold id, observed value, pass/fail)
12. `waivers` (if any)
13. `signoff_roles`
14. `unresolved_risks`
15. `deterministic_replay_commands`
16. `structured_decision_log_pointer`
17. `surface_decisions`
18. `support_bucket_snapshot`
19. `promotion_ceiling_snapshot`
20. `surface_evidence_rows`

## Gate Result Contract

Each `gate_results` entry must contain:

1. `gate_id`
2. `status` (`pass|fail|not_applicable`)
3. `release_blocking` (`true|false`)
4. `unit_evidence`
5. `e2e_evidence`
6. `logging_evidence`
7. `artifact_paths`

Release-blocking gates for this packet:

- `GA-SEC-01` (security release blocking criteria)
- `GA-PERF-01` (perf regression gates)
- `GA-REPLAY-01` (deterministic replay readiness)
- `GA-OPS-01` (rollback/incident playbook readiness)
- `GA-LOG-01` (structured logging quality)
- `GA-VNEXT-01` (support-matrix truth for vNext browser surfaces)

## VNext Surface Decision Rows

Every packet must carry explicit decision rows for the new browser surfaces
rather than implying they inherit the Browser Edition baseline decision.

Required `surface_decisions` rows:

- `Dedicated Web Worker`
- `IndexedDB durable storage`
- `BrowserArtifactStore`
- Rust-authored browser path
- `WebTransport`
- `MessageChannel`
- `MessagePort`
- `BroadcastChannel`
- `SharedArrayBuffer`
- worker offload

Each row must include:

1. `surface_id`
2. `support_bucket`
3. `promotion_ceiling`
4. `requested_channel`
5. `decision` (`promote`, `hold_preview`, `guarded_only`, `demote`)
6. `evidence_paths`
7. `rollback_trigger_ids`

`GA-VNEXT-01` is release-blocking whenever a packet claims a surface above its
documented ceiling (`preview_only`, `guarded canary-only`, `nightly-only`,
`bridge-only`, or `impossible`) or omits the evidence row for a named vNext
surface.

## Waiver Policy

Waivers are allowed only when all conditions hold:

1. waiver is attached to a non-release-blocking gate,
2. waiver includes rationale, owner, expiry, and compensating controls,
3. waiver has explicit approval from required sign-off roles,
4. waiver does not hide missing unit/e2e/logging evidence.

Any waiver that attempts to bypass a release-blocking gate forces `NO_GO`.

## Sign-Off Role Matrix

Required sign-off roles for a valid board decision:

1. Runtime Owner
2. Security Owner
3. Release Captain
4. QA/Conformance Owner
5. Support/Operations Owner

For each role, the packet must include:

1. approver identity,
2. approval timestamp (UTC),
3. approval state (`approve|reject`),
4. rationale note.

Missing sign-off from any required role forces `NO_GO`.

## Unresolved-Risk Policy

`unresolved_risks` entries must include:

1. risk id,
2. severity,
3. release_blocking flag,
4. owner,
5. mitigation_plan,
6. follow_up_bead_id,
7. expiry_utc.

If any unresolved risk has `release_blocking=true`, decision must be `NO_GO`.

## Automatic Failure Rules

GA approval fails automatically when one or more are true:

1. any release-blocking gate status is not `pass`,
2. any release-blocking gate lacks verifiable `unit_evidence`, `e2e_evidence`, or `logging_evidence`,
3. required sign-off role is missing or rejected,
4. packet references artifacts that do not exist,
5. deterministic replay command bundle is missing,
6. any vNext surface is claimed above the ceiling declared in `docs/WASM.md`
   and `docs/wasm_release_channel_strategy.md`,
7. any `Dedicated Web Worker`, `IndexedDB durable storage`,
   `BrowserArtifactStore`, Rust-authored browser path, `WebTransport`,
   `MessageChannel`, `MessagePort`, `BroadcastChannel`, `SharedArrayBuffer`, or
   worker offload row is missing an explicit decision/evidence entry.

## Structured Decision Log Schema

Decision logs must include:

1. `decision_id`
2. `board_review_id`
3. `decision_state`
4. `gate_failures`
5. `waiver_ids`
6. `unresolved_risk_ids`
7. `approver_matrix`
8. `artifact_bundle_digest`
9. `replay_pointer`

## Deterministic Review Rehearsal

The board rehearsal run must execute deterministically and preserve artifacts.
Cargo-heavy commands must use `rch`.

```bash
rch exec -- cargo test -p asupersync --test wasm_ga_go_no_go_evidence_packet -- --nocapture
rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture
rch exec -- cargo test -p asupersync --test wasm_supply_chain_controls -- --nocapture
python3 scripts/check_security_release_gate.py --policy .github/security_release_policy.json --check-deps --dep-policy .github/wasm_dependency_policy.json
python3 scripts/run_browser_onboarding_checks.py --scenario all
```

## Evidence Bundle Pointers

Minimum artifact bundle this packet must point to:

1. `artifacts/security_release_gate_report.json`
2. `artifacts/security_release_gate_events.ndjson`
3. `artifacts/wasm_dependency_audit_summary.json`
4. `artifacts/wasm_abi_contract_summary.json`
5. `artifacts/wasm_abi_contract_events.ndjson`
6. `artifacts/wasm_bundle_size_budget_v1.json`
7. `artifacts/wasm_budget_summary.json`
8. `artifacts/wasm_packaged_bootstrap_harness_v1.json`
9. `artifacts/wasm_packaged_bootstrap_perf_summary.json`
10. `artifacts/wasm_packaged_cancellation_harness_v1.json`
11. `artifacts/wasm_packaged_cancellation_perf_summary.json`
12. `artifacts/wasm_perf_regression_report.json`
13. `artifacts/wasm_typescript_package_summary.json`
14. `artifacts/wasm_typescript_package_log.ndjson`
15. `artifacts/wasm_optimization_pipeline_summary.json`
16. `artifacts/wasm/release/release_traceability.json`
17. `artifacts/wasm/release/rollback_safety_report.json`
18. `artifacts/wasm/release/incident_response_packet.json`
19. `artifacts/wasm_release_rollback_playbook_summary.json`
20. `artifacts/npm/package_release_validation.json`
21. `artifacts/npm/package_pack_dry_run_summary.json`
22. `artifacts/npm/publish_outcome.json`
23. `docs/wasm_browser_sbom_v1.json`
24. `docs/wasm_browser_provenance_attestation_v1.json`
25. `docs/wasm_browser_artifact_integrity_manifest_v1.json`
26. `artifacts/onboarding/vanilla.summary.json`
27. `artifacts/onboarding/react.summary.json`
28. `artifacts/onboarding/next.summary.json`
29. `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json`
30. `artifacts/onboarding/worker.summary.json`
31. `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`
32. `target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json`
33. `target/e2e-results/rust_browser_consumer/<timestamp>/summary.json`
34. `docs/WASM.md`
35. `docs/wasm_release_channel_strategy.md`
36. `docs/wasm_troubleshooting_compendium.md`

## Cross-References

- `docs/wasm_release_rollback_incident_playbook.md`
- `docs/wasm_release_channel_strategy.md`
- `docs/wasm_flake_governance_and_forensics.md`
- `.github/workflows/publish.yml`
- `.github/workflows/ci.yml`
