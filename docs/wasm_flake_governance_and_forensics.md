# WASM Flake Governance and Failure Forensics

Primary bead: `asupersync-umelq.18.5`

## Goal

Prevent reliability decay in Browser Edition verification by enforcing:

1. deterministic flake detection,
2. automated quarantine tracking with SLA ownership,
3. release-blocking quality thresholds,
4. replay-first incident forensics and reactivation criteria.

## Governance Loop

1. Detect instability with deterministic replay suites.
2. Quarantine unstable suites with explicit owner, severity, SLA, and replay pointer.
3. Triage using incident-forensics workflow and deterministic trace artifacts.
4. Reactivate only after policy-defined stable rerun evidence.

## Detection and Quality Gates

Canonical commands:

```bash
scripts/run_semantic_flake_detector.sh --iterations 5 --json
bash scripts/check_semantic_signal_quality.sh \
  --report target/semantic-verification/verification_report.json \
  --dashboard target/semantic-verification/flake/latest/variance_dashboard.json \
  --output target/semantic-verification/signal-quality/signal_quality_report.json
python3 ./scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json
python3 ./scripts/evaluate_wasm_pilot_cohort.py \
  --telemetry-input artifacts/pilot/pilot_observability_events.json \
  --telemetry-output artifacts/pilot/pilot_observability_summary.json \
  --telemetry-log-output artifacts/pilot/pilot_observability_alerts.ndjson
```

Release-blocking thresholds (`.github/wasm_flake_governance_policy.json`):

- `max_flake_rate_pct = 0.0`
- `max_false_positive_rate_pct = 5.0`
- `max_unresolved_high_severity_flakes = 0`
- `max_unresolved_critical_severity_flakes = 0`
- `max_critical_test_failures = 0`

If any threshold is breached, the governance checker exits non-zero.

Pilot operations note:

- `pilot_observability_summary.json` must report `status=pass` and `ci_parity_ok=true`.
- alert logs must contain owner routing and replay pointers for every breach.

## Quarantine Contract

Manifest path:

- `artifacts/wasm_flake_quarantine_manifest.json`

Manifest schema:

- `schema_version = wasm-flake-quarantine-v1`
- `entries[]` required fields:
  - `id`, `suite`, `severity`, `status`, `owner`, `opened_at_utc`, `sla_hours`
  - `replay_command`, `trace_pointer`, `reactivation_criteria`

Allowed status values:

- `open`
- `resolved`
- `reactivated`

Severity SLAs (hours):

- `critical: 24`
- `high: 72`
- `medium: 168`

Open entries exceeding SLA or unresolved high/critical entries block release.

## Failure Forensics Workflow

Use deterministic browser-incident drills to investigate and classify failures:

```bash
bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics
TEST_SEED=4242 bash ./scripts/test_wasm_incident_forensics_e2e.sh
python3 ./scripts/check_incident_forensics_playbook.py
```

For direct replay bundle triage, use the replay command template from `docs/replay-debugging.md` with `rch` offload and preserve artifact pointers in the quarantine entry.

Required forensic linkage per flaky suite:

- deterministic `replay_command`
- deterministic `trace_pointer`
- artifact directory root
- incident severity and owner
- resolution or reactivation decision notes

## Release Incident Response Integration (WASM-14 / asupersync-umelq.15.5)

When release-gate failures happen in `.github/workflows/publish.yml`, operators
must capture rollback-safety and incident-response artifacts before rerunning
promotion:

- `artifacts/wasm/release/rollback_safety_report.json`
- `artifacts/wasm/release/incident_response_packet.json`
- `artifacts/wasm/release/release_traceability.json`
- `artifacts/wasm/release/rollback_instructions.md`
- `artifacts/npm/rollback_outcome.json` (when npm rollback mode is used)

These artifacts provide:

1. deterministic reproduction commands for the incident-forensics suite,
2. rollback safety-check status and missing gate reports,
3. communication protocol expectations (`sev_1`, `sev_2`),
4. artifact-revocation strategy for npm dist-tag rollback,
5. postmortem-required fields for closure review and audit.

Deterministic repro bundle (must be preserved in incident notes):

```bash
bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics
TEST_SEED=4242 bash ./scripts/test_wasm_incident_forensics_e2e.sh
python3 ./scripts/check_incident_forensics_playbook.py
```

## Reactivation Criteria

A quarantined suite can be reactivated only when all conditions hold:

1. three consecutive deterministic reruns pass with identical replay fingerprints,
2. no unstable status transitions across reruns,
3. incident forensics artifacts are attached and replayable,
4. owner records root-cause and fix reference in manifest notes.

If any condition is missing, status remains `open` and release stays blocked.
