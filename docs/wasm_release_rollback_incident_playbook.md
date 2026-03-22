# WASM Release Rollback and Incident Response Playbook

Contract ID: `wasm-release-rollback-incident-playbook-v1`  
Bead: `asupersync-umelq.15.5`  
Depends on: `asupersync-umelq.15.4`, `asupersync-umelq.15.3`

## Purpose

Define deterministic operational response for Browser Edition release incidents.
This playbook covers:

1. incident severity classification and response ownership,
2. rollback triggers and exact rollback execution steps,
3. communication protocol and update cadence,
4. artifact revocation strategy for npm release channels,
5. postmortem and corrective-action requirements.

This playbook is release-governance only. It never weakens runtime invariants:
structured concurrency, cancellation protocol correctness, loser-drain behavior,
obligation closure, and explicit capability boundaries remain mandatory.

## Scope and Inputs

Primary automation surfaces:

- `.github/workflows/publish.yml`
- `.github/workflows/ci.yml`
- `docs/wasm_release_channel_strategy.md`

Primary incident evidence artifacts:

- `artifacts/security_release_gate_report.json`
- `artifacts/security_release_gate_events.ndjson`
- `artifacts/wasm_dependency_audit_summary.json`
- `artifacts/wasm_dependency_audit_log.ndjson`
- `artifacts/wasm_optimization_pipeline_summary.json`
- `artifacts/wasm/release/release_traceability.json`
- `artifacts/npm/npm_release_assumptions.json`
- `artifacts/npm/publish_outcome.json`
- `artifacts/npm/rollback_outcome.json`
- `artifacts/npm/rollback_actions.txt`

## Incident Severity Classification

| Severity | Trigger examples | Response target | Rollback default |
|---|---|---|---|
| `SEV-1` | release-blocking security failure, malformed artifact provenance, reproducible deterministic replay failure in stable lane | immediate response | mandatory rollback |
| `SEV-2` | canary regression with user-facing breakage, package publish drift, rollback control failure | same-day response | rollback unless explicit waiver signed |
| `SEV-3` | non-blocking CI noise, documentation drift, optional artifact omissions | next business day | no automatic rollback |

## Incident Command Roles

- Incident Commander (IC): owns severity call, go/no-go decisions, and closure.
- Release Operator: executes deterministic command bundle and captures outputs.
- Comms Lead: publishes internal/external status updates.
- Scribe: records timeline, decisions, and artifact pointers for postmortem.

## Deterministic Triage Command Bundle

Run in this order and record every command + exit code:

```bash
# 1) Re-check release gating inputs
python3 scripts/check_wasm_optimization_policy.py \
  --policy .github/wasm_optimization_policy.json

python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json

python3 scripts/check_security_release_gate.py \
  --policy .github/security_release_policy.json \
  --check-deps \
  --dep-policy .github/wasm_dependency_policy.json

# 2) Reproduce wasm compatibility contract checks (cargo-heavy via rch)
rch exec -- cargo test -p asupersync --test wasm_bundler_compatibility -- --nocapture
rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture
```

If any command fails, record:

1. failing command,
2. artifact path(s),
3. replay command,
4. incident severity,
5. initial rollback decision.

## Rollback Triggers

Rollback is mandatory when any condition is true:

1. `security_release_gate_report.json` indicates release-blocking failure.
2. dependency audit reports forbidden crate or expired transition.
3. deterministic replay evidence is missing for required promotion gates.
4. npm publish shows partial success or invalid channel/tag state.
5. `publish.yml` rollback controls fail validation.

### Surface-Specific Rollback Defaults

The vNext browser surfaces must be rolled back independently instead of being
allowed to blur together under one generic Browser Edition status line.

| Surface | Trigger class | Immediate action | Public downgrade language |
|---|---|---|---|
| `Dedicated Web Worker` direct-runtime lane | worker bootstrap, cancel-drain, worker artifact/export evidence, or dedicated-worker `browser-run.json` / `scenario_inventory` evidence regresses | demote the worker lane from `stable` to `canary` and freeze further worker promotion | keep browser main-thread runtime as the supported fallback while worker evidence is repaired |
| `IndexedDB` durable storage + `BrowserArtifactStore` | blocked-upgrade/quota/export diagnostics drift or maintained fixture evidence fails | demote durable storage/artifact claims to `canary` and stop advertising durable browser persistence as release-ready | tell users to export/clear artifacts explicitly; do not silently fall back to ambient persistence |
| Rust-authored browser path | `repository_maintained_rust_browser_fixture` validation, `browser-run.json`, or docs drift breaks | revert the surface to `preview_only` / `architecturally feasible only` and block any stable/public Rust lane claim | direct Rust users back to the repository fixture workflow until the evidence bundle is green again |
| `WebTransport` datagrams | guarded prerequisite or fallback contract regresses | demote to `preview_only` and remove any guarded canary/stable claim | require `WebSocket` / `fetch` fallback guidance in the incident note and release notes |
| Service-worker bounded broker registration + durable handoff | broker registration manifest, durable handoff metadata, stale-broker downgrade logs, or bounded-broker policy docs/tests regress | demote the broker surface from `guarded canary-only` to `preview_only` and freeze further broker promotion | keep `service_worker_not_yet_shipped` and `service_worker_direct_runtime_not_shipped` as the public truth, preserve the bounded broker framing, and route users to dedicated-worker or browser main-thread fallback guidance |
| Shared-worker bounded coordinator attach + downgrade | attach/handshake evidence, protocol-version checks, downgrade logs, or bounded-coordinator policy docs/tests regress | demote the coordinator surface from `guarded canary-only` to `preview_only` and freeze further coordinator promotion | keep `shared_worker_direct_runtime_not_shipped` as the public truth, preserve the bounded coordinator framing, and route users back to dedicated-worker or browser main-thread fallback guidance |
| Browser-native messaging (`MessageChannel`, `MessagePort`, `BroadcastChannel`) | public claim appears without public SDK export closure or contract evidence | retract the public Browser Edition claim immediately | state that these surfaces remain application-boundary-only / unshipped |
| `SharedArrayBuffer` / worker offload / parallel executor lanes | cross-origin-isolation, ownership/cancellation, replay, chaos, or perf evidence regresses | disable the lane immediately and demote `canary -> nightly` or preview-only | keep the single-threaded browser runtime as the only supported default |

## Rollback Procedure (Deterministic Order)

### A) WASM channel rollback

1. Freeze current promotion lane (`stable` or `canary`) and stop further publish jobs.
2. Demote candidate per `docs/wasm_release_channel_strategy.md`:
   - `stable -> canary`, or
   - `canary -> nightly`.
3. Archive failing artifacts and include replay command pointers.
4. Open remediation bead and link all incident artifacts before re-promotion.

### B) npm dist-tag rollback

When rollback target version is known, use `publish.yml` workflow-dispatch inputs:

- `rollback_npm_to_version=<known-good-version>`
- `rollback_reason=<incident-id-and-summary>`
- `npm_tag=<affected-tag>`

Workflow executes deterministic rollback via:

```bash
npm dist-tag add <package>@<known-good-version> <tag>
```

Action log and result evidence must include:

- `artifacts/npm/rollback_actions.txt`
- `artifacts/npm/rollback_outcome.json`

### C) Artifact revocation strategy

1. Keep latest bad build immutable for forensics; do not mutate evidence artifacts.
2. Reassign dist-tags to known-good versions; do not republish same semver with altered bytes.
3. Mark incident release as revoked in incident record and postmortem.
4. Require successful rerun of all gate commands before lifting rollback state.

## Communication Protocol

### Internal updates

- T+0: IC posts incident declaration with severity, trigger, and owner map.
- T+15m: first command-bundle status update with failing step and artifact paths.
- Every 30m for `SEV-1`/`SEV-2`: status heartbeat with new facts only.
- Resolution post: rollback status, residual risk, and next review checkpoint.

### External updates

- Stable-channel incidents require public status note with:
  - affected versions/tags,
  - mitigation (rollback/demotion),
  - expected next update time,
  - customer-safe workaround if available.

## Required Incident Artifacts

Each incident ticket must include:

1. timeline in UTC with decision points,
2. executed command bundle (exact commands),
3. artifact index with path + hash when available,
4. rollback decision record and authority,
5. replay command that reproduces the failing gate,
6. `surface_id` for the affected vNext lane when applicable,
7. `support_bucket_before` and `support_bucket_after`,
8. `channel_ceiling_before` and `channel_ceiling_after`,
9. `surface_evidence_paths`, including any `browser-run.json`,
   `scenario_inventory`, broker registration, durable handoff, or coordinator
   downgrade artifacts that justified the rollback decision.

## Postmortem Requirements

Complete postmortem within 2 business days for `SEV-1`/`SEV-2`:

1. root cause statement (single-sentence and expanded form),
2. contributing factors and missing defenses,
3. what made detection fast/slow,
4. corrective actions with owner + due date,
5. explicit prevention checks to add to CI/release automation,
6. linkage to closed remediation bead IDs.

Postmortem cannot be marked complete without:

- at least one prevention action merged or explicitly scheduled with owner/due date,
- validation evidence showing prevention check executes deterministically,
- confirmation that rollback state has been lifted through gate-driven re-promotion.

## CI Certification Contract

`check` job in `.github/workflows/ci.yml` must run:

- step name: `WASM rollback and incident playbook certification`
- command:
  - `cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture`
- required artifacts:
  - `artifacts/wasm_release_rollback_playbook_summary.json`
  - `artifacts/wasm_release_rollback_playbook_test.log`

Local deterministic reproduction command:

```bash
rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture
```
