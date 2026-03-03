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

## Promotion Rules

`nightly -> canary` promotion requires:

1. all required gates pass,
2. no critical/high unresolved findings in security release gate report,
3. dependency policy transitions are active and non-expired.

`canary -> stable` promotion requires:

1. all required gates pass on canary artifact set,
2. no blocked release criteria in security report (`gate_status != fail`),
3. artifact provenance present and reproducible for optimization, dependency,
   and security summaries,
4. no unresolved deterministic replay failures from the selected promotion run.

## Demotion and Rollback Policy

Demotion is mandatory when one of these triggers occurs post-publish:

1. any release-blocking security criterion fails,
2. dependency policy check fails due to forbidden crate hit or expired
   conditional transition,
3. deterministic replay checks for mandatory scenarios fail in two consecutive
   release-gate runs,
4. required promotion artifacts are missing or non-reproducible.

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
6. Confirm all required artifacts exist and are non-empty.
7. Publish promotion decision with command + artifact pointers.

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
   - assumptions artifact: `artifacts/npm/npm_release_assumptions.json`
   - publish outcome artifact: `artifacts/npm/publish_outcome.json`
   - rollback outcome artifact (when rollback mode is used): `artifacts/npm/rollback_outcome.json`
4. Missing package manifests are treated as an explicit controlled skip
   (artifactized) rather than an implicit silent bypass.
5. Rollback mode requires both target version and operator reason; the executed
   dist-tag commands must be captured in release artifacts.

## Non-Negotiable Constraints

1. No channel promotion can bypass dependency or security gates.
2. No channel promotion can proceed with unresolved critical findings.
3. Cargo-heavy validation in this workflow must be executed through `rch`.
4. This policy does not weaken runtime invariants: structured concurrency,
   cancellation protocol, loser-drain behavior, obligation closure, and explicit
   capability boundaries remain mandatory.
