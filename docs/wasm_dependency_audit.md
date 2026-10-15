# WASM Dependency Audit (asupersync-umelq.3.1, asupersync-umelq.3.5)

This document defines the deterministic dependency-closure audit for browser-focused
targets and the runtime policy gate for forbidden async runtimes.

## Scope

- Target family: `wasm32-unknown-unknown`
- Canonical policy: [`.github/wasm_dependency_policy.json`](../.github/wasm_dependency_policy.json)
- Profiles audited by policy:
  - `FP-BR-MIN`
  - `FP-BR-DEV`
  - `FP-BR-PROD`
  - `FP-BR-DET`
- Dependency edge mode: `cargo tree -e normal` with deterministic depth-prefix parsing

## Policy Classes

- `forbidden`: crates that violate runtime policy in core surfaces.
  - `tokio`, `tokio-util`, `tokio-stream`, `tokio-macros`
  - `hyper`, `reqwest`, `axum`
  - `async-std`, `smol`
- `conditional`: allowed only under explicit constrained boundaries.
  - `tower` (trait-compat adapter boundary only)
- `allowed`: no policy violation detected.

Each finding includes:

- crate path
- transitive chain
- policy reason
- risk score
- remediation recommendation
- transition status and owning replacement bead (when conditional)

Summary-level provenance includes:

- `audit_run_id`
- `policy_path`
- `policy_sha256`
- `policy_schema_version`
- per-profile scan command metadata

Transition-level provenance is release-gate critical:

- `crate`
- `status` (`active|resolved`)
- `owner`
- `replacement_issue`
- `expires_at_utc` (timezone-required ISO-8601)
- `notes`

## Tooling

- Script: `scripts/check_wasm_dependency_policy.py`
- Summary schema: `wasm-dependency-audit-report-v1`
- Artifact outputs:
  - `artifacts/wasm_dependency_audit_summary.json`
  - `artifacts/wasm_dependency_audit_log.ndjson`
  - `docs/wasm_browser_sbom_v1.json`
  - `docs/wasm_browser_provenance_attestation_v1.json`
  - `docs/wasm_browser_artifact_integrity_manifest_v1.json`
  - release-bound Browser Edition outputs attested by the bundle:
    - `packages/browser-core/package.json`
    - `packages/browser-core/asupersync.js`
    - `packages/browser-core/asupersync.d.ts`
    - `packages/browser-core/asupersync_bg.wasm`
    - `packages/browser-core/abi-metadata.json`
    - `packages/browser-core/debug-metadata.json`
    - `packages/browser/package.json`
    - `packages/react/package.json`
    - `packages/next/package.json`

### Local Reproduction

```bash
python3 scripts/check_wasm_dependency_policy.py --self-test
python3 scripts/check_security_release_gate.py --self-test
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json
python3 scripts/check_security_release_gate.py \
  --policy .github/security_release_policy.json \
  --check-deps \
  --dep-policy .github/wasm_dependency_policy.json
```

### CI Gate

The CI check job runs:

1. script self-tests (classification/parser checks),
2. policy audit generation,
3. merge-blocking failure on forbidden dependencies or expired transitions,
4. release-gate dependency validation via `check_security_release_gate.py --check-deps`.

Release-gate dependency validation additionally enforces transition provenance
schema integrity (owner/replacement/timestamp/notes) so policy drift or partial
transition records cannot silently bypass release checks.

Release-gate supply-chain integrity validation additionally enforces SBOM +
provenance artifact presence and SHA-256 manifest matching via:
`docs/wasm_browser_artifact_integrity_manifest_v1.json`. That manifest now
attests the shipped browser-core JS/WASM/metadata bundle plus the package
manifests for `@asupersync/browser`, `@asupersync/react`, and
`@asupersync/next`, rather than only hashing the contract JSON files.

## Adversarial Policy Assertions

Dependency controls are validated against three adversarial classes:

- provenance tampering: policy digest/provenance fields must remain coherent,
- policy bypass: expired transitions must hard-fail,
- dependency drift: canonical profile coverage must remain valid and complete.

## Current Findings Snapshot

- Forbidden count: `0`
- Conditional count: `1` (`tower`, active transition to `asupersync-umelq.3.2`)
- Gate status: `passed`

## Remediation Applied In This Bead

- Removed direct forbidden dependency from `Cargo.toml`:
  - `tokio = "1.49.0"`

This removal eliminated the only detected Tokio entry from wasm dependency closure.
