# WASM Dependency Audit (asupersync-umelq.3.1)

This document defines the deterministic dependency-closure audit for browser-focused
targets and the runtime policy gate for forbidden async runtimes.

## Scope

- Target family: `wasm32-unknown-unknown`
- Canonical policy: [`.github/wasm_dependency_policy.json`](../.github/wasm_dependency_policy.json)
- Profiles audited by policy:
  - `wasm-core-no-default`
  - `wasm-core-default`
  - `wasm-audit-all-features`
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

## Tooling

- Script: `scripts/check_wasm_dependency_policy.py`
- Summary schema: `wasm-dependency-audit-report-v1`
- Artifact outputs:
  - `artifacts/wasm_dependency_audit_summary.json`
  - `artifacts/wasm_dependency_audit_log.ndjson`

### Local Reproduction

```bash
python3 scripts/check_wasm_dependency_policy.py --self-test
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json
```

### CI Gate

The CI check job runs:

1. script self-tests (classification/parser checks),
2. policy audit generation,
3. merge-blocking failure on forbidden dependencies.

## Current Findings Snapshot

- Forbidden count: `0`
- Conditional count: `1` (`tower`, active transition to `asupersync-umelq.3.2`)
- Gate status: `passed`

## Remediation Applied In This Bead

- Removed direct forbidden dependency from `Cargo.toml`:
  - `tokio = "1.49.0"`

This removal eliminated the only detected Tokio entry from wasm dependency closure.
