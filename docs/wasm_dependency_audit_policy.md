# WASM Dependency Audit Policy

This document defines the deterministic dependency-audit gate introduced for bead `asupersync-umelq.3.1`.

## Goal

Audit browser-target dependency closure and block merges when forbidden runtime crates appear in wasm profiles.

## Canonical Inputs

- Policy: `.github/wasm_dependency_policy.json`
- Audit script: `scripts/check_wasm_dependency_policy.py`

## Gate Rules

1. Any `forbidden_crates` match fails the gate.
2. Any `conditional_crates` finding with an expired transition fails the gate.
3. Any finding at or above `risk_thresholds.high` without active or resolved transition tracking fails the gate.

## Deterministic Profiles

The policy audits the canonical `FP-BR-*` browser profiles on
`wasm32-unknown-unknown`:

- `FP-BR-MIN` (`--no-default-features --features wasm-browser-minimal`)
- `FP-BR-DEV` (`--no-default-features --features wasm-browser-dev`)
- `FP-BR-PROD` (`--no-default-features --features wasm-browser-prod`)
- `FP-BR-DET` (`--no-default-features --features wasm-browser-deterministic`)

Each profile executes `cargo tree` with deterministic flags (`--prefix depth --charset ascii`) so output ordering is stable and machine-parseable.

## Structured Outputs

- Summary JSON: `artifacts/wasm_dependency_audit_summary.json`
- NDJSON log: `artifacts/wasm_dependency_audit_log.ndjson`

Each NDJSON event includes:

- `profile_id`
- `target`
- `crate`
- `version`
- `transitive_chain`
- `decision`
- `decision_reason`
- `risk_score`
- `remediation`
- `transition_status`
- `transition_issue`

## Repro Commands

Unit checks (script internal parser/classifier checks):

```bash
python3 scripts/check_wasm_dependency_policy.py --self-test
```

Policy gate run:

```bash
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json
```

Single-profile debugging:

```bash
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json \
  --only-profile FP-BR-DET
```
