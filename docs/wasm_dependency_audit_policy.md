# WASM Dependency Audit Policy

Primary beads: `asupersync-umelq.3.1`, `asupersync-umelq.3.5`

## Goal

Enforce dependency minimization and provenance controls for browser profiles so
WASM builds remain:

- runtime-pure (no Tokio-family contamination),
- deterministic and replay-auditable,
- rollback-safe under release automation.

## Invariant Mapping

This policy is part of preserving core runtime guarantees in browser mode:

- `SEM-INV-001` structured ownership (no hidden runtime injection),
- `SEM-INV-003` cancellation protocol correctness,
- `SEM-INV-005` no obligation leaks via transitive runtime side effects,
- `SEM-INV-006` no ambient authority,
- `SEM-INV-007` deterministic replayability.

## Canonical Inputs

- Policy: `.github/wasm_dependency_policy.json`
- Audit script: `scripts/check_wasm_dependency_policy.py`
- Release gate wrapper: `scripts/check_security_release_gate.py --check-deps`

## Gate Rules

1. Any `forbidden_crates` hit fails immediately.
2. Any `conditional_crates` hit with expired transition fails.
3. Any high-risk finding (`risk_thresholds.high`) without active/resolved
   transition fails.
4. Policy schema/profile/output metadata must be valid and complete.
5. Dependency transition records must remain traceable to live replacement
   bead IDs.

## Deterministic Profiles

Policy scans canonical `FP-BR-*` profiles on `wasm32-unknown-unknown`:

- `FP-BR-MIN`: `--no-default-features --features wasm-browser-minimal`
- `FP-BR-DEV`: `--no-default-features --features wasm-browser-dev`
- `FP-BR-PROD`: `--no-default-features --features wasm-browser-prod`
- `FP-BR-DET`: `--no-default-features --features wasm-browser-deterministic`

Each scan uses deterministic `cargo tree` flags:
`--prefix depth --charset ascii -e normal`.

## Provenance and Artifact Contract

Summary artifact:

- `artifacts/wasm_dependency_audit_summary.json`
- Required provenance: `audit_run_id`, `policy_path`, `policy_sha256`,
  `policy_schema_version`, per-profile command metadata.

NDJSON log artifact:

- `artifacts/wasm_dependency_audit_log.ndjson`
- Required provenance per finding: `audit_run_id`, `policy_path`,
  `policy_sha256`, `policy_schema_version`, plus crate/chain decision fields.

These fields are release-critical because rollback and incident triage require
exact policy+artifact reproducibility.

Supply-chain artifact bundle (release-blocking via `SEC-BLOCK-07`):

- `docs/wasm_browser_sbom_v1.json`
- `docs/wasm_browser_provenance_attestation_v1.json`
- `docs/wasm_browser_artifact_integrity_manifest_v1.json`

Integrity rule:

- every required bundle artifact must appear in the integrity manifest,
- each manifest SHA-256 digest must match committed bytes exactly,
- mismatches or missing artifacts are release-blocking failures.

## Adversarial Check Expectations

The dependency gate must defend against:

- provenance tampering (policy file swapped without digest change evidence),
- policy bypass (expired active transitions treated as non-blocking),
- dependency drift (profile coverage changes without policy metadata updates).

`check_security_release_gate.py` treats dependency policy validity and
transition freshness as release-blocking.

## Repro Commands

Self-test:

```bash
python3 scripts/check_wasm_dependency_policy.py --self-test
```

Policy gate:

```bash
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json
```

Single-profile drill:

```bash
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json \
  --only-profile FP-BR-DET
```

Release-gate path (dependency checks enabled):

```bash
python3 scripts/check_security_release_gate.py \
  --check-deps \
  --dep-policy .github/wasm_dependency_policy.json
```

Artifact-integrity gate path:

```bash
python3 scripts/check_security_release_gate.py \
  --policy .github/security_release_policy.json \
  --check-deps \
  --dep-policy .github/wasm_dependency_policy.json
```
