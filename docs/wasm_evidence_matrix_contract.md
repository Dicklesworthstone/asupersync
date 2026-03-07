# WASM Browser Evidence Matrix Contract

Contract ID: `wasm-browser-evidence-matrix-v1`  
Bead: `asupersync-3qv04.8.1`  
Parent: `asupersync-3qv04.8` (WASM quality spine)

## Purpose

Define the minimum required evidence to claim Browser Edition work as complete.
This contract is fail-closed: missing evidence means the bead is not done.

The matrix explicitly covers:

1. Rust cfg/feature-gating correctness,
2. exported ABI-handle safety,
3. JS/TS package type-surface behavior,
4. browser host-bridge/runtime behavior,
5. React/Next adapter lifecycle behavior,
6. bundled-package installability and consumer bootstrap,
7. cross-browser compatibility.

## Required Evidence Matrix

Every lane below requires deterministic unit and E2E proof plus structured logs.

| Lane | Unit Evidence (Required) | Integration Evidence (Required) | E2E Evidence (Required) | Logging/Metadata (Required) | Required Artifacts | Gate Rule |
|---|---|---|---|---|---|---|
| Rust cfg + profile closure | `wasm-browser-minimal/dev/prod/deterministic` compile checks | profile-matrix script check for forbidden native surfaces | deterministic compile closure rerun with same outcome | `scenario_id`, `target`, `profile`, `feature_set`, `rustc_version`, `seed` (if used), `exit_code` | compile logs + matrix summary JSON | Any profile closure failure is release-blocking |
| ABI handle safety | unit tests for ownership/borrowing, invalid-handle rejection, close semantics | Rust<->JS ABI bridge smoke tests over generated bindings | browser scenario proving handle lifecycle under cancellation/drain | `abi_version`, `handle_kind`, `handle_id`, `state_before`, `state_after`, `error_code` | ABI test report + failure repro bundle | Missing ABI lifecycle coverage is release-blocking |
| JS/TS type surface | TS compile/type tests for package exports and diagnostics types | package import tests across supported module modes | minimal consumer app boot with generated `.d.ts` and expected diagnostics | `package_name`, `package_version`, `types_entry`, `bundler`, `node_version` | TS test logs + type-surface manifest | Type mismatch without approved waiver blocks release |
| Browser host bridge | unit tests for host callbacks/event mapping and fallback paths | integration tests for cancellation/timer/event-loop bridge seams | deterministic browser-run scenarios using packaged artifacts | `browser`, `bridge_event`, `token`, `interest`, `cancel_state`, `trace_pointer` | bridge event log + replay pointers | Host-bridge failures are release-blocking |
| React/Next adapters | unit tests for hook/adaptor lifecycle rules | adapter integration tests for hydration/mount/unmount + cancellation propagation | end-to-end React + Next templates with deterministic assertions | `framework`, `adapter_version`, `route`, `lifecycle_phase`, `cancel_outcome` | framework suite summary + artifact bundle | Missing adapter lifecycle evidence blocks GA |
| Package installability | unit checks for package metadata/exports integrity | install + build checks in clean temp workspaces | smoke boot of packaged artifacts in supported templates | `registry_source`, `lockfile_digest`, `install_command`, `build_command`, `artifact_digest` | installability report + package digest manifest | Installability regressions block release |
| Cross-browser compatibility | browser-specific unit checks for known quirks | shared scenario pack run across engine matrix | deterministic E2E runs across Chromium/Firefox/WebKit lanes | `browser_engine`, `browser_version`, `os`, `scenario_id`, `repro_command` | matrix summary JSON + per-browser logs/screenshots | Any unresolved high/critical browser regression blocks release |

## Structured Logging Contract

All WASM Browser Edition verification lanes must emit structured logs with:

1. `run_id` and `scenario_id`,
2. `seed` (or explicit `seed: null` when deterministic by construction),
3. `profile` + `feature_set`,
4. `package_version` and wasm/module hash,
5. `browser` and runtime environment metadata,
6. `result` (`pass|fail|flaky`),
7. `repro_command`,
8. `trace_pointer`,
9. `artifact_root`.

Logs missing any required field are schema violations.

## Artifact Layout and Retention

Use deterministic artifact roots:

1. Unit/integration failures: `$ASUPERSYNC_TEST_ARTIFACTS_DIR`
2. E2E suites: `target/e2e-results/<suite>/`
3. Orchestrator metadata: `target/e2e-results/orchestrator_<timestamp>/`

Retention and redaction policy:

1. Local default retention: 14 days
2. CI default retention: 30 days
3. CI redaction mode must be `metadata_only` or `strict`
4. CI must not use `none` redaction mode

This contract inherits policy details from `TESTING.md` and
`docs/wasm_flake_governance_and_forensics.md`.

## Screenshot / Video / Network Trace Policy

Artifact capture rules for browser failures:

1. Screenshot required for every failing browser E2E scenario.
2. Video capture required for flaky or nondeterministic UI/lifecycle failures.
3. Network trace required when failure involves fetch/WebSocket/stream semantics.
4. Every capture file must be linked from the scenario summary and include a
   deterministic repro command.

## Deterministic Command Bundle

Cargo-heavy commands must use `rch`.

```bash
# Rust closure checks
rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-minimal
rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-dev
rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-deterministic

# Browser E2E and matrix gates
bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics
python3 ./scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json
```

## Reproducibility Rule

Every failure row in every lane must include:

1. a direct rerun command,
2. a stable seed or deterministic fixture reference,
3. explicit artifact pointers (logs, traces, captures),
4. package/module version identifiers.

If any of these are missing, the evidence row is invalid.

## Cross-References

1. `TESTING.md`
2. `docs/wasm_flake_governance_and_forensics.md`
3. `docs/wasm_release_rollback_incident_playbook.md`
4. `docs/wasm_bundler_compatibility_matrix.md`
5. `docs/wasm_nextjs_template_cookbook.md`
6. `docs/wasm_react_reference_patterns.md`
