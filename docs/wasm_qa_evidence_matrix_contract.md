# WASM QA Evidence Matrix Contract

Beads: `asupersync-3qv04.8.1`, `asupersync-3qv04.8.4.4`

## Purpose

This contract defines the required evidence matrix for Browser Edition quality assurance. Every implementation bead in the WASM track must satisfy specific evidence requirements before calling itself done. The matrix covers Rust cfg/feature gating, exported ABI handle safety, JS/TS type surface behavior, browser host-bridge correctness, framework adapter lifecycle, bundled-package installability, cross-browser execution, and failure forensics.

## Contract Artifacts

1. Canonical artifact: `artifacts/wasm_qa_evidence_matrix_v1.json`
2. Comparator-smoke runner: `scripts/run_wasm_qa_evidence_smoke.sh`
3. Invariant suite: `tests/wasm_qa_evidence_matrix_contract.rs`
4. Compile-invariant harness: `tests/wasm_cfg_compile_invariants.rs`

## Evidence Layers

### L1: Rust Cfg and Feature Gating

Every `cfg(target_arch = "wasm32")` and `cfg(feature = "wasm-browser-*")` gate must be tested for both inclusion and exclusion. Native-only code must not leak into wasm builds; wasm-only stubs must not appear in native builds.

| Evidence ID | Description | Tool |
|-------------|-------------|------|
| L1-CFG-COMPILE | `cargo check --target wasm32-unknown-unknown` passes with each wasm profile | cargo/rch |
| L1-CFG-NATIVE | `cargo check --all-targets` still passes (no native regression) | cargo/rch |
| L1-CFG-LEAK | No native-only import reachable under wasm32 compilation | cargo/clippy |

The leak frontier for this layer is intentionally concrete rather than abstract.
At minimum, the harness must keep these prior regression surfaces in the blame path:

- `src/config.rs`
- `src/runtime/reactor/source.rs`
- `src/net/tcp/socket.rs`
- `src/trace/file.rs`

### L2: Exported ABI Handle Safety

Exported handles (task handles, stream handles, etc.) must enforce ownership, drop semantics, and error propagation across the wasm boundary.

| Evidence ID | Description | Tool |
|-------------|-------------|------|
| L2-ABI-OWNERSHIP | Each exported handle type has a single-owner invariant test | cargo test |
| L2-ABI-DROP | Drop across wasm boundary releases resources (no leak) | cargo test |
| L2-ABI-ERROR | Error values are correctly marshalled to JS-visible types | cargo test |

### L3: JS/TS Type Surface

Package entrypoints, type declarations, and module resolution must work for consumers importing the package.

| Evidence ID | Description | Tool |
|-------------|-------------|------|
| L3-TYPES-CORRECT | `.d.ts` declarations match actual exports | tsc --noEmit |
| L3-EXPORTS-RESOLVE | Package exports map resolves for ESM and CJS consumers | node --conditions |
| L3-TREE-SHAKE | Dead code elimination does not break live exports | bundler test |

### L4: Browser Host-Bridge Correctness

Fetch, streams, WebSocket, and storage bridges must correctly map browser APIs to the runtime's async model.

| Evidence ID | Description | Tool |
|-------------|-------------|------|
| L4-FETCH-BASIC | Fetch bridge completes a round-trip HTTP request | E2E harness |
| L4-STREAM-FLOW | ReadableStream/WritableStream backpressure works | E2E harness |
| L4-WS-LIFECYCLE | WebSocket open/message/close lifecycle is correct | E2E harness |
| L4-STORAGE-ROUNDTRIP | Storage bridge persists and retrieves data | E2E harness |
| L4-ABORT | AbortSignal cancellation propagates to runtime | E2E harness |

### L5: Framework Adapter Lifecycle

React provider/hook and Next adapters must handle mount, unmount, StrictMode double-mount, and SSR/hydration correctly.

| Evidence ID | Description | Tool |
|-------------|-------------|------|
| L5-REACT-MOUNT | Provider mounts and initializes runtime | React test |
| L5-REACT-STRICT | StrictMode double-mount does not leak or double-init | React test |
| L5-NEXT-SSR | Server-side rendering does not import wasm | Next test |
| L5-NEXT-HYDRATE | Client hydration bootstraps runtime correctly | Next test |

### L6: Package Installability

Published packages must install cleanly via npm/yarn/pnpm and resolve correctly in bundlers.

| Evidence ID | Description | Tool |
|-------------|-------------|------|
| L6-NPM-INSTALL | `npm install` succeeds for each package | npm |
| L6-BUNDLER-VITE | Vite consumer builds and runs | Vite |
| L6-BUNDLER-WEBPACK | Webpack consumer builds and runs | Webpack |
| L6-BUNDLER-TURBOPACK | Turbopack consumer builds and runs | Turbopack |

### L7: Cross-Browser Execution

Core functionality must work in Chrome, Firefox, and Safari (latest stable).

| Evidence ID | Description | Tool |
|-------------|-------------|------|
| L7-CHROME | E2E suite passes in Chrome | Playwright |
| L7-FIREFOX | E2E suite passes in Firefox | Playwright |
| L7-SAFARI | E2E suite passes in Safari/WebKit | Playwright |

### L8: Failure Forensics and Logging

Failures must produce diagnosable artifacts with exact repro commands.

| Evidence ID | Description | Tool |
|-------------|-------------|------|
| L8-CONSOLE-CAPTURE | Browser console output captured in CI artifacts | Playwright |
| L8-WASM-VERSION | wasm module version and build hash in logs | structured log |
| L8-REPRO-COMMAND | Every failure log includes a runnable repro command | log schema |
| L8-ARTIFACT-RETENTION | CI retains failure artifacts for at least 7 days | CI config |

## Structured Logging Contract

QA evidence logs MUST include:

- `evidence_id`: Which evidence item (e.g. L1-CFG-COMPILE)
- `layer`: Evidence layer (L1-L8)
- `tool`: Tool used for verification
- `wasm_profile`: Feature profile tested
- `browser`: Browser name and version (L7)
- `package_name`: Package under test (L3/L6)
- `verdict`: `pass`, `fail`, `skip`, or `blocked`
- `failure_reason`: Human-readable failure description (if fail)
- `repro_command`: Exact command to reproduce
- `artifact_path`: Path to failure artifacts

## E2E Log Schema

Schema version: `wasm-qa-e2e-log-v1`

Every emitted line in `events.ndjson` must include:

- `schema_version`
- `event_kind`
- `scenario_id`
- `run_id`
- `timestamp_utc`
- `wasm_profile`
- `browser`
- `package_name`
- `module_fingerprint`
- `verdict`
- `command_exit_code`
- `repro_command`
- `bundle_manifest_path`
- `artifact_path`
- `retention_class`
- `retention_until_utc`

## Artifact Bundle Layout

Bundle schema version: `wasm-qa-artifact-bundle-v1`

Each scenario bundle under `target/wasm-qa-evidence-smoke/<run>/<scenario>/` must contain:

- `bundle_manifest.json`
- `run_report.json`
- `run.log`
- `events.ndjson`

`bundle_manifest.json` and `run_report.json` must continue emitting compatibility fields for the legacy schemas:

- `schema = wasm-qa-evidence-smoke-bundle-v1`
- `schema = wasm-qa-evidence-smoke-run-report-v1`

## Retention Policy

Retention schema version: `wasm-qa-artifact-retention-v1`

Required retention classes:

| Class | Minimum retention | Intended use |
|-------|--------------------|--------------|
| `hot` | 30 days | failing runs and incident investigations |
| `warm` | 14 days | successful execute runs |
| `cold` | 7 days | dry-run and low-signal bundles |

Bundle manifests and run reports must both include `retention_class` and `retention_until_utc`.

## Comparator-Smoke Runner

Canonical runner: `scripts/run_wasm_qa_evidence_smoke.sh`

The runner reads `artifacts/wasm_qa_evidence_matrix_v1.json`, supports deterministic dry-run or execute modes for either a single scenario or the full smoke matrix (`--all`), and emits:

1. Per-scenario manifests with schema `wasm-qa-evidence-smoke-bundle-v1`
2. Aggregate run report with schema `wasm-qa-evidence-smoke-run-report-v1`
3. Structured event logs (`events.ndjson`) with schema `wasm-qa-e2e-log-v1`
4. Retention metadata following `wasm-qa-artifact-retention-v1`

When invoked as `bash ./scripts/run_wasm_qa_evidence_smoke.sh --all --execute`, the runner also emits a suite-level `summary.json` with schema `e2e-suite-summary-v3` under `target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/`. That is the canonical surface used by `scripts/run_all_e2e.sh --suite wasm-qa-evidence-smoke`.

Packaged bootstrap/load/reload baseline harness (bead `asupersync-3qv04.8.4.1`) is tracked as smoke scenario `WASM-QA-SMOKE-PACKAGED-BOOTSTRAP`, which invokes:

```bash
rch exec -- env HARNESS_PROFILE=packaged_bootstrap HARNESS_DRY_RUN=1 RCH_BIN=/bin/true FAULT_MATRIX_MODE=reduced bash scripts/test_wasm_cross_framework_e2e.sh
```

Host-bridge fetch/streams/websocket/storage baseline harness (bead `asupersync-3qv04.8.4.3`) is tracked as smoke scenario `WASM-QA-SMOKE-HOST-BRIDGE`, which invokes:

```bash
rch exec -- env HARNESS_PROFILE=host_bridge HARNESS_DRY_RUN=1 RCH_BIN=/bin/true FAULT_MATRIX_MODE=reduced bash scripts/test_wasm_cross_framework_e2e.sh
```

Cross-browser compatibility + forensics baseline harness (bead `asupersync-3qv04.8.5`) is tracked as smoke scenario `WASM-QA-SMOKE-CROSS-BROWSER`, which invokes:

```bash
rch exec -- env HARNESS_PROFILE=full HARNESS_DRY_RUN=1 RCH_BIN=/bin/true FAULT_MATRIX_MODE=reduced BROWSER_MATRIX=chromium-headless,firefox-headless,webkit-headless bash scripts/test_wasm_cross_framework_e2e.sh
```

## Validation

Canonical orchestration commands:

```bash
bash ./scripts/run_wasm_qa_evidence_smoke.sh --all --execute
bash ./scripts/run_all_e2e.sh --suite wasm-qa-evidence-smoke
```

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-wasm-qa cargo test --test wasm_qa_evidence_matrix_contract -- --nocapture
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-wasm-cfg cargo test --test wasm_cfg_compile_invariants wasm_profile_matrix_compile_closure_holds -- --ignored --nocapture
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-wasm-cfg cargo test --test wasm_cfg_compile_invariants native_all_targets_backstop_holds -- --ignored --nocapture
```

## Cross-References

- `src/types/wasm_abi.rs` -- WASM ABI types
- `src/lib.rs` -- Feature gate declarations
- `src/net/tcp/mod.rs` -- TCP cfg gating
- `src/runtime/reactor/mod.rs` -- Reactor cfg gating
- `src/runtime/reactor/source.rs` -- Reactor source export hotspot
- `src/trace/file.rs` -- Native file-trace hotspot
- `Cargo.toml` -- Feature definitions (wasm-browser-*)
- `artifacts/wasm_qa_evidence_matrix_v1.json`
- `scripts/run_all_e2e.sh`
- `scripts/run_wasm_qa_evidence_smoke.sh`
- `tests/wasm_qa_evidence_matrix_contract.rs`
- `tests/wasm_cfg_compile_invariants.rs`
