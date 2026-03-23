# WASM TypeScript Package Topology Contract

Contract ID: `wasm-typescript-package-topology-v1`  
Bead: `asupersync-umelq.9.1`

## Purpose

Define deterministic TypeScript package boundaries for Browser Edition so users
can adopt a layered API without hidden semantic drift.

## Canonical Inputs

- Policy: `.github/wasm_typescript_package_policy.json`
- Gate script: `scripts/check_wasm_typescript_package_policy.py`
- Onboarding runner: `scripts/run_browser_onboarding_checks.py`

## Package Topology

Required package set:

1. `@asupersync/browser-core`
2. `@asupersync/browser`
3. `@asupersync/react`
4. `@asupersync/next`

Layer contract:

1. `@asupersync/browser-core` owns low-level runtime and type surface contracts.
2. `@asupersync/browser` owns high-level SDK semantics and diagnostics surface.
3. `@asupersync/react` and `@asupersync/next` are adapter layers over
   `@asupersync/browser`.
4. Public exports must be tree-shake safe and must not expose
   `./internal/*` or `./native/*` subpaths.

## Shipped Package Reference Map

Use this section as the day-two ownership guide for the committed JS/TS package
surface.

| Package | Owns | Key shipped exports | Use it when | Avoid it when |
|---|---|---|---|---|
| `@asupersync/browser-core` | low-level ABI/types/handle primitives | `RuntimeHandle`, `RegionHandle`, `TaskHandle`, `FetchHandle`, `CancellationToken`, `runtimeCreate`, `scopeEnter`, `taskSpawn`, `fetchRequest`, `websocketOpen`, `abiVersion`, `abiFingerprint`, `rawBindings` | you need direct access to ABI handles, raw outcome envelopes, or packaged metadata-driven negotiation | you want app-facing ergonomics or unsupported-runtime guidance |
| `@asupersync/browser` | high-level browser SDK and diagnostics | `BrowserRuntime`, SDK `RegionHandle` / `TaskHandle` / `FetchHandle` / `CancellationToken`, `createCancellationToken`, `createBrowserSdkDiagnostics`, `detectBrowserRuntimeSupport`, `assertBrowserRuntimeSupport`, `unwrapOutcome`, `formatOutcomeFailure` | you are writing browser-only runtime code and want a friendlier API over browser-core | you are in SSR/server/edge code or need framework-specific boundary guidance |
| `@asupersync/react` | React client-boundary adapter surface | browser re-exports plus `detectReactRuntimeSupport`, `createReactUnsupportedRuntimeError`, `assertReactRuntimeSupport` | you need React-specific client-boundary checks over the browser SDK | you are calling runtime APIs during SSR or outside a client-rendered tree |
| `@asupersync/next` | Next.js boundary adapter surface | browser re-exports plus `NextRuntimeTarget`, `detectNextRuntimeSupport`, `createNextUnsupportedRuntimeError`, `assertNextRuntimeSupport` | you need explicit client/server/edge boundary guidance in a Next app | you expect server or edge modules to run Browser Edition directly |

Practical package-selection rule:

1. Start with `@asupersync/browser`.
2. Drop to `@asupersync/browser-core` only when you need raw ABI handles,
   metadata, or version negotiation.
3. Move up to `@asupersync/react` or `@asupersync/next` when framework boundary
   diagnostics matter more than raw package minimalism.

## Live Support Matrix Snapshot (2026-03-15 / `asupersync-1tte9`)

Use this as the package-facing summary of the live support boundary. The fuller
runtime/capability inventory lives in `docs/wasm_api_surface_census.md`.

| Call site or environment | Package posture today | Package guidance |
|---|---|---|
| Browser main thread | Direct runtime is supported | `@asupersync/browser` is the default; `@asupersync/react` and `@asupersync/next` client paths layer on top of the same browser runtime lane. |
| Dedicated worker bootstrap module | Direct runtime is supported for `@asupersync/browser` | `@asupersync/browser` recognizes `DedicatedWorkerGlobalScope`, and browser-core host fetch now supports `window` or `WorkerGlobalScope`. Treat this as the dedicated-worker Browser Edition lane; service/shared workers still have no direct-runtime package surface. |
| Service worker / shared worker | No direct-runtime package surface yet | Keep these environments on explicit message/data boundaries until a worker-specific host contract is shipped. |
| React client-rendered tree | Direct runtime is supported | Use `@asupersync/react` only from client-rendered trees; it intentionally inherits the browser runtime boundary. |
| React SSR / Node render path | Bridge-only | Do not initialize Browser Edition during SSR; move runtime creation into the client tree. |
| Next `client_hydrated` | Direct runtime is supported | `@asupersync/next` is valid here and should create runtime state only after hydration. |
| Next `client_ssr` | Bridge/defer only | Defer runtime initialization until the browser hydrates. |
| Next server / edge | Bridge-only | Use the explicit `use_server_bridge` / `use_edge_bridge` fallbacks instead of direct Browser Edition execution. |
| Plain Node / SSR / non-browser test process | Not a Browser Edition direct-runtime target | Use native `asupersync` or explicit bridge seams rather than catching unsupported-runtime errors and continuing. |

Maintained dedicated-worker validation path:

- fixture: `tests/fixtures/dedicated-worker-consumer`
- validator: `scripts/validate_dedicated_worker_consumer.sh`
- onboarding lane: `python3 scripts/run_browser_onboarding_checks.py --scenario worker`
- artifact pointers: `target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json`,
  `target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json`
- summary expectation: the dedicated-worker `summary.json` bundle preserves
  `scenario_inventory` plus artifact pointers under `artifacts` for lane-selection,
  storage/export, and downgrade review

## Rust Crate Layout and Artifact Provenance

The TypeScript package topology is layered over a separate Rust crate layout.

| Surface | Role | Artifact rule |
|---------|------|---------------|
| `asupersync` | Portable runtime core and canonical ABI contract owner | Rust `rlib`; no direct `wasm-bindgen` exports |
| `asupersync-browser-core` | Browser WASM producer crate | sole `cdylib`/`rlib` bindings crate; wraps the ABI dispatcher in `src/types/wasm_abi.rs` |
| `packages/browser-core/` | Published JS/WASM package root for `@asupersync/browser-core` | assembled from staged bindgen output plus package metadata |
| `packages/browser/`, `packages/react/`, `packages/next/` | Higher-level JS/TS packages | consume `@asupersync/browser-core`; no additional Rust producer crate |

Artifact provenance rules:

1. `asupersync-browser-core` is the only crate that emits the concrete browser
   WASM/JS boundary.
2. Bindgen output is staged under `pkg/browser-core/<profile>/` and is
   ephemeral build output, not the committed package source of truth.
3. `packages/browser-core/` is the package-assembly destination that receives
   artifacts from `pkg/browser-core/<profile>/`.
4. The root `asupersync` crate remains the source of truth for ABI symbols,
   compatibility policy, and dispatcher semantics.

## Next.js Boundary Strategy and Fallback Contract (WASM-10 / `asupersync-umelq.11.3`)

Source-of-truth runtime mapping lives in `src/types/wasm_abi.rs`:

- `NextjsRenderEnvironment::boundary_mode()`
- `NextjsRenderEnvironment::runtime_fallback()`
- `NextjsRenderEnvironment::runtime_fallback_reason()`

Boundary strategy:

1. `client` boundary:
   - environments: `client_ssr`, `client_hydrated`
   - direct runtime execution is allowed only in `client_hydrated`
2. `server` boundary:
   - environments: `server_component`, `node_server`
   - runtime execution is not allowed; use serialized server bridge
3. `edge` boundary:
   - environment: `edge_runtime`
   - runtime execution is not allowed; use serialized edge bridge

Deterministic fallback matrix:

| Render environment | Boundary mode | `supports_wasm_runtime` | Fallback policy | Required behavior |
|---|---|---|---|---|
| `client_hydrated` | `client` | `true` | `none_required` | execute runtime directly |
| `client_ssr` | `client` | `false` | `defer_until_hydrated` | defer runtime init until hydration completes |
| `server_component` | `server` | `false` | `use_server_bridge` | route operation through serialized server companion |
| `node_server` | `server` | `false` | `use_server_bridge` | route operation through serialized server companion |
| `edge_runtime` | `edge` | `false` | `use_edge_bridge` | route operation through serialized edge companion |

Mixed deployment guidance:

1. Keep runtime handles in client-only scope; never pass `WasmHandleRef` through server actions.
2. Treat server/edge requests as bridge requests and return serialized outcomes only.
3. Keep cancellation ownership in the originating client scope; bridge calls must return explicit cancel-compatible status instead of hidden retries.
4. If fallback path is selected, emit structured diagnostics with:
   - `boundary_mode`
   - `render_environment`
   - `runtime_fallback`
   - `repro_command`

Compatibility caveats:

1. `edge_runtime` does not imply `node_apis`; avoid Node-only adapters in edge mode.
2. `client_ssr` has browser hooks surface but no runtime initialization authority.
3. Runtime calls in non-hydrated/non-client boundaries must fail closed to fallback policy; no ambient execution escape hatches.

## Type Surface Ownership

Required symbols and package owners:

1. `Outcome` -> `@asupersync/browser-core`
2. `Budget` -> `@asupersync/browser-core`
3. `CancellationToken` -> `@asupersync/browser`
4. `RegionHandle` -> `@asupersync/browser`

Any symbol owner outside the declared package topology fails policy.

### API Ownership Notes

- `@asupersync/browser-core` is the source of truth for ABI version/fingerprint,
  four-valued `Outcome`, low-level handle classes, and the raw binding aliases.
- `@asupersync/browser` is the source of truth for user-facing runtime classes,
  structured unsupported-runtime diagnostics, and browser capability snapshots.
- `@asupersync/react` and `@asupersync/next` intentionally stay thin: they add
  framework-boundary diagnostics and re-export the browser SDK instead of
  introducing competing runtime semantics.

## Runtime and Lifecycle Rules for JS/TS Consumers

These are the practical rules users need after initial setup:

1. `BrowserRuntime` (or `RuntimeHandle` at the low level) is the ownership root.
   Create it only in a boundary that is actually classified as
   direct-runtime-supported in the live matrix above, then close it
   explicitly.
2. Region creation is structured. Enter scopes/regions from a runtime or parent
   region instead of inventing detached task roots.
3. Task, fetch, and websocket work should be opened from region scope. Keep
   handles local to the scope that owns their cleanup responsibility.
4. Cancellation remains explicit. Pass `kind` / `message` when cancelling so
   diagnostics and replay traces preserve intent.
5. Use `unwrapOutcome(...)` or explicit `outcome` branching at the browser SDK
   level; do not assume exceptions are the primary success/error channel.
6. Unsupported-runtime helpers (`assert*RuntimeSupport`) are boundary guards,
   not soft hints. Treat their failure as a signal to move the call site, not as
   something to catch and ignore.
7. Do not move live handles across client/server boundaries. Server and edge
   code should exchange serializable requests/results only.

## Upgrade and Versioning Playbook

Package versioning and ABI versioning are related but not identical:

- package versions describe published JS/TS artifacts
- ABI version + fingerprint describe compatibility of the packaged runtime wire
  contract exposed by `@asupersync/browser-core`

Consumer rules:

1. Prefer upgrading all `@asupersync/*` packages together.
2. When mixing versions intentionally, inspect `abi-metadata.json`,
   `abiVersion()`, and `abiFingerprint()` before relying on version-sensitive
   calls.
3. Treat omitted `consumerVersion` as bootstrap/introspection-only; supply an
   explicit consumer version before long-lived or version-sensitive operations.
4. Minor producer additions are allowed only when compatibility classification
   remains `Exact` or `BackwardCompatible`.
5. `ConsumerTooOld` and `MajorMismatch` are fail-closed signals. Upgrade the
   consumer package set instead of trying to paper over the mismatch.
6. Higher-level packages (`@asupersync/browser`, `@asupersync/react`,
   `@asupersync/next`) must not invent their own ABI-version state; they follow
   the packaged `browser-core` metadata.

Recommended upgrade checklist:

1. Inspect `packages/browser-core/abi-metadata.json` (or the published package
   sidecar) for `abi_version` and fingerprint changes.
2. Re-run the packaged ABI compatibility matrix:
   `rch exec -- cargo test --test wasm_packaged_abi_compatibility_matrix -- --nocapture`
3. Re-run the shipped package export/diagnostics contract:
   `rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture`
4. If a major ABI change landed, upgrade all `@asupersync/*` packages together
   and follow the migration note in `docs/wasm_abi_compatibility_policy.md`.

## Resolution Matrix and E2E Command Contract

The policy encodes deterministic install-and-run command pairs for:

1. Vanilla TypeScript (ESM + CJS)
2. React (ESM + CJS)
3. Next.js (ESM + CJS)

Each scenario defines:

1. `entrypoint`
2. `module_mode`
3. `bundler`
4. `adapter_path`
5. `runtime_profile`
6. `install_command`
7. `run_command`

Coverage gates:

1. Required frameworks: `vanilla-ts`, `react`, `next`
2. Required module modes: `esm`, `cjs`
3. Required bundlers: `vite`, `webpack`, `next-turbopack`

## Structured Logging Contract

Onboarding and policy logs must include:

1. `scenario_id`
2. `step_id`
3. `package_entrypoint`
4. `adapter_path`
5. `runtime_profile`
6. `diagnostic_category`
7. `outcome`
8. `artifact_log_path`
9. `repro_command`

`run_browser_onboarding_checks.py` emits these fields per step so onboarding
failures are diagnosable by package boundary and adapter lane.

## Gate Outputs

- Summary JSON: `artifacts/wasm_typescript_package_summary.json`
- NDJSON log: `artifacts/wasm_typescript_package_log.ndjson`

## Repro Commands

Self-test:

```bash
python3 scripts/check_wasm_typescript_package_policy.py --self-test
```

Full policy gate:

```bash
python3 scripts/check_wasm_typescript_package_policy.py \
  --policy .github/wasm_typescript_package_policy.json
```

Framework-scoped checks (used by onboarding runner):

```bash
python3 scripts/check_wasm_typescript_package_policy.py \
  --policy .github/wasm_typescript_package_policy.json \
  --only-scenario TS-PKG-VANILLA-ESM \
  --only-scenario TS-PKG-VANILLA-CJS

python3 scripts/check_wasm_typescript_package_policy.py \
  --policy .github/wasm_typescript_package_policy.json \
  --only-scenario TS-PKG-REACT-ESM \
  --only-scenario TS-PKG-REACT-CJS

python3 scripts/check_wasm_typescript_package_policy.py \
  --policy .github/wasm_typescript_package_policy.json \
  --only-scenario TS-PKG-NEXT-ESM \
  --only-scenario TS-PKG-NEXT-CJS
```

Dedicated-worker validation lane:

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario worker
PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh
```

Reference verification:

```bash
rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture
rch exec -- cargo test --test wasm_packaged_abi_compatibility_matrix -- --nocapture
```

## Cross-References

- `docs/integration.md` (support boundary and package-selection guardrails)
- `docs/wasm_dx_error_taxonomy.md` (developer-facing error and diagnostics model)
- `docs/wasm_abi_compatibility_policy.md` (packaged ABI upgrade/downgrade rules)
