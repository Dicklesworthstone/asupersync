# Browser Edition Readiness Matrix

The checked Browser Edition readiness source is
[`artifacts/browser_edition_readiness_matrix_v1.json`](../artifacts/browser_edition_readiness_matrix_v1.json).
This page is the human review view of that artifact. The JSON remains the
machine contract, and
[`tests/browser_edition_readiness_matrix_contract.rs`](../tests/browser_edition_readiness_matrix_contract.rs)
keeps this page, README, `docs/WASM.md`, and `docs/integration.md` aligned.

This matrix is a release-review boundary. It records what can be claimed, which
fixture or contract proves the claim, how a row rolls back, and what the row
explicitly does not prove.

## Support Classes

| Support class | Meaning | Default rollback |
|---|---|---|
| Direct-runtime supported | Runtime and scope handles may be constructed directly inside the documented browser boundary. | Demote to preview or unsupported when diagnostics, package guards, or fixture evidence drift. |
| Package ABI boundary | Repository-maintained wasm/package infrastructure that feeds the JS/TS packages. | Block package GA when ABI metadata, package exports, generated artifacts, or package contracts drift. |
| Preview public lane | Public but narrower Rust-authored browser path with fail-closed diagnostics. | Downgrade to internal fixture guidance when builder diagnostics, docs, or fixture evidence regress. |
| Broker/coordinator-only | The host can coordinate bounded broker/coordinator work but cannot own a direct runtime. | Demote to preview-only and preserve fail-closed direct-runtime diagnostics. |
| Bridge-only | Runtime creation must stay behind a serialized adapter or explicit bridge. | Block any direct-runtime claim at the bridged boundary. |
| Impossible / unsupported | Browser security model or package contract rules out support. | Keep fail-closed diagnostics and native-runtime or bridge guidance. |

## Readiness Rows

| Row | Support class | Required evidence | No-claim boundary |
|---|---|---|---|
| `browser_core_package_boundary` - `@asupersync/browser-core` package boundary | Package ABI boundary | `packages/browser-core/abi-metadata.json`, package metadata, ABI compatibility tests | Not a stable external Rust runtime SDK. |
| `browser_package_main_thread` - `@asupersync/browser` main-thread runtime | Direct-runtime supported | `tests/fixtures/vite-vanilla-consumer/`, `tests/wasm_js_exports_coverage_contract.rs` | No Node, SSR, service-worker, shared-worker, or native host parity claim. |
| `react_client_adapter` - `@asupersync/react` client adapter | Direct-runtime supported | `tests/fixtures/react-consumer/`, React adapter lifecycle contract | No React SSR direct-runtime claim. |
| `next_client_adapter` - `@asupersync/next` client adapter | Direct-runtime supported | `tests/fixtures/next-turbopack-consumer/`, Next adapter lifecycle contract | No direct runtime in server components, route handlers, or edge runtimes. |
| `next_server_edge_bridge` - Next server and edge bridge boundaries | Bridge-only | Next server/edge bridge fixture routes and adapter lifecycle contract | No live runtime handles across server or edge boundaries. |
| `vite_vanilla_consumer` - vanilla/Vite consumer | Direct-runtime supported | `tests/fixtures/vite-vanilla-consumer/`, `scripts/validate_vite_vanilla_consumer.sh` | Does not prove every bundler or unsupported host context. |
| `webpack_consumer` - Webpack consumer | Direct-runtime supported | `tests/fixtures/webpack-consumer/`, `scripts/validate_webpack_consumer.sh` | Does not prove every Webpack plugin, loader, or server-side runtime path. |
| `dedicated_worker_runtime` - Dedicated worker direct-runtime lane | Direct-runtime supported | `tests/fixtures/dedicated-worker-consumer/`, worker feasibility and exports contracts | No automatic worker offload, service-worker runtime, or shared-worker runtime claim. |
| `service_worker_broker` - Service-worker bounded broker | Broker/coordinator-only | `tests/fixtures/service-worker-broker-consumer/`, service-worker broker contract | No service-worker direct runtime or broad lifetime parity claim. |
| `shared_worker_coordinator` - Shared-worker bounded coordinator | Broker/coordinator-only | `tests/fixtures/shared-worker-consumer/`, shared-worker tenancy lifecycle contract | No shared-worker direct runtime or host ownership parity claim. |
| `rust_runtime_builder_browser_preview` - Rust `RuntimeBuilder::browser()` preview | Preview public lane | `tests/fixtures/rust-browser-consumer/`, builder diagnostics, Rust browser example contract | No stable external Rust Browser Edition parity claim. |
| `abi_package_artifacts` - Browser ABI and package artifacts | Package ABI boundary | `packages/browser-core/asupersync_bg.wasm`, ABI metadata, bundle budget contract | Does not prove every publishing, provenance, or Rust runtime parity gate. |
| `unsupported_native_only_surfaces` - Unsupported native-only surfaces | Impossible / unsupported | wasm cfg gates, support boundary contract, feasibility matrix | No raw TCP/UDP, filesystem, process, signal, native DB, or native TLS direct browser support. |

## Freshness Rule

Every row has a `last_reviewed_date` and `review_window_days` in the JSON
artifact. A stale row must roll back to its recorded `rollback_status` until a
fresh evidence lane rerun updates the row. The contract test includes a stale
row rehearsal so a missing or old review date fails closed instead of being
cited as current Browser Edition readiness.

## Promotion Rule

Promotion requires the row-specific fixture or contract evidence, matching docs
markers, explicit rollback status, and explicit no-claims. A green row proves
only the support class named for that row. It does not promote adjacent
surfaces, widen server/edge boundaries, or turn broker/coordinator helpers into
direct-runtime support.
