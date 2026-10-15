# Browser Consumer Compatibility Matrix

Contract ID: `browser-consumer-compatibility-matrix-v1`
Bead: `asupersync-idea-wizard-fifth-wave-3gaiun.4.3`

## Purpose

This matrix is the Browser GA B3 manifest lane. It binds the existing browser
consumer fixtures to the support classes from
`artifacts/browser_edition_readiness_matrix_v1.json` and the package gate from
`artifacts/browser_package_integrity_gate_v1.json`.

Canonical machine artifact: `artifacts/browser_consumer_compatibility_matrix_v1.json`.

The matrix is intentionally stricter than a list of scripts: each row records
the fixture, repro command, expected support-class outcome, summary artifact,
failure-bundle requirement, and no-claim boundaries. A skipped unsupported
capability is never a green Browser GA row.

## Rows

| Consumer ID | Fixture | Support class | GA effect |
| --- | --- | --- | --- |
| `vite_vanilla_consumer` | `tests/fixtures/vite-vanilla-consumer` | `direct_runtime_supported` | Eligible only when B1, B2, and B3 evidence are fresh in the same candidate window. |
| `webpack_consumer` | `tests/fixtures/webpack-consumer` | `direct_runtime_supported` | Eligible only when B1, B2, and B3 evidence are fresh in the same candidate window. |
| `react_client_consumer` | `tests/fixtures/react-consumer` | `direct_runtime_supported` | Eligible only when B1, B2, and B3 evidence are fresh in the same candidate window. |
| `next_client_consumer` | `tests/fixtures/next-turbopack-consumer` | `direct_runtime_supported` | Client-only Browser Edition evidence; server and edge routes stay bridge-only. |
| `next_server_edge_bridge` | `tests/fixtures/next-turbopack-consumer/app/api` | `bridge_only` | No direct runtime promotion. |
| `dedicated_worker_consumer` | `tests/fixtures/dedicated-worker-consumer` | `direct_runtime_supported` | Eligible only when browser-run evidence is present. |
| `service_worker_broker_consumer` | `tests/fixtures/service-worker-broker-consumer` | `broker_coordinator_only` | Broker evidence only; no service-worker direct runtime promotion. |
| `shared_worker_coordinator_consumer` | `tests/fixtures/shared-worker-consumer` | `broker_coordinator_only` | Coordinator evidence only; no shared-worker direct runtime promotion. |
| `browser_native_message_stream_consumer` | `tests/fixtures/browser-native-message-stream-consumer` | `direct_runtime_supported` | Helper evidence only; does not replace package or ABI gates. |
| `rust_browser_consumer_preview` | `tests/fixtures/rust-browser-consumer` | `preview_public_lane` | Preview evidence only; does not promote the Rust browser lane to stable. |
| `unsupported_native_only_surfaces_guard` | `tests/wasm_browser_support_boundary_contract.rs` | `impossible_unsupported` | Fail-closed guard; a skip is not green evidence. |

## Failure Bundles

On any non-pass, B3 requires a failure bundle matching
`tests/fixtures/browser_consumer_compatibility_matrix/failure_bundles.json`.
At minimum, the bundle records the consumer id, readiness surface, support
class, verdict, reason code, repro command, expected action, and
`green_for_ga=false`.

Required rehearsed failures:

- `missing_packaged_browser_artifact`
- `browser_capability_skip`
- `unsupported_direct_runtime_attempt`
- `next_edge_direct_runtime_attempt`
- `bundle_budget_regression`
- `rust_preview_rch_local_fallback`
- `native_only_surface_skip`

## No-Claim Boundaries

B3 does not execute `npm publish`, prove broad workspace health, promote the
preview Rust browser runtime to stable, promote service-worker or shared-worker
direct runtime, claim native-only browser parity, or replace the B1 readiness
matrix and B2 package integrity gate.

## Focused Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_browser_consumer_compatibility_matrix cargo test -p asupersync --test browser_consumer_compatibility_matrix_contract -- --nocapture
```
