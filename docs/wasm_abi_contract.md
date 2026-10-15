# WASM ABI Contract (WASM-ADR-007)

Contract ID: `asupersync-wasm-abi-v1`  
Status: active for browser profile lanes (`wasm-browser-dev`, `wasm-browser-prod`, `wasm-browser-deterministic`, `wasm-browser-minimal`)  
Primary owner: bindings/api

## Scope

This contract defines the stable JS/TS <-> WASM boundary schema for Asupersync:

1. ABI versioning and compatibility decisions.
2. Stable boundary symbol set and request/response payload shapes.
3. Outcome, error, and cancellation encoding rules.
4. Ownership/lifecycle boundary state transitions.
5. Deterministic drift-detection fingerprint for CI policy enforcement.

Canonical implementation: `src/types/wasm_abi.rs`.

## Concrete Artifact Strategy and Crate Layout

The ABI contract is owned by the root `asupersync` crate, but the concrete
browser artifact producer is a separate bindings crate.

Decision:

1. `asupersync` remains the canonical portable core crate and ABI-model owner.
   It stays bindgen-free so native, lab, and browser lanes share one Rust
   implementation surface for runtime semantics, cancellation, and the
   dispatcher contract.
2. A dedicated workspace member named `asupersync-browser-core` is the only
   crate allowed to produce the browser `cdylib`/`wasm-bindgen` boundary.
3. `asupersync-browser-core` exports the v1 symbols as thin wrappers over the
   dispatcher/types defined in `src/types/wasm_abi.rs`; symbol ownership and
   compatibility policy remain defined in the root crate.
4. Browser host integration details such as module bootstrap, JS error/value
   conversion, and browser event-loop wiring live in `asupersync-browser-core`,
   not in `asupersync`.
5. Generated bindgen output is staging only and lives under
   `pkg/browser-core/<profile>/`. That directory is not the long-lived package
   source of truth.
6. Published package assembly copies staged artifacts from
   `pkg/browser-core/<profile>/` into `packages/browser-core/`, after which the
   higher-level JS packages consume `@asupersync/browser-core`.
7. `@asupersync/browser`, `@asupersync/react`, and `@asupersync/next` remain
   JS/TS package layers over `@asupersync/browser-core`; they do not introduce
   extra Rust `cdylib` producers unless a later ABI decision explicitly amends
   this contract.

## Versioning Rules

- Version type: `major.minor` (`WasmAbiVersion`).
- Compatibility function: `classify_wasm_abi_compatibility(producer, consumer)`.
- Rules:
  - major mismatch => incompatible
  - same major + consumer minor < producer minor => incompatible
  - same major + equal minor => exact
  - same major + consumer minor > producer minor => backward compatible

## Break Taxonomy

`WasmAbiChangeClass` and `required_wasm_abi_bump()` are normative:

- Minor bump:
  - additive fields
  - additive symbols
  - behavioral relaxations
- Major bump:
  - behavioral tightening
  - symbol removal/rename
  - wire-encoding changes
  - outcome semantic reinterpretation
  - cancellation semantic reinterpretation

## Boundary Symbols (v1)

`WASM_ABI_SIGNATURES_V1` defines the canonical symbol + payload-shape table:

- `runtime_create`
- `runtime_close`
- `scope_enter`
- `scope_close`
- `task_spawn`
- `task_join`
- `task_cancel`
- `fetch_request`

Each symbol is bound to request/response shape classes (`WasmAbiPayloadShape`).

## Outcome and Cancellation Encoding

- Outcome envelope: `WasmAbiOutcomeEnvelope`
  - `ok { value }`
  - `err { failure }`
  - `cancelled { cancellation }`
  - `panicked { message }`
- Error payload: `WasmAbiFailure` (`code`, `recoverability`, `message`)
- Cancellation payload: `WasmAbiCancellation` maps core `CancelReason` + `CancelPhase`
  with timestamp, origin, and truncation metadata for diagnostics.

## Ownership/Lifecycle State Machine

Boundary states: `WasmBoundaryState`

- `unbound -> bound -> active`
- `active -> cancelling -> draining -> closed`
- legal direct shutdown shortcuts:
  - `bound -> closed`
  - `active -> closed`
  - `cancelling -> closed`

Validation entrypoint: `validate_wasm_boundary_transition()`.

## Next.js Hydration-safe Bootstrap Contract

This section scopes the client bootstrap protocol used by Next.js App Router
boundaries (`asupersync-umelq.11.2`) and ties it to deterministic diagnostics.

Bootstrap phases (`NextjsBootstrapPhase`):

- `server_rendered -> hydrating -> hydrated -> runtime_ready`
- `hydrated -> runtime_failed` for deterministic init failure handling
- identity transitions are allowed for idempotent re-entry in all phases

Recovery semantics:

- `soft_navigation`: runtime survives (`runtime_ready -> runtime_ready`)
- `hard_navigation`: runtime does not survive; bootstrap restarts from
  `server_rendered`
- `cache_revalidated` while `runtime_ready`: active runtime scope is
  deterministically invalidated (`runtime_ready -> hydrated`), outstanding
  runtime work is cancelled/drained, and runtime re-initialization is required
  before new side effects
- `cache_revalidated` while `hydrated`: bookkeeping-only event; does not trigger
  scope invalidation
- cancel during bootstrap must emit explicit recovery action metadata (for
  example `retry_after_cancel`) with replayable context

Scope invalidation diagnostics (`NextjsBootstrapSnapshot`):

- `scope_invalidation_count`
- `runtime_reinit_required_count`
- `active_scope_generation`
- `last_invalidated_scope_generation`

Structured log fields for bootstrap diagnostics (deterministic key set):

- `bootstrap_phase`
- `hydration_context`
- `boundary_mode` (`client|server|edge`)
- `navigation_type`
- `recovery_action`
- `route_segment`
- `active_provider_count`
- `navigation_count`
- `wasm_module_loaded`

CI/onboarding contract gate:

- `next.bootstrap_state_machine_contract` (see
  `scripts/run_browser_onboarding_checks.py`)

## Structured Observability Contract

`WasmAbiBoundaryEvent` must include:

- `abi_version`
- `symbol`
- `payload_shape`
- `state_from`
- `state_to`
- `compatibility` / `compatibility_decision`
- `compatibility_compatible`
- `compatibility_producer_major` / `compatibility_consumer_major`
- `compatibility_producer_minor` / `compatibility_consumer_minor` (when available)

`as_log_fields()` emits a deterministic key/value map for replay diagnostics.

## Drift Detection and CI Gate

- Deterministic signature fingerprint:
  - `wasm_abi_signature_fingerprint(WASM_ABI_SIGNATURES_V1)`
- Guard constant:
  - `WASM_ABI_SIGNATURE_FINGERPRINT_V1`
- Policy:
  - signature drift without version-policy update is a gate failure.
  - when fingerprint changes, update:
    1. version policy decision,
    2. migration notes,
    3. fingerprint constant.
- CI enforcement:
  - Policy file: `.github/wasm_abi_policy.json`
  - Gate script: `python3 scripts/check_wasm_abi_policy.py --policy .github/wasm_abi_policy.json`
  - Artifacts:
    - `artifacts/wasm_abi_contract_summary.json`
    - `artifacts/wasm_abi_contract_events.ndjson`

## Migration Notes Ledger

Current ABI entry: `v1.0 fingerprint=4558451663113424898`.

- `2026-02-28`: Initial `v1.0` contract baseline for WASM ABI v1 symbols,
  payload classes, and boundary state-machine semantics.

Update protocol for future ABI changes:

1. Update `WasmAbiVersion` and/or `WASM_ABI_SIGNATURE_FINGERPRINT_V1`.
2. Record a new migration ledger entry with version + fingerprint + rationale.
3. Update `.github/wasm_abi_policy.json` expected values.
4. Ensure `scripts/check_wasm_abi_policy.py` passes with updated artifacts.

## Test Evidence

See `src/types/wasm_abi.rs` test module:

- compatibility classification
- break taxonomy -> version bump mapping
- envelope serialization round-trips
- cancellation mapping
- lifecycle transition validation
- boundary event log-field contract
- signature fingerprint drift guard
