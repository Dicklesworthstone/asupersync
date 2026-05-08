# WASM DX Diagnostics, Error Taxonomy, and IntelliSense Quality (WASM-9.5)

**Bead**: `asupersync-umelq.9.5`
**Parent**: WASM-08 TypeScript SDK, Packaging, and DX Guarantees
**Date**: 2026-03-02
**Author**: SapphireHill

---

## 1. Purpose

This document defines the developer-experience (DX) error taxonomy, diagnostic enrichment surface, and IntelliSense quality contract for the Asupersync WASM Browser Edition boundary. It bridges the internal error infrastructure (`WasmAbiErrorCode`, `WasmAbiFailure`, `WasmAbiRecoverability`) to actionable developer-facing diagnostics with recovery hints, structured messages, and IDE-compatible metadata.

---

## 2. Error Taxonomy

### 2.1 Error Code Classification

The `WasmAbiErrorCode` enum classifies all boundary errors into five programmatic categories:

| Error Code | Category | Description | Developer Impact |
|-----------|----------|-------------|-----------------|
| `CapabilityDenied` | Authorization | Operation requires a capability not held by the caller | Check capability grants; review boundary mode |
| `InvalidHandle` | Lifecycle | Handle reference is stale, released, or out of bounds | Handle was used after release or transfer; check ownership |
| `DecodeFailure` | Protocol | Request/response payload could not be decoded | Version mismatch or malformed input; check ABI version |
| `CompatibilityRejected` | Version | Producer-consumer ABI version negotiation failed | Upgrade consumer package to match runtime ABI version |
| `InternalFailure` | Runtime | Unexpected internal error (should not occur in normal operation) | File a bug report with boundary event log |

### 2.2 Recoverability Classification

The `WasmAbiRecoverability` enum provides retry guidance:

| Recoverability | Action | Developer Guidance |
|---------------|--------|-------------------|
| `Transient` | Retry with backoff | Network hiccup, temporary resource exhaustion; safe to retry |
| `Permanent` | Do not retry | Capability denied, handle released, version mismatch; fix the root cause |
| `Unknown` | Retry cautiously | Internal error; retry once, then escalate |

### 2.3 Handle Error Taxonomy

The `WasmHandleError` enum provides detailed handle lifecycle violations:

| Error Variant | Trigger | Recovery Hint |
|--------------|---------|--------------|
| `SlotOutOfRange` | Handle slot exceeds table capacity | Handle was not allocated from this runtime; check origin |
| `StaleGeneration` | Generation counter mismatch on slot | Handle was released and slot reused; do not cache handles across releases |
| `AlreadyReleased` | Operation on a released handle | Handle was already freed; remove stale references |
| `InvalidTransfer` | Transfer from non-`WasmOwned` state | Handle was already transferred to JS or released; check ownership chain |
| `NotPinned` | Unpin called on non-pinned handle | Handle was never pinned; review pin/unpin pairing |
| `ReleasePinned` | Release called on pinned handle | Unpin the handle before releasing; pinned handles prevent release |

### 2.4 Dispatch Error Taxonomy

The `WasmDispatchError` enum classifies boundary-level failures before runtime execution:

| Error Variant | Trigger | Error Code Mapping | Recovery Hint |
|--------------|---------|-------------------|--------------|
| `Incompatible` | ABI version negotiation failed | `CompatibilityRejected` (Permanent) | Upgrade `@asupersync/*` packages to match runtime |
| `Handle` | Handle lifecycle violation | `InvalidHandle` (Permanent) | See handle error taxonomy above |
| `InvalidState` | Operation in wrong boundary state | `InvalidHandle` (Permanent) | Check boundary lifecycle; operation not valid in current state |
| `InvalidRequest` | Malformed request payload | `DecodeFailure` (Permanent) | Validate request structure against ABI symbol signatures |

---

## 3. Outcome-to-Developer-Action Mapping

### 3.1 Outcome Envelope

The four-valued `WasmAbiOutcomeEnvelope` maps to developer actions:

| Outcome | Developer Action | React Suspense State | Error Boundary Action | Transition State |
|---------|-----------------|---------------------|----------------------|-----------------|
| `Ok` | Process result | `Resolved` | `None` | `Committed` |
| `Err(Transient)` | Retry with backoff | `ErrorRecoverable` | `ShowWithRetry` | `Reverted` |
| `Err(Permanent)` | Show error; do not retry | `ErrorFatal` | `ShowFatal` | `Reverted` |
| `Cancelled` | Clean up; no error shown | `Cancelled` | `None` | `Cancelled` |
| `Panicked` | Show fatal error; report bug | `ErrorFatal` | `ShowFatal` | `Reverted` |

### 3.2 Recovery Decision Tree

```
outcome received
├── Ok → commit result to UI
├── Err
│   ├── Transient → retry (respect budget) → if exhausted, escalate to Permanent
│   ├── Permanent → show error boundary; log failure for diagnosis
│   └── Unknown → retry once → if still failing, treat as Permanent
├── Cancelled → clean up resources; no user-visible error
└── Panicked → show fatal boundary; include repro command in diagnostics
```

---

## 4. Diagnostic Enrichment Contract

### 4.1 Structured Log Fields

All boundary events emit deterministic log fields via `WasmAbiBoundaryEvent::as_log_fields()`:

| Field | Type | Purpose |
|-------|------|---------|
| `abi_version` | `string` | Runtime ABI version (`major.minor`) |
| `symbol` | `string` | Operation being dispatched |
| `payload_shape` | `string` | Request/response shape identifier |
| `state_from` | `string` | Boundary state before operation |
| `state_to` | `string` | Boundary state after operation |
| `compatibility` | `string` | Classification result |
| `compatibility_decision` | `string` | Pass/fail decision |
| `compatibility_producer_major` | `string` | Producer ABI major version |
| `compatibility_consumer_major` | `string` | Consumer ABI major version |
| `compatibility_producer_minor` | `string` | Producer ABI minor version |
| `compatibility_consumer_minor` | `string` | Consumer ABI minor version |
| `compatibility_compatible` | `string` | Boolean compatibility flag |

### 4.2 Suspense Diagnostic Events

`SuspenseDiagnosticEvent` provides React-specific diagnostics:

| Field | Type | Purpose |
|-------|------|---------|
| `label` | `string` | Human-readable event description |
| `from_state` | `SuspenseBoundaryState` | Previous Suspense state |
| `to_state` | `SuspenseBoundaryState` | New Suspense state |
| `is_transition` | `bool` | Whether this is a `startTransition` context |
| `error_action` | `ErrorBoundaryAction` | Error boundary response |
| `task_handle` | `Option<WasmHandleRef>` | Associated task handle (if any) |

### 4.3 Boundary Event Log

`WasmBoundaryEventLog` collects boundary events for post-hoc analysis and replay. Events are stored in order and can be serialized to NDJSON for artifact retention.

---

## 5. Developer Error Message Catalog

### 5.1 Initialization Errors

| Scenario | Error Code | Message Template | Recovery |
|----------|-----------|-----------------|----------|
| WASM module load failure | `InternalFailure` | "Failed to load WASM module: {reason}" | Check bundler configuration; ensure `.wasm` file is accessible |
| ABI version mismatch | `CompatibilityRejected` | "ABI version mismatch: runtime {producer} vs consumer {consumer}" | Upgrade `@asupersync/*` packages |
| Missing capability | `CapabilityDenied` | "Operation requires capability '{cap}' not granted to this boundary" | Add required capability to runtime configuration |
| Wrong boundary state | `InvalidHandle` | "Cannot {operation} in state '{state}'; expected '{expected}'" | Follow boundary lifecycle: Unbound → Bound → Active |

### 5.2 Handle Lifecycle Errors

| Scenario | Error Code | Message Template | Recovery |
|----------|-----------|-----------------|----------|
| Use after release | `InvalidHandle` | "Handle slot {slot} was released (generation {expected} vs {actual})" | Remove cached handle reference; re-allocate if needed |
| Double release | `InvalidHandle` | "Handle slot {slot} already released" | Guard against duplicate release calls |
| Transfer from wrong state | `InvalidHandle` | "Cannot transfer handle in state '{current}'; must be WasmOwned" | Check ownership before transfer |
| Release pinned handle | `InvalidHandle` | "Handle slot {slot} is pinned; call unpin() before release()" | Unpin first, then release |

### 5.3 Cancellation/Abort Errors

| Scenario | Error Code | Message Template | Recovery |
|----------|-----------|-----------------|----------|
| Cancelled operation | (not error) | "Operation cancelled via {source}" | Clean up; no retry needed |
| Abort signal propagation | (not error) | "AbortSignal triggered cancellation in mode '{mode}'" | Check abort controller lifecycle |
| Cancel in wrong phase | `InvalidHandle` | "Cancel phase '{phase}' not valid for state '{state}'" | Wait for appropriate lifecycle phase |

### 5.4 Feature Mismatch Errors

| Scenario | Error Code | Message Template | Recovery |
|----------|-----------|-----------------|----------|
| WASM in server boundary | `CapabilityDenied` | "WASM runtime execution not supported in '{env}'; use server bridge" | Move WASM usage to client-hydrated boundary |
| Missing bundler plugin | `DecodeFailure` | "WASM module requires async loading; configure bundler WASM support" | See bundler compatibility matrix for configuration |
| Profile not available | `CompatibilityRejected` | "Feature profile '{profile}' not available in this build" | Check build profile; use appropriate feature flags |

---

## 6. IntelliSense Quality Contract

### 6.1 Type Surface Requirements

All public types exposed through `@asupersync/browser-core` and `@asupersync/browser` must provide:

1. **JSDoc/TSDoc annotations** on every exported symbol with:
   - One-line summary
   - `@example` usage snippet for functions/methods
   - `@throws` documentation for error-returning functions
   - `@see` cross-references to related types

2. **Discriminated union exhaustiveness**: `WasmAbiOutcomeEnvelope` and `WasmAbiErrorCode` must use TypeScript discriminated unions so `switch/case` produces exhaustiveness warnings.

3. **Const enum serialization**: `WasmAbiErrorCode`, `WasmAbiRecoverability`, `WasmHandleKind`, `WasmBoundaryState` must serialize to human-readable snake_case strings, not numeric indices.

### 6.2 Autocomplete Priorities

Type definitions must be ordered for IDE autocomplete priority:

1. **Primary API** (most common operations): `Outcome`, `Budget`, `CancellationToken`, `RegionHandle`
2. **Error types**: `WasmAbiErrorCode`, `WasmAbiFailure`, `WasmAbiRecoverability`
3. **Lifecycle types**: `WasmBoundaryState`, `WasmHandleKind`, `WasmHandleOwnership`
4. **Diagnostic types**: `SuspenseBoundaryState`, `ErrorBoundaryAction`, `TransitionTaskState`
5. **Internal/advanced**: `WasmAbiSymbol`, `WasmAbiPayloadShape`, `WasmAbiChangeClass`

### 6.3 Error Type Narrowing

TypeScript consumers must be able to narrow error types progressively:

```typescript
// Level 1: Outcome discrimination
if (outcome.outcome === "err") {
  // outcome.failure is WasmAbiFailure

  // Level 2: Recoverability check
  if (outcome.failure.recoverability === "transient") {
    // Safe to retry
  }

  // Level 3: Error code specificity
  if (outcome.failure.code === "capability_denied") {
    // Specific recovery path
  }
}
```

### 6.4 Diagnostic Field Completeness

Every error path must emit sufficient context for remote diagnosis:

1. **Error code** (programmatic, machine-parseable)
2. **Recoverability** (retry guidance)
3. **Human message** (developer-readable context)
4. **Boundary state** (lifecycle position when error occurred)
5. **ABI version** (producer/consumer versions)
6. **Repro command** (deterministic reproduction pointer)

---

## 7. Boundary Violation Diagnostics

### 7.1 Next.js Boundary Violations

When WASM operations are attempted in wrong render environments:

| Render Environment | Violation | Diagnostic Message |
|-------------------|-----------|-------------------|
| `server_component` | Runtime execution | "WASM runtime not available in Server Components; use `@asupersync/next` server bridge" |
| `node_server` | Runtime execution | "WASM runtime not available in Node server context; use server bridge" |
| `edge_runtime` | Runtime execution | "WASM runtime not available in Edge Runtime; use edge bridge" |
| `client_ssr` | Runtime init | "WASM runtime deferred during SSR; will initialize after hydration" |

### 7.2 React Strict Mode Diagnostics

In React Strict Mode (development), double-invocation produces:

| Event | Diagnostic | Severity |
|-------|-----------|----------|
| Double mount | "Expected: Strict Mode remount detected; runtime survives" | Info |
| Effect cleanup | "Boundary draining via cleanup; handles will be re-acquired" | Debug |
| Double render | "Suspense boundary re-rendered; outcome is idempotent" | Debug |

---

## 8. CI Validation

### 8.1 Automated Gates

| Gate | Test File | Checks |
|------|----------|--------|
| Error taxonomy completeness | `tests/wasm_dx_error_taxonomy.rs` | All error codes, recoverability levels, handle errors documented |
| Outcome mapping exhaustiveness | `tests/wasm_abi_contract.rs` | All outcome variants map to UI states |
| Diagnostic field determinism | `tests/wasm_abi_contract.rs` | Boundary event log fields are ordered and complete |
| Error-to-dispatch mapping | `tests/wasm_dx_error_taxonomy.rs` | All dispatch errors map to failures with correct codes |
| Document cross-references | `tests/wasm_dx_error_taxonomy.rs` | Error taxonomy doc references all required types |

### 8.2 Reproduction

```bash
# Run error taxonomy validation
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_dx_docs cargo test --test wasm_dx_error_taxonomy -- --nocapture

# Run existing contract tests (outcome/error mapping)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_dx_docs cargo test --test wasm_abi_contract -- --nocapture

# Run compatibility harness (error lifecycle)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_dx_docs cargo test --test wasm_abi_compatibility_harness -- --nocapture
```

---

## 9. Cross-References

- ABI contract: `docs/wasm_abi_contract.md`
- ABI compatibility policy: `docs/wasm_abi_compatibility_policy.md`
- TypeScript type model: `docs/wasm_typescript_type_model_contract.md`
- Package topology: `docs/wasm_typescript_package_topology.md`
- Bundler compatibility: `docs/wasm_bundler_compatibility_matrix.md`
- Cancellation/abort interop: `docs/wasm_cancellation_abortsignal_contract.md`
- Implementation: `src/types/wasm_abi.rs`
- Error taxonomy tests: `tests/wasm_dx_error_taxonomy.rs`
- ABI contract tests: `tests/wasm_abi_contract.rs`
