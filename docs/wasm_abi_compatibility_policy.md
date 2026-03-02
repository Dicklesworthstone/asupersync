# WASM ABI Compatibility Policy (WASM-8.5)

**Bead**: `asupersync-umelq.8.5`
**Parent**: WASM-08 ABI Contract and Boundary Stability
**Date**: 2026-03-02
**Author**: SapphireHill

---

## 1. Purpose

This document defines the compatibility policy, upgrade lifecycle, and rollback criteria for the Asupersync WASM ABI boundary. It complements the ABI contract (`docs/wasm_abi_contract.md`) with operational rules for producers (runtime builds) and consumers (JS/TS adapters, framework integrations).

---

## 2. Versioning Model

### 2.1 Semver Rules

The ABI uses `major.minor` semver (`WasmAbiVersion`):

| Bump | Trigger | Consumer Impact |
|------|---------|----------------|
| Minor | Additive field, additive symbol, behavioral relaxation | None — consumers at same major are backward compatible |
| Major | Symbol removal/rename, wire encoding change, behavioral tightening, outcome/cancellation semantic reinterpretation | Consumers MUST upgrade; old consumers are rejected |

The normative mapping is `required_wasm_abi_bump(WasmAbiChangeClass) -> WasmAbiVersionBump`.

### 2.2 Change Classes

From `WasmAbiChangeClass`:

| Class | Bump | Example |
|-------|------|---------|
| `AdditiveField` | Minor | New optional field in `SpawnRequestV1` |
| `AdditiveSymbol` | Minor | New `task_poll` symbol |
| `BehavioralRelaxation` | Minor | Accepting wider input range on existing symbol |
| `BehavioralTightening` | Major | Rejecting previously accepted input |
| `SymbolRemoval` | Major | Removing `fetch_request` |
| `ValueEncodingChange` | Major | Changing outcome envelope wire layout |
| `OutcomeSemanticChange` | Major | Reinterpreting `cancelled` as `err` |
| `CancellationSemanticChange` | Major | Changing propagation mode defaults |

### 2.3 Compatibility Classification

`classify_wasm_abi_compatibility(producer, consumer)` returns:

| Decision | Condition | Action |
|----------|-----------|--------|
| `Exact` | Same major + same minor | Proceed |
| `BackwardCompatible` | Same major + consumer minor > producer minor | Proceed (consumer understands superset) |
| `ConsumerTooOld` | Same major + consumer minor < producer minor | Reject — consumer lacks required features |
| `MajorMismatch` | Different major | Reject — incompatible wire contract |

---

## 3. Signature Fingerprint Drift Detection

### 3.1 Mechanism

`wasm_abi_signature_fingerprint(WASM_ABI_SIGNATURES_V1)` computes a deterministic hash over the canonical symbol table. The guard constant `WASM_ABI_SIGNATURE_FINGERPRINT_V1` catches accidental drift.

### 3.2 CI Gate

- Policy file: `.github/wasm_abi_policy.json`
- Gate script: `scripts/check_wasm_abi_policy.py`
- Failure mode: if the computed fingerprint does not match `WASM_ABI_SIGNATURE_FINGERPRINT_V1`, the gate fails with an explicit message requiring:
  1. Version bump decision (minor or major per change class).
  2. Migration note in the ledger.
  3. Fingerprint constant update.

### 3.3 Canary Checks

The compatibility harness (`tests/wasm_abi_compatibility_harness.rs`) validates:

1. **Fingerprint stability**: recomputed fingerprint matches guard constant.
2. **Symbol count stability**: `WASM_ABI_SIGNATURES_V1.len()` matches expected count.
3. **Symbol ordering**: symbol names in canonical order match expected sequence.
4. **Payload shape stability**: each symbol's request/response shapes match expected values.

---

## 4. Boundary State Machine Compatibility

### 4.1 Legal Transitions

The boundary state machine (`WasmBoundaryState`) defines legal transitions:

```
Unbound → Bound → Active → Cancelling → Draining → Closed
                    ↓         ↓            ↓
                   Closed    Closed       Closed
              Bound→Closed
```

Identity transitions are always legal (idempotent re-entry).

### 4.2 Compatibility Invariants

1. **No new terminal states**: `Closed` is the sole terminal state. Adding terminal states is a major-bump change.
2. **No removing transitions**: removing a legal transition is behavioral tightening (major bump).
3. **Adding transitions**: adding a new legal transition is behavioral relaxation (minor bump).
4. **State ordering**: the `Unbound < Bound < Active < Cancelling < Draining < Closed` ordering is monotonic for normal lifecycle progression.

### 4.3 Harness Coverage

The compatibility harness exhaustively validates:
- All legal transitions are accepted by `validate_wasm_boundary_transition`.
- All illegal transitions are rejected.
- Identity transitions are accepted for every state.

---

## 5. Handle Table Compatibility

### 5.1 Handle Lifecycle

`WasmHandleTable` uses slot-based allocation with generation counters:

1. **Allocate**: assigns slot + generation → `WasmHandleRef`.
2. **Get/GetMut**: validates slot bounds + generation match.
3. **Release**: marks slot free, bumps generation (preventing use-after-free).

### 5.2 Compatibility Rules

1. **Generation monotonicity**: generation counters only increase (wrapping at `u32::MAX`).
2. **Stale handle rejection**: released handles fail with `StaleHandle` error.
3. **Slot reuse**: freed slots are recycled; generation bump distinguishes old from new occupants.
4. **Capacity growth**: table grows on demand; no pre-allocation requirement for consumers.

---

## 6. Cancellation / AbortSignal Interop Compatibility

### 6.1 Propagation Modes

`WasmAbortPropagationMode` defines three modes:
- `RuntimeToAbortSignal`: runtime cancel → JS abort; JS abort does not propagate back.
- `AbortSignalToRuntime`: JS abort → runtime cancel; runtime cancel does not propagate to JS.
- `Bidirectional`: both directions enabled.

### 6.2 Compatibility Rules

1. **Mode is producer-configured**: consumers accept the mode set by the runtime.
2. **Abort is monotonic**: `abort_signal_aborted` only transitions `false → true`, never back.
3. **Idempotence**: repeated abort events produce identical outcomes (no duplicate propagation).
4. **Phase mapping stability**: `CancelPhase → WasmBoundaryState` mapping is fixed:
   - `Requested|Cancelling → Cancelling`
   - `Finalizing → Draining`
   - `Completed → Closed`

---

## 7. React and Next.js Integration Compatibility

### 7.1 React Provider Lifecycle

Provider states follow the boundary state machine. Compatibility rules:
- Provider creation maps to `Unbound → Bound`.
- Provider mounting maps to `Bound → Active`.
- Provider unmounting maps to `Active → Closed` (or cancel path if tasks are in-flight).

### 7.2 Next.js Bootstrap Phases

`NextjsBootstrapPhase` state machine:
```
ServerRendered → Hydrating → Hydrated → RuntimeReady
                                       → RuntimeFailed
```

Compatibility rules:
- Identity transitions are always legal (idempotent re-entry).
- `RuntimeReady → Hydrating` is legal (Fast Refresh).
- `RuntimeFailed → Hydrating` is legal (Retry / Fast Refresh).
- Navigation type determines runtime survival:
  - `SoftNavigation`: runtime survives.
  - `HardNavigation`: runtime destroyed; bootstrap restarts from `ServerRendered`.
  - `PopState`: runtime survives.

### 7.3 Suspense and Error Boundary Mapping

Outcome-to-UI-state mapping is fixed:

| Outcome | Suspense State | Error Boundary | Transition State |
|---------|---------------|----------------|------------------|
| `Ok` | `Resolved` | `None` | `Committed` |
| `Err(Transient)` | `ErrorRecoverable` | `ShowWithRetry` | `Reverted` |
| `Err(Permanent)` | `ErrorFatal` | `ShowFatal` | `Reverted` |
| `Cancelled` | `Cancelled` | `None` | `Cancelled` |
| `Panicked` | `ErrorFatal` | `ShowFatal` | `Reverted` |

---

## 8. Upgrade Lifecycle

### 8.1 Minor Upgrade (Backward Compatible)

1. Producer bumps `WASM_ABI_MINOR_VERSION`.
2. Update `WASM_ABI_SIGNATURE_FINGERPRINT_V1` if signatures changed.
3. Add migration note to ledger in `docs/wasm_abi_contract.md`.
4. Existing consumers continue working without changes.
5. New consumers can use new features by checking minor version.

### 8.2 Major Upgrade (Breaking)

1. Producer bumps `WASM_ABI_MAJOR_VERSION`, resets minor to 0.
2. Update `WASM_ABI_SIGNATURE_FINGERPRINT_V1`.
3. Add migration note with upgrade instructions.
4. Update `.github/wasm_abi_policy.json`.
5. All consumers MUST upgrade to new major version.
6. Previous major version supported for one release cycle (deprecation window).

### 8.3 Deprecation Window

When a major bump occurs:
- Previous major version MUST remain functional for at least one release cycle.
- `ConsumerTooOld` and `MajorMismatch` rejections include diagnostic messages with migration pointers.
- CI gate script emits deprecation warnings for consumers on the old major version.

---

## 9. Rollback Safety

### 9.1 Criteria

A release is rollback-safe when:
1. No major version bump (consumers on previous minor still work).
2. Fingerprint change is additive-only (no symbol removal or reinterpretation).
3. Boundary state machine transitions are a superset of the previous version.
4. Handle table generation semantics are unchanged.
5. Cancellation/abort interop modes are unchanged.

### 9.2 Rollback Procedure

1. Revert `WASM_ABI_MINOR_VERSION` (or `MAJOR`).
2. Revert `WASM_ABI_SIGNATURE_FINGERPRINT_V1`.
3. Revert `.github/wasm_abi_policy.json`.
4. Run full compatibility harness to validate no regressions.
5. Add rollback note to migration ledger.

---

## 10. CI and Harness Integration

### 10.1 Automated Gates

| Gate | Script/Test | Frequency |
|------|------------|-----------|
| Fingerprint drift | `tests/wasm_abi_compatibility_harness.rs` | Every PR |
| Version-bump policy | `scripts/check_wasm_abi_policy.py` | Every PR |
| Boundary state exhaustive | `tests/wasm_abi_compatibility_harness.rs` | Every PR |
| Handle lifecycle | `tests/wasm_abi_compatibility_harness.rs` | Every PR |
| Cancel/abort interop | `tests/wasm_abi_compatibility_harness.rs` | Every PR |
| Outcome mapping | `tests/wasm_abi_compatibility_harness.rs` | Every PR |

### 10.2 Evidence Artifacts

- `artifacts/wasm_abi_contract_summary.json` — version, fingerprint, symbol count.
- `artifacts/wasm_abi_contract_events.ndjson` — boundary event log.
- Compatibility harness test output — deterministic, replayable.

### 10.3 Reproduction

```bash
# Run compatibility harness
cargo test --test wasm_abi_compatibility_harness -- --nocapture

# Run existing contract tests
cargo test --test wasm_abi_contract -- --nocapture

# Run CI policy gate
python3 scripts/check_wasm_abi_policy.py --policy .github/wasm_abi_policy.json
```

---

## 11. Cross-References

- ABI contract: `docs/wasm_abi_contract.md`
- Cancel/abort interop: `docs/wasm_cancellation_abortsignal_contract.md`
- Implementation: `src/types/wasm_abi.rs`
- Existing contract tests: `tests/wasm_abi_contract.rs`
- Compatibility harness: `tests/wasm_abi_compatibility_harness.rs`
- CI policy: `.github/wasm_abi_policy.json`
- CI gate: `scripts/check_wasm_abi_policy.py`
