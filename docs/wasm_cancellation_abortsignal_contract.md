# WASM Cancellation <-> AbortSignal Contract

This document defines deterministic interoperability between Asupersync
cancellation protocol phases and browser `AbortSignal` semantics.

## Scope

- Boundary: JS/TS adapter <-> WASM runtime ABI.
- Runtime invariant: cancellation remains `requested -> cancelling -> finalizing -> completed`.
- Browser invariant: `AbortSignal.aborted` is monotonic and idempotent.

## Propagation Modes

`WasmAbortPropagationMode`:

- `runtime_to_abort_signal`: runtime cancellation can mark JS abort; JS abort does not request runtime cancel.
- `abort_signal_to_runtime`: JS abort can request runtime cancellation; runtime cancellation does not mark JS abort.
- `bidirectional`: both directions are enabled.

## State Mapping

Runtime phase to boundary state intent (`wasm_boundary_state_for_cancel_phase`):

- `requested` or `cancelling` -> `cancelling`
- `finalizing` -> `draining`
- `completed` -> `closed`

Transition application is monotonic and only applied when legal under boundary
state transition rules.

## JS Abort Event Rules

`apply_abort_signal_event(snapshot)`:

- Always returns `abort_signal_aborted=true`.
- Propagates to runtime only when:
  - mode allows JS->runtime propagation,
  - signal was not already aborted, and
  - boundary state is `bound` or `active`.
- For propagated events:
  - `active -> cancelling`
  - `bound -> closed`
- Repeated abort events are idempotent (no duplicate runtime propagation).

## Runtime Phase Event Rules

`apply_runtime_cancel_phase_event(snapshot, phase)`:

- Applies phase->boundary mapping when transition is legal.
- Marks JS abort only when mode allows runtime->JS propagation.
- `propagated_to_abort_signal` is emitted only on first transition that flips
  abort to `true`.
- Already-aborted signals remain aborted without duplicate propagation events.

## Determinism & Reproducibility

- Interop helpers are pure data transforms (no ambient side effects).
- Outputs are fully determined by `(mode, boundary_state, abort_signal_aborted, phase/event)`.
- Unit + contract tests assert:
  - already-aborted behavior,
  - double-abort idempotence,
  - finalize/completed progression.
