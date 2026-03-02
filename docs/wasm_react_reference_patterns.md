# WASM React Reference Patterns

Bead: `asupersync-umelq.10.5`

This document defines the canonical React integration patterns for the WASM
Browser Edition surface and maps each pattern to deterministic harness
scenarios in `tests/react_wasm_strictmode_harness.rs`.

Cross-framework canonical example index:
`docs/wasm_canonical_examples.md`.

## Scope

The reference catalog covers:

1. Task groups with explicit cancellation UX.
2. Bounded retry after transient failures.
3. Bulkhead isolation across independently scoped work.
4. Tracing-hook diagnostic transitions for replay/debug flows.

All scenarios must preserve the runtime invariants:

- no leaked tasks or scopes,
- cancelled losers are drained before teardown,
- cancellation is explicit and observable,
- structured logs contain stable scenario IDs and replay metadata.

## Scenario Catalog

| Scenario ID | Pattern | Intent | Deterministic Assertions |
| --- | --- | --- | --- |
| `react_ref.task_group_cancel` | task group + cancel UX | User cancel on one grouped task drains cleanly while sibling completion remains valid. | cancel count and join count stay balanced; group scope closes leak-free. |
| `react_ref.retry_after_transient_failure` | retry | Two transient failures followed by success with bounded retry attempts. | `retry_attempts=3`, `recoverable_failures=2`, final outcome is success. |
| `react_ref.bulkhead_isolation` | bulkhead | Overload cancellation in one bulkhead does not block the sibling bulkhead path. | one cancellation, sibling success, independent scope closure. |
| `react_ref.tracing_hook_transition` | tracing hook | Emit stable hook transition diagnostics for troubleshooting and replay pointers. | hook transition is legal (`active -> cleanup`) and fields are deterministic. |

## Structured Logging Contract

Each scenario emits deterministic fields with these required keys:

- `scenario_id`
- `pattern`
- `outcome`
- `retry_attempts`
- `recoverable_failures`
- `cancel_count`
- `join_count`
- `notes`

Tracing-hook entries additionally include:

- `hook_kind`
- `from_phase`
- `to_phase`
- `label`
- `handles_count`
- `detail`

## Reproduction Commands

Run the full reference-pattern harness:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo test --test react_wasm_strictmode_harness -- --nocapture
```

Run only the reference catalog deterministic test:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo test --test react_wasm_strictmode_harness reference_pattern_catalog_scenarios_are_deterministic_and_leak_free -- --nocapture
```

Run lint/format gates for touched surface:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo clippy --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo fmt --check
```
