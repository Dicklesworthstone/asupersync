# Validation Frontier Inventory

<!-- validation-frontier-inventory-v1 -->

This document summarizes `artifacts/validation_frontier_inventory_v1.json`.
The checked contract is `tests/validation_frontier_inventory_contract.rs`.

The inventory exists because a focused channel proof lane can currently cross a
much broader Cargo graph than the requested surface. On 2026-06-10, the
`channel-mpsc-select-e2e` cfg(test) compile and filtered test attempts reached
`Checking asupersync-conformance v0.3.4` and then went RCH progress-stale with
fresh hook heartbeats. That is infrastructure/frontier evidence, not a Rust
diagnostic for the channel code.

## Rules

- Every lane in `artifacts/proof_lane_manifest_v1.json` must have one inventory
  row.
- Common AGENTS.md validation commands are inventoried even when they overlap
  manifest rows, because agents still copy those commands directly.
- Focused observed lanes must declare `dev_dependency_edges` and
  `conformance_expected`; `unknown_needs_vf2` is acceptable only as an explicit
  handoff to `asupersync-validation-frontier-v2-b5cjsv.2`.
- `compile_only` or `focused_compile` evidence cannot be cited as test execution
  proof.
- RCH stale-progress evidence must not be cited as code failure evidence unless
  a Rust diagnostic was emitted.

## Key Rows

| Lane | Source | Boundary | Conformance expectation | Current RCH behavior |
| --- | --- | --- | --- | --- |
| `default-production-tokio-tree` | manifest | production normal dependency graph | `not_expected` | mapped, not rerun in VF1 |
| `lib-tests` | manifest | broad lib test frontier | `not_expected` | mapped, not rerun in VF1 |
| `all-targets-check` | manifest | broad compile frontier | `unknown_needs_vf2` | mapped, not rerun in VF1 |
| `agents-test-all-test-internals` | AGENTS.md | broad workspace/default-package test frontier | `expected` | unknown until VF2 |
| `channel-mpsc-select-e2e-lib-check` | observed | focused lib compile | `not_expected` | green build `29880940465487991` |
| `channel-mpsc-select-e2e-lib-tests-check` | observed | focused cfg(test) compile attempt | `unknown_needs_vf2` | stale build `29880940465487999` |
| `channel-mpsc-select-e2e-filtered-run` | observed | focused filtered test execution | `unknown_needs_vf2` | stale build `29880940465487994` |
| `mpsc-recv-many-wake-cascade-exact-run` | observed | focused exact lib-test execution | `unknown_needs_vf2` | stale build `29880940465487998` |

## VF2 Handoff

`unknown_needs_vf2` means the current repository state does not yet prove the
boundary. VF2 must decide whether the broad graph edge is intentional. If the
edge is not intentional, VF2 should split or quarantine targets so focused proof
lanes finish without compiling unrelated conformance/dev-test surfaces.

## Operator Guidance

When a focused lane stalls:

1. Record the lane id, command, build id, worker id, last compiler line, and
   cancellation outcome.
2. Compare the last compiler line against this inventory.
3. If the lane reached an unexpected graph tail, file or update a validation
   frontier blocker instead of treating the touched code as failed.
4. Use broad frontier lanes for broad claims only; pair them with focused lanes
   before claiming a narrow change is validated.
