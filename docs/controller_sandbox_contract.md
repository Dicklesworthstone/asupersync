# Controller Sandbox Membrane Contract

Bead: `asupersync-1508v.7.5`

## Purpose

This contract defines the sandbox membrane for controller execution: capability-closed action surface, resource caps, temporal bounds, deterministic output, and adversarial validation ensuring controllers cannot escape their granted authority.

## Contract Artifacts

1. Canonical artifact: `artifacts/controller_sandbox_membrane_v1.json`
2. Smoke runner: `scripts/run_controller_sandbox_smoke.sh`
3. Invariant suite: `tests/controller_sandbox_contract.rs`

## Membrane Invariants

| Invariant | Description |
|-----------|------------|
| MEM-CAP-CLOSED | Only granted capabilities may be exercised |
| MEM-RESOURCE-CAPPED | Memory, CPU, decision count are capped per execution |
| MEM-TEMPORAL-BOUNDED | Wall-clock deadline enforced |
| MEM-OUTPUT-DETERMINISTIC | Same input produces same output |
| MEM-NO-SIDE-EFFECTS | No direct runtime mutation; effects via decisions only |
| MEM-VERDICT-REQUIRED | Every execution produces a logged verdict |

## Resource Caps

| Cap | Unit | Default | Enforcement |
|-----|------|---------|-------------|
| RC-MEMORY | bytes | 1 MiB | abort with verdict |
| RC-CPU-TIME | microseconds | 100,000 | timeout verdict |
| RC-DECISIONS-PER-EPOCH | count | 10 | drop excess |
| RC-OUTPUT-SIZE | bytes | 64 KiB | truncate with verdict |

## Action Surface

| Action | Required Capability |
|--------|-------------------|
| ACT-READ-SNAPSHOT | CAP-OBSERVE |
| ACT-EMIT-DECISION | CAP-DECIDE |
| ACT-REQUEST-PROMOTION | CAP-PROMOTE |
| ACT-REQUEST-ROLLBACK | CAP-ROLLBACK |
| ACT-REGISTER-CONTROLLER | CAP-ADMIN |
| ACT-READ-EVIDENCE | CAP-OBSERVE |

## Verdict Types

| Verdict | Meaning |
|---------|---------|
| VRD-ALLOW | Success, decision accepted |
| VRD-DENY-CAPABILITY | Attempted unauthorized action |
| VRD-DENY-RESOURCE | Resource cap exceeded |
| VRD-TIMEOUT | Wall-clock deadline exceeded |
| VRD-ERROR | Controller error (panic, invalid output) |
| VRD-BUDGET-EXHAUSTED | Per-epoch decision budget spent |

## Adversarial Scenarios

| Scenario | Expected Verdict |
|----------|-----------------|
| ADV-CAP-ESCALATION | VRD-DENY-CAPABILITY |
| ADV-RESOURCE-BOMB | VRD-DENY-RESOURCE / VRD-TIMEOUT |
| ADV-STATE-MUTATION | VRD-DENY-CAPABILITY |
| ADV-DECISION-FLOOD | VRD-BUDGET-EXHAUSTED |
| ADV-OUTPUT-OVERFLOW | VRD-DENY-RESOURCE |

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa072 cargo test --test controller_sandbox_contract -- --nocapture
```

## Cross-References

- `artifacts/controller_sandbox_membrane_v1.json`
- `artifacts/capability_token_model_v1.json` -- CAP-* hierarchy
- `src/runtime/kernel.rs` -- ControllerRegistry, ControllerBudget
- `docs/capability_token_model_contract.md` -- Token model AA-07.1
