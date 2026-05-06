# Failure Domain Compiler Contract

Bead: `asupersync-1508v.9.5`

## Purpose

This contract defines failure-domain compilation, restart topology hooks, and recovery authority rules: how supervised regions are grouped into restart-independent domains, how restarts propagate, and how capability tokens are narrowed and restored during recovery.

## Contract Artifacts

1. Canonical artifact: `artifacts/failure_domain_compiler_v1.json`
2. Smoke runner: `scripts/run_failure_domain_smoke.sh`
3. Invariant suite: `tests/failure_domain_contract.rs`

## Failure Domain Model

| Domain Type | Propagation | Description |
|-------------|------------|-------------|
| FD-ISOLATED | none | Independent restart, no sibling impact |
| FD-LINKED | group | All members restart together |
| FD-ESCALATING | parent | Escalates to parent after budget exhaustion |

### Domain Properties

- **FDP-BOUNDARY-EXPLICIT**: Boundaries declared at region creation
- **FDP-UNIQUE-MEMBERSHIP**: Every region belongs to exactly one domain
- **FDP-HIERARCHY-ACYCLIC**: Domain parent-child forms a DAG
- **FDP-INSPECTABLE**: Domain membership queryable at runtime

## Restart Topology

| Topology | Domain Type | Description |
|----------|------------|-------------|
| RT-ONE-FOR-ONE | FD-ISOLATED | Only failed region restarts |
| RT-ONE-FOR-ALL | FD-LINKED | All group members restart |
| RT-REST-FOR-ONE | FD-LINKED | Failed region + later regions restart |
| RT-ESCALATE-TO-PARENT | FD-ESCALATING | Escalate after budget exhaustion |

### Hooks

| Hook | Phase | Purpose |
|------|-------|---------|
| RH-PRE-RESTART | pre | Checkpoint, fence I/O, narrow authority |
| RH-POST-RESTART | post | Validate, re-register obligations, widen authority |
| RH-ESCALATION | escalation | Notify parent domain |
| RH-TOMBSTONE | terminal | Final cleanup |

## Recovery Authority Rules

- **RA-NARROW-ON-CRASH**: Revoke non-OBSERVE capabilities on crash
- **RA-GRADUAL-RESTORE**: Restore capabilities incrementally after recovery
- **RA-REVOKE-ON-BUDGET-EXHAUST**: Permanent revocation after budget exhaustion
- **RA-PARENT-INHERITS-REVOCATION**: Parent inherits child revocation set
- **RA-AUDIT-ALL-TRANSITIONS**: Log every authority change during recovery
- **RA-NO-AMBIENT-DURING-RECOVERY**: No ambient authority during recovery

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_failure_domain cargo test -p asupersync --test failure_domain_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/failure_domain_compiler_v1.json`
- `artifacts/crash_only_region_semantics_v1.json` -- Crash state machine
- `artifacts/capability_token_model_v1.json` -- CAP-* hierarchy
- `src/supervision.rs` -- SupervisionStrategy
- `src/runtime/kernel.rs` -- ControllerRegistry, RollbackReason
