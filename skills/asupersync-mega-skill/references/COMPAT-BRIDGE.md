# Compat Bridge

## What It Is

`asupersync-tokio-compat` is a separate workspace crate for running
Tokio-locked dependencies inside an Asupersync-centered application.

Important boundary rules from the repo docs:

- the main `asupersync` crate must remain Tokio-free
- the compat layer lives in its own crate
- `Cx` still crosses adapter boundaries explicitly
- region ownership and cancellation still matter

## Feature Gates

| Feature | Purpose | Entry points |
|---------|---------|--------------|
| `hyper-bridge` | hyper v1 runtime traits, body bridge | `hyper_bridge::{AsupersyncExecutor, AsupersyncTimer}`, `body_bridge` |
| `tokio-io` | Tokio `AsyncRead`/`AsyncWrite` trait adapters (bidirectional) | `io::TokioIo<T>`, `io::AsupersyncIo<T>` |
| `tower-bridge` | Tower service adapters | `tower_bridge::FromTower<S>`, `tower_bridge::IntoTower<S>` |
| `full` | all of the above | all of the above |

Always available (no feature): `runtime::with_tokio_context`, `blocking`,
`cancel`, `AdapterConfig` / `CancellationMode`.

## When To Use It

Use compat when all of these are true:

1. A needed dependency is genuinely Tokio-locked.
2. Native replacement this cycle would blow the scope.
3. You can keep the boundary narrow and explicit.
4. You have a removal plan.

## Good Uses

- Keep reqwest temporarily while migrating toward native HTTP clients.
- Run axum or tonic workloads through a bounded bridge while replacing vertical slices.
- Keep SQLx-adjacent pieces during a staged database migration.

## Bad Uses

- "We want Asupersync branding but no real migration."
- Running separate uncoordinated Tokio and Asupersync thread pools.
- Mixing `tokio::spawn` and region-owned Asupersync work without a single owner model.

## Documented Failure Modes

| Failure | Symptom | Mitigation |
|---------|---------|------------|
| Cross-runtime deadlock | blocked calls between runtimes | single bridge executor; never create ambiguous ownership |
| Timer drift | timeout mismatch across boundary | unify time source and test deterministically |
| Cancel ignored by wrapped future | work runs after parent cancel | use cancel-aware wrappers and explicit tests |
| Background task escapes region | leak or hidden liveness | keep adapter activity region-owned |

## Best-Practice Policy

Prefer this order:

1. native surface
2. explicit compat bridge
3. removal of compat once the blocker is gone

## Source Truth

- `/data/projects/asupersync/asupersync-tokio-compat/Cargo.toml`
- `/data/projects/asupersync/asupersync-tokio-compat/src/lib.rs`
- `/data/projects/asupersync/docs/integration.md` (Tokio Migration Playbook section)
- `/data/projects/asupersync/docs/tokio_adapter_boundary_architecture.md`
- `/data/projects/asupersync/docs/tokio_interop_support_matrix.md`
- `/data/projects/asupersync/docs/tokio_migration_cookbooks.md`
- `/data/projects/asupersync/docs/migration_recipe_compiler.md`
- `/data/projects/asupersync/scripts/migration_readiness_planner.py`

