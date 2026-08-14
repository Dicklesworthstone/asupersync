# Brownfield Migration To Native Asupersync

This is the default migration path when you want full replacement, not permanent coexistence.

## Order Of Work

1. Run the read-only migration readiness planner against the project, then inventory runtime entrypoints, spawns, select/race logic, timers, channels, networking, web stack, database stack, tests, and any Tokio-locked third-party crates.
2. Replace the runtime bootstrap.
3. Introduce `&Cx` into the APIs you control.
4. Replace detached/background task patterns with region-owned work.
5. Migrate primitives by domain.
6. Add deterministic tests for each migrated slice.
7. Isolate any unavoidable holdouts behind compat.
8. Remove compat as the final step.

## Run The Readiness Planner First

The repo ships a read-only planner that turns a brownfield tree into an
inventory, proof-pack, semantic map, and six-phase operator plan:

```bash
python3 scripts/migration_readiness_planner.py --list
python3 scripts/migration_readiness_planner.py --dry-run --scenario tokio-http-service
python3 scripts/migration_readiness_planner.py --project-root /path/to/rust/project --output-root target/migration-readiness
```

Read `summary.final_verdict` (`ready`, `needs_quarantine`, or `blocked`),
`semantic_map.recommendations`, `operator_report.phase_plan`, and
`operator_report.residual_risk_rows` before editing code. The planner never mutates
the scanned project. See `docs/integration.md` (Tokio Migration Playbook) and
`docs/migration_recipe_compiler.md` for turning findings into a checklist.

## Replace Bootstrap First

Typical transformations:

- `#[tokio::main]` -> explicit `RuntimeBuilder` + `block_on`
- `#[tokio::test]` -> `#[test]` + `run_test(...)` or `run_test_with_cx(...)`
- implicit runtime handles -> explicit `RuntimeHandle` or `Cx`-scoped spawn paths

## Thread `&Cx` Early

Do not wait until the end.

Refactor your own async APIs like this:

```rust
// before
async fn fetch_user(id: UserId) -> Result<User, Error>

// after
async fn fetch_user(cx: &Cx, id: UserId) -> Result<User, Error>
```

Benefits:

- cancellation becomes explicit,
- time/budget/randomness/tracing stop being ambient,
- testing becomes deterministic and easier to wire.

## Replace Task Ownership Semantics

Look for:

- `tokio::spawn`
- `JoinHandle` used as detached background work
- handler-local tasks with unclear cleanup
- `select!` branches that abandon losing futures

Preferred outcomes:

- tasks become region-owned,
- handler/request work is scoped,
- losers are cancelled and drained where semantics require it,
- shutdown flows close to quiescence instead of "best effort."

## Migrate By Domain

Do not migrate randomly. Use slices:

- sync and channels
- time and retries
- io and networking
- web/grpc
- database/messaging
- fs/process/signal
- advanced protocol surfaces

The detailed mapping is in `TOKIO-MAPPING.md`.

## Compat During Migration

Use compat only when one of these is true:

- the dependency still demands a Tokio handle,
- it requires Tokio I/O traits or hyper runtime traits,
- removing it would force a much larger redesign than the current task allows.

Rules:

- keep compat in a dedicated boundary module,
- pass `Cx` into the boundary,
- never let Tokio leak back into business logic,
- plan the boundary's removal.

## Brownfield Checklist

- runtime bootstrap replaced,
- `&Cx` threaded through owned code,
- Tokio spawns removed from handlers/services/core,
- native primitives adopted by domain,
- deterministic tests added,
- holdouts isolated,
- remaining partial/unsupported surfaces explicitly documented,
- `cargo tree -e normal -i tokio` on your core crates confirms Tokio has left the production graph (compat stays an opt-in satellite).
