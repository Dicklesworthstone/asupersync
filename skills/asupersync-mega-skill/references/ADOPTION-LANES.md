# Adoption Lanes

Use this file to choose the right integration strategy before editing code.

## Lane 1: Native Greenfield

Choose this when:

- you are starting a new Rust service, library, daemon, or CLI,
- you control most async boundaries,
- you want structured concurrency, deterministic testing, and explicit capability threading from day one.

Default moves:

- bootstrap with `RuntimeBuilder`,
- design async APIs around `&Cx`,
- use `Scope` / child regions for owned work,
- use `LabRuntime` and `run_test_with_cx` for tests,
- choose native Asupersync web/grpc/net/db/messaging surfaces instead of Tokio-ecosystem crates.

Exit criteria:

- no Tokio dependency in core code,
- no hidden ambient runtime assumptions,
- cancellation and shutdown are explicit in code and tests.

## Lane 2: Brownfield Native Migration

Choose this when:

- the project already uses Tokio heavily,
- you can change function signatures,
- you want to move to full native Asupersync rather than sit on a compat layer forever.

Default moves:

- run the read-only planner first: `python3 scripts/migration_readiness_planner.py --project-root <proj> --output-root <out>` (see `docs/integration.md`),
- replace runtime bootstrap first,
- inventory every `tokio::*` and Tokio-ecosystem dependency,
- thread `&Cx` through code you control,
- replace `tokio::spawn` with region-owned work,
- migrate primitives domain by domain,
- add deterministic tests as each slice lands.

Exit criteria:

- Tokio is removed from core modules,
- migrated domains use native Asupersync surfaces,
- any remaining Tokio-only crate is isolated behind a dedicated adapter boundary,
- `cargo tree -e normal -i tokio` on core crates prints `warning: nothing to print.` (no-Tokio production graph).

## Lane 3: Boundary Interop

Choose this when:

- a dependency still requires `tokio::runtime::Handle`, `tokio::io`, hyper runtime traits, or similar,
- replacing that crate immediately would cost too much,
- you need an incremental migration path.

Default moves:

- use `asupersync-tokio-compat`,
- keep the bridge in one adapter module or crate,
- pass `Cx` explicitly into the boundary,
- prefer strict cancellation modes,
- never let Tokio become the primary runtime for the app.

Exit criteria:

- the dependency is either removed or fully caged behind one small interop layer,
- business logic no longer knows about Tokio,
- the compat surface has an explicit removal plan.

## Wrong Choices

Pick a different lane if you catch yourself doing any of these:

- "I will keep all current APIs and only swap the executor."
- "I will let Tokio and Asupersync both spawn freely in core code."
- "I will use compat everywhere because it is easier."
- "I will postpone deterministic tests until after the migration."

If you need native guarantees, your architecture has to move, not just the dependency graph.
