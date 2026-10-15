# Migration Recipe Compiler

<!-- MIGRATION-RECIPE-COMPILER:SOURCE -->

`artifacts/migration_recipe_compiler_v1.json` is the checked source of truth for
`asupersync-idea-wizard-fifth-wave-3gaiun.13`.

The compiler contract turns migration readiness planner findings into
self-contained implementation checklists. It does not rewrite code. It is a
read-only bridge between planner output, existing migration cookbooks, proof
lanes, and manual implementation work.

## Inputs

The contract is built around the read-only planner described in
`docs/integration.md` and implemented by `scripts/migration_readiness_planner.py`.
Planner scenarios such as `tokio-http-service`, `mixed-compat-boundary`, and
`blocked-ambient-authority-service` become recipe fixtures. Each fixture maps to
a checklist mode:

| planner scenario | recipe mode | expected use |
|---|---|---|
| `native-clean` | confirm native boundary | prove the core crate remains tokio-free |
| `tokio-http-service` | quarantine and recipe | split owned web/grpc work from compat edges |
| `mixed-compat-boundary` | compat boundary review | keep hard Tokio dependencies at named edges |
| `feature-gated-tokio-edge` | feature graph proof | separate default, metrics, fuzz, and workspace graph claims |
| `blocked-ambient-authority-service` | manual design review | thread `Cx` and explicit capabilities before migration |
| `malformed-workspace` | fail closed | repair manifest readability before any migration claim |

<!-- MIGRATION-RECIPE-COMPILER:SCHEMA -->

## Recipe Schema

Every compiled recipe carries the same required fields:

| field | purpose |
|---|---|
| `recipe_id` | stable recipe identifier |
| `planner_findings` | planner findings that triggered the recipe |
| `source_concepts` | normalized Tokio, hyper, tonic, axum, tower, or reqwest concepts |
| `asupersync_modules` | native modules or compat boundaries to inspect |
| `pattern_changes` | manual code patterns to change |
| `proof_lanes` | RCH-routed proof commands to run |
| `compat_boundary_policy` | when a compat adapter remains acceptable |
| `generated_checklist` | ordered implementation checklist |
| `no_destructive_edits` | must be `true` |
| `no_auto_codemod` | must be `true` |
| `no_claims` | explicit boundaries for what the recipe does not prove |

The concept catalog covers:

- `tokio_spawn`, `tokio_select`, `tokio_mpsc`, and `tokio_time`
- `tokio_io_traits` and `tokio_fs_process_signal`
- `hyper_server_client`, `tonic_transport`, `axum_router`, `tower_layers`, and
  `reqwest_client`

Each concept maps to native Asupersync modules, existing migration docs, or the
`asupersync-tokio-compat` edge when a dependency is hard-wired to Tokio-shaped
traits.

<!-- MIGRATION-RECIPE-COMPILER:CHECKLIST -->

## Generated Checklist Policy

A compiled checklist is implementation guidance for agents, not an execution
engine. It must:

1. classify planner findings before editing
2. name the owning Asupersync module or compat boundary
3. require explicit `Cx` and region ownership for owned concurrency work
4. keep unsupported or deferred host behavior as skip, blocked, or no-claim rows
5. run proof lanes through `rch`
6. record unresolved findings as owner beads instead of claiming completion

Example output shapes are included in the artifact for native structured
concurrency, web/gRPC compat boundaries, and I/O plus fs/process/signal work.

## Validation

Use the focused remote-only contract lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_migration_recipe_compiler_contract" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test migration_recipe_compiler_contract --no-default-features -- --nocapture
```

Local Cargo fallback is not evidence for this contract.

<!-- MIGRATION-RECIPE-COMPILER:NO-DESTRUCTIVE-EDITS -->

## No Destructive Edits

The recipe compiler is not a codemod and not an auto-porting tool. Recipes may
tell an agent what to inspect and change manually. They must not rewrite source
files, create branches, create worktrees, delete files, or claim automated
migration success.

Forbidden command families include `git reset --hard`, `git clean -fd`,
`rm -rf`, `git worktree add`, and non-main `git branch` flows.

<!-- MIGRATION-RECIPE-COMPILER:NO-CLAIMS -->

## No-Claim Boundaries

This contract does not prove broad workspace health, release readiness, runtime
correctness, performance, live RCH fleet availability, or that an external
project has been migrated. It only proves that the recipe schema, fixture
coverage, checklist policy, docs links, and destructive-edit boundaries are
present and internally consistent.
