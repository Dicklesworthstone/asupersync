# WASM Next.js Template and Deployment Cookbook

Bead: `asupersync-umelq.11.5`

This cookbook defines the canonical Next.js App Router integration template for
Asupersync Browser Edition and provides deterministic replay commands for the
reference harness in `tests/nextjs_bootstrap_harness.rs`.

Cross-framework canonical example index:
`docs/wasm_canonical_examples.md`.

## Goals

1. Preserve hydration/runtime boundary semantics (`ServerRendered -> Hydrating -> Hydrated -> RuntimeReady`).
2. Keep runtime invalidation/re-init behavior deterministic across route, cache, and hot-reload events.
3. Provide deployment guidance with explicit failure signatures and repro commands.

## Maintained Example Source

The maintained Next App Router example source lives in:

- `tests/fixtures/next-turbopack-consumer`
- validation harness: `scripts/validate_next_turbopack_consumer.sh`

It makes the boundary visible in code:

- `app/client-runtime-panel.jsx` owns the direct client runtime path
- `app/api/server-bridge/route.js` stays on the serialized node/server bridge path
- `app/api/edge-bridge/route.js` keeps edge code on explicit diagnostics/bridge-only behavior

## Reference Scenarios

| Scenario ID | Focus | Invariant Checks |
| --- | --- | --- |
| `next_ref.template_deploy` | end-to-end template lifecycle | deterministic phase/environment/log-event replay |
| `next_ref.cache_revalidation_reinit` | cache invalidation at runtime-ready | runtime scope invalidated, re-init required, no hidden failure |
| `next_ref.hard_navigation_rebootstrap` | App Router hard navigation boundary | runtime scope reset, SSR boundary restored, bootstrap restarts cleanly |
| `next_ref.cancel_retry_runtime_init` | cancellation + recovery path | explicit failure record, retry recovery, runtime returns to ready |

## Structured Logging Contract

Each bootstrap event must include deterministic fields:

- `action`
- `from_phase`
- `to_phase`
- `from_environment`
- `to_environment`
- `route_segment`
- `recovery_action`

Template overlays must add:

- `scenario_id`
- `deployment_target`

## Deployment Targets

### Target A: Vercel Node Runtime

- Use client components for WASM runtime boundaries.
- Keep runtime init inside hydration-safe effects.
- Treat hard navigation/cache revalidation as explicit runtime scope invalidations.

### Target B: Node Self-Hosted App Router

- Same bootstrap contract as Vercel Node.
- Preserve structured log fields for replay in CI and staging incident capture.

### Target C: Edge + Client Split

- Edge path must not directly initialize runtime during server/edge phases.
- Runtime activation remains a client-hydrated concern.

## Reproduction Commands

Run full Next.js bootstrap harness:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq115 cargo test --test nextjs_bootstrap_harness -- --nocapture
```

Run only the template determinism scenario:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq115 cargo test --test nextjs_bootstrap_harness nextjs_reference_template_deployment_flow_is_deterministic -- --nocapture
```

Run quality gates:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq115 cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq115 cargo clippy --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq115 cargo fmt --check
```

## Failure Signatures and Recovery

1. `RuntimeUnavailable` in `ServerRendered`/`ClientSsr`
   - Trigger: runtime init attempted before hydration completion.
   - Recovery: continue hydration to `Hydrated`, then initialize runtime.
2. Bootstrap cancelled during deployment path
   - Trigger: explicit cancel signal from route/user action.
   - Recovery: `RetryRuntimeInit` recovery action, then runtime re-init.
3. Cache/hard-navigation scope invalidation drift
   - Trigger: missing invalidation accounting fields.
   - Recovery: rerun harness and verify `scope_invalidation_count` and `runtime_reinit_required_count`.
