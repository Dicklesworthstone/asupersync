# Browser And WASM Guidance

Use this only when the target actually includes browser or WASM deployment.

## Current Support Posture

The repo's browser story is explicit and fail-closed:

- direct runtime support is for the browser main thread,
- SSR / server / edge / Node-only contexts are bridge-only or unsupported for direct browser runtime execution,
- canonical browser profiles are selected by feature flags.
- `asupersync-browser-core` is the canonical browser core; `asupersync-wasm`
  may remain as excluded/non-canonical scaffold unless `Cargo.toml` says
  otherwise.
- `RuntimeBuilder::browser()` is a browser-lane API, not a blanket replacement
  for native server runtime setup.

Use this file as the lane chooser and posture summary.

For the detailed framework patterns and failure modes, read
`BROWSER-FRAMEWORKS.md`.

## Canonical Browser Profiles

The repo documents four canonical wasm browser profiles:

- `wasm-browser-minimal`
- `wasm-browser-dev`
- `wasm-browser-prod`
- `wasm-browser-deterministic`

Exactly one canonical browser profile should be selected for wasm builds.

Recommended posture:

- `minimal` for closure/contract checks
- `dev` for local diagnostics
- `prod` for production-lean browser envelope
- `deterministic` for replay-oriented validation

## Important Constraints

Direct browser runtime does **not** mean "everything from native Asupersync works in the browser."

Expect browser-path exclusions around:

- native TLS
- native database features
- Kafka
- native filesystem/process/signal/server surfaces

## Framework Guidance

Browser Edition docs define explicit boundaries for:

- browser-only modules,
- React client trees,
- Next.js client components,
- bridge-only server or edge paths.

Do not create runtime state in unsupported server or edge contexts and hope it will degrade gracefully. The repo explicitly rejects that posture.

Additional framework-specific guidance exists for:

- React task groups, retry, bulkhead isolation, and tracing hooks
- Next.js hydration/runtime phase boundaries and rebootstrap
- browser scheduler semantics and worker-offload policy
- unsupported-runtime diagnostics and evidence capture

## When To Use This Lane

Only use Browser Edition directly when:

- you actually target browser execution,
- you can keep runtime creation in supported client-side environments,
- you can respect the direct-runtime vs bridge-only boundary.

Otherwise stay on native server-side Asupersync or use an explicit bridge architecture.

## Browser Adoption Rules That Matter

- Validate profile closure before writing framework adapters.
- Get the vanilla browser path green before React or Next.
- Treat unsupported-runtime errors as useful guidance, not optional warnings.
- Keep runtime initialization inside supported client/browser boundaries.
- Capture artifacts for onboarding, replay, and policy failures instead of relying on console impressions.

## Read Next

- `BROWSER-FRAMEWORKS.md`
- `TESTING-FORENSICS.md`
- `OBSERVABILITY-FORENSICS.md`
