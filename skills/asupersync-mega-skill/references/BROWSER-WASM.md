# Browser And WASM Guidance

Use this only when the target actually includes browser or WASM deployment.

## Current Support Posture

The repo's browser story is explicit and fail-closed:

- JS/TS packages (`@asupersync/browser` and friends, workspace version 0.4.4)
  are GA for browser main-thread **and dedicated-worker** consumers; the
  scoped GA signoff is `artifacts/browser_ga_final_signoff_v1.json`
  (`pass_scoped_js_ts_ga`). Packages are still workspace-local, not yet
  published to the npm registry.
- service workers and shared workers are broker/coordinator-only: direct
  `BrowserRuntime` creation fail-closes there; use the bounded broker
  registration / coordinator attach APIs instead,
- SSR / server / edge / Node-only contexts are bridge-only or unsupported for direct browser runtime execution,
- canonical browser profiles are selected by feature flags.
- `asupersync-browser-core` is the canonical browser core; `asupersync-wasm`
  is a retained non-canonical scaffold.
- `RuntimeBuilder::browser()` is a **preview** public Rust lane:
  dispatcher-backed, narrower than the JS/TS packages, fail-closed on
  unsupported hosts with an inspectable execution ladder
  (`RuntimeBuilder::inspect_browser_execution_ladder()`; key fields
  `selected_lane`, `host_role`, `reason_code`, `preferred_lane`,
  `downgrade_order`). Not a stable external Rust Browser Edition API.

The readiness matrix (`artifacts/browser_edition_readiness_matrix_v1.json`,
human table `docs/browser_edition_readiness_matrix.md`) binds six support
classes to fixture evidence: Direct-runtime supported, Package ABI boundary,
Preview public lane, Broker/coordinator-only, Bridge-only, and
Impossible / unsupported.

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

- `minimal` for closure/ABI-contract checks (smallest artifact)
- `dev` for local diagnostics (browser I/O enabled)
- `prod` for production-lean browser envelope (browser I/O enabled)
- `deterministic` for replay-oriented validation (deterministic mode + browser trace)

Closure check (do not blend profiles):

```bash
cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-dev
```

## Important Constraints

Direct browser runtime does **not** mean "everything from native Asupersync works in the browser."

Expect browser-path exclusions around:

- native TLS
- native database features
- Kafka
- native filesystem/process/signal/server surfaces
- raw TCP/UDP and Unix sockets (browser networking is `fetch`, `WebSocket`,
  and capability-gated `WebTransport` datagrams)

Browser-native application-boundary helpers exist but are capability-gated:
`MessageChannel` / `MessagePort` / `BroadcastChannel` helpers and WHATWG
`ReadableStream` / `WritableStream` byte wrappers in `@asupersync/browser`
require explicit `BrowserNativeMessagingCapability` /
`BrowserNativeStreamCapability` authority, deny `capability_not_granted` and
`degraded_mode_denied`, and report stable `ASUPERSYNC_BROWSER_NATIVE_*` error
codes. They are guarded same-browser wrappers, not raw transport parity.

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

- you actually target browser execution (main thread or dedicated worker),
- you can keep runtime creation in supported client-side environments,
- you can respect the direct-runtime vs broker/coordinator-only vs bridge-only
  boundaries.

Otherwise stay on native server-side Asupersync or use an explicit bridge architecture.

For Rust-authored browser work, the authoritative evidence path is the
maintained fixture at `tests/fixtures/rust-browser-consumer/` plus
`scripts/validate_rust_browser_consumer.sh`; the preview
`RuntimeBuilder::browser()` lane layers on top of that, it does not replace it.
Full guide: `docs/WASM.md`; command-first workflow:
`docs/wasm_quickstart_migration.md`.

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
