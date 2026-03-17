# Asupersync Browser Edition (WASM)

This document describes the WASM/browser support in Asupersync: what works
today, what the architecture looks like, what the known limitations are, and
what is planned for future phases.

## What Works Today

### JS/TS consumers via wasm-bindgen (Phase 1 -- shipped)

Asupersync ships a Browser Edition that compiles the core runtime to
`wasm32-unknown-unknown` and exposes it to JavaScript and TypeScript through
`wasm-bindgen`. This is the primary supported path.

The npm package stack (sources in `packages/`; not yet published to the npm
registry -- use workspace-local references for now):

| Package | Role |
|---|---|
| `@asupersync/browser-core` | Low-level wasm-bindgen bindings, compiled `.wasm` artifact, ABI types |
| `@asupersync/browser` | High-level SDK: typed handles, outcome helpers, lifecycle management |
| `@asupersync/react` | React hooks and provider for structured concurrency in React apps |
| `@asupersync/next` | Next.js App Router bootstrap adapter with server/edge boundary handling |

From JavaScript, you get:

- **Structured concurrency scopes**: `runtimeCreate()`, `scopeEnter()`, `scopeClose()`
- **Task lifecycle**: `taskSpawn()`, `taskJoin()`, `taskCancel()`
- **Cancel-correct fetch**: `fetchRequest()` with automatic `AbortController` integration
- **WebSocket management**: `websocketOpen()`, `websocketSend()`, `websocketRecv()`, `websocketClose()`
- **Capability-gated WebTransport datagrams**: `openWebTransport()`, `sendDatagram()`, `recvDatagram()`, `close()`, `cancel()` in `@asupersync/browser`, plus raw `webtransportOpen()`/`webtransportSend()` helpers in `@asupersync/browser-core`
- **Four-valued outcomes**: every operation returns `ok | err | cancelled | panicked`
- **ABI versioning**: `abiVersion()`, `abiFingerprint()` for compatibility checking

Quick example (vanilla JS):

```js
import init, { runtimeCreate, scopeEnter, taskSpawn, scopeClose, runtimeClose } from "@asupersync/browser";

await init();

const rt = runtimeCreate();
if (rt.outcome !== "ok") throw new Error(rt.failure.message);

const scope = scopeEnter({ parent: rt.value });
// ... spawn tasks, fetch, etc. ...
scopeClose(scope.value);
runtimeClose(rt.value);
```

### Core semantic guarantees preserved in browser

The browser runtime preserves all core Asupersync invariants:

1. **No orphan tasks**: structured ownership (task belongs to exactly one region)
2. **Cancel-correctness**: cancellation protocol is `request -> drain -> finalize`
3. **No obligation leaks**: two-phase commit-or-abort for all effects
4. **Region close implies quiescence**: all child tasks must complete before region closes
5. **Explicit capability boundaries**: no ambient authority to browser globals

### Build profiles

Four canonical browser profiles control the wasm compilation surface:

| Profile | Feature flag | Use case |
|---|---|---|
| Minimal | `wasm-browser-minimal` | ABI boundary checks, smallest artifact |
| Dev | `wasm-browser-dev` | Local development with browser I/O |
| Prod | `wasm-browser-prod` | Production builds with browser I/O |
| Deterministic | `wasm-browser-deterministic` | Replay-safe builds with browser trace |

Build command (example for dev profile):

```bash
rustup target add wasm32-unknown-unknown
cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-dev
```

Native-only features (`cli`, `io-uring`, `tls`, `sqlite`, `postgres`, `mysql`,
`kafka`) are compile-time rejected on `wasm32`.

## Rust-Authored Browser Contract (Current Truthful Scope)

The shipped Browser Edition product today is the JS/TS package stack. The
Rust-authored lane is narrower and should be described in terms of what the
live tree actually supports, not what is architecturally plausible later.

| Goal | Current contract | Live-tree evidence | Non-goals / caveats |
|---|---|---|---|
| Compile the semantic core under `wasm32` with one canonical browser profile | Supported today for contributors, CI, and contract validation | root `Cargo.toml` browser profile features; `src/lib.rs` compile-error gates; wasm profile commands in this doc and `docs/wasm_quickstart_migration.md` | This proves cfg/feature closure, not a public browser runtime bootstrap API |
| Maintain the wasm ABI and package boundary from Rust | Supported today inside the repository via `asupersync-browser-core` and `asupersync-wasm` | `asupersync-browser-core/Cargo.toml`, `asupersync-wasm/Cargo.toml`, `packages/browser-core/`, `packages/browser/` | These crates exist to feed the JS/TS Browser Edition surface; they are not the ergonomic public Browser Edition API for external Rust consumers |
| Build a browser app that creates Browser Edition runtimes directly from Rust consumer code | Not yet a public supported lane | `tests/wasm_browser_feasibility_matrix.rs` asserts feasibility-not-shipped; `src/runtime/builder.rs` has no public wasm/browser runtime builder path and runtime startup still routes through `spawn_worker_threads()` / `start_deadline_monitor()` with `std::thread` | Do not document direct `Cx`/`Scope` browser bootstrapping from external Rust app code as supported today |

Current rule of thumb:

- Treat `@asupersync/browser`, `@asupersync/react`, and `@asupersync/next` as
  the shipped public Browser Edition product surfaces.
- Treat `asupersync-browser-core` and `asupersync-wasm` as Rust workspace
  binding/package infrastructure, not as the promised end-user browser SDK for
  Rust consumers.
- Treat `asupersync` plus exactly one `wasm-browser-*` profile as the way to
  validate browser-safe semantic-core closure, not as a guarantee of native
  `RuntimeBuilder` parity on `wasm32`.
- Treat the remaining Rust-authored browser gap as a real runtime bootstrap
  problem, not as a naming/docs cleanup: startup still assumes `std::thread`
  worker and deadline-monitor threads.

### Practical lane selection for Rust authors

If you are touching browser-facing Rust today, choose one of these concrete
lanes and avoid blending them together:

| Need | Use | Live-tree evidence |
|---|---|---|
| Prove that the semantic core still closes under browser-safe cfg/profile rules | `rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-<profile>` against `asupersync` | root `Cargo.toml`, `src/lib.rs`, `tests/wasm_browser_feasibility_matrix.rs` |
| Maintain the Rust-side ABI/package boundary that feeds the JS/TS Browser Edition packages | `rch exec -- cargo check -p asupersync-browser-core --target wasm32-unknown-unknown --no-default-features --features dev` or `rch exec -- cargo check --manifest-path asupersync-wasm/Cargo.toml --target wasm32-unknown-unknown --no-default-features --features dev` | `asupersync-browser-core/Cargo.toml`, `asupersync-browser-core/src/lib.rs`, `asupersync-wasm/Cargo.toml`, `asupersync-wasm/src/lib.rs` |
| Validate the maintained browser-facing Rust example that the repository actually proves end-to-end | `PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh` | `tests/fixtures/rust-browser-consumer/`, `scripts/validate_rust_browser_consumer.sh`, `tests/wasm_rust_browser_example_contract.rs` |
| Build a browser app that constructs Browser Edition runtimes directly from external Rust consumer code | Not yet a public supported lane | `src/runtime/builder.rs` still has no public wasm/browser runtime constructor and runtime startup still assumes `std::thread` worker/monitor threads; use the JS/TS Browser Edition packages or an explicit bridge instead |

For the command-first version of this workflow, see
`docs/wasm_quickstart_migration.md`.

## Authoritative Support Matrix (live tree)

This section is the canonical browser-feasibility classification for the
current tree. If `README.md`, package diagnostics, or older design notes lag,
this matrix wins and follow-on beads should align the other surfaces to it.

The shipped JS/TS diagnostics expose this matrix directly:

- `packages/browser/src/index.ts` reports
  `supportClass: "direct_runtime_supported" | "unsupported"` and
  `runtimeContext: "browser_main_thread" | "dedicated_worker" | "unknown"`.
- `packages/next/src/index.ts` preserves the browser diagnostics for client
  boundaries and adds `supportClass: "bridge_only"` plus explicit bridge-only
  reasons for Next `server` and `edge` targets.

### Execution Ladder Contract

Bead `asupersync-2jhnk.6.1` makes the policy artifact authoritative:

- Canonical machine-readable source:
  `.github/wasm_worker_offload_policy.json` under `execution_ladder`
- Canonical prose source: this section
- Canonical executable guards:
  `tests/wasm_browser_feasibility_matrix.rs` and
  `tests/wasm_js_exports_coverage_contract.rs`

Stable lane identifiers:

| Lane id | Kind | Rank | Admitted host roles | Selection law |
|---|---|---:|---|---|
| `lane.browser.main_thread.direct_runtime` | `direct_runtime` | 10 | `browser_main_thread` | Use only when the current host is the browser main thread and the normal Browser Edition prerequisites are present |
| `lane.browser.dedicated_worker.direct_runtime` | `direct_runtime` | 20 | `dedicated_worker` | Use only when the current host is already a dedicated worker bootstrap |
| `lane.next.server.bridge` | `bridge_only` | 30 | `next_server` | Downgrade to serialized server bridge instead of pretending direct runtime exists |
| `lane.next.edge.bridge` | `bridge_only` | 40 | `next_edge` | Downgrade to serialized edge bridge instead of pretending direct runtime exists |
| `lane.unsupported` | `unsupported` | 99 | `service_worker`, `shared_worker`, `non_browser_or_unknown` | Terminal fail-closed lane |

Host-role classification and downgrade order:

- `browser_main_thread`:
  `lane.browser.main_thread.direct_runtime` -> `lane.unsupported`
- `dedicated_worker`:
  `lane.browser.dedicated_worker.direct_runtime` -> `lane.unsupported`
- `next_server`:
  `lane.next.server.bridge` -> `lane.unsupported`
- `next_edge`:
  `lane.next.edge.bridge` -> `lane.unsupported`
- `service_worker`:
  `lane.unsupported`
- `shared_worker`:
  `lane.unsupported`
- `non_browser_or_unknown`:
  `lane.unsupported`

The important boundary is that the ladder is host-adaptive, not magical:

- We do not silently "upgrade" a main-thread entrypoint into a dedicated worker
  lane for the caller.
- We do not silently "upgrade" service-worker or shared-worker hosts into
  direct-runtime support.
- A bridge lane is a downgrade, not partial direct-runtime parity.

Canonical reason-code schema:

- `supported`:
  `supported`
- `skip`:
  `candidate_host_role_mismatch`, `candidate_prerequisite_missing`,
  `candidate_lane_unhealthy`
- `downgrade`:
  `downgrade_to_server_bridge`, `downgrade_to_edge_bridge`,
  `downgrade_to_websocket_or_fetch`, `downgrade_to_export_bytes_for_download`
- `health`:
  `demote_due_to_lane_health`
- `policy_denial`:
  `service_worker_direct_runtime_not_shipped`,
  `shared_worker_direct_runtime_not_shipped`,
  `shared_array_buffer_requires_cross_origin_isolation`
- `unsupported`:
  `missing_global_this`, `missing_webassembly`,
  `unsupported_runtime_context`, `non_browser_runtime`

Current package diagnostics are narrower than the canonical ladder contract.
Until bead `asupersync-2jhnk.6.2` lands, treat this alias mapping as the source
of truth for cross-surface comparisons:

| Current package reason | Canonical ladder reason |
|---|---|
| `service_worker_not_yet_shipped` | `service_worker_direct_runtime_not_shipped` |
| `shared_worker_not_yet_shipped` | `shared_worker_direct_runtime_not_shipped` |
| `bridge_only_server_target` | `downgrade_to_server_bridge` |
| `bridge_only_edge_target` | `downgrade_to_edge_bridge` |

Required log/event fields for all later ladder-selection artifacts:

- `lane_id`
- `lane_kind`
- `lane_rank`
- `host_role`
- `support_class`
- `reason_code`
- `fallback_lane_id`
- `lane_health_status`
- `lane_health_failure_count`
- `lane_health_retry_budget_remaining`
- `lane_health_cooldown_until_ms`
- `lane_health_last_trigger`
- `demoted_lane_id`
- `policy_schema_version`
- `repro_command`

Lane health is part of the execution-ladder contract as well, not an
implementation detail:

- demotion behavior: `bounded_retry_then_fail_closed`
- demotion fallback lane: `lane.unsupported`
- default policy: `max_consecutive_failures=2`, `cooldown_ms=30000`
- failure triggers:
  `runtime_init_failure`, `worker_bootstrap_timeout`, `worker_crash`,
  `replay_integrity_failure`, `prerequisite_drift`,
  `overload_instability`
- manual reset trigger:
  `manual_reset`

Required repro-command convention for later e2e scripts:

```text
pnpm --filter <package> test:e2e -- --lane <lane_id> --host-role <host_role> --reason <reason_code>
```

Every persisted `repro_command` must include the tokens `--lane`,
`--host-role`, and `--reason` exactly so logs and fixtures can be compared
mechanically.

Explicit non-goals of the current ladder contract:

- `service_worker_general_runtime_without_bounded_broker_contract`
- `shared_worker_general_runtime_without_tenancy_and_lifecycle_contract`
- `ambient_message_channel_promotion`
- `shared_array_buffer_multi_worker_default_lane`
- `raw_socket_filesystem_process_parity`

This is stricter than the broad feasibility matrix on purpose. Service-worker
and shared-worker direct runtime remain architecturally plausible in the
abstract, but the shipped execution ladder must still fail closed there until
their dedicated contracts exist.

### Runtime contexts

| Context | Classification | Live-tree evidence | Notes |
|---|---|---|---|
| Browser main thread (`window` + `document` + `WebAssembly`) | Direct-runtime supported | `packages/browser/src/index.ts`, `tests/wasm_js_exports_coverage_contract.rs` | Primary shipped JS/TS Browser Edition lane |
| Dedicated Web Worker (`DedicatedWorkerGlobalScope`) | Direct-runtime supported | `packages/browser/src/index.ts`, `asupersync-browser-core/src/lib.rs`, `tests/wasm_js_exports_coverage_contract.rs` | Shipped: SDK detects `DedicatedWorkerGlobalScope`, fetch routes through `WorkerGlobalScope.fetch()`; examples and QA are catching up |
| Service worker / shared worker direct runtime | Direct-runtime feasible but not yet shipped | `packages/browser/src/index.ts` currently accepts only main-thread DOM or dedicated worker globals | Deferred until lifecycle/host constraints are productized explicitly |
| Node / SSR / edge direct runtime via `@asupersync/browser` | Impossible for direct browser runtime; bridge-only or unsupported | `packages/browser/src/index.ts`, `packages/next/src/index.ts` | Browser package fails closed; Next diagnostics classify server/edge as bridge-only targets |
| Rust-authored `wasm32-unknown-unknown` consumer path | Direct-runtime feasible but not yet shipped | semantic core is target-agnostic; `asupersync` supports canonical browser profiles and the repository ships `asupersync-browser-core` / `asupersync-wasm`, but `src/runtime/builder.rs` still exposes no public Rust-callable browser runtime builder path | Planned lane, not current public support |
| Multi-worker / `SharedArrayBuffer` parallel execution | Guarded optional, not shipped | browser model is single-threaded today; true parallelism requires cross-origin isolation | Explicitly non-default even if pursued later |

### Capability families

| Surface | Classification | Live-tree evidence | Notes |
|---|---|---|---|
| Structured scopes, task lifecycle, four-valued outcomes | Direct-runtime supported | `packages/browser/src/index.ts`, `asupersync-browser-core` ABI exports | Core shipped Browser Edition surface |
| Browser `fetch` | Direct-runtime supported | `packages/browser/src/index.ts`, `asupersync-browser-core/src/lib.rs` | Main-thread and dedicated-worker hosts are both wired |
| Browser `WebSocket` | Direct-runtime supported | `asupersync-browser-core/src/lib.rs` | Shipped public JS/TS surface |
| Browser-safe persistence via public Browser Edition APIs | Direct-runtime supported in `@asupersync/browser` | `src/io/browser_storage.rs`, `src/io/cap.rs`, `packages/browser/src/index.ts` | Public `BrowserStorage` now exposes backend selection, support detection, actionable diagnostics, and the artifact store builds on top of it rather than inventing ambient persistence |
| `IndexedDB` durable storage | Direct-runtime supported in `@asupersync/browser` on browser main thread and dedicated workers | `src/io/cap.rs`, `src/io/browser_storage.rs`, `packages/browser/src/index.ts` | Rust `IndexedDbHostBackend` host backend is complete; the public JS/TS surface adds blocked-open/quota/transaction diagnostics |
| `localStorage` host-backed storage substrate | Guarded package-level support in `@asupersync/browser` on browser main thread | `src/io/browser_storage.rs`, `packages/browser/src/index.ts` | Exposed as an explicit backend, but intentionally remains non-worker and less durable than IndexedDB |
| Browser-hosted trace / crash / evidence artifacts | Direct-runtime supported through explicit `BrowserArtifactStore` export flows | `packages/browser/src/index.ts` | Persisted artifacts are opt-in, quota-bounded, retained through explicit policy, exportable via `exportArtifact()` / `exportArchive()`, and directly downloadable only on the browser main thread |
| Browser-native transport: `WebTransport` datagrams | Guarded direct-runtime support | `src/io/cap.rs`, `packages/browser-core/index.js`, `packages/browser-core/index.d.ts`, `packages/browser/src/index.ts` | Shipped as an explicit, capability-gated datagram lane when the browser exposes `globalThis.WebTransport`; this does not imply raw-socket parity. Fall back to `WebSocket` or `fetch` when the browser/runtime lacks WebTransport support or rejects the session. |
| Browser-native messaging surfaces (`MessageChannel`, `MessagePort`, `BroadcastChannel`) | Direct-runtime feasible but not yet shipped as public Browser Edition APIs | `src/io/cap.rs`, `src/runtime/reactor/browser.rs` | The Rust/browser substrate models explicit authority for these surfaces and the reactor wires `MessagePort` / `BroadcastChannel`, but `@asupersync/browser` intentionally does not export them yet. For direct off-main-thread execution, bootstrap a Browser Edition runtime inside a dedicated worker; for same-origin app coordination, keep `MessageChannel` / `BroadcastChannel` at the application boundary; for server/edge boundaries, use bridge-only adapters. |
| Raw TCP/UDP, Unix sockets, filesystem, process/signal | Impossible for direct browser runtime | `cfg`-gated native surfaces in core/runtime/docs | Must remain bridge-only or unsupported |

### Other substrate-only capabilities (Rust layer complete, no public JS/TS API)

These items have real Rust implementations but are not yet exposed in the
`@asupersync/browser` or `@asupersync/browser-core` public packages.
Follow-on beads should decide whether to ship, defer, or remove each one.

| Surface | Rust evidence | Gap | Follow-on |
|---|---|---|---|
| WHATWG `ReadableStream`/`WritableStream` bridge | `src/io/browser_stream.rs` — maps WHATWG Streams to Asupersync `AsyncRead`/`AsyncWrite` with cancel semantics | No public JS/TS API; substrate-only | Future bead |
| Storage policy/capability layer | `src/io/cap.rs` — `StorageConsistencyPolicy`, `StorageIoCap`, `StorageBackend` enum, policy validation for namespace/size/consistency | Complete but only used internally by host backends | Part of `asupersync-3ak5y` |

### Live contradictions (2026-03-15, bead asupersync-1tte9)

These are concrete mismatches between what code, docs, and packages
currently claim. Each should be resolved by the referenced follow-on bead.

The previous browser-storage contradiction is now resolved: `@asupersync/browser`
exports `BrowserStorage`, `detectBrowserStorageSupport()`, and actionable
operation diagnostics on top of the complete Rust `IndexedDbHostBackend` and
`LocalStorageHostBackend` substrate in `src/io/browser_storage.rs`.

The browser artifact lane is now explicit as well: `BrowserArtifactStore`
persists trace/crash/evidence payloads only when callers opt in, keeps
retention policy visible in the package API, supports `exportArtifact()` and
`exportArchive()` in workers or main-thread contexts, and limits direct
download helpers to browser main-thread DOM runtimes.

1. **Dedicated worker: shipped, but onboarding/examples are still catching up.**
   The browser SDK (`packages/browser/src/index.ts`) correctly detects
   `DedicatedWorkerGlobalScope` and returns `direct_runtime_supported`.
   The browser-core fetch host routes through `WorkerGlobalScope.fetch()`.
   The remaining gap is maintained onboarding/example coverage rather than
   runtime support semantics. **Follow-on:** `asupersync-2w5tu`.

2. **Browser-native messaging surfaces are explicitly bounded, not silently
   shipped.** `src/io/cap.rs` grants explicit authority for
   `MessageChannel`, `MessagePort`, and `BroadcastChannel`, and
   `src/runtime/reactor/browser.rs` wires `register_message_port()` /
   `register_broadcast_channel()` to real host listeners. The public package
   contract is still "no direct JS/TS messaging API yet": use dedicated-worker
   runtime bootstrap for direct off-main-thread execution, keep same-origin
   `MessageChannel` / `BroadcastChannel` usage at the application boundary,
   and use bridge-only adapters when the hop leaves the browser runtime
   boundary. Future public promotion should be deliberate, not inferred.

3. **Browser stream bridge: real implementation, no public surface.**
   `src/io/browser_stream.rs` bridges WHATWG `ReadableStream`/
   `WritableStream` to Asupersync `AsyncRead`/`AsyncWrite` with cancel
   semantics, byte accounting, and state-machine lifecycle. Not exported
   in any JS/TS package. **Follow-on:** future bead.

4. **Storage policy layer: mature but still mostly internal.**
   `src/io/cap.rs` has a complete `StorageConsistencyPolicy` with
   `allowed_backends`, `max_key_len`, `max_value_len`, and
   `namespace_pattern` validation. This is used internally by the host
   backends and exposed indirectly through `BrowserStorage` diagnostics,
   but is not yet surfaced as a first-class configurable public API.
   **Follow-on:** part of `asupersync-3ak5y`.

### Contract test enforcement

The authoritative support matrix is encoded in executable contract tests:

```
tests/wasm_browser_feasibility_matrix.rs
```

These tests validate that the four-bucket classification matches the live
tree. If a contradiction is resolved (e.g. IndexedDB ships in the browser
package), the corresponding test assertion must be updated.

### Host-capability fallback rules

1. **WebTransport is optional, not ambient.**
   When `globalThis.WebTransport` is absent, the runtime is not HTTPS-backed,
   or the browser rejects the session/datagram setup, treat that as a guarded
   lane denial and fall back to `WebSocket` or `fetch`. Do not widen the
   direct-runtime support claim just because a particular browser exposes a
   partial constructor.
2. **Browser-native messaging is a substrate boundary today, not a public SDK
   lane.**
   If you need direct off-main-thread runtime execution, start the runtime
   inside a dedicated worker. If you need same-origin coordination between UI
   and worker/browser contexts, keep `MessageChannel`, `MessagePort`,
   `BroadcastChannel`, or `postMessage()` at the application boundary and pass
   serialized data into Asupersync-owned scopes/tasks. If the hop leaves the
   browser runtime boundary entirely (server, edge, Node, another process),
   use an explicit bridge-only adapter instead of pretending the browser SDK
   exports a native messaging transport.

## Maintainer Admission Rule For New Browser Surfaces

Use this rule for every future Browser Edition feature request:

1. If the browser security model makes the surface impossible as a direct
   runtime capability, classify it as **impossible** and keep it
   bridge-only or unsupported. Do not add fake parity layers for raw
   sockets, ambient filesystem/process access, or native reactor semantics.
2. If the surface is browser-feasible but depends on explicit deployment or
   runtime prerequisites, classify it as **guarded optional** and name those
   prerequisites up front. `SharedArrayBuffer` worker pools, cross-origin
   isolation, and other special-host assumptions must never be treated as the
   default Browser Edition story.
3. If the surface is browser-feasible under ordinary browser constraints and
   preserves Asupersync's invariants, it should become real product work, not
   policy-only scaffolding. Classify it as **direct-runtime supported** if it
   is already shipped, or **direct-runtime feasible but not yet shipped** if
   code substrate exists ahead of public packaging, diagnostics, docs, or
   tests.

Invariant gate for steps 2 and 3:

- Preserve structured concurrency and explicit region ownership.
- Preserve cancellation as `request -> drain -> finalize`, including loser
  drain semantics.
- Preserve explicit capability boundaries; browser support must not smuggle
  in ambient authority.
- Preserve fail-closed diagnostics when a surface is outside the supported
  direct-runtime boundary.

## What Does Not Work Yet

### Rust-to-WASM compilation path (feasible, but not yet a public lane)

**Truthful current rule:** external Rust consumers do not yet have a public,
supported Browser Edition runtime-construction API. The browser product lane is
currently the JS/TS package stack, while the Rust-facing wasm story is limited
to semantic-core profile validation plus repository binding crates.

This matters because "the semantic core is portable" is weaker than "you can
ship a browser app that constructs Asupersync runtimes directly from Rust
consumer code." Today the repository supports the former, not the latter.

What Rust authors can rely on today:

- `asupersync` can be compiled for `wasm32-unknown-unknown` with exactly one
  canonical browser profile (`wasm-browser-minimal`, `wasm-browser-dev`,
  `wasm-browser-prod`, or `wasm-browser-deterministic`) to validate cfg/feature
  closure and browser-safe semantic-core surfaces.
- `asupersync-browser-core` and `asupersync-wasm` provide the Rust-side
  binding/export crates that generate and maintain the Browser Edition ABI and
  package artifacts consumed by `@asupersync/browser` and friends.
- The live support matrix and contract tests treat the Rust-authored browser
  lane as feasible-but-not-shipped, which keeps docs and tests aligned.

What Rust authors cannot rely on yet:

- a public `RuntimeBuilder` or equivalent Rust-callable API that bootstraps a
  browser executor directly from external Rust app code,
- a stable ergonomic Rust browser SDK parallel to `@asupersync/browser`,
- native-runtime parity on `wasm32`, including raw OS/network/process surfaces
  or ambient browser runtime discovery.

The core semantic layer (structured scopes, cancellation state machine,
obligation accounting, combinators) is architecturally target-agnostic and
should be portable. However:

- The runtime scheduler and I/O reactor have native-specific code paths
  (`epoll`, `io_uring`, `polling`, `socket2`, `signal-hook`) that are
  `cfg`-gated for `not(target_arch = "wasm32")`.
- A browser-specific scheduler pump (driven by `queueMicrotask` /
  `MessageChannel` / `setTimeout`) exists in the design but is not yet
  exposed as a Rust-callable API.
- There is no public `RuntimeBuilder` path that produces a wasm32-compatible
  runtime from Rust consumer code.

If and when a public Rust-authored browser lane ships, it should start from
explicit browser-safe capability constructors and the same support matrix used
for JS/TS consumers. It should not be framed as "native Asupersync, but in the
browser now" or as an ambient-global parity story.

This path is on the roadmap but not prioritized. If you need it, please
comment on [issue #11](https://github.com/Dicklesworthstone/asupersync/issues/11).

## Architectural Boundary

The cleanest way to think about the WASM story:

```
+-----------------------------------------------+
|          Shared Semantic Core                  |
|  (scopes, cancellation, combinators,           |
|   obligation accounting, trace, types)         |
+-----------------------------------------------+
         |                          |
         v                          v
+------------------+    +--------------------+
| Native Executor  |    | Browser Executor   |
| (epoll/io_uring, |    | (event-loop pump,  |
|  threads, OS I/O)|    |  Web APIs, fetch,  |
|                  |    |  WebSocket)        |
+------------------+    +--------------------+
```

The semantic core is the same code compiled to both targets. The executor
layer is environment-specific:

- **Native**: multi-threaded work-stealing scheduler, OS-level I/O reactor,
  real TCP/UDP sockets, filesystem, process/signal handling.
- **Browser**: single-threaded cooperative scheduler driven by the JS event
  loop, browser `fetch()`, `WebSocket`, and capability-gated `WebTransport`
  APIs, and browser-safe host integration points for storage and transport
  expansion.

The `asupersync-browser-core` crate is the concrete bridge: it instantiates
`WasmExportDispatcher` (the core ABI surface) and wires it to browser APIs
via `web-sys` and `wasm-bindgen-futures`.

## Browser Runtime Model

The current browser runtime model (Phase 1) is:

- **Single-threaded**: all Asupersync tasks run on the browser main thread
  or inside a single dedicated Web Worker.
- **Cooperative**: the scheduler yields back to the JS event loop between
  scheduling steps to avoid blocking the UI thread.
- **Event-loop driven**: browser timer APIs, `fetch` completions,
  WebSocket events, and WebTransport session/stream events feed into the
  runtime's wakeup machinery.

### What this means for guarantees

| Guarantee | Native | Browser | Notes |
|---|---|---|---|
| No orphan tasks | Full | Full | Structured scopes enforce ownership |
| Cancel-correctness | Full | Full | Three-phase protocol is target-agnostic |
| Bounded cleanup | Full | Cooperative | Depends on cooperative yielding; no preemption |
| Deterministic scheduling | Full (lab mode) | Partial | Browser event loop introduces nondeterminism unless strictly serialized |
| CPU parallelism | Full (work-stealing) | None (single-threaded) | See "Future: threaded WASM" below |

## Known Limitations and Constraints

### Browser environment constraints

- **No raw TCP/UDP**: networking is limited to browser APIs (`fetch`,
  `WebSocket`, and capability-gated `WebTransport` datagrams). Native
  TCP/UDP, Unix sockets, and raw I/O are unavailable.
- **No filesystem access**: `fs` module surfaces are `cfg`-gated out on
  wasm32. Browser-safe persistence is exposed through `BrowserStorage` in
  `@asupersync/browser`: `IndexedDB` is the durable default backed by the
  complete Rust `IndexedDbHostBackend`, while `localStorage` remains an
  explicit main-thread-only backend for smaller, less durable data. Runtime
  artifacts ride on top of that surface through `BrowserArtifactStore`, which
  keeps persistence opt-in and export-oriented rather than silently durable.
  Neither backend implies ambient filesystem semantics.
- **No process/signal handling**: the `process` and `signal` modules are
  native-only.
- **No multi-threading by default**: the Phase 1 browser runtime is
  single-threaded. Supported direct-runtime lanes are the browser main thread
  and a single dedicated Web Worker; service-worker/shared-worker lanes remain
  deferred. True parallelism requires additional workers plus the Phase 2
  model below.

### Cross-origin isolation for SharedArrayBuffer

Multi-threaded WASM (using `SharedArrayBuffer` + Atomics) requires
cross-origin isolation headers:

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

This is a significant deployment constraint: many web applications cannot
enable these headers due to third-party embed requirements. Phase 1
intentionally avoids this dependency.

### Artifact size budgets

Browser Edition artifacts are size-budgeted:

| Profile | Raw `.wasm` budget | Gzip budget |
|---|---|---|
| `core-min` | 650 KiB | 220 KiB |
| `core-trace` | 900 KiB | 320 KiB |
| `full-dev` | 1300 KiB | 480 KiB |

### BrowserArtifactStore defaults

Persisted browser runtime artifacts are bounded separately from `.wasm` size:

| Policy field | Default | Meaning |
|---|---|---|
| `maxArtifacts` | `32` | Maximum retained artifact records in the store |
| `maxArtifactBytes` | `512 KiB` | Largest single persisted trace/crash/evidence payload |
| `maxTotalBytes` | `4 MiB` | Total retained bytes before eviction/failure |
| `quotaStrategy` | `evict_oldest` | Oldest retained artifacts are evicted first unless callers choose `fail` |

Operational rules:

- `BrowserArtifactStore` is explicit. Nothing is persisted unless application
  or tooling code calls `persistTraceRecord()`, `persistCrashArtifact()`, or
  `persistEvidenceArtifact()`.
- `exportArtifact()` and `exportArchive()` work in main-thread and
  dedicated-worker runtimes because they return bytes/Blob-oriented payloads.
- `downloadArtifact()` and `downloadArchive()` are intentionally limited to
  browser main-thread DOM runtimes with `document` and `URL.createObjectURL()`.

## Future: Threaded WASM Executor (Phase 2)

A future phase may add a multi-threaded WASM executor using:

- `SharedArrayBuffer` + Atomics for shared memory between workers
- A native-style scheduler inside WASM (potentially in a `SharedWorker`)
- Work-stealing across Web Worker threads

This would enable closer parity with native scheduling semantics but requires:

1. Cross-origin isolation (see above)
2. Careful message-passing design (Workers don't share JS state)
3. A different cancellation propagation model across worker boundaries

This is explicitly Phase 2 and will only be pursued if demand materializes.
The single-threaded, event-loop-driven model provides the core structured
concurrency guarantees that matter most.

## Crate Map

| Crate | Purpose | Browser role |
|---|---|---|
| `asupersync` | Core runtime library | Compiles to wasm32 with browser feature profiles |
| `asupersync-browser-core` | wasm-bindgen export boundary | Bridges core runtime to JS via ABI symbol table |
| `asupersync-wasm` | Alternative WASM binding surface (scaffold) | Placeholder for future binding strategies |
| `asupersync-tokio-compat` | Tokio bridge adapters | Native-only; not applicable to browser |

## Further Reading

- [`PLAN_TO_BUILD_ASUPERSYNC_IN_WASM_FOR_USE_IN_BROWSERS.md`](../PLAN_TO_BUILD_ASUPERSYNC_IN_WASM_FOR_USE_IN_BROWSERS.md) -- full execution blueprint
- [`docs/wasm_quickstart_migration.md`](./wasm_quickstart_migration.md) -- onboarding commands and profile selection
- [`docs/wasm_canonical_examples.md`](./wasm_canonical_examples.md) -- vanilla/React/Next.js example catalog
- [`docs/wasm_browser_scheduler_semantics.md`](./wasm_browser_scheduler_semantics.md) -- scheduler/event-loop contract
- [`docs/wasm_platform_trait_seams.md`](./wasm_platform_trait_seams.md) -- seam contracts between semantic core and backends
- [`docs/wasm_troubleshooting_compendium.md`](./wasm_troubleshooting_compendium.md) -- failure recipes and diagnostics
- [Issue #11](https://github.com/Dicklesworthstone/asupersync/issues/11) -- WASM support discussion and architectural questions
