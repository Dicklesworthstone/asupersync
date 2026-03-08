# Asupersync Browser Edition (WASM)

This document describes the WASM/browser support in Asupersync: what works
today, what the architecture looks like, what the known limitations are, and
what is planned for future phases.

## What Works Today

### JS/TS consumers via wasm-bindgen (Phase 1 -- shipped)

Asupersync ships a Browser Edition that compiles the core runtime to
`wasm32-unknown-unknown` and exposes it to JavaScript and TypeScript through
`wasm-bindgen`. This is the primary supported path.

The npm package stack:

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

## What Does Not Work Yet

### Rust-to-WASM compilation path (Phase 2 -- not yet supported)

**Using Asupersync from async Rust code that itself compiles to WASM is not
documented or tested.** This is the scenario where you write Rust code using
Asupersync's `Cx`, scopes, and combinators, then compile that Rust code to
`wasm32-unknown-unknown` for execution in the browser.

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
  loop, browser `fetch()` and `WebSocket` APIs, `IndexedDB`/`localStorage`
  for persistence.

The `asupersync-browser-core` crate is the concrete bridge: it instantiates
`WasmExportDispatcher` (the core ABI surface) and wires it to browser APIs
via `web-sys` and `wasm-bindgen-futures`.

## Browser Runtime Model

The current browser runtime model (Phase 1) is:

- **Single-threaded**: all Asupersync tasks run on the browser main thread
  (or a single Web Worker).
- **Cooperative**: the scheduler yields back to the JS event loop between
  scheduling steps to avoid blocking the UI thread.
- **Event-loop driven**: browser timer APIs, `fetch` completions, and
  WebSocket events feed into the runtime's wakeup machinery.

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
  `WebSocket`, `WebRTC`). Native TCP/UDP, Unix sockets, and raw I/O are
  unavailable.
- **No filesystem access**: `fs` module surfaces are `cfg`-gated out on
  wasm32. Use `IndexedDB` or `localStorage` through explicit capability
  boundaries.
- **No process/signal handling**: the `process` and `signal` modules are
  native-only.
- **No multi-threading by default**: the Phase 1 browser runtime is
  single-threaded. True parallelism requires Web Workers (see below).

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
