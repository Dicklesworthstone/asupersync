# Rust → WASM with Asupersync: the `RuntimeBuilder::browser()` lane

> **DRAFT — pending maintainer review.** The Rust-authored browser lane is a
> **preview public** surface. This document is a code-grounded first draft written
> for issue [#51](https://github.com/Dicklesworthstone/asupersync/issues/51)
> (follow-up to #27). Every claim below is traced to the source as of this
> writing, but the maintainer is the authority on intended scope — please correct
> or refine anything that overstates support. For the broad Browser Edition
> overview (JS/TS packages, architecture, phases) see [`WASM.md`](./WASM.md);
> this doc is narrowly about the **Rust consumer** path.

## TL;DR

- `RuntimeBuilder::browser()` returns a separate `BrowserRuntimeBuilder` that
  negotiates a **browser execution lane** and, when the host supports it,
  constructs a **dispatcher-backed `BrowserRuntime`** over the WASM ABI.
- It is **preview** and **fail-closed**: on any non-browser host (including all
  native builds) it does not construct a runtime — it returns structured
  diagnostics instead.
- Supported **direct-runtime** lanes today: **browser main thread** and
  **dedicated worker**. Service workers and shared workers are *not* shipped as
  direct-runtime lanes.
- The browser lane is **single-threaded, event-loop driven**. There is no native
  TCP/UDP/QUIC, no filesystem, no OS threads/signals. Network I/O is via browser
  primitives (`fetch`, `WebSocket`), exposed through the ABI export surface, not
  the native `net`/`fs` APIs.

Source of truth: `src/runtime/builder.rs` (builder, lanes, probe, selection),
`asupersync-browser-core/` (the canonical wasm-bindgen export crate), root
`Cargo.toml` (features and wasm32 dependency table), `src/runtime/reactor/browser.rs`
(reactor), `src/time/driver.rs` (clock), `src/net/**` (the unsupported stubs).

## Target

The build target is **`wasm32-unknown-unknown`**. The root `Cargo.toml` keeps a
dedicated wasm32 dependency table:

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.4", features = ["wasm_js"] }   # JS-backed entropy
js-sys = "0.3"
wasm-bindgen = "0.2"
wasm-bindgen-futures = "0.4"
web-sys = { version = "0.3", features = [ /* BroadcastChannel, IndexedDB, MessageChannel/Port, Storage, ReadableStream/WritableStream, ... */ ] }
```

and excludes the native I/O / socket / signal / native-crypto crates from
`wasm32` builds:

```toml
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
polling = "3.11"
socket2 = "0.6"
libc = "0.2"
nix = "0.31"
signal-hook = "0.4"
aes-gcm = "0.10.3"
chacha20poly1305 = "0.10.1"
```

This is why native TCP/UDP/QUIC, filesystem, OS signals, and native AEAD crypto
are simply absent on the browser target.

## Features

`asupersync` exposes four **canonical browser profiles**. Enable **exactly one**
when compiling for the browser:

| Feature | Composition | Intended use |
|---|---|---|
| `wasm-browser-minimal` | `wasm-runtime` | smallest browser-safe surface |
| `wasm-browser-dev` | `wasm-runtime`, `browser-io` | development (used by the in-repo fixture) |
| `wasm-browser-prod` | `wasm-runtime`, `browser-io` | production browser builds |
| `wasm-browser-deterministic` | `wasm-runtime`, `deterministic-mode`, `browser-trace` | deterministic/replay lane |

All of them imply `wasm-runtime → wasm-browser-preview`. The names
`wasm-browser-preview`, `browser-io`, `browser-trace`, and `deterministic-mode`
are capability slices used to compose the profiles above; prefer the four
canonical profiles rather than the raw slices. (See the `[features]` block in
the root `Cargo.toml`.)

## How to build a Rust → WASM consumer

There are two crates you may depend on, depending on what you need:

1. **`asupersync` directly** — depend on the runtime under a browser profile and
   write your own `#[wasm_bindgen]` exports. This is what the maintained fixture
   at `tests/fixtures/rust-browser-consumer/crate/` does.
2. **`asupersync-browser-core`** — the canonical wasm-bindgen **export boundary**
   crate. It owns the live **v1 ABI** export surface (`runtime_create`,
   `scope_enter`/`scope_close`, `task_spawn`/`task_join`/`task_cancel`,
   `fetch_request`, `websocket_*`, `abi_version`/`abi_fingerprint`,
   `browser_operator_snapshot`) consumed by the `@asupersync/browser-core` JS
   package. Use it if you want the shipped ABI rather than a hand-rolled one.

A minimal consumer `Cargo.toml` (mirrors the fixture crate):

```toml
[lib]
crate-type = ["cdylib"]   # add "rlib" if you also consume it as a Rust lib

[dependencies]
asupersync = { version = "0.3", default-features = false, features = ["wasm-browser-dev"] }
wasm-bindgen = "0.2"
js-sys = "0.3"
web-sys = { version = "0.3", features = ["Window", "Document"] }
serde = { version = "1", features = ["derive"] }
serde-wasm-bindgen = "0.6"
```

Build steps:

```bash
rustup target add wasm32-unknown-unknown
# Build + generate JS bindings in one step:
wasm-pack build --target web   # or --target bundler for Vite/webpack
# (equivalently: cargo build --target wasm32-unknown-unknown, then wasm-bindgen-cli)
```

`asupersync-browser-core` is itself a `cdylib`/`rlib` crate and carries
`[package.metadata.wasm-pack.profile.release]` `wasm-opt` flags, so it is built
with `wasm-pack`. Entropy is handled for you: the wasm32 dependency table enables
`getrandom`'s `wasm_js` backend.

> The authoritative end-to-end build/run recipe (with a real Chromium matrix) is
> the fixture workflow:
> ```bash
> PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh
> ```
> See `tests/fixtures/rust-browser-consumer/README.md`. Treat that fixture and
> its evidence artifacts as the canonical reference for this lane.

## Minimal usage example

The browser builder is a distinct type from the native `RuntimeBuilder`. Each of
its terminal methods (`inspect_execution_ladder`, `build_selection`, `build`)
**consumes `self`**, so start from a fresh `RuntimeBuilder::browser()` per call.

```rust
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::builder::BrowserExecutionLane;

// 1) Inspect the truthful execution ladder with no side effects.
let ladder = RuntimeBuilder::browser().inspect_execution_ladder();
// Useful fields: ladder.supported, ladder.selected_lane, ladder.host_role,
//                ladder.reason_code, ladder.preferred_lane,
//                ladder.downgrade_order, ladder.message.

// 2) No-throw selection: get diagnostics AND (when supported) a runtime.
let selection = RuntimeBuilder::browser().build_selection();
if let Some(runtime) = selection.runtime {
    // Structured-concurrency root over the WASM ABI dispatcher.
    let scope = runtime.enter_scope(Some("app-root"))?;
    // ... drive task lifecycle / fetch / websocket through the ABI exports ...
    runtime.close_scope(&scope)?;
    runtime.close()?;
} else {
    // Fail-closed: inspect selection.error / selection.execution_ladder.
    eprintln!("browser runtime unavailable: {}", selection.execution_ladder.message);
}

// 3) Fallible build (same selection, but returns Result).
let runtime = RuntimeBuilder::browser()
    .consumer_version(asupersync::WasmAbiVersion::CURRENT) // optional: pin ABI
    .preferred_lane(BrowserExecutionLane::BrowserMainThreadDirectRuntime) // optional
    .build()?; // Err(BrowserRuntimeBuildError::Unsupported { .. }) on a non-browser host
```

### `BrowserRuntimeBuilder` API

| Method | Effect |
|---|---|
| `RuntimeBuilder::browser()` | construct the preview browser builder |
| `.preferred_lane(BrowserExecutionLane)` | request an explicit lane (still truthfully validated) |
| `.automatic_lane()` | restore automatic lane negotiation (default) |
| `.consumer_version(WasmAbiVersion)` | pin the consumer ABI version for boundary calls |
| `.abort_mode(WasmAbortPropagationMode)` | set abort propagation (default `Bidirectional`) |
| `.inspect_execution_ladder() -> BrowserExecutionLadderDiagnostics` | diagnostics only; never constructs a runtime |
| `.build_selection() -> BrowserRuntimeSelectionResult` | no-throw: `{ execution_ladder, runtime: Option, error: Option }` |
| `.build() -> Result<BrowserRuntime, BrowserRuntimeBuildError>` | fallible construct |

`BrowserExecutionLane` and the diagnostics/lane types live in
`asupersync::runtime::builder::*`; `WasmAbiVersion` and
`WasmAbortPropagationMode` live in `asupersync::types::*` (`WasmAbiVersion` is
also re-exported at the crate root).

### `BrowserRuntime` surface

The constructed runtime is intentionally **narrower than the native `Runtime`**.
It is `Rc`-backed (single-threaded) and dispatcher-backed; it does **not** expose
`spawn`/`block_on`/timer APIs directly. It provides:

- `enter_scope(label) -> Result<WasmHandleRef, WasmDispatchError>`
- `close_scope(scope) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError>`
- `close() -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError>`
- `runtime_handle()`, `consumer_version()`, `execution_ladder()`
- `dispatcher_diagnostics() -> WasmDispatcherDiagnostics` (dispatch count, leak/clean check)

Task lifecycle (`task_spawn`/`task_join`/`task_cancel`), cancel-correct `fetch`,
and `websocket_*` are reached through the ABI export surface in
`asupersync-browser-core`, not as methods on `BrowserRuntime`.

## Lane selection and fail-closed behavior

`detect_browser_execution_probe()` is `cfg`-split:

- On `wasm32`, it reads `globalThis`, the global constructor name, and a
  capability snapshot to classify a **host role**: browser main thread
  (`window` + `document`), dedicated worker, service worker, shared worker, or
  non-browser/unknown.
- On **native** (`not(target_arch = "wasm32")`), it returns a non-browser probe.
  As a result, **`build()` on native always fail-closes** with
  `BrowserRuntimeBuildError::Unsupported { .. }`. (This is pinned by
  `tests/wasm_rust_browser_example_contract.rs`.)

`BrowserExecutionLane` values:

- `BrowserMainThreadDirectRuntime` — supported direct-runtime lane
- `DedicatedWorkerDirectRuntime` — supported direct-runtime lane
- `Unsupported` — terminal fail-closed lane

Support reasons (`BrowserRuntimeSupportReason`) you may see in diagnostics:
`Supported`, `MissingGlobalThis`, `MissingWebAssembly`, `UnsupportedRuntimeContext`,
`ServiceWorkerNotYetShipped`, `SharedWorkerNotYetShipped`. When a requested lane
isn't truthfully available, selection preserves the **truthful** lane/reason and
exposes a `downgrade_order` rather than pretending the requested lane works.

## Runtime model under wasm32

- **Executor**: single-threaded, browser-event-loop driven. `worker_threads` and
  the native parallel scheduler/blocking pool do not apply.
- **Reactor**: `BrowserReactor` (`src/runtime/reactor/browser.rs`). There is no
  blocking poll. `wake()` is a pure wakeup that never invents readiness; `poll()`
  drains pending events from the microtask/macrotask queue in bounded batches.
  It wires real host listeners for `MessagePort` and `BroadcastChannel` via
  `wasm-bindgen` closures and bridges fetch/WebSocket completions.
- **Timer/clock**: `BrowserClock` (`src/time/driver.rs`) builds a monotonic clock
  from host time samples (`performance.now()`), preserving monotonicity even if
  the host sample regresses and bounding catch-up per sample.
- **Entropy**: `getrandom` with the `wasm_js` backend.

## What it does NOT support (be explicit)

- **Native sockets**: TCP and UDP fail closed. The wasm32 stubs return
  `io::ErrorKind::Unsupported`, e.g. *"`<op>` is unavailable in wasm-browser
  profiles; use browser transport bindings or VirtualTcp"*
  (`src/net/tcp/mod.rs`, `src/net/udp.rs`). Native QUIC/HTTP3 paths are likewise
  not available on the browser target.
- **Filesystem, OS threads, OS signals, native AEAD crypto**: the crates backing
  these (`socket2`, `polling`, `nix`, `libc`, `signal-hook`, `aes-gcm`,
  `chacha20poly1305`) are excluded from `wasm32` builds.
- **Service-worker / shared-worker direct runtime**: not shipped as direct lanes
  — they fail closed with `*NotYetShipped`. Bounded **service-worker broker** and
  **shared-worker coordinator** *host-class preflight diagnostics* exist
  (`BrowserServiceWorkerBrokerSupportDiagnostics`,
  `BrowserSharedWorkerCoordinatorSupportDiagnostics`), but those are
  diagnostics/preflight only; full registration, same-origin script resolution,
  and handshake admission remain on the JS helper surface.
- **A stable, ergonomic Rust browser SDK** on par with `@asupersync/browser`, and
  **native-runtime parity on wasm32** generally. This lane is preview, narrower
  than the JS/TS packages, and anchored by the fixture/evidence workflow.

## Caveats / open questions for the maintainer

- **Doc placement / naming.** This file is `docs/wasm_rust_browser_lane.md` to
  follow the `docs/wasm_*.md` convention and to avoid a case collision with the
  existing `docs/WASM.md` on case-insensitive filesystems. If you'd rather fold
  this into `WASM.md` or `wasm_quickstart_migration.md`, say so.
- **`getrandom` backend.** The wasm32 table enables `getrandom`'s `wasm_js`
  feature. Whether downstream consumers also need the `getrandom_backend="wasm_js"`
  cfg (a `getrandom` 0.3+ requirement in some setups) for their *own* crate was
  not verified here — please confirm the exact consumer-side requirement.
- **Stability of the surface.** Method names and types above are taken from the
  current source; since the lane is preview, please flag anything you expect to
  rename or change before this is treated as stable guidance.
- **Cross-links.** This draft links from the "Rust-to-WASM compilation path"
  section of `WASM.md`; adjust if you maintain a different doc index.

## See also

- [`WASM.md`](./WASM.md) — full Browser Edition overview, architecture, phases.
- [`wasm_quickstart_migration.md`](./wasm_quickstart_migration.md) — migration/quickstart.
- [`wasm_canonical_examples.md`](./wasm_canonical_examples.md) — cross-framework examples.
- `tests/fixtures/rust-browser-consumer/` + `scripts/validate_rust_browser_consumer.sh` — canonical evidence.
- `tests/wasm_rust_browser_example_contract.rs` — pins the public API contract.
- Source: `src/runtime/builder.rs`, `asupersync-browser-core/`, `src/runtime/reactor/browser.rs`, `src/time/driver.rs`.
