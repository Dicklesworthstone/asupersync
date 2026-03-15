# WASM Artifact Strategy and Crate Layout (WASM-ADR-010)

Decision ID: `asupersync-3qv04.2.1`
Status: accepted
Date: 2026-03-06
Author: SapphireHill

## Context

With the WASM compile closure complete (all `asupersync-3qv04.1.*` beads closed), the
runtime compiles cleanly under all four canonical browser profiles
(`wasm-browser-minimal`, `wasm-browser-dev`, `wasm-browser-prod`,
`wasm-browser-deterministic`). The next step is to materialize the concrete
JS/WASM boundary: exported symbols, artifact generation, and crate layout.

The planning document (`PLAN_TO_BUILD_ASUPERSYNC_IN_WASM_FOR_USE_IN_BROWSERS.md`)
adopted **Option C: Hybrid staged split** with a five-crate end-state topology.
This decision record concretizes the _first extraction step_ and the artifact
pipeline that downstream beads (3qv04.2.2, 3qv04.4.1) depend on.

## Decision

### 1. Crate Layout: `asupersync-browser-core` Bindings Crate

Create a single new workspace member `asupersync-browser-core/` that owns the
`#[wasm_bindgen]` export boundary. This is **not** the full end-state split; it
is the first concrete extraction aligned with the hybrid staged approach.

```
asupersync-browser-core/
  Cargo.toml
  src/
    lib.rs          # crate root, re-exports, wasm_bindgen glue setup
    exports.rs      # #[wasm_bindgen] functions wrapping WasmExportDispatcher
    types.rs        # JS-visible type wrappers (JsValue conversions)
    error.rs        # JS error conversions
```

**Rationale:** A dedicated bindings crate isolates `wasm-bindgen`/`js-sys`/`web-sys`
dependencies from the core runtime. The core crate stays `wasm-bindgen`-free,
preserving its role as platform-agnostic library code. This matches the
`asupersync-tokio-compat` pattern: one focused bridge crate per ecosystem boundary.

**Workspace Cargo.toml addition:**

```toml
[workspace]
members = [
    ".",
    "asupersync-macros",
    "asupersync-tokio-compat",
    "asupersync-browser-core",           # <-- new
    "conformance",
    "franken_kernel",
    "franken_evidence",
    "franken_decision",
    "frankenlab",
]
```

### 2. Dependency Strategy

**`asupersync-browser-core/Cargo.toml`:**

```toml
[package]
name = "asupersync-browser-core"
version = "0.1.0"
edition = "2024"
license-file = "../LICENSE"
description = "WASM/JS bindings for the Asupersync async runtime (Browser Edition)."

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
asupersync = { version = "0.2.8", path = "..", default-features = false, features = ["wasm-browser-prod"] }
wasm-bindgen = "0.2"
js-sys = "0.3"
web-sys = { version = "0.3", features = [
    "Window",
    "Performance",
    "AbortController",
    "AbortSignal",
    "console",
] }
serde = { version = "1", features = ["derive"] }
serde-wasm-bindgen = "0.6"

[dev-dependencies]
wasm-bindgen-test = "0.3"

[features]
default = ["prod"]
minimal = []
dev = []
prod = []
deterministic = []
```

**Key constraints:**
- The bindings crate depends on asupersync with `default-features = false`.
- Browser profile selection is feature-gated (matching canonical profiles).
- `wasm-bindgen`, `js-sys`, `web-sys` never appear in the core crate.

### 3. Export Surface: Thin Wrapper over `WasmExportDispatcher`

The bindings crate does **not** reimplement ABI logic. Each exported function is
a thin `#[wasm_bindgen]` wrapper that delegates to the existing
`WasmExportDispatcher` in `src/types/wasm_abi.rs`.

**Canonical v1 export mapping:**

| JS function name     | Dispatcher method            | Request type              | Response type             |
|----------------------|------------------------------|---------------------------|---------------------------|
| `runtime_create`     | `dispatcher.runtime_create()`| (none)                    | `WasmHandleRef` as u64    |
| `runtime_close`      | `dispatcher.runtime_close()` | handle: u64               | `JsValue` (outcome)       |
| `scope_enter`        | `dispatcher.scope_enter()`   | parent: u64, label?: str  | `WasmHandleRef` as u64    |
| `scope_close`        | `dispatcher.scope_close()`   | handle: u64               | `JsValue` (outcome)       |
| `task_spawn`         | `dispatcher.task_spawn()`    | scope: u64, label?: str   | `WasmHandleRef` as u64    |
| `task_join`          | `dispatcher.task_join()`     | handle: u64               | `JsValue` (outcome)       |
| `task_cancel`        | `dispatcher.task_cancel()`   | handle: u64, kind?: str   | `JsValue` (outcome)       |
| `fetch_request`      | `dispatcher.fetch_request()` | scope: u64, url: str, ... | `JsValue` (outcome)       |

**Handle encoding:** `WasmHandleRef` (slot + generation) is encoded as a single
`u64` across the boundary. The JS side treats handles as opaque numbers; the Rust
side validates slot/generation on every call.

**Outcome encoding:** `WasmAbiOutcomeEnvelope` is serialized to `JsValue` via
`serde-wasm-bindgen` for structured access on the JS side, preserving the
four-valued outcome model (ok/err/cancelled/panicked).

### 4. Build Pipeline: wasm-pack

**Tool choice:** `wasm-pack` (wraps `wasm-bindgen-cli` and `wasm-opt`).

**Rationale:**
- Generates the complete artifact bundle (`.wasm`, JS glue, `.d.ts`, `package.json`).
- Handles `wasm-opt` optimization in release builds.
- Produces output directly consumable by npm/bundlers.
- Well-maintained, widely adopted, minimal configuration.

**Build commands (canonical):**

```bash
# Development build (fast, with debug symbols)
wasm-pack build asupersync-browser-core --target web --dev --out-dir pkg/dev \
  -- --features dev

# Production build (optimized, with wasm-opt)
wasm-pack build asupersync-browser-core --target web --release --out-dir pkg/prod \
  -- --features prod

# Minimal build (smallest possible surface)
wasm-pack build asupersync-browser-core --target web --release --out-dir pkg/minimal \
  -- --features minimal

# Deterministic build (for lab/replay testing)
wasm-pack build asupersync-browser-core --target web --dev --out-dir pkg/deterministic \
  -- --features deterministic
```

**Target:** `web` (not `bundler` or `nodejs`). The `web` target produces ESM
output that works with both direct `<script type="module">` usage and bundlers
(vite, webpack, turbopack). The `@asupersync/browser-core` npm package will
wrap and re-export the wasm-pack output.

### 5. Artifact Layout

```
asupersync-browser-core/
  pkg/
    prod/
      asupersync_browser_core_bg.wasm      # optimized wasm binary
      asupersync_browser_core_bg.wasm.d.ts  # TypeScript types for wasm imports
      asupersync_browser_core.js            # JS glue (init function, exports)
      asupersync_browser_core.d.ts          # TypeScript declarations
      package.json                  # npm package metadata (generated)
    dev/
      ...                           # same structure, unoptimized
    minimal/
      ...
    deterministic/
      ...
```

**Artifact integrity:** Each profile build produces a SHA-256 manifest of all
output files. The CI gate (`scripts/check_wasm_abi_policy.py`) validates that
the ABI fingerprint in the built artifact matches
`WASM_ABI_SIGNATURE_FINGERPRINT_V1`.

### 6. Relationship to End-State Topology

This decision is Stage 1 of the hybrid staged split:

| End-state crate           | Current status                     | This decision                    |
|---------------------------|------------------------------------|----------------------------------|
| `asupersync-core`         | Not yet extracted                  | No change (future Stage 2)       |
| `asupersync-native`       | Not yet extracted                  | No change (future Stage 2)       |
| `asupersync-browser-core-core`    | Not yet extracted                  | No change (future Stage 2)       |
| `asupersync-browser-core-bindings`| Does not exist                     | Created as `asupersync-browser-core`     |
| `asupersync`              | Monolith with cfg-gated wasm paths | Unchanged; bindings crate depends on it |

When the full split happens (Stage 2), `asupersync-browser-core` will be renamed to
`asupersync-browser-core-bindings` and will depend on `asupersync-browser-core-core` instead
of the monolith. The export surface remains stable across this transition
because the bindings crate only exposes the dispatcher, not internal types.

### 7. Relationship to JS Package Topology

The `asupersync-browser-core` crate produces the raw wasm artifact. The JS package
hierarchy wraps it:

```
asupersync-browser-core (Rust, this crate)
  |
  v  (wasm-pack output)
@asupersync/browser-core (npm)
  |
  v  (re-exports + high-level SDK)
@asupersync/browser (npm)
  |
  +---> @asupersync/react (npm)
  +---> @asupersync/next (npm)
```

`@asupersync/browser-core` vendors the wasm-pack output and provides the
`init()` function, type re-exports, and module-resolution entrypoints (ESM/CJS).

## Consequences

1. **Downstream beads unblocked:**
   - `asupersync-3qv04.2.2` can implement concrete `#[wasm_bindgen]` exports.
   - `asupersync-3qv04.4.1` can create the JS package tree.

2. **Core crate stays clean:** No `wasm-bindgen` dependency in the main crate.

3. **Incremental extraction:** The bindings crate can be built and tested
   independently. When the full split happens, only the dependency target changes.

4. **CI integration:** The existing ABI fingerprint gate applies unchanged;
   the bindings crate imports `WASM_ABI_SIGNATURE_FINGERPRINT_V1` and the
   dispatcher from the core crate.

## Rejected Alternatives

### A. In-crate `#[wasm_bindgen]` exports

Add `#[wasm_bindgen]` directly to `src/types/wasm_abi.rs` behind `cfg(target_arch = "wasm32")`.

Rejected because:
- Pollutes core crate with `wasm-bindgen` dependency.
- Makes the wasm boundary harder to test in isolation.
- Conflicts with the hybrid staged split plan.

### B. Immediate full five-crate split

Extract `asupersync-core`, `asupersync-native`, `asupersync-browser-core-core`, and
`asupersync-browser-core-bindings` simultaneously.

Rejected because:
- Premature: wasm parity is not proven yet.
- High risk of API churn during the extract.
- The planning doc explicitly chose staged extraction.

### C. Custom wasm-bindgen-cli pipeline (no wasm-pack)

Use `wasm-bindgen-cli` directly with manual `wasm-opt` and artifact assembly.

Rejected because:
- More configuration, same output.
- wasm-pack handles the common case well.
- Can always eject to raw `wasm-bindgen-cli` later if needed.
