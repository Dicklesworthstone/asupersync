# Rust Browser Consumer Fixture

Fixture for beads `asupersync-4l9iw.2` and `asupersync-4l9iw.8`.

Purpose:
- prove the repository-maintained Rust-authored browser lane with a real wasm package layout
- keep the example honest about scope: this is a maintained in-repo workflow, not broad public `RuntimeBuilder` parity for external Rust consumers
- demonstrate structured-concurrency lifecycle behavior through the existing dispatcher/provider helpers on both browser main-thread and dedicated-worker entrypoints
- capture truthful `RuntimeBuilder` execution-ladder diagnostics for preferred-lane mismatch, downgrade, and guarded-capability snapshots without pretending a public wasm/browser runtime constructor already exists

This fixture is executed through:
- `scripts/validate_rust_browser_consumer.sh`

The validation script:
- builds the nested Rust crate with `rch exec -- wasm-pack build ...`
- stages the generated `pkg/` output next to the copied frontend consumer
- runs a Vite bundle check against the resulting browser artifacts
- runs a real browser matrix that proves:
  - browser main-thread lifecycle + execution-ladder diagnostics
  - dedicated-worker lifecycle + execution-ladder diagnostics
  - missing-`WebAssembly` downgrade selection in the main-thread lane
  - guarded advanced-capability snapshots such as `localStorage`, `indexedDB`, and `WebTransport`

## Layout

- `crate/Cargo.toml`
  Rust-authored wasm package that depends on the root `asupersync` crate under a canonical browser profile
- `crate/src/lib.rs`
  exports a small browser-facing demo plus Rust-side `RuntimeBuilder` execution-ladder inspection helpers
- `src/main.ts`
  initializes the generated wasm package, captures the browser main-thread matrix, and coordinates the dedicated worker probe
- `src/worker.ts`
  initializes the same generated wasm package inside a dedicated worker and returns worker lifecycle + ladder diagnostics
- `scripts/check-bundle.mjs`
  asserts the built Vite output retains both main-thread and worker JavaScript assets plus the generated wasm asset
- `scripts/check-browser-run.mjs`
  drives a real Chromium run and asserts the maintained Rust browser matrix stays truthful

## Boundary Rules

- This fixture is a repository-maintained example for the current Rust-authored browser contract.
- It does not claim a general external Rust-browser bootstrap API beyond what `docs/WASM.md` currently marks as truthful scope.
- It uses the existing wasm dispatcher/provider helpers plus `RuntimeBuilder::inspect_browser_execution_ladder*()` diagnostics instead of inventing a new public browser `RuntimeBuilder` story.

## Deterministic Validation

Run the maintained example through the canonical validation path:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh
```

Artifacts are emitted under:

```text
target/e2e-results/rust_browser_consumer/
```
