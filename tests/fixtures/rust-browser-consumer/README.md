# Rust Browser Consumer Fixture

Fixture for beads `asupersync-4l9iw.2` and `asupersync-4l9iw.8`.

Purpose:
- prove the repository-maintained Rust-authored browser lane with a real wasm package layout
- keep the example honest about scope: the crate now exposes a preview public Rust browser builder, but this fixture still validates the maintained in-repo lane rather than claiming broad stable parity with the JS/TS Browser Edition packages
- demonstrate structured-concurrency lifecycle behavior through the existing dispatcher/provider helpers on both browser main-thread and dedicated-worker entrypoints
- capture truthful `RuntimeBuilder` execution-ladder diagnostics plus the preview public browser-builder path for preferred-lane mismatch, downgrade, and guarded-capability snapshots

This fixture is executed through:
- `scripts/validate_rust_browser_consumer.sh`

The validation script:
- builds the nested Rust crate through a local `wasm-pack build ...` invocation whose internal cargo calls are routed through `rch exec -- env CARGO_TARGET_DIR=<isolated-work-dir> cargo ...`
- stages the generated `pkg/` output next to the copied frontend consumer
- runs a Vite bundle check against the resulting browser artifacts
- mirrors `browser-run.json` into `summary.json`, including `service_worker_fail_closed_reason_code`, `shared_worker_fail_closed_reason_code`, and `downgrade_reason_code`, so the synthetic unsupported-worker evidence stays visible in the top-level QA artifact
- runs a real browser matrix that proves:
  - browser main-thread lifecycle + execution-ladder diagnostics
  - dedicated-worker lifecycle + execution-ladder diagnostics
  - missing-`WebAssembly` downgrade selection in the main-thread lane
  - synthetic service-worker and shared-worker fail-closed ladder snapshots produced by the Rust-side builder seam
  - bounded service-worker broker and shared-worker coordinator support diagnostics exported from the Rust preview browser surface without widening the direct-runtime claim
  - guarded advanced-capability snapshots such as `localStorage`, `indexedDB`, and `WebTransport`

## Layout

- `crate/Cargo.toml`
  Rust-authored wasm package that depends on the root `asupersync` crate under a canonical browser profile
- `crate/src/lib.rs`
  exports a small browser-facing demo plus Rust-side `RuntimeBuilder` execution-ladder inspection helpers, bounded worker-support diagnostics, and preview public browser-builder selection probes
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
- It does not claim stable broad Rust-browser parity with the JS/TS Browser Edition packages.
- It exercises the preview public Rust browser builder while keeping the repository-maintained fixture and its evidence artifacts as the authority for this lane.
- It still uses the existing wasm dispatcher/provider helpers alongside `RuntimeBuilder::inspect_browser_execution_ladder*()` so the fixture covers both lifecycle behavior and truthful lane selection.
- Service-worker and shared-worker snapshots in this fixture are synthetic ladder inspections, not claims that those direct-runtime hosts are already shipped for Rust.
- The bounded service-worker broker and shared-worker coordinator snapshots are host-class preflight diagnostics only; full registration, same-origin script resolution, and handshake admission remain on the JS helper surface.

## Deterministic Validation

Run the maintained example through the canonical validation path:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh
```

Artifacts are emitted under:

```text
target/e2e-results/rust_browser_consumer/
```
