//! JS error conversions for the WASM boundary.
//!
//! Maps `WasmAbiFailure` and Rust panics to structured JS errors with
//! deterministic codes and diagnostic metadata.
//!
//! Implementation deferred to bead `asupersync-3qv04.2.2`.
