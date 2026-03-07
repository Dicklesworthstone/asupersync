//! # asupersync-wasm
//!
//! WASM/JS bindings for the Asupersync async runtime (Browser Edition).
//!
//! This crate provides the concrete `#[wasm_bindgen]` export boundary that
//! bridges the Asupersync runtime to JavaScript. It wraps the
//! [`WasmExportDispatcher`] from the core crate with thin JS-callable functions.
//!
//! ## Architecture
//!
//! ```text
//! JS caller  -->  #[wasm_bindgen] exports (this crate)
//!                       |
//!                       v
//!                 WasmExportDispatcher (asupersync::types::wasm_abi)
//!                       |
//!                       v
//!                 Asupersync runtime (regions, tasks, scopes)
//! ```
//!
//! The export surface matches the v1 ABI symbol table defined in the core
//! crate. Handle encoding uses opaque `u64` values (slot + generation).
//! Outcomes are serialized via `serde-wasm-bindgen` preserving the four-valued
//! model (ok, err, cancelled, panicked).
//!
//! ## Crate Features
//!
//! - `minimal` — smallest wasm surface, no browser I/O
//! - `dev` — development profile with browser I/O
//! - `prod` — production profile with browser I/O (default)
//! - `deterministic` — replay-safe profile with browser trace

#![deny(unsafe_code)]

mod exports;
mod error;
mod types;
