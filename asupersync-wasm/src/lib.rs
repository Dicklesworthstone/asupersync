//! # asupersync-wasm
//!
//! Non-canonical Browser Edition binding scaffold.
//!
//! This crate is intentionally not the owner of the shipped JS/WASM boundary
//! today. `asupersync-browser-core` owns the live v1 wasm-bindgen export
//! surface consumed by `@asupersync/browser-core` and the higher-level JS/TS
//! packages.
//!
//! `asupersync-wasm` is retained as workspace scaffolding for future or
//! alternative binding strategies so the repository can converge on one
//! truthful boundary owner without deleting historical structure.
//!
//! ## Current role
//!
//! ```text
//! JS/TS packages  -->  asupersync-browser-core  -->  live v1 ABI boundary
//!                                           \
//!                                            \-> asupersync-wasm (retained scaffold)
//! ```
//!
//! Until a later bead deliberately gives this crate a new supported role, treat
//! it as a non-canonical scaffold rather than a second live boundary.
//!
//! The crate therefore exposes only explicit scaffold metadata and fail-closed
//! helpers that point callers at the canonical boundary owner.

#![deny(unsafe_code)]

pub mod error;
mod exports;
pub mod types;

pub use crate::error::RetainedBoundaryError;
pub use crate::exports::{
    canonical_boundary_status, canonical_boundary_status_json, fail_closed_symbol,
    fail_closed_symbol_json,
};
pub use crate::types::RetainedBoundaryStatus;
