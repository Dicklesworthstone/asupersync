//! Internal utilities for the Asupersync runtime.
//!
//! These utilities are intentionally minimal and dependency-free to maintain
//! determinism in the lab runtime.

pub mod arena;
pub mod det_rng;

pub use arena::{Arena, ArenaIndex};
pub use det_rng::DetRng;
