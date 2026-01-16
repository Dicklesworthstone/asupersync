//! Tracing infrastructure for deterministic replay.
//!
//! This module provides structured tracing for the runtime, enabling:
//!
//! - Deterministic replay of executions
//! - Debugging and analysis of concurrent behavior
//! - Mazurkiewicz trace semantics for DPOR

pub mod buffer;
pub mod event;
pub mod format;

pub use buffer::TraceBuffer;
pub use event::{TraceData, TraceEvent};
