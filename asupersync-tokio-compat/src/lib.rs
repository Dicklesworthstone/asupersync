//! # asupersync-tokio-compat
//!
//! Compatibility bridge for running Tokio-locked crates within the Asupersync
//! async runtime.
//!
//! This crate provides adapter primitives that implement Tokio/hyper runtime
//! traits using Asupersync's executor, timer, and I/O subsystems. It allows
//! crates like reqwest, axum, tonic, and sqlx to execute within an Asupersync
//! runtime while preserving Asupersync's core invariants:
//!
//! - **No ambient authority**: All adapter entry points require explicit `Cx`
//! - **Structured concurrency**: Adapter-spawned tasks are region-owned
//! - **Cancellation protocol**: Cancellation propagates through adapters
//! - **No obligation leaks**: Resources are tracked and released on region close
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │     User Application (Cx)        │
//! ├─────────────────────────────────┤
//! │     asupersync-tokio-compat      │  ← This crate
//! │  (executor, timer, I/O bridges)  │
//! ├─────────────────────────────────┤
//! │     Tokio-locked crates          │
//! │  (reqwest, axum, tonic, sqlx)    │
//! └─────────────────────────────────┘
//! ```
//!
//! # Feature Flags
//!
//! | Feature | Enables |
//! |---------|---------|
//! | `hyper-bridge` | hyper v1 runtime trait implementations |
//! | `tokio-io` | Bidirectional `AsyncRead`/`AsyncWrite` adapters |
//! | `full` | All adapters |
//!
//! # Hard Boundary Rules
//!
//! 1. The main `asupersync` crate does NOT depend on this crate (one-way dep).
//! 2. No Tokio runtime is embedded or started by this crate.
//! 3. `Cx` must cross every adapter boundary explicitly.
//! 4. All spawned tasks are region-owned and cancellation-aware.

#![deny(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

/// Stable policy identifier for compatibility scaffolding and release controls.
pub const COMPAT_POLICY_VERSION: &str = "1.0.0";
/// Current semver compatibility line for this pre-1.0 adapter crate.
pub const COMPATIBILITY_LINE: &str = "0.1.x";
/// Track-level owner for escalation and exception handling.
pub const OWNER_TRACK_ID: &str = "asupersync-2oh2u.7";

pub mod blocking;
pub mod cancel;
pub mod io;

#[cfg(feature = "hyper-bridge")]
pub mod hyper_bridge;

#[cfg(feature = "tower-bridge")]
pub mod tower_bridge;

/// Cancellation mode for adapter-wrapped futures.
///
/// Controls how Asupersync cancellation interacts with Tokio-originated futures
/// that may not be cancel-aware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CancellationMode {
    /// Just await the future. If cancellation is requested, the future may
    /// still complete normally. The result is returned as-is.
    #[default]
    BestEffort,

    /// Fail if the future completes after cancellation was requested.
    /// Returns `Err(AdapterError::CancellationIgnored)`.
    Strict,

    /// Use a timeout as a cancellation mechanism. If cancellation is requested
    /// and the future doesn't complete within the fallback timeout, it is
    /// dropped.
    TimeoutFallback,
}

/// Configuration for adapter behavior.
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    /// How to handle cancellation for wrapped futures.
    pub cancellation_mode: CancellationMode,

    /// Fallback timeout duration for `CancellationMode::TimeoutFallback`.
    pub fallback_timeout: Option<std::time::Duration>,

    /// Minimum remaining poll budget before the adapter refuses to proceed.
    /// Prevents starting expensive operations with insufficient budget.
    pub min_budget_for_call: u64,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            cancellation_mode: CancellationMode::default(),
            fallback_timeout: Some(std::time::Duration::from_secs(30)),
            min_budget_for_call: 10,
        }
    }
}

impl AdapterConfig {
    /// Create a new adapter configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the cancellation mode.
    #[must_use]
    pub fn with_cancellation_mode(mut self, mode: CancellationMode) -> Self {
        self.cancellation_mode = mode;
        self
    }

    /// Set the fallback timeout for `TimeoutFallback` mode.
    #[must_use]
    pub fn with_fallback_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.fallback_timeout = Some(timeout);
        self
    }

    /// Set the minimum budget for proceeding with an adapter call.
    #[must_use]
    pub fn with_min_budget(mut self, budget: u64) -> Self {
        self.min_budget_for_call = budget;
        self
    }
}

/// Errors returned by adapter operations.
#[derive(Debug)]
pub enum AdapterError<E> {
    /// The wrapped service returned an error.
    Service(E),

    /// The operation was cancelled via Asupersync's cancellation protocol.
    Cancelled,

    /// The operation timed out (in `TimeoutFallback` mode).
    Timeout,

    /// Insufficient poll budget to start the operation.
    InsufficientBudget {
        /// Budget remaining when the call was attempted.
        remaining: u64,
        /// Minimum budget required by the adapter configuration.
        required: u64,
    },

    /// The future completed after cancellation was requested, and
    /// `CancellationMode::Strict` was configured.
    CancellationIgnored,
}

impl<E: std::fmt::Display> std::fmt::Display for AdapterError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Service(e) => write!(f, "adapter service error: {e}"),
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::InsufficientBudget {
                remaining,
                required,
            } => {
                write!(
                    f,
                    "insufficient budget: {remaining} remaining, {required} required"
                )
            }
            Self::CancellationIgnored => {
                write!(f, "service did not respect cancellation")
            }
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for AdapterError<E> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_policy_constants_are_present() {
        assert_eq!(COMPAT_POLICY_VERSION, "1.0.0");
        assert_eq!(COMPATIBILITY_LINE, "0.1.x");
        assert_eq!(OWNER_TRACK_ID, "asupersync-2oh2u.7");
    }
}
