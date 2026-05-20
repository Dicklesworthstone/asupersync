//! ATP-QUIC Integration Layer
//!
//! This module integrates the native QUIC transport layer with ATP requirements:
//! - Exposes transport metrics to ATP Transfer Brain
//! - Provides structured logging for replay and diagnostics
//! - Implements anti-amplification protection
//! - Handles ATP-specific recovery and cancellation semantics

pub mod connection;
pub mod metrics;
pub mod packet_protection;
pub mod recovery;
pub mod transfer_brain;

pub use connection::*;
pub use metrics::*;
pub use packet_protection::*;
pub use recovery::*;
pub use transfer_brain::*;
