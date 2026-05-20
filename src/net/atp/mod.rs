//! ATP (Asupersync Transfer Protocol) - Self-contained data movement layer.
//!
//! ATP provides verified object graph transfer over native QUIC with:
//! - Binary frame codec with varints and versioning
//! - Session negotiation and capabilities exchange
//! - Content-addressed objects with manifests and Merkle proofs
//! - Path discovery, NAT traversal, and relay coordination
//! - Deterministic replay and structured logging
//!
//! Key design principles:
//! - No external QUIC crates - uses asupersync's native QUIC
//! - Fail-closed error handling with typed protocol errors
//! - Cancellation-correct with proper obligation tracking
//! - Platform-agnostic with explicit capability detection

pub mod protocol;

pub use protocol::*;
