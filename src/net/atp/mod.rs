//! ATP (Asupersync Transfer Protocol) - Self-contained data movement layer.
//!
//! ATP provides verified object graph transfer over native QUIC with:
//! - Binary frame codec with varints and versioning
//! - Session negotiation and capabilities exchange
//! - Content-addressed objects with manifests and Merkle proofs
//! - Path discovery, NAT traversal, and relay coordination
//! - Deterministic replay and structured logging
//! - High-level SDK APIs for object, tree, stream, and buffer movement
//!
//! Key design principles:
//! - No external QUIC crates - uses asupersync's native QUIC
//! - Fail-closed error handling with typed protocol errors
//! - Cancellation-correct with proper obligation tracking
//! - Platform-agnostic with explicit capability detection
//! - Cx-first APIs with explicit capability boundaries

pub mod chunk;
pub mod datagram;
pub mod discovery;
pub mod handshake;
pub mod loss;
pub mod object;
pub mod ops;
pub mod path;
#[path = "protocol/mod.rs"]
pub mod protocol;
pub mod quic;
pub mod relay;
pub mod rendezvous;
pub mod sdk;
pub mod streams;
pub mod stun;

// Re-export key types for H3 adapter
pub use protocol::{AtpFrame, FrameType};

pub use chunk::*;
// Datagram module exports CongestionAlgorithm, avoid glob
// pub use datagram::*;
pub use discovery::*;
// Handshake module exports TransportParameters, avoid glob
// pub use handshake::*;
pub use object::*;
// pub use loss::*;
pub use path::*;
// pub use protocol::*;
pub use quic::*;
// pub use sdk::*;
// pub use streams::*;

// H3 adapter for WebTransport support
pub mod h3;

// Test utilities for ATP module testing
#[cfg(any(test, feature = "test-internals"))]
pub mod test_utils;
