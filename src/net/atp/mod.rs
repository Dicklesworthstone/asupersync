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

// TODO: Fix compilation issues in ATP network modules
// pub mod chunk;
// pub mod loss;
pub mod path;
#[path = "protocol/mod.rs"]
pub mod protocol;
// pub mod quic;
// pub mod rendezvous;
// TODO: Fix compilation issues in ATP SDK
// pub mod sdk;
pub mod stun;

// Re-export key types for H3 adapter
pub use protocol::{AtpFrame, FrameType};

// pub use loss::*;
pub use path::*;
pub use protocol::*;
// pub use quic::*;
// pub use sdk::*;

// H3 adapter for WebTransport support
pub mod h3;
