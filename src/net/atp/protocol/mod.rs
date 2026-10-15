//! ATP Protocol Layer - Binary frames, session negotiation, and transport.
//!
//! # Resource Management
//!
//! The `resource_manager` module provides Byzantine-resistant per-peer resource
//! limits to prevent resource exhaustion attacks. Integration points:
//!
//! - Session establishment: Check session limits before accepting new connections
//! - Frame processing: Validate frame rates and memory usage per peer
//! - Object requests: Limit concurrent requests per peer to prevent amplification
//! - Memory allocation: Track and limit per-peer memory usage for large objects
//!
//! The Byzantine defense processor wires `ResourceManager` into frame handling,
//! object requests, and session lifecycle accounting; transport adapters should
//! route inbound peer traffic through that processor before dispatching payloads.

pub mod byzantine_defense;
pub mod codec;
pub mod frames;
pub mod outcome;
pub mod packet_assembly;
pub mod quic_frames;
pub mod resource_manager;
pub mod session;
pub mod transcript;
pub mod transport_params;
pub mod varint;

pub use byzantine_defense::*;
pub use codec::*;
pub use frames::*;
pub use outcome::*;
pub use packet_assembly::*;
pub use quic_frames::*;
pub use resource_manager::*;
pub use session::*;
pub use transcript::*;
pub use transport_params::*;
pub use varint::*;

/// Compatibility name for adapter code that treats ATP frames abstractly.
pub type AtpFrame = Frame;
