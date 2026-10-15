//! ATP-over-H3/WebTransport adapter.
//!
//! This module provides an adapter that maps ATP frames onto H3 and WebTransport
//! streams/datagrams for browser compatibility while preserving ATP semantics
//! where possible and documenting unsupported native features.
//!
//! # Design Philosophy
//!
//! Native ATP remains the feature-complete path. This adapter enables browser
//! and web app compatibility by mapping ATP control/data/proof/repair frames
//! onto WebTransport bidirectional streams and unreliable datagrams.
//!
//! # Frame Mapping
//!
//! - ATP Control frames → WebTransport bidirectional streams (reliable)
//! - ATP Data frames → WebTransport bidirectional streams (reliable)
//! - ATP Proof frames → WebTransport bidirectional streams (reliable)
//! - ATP Repair frames → WebTransport unreliable datagrams (best effort)
//!
//! # Unsupported Features
//!
//! The following native ATP features are not available over WebTransport:
//! - Native QUIC connection migration
//! - Full control over packet pacing and congestion control
//! - Raw UDP socket access for STUN/relay operations
//! - Custom QUIC extensions and protocol negotiation
//! - Zero-copy buffer management
//! - Fine-grained flow control below H3 layer
//!
//! # Browser Security Constraints
//!
//! WebTransport operates within browser security model:
//! - Same-origin policy applies unless CORS headers permit
//! - Certificate validation required (no self-signed certs)
//! - No access to raw networking primitives
//! - WASM memory model constraints
//! - Limited threading and async execution models

pub mod adapter;
pub mod codec;
pub mod session;
pub mod stream;

pub use adapter::{
    AdapterConfig, AdapterDowngrade, AdapterNegotiationReport, AdapterStats, AtpH3Adapter,
    FeatureSupport, H3_WEBTRANSPORT_ADAPTER_KIND, NATIVE_ATP_FOUNDATION_KIND, TransmissionStrategy,
};
pub use codec::{H3FrameCodec, WebTransportFrameType};
pub use session::{H3Session, SessionState, SessionStats};
pub use stream::{AtpH3Stream, StreamDirection, StreamState, StreamStats};

/// ATP-over-H3 adapter errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AtpH3Error {
    /// WebTransport session error.
    #[error("WebTransport session error: {0}")]
    Session(String),

    /// Frame encoding/decoding error.
    #[error("Frame codec error: {0}")]
    Codec(String),

    /// Unsupported ATP feature.
    #[error("Unsupported feature in WebTransport context: {0}")]
    UnsupportedFeature(String),

    /// Browser security constraint violation.
    #[error("Browser security constraint: {0}")]
    SecurityConstraint(String),

    /// Stream management error.
    #[error("Stream error: {0}")]
    Stream(String),
}

/// Result type for ATP-over-H3 operations.
pub type AtpH3Result<T> = Result<T, AtpH3Error>;
