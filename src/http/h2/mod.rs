//! HTTP/2 protocol implementation.
//!
//! This module provides an HTTP/2 implementation following RFC 7540 and RFC 7541 (HPACK).
//!
//! # Components
//!
//! - [`frame`]: HTTP/2 frame types and encoding/decoding (RFC 7540 Section 4)
//! - [`hpack`]: HPACK header compression (RFC 7541)
//! - [`settings`]: HTTP/2 connection settings (RFC 7540 Section 6.5)
//! - [`stream`]: Stream state management (RFC 7540 Section 5)
//! - [`connection`]: Connection management
//! - [`error`]: HTTP/2 error types (RFC 7540 Section 7)

pub mod connection;
pub mod error;
pub mod frame;
#[cfg(test)]
pub mod frame_golden_tests;
pub mod hpack;
pub mod settings;
pub mod stream;

// Re-export commonly used types
pub use connection::{Connection, ConnectionState, FrameCodec};
pub use error::{ErrorCode, H2Error};
pub use frame::{Frame, FrameHeader, FrameType, Setting};
pub use hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder, Header};
pub use settings::{Settings, SettingsBuilder};
pub use stream::{Stream, StreamState, StreamStore};
