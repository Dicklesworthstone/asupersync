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
//! - `client` (native): Bounded requests with caller-owned connection driving
//! - [`error`]: HTTP/2 error types (RFC 7540 Section 7)

#[cfg(not(target_arch = "wasm32"))]
pub mod client;
pub mod connection;
pub mod error;
pub mod frame;
#[cfg(test)]
pub mod frame_golden_tests;
pub mod hpack;
#[cfg(not(target_arch = "wasm32"))]
pub mod listener;
pub mod settings;
pub mod stream;

// Re-export commonly used types
#[cfg(not(target_arch = "wasm32"))]
pub use client::{Http2Client, Http2ClientError, Http2RequestBuilder, Http2Response};
pub use connection::{Connection, ConnectionState, FrameCodec};
pub use error::{ErrorCode, H2Error};
pub use frame::{Frame, FrameHeader, FrameType, Setting};
pub use hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder, Header};
pub use settings::{Settings, SettingsBuilder};
pub use stream::{Stream, StreamState, StreamStore};
