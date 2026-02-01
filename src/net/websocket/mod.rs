//! WebSocket protocol implementation (RFC 6455).
//!
//! This module provides complete WebSocket support with Cx integration for
//! structured concurrency and cancel-correctness.
//!
//! # Architecture
//!
//! - `frame`: Wire format encoding/decoding (RFC 6455 Section 5)
//! - `handshake`: HTTP upgrade negotiation (RFC 6455 Section 4)
//! - `close`: Close handshake protocol (RFC 6455 Section 7)
//! - `client`: WebSocket client with Cx integration
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::websocket::{WebSocket, Message};
//!
//! // Connect to a WebSocket server
//! let ws = WebSocket::connect(&cx, "ws://example.com/chat").await?;
//!
//! // Send a message
//! ws.send(&cx, Message::text("Hello!")).await?;
//!
//! // Receive messages
//! while let Some(msg) = ws.recv(&cx).await? {
//!     println!("Received: {:?}", msg);
//! }
//! ```

mod client;
mod close;
mod frame;
mod handshake;

pub use client::{Message, WebSocket, WebSocketConfig, WsConnectError};
pub use close::{CloseConfig, CloseHandshake, CloseReason, CloseState};
pub use frame::{apply_mask, CloseCode, Frame, FrameCodec, Opcode, Role, WsError};
pub use handshake::{
    compute_accept_key, ClientHandshake, HandshakeError, HttpRequest, HttpResponse,
    ServerHandshake, WsUrl,
};
