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
//! - `server`: WebSocket server/acceptor with Cx integration
//!
//! # Client Example
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
//!
//! # Server Example
//!
//! ```ignore
//! use asupersync::net::websocket::{WebSocketAcceptor, Message};
//!
//! // Create acceptor
//! let acceptor = WebSocketAcceptor::new().protocol("chat");
//!
//! // Accept upgrade request
//! let ws = acceptor.accept(&cx, request_bytes, tcp_stream).await?;
//!
//! // Echo messages
//! while let Some(msg) = ws.recv(&cx).await? {
//!     ws.send(&cx, msg).await?;
//! }
//! ```

mod client;
mod close;
mod frame;
mod handshake;
mod server;

pub use client::{Message, WebSocket, WebSocketConfig, WsConnectError};
pub use close::{CloseConfig, CloseHandshake, CloseReason, CloseState};
pub use frame::{apply_mask, CloseCode, Frame, FrameCodec, Opcode, Role, WsError};
pub use handshake::{
    compute_accept_key, AcceptResponse, ClientHandshake, HandshakeError, HttpRequest,
    HttpResponse, ServerHandshake, WsUrl,
};
pub use server::{ServerWebSocket, WebSocketAcceptor, WsAcceptError};
