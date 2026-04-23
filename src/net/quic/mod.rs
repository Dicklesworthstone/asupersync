//! QUIC protocol support via quinn.
//!
//! This module provides cancel-correct QUIC connections with structured
//! concurrency support, wrapping the quinn library with Cx integration.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::quic::{QuicConfig, QuicEndpoint};
//!
//! // Create a client endpoint
//! let endpoint = QuicEndpoint::client(&cx, QuicConfig::new())?;
//!
//! // Connect to a server
//! let connection = endpoint.connect(&cx, addr, "example.com").await?;
//!
//! // Open a bidirectional stream
//! let (mut send, mut recv) = connection.open_bi(&cx).await?;
//!
//! // Send and receive data
//! send.write_all(&cx, b"Hello, QUIC!").await?;
//! let response = recv.read_to_end(&cx, 1024).await?;
//!
//! // Close the connection gracefully
//! connection.close(&cx, 0, b"done").await?;
//! ```
//!
//! # Cancellation Semantics
//!
//! All QUIC operations respect Cx cancellation:
//! - Endpoint operations check cancellation at entry
//! - Stream operations check cancellation before I/O
//! - On connection shutdown, streams are reset/stopped appropriately
//! - Connection close marks streams for cleanup
//!
//! # Feature Flag
//!
//! This compatibility wrapper requires the `quic-compat` feature to be enabled:
//!
//! ```toml
//! [dependencies]
//! asupersync = { version = "0.1", features = ["quic-compat"] }
//! ```

mod config;
mod connection;
mod endpoint;
mod error;
mod stream;

#[cfg(test)]
pub mod conformance;

pub use config::{ClientAuth, QuicConfig};
pub use connection::QuicConnection;
pub use endpoint::{QuicEndpoint, QuicIncoming};
pub use error::QuicError;
pub use stream::{RecvStream, SendStream, StreamTracker};
