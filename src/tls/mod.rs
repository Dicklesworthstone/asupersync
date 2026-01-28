//! TLS/SSL support via rustls.
//!
//! This module provides TLS client and server support built on rustls.
//! It integrates with the asupersync async runtime's I/O traits.
//!
//! # Features
//!
//! - `tls` - Enable basic TLS support via rustls
//! - `tls-native-roots` - Use platform root certificates
//! - `tls-webpki-roots` - Use Mozilla root certificates
//!
//! # Client Example
//!
//! ```ignore
//! use asupersync::tls::{TlsConnector, TlsConnectorBuilder};
//!
//! // Create a connector with webpki roots
//! let connector = TlsConnectorBuilder::new()
//!     .with_webpki_roots()
//!     .alpn_http()
//!     .build()?;
//!
//! // Connect to a server
//! let tls_stream = connector.connect("example.com", tcp_stream).await?;
//! ```
//!
//! # Cancel-Safety
//!
//! TLS handshake operations are NOT cancel-safe. If cancelled mid-handshake,
//! the connection is in an undefined state and should be dropped. Once the
//! handshake completes, read/write operations follow the cancel-safety
//! properties of the underlying I/O traits.

mod connector;
mod error;
mod types;

pub use connector::{TlsConnector, TlsConnectorBuilder};
pub use error::TlsError;
pub use types::{Certificate, CertificateChain, PrivateKey, RootCertStore};
