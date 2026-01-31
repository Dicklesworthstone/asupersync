//! TLS/SSL support via rustls.
//!
// Allow clippy lints that are allowed at the crate level but not picked up in this module
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
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

use crate::time::{TimeSource, WallClock};
use crate::types::Time;
use std::sync::OnceLock;

mod acceptor;
mod connector;
mod error;
mod stream;
mod types;

fn wall_clock_now() -> Time {
    static CLOCK: OnceLock<WallClock> = OnceLock::new();
    CLOCK.get_or_init(WallClock::new).now()
}

pub use acceptor::{ClientAuth, TlsAcceptor, TlsAcceptorBuilder};
pub use connector::{TlsConnector, TlsConnectorBuilder};
pub use error::TlsError;
pub use stream::TlsStream;
pub use types::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, PrivateKey, RootCertStore,
};
