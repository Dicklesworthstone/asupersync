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
//! - `tls` - Enable basic TLS support via rustls, with the ring crypto provider
//! - `tls-ring` - The same as `tls`
//! - `tls-core` - The TLS code without a crypto provider; see below
//! - `tls-native-roots` - Use platform root certificates
//! - `tls-webpki-roots` - Use Mozilla root certificates
//!
//! # Crypto Provider
//!
//! Every builder that needs a rustls `CryptoProvider` picks it in this order:
//!
//! 1. the provider passed to `crypto_provider` on [`TlsConnectorBuilder`] or
//!    [`TlsAcceptorBuilder`];
//! 2. the ring provider, when `tls` or `tls-ring` links it;
//! 3. rustls's process default, set with `CryptoProvider::install_default`;
//! 4. otherwise building fails with [`TlsError::Configuration`].
//!
//! A `tls-core` build links no provider, so it relies on 1 or 3. That lets a
//! consumer that must not link ring use a different provider, for example a
//! pure-Rust one.
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
//!
//! With TLS enabled, `TlsConnector::connect_with_cx` and
//! `TlsAcceptor::accept_with_cx` additionally observe the supplied context while
//! the handshake is parked. Acknowledged cancellation drops the unfinished
//! connection rather than waiting for another transport event. Existing
//! certificate, pinning, ALPN, early-data and timeout policies still apply.

#[cfg(any(test, feature = "tls"))]
use crate::cx::Cx;
#[cfg(any(test, feature = "tls"))]
use crate::types::Time;

mod acceptor;
#[cfg(feature = "tls")]
mod channel_binding;
mod connector;
#[cfg(feature = "tls")]
pub(crate) mod der_min;
mod error;
#[cfg(feature = "tls")]
mod handshake;
mod stream;
mod types;

#[cfg(all(test, feature = "tls"))]
mod record_conformance_tests;

#[cfg(any(test, feature = "tls"))]
fn timeout_now() -> Time {
    Cx::current()
        .and_then(|current| current.timer_driver())
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

pub use acceptor::EarlyDataReplayProtection;
#[cfg(feature = "tls")]
pub use acceptor::TlsCertificates;
pub use acceptor::{ClientAuth, TlsAcceptor, TlsAcceptorBuilder};
pub use connector::{TlsConnector, TlsConnectorBuilder};
pub use error::TlsError;
pub use stream::TlsStream;
pub use types::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, PrivateKey, RootCertStore,
};

/// Resolves the crypto provider for a TLS configuration in the order the
/// module documentation gives: `explicit`, then the linked ring provider, then
/// rustls's process default.
///
/// # Errors
///
/// Returns [`TlsError::Configuration`] when none of the three is available.
#[cfg(feature = "tls")]
pub(crate) fn resolve_crypto_provider(
    explicit: Option<&std::sync::Arc<rustls::crypto::CryptoProvider>>,
) -> Result<std::sync::Arc<rustls::crypto::CryptoProvider>, TlsError> {
    select_crypto_provider(explicit, linked_crypto_provider, || {
        rustls::crypto::CryptoProvider::get_default().cloned()
    })
}

#[cfg(feature = "tls")]
fn select_crypto_provider(
    explicit: Option<&std::sync::Arc<rustls::crypto::CryptoProvider>>,
    linked: impl FnOnce() -> Option<std::sync::Arc<rustls::crypto::CryptoProvider>>,
    process_default: impl FnOnce() -> Option<std::sync::Arc<rustls::crypto::CryptoProvider>>,
) -> Result<std::sync::Arc<rustls::crypto::CryptoProvider>, TlsError> {
    if let Some(provider) = explicit {
        return Ok(std::sync::Arc::clone(provider));
    }
    linked().or_else(process_default).ok_or_else(|| {
        TlsError::Configuration(
            "no rustls crypto provider: pass one with crypto_provider(), install a process \
             default with CryptoProvider::install_default(), or enable the tls-ring feature"
                .into(),
        )
    })
}

/// The provider this build links: ring under `tls` / `tls-ring`, none under
/// `tls-core` alone.
#[cfg(feature = "tls")]
fn linked_crypto_provider() -> Option<std::sync::Arc<rustls::crypto::CryptoProvider>> {
    #[cfg(feature = "tls-ring")]
    {
        Some(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
    }
    #[cfg(not(feature = "tls-ring"))]
    {
        None
    }
}

#[cfg(test)]
#[path = "mod_inline_tests.rs"]
mod tests;
