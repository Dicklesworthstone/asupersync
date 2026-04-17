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

use crate::cx::Cx;
use crate::types::Time;

mod acceptor;
mod connector;
mod error;
mod stream;
mod types;

#[cfg(all(test, feature = "tls"))]
mod record_conformance_tests;

fn timeout_now() -> Time {
    Cx::current()
        .and_then(|current| current.timer_driver())
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

pub use acceptor::{ClientAuth, TlsAcceptor, TlsAcceptorBuilder};
pub use connector::{TlsConnector, TlsConnectorBuilder};
pub use error::TlsError;
pub use stream::TlsStream;
pub use types::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, PrivateKey, RootCertStore,
};

#[cfg(test)]
mod tests {
    use super::timeout_now;
    use crate::cx::Cx;
    use crate::time::{TimerDriverHandle, VirtualClock, wall_now};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use std::sync::Arc;

    #[test]
    fn timeout_now_uses_current_timer_driver_clock_when_available() {
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(42)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(virtual_clock);
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 0),
            TaskId::new_for_test(9, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver.clone()),
            None,
        );
        let _current = Cx::set_current(Some(cx));

        assert_eq!(timeout_now(), timer_driver.now());
    }

    #[test]
    fn timeout_now_falls_back_to_wall_now_when_no_context_is_active() {
        let before = wall_now();
        let now = timeout_now();
        let after = wall_now();

        assert!(now >= before);
        assert!(now <= after);
    }
}
