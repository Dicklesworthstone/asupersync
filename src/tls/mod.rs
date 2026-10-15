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

#[cfg(any(test, feature = "tls"))]
use crate::cx::Cx;
#[cfg(any(test, feature = "tls"))]
use crate::types::Time;

mod acceptor;
mod connector;
#[cfg(feature = "tls")]
pub(crate) mod der_min;
mod error;
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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

    // --- crypto provider selection (tls-core / tls-ring) ---------------

    /// Public parser fixture from rustls-pemfile 2.2.0 tests/data/crl.pem
    /// (Apache-2.0 / ISC / MIT), issued by a CA unrelated to the test server.
    #[cfg(feature = "tls")]
    pub(crate) const RUSTLS_PEMFILE_CRL_PEM: &[u8] = b"-----BEGIN X509 CRL-----\n\
MIICiTBzAgEBMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMMD3Bvbnl0b3duIFJT\n\
QSBDQRcNMjMwNjI3MDgyODEyWhcNMjMwNzI3MDgyODEyWjAVMBMCAgHIFw0yMzA2\n\
MjcwODI3NTlaoA4wDDAKBgNVHRQEAwIBAjANBgkqhkiG9w0BAQsFAAOCAgEAP6EX\n\
9+hxjx/AqdBpynZXjGkEqigBcLcJ2PADOXngdQI1jC0WuYnZymUimemeULtt8X+1\n\
ai2KxAuF1m4NEKZsrGKvO+/9s/X1xbGroyHSAMKtZafFopFpoB2aNbYlx7yIyLtD\n\
BBIZIF50g20U+3izqpHutTD10itdk9TLsSceJHpwTkNJtaWMkOfBV28nKzEzVutV\n\
f6WzRpURGzui6nQy7aIqImeanpoBoz323psMfC32U0uMBCZltyHNqsX58/2Uhucx\n\
0IPnitNuhv4scCPf/jeRfGIWDrTf1/25LDzRxyg1S4z9aa+3GM4O3dqy4igZEhgT\n\
q3pjlJ2hUL5E0oqbZDIQD1SN8UUUv5N2AjwZcxVBNnYeGyuO7YpTBYiu62o73iL2\n\
CjgElfaMq/9hEr9GR9kJozh7VTxtQPbnr4DiucQvhv8o/A1z+zkC0gj8iCLFtDbO\n\
8bvDowcdle9LKkrLaBe6sO+fSH/I9Wj8vrEJKsuwaEraIdEaq2VrIMUPEWN0/MH9\n\
vTwHyadGSMK4CWtrn9fCAgSLw6NX74D7Cx1IaS8vstMjpeUqOS0dk5ThiW47HceB\n\
DTko7rV5N+RGH2nW1ynLoZKCJQqqZcLilFMyKPui3jifJnQlMFi54jGVgg/D6UQn\n\
7dA7wb2ux/1hSiaarp+mi7ncVOyByz6/WQP8mfc=\n\
-----END X509 CRL-----\n";

    #[cfg(feature = "tls-ring")]
    type Provider = Arc<rustls::crypto::CryptoProvider>;

    #[cfg(feature = "tls")]
    #[test]
    fn a_missing_crypto_provider_is_a_configuration_error_naming_the_fixes() {
        let err = super::select_crypto_provider(None, || None, || None)
            .expect_err("nothing to resolve must not produce a provider");
        let super::TlsError::Configuration(message) = err else {
            panic!("expected a configuration error, got {err:?}");
        };
        for fix in [
            "crypto_provider()",
            "CryptoProvider::install_default()",
            "tls-ring",
        ] {
            assert!(message.contains(fix), "{message:?} does not name {fix}");
        }
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn the_ring_build_links_the_ring_provider() {
        let linked = super::linked_crypto_provider().expect("tls-ring links ring");
        let ring = rustls::crypto::ring::default_provider();
        let suites = |provider: &rustls::crypto::CryptoProvider| {
            provider
                .cipher_suites
                .iter()
                .map(|suite| suite.suite())
                .collect::<Vec<_>>()
        };
        assert_eq!(suites(&linked), suites(&ring));
    }

    #[cfg(all(feature = "tls", not(feature = "tls-ring")))]
    #[test]
    fn the_core_build_links_no_provider() {
        assert!(super::linked_crypto_provider().is_none());
    }

    #[cfg(feature = "tls-ring")]
    fn ring_provider(suites: &[rustls::CipherSuite]) -> Provider {
        let mut provider = rustls::crypto::ring::default_provider();
        if !suites.is_empty() {
            provider
                .cipher_suites
                .retain(|suite| suites.contains(&suite.suite()));
            assert_eq!(
                provider.cipher_suites.len(),
                suites.len(),
                "ring has {suites:?}"
            );
        }
        Arc::new(provider)
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn crypto_provider_resolution_is_explicit_then_linked_then_process_default() {
        let explicit = ring_provider(&[]);
        let linked = ring_provider(&[]);
        let process_default = ring_provider(&[]);

        // Each later source is consulted only when every earlier one is absent.
        let chosen = super::select_crypto_provider(
            Some(&explicit),
            || panic!("the linked provider must not be consulted"),
            || panic!("the process default must not be consulted"),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&chosen, &explicit));

        let chosen = super::select_crypto_provider(
            None,
            || Some(Arc::clone(&linked)),
            || panic!("the process default must not be consulted"),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&chosen, &linked));

        let chosen =
            super::select_crypto_provider(None, || None, || Some(Arc::clone(&process_default)))
                .unwrap();
        assert!(Arc::ptr_eq(&chosen, &process_default));
    }

    #[cfg(feature = "tls-ring")]
    const TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
    #[cfg(feature = "tls-ring")]
    const TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

    #[cfg(feature = "tls-ring")]
    fn test_connector() -> super::TlsConnectorBuilder {
        super::TlsConnectorBuilder::new()
            .add_root_certificates(super::Certificate::from_pem(TEST_CERT_PEM).unwrap())
            .handshake_timeout(std::time::Duration::from_secs(5))
    }

    #[cfg(feature = "tls-ring")]
    fn test_acceptor() -> super::TlsAcceptorBuilder {
        super::TlsAcceptorBuilder::new(
            super::CertificateChain::from_pem(TEST_CERT_PEM).unwrap(),
            super::PrivateKey::from_pem(TEST_KEY_PEM).unwrap(),
        )
        .handshake_timeout(std::time::Duration::from_secs(5))
    }

    /// What one side of a completed handshake reports.
    #[cfg(feature = "tls-ring")]
    #[derive(Debug)]
    struct Negotiated {
        suite: Option<rustls::CipherSuite>,
        group: Option<rustls::NamedGroup>,
        peer_chain: Option<Vec<Vec<u8>>>,
        peer_leaf: Option<Vec<u8>>,
    }

    /// Runs one in-process handshake and returns what each side negotiated,
    /// or that side's error.
    #[cfg(feature = "tls-ring")]
    fn handshake(
        connector: &super::TlsConnector,
        acceptor: &super::TlsAcceptor,
    ) -> (Result<Negotiated, String>, Result<Negotiated, String>) {
        use crate::net::tcp::VirtualTcpStream;
        use futures_lite::future::zip;

        fn report<IO>(
            side: Result<super::TlsStream<IO>, super::TlsError>,
        ) -> Result<Negotiated, String> {
            let stream = side.map_err(|err| err.to_string())?;
            Ok(Negotiated {
                suite: stream.negotiated_cipher_suite(),
                group: stream.negotiated_key_exchange_group(),
                peer_chain: stream.peer_certificate_chain_der(),
                peer_leaf: stream.peer_leaf_certificate_der(),
            })
        }

        let mut outcome = None;
        crate::test_utils::run_test_with_cx(|_cx| async {
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5400".parse().unwrap(),
                "127.0.0.1:5401".parse().unwrap(),
            );
            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;
            outcome = Some((report(client), report(server)));
        });
        outcome.expect("the handshake future ran to completion")
    }

    /// The cipher suite each side negotiated, or that side's error.
    #[cfg(feature = "tls-ring")]
    fn negotiated_suites(
        connector: &super::TlsConnector,
        acceptor: &super::TlsAcceptor,
    ) -> (
        Result<rustls::CipherSuite, String>,
        Result<rustls::CipherSuite, String>,
    ) {
        let suite = |side: Result<Negotiated, String>| {
            side.and_then(|n| {
                n.suite
                    .ok_or_else(|| "handshake completed without a cipher suite".to_owned())
            })
        };
        let (client, server) = handshake(connector, acceptor);
        (suite(client), suite(server))
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn builders_keep_the_explicit_provider_instance() {
        let provider = ring_provider(&[]);
        let connector = test_connector()
            .crypto_provider(Arc::clone(&provider))
            .build()
            .unwrap();
        assert!(Arc::ptr_eq(connector.config().crypto_provider(), &provider));
        let acceptor = test_acceptor()
            .crypto_provider(Arc::clone(&provider))
            .build()
            .unwrap();
        assert!(Arc::ptr_eq(acceptor.config().crypto_provider(), &provider));
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn an_explicit_client_provider_decides_the_negotiated_suite() {
        use rustls::CipherSuite::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256};

        let acceptor = test_acceptor().build().unwrap();
        // Two different restrictions negotiate two different suites, so the
        // result cannot come from a provider that ignores the explicit one.
        for wanted in [TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256] {
            let connector = test_connector()
                .crypto_provider(ring_provider(&[wanted]))
                .build()
                .unwrap();
            let (client, server) = negotiated_suites(&connector, &acceptor);
            assert_eq!(client, Ok(wanted));
            assert_eq!(server, Ok(wanted));
        }
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn an_explicit_server_provider_decides_the_negotiated_suite() {
        use rustls::CipherSuite::{TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256};

        let connector = test_connector().build().unwrap();
        for wanted in [TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256] {
            let acceptor = test_acceptor()
                .crypto_provider(ring_provider(&[wanted]))
                .build()
                .unwrap();
            let (client, server) = negotiated_suites(&connector, &acceptor);
            assert_eq!(client, Ok(wanted));
            assert_eq!(server, Ok(wanted));
        }
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn the_stream_reports_the_key_exchange_and_the_peer_chain() {
        let acceptor = test_acceptor().build().unwrap();
        let fixture = super::Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let fixture_der: Vec<Vec<u8>> = fixture.iter().map(|c| c.as_der().to_vec()).collect();
        // An explicit provider limited to one group decides the key exchange,
        // and two different limits give two different groups.
        for group in [rustls::NamedGroup::secp256r1, rustls::NamedGroup::X25519] {
            let mut provider = rustls::crypto::ring::default_provider();
            provider.kx_groups.retain(|kx| kx.name() == group);
            assert_eq!(provider.kx_groups.len(), 1, "ring has {group:?}");
            let connector = test_connector()
                .crypto_provider(Arc::new(provider))
                .build()
                .unwrap();
            let (client, server) = handshake(&connector, &acceptor);
            let (client, server) = (client.unwrap(), server.unwrap());
            assert_eq!(client.group, Some(group));
            assert_eq!(server.group, Some(group));
            // The client saw the server's chain; the server, without client
            // authentication, saw none.
            assert_eq!(client.peer_chain.as_ref(), Some(&fixture_der));
            assert_eq!(client.peer_leaf.as_ref(), fixture_der.first());
            assert_eq!(server.peer_chain, None);
            assert_eq!(server.peer_leaf, None);
        }
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn providers_without_a_common_suite_fail_the_handshake() {
        use rustls::CipherSuite::{TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256};

        let connector = test_connector()
            .crypto_provider(ring_provider(&[TLS13_CHACHA20_POLY1305_SHA256]))
            .build()
            .unwrap();
        let acceptor = test_acceptor()
            .crypto_provider(ring_provider(&[TLS13_AES_256_GCM_SHA384]))
            .build()
            .unwrap();
        let (client, server) = negotiated_suites(&connector, &acceptor);
        assert!(client.is_err(), "client negotiated {client:?}");
        assert!(server.is_err(), "server negotiated {server:?}");
    }

    /// A ring provider that verifies no RSA signature: a client using it
    /// offers only ECDSA and EdDSA schemes, which the RSA test server cannot
    /// sign with.
    #[cfg(feature = "tls-ring")]
    fn ring_provider_without_rsa_signatures() -> Provider {
        use rustls::SignatureScheme;

        let mut provider = rustls::crypto::ring::default_provider();
        let mapping: Vec<_> = provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .copied()
            .filter(|(scheme, _)| {
                !matches!(
                    scheme,
                    SignatureScheme::RSA_PKCS1_SHA256
                        | SignatureScheme::RSA_PKCS1_SHA384
                        | SignatureScheme::RSA_PKCS1_SHA512
                        | SignatureScheme::RSA_PSS_SHA256
                        | SignatureScheme::RSA_PSS_SHA384
                        | SignatureScheme::RSA_PSS_SHA512
                )
            })
            .collect();
        assert!(!mapping.is_empty(), "ring verifies some non-RSA scheme");
        provider.signature_verification_algorithms.mapping = Box::leak(mapping.into_boxed_slice());
        Arc::new(provider)
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn the_crl_verifier_uses_the_connection_provider() {
        // With CRLs, the connector installs its own WebPkiServerVerifier. Built
        // with plain `WebPkiServerVerifier::builder`, it took rustls's process
        // default (installing ring), so it offered RSA schemes the connection's
        // provider does not verify and this handshake succeeded.
        let acceptor = test_acceptor().build().unwrap();
        let no_rsa = ring_provider_without_rsa_signatures();
        for with_crl in [false, true] {
            let mut connector = test_connector().crypto_provider(Arc::clone(&no_rsa));
            if with_crl {
                connector = connector.with_crl_pem(RUSTLS_PEMFILE_CRL_PEM.to_vec());
            }
            let (client, server) = negotiated_suites(&connector.build().unwrap(), &acceptor);
            assert!(
                client.is_err() && server.is_err(),
                "with_crl={with_crl}: an RSA server must not authenticate to a client \
                 whose provider verifies no RSA signature ({client:?}, {server:?})"
            );
        }
        // The honest counterpart: the same CRL with a full provider succeeds.
        let connector = test_connector()
            .crypto_provider(ring_provider(&[]))
            .with_crl_pem(RUSTLS_PEMFILE_CRL_PEM.to_vec())
            .build()
            .unwrap();
        let (client, server) = negotiated_suites(&connector, &acceptor);
        assert!(client.is_ok() && server.is_ok(), "{client:?} / {server:?}");
    }
}
