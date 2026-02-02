//! QUIC endpoint type.
//!
//! Provides cancel-correct endpoint management for QUIC connections.

use super::config::QuicConfig;
use super::connection::QuicConnection;
use super::error::QuicError;
use crate::cx::Cx;
use std::net::SocketAddr;
use std::sync::Arc;

/// A QUIC endpoint for creating client or server connections.
///
/// The endpoint manages the UDP socket and cryptographic configuration
/// for QUIC connections.
#[derive(Debug, Clone)]
pub struct QuicEndpoint {
    inner: quinn::Endpoint,
}

impl QuicEndpoint {
    /// Create a client endpoint bound to an ephemeral port.
    ///
    /// The client endpoint can connect to servers but cannot accept
    /// incoming connections.
    pub fn client(cx: &Cx, config: QuicConfig) -> Result<Self, QuicError> {
        cx.checkpoint().map_err(|_| QuicError::Cancelled)?;

        let mut root_certs = if let Some(store) = config.root_certs.clone() {
            store
        } else {
            let mut store = crate::tls::RootCertStore::empty();
            #[cfg(feature = "tls-native-roots")]
            {
                store
                    .extend_from_native_roots()
                    .map_err(|e| QuicError::TlsConfig(e.to_string()))?;
            }
            store.extend_from_webpki_roots();
            store
        };

        let mut crypto = if config.insecure_skip_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth()
        } else {
            if root_certs.is_empty() {
                return Err(QuicError::Config(
                    "no root certificates configured; enable tls-native-roots/tls-webpki-roots or provide RootCertStore".into(),
                ));
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(root_certs.into_inner())
                .with_no_client_auth()
        };

        if !config.alpn_protocols.is_empty() {
            crypto.alpn_protocols = config.alpn_protocols.clone();
        }

        let mut transport = config.to_transport_config();

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| QuicError::TlsConfig(e.to_string()))?,
        ));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { inner: endpoint })
    }

    /// Create a server endpoint bound to the specified address.
    ///
    /// The server endpoint can accept incoming connections.
    pub fn server(cx: &Cx, addr: SocketAddr, config: QuicConfig) -> Result<Self, QuicError> {
        cx.checkpoint()?;

        if !config.is_valid_for_server() {
            return Err(QuicError::Config(
                "server requires cert_chain and private_key".into(),
            ));
        }

        let cert_chain = config
            .cert_chain
            .as_ref()
            .unwrap()
            .iter()
            .map(|c| rustls::pki_types::CertificateDer::from(c.clone()))
            .collect::<Vec<_>>();

        let private_key = rustls::pki_types::PrivateKeyDer::try_from(
            config.private_key.as_ref().unwrap().clone(),
        )
        .map_err(|e| QuicError::TlsConfig(format!("invalid private key: {e}")))?;

        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| QuicError::TlsConfig(e.to_string()))?;

        if !config.alpn_protocols.is_empty() {
            crypto.alpn_protocols = config.alpn_protocols.clone();
        }

        let transport = config.to_transport_config();

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .map_err(|e| QuicError::TlsConfig(e.to_string()))?,
        ));
        server_config.transport_config(Arc::new(transport));

        let endpoint = quinn::Endpoint::server(server_config, addr)?;

        Ok(Self { inner: endpoint })
    }

    /// Connect to a remote QUIC server.
    ///
    /// The `server_name` is used for TLS server name indication (SNI).
    pub async fn connect(
        &self,
        cx: &Cx,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuicConnection, QuicError> {
        cx.checkpoint()?;

        let connecting = self.inner.connect(addr, server_name)?;

        // Wait for the connection to complete
        let connection = connecting.await?;

        Ok(QuicConnection::new(connection))
    }

    /// Connect with a custom client configuration.
    pub async fn connect_with(
        &self,
        cx: &Cx,
        addr: SocketAddr,
        server_name: &str,
        config: quinn::ClientConfig,
    ) -> Result<QuicConnection, QuicError> {
        cx.checkpoint()?;

        let connecting = self.inner.connect_with(config, addr, server_name)?;
        let connection = connecting.await?;

        Ok(QuicConnection::new(connection))
    }

    /// Accept an incoming connection.
    ///
    /// Returns `None` if the endpoint is closed.
    pub async fn accept(&self, cx: &Cx) -> Result<QuicConnection, QuicError> {
        cx.checkpoint()?;

        let incoming = self.inner.accept().await.ok_or(QuicError::EndpointClosed)?;

        let connection = incoming.await?;

        Ok(QuicConnection::new(connection))
    }

    /// Get the local address this endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, QuicError> {
        self.inner.local_addr().map_err(QuicError::from)
    }

    /// Close the endpoint, refusing new connections.
    ///
    /// Existing connections remain open until individually closed.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code.into(), reason);
    }

    /// Wait for the endpoint to close completely.
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }

    /// Get a reference to the inner quinn endpoint.
    #[must_use]
    pub fn inner(&self) -> &quinn::Endpoint {
        &self.inner
    }
}

/// Skip server certificate verification (for testing).
///
/// WARNING: This is insecure and should only be used in controlled environments.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
