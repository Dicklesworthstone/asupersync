//! Real QUIC/TLS-1.3 handshake driver wrapping `rustls::quic`.
//!
//! # Why this exists
//!
//! Until this module, the native QUIC stack had **no real handshake driver**:
//! the `QuicFrame::Crypto` handler was a no-op, keys were installed out-of-band,
//! and every "loopback e2e" used deterministic in-process transitions
//! ([`super::endpoint_api::establish_loopback`]) rather than a TLS exchange over a
//! socket. That made cross-machine ATP-over-QUIC impossible — there was no way to
//! reach the `Established` state from two endpoints that only share a UDP path.
//!
//! This driver fills exactly that gap. It owns a [`rustls::quic::Connection`] and
//! runs the canonical QUIC/TLS-1.3 drive loop: pull outbound handshake bytes with
//! [`rustls::quic::Connection::write_hs`] (to be carried as CRYPTO frames),
//! feed received CRYPTO bytes with [`rustls::quic::Connection::read_hs`], and
//! install each [`rustls::quic::KeyChange`] into the existing
//! [`RustlsQuicCryptoProvider`] as the Initial → Handshake → 1-RTT encryption
//! levels become available. Server-certificate verification is performed by
//! rustls inside the client config's verifier (wire in
//! [`super::tls::QuicServerIdentityVerifier`]'s WebPKI verifier — no insecure
//! skip-verify path).
//!
//! # Scope boundary
//!
//! `write_hs`/`read_hs` operate on **plaintext** TLS handshake bytes. The packet
//! AEAD/header-protection (Initial/Handshake long-header and 1-RTT short-header)
//! is a *separate* layer ([`super::connection_manager::ConnectionRouter`]) that
//! *consumes* the keys this driver installs. This module is therefore the
//! TLS-key-agreement half and is unit-testable in isolation (two drivers pumping
//! handshake bytes between each other, no packets, no socket). Wiring it into the
//! CRYPTO frame handler + long-header packet I/O + connect/accept is tracked
//! separately (P1/P2 of the ATP-over-QUIC plan).

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::quic::{ClientConnection, Connection, KeyChange, ServerConnection, Version};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use super::tls::{
    PacketProtectionSpace, QuicHandshakeTranscript, QuicPacketProtectionProvider, QuicTlsError,
    RustlsQuicCryptoProvider, RustlsQuicProviderSide,
};

/// ALPN protocol identifier for the ATP-over-QUIC transport. QUIC mandates ALPN,
/// and both peers must advertise a common protocol or the handshake fails closed.
pub const ATP_QUIC_ALPN: &[u8] = b"atpq/1";

fn handshake_failure(code: &'static str) -> QuicTlsError {
    QuicTlsError::CryptoProviderFailure {
        provider: "rustls-quic-handshake",
        code,
    }
}

/// Encryption level a chunk of handshake (CRYPTO) data belongs to. The packet
/// layer maps these to QUIC packet number spaces (Initial/Handshake/1-RTT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeLevel {
    /// Initial packet number space (CRYPTO carried in long-header Initial packets).
    Initial,
    /// Handshake packet number space (long-header Handshake packets).
    Handshake,
    /// Application (1-RTT) packet number space (short-header packets).
    OneRtt,
}

/// A contiguous run of outbound handshake bytes at a single encryption level.
#[derive(Debug, Clone)]
pub struct HandshakeSegment {
    /// Encryption level these bytes must be sent at.
    pub level: HandshakeLevel,
    /// Plaintext TLS handshake bytes to carry in CRYPTO frames at `level`.
    pub data: Vec<u8>,
}

/// Drives a real QUIC/TLS-1.3 handshake via rustls, installing the derived AEAD
/// keys into the packet-protection provider as each level becomes available.
pub struct QuicHandshakeDriver {
    tls: Connection,
    provider: RustlsQuicCryptoProvider,
    transcript: QuicHandshakeTranscript,
    write_level: HandshakeLevel,
    handshake_keys_installed: bool,
    one_rtt_keys_installed: bool,
}

impl QuicHandshakeDriver {
    /// Start a client handshake against `server_name`, advertising `transport_params`.
    pub fn client(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        let conn = ClientConnection::new(config, Version::V1, server_name, transport_params)
            .map_err(|_| handshake_failure("client_connection_init"))?;
        let provider = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Client)?;
        Ok(Self::new(Connection::Client(conn), provider))
    }

    /// Start a server handshake, advertising `transport_params`.
    pub fn server(
        config: Arc<ServerConfig>,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        let conn = ServerConnection::new(config, Version::V1, transport_params)
            .map_err(|_| handshake_failure("server_connection_init"))?;
        let provider = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Server)?;
        Ok(Self::new(Connection::Server(conn), provider))
    }

    fn new(tls: Connection, provider: RustlsQuicCryptoProvider) -> Self {
        Self {
            tls,
            provider,
            transcript: QuicHandshakeTranscript::new(),
            write_level: HandshakeLevel::Initial,
            handshake_keys_installed: false,
            one_rtt_keys_installed: false,
        }
    }

    /// Install Initial-space packet-protection keys derived from the client's
    /// chosen Destination Connection ID (RFC 9001 §5.2). The packet layer needs
    /// these to protect/unprotect Initial packets; the TLS exchange itself does
    /// not (it operates on plaintext), so the in-isolation handshake test can
    /// skip this.
    pub fn install_initial_keys(&mut self, dcid: &[u8]) -> Result<(), QuicTlsError> {
        self.provider
            .derive_keys(PacketProtectionSpace::Initial, &self.transcript, dcid)
            .map(|_| ())
    }

    /// Drain all currently-available outbound handshake bytes, installing each
    /// key change into the provider and advancing the write level as the
    /// handshake crosses encryption boundaries. Returns one segment per level
    /// that produced data.
    pub fn pump_outbound(&mut self) -> Result<Vec<HandshakeSegment>, QuicTlsError> {
        let mut segments = Vec::new();
        loop {
            let mut buf = Vec::new();
            let key_change = self.tls.write_hs(&mut buf);
            let produced = !buf.is_empty();
            if produced {
                // The data emitted alongside a KeyChange belongs to the level in
                // effect *before* the change, so record it before advancing.
                segments.push(HandshakeSegment {
                    level: self.write_level,
                    data: buf,
                });
            }
            match key_change {
                Some(KeyChange::Handshake { keys }) => {
                    self.provider
                        .install_key_change(KeyChange::Handshake { keys }, &self.transcript)?;
                    self.handshake_keys_installed = true;
                    self.write_level = HandshakeLevel::Handshake;
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    self.provider
                        .install_key_change(KeyChange::OneRtt { keys, next }, &self.transcript)?;
                    self.one_rtt_keys_installed = true;
                    self.write_level = HandshakeLevel::OneRtt;
                }
                None => {
                    if !produced {
                        break;
                    }
                }
            }
        }
        Ok(segments)
    }

    /// Feed received plaintext handshake bytes (the payload of CRYPTO frames) to
    /// the TLS state machine. Bytes from different encryption levels must be
    /// supplied in separate calls (rustls requirement); the packet layer already
    /// delivers them per-space, so callers pass one space's CRYPTO data per call.
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<(), QuicTlsError> {
        self.tls.read_hs(data).map_err(|_| {
            // Surface a fatal alert as a redacted, stable code if one arose.
            if self.tls.alert().is_some() {
                handshake_failure("read_hs_fatal_alert")
            } else {
                handshake_failure("read_hs_failed")
            }
        })
    }

    /// True once the TLS handshake has fully completed for this endpoint.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.tls.is_handshaking()
    }

    /// True once 1-RTT (application) keys have been installed.
    #[must_use]
    pub fn one_rtt_keys_installed(&self) -> bool {
        self.one_rtt_keys_installed
    }

    /// True once Handshake-space keys have been installed.
    #[must_use]
    pub fn handshake_keys_installed(&self) -> bool {
        self.handshake_keys_installed
    }

    /// The peer's TLS-encoded QUIC transport parameters, once received.
    #[must_use]
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.tls.quic_transport_parameters()
    }

    /// Borrow the packet-protection provider holding the installed keys.
    #[must_use]
    pub fn provider(&self) -> &RustlsQuicCryptoProvider {
        &self.provider
    }

    /// Consume the driver, yielding the provider for use by the packet layer.
    #[must_use]
    pub fn into_provider(self) -> RustlsQuicCryptoProvider {
        self.provider
    }
}

/// Build a TLS-1.3-only client config for QUIC that verifies the server chain
/// against `roots` (WebPKI) and advertises `alpn`. No insecure skip-verify path.
pub fn client_config(
    roots: Vec<CertificateDer<'static>>,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<ClientConfig>, QuicTlsError> {
    let mut root_store = RootCertStore::empty();
    for cert in roots {
        root_store
            .add(cert)
            .map_err(|_| handshake_failure("client_root_add_failed"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| handshake_failure("client_protocol_versions"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Ok(Arc::new(config))
}

/// Build a TLS-1.3-only server config for QUIC presenting `cert_chain`/`key` and
/// advertising `alpn`.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<ServerConfig>, QuicTlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| handshake_failure("server_protocol_versions"))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|_| handshake_failure("server_single_cert"))?;
    config.alpn_protocols = alpn;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical CA + leaf chain (P-256), valid ~100 years, generated with openssl
    // for the in-process handshake test. The leaf carries SAN DNS:localhost /
    // IP:127.0.0.1 and the serverAuth EKU that rustls-webpki requires; the client
    // trusts the CA, so this exercises the REAL WebPKI verifier path end-to-end
    // (no insecure skip-verify).
    const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwTCCAWigAwIBAgIUTQyiZ96ufyKHVqRYRZBXpRQABGMwCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAUMRIwEAYDVQQDDAlhdHBxLXRlc3QwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBbxlDvlrJDWhuXLXcrwcK4\n\
eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hdo4GSMIGPMBoGA1UdEQQTMBGCCWxv\n\
Y2FsaG9zdIcEfwAAATATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA\n\
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUTWWIxYJyvXlJNVcDd8An36rhuMQw\n\
HwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNzvtYwCgYIKoZIzj0EAwIDRwAw\n\
RAIgOkNWPyvljX7zxCWN9sJ/rpX7XV5ubXvNrPdV70sF8oECIGtMuJr6XEmcump1\n\
YuX2YYZ2gAU6aNU/up/PediXcN5u\n\
-----END CERTIFICATE-----\n";

    const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpE59cRbMDhBIZaha\n\
UPAvB8O86PWbkhxy/8cx/FrSa1ShRANCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBb\n\
xlDvlrJDWhuXLXcrwcK4eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hd\n\
-----END PRIVATE KEY-----\n";

    const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBlDCCATugAwIBAgIUYOTxo/FMMZjqCnJT+IDmJ2BNux0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAXMRUwEwYDVQQDDAxhdHBxLXRlc3QtY2EwWTATBgcqhkjOPQIB\n\
BggqhkjOPQMBBwNCAASAsNg5paEJFgZwYGu7aCzsZYPyDyjzzcT7fi3O5JHGW0xA\n\
pTqjgqykWTDkyfwdITXWXIfrx2D2+QwoGXOV4OFSo2MwYTAdBgNVHQ4EFgQUG872\n\
eUJJNl9C6SZHmR9sCRNzvtYwHwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNz\n\
vtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID\n\
RwAwRAIgFLcs0Qdsy190QfKzpvLj28srfpw6wZ2PURF20N+twm8CIFZMWnG65VsE\n\
WkX8ykcdUfalGtZ1XFOTo+aaWs+3gyI1\n\
-----END CERTIFICATE-----\n";

    fn parse_one_cert(pem: &str) -> CertificateDer<'static> {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        rustls_pemfile::certs(&mut reader)
            .next()
            .expect("one cert")
            .expect("valid cert pem")
    }

    fn leaf_cert() -> CertificateDer<'static> {
        parse_one_cert(LEAF_CERT_PEM)
    }

    fn ca_cert() -> CertificateDer<'static> {
        parse_one_cert(CA_CERT_PEM)
    }

    fn leaf_key() -> PrivateKeyDer<'static> {
        let mut reader = std::io::BufReader::new(LEAF_KEY_PEM.as_bytes());
        rustls_pemfile::private_key(&mut reader)
            .expect("read key pem")
            .expect("one key")
    }

    fn drive_to_completion(client: &mut QuicHandshakeDriver, server: &mut QuicHandshakeDriver) {
        for _ in 0..16 {
            for seg in client.pump_outbound().expect("client pump") {
                server.read_handshake(&seg.data).expect("server read");
            }
            for seg in server.pump_outbound().expect("server pump") {
                client.read_handshake(&seg.data).expect("client read");
            }
            if client.is_complete() && server.is_complete() {
                return;
            }
        }
        panic!("handshake did not converge within bound");
    }

    #[test]
    fn real_tls13_handshake_completes_and_installs_one_rtt_keys() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");

        // Distinct, non-empty transport-parameter blobs prove they cross.
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        assert!(!client.is_complete());
        assert!(!server.is_complete());

        drive_to_completion(&mut client, &mut server);

        // Both sides reached a verified, completed TLS-1.3 handshake.
        assert!(client.is_complete(), "client handshake incomplete");
        assert!(server.is_complete(), "server handshake incomplete");

        // 1-RTT (application) keys were derived from the wire transcript on both.
        assert!(client.one_rtt_keys_installed(), "client missing 1-RTT keys");
        assert!(server.one_rtt_keys_installed(), "server missing 1-RTT keys");

        // Transport parameters were exchanged in both directions.
        assert_eq!(
            client.peer_transport_parameters(),
            Some(b"server-params".as_slice())
        );
        assert_eq!(
            server.peer_transport_parameters(),
            Some(b"client-params".as_slice())
        );
    }

    #[test]
    fn handshake_fails_closed_when_client_does_not_trust_server() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        // Client trusts NO roots: the config still builds, but verification of the
        // server's certificate must fail during the handshake (fail-closed), and
        // the client must never reach completion.
        let client_cfg = client_config(Vec::new(), alpn).expect("client config builds w/o roots");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        let mut client_rejected = false;
        'drive: for _ in 0..16 {
            for seg in client.pump_outbound().expect("client pump") {
                let _ = server.read_handshake(&seg.data);
            }
            for seg in server.pump_outbound().expect("server pump") {
                if client.read_handshake(&seg.data).is_err() {
                    client_rejected = true;
                    break 'drive;
                }
            }
            if client.is_complete() {
                break;
            }
        }

        assert!(
            client_rejected,
            "client must reject the untrusted server certificate"
        );
        assert!(
            !client.is_complete(),
            "client must not complete against an untrusted server"
        );
    }
}
