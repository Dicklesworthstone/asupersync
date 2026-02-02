//! QUIC configuration types.
//!
//! Provides configuration for QUIC endpoints and connections.

use crate::tls::RootCertStore;
use std::time::Duration;

/// Client authentication requirement for QUIC servers.
#[derive(Debug, Clone, Copy, Default)]
pub enum ClientAuth {
    /// No client authentication required.
    #[default]
    None,
    /// Client authentication is optional.
    Optional,
    /// Client authentication is required.
    Required,
}

/// Configuration for QUIC endpoints.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Certificate chain for server (DER-encoded).
    pub cert_chain: Option<Vec<Vec<u8>>>,
    /// Private key for server (DER-encoded).
    pub private_key: Option<Vec<u8>>,
    /// Client authentication requirement (server only).
    pub client_auth: ClientAuth,
    /// Maximum concurrent bidirectional streams per connection.
    pub max_bi_streams: u32,
    /// Maximum concurrent unidirectional streams per connection.
    pub max_uni_streams: u32,
    /// Keep-alive interval. If None, keep-alive is disabled.
    pub keep_alive: Option<Duration>,
    /// Maximum idle timeout before connection is closed.
    pub idle_timeout: Duration,
    /// Initial maximum data per stream (flow control).
    pub initial_max_stream_data: u64,
    /// Initial maximum data per connection (flow control).
    pub initial_max_data: u64,
    /// Enable 0-RTT for faster connection resumption.
    pub enable_0rtt: bool,
    /// ALPN protocols to negotiate.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Root certificates for verifying servers (client mode).
    pub root_certs: Option<RootCertStore>,
    /// Root certificates for verifying client certificates (server mode).
    pub client_auth_roots: Option<RootCertStore>,
    /// Disable server certificate verification (insecure; testing only).
    pub insecure_skip_verify: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            cert_chain: None,
            private_key: None,
            client_auth: ClientAuth::None,
            max_bi_streams: 100,
            max_uni_streams: 100,
            keep_alive: Some(Duration::from_secs(15)),
            idle_timeout: Duration::from_secs(30),
            initial_max_stream_data: 1024 * 1024, // 1 MB
            initial_max_data: 10 * 1024 * 1024,   // 10 MB
            enable_0rtt: false,
            alpn_protocols: Vec::new(),
            root_certs: None,
            client_auth_roots: None,
            insecure_skip_verify: false,
        }
    }
}

impl QuicConfig {
    /// Create a new configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the certificate chain and private key for server mode.
    #[must_use]
    pub fn with_cert(mut self, cert_chain: Vec<Vec<u8>>, private_key: Vec<u8>) -> Self {
        self.cert_chain = Some(cert_chain);
        self.private_key = Some(private_key);
        self
    }

    /// Set client authentication requirement.
    #[must_use]
    pub fn with_client_auth(mut self, client_auth: ClientAuth) -> Self {
        self.client_auth = client_auth;
        self
    }

    /// Set maximum concurrent bidirectional streams.
    #[must_use]
    pub fn max_bi_streams(mut self, count: u32) -> Self {
        self.max_bi_streams = count;
        self
    }

    /// Set maximum concurrent unidirectional streams.
    #[must_use]
    pub fn max_uni_streams(mut self, count: u32) -> Self {
        self.max_uni_streams = count;
        self
    }

    /// Set keep-alive interval.
    #[must_use]
    pub fn keep_alive(mut self, interval: Option<Duration>) -> Self {
        self.keep_alive = interval;
        self
    }

    /// Set idle timeout.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set initial flow control limits.
    #[must_use]
    pub fn flow_control(mut self, max_stream_data: u64, max_data: u64) -> Self {
        self.initial_max_stream_data = max_stream_data;
        self.initial_max_data = max_data;
        self
    }

    /// Enable 0-RTT connection resumption.
    #[must_use]
    pub fn enable_0rtt(mut self, enable: bool) -> Self {
        self.enable_0rtt = enable;
        self
    }

    /// Add an ALPN protocol.
    #[must_use]
    pub fn alpn(mut self, protocol: impl Into<Vec<u8>>) -> Self {
        self.alpn_protocols.push(protocol.into());
        self
    }

    /// Provide custom root certificates for verifying servers.
    #[must_use]
    pub fn with_root_certs(mut self, root_certs: RootCertStore) -> Self {
        self.root_certs = Some(root_certs);
        self
    }

    /// Provide root certificates for verifying client certificates.
    #[must_use]
    pub fn with_client_auth_roots(mut self, root_certs: RootCertStore) -> Self {
        self.client_auth_roots = Some(root_certs);
        self
    }

    /// Disable server certificate verification (insecure; testing only).
    #[must_use]
    pub fn insecure_skip_verify(mut self, enable: bool) -> Self {
        self.insecure_skip_verify = enable;
        self
    }

    /// Build quinn transport configuration from this config.
    pub(crate) fn to_transport_config(&self) -> quinn::TransportConfig {
        let mut transport = quinn::TransportConfig::default();

        transport.max_concurrent_bidi_streams(self.max_bi_streams.into());
        transport.max_concurrent_uni_streams(self.max_uni_streams.into());

        if let Some(ka) = self.keep_alive {
            transport.keep_alive_interval(Some(ka));
        }

        let idle_timeout = quinn::IdleTimeout::try_from(self.idle_timeout).ok();
        transport.max_idle_timeout(idle_timeout);

        transport.initial_max_udp_payload_size(1472);
        // VarInt only supports values up to 2^62-1, cap at u32::MAX for safety
        let stream_window = self.initial_max_stream_data.min(u32::MAX as u64) as u32;
        let conn_window = self.initial_max_data.min(u32::MAX as u64) as u32;
        transport.stream_receive_window(stream_window.into());
        transport.receive_window(conn_window.into());

        transport
    }

    /// Check if this configuration is valid for server mode.
    #[must_use]
    pub fn is_valid_for_server(&self) -> bool {
        self.cert_chain.is_some() && self.private_key.is_some()
    }
}
