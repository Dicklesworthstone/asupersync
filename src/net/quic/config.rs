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
    ///
    /// Required when `client_auth` is `Optional` or `Required`.
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

        // VarInt only supports values up to 2^62-1, cap at u32::MAX for safety
        let stream_window = self.initial_max_stream_data.min(u64::from(u32::MAX)) as u32;
        let conn_window = self.initial_max_data.min(u64::from(u32::MAX)) as u32;
        transport.stream_receive_window(stream_window.into());
        transport.receive_window(conn_window.into());

        transport
    }

    /// Check if this configuration is valid for server mode.
    #[must_use]
    pub fn is_valid_for_server(&self) -> bool {
        let has_identity = self.cert_chain.is_some() && self.private_key.is_some();
        if !has_identity {
            return false;
        }

        match self.client_auth {
            ClientAuth::None => true,
            ClientAuth::Optional | ClientAuth::Required => self
                .client_auth_roots
                .as_ref()
                .is_some_and(|roots| !roots.is_empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = QuicConfig::default();
        assert!(config.cert_chain.is_none());
        assert!(config.private_key.is_none());
        assert!(matches!(config.client_auth, ClientAuth::None));
        assert_eq!(config.max_bi_streams, 100);
        assert_eq!(config.max_uni_streams, 100);
        assert_eq!(config.keep_alive, Some(Duration::from_secs(15)));
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
        assert_eq!(config.initial_max_stream_data, 1024 * 1024);
        assert_eq!(config.initial_max_data, 10 * 1024 * 1024);
        assert!(!config.enable_0rtt);
        assert!(config.alpn_protocols.is_empty());
        assert!(config.root_certs.is_none());
        assert!(config.client_auth_roots.is_none());
        assert!(!config.insecure_skip_verify);
    }

    #[test]
    fn new_equals_default() {
        let new = QuicConfig::new();
        let def = QuicConfig::default();
        assert_eq!(new.max_bi_streams, def.max_bi_streams);
        assert_eq!(new.idle_timeout, def.idle_timeout);
    }

    #[test]
    fn builder_with_cert() {
        let config = QuicConfig::new().with_cert(vec![vec![1, 2, 3]], vec![4, 5, 6]);
        assert!(config.cert_chain.is_some());
        assert_eq!(config.cert_chain.unwrap().len(), 1);
        assert!(config.private_key.is_some());
    }

    #[test]
    fn builder_with_client_auth() {
        let config = QuicConfig::new().with_client_auth(ClientAuth::Required);
        assert!(matches!(config.client_auth, ClientAuth::Required));
    }

    #[test]
    fn builder_max_streams() {
        let config = QuicConfig::new().max_bi_streams(50).max_uni_streams(25);
        assert_eq!(config.max_bi_streams, 50);
        assert_eq!(config.max_uni_streams, 25);
    }

    #[test]
    fn builder_keep_alive() {
        let config = QuicConfig::new().keep_alive(None);
        assert!(config.keep_alive.is_none());

        let config2 = QuicConfig::new().keep_alive(Some(Duration::from_secs(5)));
        assert_eq!(config2.keep_alive, Some(Duration::from_secs(5)));
    }

    #[test]
    fn builder_idle_timeout() {
        let config = QuicConfig::new().idle_timeout(Duration::from_secs(60));
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn builder_flow_control() {
        let config = QuicConfig::new().flow_control(512, 4096);
        assert_eq!(config.initial_max_stream_data, 512);
        assert_eq!(config.initial_max_data, 4096);
    }

    #[test]
    fn builder_enable_0rtt() {
        let config = QuicConfig::new().enable_0rtt(true);
        assert!(config.enable_0rtt);
    }

    #[test]
    fn builder_alpn() {
        let config = QuicConfig::new()
            .alpn(b"h3".to_vec())
            .alpn(b"h3-29".to_vec());
        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h3");
        assert_eq!(config.alpn_protocols[1], b"h3-29");
    }

    #[test]
    fn builder_insecure_skip_verify() {
        let config = QuicConfig::new().insecure_skip_verify(true);
        assert!(config.insecure_skip_verify);
    }

    #[test]
    fn builder_chaining() {
        let config = QuicConfig::new()
            .max_bi_streams(10)
            .max_uni_streams(5)
            .idle_timeout(Duration::from_secs(120))
            .enable_0rtt(true)
            .alpn(b"test".to_vec());

        assert_eq!(config.max_bi_streams, 10);
        assert_eq!(config.max_uni_streams, 5);
        assert_eq!(config.idle_timeout, Duration::from_secs(120));
        assert!(config.enable_0rtt);
        assert_eq!(config.alpn_protocols.len(), 1);
    }

    #[test]
    fn is_valid_for_server_no_cert() {
        let config = QuicConfig::new();
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_with_cert_no_client_auth() {
        let config = QuicConfig::new().with_cert(vec![vec![1]], vec![2]);
        assert!(config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_cert_only_no_key() {
        let mut config = QuicConfig::new();
        config.cert_chain = Some(vec![vec![1]]);
        // No private_key
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_key_only_no_cert() {
        let mut config = QuicConfig::new();
        config.private_key = Some(vec![1]);
        // No cert_chain
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_required_auth_no_roots() {
        let config = QuicConfig::new()
            .with_cert(vec![vec![1]], vec![2])
            .with_client_auth(ClientAuth::Required);
        // No client_auth_roots
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_optional_auth_no_roots() {
        let config = QuicConfig::new()
            .with_cert(vec![vec![1]], vec![2])
            .with_client_auth(ClientAuth::Optional);
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn to_transport_config_default() {
        let config = QuicConfig::new();
        // Should not panic
        let _transport = config.to_transport_config();
    }

    #[test]
    fn to_transport_config_custom() {
        let config = QuicConfig::new()
            .max_bi_streams(50)
            .max_uni_streams(25)
            .keep_alive(Some(Duration::from_secs(10)))
            .idle_timeout(Duration::from_secs(60))
            .flow_control(2048, 8192);

        let _transport = config.to_transport_config();
    }

    #[test]
    fn to_transport_config_no_keep_alive() {
        let config = QuicConfig::new().keep_alive(None);
        let _transport = config.to_transport_config();
    }

    #[test]
    fn to_transport_config_large_flow_control_capped() {
        // Values larger than u32::MAX should be capped
        let config = QuicConfig::new().flow_control(u64::MAX, u64::MAX);
        let _transport = config.to_transport_config();
    }

    #[test]
    fn client_auth_default() {
        let auth = ClientAuth::default();
        assert!(matches!(auth, ClientAuth::None));
    }

    #[test]
    fn client_auth_debug() {
        let debug = format!("{:?}", ClientAuth::Required);
        assert!(debug.contains("Required"));
    }

    #[test]
    fn client_auth_clone_copy() {
        let a = ClientAuth::Optional;
        let b = a; // Copy
        let c = a.clone();
        assert!(matches!(b, ClientAuth::Optional));
        assert!(matches!(c, ClientAuth::Optional));
    }

    #[test]
    fn config_debug() {
        let config = QuicConfig::new();
        let debug = format!("{config:?}");
        assert!(debug.contains("QuicConfig"));
    }

    #[test]
    fn config_clone() {
        let config = QuicConfig::new().max_bi_streams(42).alpn(b"test".to_vec());
        let cloned = config.clone();
        assert_eq!(cloned.max_bi_streams, 42);
        assert_eq!(cloned.alpn_protocols.len(), 1);
    }
}
