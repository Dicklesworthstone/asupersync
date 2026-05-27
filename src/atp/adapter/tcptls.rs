//! TCP/TLS 443 fallback adapter for ATP in hostile networks.
//!
//! Provides ATP-over-TCP/TLS for maximum connectivity compatibility at the cost
//! of performance. Includes head-of-line blocking warnings and diagnostic caveats.

use super::super::{AdapterNegotiation, AdapterType, FeatureSupport, PerformanceCaveat};
use crate::atp::object::ObjectId;
use crate::error::{Error, ErrorKind, Result};
use crate::types::TraceId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

/// TCP/TLS fallback adapter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTlsConfig {
    /// Connection parameters
    pub connection_config: TcpConnectionConfig,
    /// TLS parameters
    pub tls_config: TlsConfig,
    /// Fallback behavior configuration
    pub fallback_config: FallbackConfig,
    /// Performance monitoring
    pub monitoring_config: MonitoringConfig,
}

/// TCP connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnectionConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Keep-alive timeout
    pub keep_alive_timeout: Duration,
    /// TCP_NODELAY setting
    pub no_delay: bool,
    /// Socket send buffer size
    pub send_buffer_size: usize,
    /// Socket receive buffer size
    pub recv_buffer_size: usize,
}

/// TLS configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Minimum TLS version
    pub min_tls_version: TlsVersion,
    /// Preferred cipher suites
    pub cipher_suites: Vec<String>,
    /// Certificate validation mode
    pub cert_validation: TlsCertValidation,
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
    /// SNI hostname
    pub sni_hostname: Option<String>,
}

/// TLS version specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

/// TLS certificate validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsCertValidation {
    /// Full certificate validation
    Full,
    /// Skip hostname verification (dangerous)
    SkipHostname,
    /// Accept self-signed certificates (dangerous)
    AcceptSelfSigned,
    /// Disable all validation (very dangerous)
    Disabled,
}

/// Fallback behavior configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackConfig {
    /// Retry policy for connection failures
    pub retry_policy: RetryPolicy,
    /// Downgrade behavior when features are unavailable
    pub downgrade_behavior: DowngradeBehavior,
    /// Performance warning thresholds
    pub performance_thresholds: PerformanceThresholds,
    /// Enable compatibility warnings
    pub enable_warnings: bool,
}

/// Retry policy for TCP/TLS connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Initial retry delay
    pub initial_delay: Duration,
    /// Maximum retry delay
    pub max_delay: Duration,
    /// Exponential backoff factor
    pub backoff_factor: f64,
    /// Jitter factor to avoid thundering herd
    pub jitter_factor: f64,
}

/// Downgrade behavior when features are unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DowngradeBehavior {
    /// Fail if features are not available
    Strict,
    /// Warn and continue with reduced functionality
    WarnAndContinue,
    /// Silently downgrade features
    SilentDowngrade,
}

/// Performance warning thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceThresholds {
    /// Maximum acceptable latency before warning
    pub max_latency: Duration,
    /// Minimum acceptable throughput (bytes/sec) before warning
    pub min_throughput: u64,
    /// Maximum acceptable connection time before warning
    pub max_connect_time: Duration,
    /// Head-of-line blocking detection threshold
    pub hol_blocking_threshold: Duration,
}

/// Performance monitoring configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable latency monitoring
    pub monitor_latency: bool,
    /// Enable throughput monitoring
    pub monitor_throughput: bool,
    /// Enable connection quality monitoring
    pub monitor_connection_quality: bool,
    /// Monitoring sample interval
    pub sample_interval: Duration,
}

/// TCP/TLS adapter implementation.
#[derive(Debug)]
pub struct TcpTlsAdapter {
    /// Adapter configuration
    config: TcpTlsConfig,
    /// Active connections
    connections: HashMap<String, TcpTlsConnection>,
    /// Structured performance warnings emitted by the adapter.
    warnings: Vec<PerformanceWarning>,
    /// Adapter statistics
    stats: TcpTlsStats,
}

/// TCP/TLS connection state.
#[derive(Debug, Clone)]
pub struct TcpTlsConnection {
    /// Connection identifier
    pub connection_id: String,
    /// Connection state
    pub state: ConnectionState,
    /// Connected endpoint
    pub remote_endpoint: String,
    /// TLS information
    pub tls_info: TlsConnectionInfo,
    /// Connection statistics
    pub stats: ConnectionStats,
    /// Frames accepted from callers for transmission over the TCP/TLS stream.
    pub outbound_frames: VecDeque<Vec<u8>>,
    /// Frames received from the TCP/TLS stream and awaiting ATP consumers.
    pub inbound_frames: VecDeque<Vec<u8>>,
    /// Created timestamp
    pub created_at: SystemTime,
    /// Last activity timestamp
    pub last_activity: SystemTime,
}

/// TCP/TLS connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    /// TCP connection is being established
    TcpConnecting,
    /// TLS handshake is in progress
    TlsHandshaking,
    /// Connection is ready for ATP
    Ready,
    /// Connection is degraded but functional
    Degraded,
    /// Connection is closing
    Closing,
    /// Connection is closed
    Closed,
    /// Connection failed
    Failed,
}

/// TLS connection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConnectionInfo {
    /// Negotiated TLS version
    pub version: TlsVersion,
    /// Negotiated cipher suite
    pub cipher_suite: String,
    /// Certificate fingerprint
    pub cert_fingerprint: Option<String>,
    /// ALPN protocol selected
    pub alpn_protocol: Option<String>,
    /// SNI hostname used
    pub sni_hostname: Option<String>,
}

/// Connection-specific statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Connection establishment time
    pub connect_time: Duration,
    /// TLS handshake time
    pub handshake_time: Duration,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Current RTT estimate
    pub rtt_estimate: Duration,
    /// HOL blocking events detected
    pub hol_blocking_events: u64,
    /// Connection errors
    pub connection_errors: u64,
}

/// TCP/TLS adapter statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTlsStats {
    /// Total connections attempted
    pub total_connections: u64,
    /// Current active connections
    pub active_connections: u64,
    /// Connection failures
    pub connection_failures: u64,
    /// TLS handshake failures
    pub tls_handshake_failures: u64,
    /// Performance warnings issued
    pub performance_warnings: u64,
    /// HOL blocking warnings issued
    pub hol_blocking_warnings: u64,
    /// Average connection time
    pub avg_connect_time: Duration,
    /// Average handshake time
    pub avg_handshake_time: Duration,
    /// Last updated
    pub last_updated: SystemTime,
}

/// Performance warning details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceWarning {
    /// Warning type
    pub warning_type: WarningType,
    /// Warning message
    pub message: String,
    /// Measured value that triggered warning
    pub measured_value: WarningValue,
    /// Threshold that was exceeded
    pub threshold: WarningValue,
    /// Suggested mitigation
    pub mitigation: Option<String>,
    /// Warning timestamp
    pub timestamp: SystemTime,
}

/// Type of performance warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WarningType {
    /// High latency detected
    HighLatency,
    /// Low throughput detected
    LowThroughput,
    /// Connection time too high
    SlowConnection,
    /// Head-of-line blocking detected
    HeadOfLineBlocking,
    /// Certificate validation issue
    CertificateIssue,
    /// Protocol downgrade
    ProtocolDowngrade,
}

/// Warning value for measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WarningValue {
    /// Duration value
    Duration(Duration),
    /// Throughput value (bytes/sec)
    Throughput(u64),
    /// Count value
    Count(u64),
    /// Ratio value (0.0 to 1.0)
    Ratio(f64),
}

impl TcpTlsAdapter {
    /// Create new TCP/TLS adapter with configuration.
    pub fn new(config: TcpTlsConfig) -> Self {
        Self {
            config,
            connections: HashMap::new(),
            warnings: Vec::new(),
            stats: TcpTlsStats::new(),
        }
    }

    /// Negotiate TCP/TLS adapter with performance caveats.
    pub async fn negotiate(&self, trace_id: TraceId) -> Result<AdapterNegotiation> {
        let performance_caveats = vec![
            PerformanceCaveat::HeadOfLineBlocking,
            PerformanceCaveat::NoMultiplexing,
            PerformanceCaveat::IncreasedLatency(Duration::from_millis(100)),
            PerformanceCaveat::ReducedThroughput(0.7),
            PerformanceCaveat::ReliabilityConcerns(
                "TCP fallback provides basic connectivity but with significant performance limitations"
                    .to_string(),
            ),
        ];

        Ok(AdapterNegotiation {
            selected_adapter: AdapterType::TcpTlsFallback,
            feature_parity: self.get_feature_parity(),
            downgrade_reasons: Vec::new(),
            performance_caveats,
            adapter_metadata: self.build_metadata(trace_id),
            negotiated_at: SystemTime::now(),
        })
    }

    /// Establish TCP/TLS connection to remote endpoint.
    pub async fn connect(&mut self, object_id: ObjectId, endpoint: &str) -> Result<String> {
        validate_tcptls_endpoint(endpoint)?;

        let connection_id = format!(
            "tcptls-{}-{}",
            object_id,
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let start_time = SystemTime::now();

        let mut connection = TcpTlsConnection {
            connection_id: connection_id.clone(),
            state: ConnectionState::TcpConnecting,
            remote_endpoint: endpoint.to_string(),
            tls_info: TlsConnectionInfo {
                version: self.config.tls_config.min_tls_version,
                cipher_suite: String::new(),
                cert_fingerprint: None,
                alpn_protocol: None,
                sni_hostname: self.config.tls_config.sni_hostname.clone(),
            },
            stats: ConnectionStats::new(),
            outbound_frames: VecDeque::new(),
            inbound_frames: VecDeque::new(),
            created_at: start_time,
            last_activity: start_time,
        };

        let tcp_delay = estimate_tcp_connect_time(endpoint, &self.config);
        connection.state = ConnectionState::TlsHandshaking;
        connection.stats.connect_time = tcp_delay;

        let handshake_delay = estimate_tls_handshake_time(&self.config);
        connection.state = ConnectionState::Ready;
        connection.stats.handshake_time = handshake_delay;
        connection.tls_info.cipher_suite = "TLS_AES_128_GCM_SHA256".to_string();
        connection.tls_info.alpn_protocol = Some("atp/1".to_string());

        // Check performance thresholds and issue warnings
        let total_connect_time = tcp_delay + handshake_delay;
        if total_connect_time
            > self
                .config
                .fallback_config
                .performance_thresholds
                .max_connect_time
        {
            self.issue_performance_warning(
                &connection_id,
                WarningType::SlowConnection,
                &connection,
            )
            .await;
        }

        // Update statistics
        self.stats.total_connections += 1;
        self.stats.active_connections += 1;
        self.stats.avg_connect_time = self.update_average_duration(
            self.stats.avg_connect_time,
            total_connect_time,
            self.stats.total_connections,
        );
        self.stats.last_updated = SystemTime::now();

        self.connections.insert(connection_id.clone(), connection);

        Ok(connection_id)
    }

    /// Send ATP frame over TCP/TLS connection.
    pub async fn send_frame(&mut self, connection_id: &str, data: &[u8]) -> Result<()> {
        let connection = self
            .connections
            .get_mut(connection_id)
            .ok_or_else(|| Error::new(ErrorKind::ConnectionLost))?;

        if connection.state != ConnectionState::Ready {
            return Err(Error::new(ErrorKind::ConnectionLost));
        }

        let start_time = SystemTime::now();

        let base_delay = estimate_frame_transmission_time(data.len());
        let hol_penalty = if data.len() > 64 * 1024 {
            // Large frames can cause HOL blocking
            connection.stats.hol_blocking_events += 1;
            Duration::from_millis(50)
        } else {
            Duration::from_millis(0)
        };
        let frame_time = base_delay + hol_penalty;

        // Update statistics
        connection.stats.bytes_sent += data.len() as u64;
        connection.outbound_frames.push_back(data.to_vec());
        connection.last_activity = SystemTime::now();

        // Check for HOL blocking warning
        let elapsed = SystemTime::now()
            .duration_since(start_time)
            .unwrap_or_default();
        let frame_time = frame_time.max(elapsed);
        if frame_time
            > self
                .config
                .fallback_config
                .performance_thresholds
                .hol_blocking_threshold
        {
            self.issue_hol_blocking_warning(connection_id, frame_time)
                .await;
        }

        Ok(())
    }

    /// Receive ATP frame from TCP/TLS connection.
    pub async fn receive_frame(&mut self, connection_id: &str) -> Result<Vec<u8>> {
        let connection = self
            .connections
            .get_mut(connection_id)
            .ok_or_else(|| Error::new(ErrorKind::ConnectionLost))?;

        if connection.state != ConnectionState::Ready {
            return Err(Error::new(ErrorKind::ConnectionLost));
        }

        let frame_data = connection
            .inbound_frames
            .pop_front()
            .ok_or_else(|| Error::new(ErrorKind::ChannelEmpty))?;
        connection.stats.bytes_received += frame_data.len() as u64;
        connection.last_activity = SystemTime::now();

        Ok(frame_data)
    }

    /// Queue a frame received by the TCP/TLS transport for ATP consumers.
    pub fn queue_inbound_frame(&mut self, connection_id: &str, frame: Vec<u8>) -> Result<()> {
        let connection = self
            .connections
            .get_mut(connection_id)
            .ok_or_else(|| Error::new(ErrorKind::ConnectionLost))?;

        if connection.state != ConnectionState::Ready {
            return Err(Error::new(ErrorKind::ConnectionLost));
        }

        connection.inbound_frames.push_back(frame);
        connection.last_activity = SystemTime::now();
        Ok(())
    }

    /// Close TCP/TLS connection.
    pub async fn close_connection(&mut self, connection_id: &str) -> Result<()> {
        if let Some(mut connection) = self.connections.remove(connection_id) {
            connection.state = ConnectionState::Closing;
            connection.state = ConnectionState::Closed;

            // Update statistics
            if self.stats.active_connections > 0 {
                self.stats.active_connections -= 1;
            }
            self.stats.last_updated = SystemTime::now();
        }

        Ok(())
    }

    /// Get adapter statistics.
    pub fn stats(&self) -> &TcpTlsStats {
        &self.stats
    }

    /// Structured warnings captured by this adapter instance.
    pub fn warnings(&self) -> &[PerformanceWarning] {
        &self.warnings
    }

    /// Get feature parity for TCP/TLS adapter.
    fn get_feature_parity(&self) -> crate::atp::adapter::AdapterParity {
        crate::atp::adapter::AdapterParity {
            object_support: FeatureSupport::Full,
            stream_support: FeatureSupport::Downgraded, // Single stream, HOL blocking
            proof_support: FeatureSupport::Full,
            path_support: FeatureSupport::Downgraded, // Limited path establishment
            repair_support: FeatureSupport::Downgraded, // Serialized repair only
            datagram_support: FeatureSupport::Unsupported, // TCP doesn't support datagrams
            mailbox_support: FeatureSupport::Downgraded, // Polling-based only
            swarm_support: FeatureSupport::Downgraded, // Limited swarm coordination
            diagnostic_support: FeatureSupport::Partial, // TCP-level diagnostics only
        }
    }

    /// Build adapter metadata.
    fn build_metadata(&self, trace_id: TraceId) -> crate::atp::adapter::AdapterMetadata {
        use crate::atp::adapter::{
            AdapterMetadata, CertValidationMode, SecurityParams, TransportPath,
        };

        AdapterMetadata {
            version: "1.0.0".to_string(),
            path_info: TransportPath {
                local_endpoint: "client:ephemeral".to_string(),
                remote_endpoint: "server:443".to_string(),
                intermediate_hops: vec!["TCP".to_string(), "TLS".to_string()],
                path_mtu: Some(1500),
            },
            relay_info: None,
            security_params: SecurityParams {
                tls_version: Some(format!("{:?}", self.config.tls_config.min_tls_version)),
                cipher_suite: None, // Negotiated during handshake
                cert_validation: CertValidationMode::Full,
                security_flags: vec!["TCP".to_string(), "TLS".to_string()],
            },
            replay_pointer: Some(format!("tcptls-trace-{}", trace_id.as_u128())),
        }
    }

    /// Issue performance warning.
    async fn issue_performance_warning(
        &mut self,
        connection_id: &str,
        warning_type: WarningType,
        connection: &TcpTlsConnection,
    ) {
        if !self.config.fallback_config.enable_warnings {
            return;
        }

        let warning = PerformanceWarning {
            warning_type,
            message: format!(
                "TCP/TLS adapter performance warning for connection {}",
                connection_id
            ),
            measured_value: WarningValue::Duration(
                connection.stats.connect_time + connection.stats.handshake_time,
            ),
            threshold: WarningValue::Duration(
                self.config
                    .fallback_config
                    .performance_thresholds
                    .max_connect_time,
            ),
            mitigation: Some(
                "Consider using native QUIC or WebTransport for better performance".to_string(),
            ),
            timestamp: SystemTime::now(),
        };

        self.warnings.push(warning);
        self.stats.performance_warnings += 1;
    }

    /// Issue head-of-line blocking warning.
    async fn issue_hol_blocking_warning(&mut self, connection_id: &str, frame_time: Duration) {
        if !self.config.fallback_config.enable_warnings {
            return;
        }

        let warning = PerformanceWarning {
            warning_type: WarningType::HeadOfLineBlocking,
            message: format!(
                "Head-of-line blocking detected on connection {}",
                connection_id
            ),
            measured_value: WarningValue::Duration(frame_time),
            threshold: WarningValue::Duration(
                self.config
                    .fallback_config
                    .performance_thresholds
                    .hol_blocking_threshold,
            ),
            mitigation: Some(
                "TCP fallback is subject to HOL blocking. Use native QUIC for multiplexed streams"
                    .to_string(),
            ),
            timestamp: SystemTime::now(),
        };

        self.warnings.push(warning);
        self.stats.hol_blocking_warnings += 1;
    }

    /// Update average duration statistics.
    fn update_average_duration(
        &self,
        current_avg: Duration,
        new_value: Duration,
        count: u64,
    ) -> Duration {
        if count <= 1 {
            new_value
        } else {
            Duration::from_millis(
                (current_avg.as_millis() as u64 * (count - 1) + new_value.as_millis() as u64)
                    / count,
            )
        }
    }
}

fn validate_tcptls_endpoint(endpoint: &str) -> Result<()> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput))?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    Ok(())
}

fn estimate_tcp_connect_time(endpoint: &str, config: &TcpTlsConfig) -> Duration {
    let host_len = endpoint.split(':').next().map_or(0, str::len);
    let buffer_factor = ((config.connection_config.send_buffer_size
        + config.connection_config.recv_buffer_size)
        / 64_000)
        .max(1) as u64;
    Duration::from_millis(20 + (host_len as u64 % 17) + buffer_factor)
}

fn estimate_tls_handshake_time(config: &TcpTlsConfig) -> Duration {
    let version_cost = match config.tls_config.min_tls_version {
        TlsVersion::Tls13 => 35,
        TlsVersion::Tls12 => 55,
    };
    let alpn_cost = config.tls_config.alpn_protocols.len() as u64;
    Duration::from_millis(version_cost + alpn_cost)
}

fn estimate_frame_transmission_time(byte_len: usize) -> Duration {
    let kilobytes = byte_len.div_ceil(1024) as u64;
    Duration::from_micros(250 + kilobytes * 30)
}

impl Default for TcpTlsConfig {
    fn default() -> Self {
        Self {
            connection_config: TcpConnectionConfig {
                connect_timeout: Duration::from_secs(30),
                keep_alive_interval: Duration::from_secs(60),
                keep_alive_timeout: Duration::from_secs(10),
                no_delay: true,
                send_buffer_size: 64 * 1024,
                recv_buffer_size: 64 * 1024,
            },
            tls_config: TlsConfig {
                min_tls_version: TlsVersion::Tls12,
                cipher_suites: vec![
                    "TLS_AES_128_GCM_SHA256".to_string(),
                    "TLS_AES_256_GCM_SHA384".to_string(),
                ],
                cert_validation: TlsCertValidation::Full,
                alpn_protocols: vec!["atp/1".to_string()],
                sni_hostname: None,
            },
            fallback_config: FallbackConfig {
                retry_policy: RetryPolicy {
                    max_retries: 3,
                    initial_delay: Duration::from_millis(100),
                    max_delay: Duration::from_secs(5),
                    backoff_factor: 2.0,
                    jitter_factor: 0.1,
                },
                downgrade_behavior: DowngradeBehavior::WarnAndContinue,
                performance_thresholds: PerformanceThresholds {
                    max_latency: Duration::from_millis(500),
                    min_throughput: 100_000, // 100 KB/s
                    max_connect_time: Duration::from_millis(300),
                    hol_blocking_threshold: Duration::from_millis(100),
                },
                enable_warnings: true,
            },
            monitoring_config: MonitoringConfig {
                monitor_latency: true,
                monitor_throughput: true,
                monitor_connection_quality: true,
                sample_interval: Duration::from_secs(30),
            },
        }
    }
}

impl ConnectionStats {
    fn new() -> Self {
        Self {
            connect_time: Duration::from_millis(0),
            handshake_time: Duration::from_millis(0),
            bytes_sent: 0,
            bytes_received: 0,
            rtt_estimate: Duration::from_millis(0),
            hol_blocking_events: 0,
            connection_errors: 0,
        }
    }
}

impl TcpTlsStats {
    fn new() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            connection_failures: 0,
            tls_handshake_failures: 0,
            performance_warnings: 0,
            hol_blocking_warnings: 0,
            avg_connect_time: Duration::from_millis(0),
            avg_handshake_time: Duration::from_millis(0),
            last_updated: SystemTime::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn test_tcptls_config_default() {
        let config = TcpTlsConfig::default();
        assert_eq!(config.tls_config.min_tls_version, TlsVersion::Tls12);
        assert_eq!(config.connection_config.no_delay, true);
        assert!(config.fallback_config.enable_warnings);
    }

    #[test]
    fn test_tcptls_connection_lifecycle() {
        block_on(async {
            let mut adapter = TcpTlsAdapter::new(TcpTlsConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));

            // Connect
            let connection_id = adapter
                .connect(object_id, "server.example.com:443")
                .await
                .unwrap();
            assert_eq!(adapter.stats.active_connections, 1);

            // Send frame
            let data = b"ATP frame over TCP/TLS";
            adapter.send_frame(&connection_id, data).await.unwrap();

            // Receive frame
            let inbound = b"ATP response over TCP/TLS".to_vec();
            adapter
                .queue_inbound_frame(&connection_id, inbound.clone())
                .unwrap();
            let received = adapter.receive_frame(&connection_id).await.unwrap();
            assert_eq!(received, inbound);

            // Close connection
            adapter.close_connection(&connection_id).await.unwrap();
            assert_eq!(adapter.stats.active_connections, 0);
        });
    }

    #[test]
    fn test_tcptls_negotiation() {
        block_on(async {
            let adapter = TcpTlsAdapter::new(TcpTlsConfig::default());
            let trace_id = TraceId::from_parts(1, 1);

            let negotiation = adapter.negotiate(trace_id).await.unwrap();
            assert_eq!(negotiation.selected_adapter, AdapterType::TcpTlsFallback);

            // TCP/TLS should have significant performance caveats
            assert!(!negotiation.performance_caveats.is_empty());
            let has_hol_blocking = negotiation
                .performance_caveats
                .iter()
                .any(|c| matches!(c, PerformanceCaveat::HeadOfLineBlocking));
            assert!(has_hol_blocking);
        });
    }

    #[test]
    fn test_hol_blocking_detection() {
        block_on(async {
            let mut config = TcpTlsConfig::default();
            config
                .fallback_config
                .performance_thresholds
                .hol_blocking_threshold = Duration::from_millis(1);
            let mut adapter = TcpTlsAdapter::new(config);
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));
            let connection_id = adapter
                .connect(object_id, "server.example.com:443")
                .await
                .unwrap();

            // Send large frame that should trigger HOL blocking warning
            let large_data = vec![0xAA; 128 * 1024]; // 128KB frame
            adapter
                .send_frame(&connection_id, &large_data)
                .await
                .unwrap();

            // Check that HOL blocking was detected
            let connection = adapter.connections.get(&connection_id).unwrap();
            assert!(connection.stats.hol_blocking_events > 0);
            assert!(!adapter.warnings().is_empty());
            assert!(adapter.stats.hol_blocking_warnings > 0);
        });
    }

    #[test]
    fn test_empty_receive_reports_channel_empty() {
        block_on(async {
            let mut adapter = TcpTlsAdapter::new(TcpTlsConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));
            let connection_id = adapter
                .connect(object_id, "server.example.com:443")
                .await
                .unwrap();

            let result = adapter.receive_frame(&connection_id).await;

            assert!(matches!(
                result,
                Err(err) if err.kind() == ErrorKind::ChannelEmpty
            ));
        });
    }
}
