//! ATP Compatibility Adapters for alternative transports.
//!
//! Provides ATP-over-WebTransport, MASQUE/CONNECT-UDP, and TCP/TLS 443 fallback
//! adapters while preserving ATP's core guarantees. Native QUIC remains the
//! foundation; these are compatibility adapters for constrained environments.

pub mod integration_tests;
pub mod masque;
pub mod tcptls;
pub mod webtransport;

use crate::atp::object::ObjectId;
use crate::error::{Error, ErrorKind, Result};
use crate::types::TraceId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};

/// ATP adapter types for alternative transport protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterType {
    /// Native ATP over native QUIC (baseline)
    #[serde(rename = "native-quic")]
    NativeQuic,
    /// ATP over HTTP/3 with WebTransport streams/datagrams
    #[serde(rename = "webtransport")]
    WebTransport,
    /// ATP over MASQUE/CONNECT-UDP for proxy traversal
    #[serde(rename = "masque-connect-udp")]
    MasqueConnectUdp,
    /// ATP over TCP/TLS 443 fallback for hostile networks
    #[serde(rename = "tcp-tls-443")]
    TcpTlsFallback,
}

/// Adapter feature compatibility matrix showing supported/downgraded capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterParity {
    /// Object verification and manifest support
    pub object_support: FeatureSupport,
    /// Stream protocol support
    pub stream_support: FeatureSupport,
    /// Proof generation and verification
    pub proof_support: FeatureSupport,
    /// Path establishment and selection
    pub path_support: FeatureSupport,
    /// RaptorQ repair capabilities
    pub repair_support: FeatureSupport,
    /// Datagram transmission support
    pub datagram_support: FeatureSupport,
    /// Mailbox and inbox support
    pub mailbox_support: FeatureSupport,
    /// Swarm coordination support
    pub swarm_support: FeatureSupport,
    /// Diagnostic and telemetry support
    pub diagnostic_support: FeatureSupport,
}

/// Feature support levels for adapter capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeatureSupport {
    /// Full feature support with no limitations
    Full,
    /// Partial support with documented limitations
    Partial,
    /// Feature is downgraded with fallback behavior
    Downgraded,
    /// Feature is not supported
    Unsupported,
}

/// Adapter configuration for transport selection and policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    /// Preferred adapter types in order of preference
    pub preferred_adapters: Vec<AdapterType>,
    /// Downgrade policy when preferred adapters fail
    pub downgrade_policy: DowngradePolicy,
    /// Feature requirements that must be satisfied
    pub required_features: Vec<RequiredFeature>,
    /// Adapter-specific configurations
    pub adapter_configs: HashMap<AdapterType, AdapterSpecificConfig>,
    /// Performance caveat reporting configuration
    pub caveat_reporting: CaveatReporting,
}

/// Policy for adapter downgrading when preferred options fail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DowngradePolicy {
    /// Fail if preferred adapter cannot be used
    Strict,
    /// Allow downgrade to any compatible adapter
    AllowDowngrade,
    /// Allow downgrade only to specified adapters
    AllowSpecific(Vec<AdapterType>),
    /// Use fallback adapter as last resort
    FallbackOnly(AdapterType),
}

/// Required feature that must be supported by chosen adapter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequiredFeature {
    /// Object verification must be supported
    ObjectVerification,
    /// Stream protocol must be supported
    StreamProtocol,
    /// Proof generation must be supported
    ProofGeneration,
    /// Repair capabilities must be supported
    RepairCapabilities,
    /// Swarm coordination must be supported
    SwarmCoordination,
}

/// Adapter-specific configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterSpecificConfig {
    /// Connection timeout for this adapter
    pub connection_timeout: Duration,
    /// Maximum concurrent streams/connections
    pub max_concurrent: usize,
    /// Adapter-specific feature flags
    pub feature_flags: HashMap<String, bool>,
    /// Performance tuning parameters
    pub performance_config: PerformanceConfig,
}

/// Performance configuration and caveat reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Buffer sizes for this adapter
    pub buffer_sizes: BufferSizes,
    /// Retry policy configuration
    pub retry_policy: RetryPolicy,
    /// Keep-alive settings
    pub keep_alive: KeepAliveConfig,
}

/// Buffer size configuration for adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferSizes {
    /// Send buffer size in bytes
    pub send_buffer: usize,
    /// Receive buffer size in bytes
    pub recv_buffer: usize,
    /// Maximum frame size
    pub max_frame_size: usize,
}

/// Retry policy for adapter connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum retry attempts
    pub max_attempts: usize,
    /// Base retry delay
    pub base_delay: Duration,
    /// Maximum retry delay
    pub max_delay: Duration,
    /// Exponential backoff factor
    pub backoff_factor: f64,
}

/// Keep-alive configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeepAliveConfig {
    /// Keep-alive interval
    pub interval: Duration,
    /// Keep-alive timeout
    pub timeout: Duration,
    /// Enable keep-alive
    pub enabled: bool,
}

/// Caveat reporting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaveatReporting {
    /// Report nested transport performance issues
    pub report_performance: bool,
    /// Report head-of-line blocking issues
    pub report_hol_blocking: bool,
    /// Report diagnostic limitations
    pub report_diagnostic_limits: bool,
    /// Include detailed timing information
    pub include_timing: bool,
}

/// Adapter negotiation result with selected transport and capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterNegotiation {
    /// Selected adapter type
    pub selected_adapter: AdapterType,
    /// Negotiated feature parity
    pub feature_parity: AdapterParity,
    /// Downgrade reasons if applicable
    pub downgrade_reasons: Vec<DowngradeReason>,
    /// Performance caveats for this adapter
    pub performance_caveats: Vec<PerformanceCaveat>,
    /// Adapter-specific metadata
    pub adapter_metadata: AdapterMetadata,
    /// Negotiation timestamp
    pub negotiated_at: SystemTime,
}

/// Reason for adapter downgrading.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DowngradeReason {
    /// Preferred adapter not available
    AdapterUnavailable,
    /// Feature requirements not met
    FeatureRequirementsNotMet(Vec<RequiredFeature>),
    /// Connection failed
    ConnectionFailed(String),
    /// Performance below threshold
    PerformanceBelowThreshold,
    /// Policy-enforced downgrade
    PolicyEnforced,
    /// Network conditions require fallback
    NetworkConditions,
}

/// Performance caveat for adapter selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceCaveat {
    /// Head-of-line blocking may occur
    HeadOfLineBlocking,
    /// Increased latency expected
    IncreasedLatency(Duration),
    /// Reduced throughput expected
    ReducedThroughput(f64),
    /// No multiplexing support
    NoMultiplexing,
    /// Limited concurrent streams
    LimitedConcurrency(usize),
    /// Nested transport overhead
    NestedTransportOverhead,
    /// Reliability concerns
    ReliabilityConcerns(String),
}

/// Adapter-specific metadata and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterMetadata {
    /// Adapter version
    pub version: String,
    /// Transport path information
    pub path_info: TransportPath,
    /// Relay/proxy information if applicable
    pub relay_info: Option<RelayInfo>,
    /// Security parameters
    pub security_params: SecurityParams,
    /// Replay pointer for deterministic testing
    pub replay_pointer: Option<String>,
}

/// Transport path information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportPath {
    /// Local endpoint
    pub local_endpoint: String,
    /// Remote endpoint
    pub remote_endpoint: String,
    /// Intermediate hops if known
    pub intermediate_hops: Vec<String>,
    /// Path MTU if available
    pub path_mtu: Option<usize>,
}

/// Relay/proxy information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    /// Relay/proxy address
    pub relay_address: String,
    /// Relay type (MASQUE, CONNECT, etc.)
    pub relay_type: String,
    /// Relay capabilities
    pub relay_capabilities: Vec<String>,
    /// Relay path ID for diagnostics
    pub relay_path_id: String,
}

/// Security parameters for adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParams {
    /// TLS version if applicable
    pub tls_version: Option<String>,
    /// Cipher suite
    pub cipher_suite: Option<String>,
    /// Certificate validation mode
    pub cert_validation: CertValidationMode,
    /// Additional security flags
    pub security_flags: Vec<String>,
}

/// Certificate validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CertValidationMode {
    /// Full certificate validation
    Full,
    /// Relaxed validation for testing
    Relaxed,
    /// Custom validation logic
    Custom,
}

/// ATP compatibility adapter manager.
#[derive(Debug)]
pub struct AdapterManager {
    /// Adapter configuration
    config: AdapterConfig,
    /// Adapter parity matrix
    parity_matrix: HashMap<AdapterType, AdapterParity>,
    /// Active adapter sessions
    active_sessions: HashMap<String, AdapterSession>,
    /// Adapter metrics
    metrics: AdapterMetrics,
}

/// Active adapter session.
#[derive(Debug, Clone)]
pub struct AdapterSession {
    /// Session identifier
    pub session_id: String,
    /// Negotiated adapter
    pub negotiation: AdapterNegotiation,
    /// Session start time
    pub started_at: SystemTime,
    /// Last activity time
    pub last_activity: SystemTime,
    /// Session statistics
    pub stats: SessionStats,
}

/// Session statistics for adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Objects transferred
    pub objects_transferred: u64,
    /// Streams created
    pub streams_created: u64,
    /// Connection errors
    pub connection_errors: u64,
    /// Average latency
    pub avg_latency: Duration,
}

/// Adapter metrics for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterMetrics {
    /// Sessions per adapter type
    pub sessions_by_adapter: HashMap<AdapterType, u64>,
    /// Downgrade frequency
    pub downgrade_frequency: HashMap<DowngradeReason, u64>,
    /// Performance caveat frequency
    pub caveat_frequency: HashMap<String, u64>,
    /// Average session duration by adapter
    pub avg_session_duration: HashMap<AdapterType, Duration>,
    /// Success rates by adapter
    pub success_rates: HashMap<AdapterType, f64>,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

impl AdapterManager {
    /// Create a new adapter manager with configuration.
    pub fn new(config: AdapterConfig) -> Self {
        let parity_matrix = Self::build_parity_matrix();
        Self {
            config,
            parity_matrix,
            active_sessions: HashMap::new(),
            metrics: AdapterMetrics::new(),
        }
    }

    /// Negotiate adapter for new connection based on requirements and policy.
    pub async fn negotiate_adapter(
        &mut self,
        requirements: &[RequiredFeature],
        trace_id: TraceId,
    ) -> Result<AdapterNegotiation> {
        // Try preferred adapters in order
        for &adapter_type in &self.config.preferred_adapters {
            if let Ok(negotiation) = self.try_adapter(adapter_type, requirements, trace_id).await {
                self.record_successful_negotiation(&negotiation);
                return Ok(negotiation);
            }
        }

        // Apply downgrade policy
        match &self.config.downgrade_policy {
            DowngradePolicy::Strict => Err(Error::new(ErrorKind::ConnectionRefused)),
            DowngradePolicy::AllowDowngrade => {
                self.try_fallback_adapters(requirements, trace_id).await
            }
            DowngradePolicy::AllowSpecific(allowed) => {
                self.try_specific_adapters(allowed, requirements, trace_id)
                    .await
            }
            DowngradePolicy::FallbackOnly(fallback) => {
                self.try_adapter(*fallback, requirements, trace_id).await
            }
        }
    }

    /// Start adapter session with negotiated parameters.
    pub async fn start_session(
        &mut self,
        negotiation: AdapterNegotiation,
        _object_id: ObjectId,
    ) -> Result<String> {
        let session_id = format!(
            "adapter-{:?}-{}",
            negotiation.selected_adapter,
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let session = AdapterSession {
            session_id: session_id.clone(),
            negotiation,
            started_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            stats: SessionStats::new(),
        };

        self.active_sessions.insert(session_id.clone(), session);
        self.update_metrics();

        Ok(session_id)
    }

    /// Get adapter feature parity for specific adapter type.
    pub fn get_adapter_parity(&self, adapter_type: AdapterType) -> Option<&AdapterParity> {
        self.parity_matrix.get(&adapter_type)
    }

    /// Get current adapter metrics.
    pub fn metrics(&self) -> &AdapterMetrics {
        &self.metrics
    }

    /// Build feature parity matrix for all adapter types.
    fn build_parity_matrix() -> HashMap<AdapterType, AdapterParity> {
        let mut matrix = HashMap::new();

        // Native QUIC - full support baseline
        matrix.insert(
            AdapterType::NativeQuic,
            AdapterParity {
                object_support: FeatureSupport::Full,
                stream_support: FeatureSupport::Full,
                proof_support: FeatureSupport::Full,
                path_support: FeatureSupport::Full,
                repair_support: FeatureSupport::Full,
                datagram_support: FeatureSupport::Full,
                mailbox_support: FeatureSupport::Full,
                swarm_support: FeatureSupport::Full,
                diagnostic_support: FeatureSupport::Full,
            },
        );

        // WebTransport - good support with some limitations
        matrix.insert(
            AdapterType::WebTransport,
            AdapterParity {
                object_support: FeatureSupport::Full,
                stream_support: FeatureSupport::Full,
                proof_support: FeatureSupport::Partial, // Limited by browser sandbox
                path_support: FeatureSupport::Partial,  // Limited path control
                repair_support: FeatureSupport::Partial, // Limited repair strategies
                datagram_support: FeatureSupport::Full,
                mailbox_support: FeatureSupport::Full,
                swarm_support: FeatureSupport::Partial, // Limited coordination
                diagnostic_support: FeatureSupport::Partial, // Limited diagnostics
            },
        );

        // MASQUE/CONNECT-UDP - proxy limitations
        matrix.insert(
            AdapterType::MasqueConnectUdp,
            AdapterParity {
                object_support: FeatureSupport::Full,
                stream_support: FeatureSupport::Downgraded, // Through UDP simulation
                proof_support: FeatureSupport::Full,
                path_support: FeatureSupport::Downgraded, // Via proxy path
                repair_support: FeatureSupport::Partial,  // Limited by proxy
                datagram_support: FeatureSupport::Full,
                mailbox_support: FeatureSupport::Full,
                swarm_support: FeatureSupport::Downgraded, // Proxy coordination limits
                diagnostic_support: FeatureSupport::Partial, // Proxy visibility limits
            },
        );

        // TCP/TLS 443 - significant limitations
        matrix.insert(
            AdapterType::TcpTlsFallback,
            AdapterParity {
                object_support: FeatureSupport::Full,
                stream_support: FeatureSupport::Downgraded, // Single stream, HOL blocking
                proof_support: FeatureSupport::Full,
                path_support: FeatureSupport::Downgraded, // Limited path establishment
                repair_support: FeatureSupport::Downgraded, // Serialized repair only
                datagram_support: FeatureSupport::Unsupported, // TCP doesn't support datagrams
                mailbox_support: FeatureSupport::Downgraded, // Polling-based only
                swarm_support: FeatureSupport::Downgraded, // Limited swarm coordination
                diagnostic_support: FeatureSupport::Partial, // TCP-level diagnostics only
            },
        );

        matrix
    }

    /// Try to negotiate specific adapter type.
    async fn try_adapter(
        &self,
        adapter_type: AdapterType,
        requirements: &[RequiredFeature],
        trace_id: TraceId,
    ) -> Result<AdapterNegotiation> {
        let parity = self
            .parity_matrix
            .get(&adapter_type)
            .ok_or_else(|| Error::new(ErrorKind::ConfigError))?;

        // Check if adapter meets requirements
        let mut downgrade_reasons = Vec::new();
        let mut performance_caveats = Vec::new();

        for requirement in requirements {
            if !self.check_feature_requirement(parity, requirement) {
                downgrade_reasons.push(DowngradeReason::FeatureRequirementsNotMet(vec![
                    requirement.clone(),
                ]));
            }
        }

        if !downgrade_reasons.is_empty() {
            return Err(Error::new(ErrorKind::ConnectionRefused).with_message(format!(
                "{adapter_type} does not satisfy required ATP adapter features: {downgrade_reasons:?}"
            )));
        }

        // Add adapter-specific performance caveats
        self.add_adapter_caveats(adapter_type, &mut performance_caveats);

        let negotiation = AdapterNegotiation {
            selected_adapter: adapter_type,
            feature_parity: parity.clone(),
            downgrade_reasons,
            performance_caveats,
            adapter_metadata: self.build_adapter_metadata(adapter_type, trace_id),
            negotiated_at: SystemTime::now(),
        };

        Ok(negotiation)
    }

    /// Try fallback adapters when preferred options fail.
    async fn try_fallback_adapters(
        &self,
        requirements: &[RequiredFeature],
        trace_id: TraceId,
    ) -> Result<AdapterNegotiation> {
        // Try adapters in capability order: WebTransport, MASQUE, TCP/TLS
        let fallback_order = [
            AdapterType::WebTransport,
            AdapterType::MasqueConnectUdp,
            AdapterType::TcpTlsFallback,
        ];

        for &adapter_type in &fallback_order {
            if let Ok(negotiation) = self.try_adapter(adapter_type, requirements, trace_id).await {
                return Ok(negotiation);
            }
        }

        Err(Error::new(ErrorKind::ConnectionRefused))
    }

    /// Try specific allowed adapters.
    async fn try_specific_adapters(
        &self,
        allowed: &[AdapterType],
        requirements: &[RequiredFeature],
        trace_id: TraceId,
    ) -> Result<AdapterNegotiation> {
        for &adapter_type in allowed {
            if let Ok(negotiation) = self.try_adapter(adapter_type, requirements, trace_id).await {
                return Ok(negotiation);
            }
        }

        Err(Error::new(ErrorKind::ConnectionRefused))
    }

    /// Check if adapter feature parity meets requirement.
    fn check_feature_requirement(
        &self,
        parity: &AdapterParity,
        requirement: &RequiredFeature,
    ) -> bool {
        match requirement {
            RequiredFeature::ObjectVerification => matches!(
                parity.object_support,
                FeatureSupport::Full | FeatureSupport::Partial
            ),
            RequiredFeature::StreamProtocol => matches!(
                parity.stream_support,
                FeatureSupport::Full | FeatureSupport::Partial | FeatureSupport::Downgraded
            ),
            RequiredFeature::ProofGeneration => matches!(
                parity.proof_support,
                FeatureSupport::Full | FeatureSupport::Partial
            ),
            RequiredFeature::RepairCapabilities => matches!(
                parity.repair_support,
                FeatureSupport::Full | FeatureSupport::Partial | FeatureSupport::Downgraded
            ),
            RequiredFeature::SwarmCoordination => matches!(
                parity.swarm_support,
                FeatureSupport::Full | FeatureSupport::Partial | FeatureSupport::Downgraded
            ),
        }
    }

    /// Add adapter-specific performance caveats.
    fn add_adapter_caveats(&self, adapter_type: AdapterType, caveats: &mut Vec<PerformanceCaveat>) {
        match adapter_type {
            AdapterType::NativeQuic => {
                // No caveats for native implementation
            }
            AdapterType::WebTransport => {
                caveats.push(PerformanceCaveat::NestedTransportOverhead);
            }
            AdapterType::MasqueConnectUdp => {
                caveats.push(PerformanceCaveat::NestedTransportOverhead);
                caveats.push(PerformanceCaveat::IncreasedLatency(Duration::from_millis(
                    50,
                )));
            }
            AdapterType::TcpTlsFallback => {
                caveats.push(PerformanceCaveat::HeadOfLineBlocking);
                caveats.push(PerformanceCaveat::NoMultiplexing);
                caveats.push(PerformanceCaveat::IncreasedLatency(Duration::from_millis(
                    100,
                )));
                caveats.push(PerformanceCaveat::ReducedThroughput(0.7)); // 30% throughput reduction
            }
        }
    }

    /// Build adapter metadata.
    fn build_adapter_metadata(
        &self,
        _adapter_type: AdapterType,
        trace_id: TraceId,
    ) -> AdapterMetadata {
        AdapterMetadata {
            version: "1.0.0".to_string(),
            path_info: TransportPath {
                local_endpoint: "0.0.0.0:0".to_string(),
                remote_endpoint: "example.com:443".to_string(),
                intermediate_hops: Vec::new(),
                path_mtu: Some(1500),
            },
            relay_info: None, // Would be populated for MASQUE adapters
            security_params: SecurityParams {
                tls_version: Some("TLS 1.3".to_string()),
                cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
                cert_validation: CertValidationMode::Full,
                security_flags: vec!["ALPN".to_string()],
            },
            replay_pointer: Some(format!("trace-{}", trace_id.as_u128())),
        }
    }

    /// Record successful negotiation for metrics.
    fn record_successful_negotiation(&mut self, negotiation: &AdapterNegotiation) {
        *self
            .metrics
            .sessions_by_adapter
            .entry(negotiation.selected_adapter)
            .or_insert(0) += 1;
        self.metrics.last_updated = SystemTime::now();
    }

    /// Update adapter metrics.
    fn update_metrics(&mut self) {
        self.metrics.last_updated = SystemTime::now();
    }
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            preferred_adapters: vec![
                AdapterType::NativeQuic,
                AdapterType::WebTransport,
                AdapterType::MasqueConnectUdp,
                AdapterType::TcpTlsFallback,
            ],
            downgrade_policy: DowngradePolicy::AllowDowngrade,
            required_features: vec![RequiredFeature::ObjectVerification],
            adapter_configs: HashMap::new(),
            caveat_reporting: CaveatReporting {
                report_performance: true,
                report_hol_blocking: true,
                report_diagnostic_limits: true,
                include_timing: true,
            },
        }
    }
}

impl SessionStats {
    fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            objects_transferred: 0,
            streams_created: 0,
            connection_errors: 0,
            avg_latency: Duration::from_millis(0),
        }
    }
}

impl AdapterMetrics {
    fn new() -> Self {
        Self {
            sessions_by_adapter: HashMap::new(),
            downgrade_frequency: HashMap::new(),
            caveat_frequency: HashMap::new(),
            avg_session_duration: HashMap::new(),
            success_rates: HashMap::new(),
            last_updated: SystemTime::now(),
        }
    }
}

impl fmt::Display for AdapterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterType::NativeQuic => write!(f, "native-quic"),
            AdapterType::WebTransport => write!(f, "webtransport"),
            AdapterType::MasqueConnectUdp => write!(f, "masque-connect-udp"),
            AdapterType::TcpTlsFallback => write!(f, "tcp-tls-443"),
        }
    }
}

impl fmt::Display for FeatureSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureSupport::Full => write!(f, "full"),
            FeatureSupport::Partial => write!(f, "partial"),
            FeatureSupport::Downgraded => write!(f, "downgraded"),
            FeatureSupport::Unsupported => write!(f, "unsupported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn test_adapter_parity_matrix() {
        let manager = AdapterManager::new(AdapterConfig::default());

        // Native QUIC should have full support
        let native_parity = manager.get_adapter_parity(AdapterType::NativeQuic).unwrap();
        assert_eq!(native_parity.object_support, FeatureSupport::Full);
        assert_eq!(native_parity.stream_support, FeatureSupport::Full);

        // TCP fallback should have limited datagram support
        let tcp_parity = manager
            .get_adapter_parity(AdapterType::TcpTlsFallback)
            .unwrap();
        assert_eq!(tcp_parity.datagram_support, FeatureSupport::Unsupported);
        assert_eq!(tcp_parity.stream_support, FeatureSupport::Downgraded);
    }

    #[test]
    fn test_feature_requirements() {
        let manager = AdapterManager::new(AdapterConfig::default());
        let tcp_parity = manager
            .get_adapter_parity(AdapterType::TcpTlsFallback)
            .unwrap();

        // Object verification should be supported
        assert!(
            manager.check_feature_requirement(tcp_parity, &RequiredFeature::ObjectVerification)
        );

        // Stream protocol should be supported (even if downgraded)
        assert!(manager.check_feature_requirement(tcp_parity, &RequiredFeature::StreamProtocol));
    }

    #[test]
    fn test_adapter_negotiation() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            let requirements = vec![RequiredFeature::ObjectVerification];
            let trace_id = TraceId::from_parts(1, 1);

            let negotiation = manager
                .negotiate_adapter(&requirements, trace_id)
                .await
                .unwrap();
            assert_eq!(negotiation.selected_adapter, AdapterType::NativeQuic);
        });
    }

    #[test]
    fn adapter_negotiation_skips_unmet_feature_requirements() {
        block_on(async {
            let mut manager = AdapterManager::new(AdapterConfig::default());
            manager.config.preferred_adapters =
                vec![AdapterType::NativeQuic, AdapterType::WebTransport];
            manager
                .parity_matrix
                .get_mut(&AdapterType::NativeQuic)
                .expect("native parity")
                .object_support = FeatureSupport::Unsupported;

            let negotiation = manager
                .negotiate_adapter(
                    &[RequiredFeature::ObjectVerification],
                    TraceId::from_parts(1, 1),
                )
                .await
                .expect("compatible fallback should be selected");

            assert_eq!(negotiation.selected_adapter, AdapterType::WebTransport);
            assert!(
                negotiation.downgrade_reasons.is_empty(),
                "selected adapter should satisfy the requested features"
            );
        });
    }

    #[test]
    fn test_adapter_display() {
        assert_eq!(format!("{}", AdapterType::NativeQuic), "native-quic");
        assert_eq!(format!("{}", AdapterType::WebTransport), "webtransport");
        assert_eq!(
            format!("{}", AdapterType::MasqueConnectUdp),
            "masque-connect-udp"
        );
        assert_eq!(format!("{}", AdapterType::TcpTlsFallback), "tcp-tls-443");
    }

    #[test]
    fn test_feature_support_display() {
        assert_eq!(format!("{}", FeatureSupport::Full), "full");
        assert_eq!(format!("{}", FeatureSupport::Partial), "partial");
        assert_eq!(format!("{}", FeatureSupport::Downgraded), "downgraded");
        assert_eq!(format!("{}", FeatureSupport::Unsupported), "unsupported");
    }
}
