//! ATP diagnostics and path troubleshooting.

use crate::cx::Cx;
use crate::net::atp::protocol::{AtpOutcome, AtpError, PathError, PeerId, SessionId, TransferNonce};
use crate::atp::path::PathCandidateId;
use super::{AtpSession, TransferId, AtpSdk};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Deserialize, Serialize};

/// Comprehensive path diagnosis result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathDiagnosis {
    /// Target peer being diagnosed.
    pub peer_id: PeerId,
    /// Diagnosis timestamp.
    pub timestamp_nanos: u64,
    /// Overall path connectivity result.
    pub connectivity: ConnectivityResult,
    /// Discovered path candidates.
    pub path_candidates: Vec<PathCandidate>,
    /// NAT traversal results.
    pub nat_traversal: NatTraversalResult,
    /// Relay availability and performance.
    pub relay_info: RelayInfo,
    /// STUN/TURN server results.
    pub stun_results: Vec<StunResult>,
    /// Network quality metrics.
    pub network_quality: NetworkQuality,
    /// Recommended transfer strategy.
    pub recommended_strategy: TransferStrategy,
    /// Diagnostic warnings and issues.
    pub warnings: Vec<DiagnosticWarning>,
}

/// Overall connectivity assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectivityResult {
    /// Direct connection is possible.
    DirectConnectable,
    /// Connection requires relay.
    RelayRequired,
    /// Connection requires mailbox delivery.
    MailboxRequired,
    /// No connectivity possible.
    Unreachable,
}

/// Path candidate discovered during diagnosis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathCandidate {
    /// Path candidate identifier.
    pub id: PathCandidateId,
    /// Local endpoint for this path.
    pub local_endpoint: SocketAddr,
    /// Remote endpoint (if known).
    pub remote_endpoint: Option<SocketAddr>,
    /// Path type.
    pub path_type: PathType,
    /// Path quality metrics.
    pub quality: PathQuality,
    /// Whether this path is currently usable.
    pub usable: bool,
    /// Path-specific issues.
    pub issues: Vec<String>,
}

/// Type of network path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathType {
    /// Direct local network path.
    LocalDirect,
    /// Internet direct path.
    InternetDirect,
    /// STUN-discovered reflexive path.
    StunReflexive,
    /// UPnP port-mapped path.
    UpnpMapped,
    /// Relay-mediated path.
    Relay,
    /// TURN-allocated path.
    Turn,
}

/// Path quality metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathQuality {
    /// Round-trip time in milliseconds.
    pub rtt_ms: f64,
    /// Packet loss percentage (0.0-100.0).
    pub packet_loss_percent: f64,
    /// Available bandwidth in bits per second.
    pub bandwidth_bps: u64,
    /// Jitter in milliseconds.
    pub jitter_ms: f64,
    /// Path reliability score (0.0-1.0).
    pub reliability_score: f64,
}

/// NAT traversal assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NatTraversalResult {
    /// Local NAT type.
    pub local_nat_type: NatType,
    /// Remote NAT type (if detectable).
    pub remote_nat_type: Option<NatType>,
    /// Whether hole punching is likely to succeed.
    pub hole_punching_feasible: bool,
    /// Predicted success probability (0.0-1.0).
    pub success_probability: f64,
    /// NAT traversal strategies to try.
    pub recommended_strategies: Vec<NatStrategy>,
}

/// NAT type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// Open internet (no NAT).
    Open,
    /// Full cone NAT.
    FullCone,
    /// Restricted cone NAT.
    RestrictedCone,
    /// Port-restricted cone NAT.
    PortRestrictedCone,
    /// Symmetric NAT.
    Symmetric,
    /// Blocked or unknown.
    Blocked,
}

/// NAT traversal strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatStrategy {
    /// Direct connection attempt.
    Direct,
    /// STUN binding discovery.
    StunBinding,
    /// UPnP port mapping.
    UpnpMapping,
    /// ICE candidate gathering.
    IceCandidates,
    /// UDP hole punching.
    UdpHolePunch,
    /// TCP hole punching.
    TcpHolePunch,
    /// TURN relay allocation.
    TurnRelay,
}

/// Relay server information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayInfo {
    /// Available relay servers.
    pub available_relays: Vec<RelayServer>,
    /// Best relay for this peer pair.
    pub recommended_relay: Option<RelayServer>,
    /// Overall relay availability.
    pub availability_score: f64,
}

/// Relay server details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayServer {
    /// Relay server address.
    pub address: SocketAddr,
    /// Server identifier.
    pub server_id: String,
    /// Geographic region.
    pub region: Option<String>,
    /// Whether the relay is currently online.
    pub online: bool,
    /// Relay performance metrics.
    pub performance: Option<RelayPerformance>,
}

/// Relay performance metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayPerformance {
    /// Latency to relay server.
    pub latency_ms: f64,
    /// Available bandwidth through relay.
    pub bandwidth_bps: u64,
    /// Current load percentage.
    pub load_percent: f64,
    /// Reliability score.
    pub reliability_score: f64,
}

/// STUN server test result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StunResult {
    /// STUN server address.
    pub server_address: SocketAddr,
    /// Whether the server responded.
    pub responsive: bool,
    /// Response time in milliseconds.
    pub response_time_ms: Option<u64>,
    /// Discovered public address.
    pub public_address: Option<SocketAddr>,
    /// Error message if any.
    pub error: Option<String>,
}

/// Network quality assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkQuality {
    /// Overall quality score (0.0-1.0).
    pub overall_score: f64,
    /// Connection stability.
    pub stability_score: f64,
    /// Throughput capability.
    pub throughput_score: f64,
    /// Latency score.
    pub latency_score: f64,
    /// Network congestion level.
    pub congestion_level: CongestionLevel,
    /// Quality-affecting factors.
    pub affecting_factors: Vec<String>,
}

/// Network congestion level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CongestionLevel {
    /// No congestion detected.
    None,
    /// Light congestion.
    Light,
    /// Moderate congestion.
    Moderate,
    /// Heavy congestion.
    Heavy,
    /// Severe congestion.
    Severe,
}

/// Recommended transfer strategy based on diagnosis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferStrategy {
    /// Primary transfer method.
    pub primary_method: TransferMethod,
    /// Fallback methods in order of preference.
    pub fallback_methods: Vec<TransferMethod>,
    /// Recommended chunk size.
    pub chunk_size_bytes: u32,
    /// Whether to enable compression.
    pub enable_compression: bool,
    /// Whether to enable repair symbols.
    pub enable_repair: bool,
    /// Parallelization factor.
    pub parallel_streams: u32,
    /// Estimated transfer time for 1MB.
    pub estimated_mb_transfer_time_ms: u64,
}

/// Transfer method recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferMethod {
    /// Direct peer-to-peer.
    DirectP2P,
    /// Via relay server.
    Relay,
    /// Store-and-forward mailbox.
    Mailbox,
    /// Multi-source swarm.
    Swarm,
}

/// Diagnostic warning or issue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticWarning {
    /// Warning severity.
    pub severity: WarningSeverity,
    /// Warning category.
    pub category: WarningCategory,
    /// Human-readable warning message.
    pub message: String,
    /// Suggested remediation.
    pub suggested_action: Option<String>,
}

/// Warning severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WarningSeverity {
    /// Informational notice.
    Info,
    /// Warning about suboptimal conditions.
    Warning,
    /// Error that may prevent transfer.
    Error,
    /// Critical error that will prevent transfer.
    Critical,
}

/// Warning category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarningCategory {
    /// Network connectivity issues.
    Connectivity,
    /// NAT traversal problems.
    NatTraversal,
    /// Firewall blocking.
    Firewall,
    /// Performance concerns.
    Performance,
    /// Security considerations.
    Security,
    /// Configuration issues.
    Configuration,
}

impl AtpSdk {
    /// Perform comprehensive path diagnosis for a target peer.
    pub async fn path_diagnose(
        &self,
        cx: &Cx,
        target_peer: PeerId,
    ) -> AtpOutcome<PathDiagnosis> {
        let timestamp_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Simulate comprehensive path diagnosis
        let diagnosis = PathDiagnosis {
            peer_id: target_peer,
            timestamp_nanos,
            connectivity: self.assess_connectivity(cx, target_peer).await?,
            path_candidates: self.discover_path_candidates(cx, target_peer).await?,
            nat_traversal: self.assess_nat_traversal(cx, target_peer).await?,
            relay_info: self.assess_relay_availability(cx).await?,
            stun_results: self.test_stun_servers(cx).await?,
            network_quality: self.assess_network_quality(cx).await?,
            recommended_strategy: TransferStrategy::default(),
            warnings: Vec::new(),
        };

        Ok(diagnosis)
    }

    async fn assess_connectivity(
        &self,
        _cx: &Cx,
        _target_peer: PeerId,
    ) -> AtpOutcome<ConnectivityResult> {
        // Simulate connectivity assessment
        Ok(ConnectivityResult::DirectConnectable)
    }

    async fn discover_path_candidates(
        &self,
        _cx: &Cx,
        _target_peer: PeerId,
    ) -> AtpOutcome<Vec<PathCandidate>> {
        // Simulate path discovery
        let candidates = vec![
            PathCandidate {
                id: PathCandidateId::new(1),
                local_endpoint: "192.168.1.100:12345".parse().unwrap(),
                remote_endpoint: Some("203.0.113.50:54321".parse().unwrap()),
                path_type: PathType::InternetDirect,
                quality: PathQuality {
                    rtt_ms: 25.5,
                    packet_loss_percent: 0.1,
                    bandwidth_bps: 100_000_000, // 100 Mbps
                    jitter_ms: 2.1,
                    reliability_score: 0.95,
                },
                usable: true,
                issues: Vec::new(),
            },
            PathCandidate {
                id: PathCandidateId::new(2),
                local_endpoint: "10.0.0.50:12346".parse().unwrap(),
                remote_endpoint: None,
                path_type: PathType::Relay,
                quality: PathQuality {
                    rtt_ms: 45.0,
                    packet_loss_percent: 0.5,
                    bandwidth_bps: 50_000_000, // 50 Mbps
                    jitter_ms: 5.0,
                    reliability_score: 0.85,
                },
                usable: true,
                issues: vec!["Higher latency due to relay".to_string()],
            },
        ];

        Ok(candidates)
    }

    async fn assess_nat_traversal(
        &self,
        _cx: &Cx,
        _target_peer: PeerId,
    ) -> AtpOutcome<NatTraversalResult> {
        // Simulate NAT assessment
        Ok(NatTraversalResult {
            local_nat_type: NatType::FullCone,
            remote_nat_type: Some(NatType::RestrictedCone),
            hole_punching_feasible: true,
            success_probability: 0.85,
            recommended_strategies: vec![
                NatStrategy::Direct,
                NatStrategy::StunBinding,
                NatStrategy::UdpHolePunch,
                NatStrategy::TurnRelay,
            ],
        })
    }

    async fn assess_relay_availability(&self, _cx: &Cx) -> AtpOutcome<RelayInfo> {
        // Simulate relay assessment
        let relays = vec![
            RelayServer {
                address: "relay1.example.com:443".parse().unwrap(),
                server_id: "relay-us-west-1".to_string(),
                region: Some("us-west-1".to_string()),
                online: true,
                performance: Some(RelayPerformance {
                    latency_ms: 15.0,
                    bandwidth_bps: 1_000_000_000, // 1 Gbps
                    load_percent: 25.0,
                    reliability_score: 0.99,
                }),
            },
            RelayServer {
                address: "relay2.example.com:443".parse().unwrap(),
                server_id: "relay-eu-central-1".to_string(),
                region: Some("eu-central-1".to_string()),
                online: true,
                performance: Some(RelayPerformance {
                    latency_ms: 75.0,
                    bandwidth_bps: 500_000_000, // 500 Mbps
                    load_percent: 60.0,
                    reliability_score: 0.97,
                }),
            },
        ];

        Ok(RelayInfo {
            recommended_relay: relays.first().cloned(),
            availability_score: 0.98,
            available_relays: relays,
        })
    }

    async fn test_stun_servers(&self, _cx: &Cx) -> AtpOutcome<Vec<StunResult>> {
        // Simulate STUN server tests
        let results = vec![
            StunResult {
                server_address: "stun.l.google.com:19302".parse().unwrap(),
                responsive: true,
                response_time_ms: Some(12),
                public_address: Some("203.0.113.42:54321".parse().unwrap()),
                error: None,
            },
            StunResult {
                server_address: "stun1.l.google.com:19302".parse().unwrap(),
                responsive: true,
                response_time_ms: Some(18),
                public_address: Some("203.0.113.42:54322".parse().unwrap()),
                error: None,
            },
        ];

        Ok(results)
    }

    async fn assess_network_quality(&self, _cx: &Cx) -> AtpOutcome<NetworkQuality> {
        // Simulate network quality assessment
        Ok(NetworkQuality {
            overall_score: 0.88,
            stability_score: 0.92,
            throughput_score: 0.85,
            latency_score: 0.90,
            congestion_level: CongestionLevel::Light,
            affecting_factors: vec![
                "Shared bandwidth with other devices".to_string(),
                "WiFi interference from neighboring networks".to_string(),
            ],
        })
    }
}

impl AtpSession {
    /// Run continuous path monitoring for this session.
    pub async fn start_path_monitoring(
        &self,
        cx: &Cx,
        interval_ms: u64,
    ) -> AtpOutcome<PathMonitor> {
        PathMonitor::start(self.clone(), cx.clone(), interval_ms).await
    }
}

/// Continuous path monitoring for active sessions.
#[derive(Debug)]
pub struct PathMonitor {
    session: AtpSession,
    monitoring: bool,
    interval_ms: u64,
    last_diagnosis: Option<PathDiagnosis>,
}

impl PathMonitor {
    async fn start(
        session: AtpSession,
        cx: Cx,
        interval_ms: u64,
    ) -> AtpOutcome<Self> {
        let monitor = Self {
            session: session.clone(),
            monitoring: true,
            interval_ms,
            last_diagnosis: None,
        };

        // Start background monitoring task
        // TODO: Replace with proper Cx::spawn background task
        // For now, just create the monitor without background processing

        Ok(monitor)
    }

    async fn monitoring_loop(&mut self, _cx: Cx) {
        while self.monitoring {
            // Simulate path monitoring
            crate::time::sleep(Duration::from_millis(self.interval_ms)).await;

            // In a real implementation, this would:
            // 1. Check path quality metrics
            // 2. Detect path changes
            // 3. Trigger path reselection if needed
            // 4. Update transfer strategies
        }
    }

    /// Get the latest path diagnosis.
    #[must_use]
    pub const fn last_diagnosis(&self) -> Option<&PathDiagnosis> {
        self.last_diagnosis.as_ref()
    }

    /// Stop path monitoring.
    pub fn stop(&mut self) {
        self.monitoring = false;
    }
}

impl Clone for PathMonitor {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            monitoring: self.monitoring,
            interval_ms: self.interval_ms,
            last_diagnosis: self.last_diagnosis.clone(),
        }
    }
}

impl Default for TransferStrategy {
    fn default() -> Self {
        Self {
            primary_method: TransferMethod::DirectP2P,
            fallback_methods: vec![TransferMethod::Relay, TransferMethod::Mailbox],
            chunk_size_bytes: 1024 * 1024, // 1MB
            enable_compression: true,
            enable_repair: false,
            parallel_streams: 1,
            estimated_mb_transfer_time_ms: 100,
        }
    }
}

impl PathQuality {
    /// Calculate overall quality score (0.0-1.0).
    #[must_use]
    pub fn overall_score(&self) -> f64 {
        let latency_score = (200.0 - self.rtt_ms.min(200.0)) / 200.0;
        let loss_score = (1.0 - (self.packet_loss_percent / 100.0)).max(0.0);
        let jitter_score = (10.0 - self.jitter_ms.min(10.0)) / 10.0;

        // Weighted average
        (latency_score * 0.3 + loss_score * 0.4 + jitter_score * 0.2 + self.reliability_score * 0.1)
            .max(0.0)
            .min(1.0)
    }

    /// Check if this path quality is acceptable for transfers.
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        self.overall_score() >= 0.6 && self.packet_loss_percent < 5.0 && self.rtt_ms < 500.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::net::atp::sdk::{AtpSdk, SessionConfig};

    #[test]
    fn path_diagnosis_basic() {
        crate::test_utils::init_test("path_diagnosis_basic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(crate::types::Budget::INFINITE);
        let cx = crate::cx::Cx::for_testing();
        let scope = crate::cx::Scope::<crate::combinator::FailFast>::new(region, crate::types::Budget::INFINITE);

        let (_, result) = scope.spawn(&mut runtime.state, &cx, async move {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let target_peer = PeerId::from_label("target_peer");
            let diagnosis = sdk.path_diagnose(&cx, target_peer).await.unwrap();

            assert_eq!(diagnosis.peer_id, target_peer);
            assert!(!diagnosis.path_candidates.is_empty());
            assert!(diagnosis.timestamp_nanos > 0);
        }).unwrap();

        runtime.run_until_idle();
        result.join().unwrap();

        crate::test_complete!("path_diagnosis_basic");
    }

    #[test]
    fn path_quality_scoring() {
        let good_quality = PathQuality {
            rtt_ms: 20.0,
            packet_loss_percent: 0.1,
            bandwidth_bps: 100_000_000,
            jitter_ms: 1.0,
            reliability_score: 0.95,
        };

        let poor_quality = PathQuality {
            rtt_ms: 300.0,
            packet_loss_percent: 10.0,
            bandwidth_bps: 1_000_000,
            jitter_ms: 50.0,
            reliability_score: 0.5,
        };

        assert!(good_quality.overall_score() > poor_quality.overall_score());
        assert!(good_quality.is_acceptable());
        assert!(!poor_quality.is_acceptable());
    }

    #[test]
    fn nat_traversal_assessment() {
        let nat_result = NatTraversalResult {
            local_nat_type: NatType::FullCone,
            remote_nat_type: Some(NatType::Symmetric),
            hole_punching_feasible: false,
            success_probability: 0.2,
            recommended_strategies: vec![NatStrategy::TurnRelay],
        };

        assert_eq!(nat_result.local_nat_type, NatType::FullCone);
        assert!(!nat_result.hole_punching_feasible);
        assert!(nat_result.success_probability < 0.5);
    }

    #[test]
    fn diagnostic_warning_severity() {
        let info = DiagnosticWarning {
            severity: WarningSeverity::Info,
            category: WarningCategory::Performance,
            message: "Suboptimal path selected".to_string(),
            suggested_action: Some("Try alternative path".to_string()),
        };

        let critical = DiagnosticWarning {
            severity: WarningSeverity::Critical,
            category: WarningCategory::Connectivity,
            message: "No paths available".to_string(),
            suggested_action: Some("Check network configuration".to_string()),
        };

        assert!(critical.severity > info.severity);
    }

    #[test]
    fn transfer_strategy_defaults() {
        let strategy = TransferStrategy::default();

        assert_eq!(strategy.primary_method, TransferMethod::DirectP2P);
        assert!(strategy.fallback_methods.contains(&TransferMethod::Relay));
        assert!(strategy.enable_compression);
        assert_eq!(strategy.parallel_streams, 1);
    }

    #[test]
    fn path_monitoring() {
        crate::test_utils::init_test("path_monitoring");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(crate::types::Budget::INFINITE);
        let cx = crate::cx::Cx::for_testing();
        let scope = crate::cx::Scope::<crate::combinator::FailFast>::new(region, crate::types::Budget::INFINITE);

        let (_, result) = scope.spawn(&mut runtime.state, &cx, async move {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options = crate::net::atp::sdk::SessionOptions::direct(peer);
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let monitor = session.start_path_monitoring(&cx, 100).await.unwrap();
            assert!(monitor.last_diagnosis().is_none());

            // In a real test, we would wait for monitoring to produce results
            crate::time::sleep(Duration::from_millis(50)).await;
        }).unwrap();

        runtime.run_until_idle();
        result.join().unwrap();

        crate::test_complete!("path_monitoring");
    }
}