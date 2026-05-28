//! ATP diagnostics and path troubleshooting.

#![allow(dead_code)]

use super::{AtpSdk, AtpSession, SdkMode};
use crate::atp::path::PathCandidateId;
use crate::cx::Cx;
use crate::net::atp::protocol::{AtpError, AtpOutcome, PeerId, PlatformError};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    pub async fn path_diagnose(&self, cx: &Cx, target_peer: PeerId) -> AtpOutcome<PathDiagnosis> {
        let timestamp_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Helper macro to extract Ok value or early return with the outcome error
        macro_rules! try_outcome {
            ($expr:expr) => {
                match $expr {
                    AtpOutcome::Ok(v) => v,
                    AtpOutcome::Err(e) => return AtpOutcome::Err(e),
                    AtpOutcome::Cancelled(r) => return AtpOutcome::Cancelled(r),
                    AtpOutcome::Panicked(p) => return AtpOutcome::Panicked(p),
                }
            };
        }

        let connectivity = try_outcome!(self.assess_connectivity(cx, target_peer).await);
        let path_candidates = try_outcome!(self.discover_path_candidates(cx, target_peer).await);
        let nat_traversal = try_outcome!(self.assess_nat_traversal(cx, target_peer).await);
        let relay_info = try_outcome!(self.assess_relay_availability(cx).await);
        let stun_results = try_outcome!(self.test_stun_servers(cx).await);
        let network_quality = self.assess_network_quality_from(&path_candidates, &relay_info);
        let recommended_strategy =
            TransferStrategy::for_diagnosis(&connectivity, &network_quality, &relay_info);
        let warnings = diagnostic_warnings(
            &connectivity,
            &path_candidates,
            &nat_traversal,
            &relay_info,
            &stun_results,
            &network_quality,
        );

        let diagnosis = PathDiagnosis {
            peer_id: target_peer,
            timestamp_nanos,
            connectivity,
            path_candidates,
            nat_traversal,
            relay_info,
            stun_results,
            network_quality,
            recommended_strategy,
            warnings,
        };

        AtpOutcome::ok(diagnosis)
    }

    async fn assess_connectivity(
        &self,
        _cx: &Cx,
        _target_peer: PeerId,
    ) -> AtpOutcome<ConnectivityResult> {
        if !discover_local_path_candidates().is_empty() {
            return AtpOutcome::ok(ConnectivityResult::DirectConnectable);
        }

        match self.mode() {
            SdkMode::DaemonDelegated {
                daemon_endpoint, ..
            } if parse_daemon_endpoint(daemon_endpoint).is_some() => {
                AtpOutcome::ok(ConnectivityResult::RelayRequired)
            }
            _ => AtpOutcome::ok(ConnectivityResult::MailboxRequired),
        }
    }

    async fn discover_path_candidates(
        &self,
        _cx: &Cx,
        _target_peer: PeerId,
    ) -> AtpOutcome<Vec<PathCandidate>> {
        AtpOutcome::ok(discover_local_path_candidates())
    }

    async fn assess_nat_traversal(
        &self,
        _cx: &Cx,
        _target_peer: PeerId,
    ) -> AtpOutcome<NatTraversalResult> {
        let candidates = discover_local_path_candidates();
        let has_private = candidates
            .iter()
            .any(|candidate| is_private_or_local(candidate.local_endpoint.ip()));
        let has_path = !candidates.is_empty();
        let local_nat_type = if !has_path {
            NatType::Blocked
        } else if has_private {
            NatType::PortRestrictedCone
        } else {
            NatType::Open
        };

        AtpOutcome::ok(NatTraversalResult {
            local_nat_type,
            remote_nat_type: None,
            hole_punching_feasible: has_path,
            success_probability: if !has_path {
                0.0
            } else if has_private {
                0.65
            } else {
                0.95
            },
            recommended_strategies: nat_strategies_for(local_nat_type),
        })
    }

    async fn assess_relay_availability(&self, _cx: &Cx) -> AtpOutcome<RelayInfo> {
        let relays = match self.mode() {
            SdkMode::DaemonDelegated {
                daemon_endpoint, ..
            } => parse_daemon_endpoint(daemon_endpoint)
                .map(|address| RelayServer {
                    address,
                    server_id: format!("atpd:{address}"),
                    region: None,
                    online: true,
                    performance: None,
                })
                .into_iter()
                .collect(),
            SdkMode::InProcess => Vec::new(),
        };

        AtpOutcome::ok(RelayInfo {
            recommended_relay: relays.first().cloned(),
            availability_score: if relays.is_empty() { 0.0 } else { 1.0 },
            available_relays: relays,
        })
    }

    async fn test_stun_servers(&self, _cx: &Cx) -> AtpOutcome<Vec<StunResult>> {
        AtpOutcome::ok(Vec::new())
    }

    fn assess_network_quality_from(
        &self,
        candidates: &[PathCandidate],
        relay_info: &RelayInfo,
    ) -> NetworkQuality {
        network_quality_from_candidates(candidates, relay_info)
    }
}

fn discover_local_path_candidates() -> Vec<PathCandidate> {
    let mut candidates = Vec::new();

    for target in ["1.1.1.1:53", "[2001:4860:4860::8888]:53"] {
        if let Some(endpoint) = local_endpoint_for_route(target) {
            let id = PathCandidateId::new(candidates.len() as u64 + 1);
            candidates.push(PathCandidate {
                id,
                local_endpoint: endpoint,
                remote_endpoint: None,
                path_type: if is_private_or_local(endpoint.ip()) {
                    PathType::LocalDirect
                } else {
                    PathType::InternetDirect
                },
                quality: quality_for_endpoint(endpoint),
                usable: true,
                issues: endpoint_issues(endpoint),
            });
        }
    }

    candidates
}

fn local_endpoint_for_route(target: &str) -> Option<SocketAddr> {
    let bind_addr = if target.starts_with('[') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).ok()?;
    socket.connect(target).ok()?;
    socket.local_addr().ok()
}

fn quality_for_endpoint(endpoint: SocketAddr) -> PathQuality {
    let private_or_local = is_private_or_local(endpoint.ip());
    let loopback = endpoint.ip().is_loopback();
    let reliability_score = if loopback {
        0.99
    } else if private_or_local {
        0.80
    } else {
        0.90
    };
    let rtt_ms = if loopback {
        1.0
    } else if private_or_local {
        40.0
    } else {
        25.0
    };

    PathQuality {
        rtt_ms,
        packet_loss_percent: 0.0,
        bandwidth_bps: interface_speed_bps(endpoint.ip()).unwrap_or(0),
        jitter_ms: 0.0,
        reliability_score,
    }
}

fn endpoint_issues(endpoint: SocketAddr) -> Vec<String> {
    let mut issues = Vec::new();
    if endpoint.ip().is_unspecified() {
        issues.push("Route probe returned an unspecified local address".to_string());
    }
    if is_private_or_local(endpoint.ip()) && !endpoint.ip().is_loopback() {
        issues.push("Local endpoint is behind a private or local address boundary".to_string());
    }
    issues
}

fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() || ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ((ipv6.segments()[0] & 0xfe00) == 0xfc00)
                || ((ipv6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn interface_speed_bps(_ip: IpAddr) -> Option<u64> {
    std::fs::read_dir("/sys/class/net")
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "lo" {
                return None;
            }
            let speed_path = entry.path().join("speed");
            let speed_mbps = std::fs::read_to_string(speed_path)
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()?;
            Some(speed_mbps.saturating_mul(1_000_000))
        })
        .max()
}

fn parse_daemon_endpoint(endpoint: &str) -> Option<SocketAddr> {
    endpoint
        .strip_prefix("tcp://")
        .unwrap_or(endpoint)
        .parse()
        .ok()
}

fn nat_strategies_for(nat_type: NatType) -> Vec<NatStrategy> {
    match nat_type {
        NatType::Open => vec![NatStrategy::Direct],
        NatType::FullCone | NatType::RestrictedCone | NatType::PortRestrictedCone => vec![
            NatStrategy::Direct,
            NatStrategy::StunBinding,
            NatStrategy::UdpHolePunch,
            NatStrategy::TurnRelay,
        ],
        NatType::Symmetric => vec![NatStrategy::StunBinding, NatStrategy::TurnRelay],
        NatType::Blocked => vec![NatStrategy::TurnRelay],
    }
}

fn latency_score(rtt_ms: f64) -> f64 {
    (1.0 - (rtt_ms.max(0.0) / 250.0)).clamp(0.0, 1.0)
}

fn bandwidth_score(bandwidth_bps: u64) -> f64 {
    if bandwidth_bps == 0 {
        0.5
    } else {
        ((bandwidth_bps as f64) / 1_000_000_000.0).clamp(0.0, 1.0)
    }
}

fn congestion_from_score(score: f64) -> CongestionLevel {
    if score >= 0.85 {
        CongestionLevel::None
    } else if score >= 0.65 {
        CongestionLevel::Light
    } else if score >= 0.45 {
        CongestionLevel::Moderate
    } else if score >= 0.25 {
        CongestionLevel::Heavy
    } else {
        CongestionLevel::Severe
    }
}

fn quality_factors(candidates: &[PathCandidate], relay_info: &RelayInfo) -> Vec<String> {
    let mut factors = Vec::new();

    if candidates.is_empty() {
        factors.push("No local UDP route candidates were discovered".to_string());
    }
    if candidates
        .iter()
        .any(|candidate| candidate.quality.bandwidth_bps == 0)
    {
        factors.push("Interface speed was not reported by the operating system".to_string());
    }
    if relay_info.available_relays.is_empty() {
        factors.push("No daemon relay endpoint is configured".to_string());
    }

    factors
}

fn diagnostic_warnings(
    connectivity: &ConnectivityResult,
    candidates: &[PathCandidate],
    nat: &NatTraversalResult,
    relay_info: &RelayInfo,
    stun_results: &[StunResult],
    network_quality: &NetworkQuality,
) -> Vec<DiagnosticWarning> {
    let mut warnings = Vec::new();

    if candidates.is_empty() {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Error,
            category: WarningCategory::Connectivity,
            message: "No local UDP path candidates were discovered".to_string(),
            suggested_action: Some(
                "Check local network interfaces and socket permissions".to_string(),
            ),
        });
    }
    if matches!(connectivity, ConnectivityResult::MailboxRequired) {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warning,
            category: WarningCategory::Connectivity,
            message: "Direct connectivity is unavailable without a configured relay".to_string(),
            suggested_action: Some(
                "Configure atpd daemon delegation or mailbox delivery".to_string(),
            ),
        });
    }
    if nat.local_nat_type != NatType::Open && stun_results.is_empty() {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Info,
            category: WarningCategory::NatTraversal,
            message: "NAT classification is local-only because no STUN servers are configured"
                .to_string(),
            suggested_action: Some(
                "Provide STUN/TURN configuration for public reflexive address checks".to_string(),
            ),
        });
    }
    if relay_info.available_relays.is_empty() {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Info,
            category: WarningCategory::Configuration,
            message: "No relay endpoint is configured for fallback transfer".to_string(),
            suggested_action: Some(
                "Use daemon-delegated SDK mode with a tcp://host:port relay endpoint".to_string(),
            ),
        });
    }
    if network_quality.overall_score < 0.45 {
        warnings.push(DiagnosticWarning {
            severity: WarningSeverity::Warning,
            category: WarningCategory::Performance,
            message: "Observed path evidence indicates weak transfer quality".to_string(),
            suggested_action: Some(
                "Prefer relay/mailbox fallback or reduce parallelism".to_string(),
            ),
        });
    }

    warnings
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

fn diagnose_session_path(session: &AtpSession) -> PathDiagnosis {
    let timestamp_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let path_candidates = discover_local_path_candidates();
    let relay_info = relay_info_for_mode(&session.mode);
    let nat_traversal = nat_result_for_candidates(&path_candidates);
    let connectivity = connectivity_for_session(session, &path_candidates, &relay_info);
    let network_quality = network_quality_from_candidates(&path_candidates, &relay_info);
    let stun_results = Vec::new();
    let recommended_strategy =
        TransferStrategy::for_diagnosis(&connectivity, &network_quality, &relay_info);
    let warnings = diagnostic_warnings(
        &connectivity,
        &path_candidates,
        &nat_traversal,
        &relay_info,
        &stun_results,
        &network_quality,
    );

    PathDiagnosis {
        peer_id: session.remote_peer(),
        timestamp_nanos,
        connectivity,
        path_candidates,
        nat_traversal,
        relay_info,
        stun_results,
        network_quality,
        recommended_strategy,
        warnings,
    }
}

fn connectivity_for_session(
    session: &AtpSession,
    candidates: &[PathCandidate],
    relay_info: &RelayInfo,
) -> ConnectivityResult {
    match session.context() {
        crate::net::atp::protocol::SessionContextKind::Direct if !candidates.is_empty() => {
            ConnectivityResult::DirectConnectable
        }
        crate::net::atp::protocol::SessionContextKind::Relay
            if !relay_info.available_relays.is_empty() =>
        {
            ConnectivityResult::RelayRequired
        }
        crate::net::atp::protocol::SessionContextKind::Mailbox => {
            ConnectivityResult::MailboxRequired
        }
        crate::net::atp::protocol::SessionContextKind::Swarm if !candidates.is_empty() => {
            ConnectivityResult::DirectConnectable
        }
        _ if !candidates.is_empty() => ConnectivityResult::DirectConnectable,
        _ if !relay_info.available_relays.is_empty() => ConnectivityResult::RelayRequired,
        _ => ConnectivityResult::MailboxRequired,
    }
}

fn relay_info_for_mode(mode: &SdkMode) -> RelayInfo {
    let relays = match mode {
        SdkMode::DaemonDelegated {
            daemon_endpoint, ..
        } => parse_daemon_endpoint(daemon_endpoint)
            .map(|address| RelayServer {
                address,
                server_id: format!("atpd:{address}"),
                region: None,
                online: true,
                performance: None,
            })
            .into_iter()
            .collect(),
        SdkMode::InProcess => Vec::new(),
    };

    RelayInfo {
        recommended_relay: relays.first().cloned(),
        availability_score: if relays.is_empty() { 0.0 } else { 1.0 },
        available_relays: relays,
    }
}

fn nat_result_for_candidates(candidates: &[PathCandidate]) -> NatTraversalResult {
    let has_private = candidates
        .iter()
        .any(|candidate| is_private_or_local(candidate.local_endpoint.ip()));
    let has_path = !candidates.is_empty();
    let local_nat_type = if !has_path {
        NatType::Blocked
    } else if has_private {
        NatType::PortRestrictedCone
    } else {
        NatType::Open
    };

    NatTraversalResult {
        local_nat_type,
        remote_nat_type: None,
        hole_punching_feasible: has_path,
        success_probability: if !has_path {
            0.0
        } else if has_private {
            0.65
        } else {
            0.95
        },
        recommended_strategies: nat_strategies_for(local_nat_type),
    }
}

fn network_quality_from_candidates(
    candidates: &[PathCandidate],
    relay_info: &RelayInfo,
) -> NetworkQuality {
    if candidates.is_empty() && relay_info.available_relays.is_empty() {
        return NetworkQuality {
            overall_score: 0.0,
            stability_score: 0.0,
            throughput_score: 0.0,
            latency_score: 0.0,
            congestion_level: CongestionLevel::Severe,
            affecting_factors: vec!["No local UDP path or configured relay".to_string()],
        };
    }

    let usable_candidates = candidates
        .iter()
        .filter(|candidate| candidate.usable)
        .collect::<Vec<_>>();
    let reliability = usable_candidates
        .iter()
        .map(|candidate| candidate.quality.reliability_score)
        .fold(0.0, f64::max);
    let latency_score = usable_candidates
        .iter()
        .map(|candidate| latency_score(candidate.quality.rtt_ms))
        .fold(0.0, f64::max);
    let throughput_score = usable_candidates
        .iter()
        .map(|candidate| bandwidth_score(candidate.quality.bandwidth_bps))
        .fold(0.0, f64::max);
    let relay_bonus = relay_info.availability_score * 0.15;
    let overall_score =
        ((reliability * 0.40) + (latency_score * 0.25) + (throughput_score * 0.20) + relay_bonus)
            .clamp(0.0, 1.0);

    NetworkQuality {
        overall_score,
        stability_score: reliability.clamp(0.0, 1.0),
        throughput_score: throughput_score.clamp(0.0, 1.0),
        latency_score: latency_score.clamp(0.0, 1.0),
        congestion_level: congestion_from_score(overall_score),
        affecting_factors: quality_factors(candidates, relay_info),
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
    async fn start(session: AtpSession, cx: Cx, interval_ms: u64) -> AtpOutcome<Self> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }

        crate::runtime::yield_now().await;

        AtpOutcome::ok(Self {
            session,
            monitoring: true,
            interval_ms,
            last_diagnosis: None,
        })
    }

    /// Sample the session path state once and update the latest diagnosis.
    pub async fn tick(&mut self, cx: &Cx) -> AtpOutcome<PathDiagnosis> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }

        let diagnosis = diagnose_session_path(&self.session);
        self.last_diagnosis = Some(diagnosis.clone());
        AtpOutcome::ok(diagnosis)
    }

    /// Run monitoring in the current task until stopped or cancelled.
    pub async fn run_until_stopped(&mut self, cx: &Cx) -> AtpOutcome<()> {
        while self.monitoring {
            crate::time::sleep(
                crate::time::wall_now(),
                Duration::from_millis(self.interval_ms),
            )
            .await;

            match self.tick(cx).await {
                AtpOutcome::Ok(_) => {}
                AtpOutcome::Err(error) => return AtpOutcome::Err(error),
                AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
                AtpOutcome::Panicked(panic) => return AtpOutcome::Panicked(panic),
            }
        }

        AtpOutcome::ok(())
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

impl TransferStrategy {
    fn for_diagnosis(
        connectivity: &ConnectivityResult,
        network_quality: &NetworkQuality,
        relay_info: &RelayInfo,
    ) -> Self {
        let relay_available = !relay_info.available_relays.is_empty();
        let primary_method = if matches!(connectivity, ConnectivityResult::DirectConnectable)
            && network_quality.overall_score >= 0.45
        {
            TransferMethod::DirectP2P
        } else if relay_available
            && matches!(
                connectivity,
                ConnectivityResult::RelayRequired | ConnectivityResult::DirectConnectable
            )
        {
            TransferMethod::Relay
        } else {
            TransferMethod::Mailbox
        };

        let fallback_methods = match primary_method {
            TransferMethod::DirectP2P => {
                vec![
                    TransferMethod::Relay,
                    TransferMethod::Mailbox,
                    TransferMethod::Swarm,
                ]
            }
            TransferMethod::Relay => {
                vec![
                    TransferMethod::DirectP2P,
                    TransferMethod::Mailbox,
                    TransferMethod::Swarm,
                ]
            }
            TransferMethod::Mailbox => vec![TransferMethod::Relay, TransferMethod::Swarm],
            TransferMethod::Swarm => vec![TransferMethod::DirectP2P, TransferMethod::Relay],
        };

        let chunk_size_bytes = if network_quality.latency_score < 0.4 {
            256 * 1024
        } else if network_quality.throughput_score > 0.75 {
            2 * 1024 * 1024
        } else {
            1024 * 1024
        };
        let parallel_streams = if network_quality.overall_score > 0.8 {
            4
        } else if network_quality.overall_score > 0.55 {
            2
        } else {
            1
        };

        Self {
            primary_method,
            fallback_methods,
            chunk_size_bytes,
            enable_compression: network_quality.throughput_score < 0.7,
            enable_repair: network_quality.stability_score < 0.75,
            parallel_streams,
            estimated_mb_transfer_time_ms: estimate_mb_transfer_time_ms(network_quality),
        }
    }
}

fn estimate_mb_transfer_time_ms(network_quality: &NetworkQuality) -> u64 {
    let throughput_factor = network_quality.throughput_score.clamp(0.05, 1.0);
    let latency_penalty = 1.0 + (1.0 - network_quality.latency_score.clamp(0.0, 1.0));
    ((100.0 / throughput_factor) * latency_penalty)
        .ceil()
        .clamp(1.0, u64::MAX as f64) as u64
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
            .clamp(0.0, 1.0)
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
    use crate::net::atp::sdk::{AtpSdk, SessionConfig};
    use futures_lite::future::block_on;

    #[test]
    fn path_diagnosis_basic() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let target_peer = PeerId::from_label("target_peer");
            let diagnosis = sdk.path_diagnose(&cx, target_peer).await.unwrap();

            assert_eq!(diagnosis.peer_id, target_peer);
            assert!(!diagnosis.path_candidates.is_empty());
            assert!(diagnosis.timestamp_nanos > 0);
        });

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
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options = crate::net::atp::sdk::SessionOptions::direct(peer);
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let monitor = session.start_path_monitoring(&cx, 100).await.unwrap();
            assert!(monitor.last_diagnosis().is_none());
        });

        crate::test_complete!("path_monitoring");
    }
}
