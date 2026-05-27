//! Direct ATP path discovery models.
//!
//! This module is intentionally deterministic and socket-free. Runtime code can
//! feed real LAN beacons, configured endpoints, and platform network probes into
//! these builders while tests keep policy, ranking, and diagnostic output stable.

use crate::atp::path::{
    PathBudget, PathCandidate, PathCandidateId, PathKind, PathSecurity, PathTraceId,
};
use crate::net::atp::path::PathCandidateMetrics;
use crate::net::atp::stun::{EndpointFamily, ObservedEndpoint};
use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Stable schema for path doctor output from direct discovery.
pub const ATP_PATH_DOCTOR_SCHEMA: &str = "asupersync.atp.path.doctor.v1";

/// Policy gates for direct ATP path discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathDiscoveryPolicy {
    /// Whether LAN discovery may advertise or consume local-network beacons.
    pub lan_discovery_enabled: bool,
    /// Whether user-provided direct UDP endpoints may become candidates.
    pub explicit_direct_enabled: bool,
    /// Whether public IPv6 endpoints may become direct candidates.
    pub public_ipv6_enabled: bool,
    /// Optional Tailscale/private-route candidate policy.
    pub tailscale_policy: TailscalePathPolicy,
    /// Maximum age for a Tailscale observation before it is rejected.
    pub tailscale_max_staleness_micros: u64,
    /// Whether public IPv6 ranks ahead of explicit public UDP candidates.
    pub prefer_public_ipv6: bool,
}

impl Default for PathDiscoveryPolicy {
    fn default() -> Self {
        Self {
            lan_discovery_enabled: false,
            explicit_direct_enabled: true,
            public_ipv6_enabled: true,
            tailscale_policy: TailscalePathPolicy::Allow,
            tailscale_max_staleness_micros: 30_000_000,
            prefer_public_ipv6: true,
        }
    }
}

impl PathDiscoveryPolicy {
    /// Conservative policy: LAN discovery is silent until explicitly enabled.
    #[must_use]
    pub const fn safe_default() -> Self {
        Self {
            lan_discovery_enabled: false,
            explicit_direct_enabled: true,
            public_ipv6_enabled: true,
            tailscale_policy: TailscalePathPolicy::Allow,
            tailscale_max_staleness_micros: 30_000_000,
            prefer_public_ipv6: true,
        }
    }

    /// Policy variant that denies every direct discovery source.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            lan_discovery_enabled: false,
            explicit_direct_enabled: false,
            public_ipv6_enabled: false,
            tailscale_policy: TailscalePathPolicy::Disabled,
            tailscale_max_staleness_micros: 30_000_000,
            prefer_public_ipv6: false,
        }
    }

    /// Enable local-network discovery.
    #[must_use]
    pub const fn with_lan_discovery(mut self, enabled: bool) -> Self {
        self.lan_discovery_enabled = enabled;
        self
    }

    /// Set optional Tailscale candidate handling.
    #[must_use]
    pub const fn with_tailscale_policy(mut self, tailscale_policy: TailscalePathPolicy) -> Self {
        self.tailscale_policy = tailscale_policy;
        self
    }

    /// Set the maximum allowed age for Tailscale observations.
    #[must_use]
    pub const fn with_tailscale_max_staleness_micros(mut self, staleness_micros: u64) -> Self {
        self.tailscale_max_staleness_micros = staleness_micros;
        self
    }
}

/// Policy mode for optional Tailscale/private-route candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailscalePathPolicy {
    /// Do not run Tailscale discovery from configuration.
    Disabled,
    /// Admit Tailscale candidates when a provider reports them.
    Allow,
    /// Rank Tailscale candidates ahead of native direct candidates.
    Prefer,
    /// Reject Tailscale candidates even if a provider reports them.
    Forbid,
}

impl TailscalePathPolicy {
    /// Stable policy code for diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Allow => "allow",
            Self::Prefer => "prefer",
            Self::Forbid => "forbid",
        }
    }
}

/// Source that produced a direct path candidate or rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DirectCandidateSource {
    /// LAN multicast/local-network discovery.
    LanDiscovery,
    /// User-provided UDP host:port.
    ExplicitDirectUdp,
    /// Public IPv6 local endpoint.
    PublicIpv6,
    /// Optional Tailscale/private-route provider.
    TailscaleProvider,
}

impl DirectCandidateSource {
    /// Stable source code for logs and doctor output.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LanDiscovery => "lan_discovery",
            Self::ExplicitDirectUdp => "explicit_direct_udp",
            Self::PublicIpv6 => "public_ipv6",
            Self::TailscaleProvider => "tailscale_provider",
        }
    }

    const fn path_kind(self) -> PathKind {
        match self {
            Self::LanDiscovery => PathKind::LanMulticast,
            Self::ExplicitDirectUdp => PathKind::ExplicitPublicUdp,
            Self::PublicIpv6 => PathKind::PublicIpv6,
            Self::TailscaleProvider => PathKind::TailscaleIp,
        }
    }
}

/// Stable rejection reason for a candidate source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DirectCandidateRejection {
    /// The source is disabled by policy.
    PolicyDisabled,
    /// A stricter policy forbids this optional source.
    PolicyForbidden,
    /// IPv6 is unavailable on this platform/profile.
    Ipv6Unavailable,
    /// Tailscale was allowed but no local provider candidate was present.
    TailscaleNotPresent,
    /// Tailscale candidate data was too old to trust.
    StaleCandidate,
    /// Endpoint string was empty.
    EmptyEndpoint,
    /// Endpoint string could not be parsed as `host:port`.
    InvalidEndpoint,
    /// Endpoint port was zero.
    ZeroPort,
    /// Endpoint address was unspecified.
    UnspecifiedAddress,
    /// Endpoint address was multicast.
    MulticastAddress,
    /// Endpoint address was loopback.
    LoopbackAddress,
    /// LAN discovery input was not a local-network address.
    NotLanAddress,
    /// Public IPv6 discovery input was not a usable public IPv6 address.
    NotPublicIpv6,
    /// Tailscale discovery input was not a usable Tailscale address.
    NotTailscaleAddress,
    /// LAN advertisement repeated an already-seen peer/endpoint tuple.
    DuplicateAdvertisement,
    /// Peer label was empty.
    EmptyPeerLabel,
}

impl DirectCandidateRejection {
    /// Stable reason code for logs and doctor output.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PolicyDisabled => "policy_disabled",
            Self::PolicyForbidden => "policy_forbidden",
            Self::Ipv6Unavailable => "ipv6_unavailable",
            Self::TailscaleNotPresent => "tailscale_not_present",
            Self::StaleCandidate => "stale_candidate",
            Self::EmptyEndpoint => "empty_endpoint",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::ZeroPort => "zero_port",
            Self::UnspecifiedAddress => "unspecified_address",
            Self::MulticastAddress => "multicast_address",
            Self::LoopbackAddress => "loopback_address",
            Self::NotLanAddress => "not_lan_address",
            Self::NotPublicIpv6 => "not_public_ipv6",
            Self::NotTailscaleAddress => "not_tailscale_address",
            Self::DuplicateAdvertisement => "duplicate_advertisement",
            Self::EmptyPeerLabel => "empty_peer_label",
        }
    }
}

/// One rejected direct path source with redaction-safe detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPathRejection {
    /// Candidate source that was rejected.
    pub source: DirectCandidateSource,
    /// Stable rejection reason.
    pub reason: DirectCandidateRejection,
    /// Redacted detail safe for path doctor output.
    pub detail: String,
}

impl DirectPathRejection {
    fn new(
        source: DirectCandidateSource,
        reason: DirectCandidateRejection,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            source,
            reason,
            detail: detail.into(),
        }
    }
}

/// Validation error for direct discovery inputs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{candidate_source}: {reason} ({detail})", candidate_source = .candidate_source.code(), reason = .reason.code())]
pub struct DirectDiscoveryError {
    /// Candidate source that failed validation.
    pub candidate_source: DirectCandidateSource,
    /// Stable rejection reason.
    pub reason: DirectCandidateRejection,
    /// Redacted detail safe for logs.
    pub detail: String,
}

impl DirectDiscoveryError {
    fn new(
        source: DirectCandidateSource,
        reason: DirectCandidateRejection,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            candidate_source: source,
            reason,
            detail: detail.into(),
        }
    }

    fn rejection(&self) -> DirectPathRejection {
        DirectPathRejection::new(self.candidate_source, self.reason, self.detail.clone())
    }
}

/// One local-network peer advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPeerAdvertisement {
    peer_label: String,
    endpoint: SocketAddr,
    nonce: u64,
    observed_at_micros: u64,
}

impl LanPeerAdvertisement {
    /// Build a LAN advertisement when policy allows advertising.
    ///
    /// Returns `Ok(None)` when LAN discovery is disabled so disabled discovery
    /// remains silent instead of emitting beacons.
    pub fn maybe_new(
        policy: PathDiscoveryPolicy,
        peer_label: impl Into<String>,
        endpoint: SocketAddr,
        nonce: u64,
        observed_at_micros: u64,
    ) -> Result<Option<Self>, DirectDiscoveryError> {
        if !policy.lan_discovery_enabled {
            return Ok(None);
        }

        let peer_label = peer_label.into();
        if peer_label.trim().is_empty() {
            return Err(DirectDiscoveryError::new(
                DirectCandidateSource::LanDiscovery,
                DirectCandidateRejection::EmptyPeerLabel,
                "peer label is empty",
            ));
        }
        validate_endpoint_basics(DirectCandidateSource::LanDiscovery, endpoint)?;
        if !is_lan_address(endpoint.ip()) {
            return Err(DirectDiscoveryError::new(
                DirectCandidateSource::LanDiscovery,
                DirectCandidateRejection::NotLanAddress,
                endpoint_scope(endpoint),
            ));
        }

        Ok(Some(Self {
            peer_label,
            endpoint,
            nonce,
            observed_at_micros,
        }))
    }

    /// Redacted label supplied by the caller.
    #[must_use]
    pub fn peer_label(&self) -> &str {
        &self.peer_label
    }

    /// Advertised UDP endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Probe nonce.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Caller-supplied observation timestamp.
    #[must_use]
    pub const fn observed_at_micros(&self) -> u64 {
        self.observed_at_micros
    }
}

/// Provider source for an optional Tailscale/private-route candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailscaleDetectionSource {
    /// Deterministic lab provider used by lab/e2e tests.
    LabProvider,
    /// Host interface inventory observed a Tailscale address.
    LocalInterface,
    /// `tailscale status`-style host integration reported a candidate.
    StatusCommand,
}

impl TailscaleDetectionSource {
    /// Stable source code for redaction-safe diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LabProvider => "lab_provider",
            Self::LocalInterface => "local_interface",
            Self::StatusCommand => "status_command",
        }
    }

    const fn evidence_code(self) -> &'static str {
        match self {
            Self::LabProvider => "tailscale_lab_provider_candidate_validated",
            Self::LocalInterface => "tailscale_local_interface_candidate_validated",
            Self::StatusCommand => "tailscale_status_command_candidate_validated",
        }
    }
}

/// One optional Tailscale/private-route candidate observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleCandidateObservation {
    endpoint: SocketAddr,
    detection_source: TailscaleDetectionSource,
    observed_at_micros: u64,
}

impl TailscaleCandidateObservation {
    /// Build an observation from a deterministic or host-backed provider.
    #[must_use]
    pub const fn new(
        endpoint: SocketAddr,
        detection_source: TailscaleDetectionSource,
        observed_at_micros: u64,
    ) -> Self {
        Self {
            endpoint,
            detection_source,
            observed_at_micros,
        }
    }

    /// Candidate endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Provider source.
    #[must_use]
    pub const fn detection_source(&self) -> TailscaleDetectionSource {
        self.detection_source
    }

    /// Caller-supplied observation timestamp.
    #[must_use]
    pub const fn observed_at_micros(&self) -> u64 {
        self.observed_at_micros
    }
}

/// Direct path candidate with ranking and redaction-safe evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPathCandidate {
    /// Path candidate id.
    pub id: PathCandidateId,
    /// Trace id for structured path logs.
    pub trace_id: PathTraceId,
    /// Candidate source.
    pub source: DirectCandidateSource,
    /// UDP endpoint to attempt.
    pub endpoint: SocketAddr,
    /// Candidate metrics for path racing.
    pub metrics: PathCandidateMetrics,
    /// Stable caveat/evidence code.
    pub evidence: &'static str,
}

impl DirectPathCandidate {
    /// Convert to the shared ATP path candidate model.
    #[must_use]
    pub fn to_path_candidate(&self) -> PathCandidate {
        PathCandidate::new(self.id, self.source.path_kind(), self.trace_id)
            .with_budget(PathBudget::default())
            .with_security(PathSecurity::for_kind(self.source.path_kind()))
    }

    /// Redacted endpoint scope for doctor/log output.
    #[must_use]
    pub fn endpoint_scope(&self) -> String {
        endpoint_scope(self.endpoint)
    }

    /// STUN-like endpoint record for existing NAT/path classification code.
    pub fn observed_endpoint(&self) -> Result<ObservedEndpoint, DirectDiscoveryError> {
        let family = match self.endpoint.ip() {
            IpAddr::V4(_) => EndpointFamily::Ipv4,
            IpAddr::V6(_) => EndpointFamily::Ipv6,
        };
        ObservedEndpoint::new(family, self.endpoint.ip().to_string(), self.endpoint.port()).map_err(
            |err| {
                DirectDiscoveryError::new(
                    self.source,
                    DirectCandidateRejection::InvalidEndpoint,
                    err.to_string(),
                )
            },
        )
    }
}

/// Inputs for a deterministic direct path discovery run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathDiscoveryInputs {
    /// LAN advertisements observed locally.
    pub lan_advertisements: Vec<LanPeerAdvertisement>,
    /// Optional user-provided direct UDP endpoint.
    pub explicit_direct_endpoint: Option<String>,
    /// Local UDP endpoints discovered by platform/network code.
    pub local_udp_endpoints: Vec<SocketAddr>,
    /// Optional Tailscale/private-route observations from deterministic or host providers.
    pub tailscale_candidates: Vec<TailscaleCandidateObservation>,
    /// Whether platform probing says IPv6 can be attempted.
    pub platform_ipv6_available: bool,
    /// Caller-supplied monotonic timestamp for stale-provider decisions.
    pub now_micros: u64,
}

/// Deterministic path discovery output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDiscoveryReport {
    /// Ranked direct path candidates.
    pub candidates: Vec<DirectPathCandidate>,
    /// Rejected/disabled sources with safe detail.
    pub rejections: Vec<DirectPathRejection>,
    /// Selected candidate after ranking.
    pub selected: Option<PathCandidateId>,
    /// Structured path logs.
    pub logs: Vec<PathDiscoveryLogEntry>,
}

impl PathDiscoveryReport {
    /// Build a redaction-safe doctor report.
    #[must_use]
    pub fn doctor_report(&self) -> AtpPathDoctorReport {
        AtpPathDoctorReport::from_discovery(self)
    }
}

/// Redaction-safe structured path log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDiscoveryLogEntry {
    /// Source being logged.
    pub source: DirectCandidateSource,
    /// Stable event code.
    pub event: &'static str,
    /// Candidate id, if one was built.
    pub candidate_id: Option<PathCandidateId>,
    /// Redacted endpoint scope.
    pub endpoint_scope: Option<String>,
    /// Rejection reason, if any.
    pub rejection: Option<DirectCandidateRejection>,
}

/// ATP path doctor candidate entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpPathDoctorCandidate {
    /// Candidate id.
    pub id: PathCandidateId,
    /// Candidate source.
    pub source: DirectCandidateSource,
    /// Shared path kind.
    pub kind: PathKind,
    /// Lower values are preferred.
    pub preference_rank: u8,
    /// Redacted endpoint classification.
    pub endpoint_scope: String,
    /// Evidence code explaining availability.
    pub evidence: &'static str,
}

/// ATP path doctor report for direct candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpPathDoctorReport {
    /// Stable report schema.
    pub schema_version: &'static str,
    /// Candidate availability.
    pub candidates: Vec<AtpPathDoctorCandidate>,
    /// Rejection reasons.
    pub rejections: Vec<DirectPathRejection>,
    /// Selected path evidence.
    pub selected: Option<AtpPathDoctorCandidate>,
    /// Safe next-step guidance.
    pub guidance: Vec<&'static str>,
}

impl AtpPathDoctorReport {
    fn from_discovery(report: &PathDiscoveryReport) -> Self {
        let candidates = report
            .candidates
            .iter()
            .map(|candidate| AtpPathDoctorCandidate {
                id: candidate.id,
                source: candidate.source,
                kind: candidate.source.path_kind(),
                preference_rank: candidate.metrics.preference_rank,
                endpoint_scope: candidate.endpoint_scope(),
                evidence: candidate.evidence,
            })
            .collect::<Vec<_>>();
        let selected = report.selected.and_then(|selected| {
            candidates
                .iter()
                .find(|candidate| candidate.id == selected)
                .cloned()
        });
        let guidance = guidance_for(report, selected.as_ref());
        Self {
            schema_version: ATP_PATH_DOCTOR_SCHEMA,
            candidates,
            rejections: report.rejections.clone(),
            selected,
            guidance,
        }
    }
}

/// Run deterministic direct path discovery.
#[must_use]
pub fn discover_direct_paths(
    policy: PathDiscoveryPolicy,
    inputs: PathDiscoveryInputs,
) -> PathDiscoveryReport {
    let mut candidates = Vec::new();
    let mut rejections = Vec::new();
    let mut logs = Vec::new();

    collect_lan_candidates(policy, &inputs, &mut candidates, &mut rejections, &mut logs);
    collect_explicit_candidate(policy, &inputs, &mut candidates, &mut rejections, &mut logs);
    collect_public_ipv6_candidates(policy, &inputs, &mut candidates, &mut rejections, &mut logs);
    collect_tailscale_candidates(policy, &inputs, &mut candidates, &mut rejections, &mut logs);

    candidates.sort_by_key(|candidate| (candidate.metrics.preference_rank, candidate.id.get()));
    let selected = candidates.first().map(|candidate| candidate.id);

    PathDiscoveryReport {
        candidates,
        rejections,
        selected,
        logs,
    }
}

/// Build one explicit direct UDP candidate from `host:port`.
pub fn explicit_direct_candidate(
    policy: PathDiscoveryPolicy,
    endpoint: &str,
    id: PathCandidateId,
    trace_id: PathTraceId,
) -> Result<DirectPathCandidate, DirectDiscoveryError> {
    if !policy.explicit_direct_enabled {
        return Err(DirectDiscoveryError::new(
            DirectCandidateSource::ExplicitDirectUdp,
            DirectCandidateRejection::PolicyDisabled,
            "explicit direct endpoints disabled by policy",
        ));
    }
    if endpoint.trim().is_empty() {
        return Err(DirectDiscoveryError::new(
            DirectCandidateSource::ExplicitDirectUdp,
            DirectCandidateRejection::EmptyEndpoint,
            "endpoint is empty",
        ));
    }
    let endpoint = endpoint.parse::<SocketAddr>().map_err(|err| {
        DirectDiscoveryError::new(
            DirectCandidateSource::ExplicitDirectUdp,
            DirectCandidateRejection::InvalidEndpoint,
            format!("endpoint parse failed: {err}"),
        )
    })?;
    validate_endpoint_basics(DirectCandidateSource::ExplicitDirectUdp, endpoint)?;

    Ok(candidate(
        id,
        trace_id,
        DirectCandidateSource::ExplicitDirectUdp,
        endpoint,
        20,
        "explicit_direct_endpoint_validated",
        Some(20_000),
    ))
}

fn collect_lan_candidates(
    policy: PathDiscoveryPolicy,
    inputs: &PathDiscoveryInputs,
    candidates: &mut Vec<DirectPathCandidate>,
    rejections: &mut Vec<DirectPathRejection>,
    logs: &mut Vec<PathDiscoveryLogEntry>,
) {
    if !policy.lan_discovery_enabled {
        rejections.push(DirectPathRejection::new(
            DirectCandidateSource::LanDiscovery,
            DirectCandidateRejection::PolicyDisabled,
            "lan discovery disabled by policy",
        ));
        logs.push(rejection_log(
            DirectCandidateSource::LanDiscovery,
            DirectCandidateRejection::PolicyDisabled,
            None,
        ));
        return;
    }

    let mut seen = BTreeSet::new();
    for (offset, advertisement) in inputs.lan_advertisements.iter().enumerate() {
        let key = (
            advertisement.peer_label().to_string(),
            advertisement.endpoint(),
        );
        if !seen.insert(key) {
            rejections.push(DirectPathRejection::new(
                DirectCandidateSource::LanDiscovery,
                DirectCandidateRejection::DuplicateAdvertisement,
                endpoint_scope(advertisement.endpoint()),
            ));
            logs.push(rejection_log(
                DirectCandidateSource::LanDiscovery,
                DirectCandidateRejection::DuplicateAdvertisement,
                Some(endpoint_scope(advertisement.endpoint())),
            ));
            continue;
        }
        let candidate = candidate(
            PathCandidateId::new(1_000 + offset as u64),
            PathTraceId::new(11_000 + offset as u64),
            DirectCandidateSource::LanDiscovery,
            advertisement.endpoint(),
            5,
            "lan_advertisement_validated",
            Some(2_000),
        );
        logs.push(candidate_log(&candidate));
        candidates.push(candidate);
    }
}

fn collect_explicit_candidate(
    policy: PathDiscoveryPolicy,
    inputs: &PathDiscoveryInputs,
    candidates: &mut Vec<DirectPathCandidate>,
    rejections: &mut Vec<DirectPathRejection>,
    logs: &mut Vec<PathDiscoveryLogEntry>,
) {
    let Some(endpoint) = inputs.explicit_direct_endpoint.as_deref() else {
        return;
    };
    match explicit_direct_candidate(
        policy,
        endpoint,
        PathCandidateId::new(2_000),
        PathTraceId::new(12_000),
    ) {
        Ok(candidate) => {
            logs.push(candidate_log(&candidate));
            candidates.push(candidate);
        }
        Err(err) => {
            rejections.push(err.rejection());
            logs.push(rejection_log(
                err.candidate_source,
                err.reason,
                Some(err.detail),
            ));
        }
    }
}

fn collect_public_ipv6_candidates(
    policy: PathDiscoveryPolicy,
    inputs: &PathDiscoveryInputs,
    candidates: &mut Vec<DirectPathCandidate>,
    rejections: &mut Vec<DirectPathRejection>,
    logs: &mut Vec<PathDiscoveryLogEntry>,
) {
    if !policy.public_ipv6_enabled {
        rejections.push(DirectPathRejection::new(
            DirectCandidateSource::PublicIpv6,
            DirectCandidateRejection::PolicyDisabled,
            "public ipv6 disabled by policy",
        ));
        logs.push(rejection_log(
            DirectCandidateSource::PublicIpv6,
            DirectCandidateRejection::PolicyDisabled,
            None,
        ));
        return;
    }
    if !inputs.platform_ipv6_available {
        rejections.push(DirectPathRejection::new(
            DirectCandidateSource::PublicIpv6,
            DirectCandidateRejection::Ipv6Unavailable,
            "platform reports ipv6 unavailable",
        ));
        logs.push(rejection_log(
            DirectCandidateSource::PublicIpv6,
            DirectCandidateRejection::Ipv6Unavailable,
            None,
        ));
        return;
    }

    let mut accepted = 0u64;
    for endpoint in &inputs.local_udp_endpoints {
        match public_ipv6_candidate(policy, *endpoint, accepted) {
            Ok(candidate) => {
                accepted += 1;
                logs.push(candidate_log(&candidate));
                candidates.push(candidate);
            }
            Err(err) => {
                rejections.push(err.rejection());
                logs.push(rejection_log(
                    err.candidate_source,
                    err.reason,
                    Some(err.detail),
                ));
            }
        }
    }
}

fn public_ipv6_candidate(
    policy: PathDiscoveryPolicy,
    endpoint: SocketAddr,
    offset: u64,
) -> Result<DirectPathCandidate, DirectDiscoveryError> {
    validate_endpoint_basics(DirectCandidateSource::PublicIpv6, endpoint)?;
    let IpAddr::V6(address) = endpoint.ip() else {
        return Err(DirectDiscoveryError::new(
            DirectCandidateSource::PublicIpv6,
            DirectCandidateRejection::NotPublicIpv6,
            endpoint_scope(endpoint),
        ));
    };
    if !is_public_ipv6(address) {
        return Err(DirectDiscoveryError::new(
            DirectCandidateSource::PublicIpv6,
            DirectCandidateRejection::NotPublicIpv6,
            endpoint_scope(endpoint),
        ));
    }

    let rank = if policy.prefer_public_ipv6 { 10 } else { 30 };
    Ok(candidate(
        PathCandidateId::new(3_000 + offset),
        PathTraceId::new(13_000 + offset),
        DirectCandidateSource::PublicIpv6,
        endpoint,
        rank,
        "public_ipv6_candidate_validated",
        Some(10_000),
    ))
}

fn collect_tailscale_candidates(
    policy: PathDiscoveryPolicy,
    inputs: &PathDiscoveryInputs,
    candidates: &mut Vec<DirectPathCandidate>,
    rejections: &mut Vec<DirectPathRejection>,
    logs: &mut Vec<PathDiscoveryLogEntry>,
) {
    match policy.tailscale_policy {
        TailscalePathPolicy::Disabled => {
            rejections.push(DirectPathRejection::new(
                DirectCandidateSource::TailscaleProvider,
                DirectCandidateRejection::PolicyDisabled,
                "tailscale disabled by configuration",
            ));
            logs.push(rejection_log(
                DirectCandidateSource::TailscaleProvider,
                DirectCandidateRejection::PolicyDisabled,
                None,
            ));
            return;
        }
        TailscalePathPolicy::Forbid => {
            rejections.push(DirectPathRejection::new(
                DirectCandidateSource::TailscaleProvider,
                DirectCandidateRejection::PolicyForbidden,
                "tailscale forbidden by policy; provider candidates ignored",
            ));
            logs.push(rejection_log(
                DirectCandidateSource::TailscaleProvider,
                DirectCandidateRejection::PolicyForbidden,
                None,
            ));
            return;
        }
        TailscalePathPolicy::Allow | TailscalePathPolicy::Prefer => {}
    }

    if inputs.tailscale_candidates.is_empty() {
        rejections.push(DirectPathRejection::new(
            DirectCandidateSource::TailscaleProvider,
            DirectCandidateRejection::TailscaleNotPresent,
            "tailscale provider supplied no candidates",
        ));
        logs.push(rejection_log(
            DirectCandidateSource::TailscaleProvider,
            DirectCandidateRejection::TailscaleNotPresent,
            None,
        ));
        return;
    }

    let mut seen = BTreeSet::new();
    let mut accepted = 0u64;
    for observation in &inputs.tailscale_candidates {
        if !seen.insert(observation.endpoint()) {
            rejections.push(DirectPathRejection::new(
                DirectCandidateSource::TailscaleProvider,
                DirectCandidateRejection::DuplicateAdvertisement,
                endpoint_scope(observation.endpoint()),
            ));
            logs.push(rejection_log(
                DirectCandidateSource::TailscaleProvider,
                DirectCandidateRejection::DuplicateAdvertisement,
                Some(endpoint_scope(observation.endpoint())),
            ));
            continue;
        }

        match tailscale_candidate(policy, inputs.now_micros, observation, accepted) {
            Ok(candidate) => {
                accepted += 1;
                logs.push(candidate_log(&candidate));
                candidates.push(candidate);
            }
            Err(err) => {
                rejections.push(err.rejection());
                logs.push(rejection_log(
                    err.candidate_source,
                    err.reason,
                    Some(err.detail),
                ));
            }
        }
    }
}

fn tailscale_candidate(
    policy: PathDiscoveryPolicy,
    now_micros: u64,
    observation: &TailscaleCandidateObservation,
    offset: u64,
) -> Result<DirectPathCandidate, DirectDiscoveryError> {
    let endpoint = observation.endpoint();
    validate_endpoint_basics(DirectCandidateSource::TailscaleProvider, endpoint)?;
    if !is_tailscale_address(endpoint.ip()) {
        return Err(DirectDiscoveryError::new(
            DirectCandidateSource::TailscaleProvider,
            DirectCandidateRejection::NotTailscaleAddress,
            endpoint_scope(endpoint),
        ));
    }

    if now_micros
        > observation
            .observed_at_micros()
            .saturating_add(policy.tailscale_max_staleness_micros)
    {
        return Err(DirectDiscoveryError::new(
            DirectCandidateSource::TailscaleProvider,
            DirectCandidateRejection::StaleCandidate,
            format!(
                "policy={} source={} scope={}",
                policy.tailscale_policy.code(),
                observation.detection_source().code(),
                endpoint_scope(endpoint)
            ),
        ));
    }

    let rank = match policy.tailscale_policy {
        TailscalePathPolicy::Prefer => 3,
        TailscalePathPolicy::Allow => 15,
        TailscalePathPolicy::Disabled | TailscalePathPolicy::Forbid => unreachable!(
            "disabled and forbidden Tailscale policies are handled before candidate validation"
        ),
    };

    Ok(candidate(
        PathCandidateId::new(4_000 + offset),
        PathTraceId::new(14_000 + offset),
        DirectCandidateSource::TailscaleProvider,
        endpoint,
        rank,
        observation.detection_source().evidence_code(),
        Some(8_000),
    ))
}

fn candidate(
    id: PathCandidateId,
    trace_id: PathTraceId,
    source: DirectCandidateSource,
    endpoint: SocketAddr,
    preference_rank: u8,
    evidence: &'static str,
    expected_rtt_micros: Option<u32>,
) -> DirectPathCandidate {
    DirectPathCandidate {
        id,
        trace_id,
        source,
        endpoint,
        metrics: PathCandidateMetrics {
            preference_rank,
            expected_rtt_micros,
            expected_loss_ppm: Some(1_000),
        },
        evidence,
    }
}

fn validate_endpoint_basics(
    source: DirectCandidateSource,
    endpoint: SocketAddr,
) -> Result<(), DirectDiscoveryError> {
    if endpoint.port() == 0 {
        return Err(DirectDiscoveryError::new(
            source,
            DirectCandidateRejection::ZeroPort,
            endpoint_scope(endpoint),
        ));
    }
    if endpoint.ip().is_unspecified() {
        return Err(DirectDiscoveryError::new(
            source,
            DirectCandidateRejection::UnspecifiedAddress,
            endpoint_scope(endpoint),
        ));
    }
    if endpoint.ip().is_loopback() {
        return Err(DirectDiscoveryError::new(
            source,
            DirectCandidateRejection::LoopbackAddress,
            endpoint_scope(endpoint),
        ));
    }
    if is_multicast(endpoint.ip()) {
        return Err(DirectDiscoveryError::new(
            source,
            DirectCandidateRejection::MulticastAddress,
            endpoint_scope(endpoint),
        ));
    }
    Ok(())
}

fn is_lan_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private() || address.is_link_local() || address.octets()[0] == 169
        }
        IpAddr::V6(address) => is_unique_local_ipv6(address) || is_unicast_link_local_ipv6(address),
    }
}

fn is_tailscale_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_tailscale_ipv4(address),
        IpAddr::V6(address) => is_tailscale_ipv6(address),
    }
}

fn is_tailscale_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_tailscale_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || is_unique_local_ipv6(address)
        || is_unicast_link_local_ipv6(address)
        || is_documentation_ipv6(address))
}

fn is_multicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_multicast(),
        IpAddr::V6(address) => address.is_multicast(),
    }
}

fn is_unique_local_ipv6(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

fn is_unicast_link_local_ipv6(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

fn is_documentation_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn endpoint_scope(endpoint: SocketAddr) -> String {
    match endpoint.ip() {
        IpAddr::V4(address) if is_tailscale_ipv4(address) => {
            format!("tailscale-ipv4:{}", endpoint.port())
        }
        IpAddr::V4(address) if address.is_private() || address.is_link_local() => {
            format!("private-ipv4:{}", endpoint.port())
        }
        IpAddr::V4(address) if address == Ipv4Addr::UNSPECIFIED => {
            format!("unspecified-ipv4:{}", endpoint.port())
        }
        IpAddr::V4(address) if address.is_loopback() => {
            format!("loopback-ipv4:{}", endpoint.port())
        }
        IpAddr::V4(address) if address.is_multicast() => {
            format!("multicast-ipv4:{}", endpoint.port())
        }
        IpAddr::V4(_) => format!("public-ipv4:{}", endpoint.port()),
        IpAddr::V6(address) if address == Ipv6Addr::UNSPECIFIED => {
            format!("unspecified-ipv6:{}", endpoint.port())
        }
        IpAddr::V6(address) if address.is_loopback() => {
            format!("loopback-ipv6:{}", endpoint.port())
        }
        IpAddr::V6(address) if address.is_multicast() => {
            format!("multicast-ipv6:{}", endpoint.port())
        }
        IpAddr::V6(address) if is_tailscale_ipv6(address) => {
            format!("tailscale-ipv6:{}", endpoint.port())
        }
        IpAddr::V6(address)
            if is_unique_local_ipv6(address) || is_unicast_link_local_ipv6(address) =>
        {
            format!("private-ipv6:{}", endpoint.port())
        }
        IpAddr::V6(_) => format!("public-ipv6:{}", endpoint.port()),
    }
}

fn candidate_log(candidate: &DirectPathCandidate) -> PathDiscoveryLogEntry {
    PathDiscoveryLogEntry {
        source: candidate.source,
        event: "candidate_available",
        candidate_id: Some(candidate.id),
        endpoint_scope: Some(candidate.endpoint_scope()),
        rejection: None,
    }
}

fn rejection_log(
    source: DirectCandidateSource,
    rejection: DirectCandidateRejection,
    endpoint_scope: Option<String>,
) -> PathDiscoveryLogEntry {
    PathDiscoveryLogEntry {
        source,
        event: "candidate_rejected",
        candidate_id: None,
        endpoint_scope,
        rejection: Some(rejection),
    }
}

fn guidance_for(
    report: &PathDiscoveryReport,
    selected: Option<&AtpPathDoctorCandidate>,
) -> Vec<&'static str> {
    if let Some(selected) = selected {
        return match selected.source {
            DirectCandidateSource::LanDiscovery => vec![
                "attempt_lan_candidate_first",
                "keep_relay_fallback_until_lan_path_validates",
            ],
            DirectCandidateSource::ExplicitDirectUdp => vec![
                "attempt_explicit_udp_candidate",
                "verify_remote_firewall_and_port_forwarding_if_probe_fails",
            ],
            DirectCandidateSource::PublicIpv6 => vec![
                "attempt_public_ipv6_candidate_first",
                "keep_ipv4_or_relay_fallback_for_ipv6_unavailable_peers",
            ],
            DirectCandidateSource::TailscaleProvider => vec![
                "attempt_tailscale_candidate_when_policy_allows",
                "keep_native_direct_or_atp_relay_fallback_because_tailscale_is_optional",
            ],
        };
    }

    if report
        .rejections
        .iter()
        .all(|rejection| rejection.reason == DirectCandidateRejection::PolicyDisabled)
    {
        return vec!["enable_at_least_one_direct_path_policy_or_configure_relay"];
    }
    vec!["configure_explicit_endpoint_enable_lan_ipv6_tailscale_or_relay_fallback"]
}

/// Deterministic local/e2e scenario catalog for ATP-F2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathDiscoveryScenario {
    /// LAN discovery allowed and one local peer is advertised.
    LanDiscovery,
    /// User supplied an explicit direct endpoint.
    ExplicitDirect,
    /// Platform has a public IPv6 endpoint.
    Ipv6Available,
    /// Deterministic lab Tailscale provider reported one candidate.
    TailscaleLabProvider,
    /// Platform has no IPv6 support.
    Ipv6Unavailable,
    /// Direct discovery is denied by policy.
    PolicyDenied,
}

impl fmt::Display for PathDiscoveryScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LanDiscovery => "lan_discovery",
            Self::ExplicitDirect => "explicit_direct",
            Self::Ipv6Available => "ipv6_available",
            Self::TailscaleLabProvider => "tailscale_lab_provider",
            Self::Ipv6Unavailable => "ipv6_unavailable",
            Self::PolicyDenied => "policy_denied",
        })
    }
}

/// Run a deterministic discovery scenario for local e2e/lab coverage.
#[must_use]
pub fn run_discovery_scenario(scenario: PathDiscoveryScenario) -> AtpPathDoctorReport {
    let policy = match scenario {
        PathDiscoveryScenario::LanDiscovery => {
            PathDiscoveryPolicy::safe_default().with_lan_discovery(true)
        }
        PathDiscoveryScenario::PolicyDenied => PathDiscoveryPolicy::disabled(),
        PathDiscoveryScenario::ExplicitDirect
        | PathDiscoveryScenario::Ipv6Available
        | PathDiscoveryScenario::TailscaleLabProvider
        | PathDiscoveryScenario::Ipv6Unavailable => PathDiscoveryPolicy::safe_default(),
    };

    let lan_advertisements = if matches!(scenario, PathDiscoveryScenario::LanDiscovery) {
        let endpoint = "192.168.1.10:41641".parse().expect("scenario endpoint");
        LanPeerAdvertisement::maybe_new(policy, "peer-a", endpoint, 99, 1_000)
            .expect("scenario advertisement")
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };

    let explicit_direct_endpoint = matches!(scenario, PathDiscoveryScenario::ExplicitDirect)
        .then(|| "198.51.100.20:41641".to_string());
    let local_udp_endpoints = match scenario {
        PathDiscoveryScenario::Ipv6Available => {
            vec![
                "[2606:4700:4700::1111]:41641"
                    .parse()
                    .expect("scenario ipv6"),
            ]
        }
        PathDiscoveryScenario::Ipv6Unavailable => {
            vec!["10.0.0.2:41641".parse().expect("scenario private")]
        }
        _ => Vec::new(),
    };
    let platform_ipv6_available = matches!(scenario, PathDiscoveryScenario::Ipv6Available);
    let tailscale_candidates = if matches!(scenario, PathDiscoveryScenario::TailscaleLabProvider) {
        vec![TailscaleCandidateObservation::new(
            "100.100.10.20:41641".parse().expect("scenario tailscale"),
            TailscaleDetectionSource::LabProvider,
            1_000,
        )]
    } else {
        Vec::new()
    };

    discover_direct_paths(
        policy,
        PathDiscoveryInputs {
            lan_advertisements,
            explicit_direct_endpoint,
            local_udp_endpoints,
            tailscale_candidates,
            platform_ipv6_available,
            now_micros: 2_000,
        },
    )
    .doctor_report()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(address: &str) -> SocketAddr {
        address.parse().expect("socket address")
    }

    #[test]
    fn lan_discovery_is_silent_when_disabled() {
        let policy = PathDiscoveryPolicy::safe_default();
        let advertisement =
            LanPeerAdvertisement::maybe_new(policy, "peer-a", socket("192.168.1.10:41641"), 1, 1)
                .expect("disabled is not an error");

        assert_eq!(advertisement, None);
    }

    #[test]
    fn lan_discovery_advertises_and_deduplicates_local_peers() {
        let policy = PathDiscoveryPolicy::safe_default().with_lan_discovery(true);
        let advertisement =
            LanPeerAdvertisement::maybe_new(policy, "peer-a", socket("192.168.1.10:41641"), 1, 1)
                .expect("advertisement")
                .expect("enabled");
        let report = discover_direct_paths(
            policy,
            PathDiscoveryInputs {
                lan_advertisements: vec![advertisement.clone(), advertisement],
                ..PathDiscoveryInputs::default()
            },
        );

        assert_eq!(report.candidates.len(), 1);
        assert_eq!(
            report.candidates[0].source,
            DirectCandidateSource::LanDiscovery
        );
        assert_eq!(
            report.rejections[0].reason,
            DirectCandidateRejection::DuplicateAdvertisement
        );
        assert_eq!(report.logs[0].event, "candidate_available");
    }

    #[test]
    fn explicit_direct_endpoint_reports_validation_errors() {
        let policy = PathDiscoveryPolicy::safe_default();
        let err = explicit_direct_candidate(
            policy,
            "not an endpoint",
            PathCandidateId::new(1),
            PathTraceId::new(2),
        )
        .expect_err("invalid endpoint");

        assert_eq!(
            err.candidate_source,
            DirectCandidateSource::ExplicitDirectUdp
        );
        assert_eq!(err.reason, DirectCandidateRejection::InvalidEndpoint);
        assert!(err.detail.contains("endpoint parse failed"));
    }

    #[test]
    fn explicit_direct_endpoint_builds_candidate() {
        let candidate = explicit_direct_candidate(
            PathDiscoveryPolicy::safe_default(),
            "198.51.100.20:41641",
            PathCandidateId::new(7),
            PathTraceId::new(8),
        )
        .expect("candidate");

        assert_eq!(candidate.source, DirectCandidateSource::ExplicitDirectUdp);
        assert_eq!(candidate.metrics.preference_rank, 20);
        assert_eq!(
            candidate.to_path_candidate().kind,
            PathKind::ExplicitPublicUdp
        );
    }

    #[test]
    fn public_ipv6_candidate_is_ranked_ahead_when_policy_prefers_it() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs {
                explicit_direct_endpoint: Some("198.51.100.20:41641".to_string()),
                local_udp_endpoints: vec![socket("[2606:4700:4700::1111]:41641")],
                platform_ipv6_available: true,
                ..PathDiscoveryInputs::default()
            },
        );

        assert_eq!(report.candidates.len(), 2);
        assert_eq!(
            report.candidates[0].source,
            DirectCandidateSource::PublicIpv6
        );
        assert_eq!(report.selected, Some(report.candidates[0].id));
    }

    #[test]
    fn public_ipv6_candidate_requires_platform_and_public_address() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![socket("[fd00::1]:41641")],
                platform_ipv6_available: true,
                ..PathDiscoveryInputs::default()
            },
        );

        assert!(report.candidates.is_empty());
        assert_eq!(
            report.rejections[1].reason,
            DirectCandidateRejection::NotPublicIpv6
        );

        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![socket("[2606:4700:4700::1111]:41641")],
                platform_ipv6_available: false,
                ..PathDiscoveryInputs::default()
            },
        );
        assert_eq!(
            report.rejections[1].reason,
            DirectCandidateRejection::Ipv6Unavailable
        );
    }

    #[test]
    fn tailscale_provider_is_optional_and_reports_absence_without_network_dependency() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default(),
            PathDiscoveryInputs::default(),
        );

        assert!(report.candidates.is_empty());
        assert!(report.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::TailscaleNotPresent
        }));
        assert!(report.logs.iter().any(|log| {
            log.source == DirectCandidateSource::TailscaleProvider
                && log.event == "candidate_rejected"
                && log.rejection == Some(DirectCandidateRejection::TailscaleNotPresent)
        }));
    }

    #[test]
    fn tailscale_policy_distinguishes_disabled_forbidden_allowed_and_preferred() {
        let tailscale = TailscaleCandidateObservation::new(
            socket("100.100.10.20:41641"),
            TailscaleDetectionSource::LabProvider,
            1_000,
        );
        let public_ipv6 = socket("[2606:4700:4700::1111]:41641");

        let disabled = discover_direct_paths(
            PathDiscoveryPolicy::safe_default()
                .with_tailscale_policy(TailscalePathPolicy::Disabled),
            PathDiscoveryInputs {
                tailscale_candidates: vec![tailscale.clone()],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(disabled.candidates.is_empty());
        assert!(disabled.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::PolicyDisabled
        }));

        let forbidden = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Forbid),
            PathDiscoveryInputs {
                tailscale_candidates: vec![tailscale.clone()],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(forbidden.candidates.is_empty());
        assert!(forbidden.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::PolicyForbidden
        }));

        let allowed = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Allow),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![public_ipv6],
                tailscale_candidates: vec![tailscale.clone()],
                platform_ipv6_available: true,
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert_eq!(
            allowed.selected.and_then(|id| {
                allowed
                    .candidates
                    .iter()
                    .find(|candidate| candidate.id == id)
                    .map(|candidate| candidate.source)
            }),
            Some(DirectCandidateSource::PublicIpv6)
        );

        let preferred = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Prefer),
            PathDiscoveryInputs {
                local_udp_endpoints: vec![public_ipv6],
                tailscale_candidates: vec![tailscale],
                platform_ipv6_available: true,
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert_eq!(
            preferred.selected.and_then(|id| {
                preferred
                    .candidates
                    .iter()
                    .find(|candidate| candidate.id == id)
                    .map(|candidate| candidate.source)
            }),
            Some(DirectCandidateSource::TailscaleProvider)
        );
    }

    #[test]
    fn tailscale_candidates_are_redacted_validated_and_stale_checked() {
        let report = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Prefer),
            PathDiscoveryInputs {
                explicit_direct_endpoint: Some("198.51.100.20:41641".to_string()),
                tailscale_candidates: vec![TailscaleCandidateObservation::new(
                    socket("100.100.10.20:41641"),
                    TailscaleDetectionSource::LabProvider,
                    1_000,
                )],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );

        assert_eq!(
            report
                .selected
                .and_then(|id| report
                    .candidates
                    .iter()
                    .find(|candidate| candidate.id == id))
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::TailscaleProvider)
        );
        let doctor = report.doctor_report();
        let selected = doctor.selected.as_ref().expect("selected Tailscale");
        assert_eq!(selected.kind, PathKind::TailscaleIp);
        assert_eq!(selected.endpoint_scope, "tailscale-ipv4:41641");
        assert_eq!(
            selected.evidence,
            "tailscale_lab_provider_candidate_validated"
        );
        assert!(
            doctor.guidance.contains(
                &"keep_native_direct_or_atp_relay_fallback_because_tailscale_is_optional"
            )
        );
        assert!(
            doctor
                .candidates
                .iter()
                .all(|candidate| !candidate.endpoint_scope.contains("100.100.10.20"))
        );

        let stale = discover_direct_paths(
            PathDiscoveryPolicy::safe_default()
                .with_tailscale_policy(TailscalePathPolicy::Allow)
                .with_tailscale_max_staleness_micros(10),
            PathDiscoveryInputs {
                tailscale_candidates: vec![TailscaleCandidateObservation::new(
                    socket("100.100.10.20:41641"),
                    TailscaleDetectionSource::StatusCommand,
                    1_000,
                )],
                now_micros: 1_011,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(stale.candidates.is_empty());
        assert!(stale.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::StaleCandidate
                && rejection.detail.contains("source=status_command")
                && !rejection.detail.contains("100.100.10.20")
        }));

        let wrong_network = discover_direct_paths(
            PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Allow),
            PathDiscoveryInputs {
                tailscale_candidates: vec![TailscaleCandidateObservation::new(
                    socket("10.0.0.2:41641"),
                    TailscaleDetectionSource::LocalInterface,
                    1_000,
                )],
                now_micros: 2_000,
                ..PathDiscoveryInputs::default()
            },
        );
        assert!(wrong_network.rejections.iter().any(|rejection| {
            rejection.source == DirectCandidateSource::TailscaleProvider
                && rejection.reason == DirectCandidateRejection::NotTailscaleAddress
                && rejection.detail == "private-ipv4:41641"
        }));
    }

    #[test]
    fn path_doctor_reports_availability_rejections_and_guidance_without_endpoint_leaks() {
        let report = run_discovery_scenario(PathDiscoveryScenario::Ipv6Available);

        assert_eq!(report.schema_version, ATP_PATH_DOCTOR_SCHEMA);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(
            report.selected.as_ref().map(|candidate| candidate.source),
            Some(DirectCandidateSource::PublicIpv6)
        );
        assert_eq!(report.candidates[0].endpoint_scope, "public-ipv6:41641");
        assert!(
            report
                .guidance
                .contains(&"attempt_public_ipv6_candidate_first")
        );
    }

    #[test]
    fn deterministic_scenarios_cover_pnemzp_paths() {
        let scenarios = [
            PathDiscoveryScenario::LanDiscovery,
            PathDiscoveryScenario::ExplicitDirect,
            PathDiscoveryScenario::Ipv6Available,
            PathDiscoveryScenario::TailscaleLabProvider,
            PathDiscoveryScenario::Ipv6Unavailable,
            PathDiscoveryScenario::PolicyDenied,
        ];
        let reports = scenarios
            .into_iter()
            .map(run_discovery_scenario)
            .collect::<Vec<_>>();

        assert_eq!(
            reports[0]
                .selected
                .as_ref()
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::LanDiscovery)
        );
        assert_eq!(
            reports[1]
                .selected
                .as_ref()
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::ExplicitDirectUdp)
        );
        assert_eq!(
            reports[2]
                .selected
                .as_ref()
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::PublicIpv6)
        );
        assert_eq!(
            reports[3]
                .selected
                .as_ref()
                .map(|candidate| candidate.source),
            Some(DirectCandidateSource::TailscaleProvider)
        );
        assert!(reports[4].selected.is_none());
        assert_eq!(
            reports[5].guidance,
            vec!["enable_at_least_one_direct_path_policy_or_configure_relay"]
        );
    }

    #[test]
    fn tailscale_lab_provider_scenario_is_redaction_safe() {
        let report = run_discovery_scenario(PathDiscoveryScenario::TailscaleLabProvider);

        assert_eq!(
            report.selected.as_ref().map(|candidate| candidate.source),
            Some(DirectCandidateSource::TailscaleProvider)
        );
        let candidate = report.selected.as_ref().expect("candidate");
        assert_eq!(candidate.endpoint_scope, "tailscale-ipv4:41641");
        assert_eq!(
            candidate.evidence,
            "tailscale_lab_provider_candidate_validated"
        );
    }
}
