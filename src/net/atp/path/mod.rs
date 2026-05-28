//! NAT classification and migration state for ATP path discovery.

use crate::net::atp::stun::{EndpointFamily, EndpointObservation, ObservedEndpoint};
use std::collections::BTreeMap;

/// Coarse NAT profile inferred from endpoint observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NatProfile {
    /// Public IPv6 is directly usable.
    Ipv6Direct,
    /// UDP appears usable with stable endpoint mapping.
    LikelyEasyNat,
    /// Multiple observers saw incompatible mappings, suggesting symmetric NAT.
    HardSymmetricNat,
    /// UDP probing failed before any useful observation was made.
    UdpBlocked,
    /// Evidence is insufficient or contradictory.
    Unknown,
}

/// Hairpin behavior evidence for a NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HairpinBehavior {
    /// Hairpinning was measured successfully.
    Supported,
    /// Hairpinning was measured and failed.
    NotSupported,
    /// Hairpinning was not measured.
    Unknown,
}

/// Confidence attached to a NAT classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NatConfidence {
    /// Evidence is weak or absent.
    Low,
    /// Evidence is plausible but not conclusive.
    Medium,
    /// Evidence is strong enough for path-selection decisions.
    High,
}

/// UDP probe outcome before endpoint classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UdpProbe {
    /// UDP probe completed.
    Succeeded,
    /// UDP probe failed or timed out.
    Blocked,
    /// UDP probe has not run.
    NotMeasured,
}

/// Policy for using Tailscale-derived path candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TailscalePreference {
    /// Use Tailscale when a provider yields candidates, but do not prefer it.
    Auto,
    /// Prefer Tailscale candidates over other non-relay paths.
    Prefer,
    /// Ignore Tailscale provider output.
    Disabled,
}

/// Router-assist protocols that may expose a public UDP mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouterAssistProtocol {
    /// UPnP IGD port mapping.
    UpnpIgd,
    /// NAT-PMP port mapping.
    NatPmp,
    /// Port Control Protocol mapping.
    Pcp,
}

impl RouterAssistProtocol {
    /// Stable protocol code for path logs and doctor output.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UpnpIgd => "upnp_igd",
            Self::NatPmp => "nat_pmp",
            Self::Pcp => "pcp",
        }
    }
}

/// Policy for using optional router-assist providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterAssistPolicy {
    enabled: bool,
    mapping_mutation_allowed: bool,
    max_mapping_lifetime_micros: u64,
    prefer_pcp: bool,
}

impl RouterAssistPolicy {
    /// Router assist is disabled; hole punching must use rendezvous or fallback.
    pub const DISABLED: Self = Self {
        enabled: false,
        mapping_mutation_allowed: false,
        max_mapping_lifetime_micros: 0,
        prefer_pcp: false,
    };

    /// Build a capability-gated router-assist policy.
    #[must_use]
    pub const fn new(mapping_mutation_allowed: bool, max_mapping_lifetime_micros: u64) -> Self {
        Self {
            enabled: true,
            mapping_mutation_allowed,
            max_mapping_lifetime_micros,
            prefer_pcp: true,
        }
    }

    /// Prefer PCP over NAT-PMP/UPnP when multiple mappings are available.
    #[must_use]
    pub const fn with_prefer_pcp(mut self, prefer_pcp: bool) -> Self {
        self.prefer_pcp = prefer_pcp;
        self
    }

    /// Whether router assist is enabled at all.
    #[must_use]
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Whether the caller granted authority to mutate router mappings.
    #[must_use]
    pub const fn mapping_mutation_allowed(self) -> bool {
        self.mapping_mutation_allowed
    }

    /// Maximum mapping lifetime admitted by policy.
    #[must_use]
    pub const fn max_mapping_lifetime_micros(self) -> u64 {
        self.max_mapping_lifetime_micros
    }
}

/// Deterministic router-assist provider failure surfaced as a non-fatal caveat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAssistProviderFailure {
    reason: String,
}

impl RouterAssistProviderFailure {
    /// Construct a provider failure.
    ///
    /// # Errors
    ///
    /// Returns [`RouterAssistCandidateError::EmptyFailureReason`] when the
    /// reason is empty or whitespace.
    pub fn new(reason: impl Into<String>) -> Result<Self, RouterAssistCandidateError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(RouterAssistCandidateError::EmptyFailureReason);
        }
        Ok(Self { reason })
    }

    /// Stable failure reason for path logs.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Provider-reported public mapping candidate for optional router assist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAssistProviderCandidate {
    provider_label: String,
    protocol: RouterAssistProtocol,
    internal_endpoint: ObservedEndpoint,
    external_endpoint: ObservedEndpoint,
    lease_lifetime_micros: u64,
    observed_at_micros: u64,
}

impl RouterAssistProviderCandidate {
    /// Build a provider candidate without invoking a router API.
    ///
    /// # Errors
    ///
    /// Returns [`RouterAssistCandidateError::EmptyProviderLabel`] or
    /// [`RouterAssistCandidateError::ZeroLeaseLifetime`] for invalid metadata.
    pub fn new(
        provider_label: impl Into<String>,
        protocol: RouterAssistProtocol,
        internal_endpoint: ObservedEndpoint,
        external_endpoint: ObservedEndpoint,
        lease_lifetime_micros: u64,
        observed_at_micros: u64,
    ) -> Result<Self, RouterAssistCandidateError> {
        let provider_label = provider_label.into();
        if provider_label.trim().is_empty() {
            return Err(RouterAssistCandidateError::EmptyProviderLabel);
        }
        if lease_lifetime_micros == 0 {
            return Err(RouterAssistCandidateError::ZeroLeaseLifetime);
        }

        Ok(Self {
            provider_label,
            protocol,
            internal_endpoint,
            external_endpoint,
            lease_lifetime_micros,
            observed_at_micros,
        })
    }

    /// Provider label used in diagnostic output.
    #[must_use]
    pub fn provider_label(&self) -> &str {
        &self.provider_label
    }

    /// Router-assist protocol used by this mapping.
    #[must_use]
    pub const fn protocol(&self) -> RouterAssistProtocol {
        self.protocol
    }

    /// Local UDP endpoint that would receive traffic.
    #[must_use]
    pub const fn internal_endpoint(&self) -> &ObservedEndpoint {
        &self.internal_endpoint
    }

    /// Public UDP endpoint advertised through rendezvous.
    #[must_use]
    pub const fn external_endpoint(&self) -> &ObservedEndpoint {
        &self.external_endpoint
    }

    /// Mapping lifetime reported by the provider.
    #[must_use]
    pub const fn lease_lifetime_micros(&self) -> u64 {
        self.lease_lifetime_micros
    }

    /// Deterministic observation timestamp.
    #[must_use]
    pub const fn observed_at_micros(&self) -> u64 {
        self.observed_at_micros
    }
}

/// Deterministic provider failure surfaced as a non-fatal path caveat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleProviderFailure {
    reason: String,
}

impl TailscaleProviderFailure {
    /// Construct a provider failure.
    ///
    /// # Errors
    ///
    /// Returns [`TailscaleCandidateError::EmptyFailureReason`] when the reason
    /// is empty or whitespace.
    pub fn new(reason: impl Into<String>) -> Result<Self, TailscaleCandidateError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(TailscaleCandidateError::EmptyFailureReason);
        }
        Ok(Self { reason })
    }

    /// Stable failure reason for path logs.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Provider output for one peer's Tailscale reachability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleProviderCandidate {
    node_id: String,
    peer_label: String,
    endpoint: ObservedEndpoint,
    magic_dns_name: Option<String>,
    derp_region_id: Option<u16>,
    observed_at_micros: u64,
}

impl TailscaleProviderCandidate {
    /// Build one provider candidate without depending on a tailnet client.
    ///
    /// # Errors
    ///
    /// Returns [`TailscaleCandidateError::EmptyNodeId`] or
    /// [`TailscaleCandidateError::EmptyPeerLabel`] for blank identifiers.
    pub fn new(
        node_id: impl Into<String>,
        peer_label: impl Into<String>,
        endpoint: ObservedEndpoint,
        magic_dns_name: Option<String>,
        derp_region_id: Option<u16>,
        observed_at_micros: u64,
    ) -> Result<Self, TailscaleCandidateError> {
        let node_id = node_id.into();
        if node_id.trim().is_empty() {
            return Err(TailscaleCandidateError::EmptyNodeId);
        }

        let peer_label = peer_label.into();
        if peer_label.trim().is_empty() {
            return Err(TailscaleCandidateError::EmptyPeerLabel);
        }

        Ok(Self {
            node_id,
            peer_label,
            endpoint,
            magic_dns_name,
            derp_region_id,
            observed_at_micros,
        })
    }

    /// Provider node identifier.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Redacted or caller-supplied peer label.
    #[must_use]
    pub fn peer_label(&self) -> &str {
        &self.peer_label
    }

    /// Endpoint offered by the provider.
    #[must_use]
    pub const fn endpoint(&self) -> &ObservedEndpoint {
        &self.endpoint
    }

    /// Optional MagicDNS name.
    #[must_use]
    pub fn magic_dns_name(&self) -> Option<&str> {
        self.magic_dns_name.as_deref()
    }

    /// Optional DERP region hint from the provider.
    #[must_use]
    pub const fn derp_region_id(&self) -> Option<u16> {
        self.derp_region_id
    }

    /// Deterministic observation timestamp.
    #[must_use]
    pub const fn observed_at_micros(&self) -> u64 {
        self.observed_at_micros
    }
}

/// Path metrics shared with path racing and proof summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCandidateMetrics {
    /// Lower values race earlier.
    pub preference_rank: u8,
    /// Conservative RTT hint for the path race.
    pub expected_rtt_micros: Option<u32>,
    /// Expected loss in parts per million.
    pub expected_loss_ppm: Option<u32>,
}

/// Stable proof summary for a Tailscale path candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleProofSummary {
    /// Provider node identifier.
    pub node_id: String,
    /// Redacted or caller-supplied peer label.
    pub peer_label: String,
    /// Whether MagicDNS was present.
    pub magic_dns_present: bool,
    /// Stable caveat code.
    pub caveat: &'static str,
}

/// Candidate path emitted from Tailscale provider output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscalePathCandidate {
    endpoint: ObservedEndpoint,
    magic_dns_name: Option<String>,
    derp_region_id: Option<u16>,
    metrics: PathCandidateMetrics,
    proof_summary: TailscaleProofSummary,
}

impl TailscalePathCandidate {
    /// Endpoint to race.
    #[must_use]
    pub const fn endpoint(&self) -> &ObservedEndpoint {
        &self.endpoint
    }

    /// Optional MagicDNS name.
    #[must_use]
    pub fn magic_dns_name(&self) -> Option<&str> {
        self.magic_dns_name.as_deref()
    }

    /// Optional DERP region hint.
    #[must_use]
    pub const fn derp_region_id(&self) -> Option<u16> {
        self.derp_region_id
    }

    /// Candidate metrics for path racing.
    #[must_use]
    pub const fn metrics(&self) -> PathCandidateMetrics {
        self.metrics
    }

    /// Redaction-safe proof summary.
    #[must_use]
    pub const fn proof_summary(&self) -> &TailscaleProofSummary {
        &self.proof_summary
    }
}

/// Candidate selection output that keeps provider failure non-fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleCandidateSet {
    candidates: Vec<TailscalePathCandidate>,
    provider_failure: Option<TailscaleProviderFailure>,
    caveat: &'static str,
}

impl TailscaleCandidateSet {
    /// Selected candidates.
    #[must_use]
    pub fn candidates(&self) -> &[TailscalePathCandidate] {
        &self.candidates
    }

    /// Non-fatal provider failure, if any.
    #[must_use]
    pub const fn provider_failure(&self) -> Option<&TailscaleProviderFailure> {
        self.provider_failure.as_ref()
    }

    /// Stable caveat code for path logs.
    #[must_use]
    pub const fn caveat(&self) -> &'static str {
        self.caveat
    }
}

/// Selected router-assist candidates plus policy caveat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAssistCandidateSet {
    candidates: Vec<RouterAssistProviderCandidate>,
    selected: Option<RouterAssistProviderCandidate>,
    provider_failure: Option<RouterAssistProviderFailure>,
    caveat: &'static str,
}

impl RouterAssistCandidateSet {
    /// Policy-approved router-assist candidates.
    #[must_use]
    pub fn candidates(&self) -> &[RouterAssistProviderCandidate] {
        &self.candidates
    }

    /// Deterministically selected router-assist candidate, if one is usable.
    #[must_use]
    pub const fn selected(&self) -> Option<&RouterAssistProviderCandidate> {
        self.selected.as_ref()
    }

    /// Non-fatal provider failure, if any.
    #[must_use]
    pub const fn provider_failure(&self) -> Option<&RouterAssistProviderFailure> {
        self.provider_failure.as_ref()
    }

    /// Stable caveat code for path logs and doctor output.
    #[must_use]
    pub const fn caveat(&self) -> &'static str {
        self.caveat
    }

    /// Router assist is always optional; relay/rendezvous fallback remains valid.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        false
    }
}

/// Stable path-doctor recommendation for NAT traversal and fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathDoctorRecommendation {
    /// Public IPv6 should be used directly.
    UseIpv6Direct,
    /// UDP hole punching is expected to be viable.
    TryNatPunchedUdp,
    /// Router assist may help, but relay remains the fallback.
    TryRouterAssistThenRelay,
    /// Hard NAT should fall back to relay or an explicitly configured path provider.
    UseRelayOrTailscale,
    /// UDP is blocked; use stream-friendly fallback transport.
    UseRelayOrTcpTlsFallback,
    /// Evidence is insufficient for a deterministic recommendation.
    GatherMoreEvidence,
}

impl PathDoctorRecommendation {
    /// Stable recommendation code for CLI output and proof logs.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UseIpv6Direct => "use_ipv6_direct",
            Self::TryNatPunchedUdp => "try_nat_punched_udp",
            Self::TryRouterAssistThenRelay => "try_router_assist_then_relay",
            Self::UseRelayOrTailscale => "use_relay_or_tailscale",
            Self::UseRelayOrTcpTlsFallback => "use_relay_or_tcp_tls_fallback",
            Self::GatherMoreEvidence => "gather_more_evidence",
        }
    }
}

/// Whether path selection could mutate router state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouterAssistMutationStatus {
    /// Router assist is disabled by policy.
    Disabled,
    /// Router assist was enabled but mapping mutation authority was not granted.
    BlockedWithoutCapability,
    /// Router assist policy was malformed.
    InvalidLifetimePolicy,
    /// Provider failure was surfaced as a non-fatal diagnostic.
    ProviderFailedNonfatal,
    /// Providers returned no policy-approved mapping.
    NoPolicyApprovedCandidate,
    /// A provider candidate was selected under explicit mapping authority.
    ExplicitlyAuthorizedCandidate,
}

impl RouterAssistMutationStatus {
    /// Stable mutation-status code for CLI output and proof logs.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Disabled => "router_assist_disabled",
            Self::BlockedWithoutCapability => "router_assist_blocked_without_capability",
            Self::InvalidLifetimePolicy => "router_assist_invalid_lifetime_policy",
            Self::ProviderFailedNonfatal => "router_assist_provider_failed_nonfatal",
            Self::NoPolicyApprovedCandidate => "router_assist_no_policy_approved_candidate",
            Self::ExplicitlyAuthorizedCandidate => "router_assist_explicitly_authorized_candidate",
        }
    }
}

/// Deterministic path-doctor report for NAT and router-assist decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAssistPathDoctorReport {
    nat_profile: NatProfile,
    nat_confidence: NatConfidence,
    hairpin: HairpinBehavior,
    nat_caveat: &'static str,
    router_assist_caveat: &'static str,
    router_assist_protocol: Option<RouterAssistProtocol>,
    recommendation: PathDoctorRecommendation,
    mutation_status: RouterAssistMutationStatus,
}

impl RouterAssistPathDoctorReport {
    /// NAT profile inferred from rendezvous observations.
    #[must_use]
    pub const fn nat_profile(&self) -> NatProfile {
        self.nat_profile
    }

    /// NAT classification confidence.
    #[must_use]
    pub const fn nat_confidence(&self) -> NatConfidence {
        self.nat_confidence
    }

    /// Hairpin measurement carried into path-doctor output.
    #[must_use]
    pub const fn hairpin(&self) -> HairpinBehavior {
        self.hairpin
    }

    /// Stable NAT caveat code.
    #[must_use]
    pub const fn nat_caveat(&self) -> &'static str {
        self.nat_caveat
    }

    /// Stable router-assist caveat code.
    #[must_use]
    pub const fn router_assist_caveat(&self) -> &'static str {
        self.router_assist_caveat
    }

    /// Selected router-assist protocol, if one was authorized.
    #[must_use]
    pub const fn router_assist_protocol(&self) -> Option<RouterAssistProtocol> {
        self.router_assist_protocol
    }

    /// Deterministic path-doctor recommendation.
    #[must_use]
    pub const fn recommendation(&self) -> PathDoctorRecommendation {
        self.recommendation
    }

    /// Router-assist mutation status.
    #[must_use]
    pub const fn mutation_status(&self) -> RouterAssistMutationStatus {
        self.mutation_status
    }

    /// Whether this report authorizes a router mapping mutation.
    #[must_use]
    pub const fn router_state_change_authorized(&self) -> bool {
        matches!(
            self.mutation_status,
            RouterAssistMutationStatus::ExplicitlyAuthorizedCandidate
        )
    }
}

/// Validation errors for Tailscale candidate input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TailscaleCandidateError {
    /// Provider node id was empty.
    #[error("tailscale node id is empty")]
    EmptyNodeId,
    /// Peer label was empty.
    #[error("tailscale peer label is empty")]
    EmptyPeerLabel,
    /// Provider failure reason was empty.
    #[error("tailscale provider failure reason is empty")]
    EmptyFailureReason,
}

/// Validation errors for router-assist provider input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouterAssistCandidateError {
    /// Provider label was empty.
    #[error("router-assist provider label is empty")]
    EmptyProviderLabel,
    /// Mapping lease lifetime was zero.
    #[error("router-assist lease lifetime is zero")]
    ZeroLeaseLifetime,
    /// Provider failure reason was empty.
    #[error("router-assist provider failure reason is empty")]
    EmptyFailureReason,
}

/// Stable identifier for an ATP transport path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AtpPathId(u64);

impl AtpPathId {
    /// The initial path used by a new connection.
    pub const INITIAL: Self = Self(0);

    /// Construct a path identifier from a deterministic numeric value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the numeric path identifier.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Local and remote endpoint pair that defines one ATP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpPathEndpoints {
    local: ObservedEndpoint,
    remote: ObservedEndpoint,
}

impl AtpPathEndpoints {
    /// Construct a path endpoint pair.
    #[must_use]
    pub const fn new(local: ObservedEndpoint, remote: ObservedEndpoint) -> Self {
        Self { local, remote }
    }

    /// Local UDP endpoint.
    #[must_use]
    pub const fn local(&self) -> &ObservedEndpoint {
        &self.local
    }

    /// Remote UDP endpoint.
    #[must_use]
    pub const fn remote(&self) -> &ObservedEndpoint {
        &self.remote
    }

    /// Whether the remote endpoint changed while the local endpoint stayed stable.
    #[must_use]
    pub fn is_nat_rebinding_from(&self, previous: &Self) -> bool {
        self.local == previous.local && self.remote != previous.remote
    }
}

/// Candidate path offered to the ATP path manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpPathCandidate {
    id: AtpPathId,
    endpoints: AtpPathEndpoints,
    preference_rank: u8,
    observed_at_micros: u64,
    explanation: String,
    verifier_context: String,
}

impl AtpPathCandidate {
    /// Build a candidate path with a user-visible explanation and verifier handle.
    ///
    /// # Errors
    ///
    /// Returns [`PathMigrationError::EmptyExplanation`] or
    /// [`PathMigrationError::EmptyVerifierContext`] when diagnostic text is blank.
    pub fn new(
        id: AtpPathId,
        endpoints: AtpPathEndpoints,
        preference_rank: u8,
        observed_at_micros: u64,
        explanation: impl Into<String>,
        verifier_context: impl Into<String>,
    ) -> Result<Self, PathMigrationError> {
        let explanation = explanation.into();
        if explanation.trim().is_empty() {
            return Err(PathMigrationError::EmptyExplanation);
        }

        let verifier_context = verifier_context.into();
        if verifier_context.trim().is_empty() {
            return Err(PathMigrationError::EmptyVerifierContext);
        }

        Ok(Self {
            id,
            endpoints,
            preference_rank,
            observed_at_micros,
            explanation,
            verifier_context,
        })
    }

    /// Candidate path identifier.
    #[must_use]
    pub const fn id(&self) -> AtpPathId {
        self.id
    }

    /// Endpoint pair for this path.
    #[must_use]
    pub const fn endpoints(&self) -> &AtpPathEndpoints {
        &self.endpoints
    }

    /// Lower rank wins path races.
    #[must_use]
    pub const fn preference_rank(&self) -> u8 {
        self.preference_rank
    }

    /// Deterministic observation timestamp.
    #[must_use]
    pub const fn observed_at_micros(&self) -> u64 {
        self.observed_at_micros
    }

    /// User-visible path explanation.
    #[must_use]
    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    /// Verifier continuity context for replay artifacts.
    #[must_use]
    pub fn verifier_context(&self) -> &str {
        &self.verifier_context
    }
}

/// Reason a path migration was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMigrationReason {
    /// Endpoint intentionally requested migration to a better path.
    ActiveMigration,
    /// Remote endpoint changed without a user-visible path switch.
    NatRebinding,
    /// Peer supplied a preferred address.
    PreferredAddress,
    /// Direct path degraded and relay fallback was selected.
    RelayFallback,
    /// Tailscale-like provider replaced the active path.
    TailscaleReplacement,
    /// Mobile network churn produced a new viable path.
    MobileChurn,
}

/// Path migration lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMigrationStatus {
    /// Migration request was recorded.
    Requested,
    /// QUIC PATH_CHALLENGE is outstanding.
    Validating,
    /// PATH_RESPONSE matched the outstanding challenge.
    Validated,
    /// Migration was rejected.
    Rejected,
    /// Migration became the active path.
    Committed,
    /// Validation timed out.
    TimedOut,
}

/// Continuity guarantees preserved across migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathContinuity {
    /// Stream data offsets and flow-control windows remain bound to the connection.
    pub stream_flow_control: bool,
    /// Congestion and loss accounting remain attached to the connection.
    pub congestion_loss: bool,
    /// Packet protection and key phase remain continuous.
    pub packet_protection: bool,
    /// ATP object verifier context remains continuous.
    pub verifier: bool,
}

impl PathContinuity {
    /// Continuity required for an ATP migration commit.
    pub const VERIFIED: Self = Self {
        stream_flow_control: true,
        congestion_loss: true,
        packet_protection: true,
        verifier: true,
    };

    /// Whether every continuity invariant is preserved.
    #[must_use]
    pub const fn is_verified(self) -> bool {
        self.stream_flow_control && self.congestion_loss && self.packet_protection && self.verifier
    }
}

/// Immutable record of one path migration attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMigrationRecord {
    sequence: u64,
    old_path_id: AtpPathId,
    candidate: AtpPathCandidate,
    reason: PathMigrationReason,
    status: PathMigrationStatus,
    requested_at_micros: u64,
    updated_at_micros: u64,
    continuity: PathContinuity,
}

impl PathMigrationRecord {
    /// Monotonic migration attempt sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Path active when the migration was requested.
    #[must_use]
    pub const fn old_path_id(&self) -> AtpPathId {
        self.old_path_id
    }

    /// Candidate path.
    #[must_use]
    pub const fn candidate(&self) -> &AtpPathCandidate {
        &self.candidate
    }

    /// Migration reason.
    #[must_use]
    pub const fn reason(&self) -> PathMigrationReason {
        self.reason
    }

    /// Current record status.
    #[must_use]
    pub const fn status(&self) -> PathMigrationStatus {
        self.status
    }

    /// Request timestamp.
    #[must_use]
    pub const fn requested_at_micros(&self) -> u64 {
        self.requested_at_micros
    }

    /// Last update timestamp.
    #[must_use]
    pub const fn updated_at_micros(&self) -> u64 {
        self.updated_at_micros
    }

    /// Continuity guarantees.
    #[must_use]
    pub const fn continuity(&self) -> PathContinuity {
        self.continuity
    }

    fn with_status(mut self, status: PathMigrationStatus, now_micros: u64) -> Self {
        self.status = status;
        self.updated_at_micros = now_micros;
        self
    }
}

/// Errors returned by ATP path migration state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathMigrationError {
    /// Candidate explanation was blank.
    #[error("path explanation is empty")]
    EmptyExplanation,
    /// Candidate verifier context was blank.
    #[error("path verifier context is empty")]
    EmptyVerifierContext,
    /// Candidate path is already active.
    #[error("path is already active")]
    AlreadyActive,
    /// Candidate path already has an outstanding migration attempt.
    #[error("path migration is already pending")]
    AlreadyPending,
    /// No pending migration exists for the path.
    #[error("path migration is not pending")]
    NotPending,
    /// Commit was attempted before path validation completed.
    #[error("path migration is not validated")]
    NotValidated,
    /// Continuity invariants were not preserved.
    #[error("path migration continuity invariant failed")]
    ContinuityFailed,
}

/// ATP path manager for request/observe/race/reject migration hooks.
#[derive(Debug, Clone)]
pub struct AtpPathManager {
    active_path: AtpPathCandidate,
    pending: BTreeMap<AtpPathId, PathMigrationRecord>,
    history: Vec<PathMigrationRecord>,
    next_sequence: u64,
}

impl AtpPathManager {
    /// Construct a path manager around the initial path.
    #[must_use]
    pub fn new(active_path: AtpPathCandidate) -> Self {
        Self {
            active_path,
            pending: BTreeMap::new(),
            history: Vec::new(),
            next_sequence: 1,
        }
    }

    /// Active path candidate.
    #[must_use]
    pub const fn active_path(&self) -> &AtpPathCandidate {
        &self.active_path
    }

    /// Active path identifier.
    #[must_use]
    pub const fn active_path_id(&self) -> AtpPathId {
        self.active_path.id()
    }

    /// Pending migration attempts.
    #[must_use]
    pub fn pending(&self) -> &BTreeMap<AtpPathId, PathMigrationRecord> {
        &self.pending
    }

    /// Completed or rejected migration records.
    #[must_use]
    pub fn history(&self) -> &[PathMigrationRecord] {
        &self.history
    }

    /// Record a migration request and mark it as awaiting validation.
    pub fn request_migration(
        &mut self,
        candidate: AtpPathCandidate,
        reason: PathMigrationReason,
        now_micros: u64,
    ) -> Result<PathMigrationRecord, PathMigrationError> {
        if candidate.id() == self.active_path.id() {
            return Err(PathMigrationError::AlreadyActive);
        }
        if self.pending.contains_key(&candidate.id()) {
            return Err(PathMigrationError::AlreadyPending);
        }

        let record = PathMigrationRecord {
            sequence: self.next_sequence,
            old_path_id: self.active_path.id(),
            candidate,
            reason,
            status: PathMigrationStatus::Validating,
            requested_at_micros: now_micros,
            updated_at_micros: now_micros,
            continuity: PathContinuity::VERIFIED,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.pending.insert(record.candidate.id(), record.clone());
        Ok(record)
    }

    /// Mark a pending path as validation-confirmed.
    pub fn observe_validation(
        &mut self,
        path_id: AtpPathId,
        now_micros: u64,
    ) -> Result<PathMigrationRecord, PathMigrationError> {
        let Some(record) = self.pending.get_mut(&path_id) else {
            return Err(PathMigrationError::NotPending);
        };
        *record = record
            .clone()
            .with_status(PathMigrationStatus::Validated, now_micros);
        Ok(record.clone())
    }

    /// Commit a validated migration as the active path.
    pub fn commit_migration(
        &mut self,
        path_id: AtpPathId,
        now_micros: u64,
    ) -> Result<PathMigrationRecord, PathMigrationError> {
        let Some(record) = self.pending.remove(&path_id) else {
            return Err(PathMigrationError::NotPending);
        };
        if record.status != PathMigrationStatus::Validated {
            self.pending.insert(path_id, record);
            return Err(PathMigrationError::NotValidated);
        }
        if !record.continuity.is_verified() {
            self.pending.insert(path_id, record);
            return Err(PathMigrationError::ContinuityFailed);
        }

        let committed = record.with_status(PathMigrationStatus::Committed, now_micros);
        self.active_path = committed.candidate.clone();
        self.history.push(committed.clone());
        Ok(committed)
    }

    /// Reject and archive a pending migration.
    pub fn reject_migration(
        &mut self,
        path_id: AtpPathId,
        status: PathMigrationStatus,
        now_micros: u64,
    ) -> Result<PathMigrationRecord, PathMigrationError> {
        let Some(record) = self.pending.remove(&path_id) else {
            return Err(PathMigrationError::NotPending);
        };
        let rejected = record.with_status(status, now_micros);
        self.history.push(rejected.clone());
        Ok(rejected)
    }

    /// Pick the best candidate by preference rank, then observation time.
    #[must_use]
    pub fn race_candidates<I>(&self, candidates: I) -> Option<AtpPathCandidate>
    where
        I: IntoIterator<Item = AtpPathCandidate>,
    {
        candidates
            .into_iter()
            .min_by_key(|candidate| (candidate.preference_rank(), candidate.observed_at_micros()))
    }
}

/// Evidence used by the deterministic NAT classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatEvidence {
    local_endpoint: ObservedEndpoint,
    observations: Vec<EndpointObservation>,
    udp_probe: UdpProbe,
    hairpin: HairpinBehavior,
}

impl NatEvidence {
    /// Construct NAT evidence from local and observed endpoints.
    #[must_use]
    pub fn new(
        local_endpoint: ObservedEndpoint,
        observations: Vec<EndpointObservation>,
        udp_probe: UdpProbe,
        hairpin: HairpinBehavior,
    ) -> Self {
        Self {
            local_endpoint,
            observations,
            udp_probe,
            hairpin,
        }
    }

    /// Local endpoint supplied by the peer.
    #[must_use]
    pub const fn local_endpoint(&self) -> &ObservedEndpoint {
        &self.local_endpoint
    }

    /// Endpoint observations from rendezvous servers.
    #[must_use]
    pub fn observations(&self) -> &[EndpointObservation] {
        &self.observations
    }

    /// UDP probe result.
    #[must_use]
    pub const fn udp_probe(&self) -> UdpProbe {
        self.udp_probe
    }

    /// Hairpin measurement result.
    #[must_use]
    pub const fn hairpin(&self) -> HairpinBehavior {
        self.hairpin
    }
}

/// Result of NAT classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatClassification {
    /// Coarse NAT profile.
    pub profile: NatProfile,
    /// Confidence in the profile.
    pub confidence: NatConfidence,
    /// Hairpin behavior evidence.
    pub hairpin: HairpinBehavior,
    /// Stable caveat code for path logs.
    pub caveat: &'static str,
}

/// Classify NAT behavior from STUN-like observations.
#[must_use]
pub fn classify_nat(evidence: &NatEvidence) -> NatClassification {
    if matches!(evidence.udp_probe, UdpProbe::Blocked) {
        return NatClassification {
            profile: NatProfile::UdpBlocked,
            confidence: NatConfidence::High,
            hairpin: evidence.hairpin,
            caveat: "udp_probe_blocked",
        };
    }

    if evidence.local_endpoint.family() == EndpointFamily::Ipv6
        && evidence
            .observations
            .iter()
            .any(|observation| observation.observed_endpoint().is_ipv6())
    {
        return NatClassification {
            profile: NatProfile::Ipv6Direct,
            confidence: NatConfidence::High,
            hairpin: evidence.hairpin,
            caveat: "ipv6_observed",
        };
    }

    if evidence.observations.is_empty() {
        return NatClassification {
            profile: NatProfile::Unknown,
            confidence: NatConfidence::Low,
            hairpin: evidence.hairpin,
            caveat: "no_observations",
        };
    }

    if has_incompatible_mappings(&evidence.observations) {
        return NatClassification {
            profile: NatProfile::HardSymmetricNat,
            confidence: NatConfidence::High,
            hairpin: evidence.hairpin,
            caveat: "incompatible_observed_mappings",
        };
    }

    NatClassification {
        profile: NatProfile::LikelyEasyNat,
        confidence: match evidence.hairpin {
            HairpinBehavior::Unknown => NatConfidence::Medium,
            HairpinBehavior::Supported | HairpinBehavior::NotSupported => NatConfidence::High,
        },
        hairpin: evidence.hairpin,
        caveat: "stable_observed_mapping",
    }
}

/// Select Tailscale candidates from provider output without depending on
/// Tailscale at runtime.
#[must_use]
pub fn select_tailscale_candidates(
    preference: TailscalePreference,
    provider_output: Result<Vec<TailscaleProviderCandidate>, TailscaleProviderFailure>,
) -> TailscaleCandidateSet {
    if matches!(preference, TailscalePreference::Disabled) {
        return TailscaleCandidateSet {
            candidates: Vec::new(),
            provider_failure: None,
            caveat: "tailscale_disabled",
        };
    }

    let provider_candidates = match provider_output {
        Ok(candidates) => candidates,
        Err(failure) => {
            return TailscaleCandidateSet {
                candidates: Vec::new(),
                provider_failure: Some(failure),
                caveat: "tailscale_provider_failed_nonfatal",
            };
        }
    };

    let preference_rank = match preference {
        TailscalePreference::Prefer => 10,
        TailscalePreference::Auto => 40,
        TailscalePreference::Disabled => unreachable!("disabled returned earlier"),
    };

    let candidates = provider_candidates
        .into_iter()
        .map(|candidate| {
            let caveat = if candidate.magic_dns_name.is_some() {
                "tailscale_magic_dns_candidate"
            } else {
                "tailscale_ip_candidate"
            };
            TailscalePathCandidate {
                endpoint: candidate.endpoint,
                magic_dns_name: candidate.magic_dns_name,
                derp_region_id: candidate.derp_region_id,
                metrics: PathCandidateMetrics {
                    preference_rank,
                    expected_rtt_micros: Some(5_000),
                    expected_loss_ppm: Some(1_000),
                },
                proof_summary: TailscaleProofSummary {
                    node_id: candidate.node_id,
                    peer_label: candidate.peer_label,
                    magic_dns_present: caveat == "tailscale_magic_dns_candidate",
                    caveat,
                },
            }
        })
        .collect();

    TailscaleCandidateSet {
        candidates,
        provider_failure: None,
        caveat: match preference {
            TailscalePreference::Prefer => "tailscale_preferred",
            TailscalePreference::Auto => "tailscale_auto",
            TailscalePreference::Disabled => unreachable!("disabled returned earlier"),
        },
    }
}

/// Select optional router-assist mappings under explicit capability policy.
#[must_use]
pub fn select_router_assist_candidates(
    policy: RouterAssistPolicy,
    provider_output: Result<Vec<RouterAssistProviderCandidate>, RouterAssistProviderFailure>,
) -> RouterAssistCandidateSet {
    if !policy.enabled() {
        return RouterAssistCandidateSet {
            candidates: Vec::new(),
            selected: None,
            provider_failure: None,
            caveat: "router_assist_disabled",
        };
    }

    if !policy.mapping_mutation_allowed() {
        return RouterAssistCandidateSet {
            candidates: Vec::new(),
            selected: None,
            provider_failure: None,
            caveat: "router_assist_mapping_capability_denied",
        };
    }

    if policy.max_mapping_lifetime_micros() == 0 {
        return RouterAssistCandidateSet {
            candidates: Vec::new(),
            selected: None,
            provider_failure: None,
            caveat: "router_assist_invalid_lifetime_policy",
        };
    }

    let provider_candidates = match provider_output {
        Ok(candidates) => candidates,
        Err(failure) => {
            return RouterAssistCandidateSet {
                candidates: Vec::new(),
                selected: None,
                provider_failure: Some(failure),
                caveat: "router_assist_provider_failed_nonfatal",
            };
        }
    };

    let candidates = provider_candidates
        .into_iter()
        .filter(|candidate| {
            candidate.lease_lifetime_micros() <= policy.max_mapping_lifetime_micros()
        })
        .collect::<Vec<_>>();
    let selected = candidates
        .iter()
        .min_by_key(|candidate| {
            (
                router_assist_protocol_rank(candidate.protocol(), policy.prefer_pcp),
                candidate.observed_at_micros(),
                candidate.external_endpoint().port(),
            )
        })
        .cloned();
    let caveat = if selected.is_some() {
        "router_assist_candidate_selected"
    } else {
        "router_assist_no_policy_approved_candidates"
    };

    RouterAssistCandidateSet {
        candidates,
        selected,
        provider_failure: None,
        caveat,
    }
}

/// Build deterministic path-doctor output for NAT and router-assist evidence.
#[must_use]
pub fn build_router_assist_path_doctor_report(
    classification: NatClassification,
    router_assist: &RouterAssistCandidateSet,
) -> RouterAssistPathDoctorReport {
    let router_assist_protocol = router_assist
        .selected()
        .map(RouterAssistProviderCandidate::protocol);
    let mutation_status = router_assist_mutation_status(router_assist);
    let recommendation = match classification.profile {
        NatProfile::Ipv6Direct => PathDoctorRecommendation::UseIpv6Direct,
        NatProfile::LikelyEasyNat => PathDoctorRecommendation::TryNatPunchedUdp,
        NatProfile::HardSymmetricNat if router_assist_protocol.is_some() => {
            PathDoctorRecommendation::TryRouterAssistThenRelay
        }
        NatProfile::HardSymmetricNat => PathDoctorRecommendation::UseRelayOrTailscale,
        NatProfile::UdpBlocked => PathDoctorRecommendation::UseRelayOrTcpTlsFallback,
        NatProfile::Unknown => PathDoctorRecommendation::GatherMoreEvidence,
    };

    RouterAssistPathDoctorReport {
        nat_profile: classification.profile,
        nat_confidence: classification.confidence,
        hairpin: classification.hairpin,
        nat_caveat: classification.caveat,
        router_assist_caveat: router_assist.caveat(),
        router_assist_protocol,
        recommendation,
        mutation_status,
    }
}

fn router_assist_mutation_status(
    router_assist: &RouterAssistCandidateSet,
) -> RouterAssistMutationStatus {
    if router_assist.selected().is_some() {
        return RouterAssistMutationStatus::ExplicitlyAuthorizedCandidate;
    }

    match router_assist.caveat() {
        "router_assist_disabled" => RouterAssistMutationStatus::Disabled,
        "router_assist_mapping_capability_denied" => {
            RouterAssistMutationStatus::BlockedWithoutCapability
        }
        "router_assist_invalid_lifetime_policy" => {
            RouterAssistMutationStatus::InvalidLifetimePolicy
        }
        "router_assist_provider_failed_nonfatal" => {
            RouterAssistMutationStatus::ProviderFailedNonfatal
        }
        "router_assist_no_policy_approved_candidates" => {
            RouterAssistMutationStatus::NoPolicyApprovedCandidate
        }
        _ => RouterAssistMutationStatus::NoPolicyApprovedCandidate,
    }
}

const fn router_assist_protocol_rank(protocol: RouterAssistProtocol, prefer_pcp: bool) -> u8 {
    match (prefer_pcp, protocol) {
        (true, RouterAssistProtocol::Pcp) | (false, RouterAssistProtocol::NatPmp) => 0,
        (true, RouterAssistProtocol::NatPmp) | (false, RouterAssistProtocol::Pcp) => 1,
        (_, RouterAssistProtocol::UpnpIgd) => 2,
    }
}

fn has_incompatible_mappings(observations: &[EndpointObservation]) -> bool {
    let Some(first) = observations.first() else {
        return false;
    };
    let first_endpoint = first.observed_endpoint();
    observations
        .iter()
        .skip(1)
        .any(|observation| observation.observed_endpoint() != first_endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::stun::{ObservationRequest, ObservedEndpoint};

    fn endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, address, port).expect("endpoint")
    }

    fn ipv6_endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv6, address, port).expect("endpoint")
    }

    fn tailscale_candidate(address: &str) -> TailscaleProviderCandidate {
        TailscaleProviderCandidate::new(
            "node-1",
            "peer-a",
            ipv6_endpoint(address, 41_641),
            Some("peer-a.tailnet.ts.net".to_owned()),
            Some(7),
            123,
        )
        .expect("tailscale candidate")
    }

    fn router_assist_candidate(
        provider_label: &str,
        protocol: RouterAssistProtocol,
        external_port: u16,
        lease_lifetime_micros: u64,
        observed_at_micros: u64,
    ) -> RouterAssistProviderCandidate {
        RouterAssistProviderCandidate::new(
            provider_label,
            protocol,
            endpoint("10.0.0.2", 41_641),
            endpoint("198.51.100.7", external_port),
            lease_lifetime_micros,
            observed_at_micros,
        )
        .expect("router-assist candidate")
    }

    fn observation(
        local: ObservedEndpoint,
        observed: ObservedEndpoint,
        nonce: u64,
    ) -> EndpointObservation {
        EndpointObservation::from_request(ObservationRequest {
            local_endpoint: local,
            observed_endpoint: observed,
            observer_id: format!("observer-{nonce}"),
            probe_nonce: nonce,
            observed_at_micros: nonce,
        })
        .expect("observation")
    }

    #[test]
    fn classifies_udp_blocked_without_observations() {
        let evidence = NatEvidence::new(
            endpoint("10.0.0.2", 40_000),
            Vec::new(),
            UdpProbe::Blocked,
            HairpinBehavior::Unknown,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::UdpBlocked);
        assert_eq!(classification.confidence, NatConfidence::High);
        assert_eq!(classification.caveat, "udp_probe_blocked");
    }

    #[test]
    fn classifies_ipv6_direct_when_ipv6_is_observed() {
        let local = ipv6_endpoint("2001:db8::1", 40_000);
        let observed = ipv6_endpoint("2001:db8::1", 40_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![observation(local, observed, 1)],
            UdpProbe::Succeeded,
            HairpinBehavior::Supported,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::Ipv6Direct);
        assert_eq!(classification.confidence, NatConfidence::High);
    }

    #[test]
    fn classifies_hard_nat_when_observers_disagree() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed_a = endpoint("198.51.100.10", 50_000);
        let observed_b = endpoint("198.51.100.10", 51_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed_a, 1),
                observation(local, observed_b, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::NotSupported,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::HardSymmetricNat);
        assert_eq!(classification.hairpin, HairpinBehavior::NotSupported);
    }

    #[test]
    fn classifies_stable_mapping_as_easy_nat() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed = endpoint("198.51.100.10", 50_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed.clone(), 1),
                observation(local, observed, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::Unknown,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::LikelyEasyNat);
        assert_eq!(classification.confidence, NatConfidence::Medium);
    }

    #[test]
    fn classifies_unknown_when_udp_probe_has_no_observations() {
        let evidence = NatEvidence::new(
            endpoint("10.0.0.2", 40_000),
            Vec::new(),
            UdpProbe::NotMeasured,
            HairpinBehavior::Unknown,
        );

        let classification = classify_nat(&evidence);
        assert_eq!(classification.profile, NatProfile::Unknown);
        assert_eq!(classification.confidence, NatConfidence::Low);
        assert_eq!(classification.caveat, "no_observations");
    }

    #[test]
    fn tailscale_disabled_ignores_provider_output() {
        let set = select_tailscale_candidates(
            TailscalePreference::Disabled,
            Ok(vec![tailscale_candidate("fd7a:115c:a1e0::1")]),
        );

        assert!(set.candidates().is_empty());
        assert_eq!(set.caveat(), "tailscale_disabled");
        assert!(set.provider_failure().is_none());
    }

    #[test]
    fn tailscale_provider_failure_is_nonfatal() {
        let failure = TailscaleProviderFailure::new("tailscaled_unreachable").expect("failure");
        let set = select_tailscale_candidates(TailscalePreference::Prefer, Err(failure));

        assert!(set.candidates().is_empty());
        assert_eq!(set.caveat(), "tailscale_provider_failed_nonfatal");
        assert_eq!(
            set.provider_failure().map(TailscaleProviderFailure::reason),
            Some("tailscaled_unreachable")
        );
    }

    #[test]
    fn tailscale_candidate_has_metrics_and_proof_summary() {
        let set = select_tailscale_candidates(
            TailscalePreference::Prefer,
            Ok(vec![tailscale_candidate("fd7a:115c:a1e0::2")]),
        );

        let candidate = &set.candidates()[0];
        assert_eq!(set.caveat(), "tailscale_preferred");
        assert_eq!(candidate.endpoint().address(), "fd7a:115c:a1e0::2");
        assert_eq!(candidate.metrics().preference_rank, 10);
        assert_eq!(candidate.metrics().expected_rtt_micros, Some(5_000));
        assert_eq!(candidate.proof_summary().node_id, "node-1");
        assert_eq!(candidate.proof_summary().peer_label, "peer-a");
        assert!(candidate.proof_summary().magic_dns_present);
        assert_eq!(
            candidate.proof_summary().caveat,
            "tailscale_magic_dns_candidate"
        );
    }

    #[test]
    fn router_assist_disabled_ignores_provider_candidates() {
        let candidate =
            router_assist_candidate("upnp", RouterAssistProtocol::UpnpIgd, 49_152, 60_000_000, 1);

        let set =
            select_router_assist_candidates(RouterAssistPolicy::DISABLED, Ok(vec![candidate]));

        assert_eq!(set.caveat(), "router_assist_disabled");
        assert!(set.candidates().is_empty());
        assert!(set.selected().is_none());
        assert!(!set.is_required());
    }

    #[test]
    fn router_assist_requires_explicit_mapping_capability() {
        let policy = RouterAssistPolicy::new(false, 60_000_000);
        let candidate =
            router_assist_candidate("pcp", RouterAssistProtocol::Pcp, 50_000, 60_000_000, 1);

        let set = select_router_assist_candidates(policy, Ok(vec![candidate]));

        assert_eq!(set.caveat(), "router_assist_mapping_capability_denied");
        assert!(set.candidates().is_empty());
        assert!(set.selected().is_none());
        assert!(set.provider_failure().is_none());
    }

    #[test]
    fn router_assist_provider_failure_is_nonfatal() {
        let policy = RouterAssistPolicy::new(true, 60_000_000);
        let failure =
            RouterAssistProviderFailure::new("router control socket unavailable").expect("failure");

        let set = select_router_assist_candidates(policy, Err(failure));

        assert_eq!(set.caveat(), "router_assist_provider_failed_nonfatal");
        assert!(set.candidates().is_empty());
        assert!(set.selected().is_none());
        assert_eq!(
            set.provider_failure()
                .map(RouterAssistProviderFailure::reason),
            Some("router control socket unavailable")
        );
    }

    #[test]
    fn router_assist_selection_filters_lifetime_and_prefers_pcp() {
        let policy = RouterAssistPolicy::new(true, 60_000_000);
        let expired_by_policy = router_assist_candidate(
            "long-upnp",
            RouterAssistProtocol::UpnpIgd,
            49_152,
            120_000_000,
            1,
        );
        let nat_pmp = router_assist_candidate(
            "nat-pmp",
            RouterAssistProtocol::NatPmp,
            49_153,
            30_000_000,
            2,
        );
        let pcp = router_assist_candidate("pcp", RouterAssistProtocol::Pcp, 49_154, 30_000_000, 3);

        let set =
            select_router_assist_candidates(policy, Ok(vec![expired_by_policy, nat_pmp, pcp]));

        assert_eq!(set.caveat(), "router_assist_candidate_selected");
        assert_eq!(set.candidates().len(), 2);
        let selected = set.selected().expect("selected pcp mapping");
        assert_eq!(selected.protocol(), RouterAssistProtocol::Pcp);
        assert_eq!(selected.protocol().code(), "pcp");
        assert_eq!(selected.external_endpoint().port(), 49_154);
    }

    #[test]
    fn path_doctor_reports_hard_nat_fallback_without_router_mutation() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed_a = endpoint("198.51.100.10", 50_000);
        let observed_b = endpoint("198.51.100.10", 51_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed_a, 1),
                observation(local, observed_b, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::NotSupported,
        );
        let router_assist =
            select_router_assist_candidates(RouterAssistPolicy::DISABLED, Ok(Vec::new()));

        let report =
            build_router_assist_path_doctor_report(classify_nat(&evidence), &router_assist);

        assert_eq!(report.nat_profile(), NatProfile::HardSymmetricNat);
        assert_eq!(report.nat_confidence(), NatConfidence::High);
        assert_eq!(report.hairpin(), HairpinBehavior::NotSupported);
        assert_eq!(report.nat_caveat(), "incompatible_observed_mappings");
        assert_eq!(report.router_assist_caveat(), "router_assist_disabled");
        assert_eq!(report.router_assist_protocol(), None);
        assert_eq!(report.recommendation().code(), "use_relay_or_tailscale");
        assert_eq!(
            report.mutation_status(),
            RouterAssistMutationStatus::Disabled
        );
        assert!(!report.router_state_change_authorized());
    }

    #[test]
    fn path_doctor_marks_router_assist_as_explicitly_authorized() {
        let local = endpoint("10.0.0.2", 40_000);
        let observed_a = endpoint("198.51.100.10", 50_000);
        let observed_b = endpoint("198.51.100.10", 51_000);
        let evidence = NatEvidence::new(
            local.clone(),
            vec![
                observation(local.clone(), observed_a, 1),
                observation(local, observed_b, 2),
            ],
            UdpProbe::Succeeded,
            HairpinBehavior::NotSupported,
        );
        let policy = RouterAssistPolicy::new(true, 60_000_000);
        let candidate =
            router_assist_candidate("pcp", RouterAssistProtocol::Pcp, 49_154, 30_000_000, 3);
        let router_assist = select_router_assist_candidates(policy, Ok(vec![candidate]));

        let report =
            build_router_assist_path_doctor_report(classify_nat(&evidence), &router_assist);

        assert_eq!(
            report.recommendation().code(),
            "try_router_assist_then_relay"
        );
        assert_eq!(
            report.router_assist_protocol(),
            Some(RouterAssistProtocol::Pcp)
        );
        assert_eq!(
            report.mutation_status().code(),
            "router_assist_explicitly_authorized_candidate"
        );
        assert!(report.router_state_change_authorized());
    }

    #[test]
    fn tailscale_input_rejects_blank_identifiers() {
        let err = TailscaleProviderCandidate::new(
            " ",
            "peer-a",
            ipv6_endpoint("fd7a:115c:a1e0::3", 41_641),
            None,
            None,
            1,
        )
        .expect_err("blank node id");
        assert_eq!(err, TailscaleCandidateError::EmptyNodeId);

        let err = TailscaleProviderFailure::new(" ").expect_err("blank failure");
        assert_eq!(err, TailscaleCandidateError::EmptyFailureReason);
    }
}
