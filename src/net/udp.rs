//! UDP networking primitives.
//!
//! Provides async UDP socket operations with reactor-based wakeup.
//!
//! # Cancel Safety
//!
//! - `send_to`/`send`: atomic datagrams, cancel-safe.
//! - `recv_from`/`recv`: cancel discards the datagram (UDP is unreliable).
//! - `connect`: cancel-safe (stateless).

#[cfg(not(target_arch = "wasm32"))]
use crate::cx::Cx;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::lookup_all;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use crate::stream::Stream;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
use smallvec::SmallVec;
use std::io;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
use std::io::IoSlice;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Smallest UDP socket buffer requested by the tuning helper.
pub const UDP_MIN_SOCKET_BUFFER_BYTES: usize = 8 * 1024;
/// Largest UDP socket buffer requested by the tuning helper.
pub const UDP_MAX_SOCKET_BUFFER_BYTES: usize = 16 * 1024 * 1024;
/// Bytes carried by a UDP rendezvous anti-replay nonce.
pub const UDP_RENDEZVOUS_NONCE_BYTES: usize = 16;
/// Maximum peer or signing-key id length accepted by UDP rendezvous metadata.
pub const UDP_RENDEZVOUS_MAX_ID_BYTES: usize = 128;
/// Maximum candidate count accepted from one UDP rendezvous exchange.
pub const UDP_RENDEZVOUS_MAX_CANDIDATES: usize = 16;
/// Maximum bounded probe-attempt budget accepted from one UDP rendezvous exchange.
pub const UDP_RENDEZVOUS_MAX_ATTEMPTS: u8 = 32;
/// Maximum packet size accepted by recv_batch_from to prevent DoS via unbounded allocation.
pub const UDP_MAX_PACKET_SIZE: usize = 1024 * 1024; // 1MB per packet
/// Maximum batch size accepted by recv_batch_from to prevent DoS via unbounded allocation.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub const UDP_MAX_BATCH_SIZE: usize = 1000;
/// Default UDP GSO segment size used by send-batch planning.
///
/// ATP-RQ's default symbol is 1400 bytes, its datagram header is 24 bytes, and
/// authenticated/encrypted transfers add a 32-byte tag. This ceiling keeps both
/// clean-link RQ shapes eligible for UDP GSO instead of silently falling back to
/// plain sendmmsg.
pub const UDP_DEFAULT_GSO_SEGMENT_BYTES: usize = 1456;
/// Maximum UDP GSO segments planned into one super-packet.
pub const UDP_MAX_GSO_SEGMENTS: usize = 64;
/// Maximum datagrams planned into one sendmmsg syscall batch.
pub const UDP_MAX_SENDMMSG_BATCH: usize = 1024;

/// Platform family backing the UDP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPlatform {
    /// Linux socket backend.
    Linux,
    /// macOS or other Darwin socket backend.
    Darwin,
    /// Windows socket backend.
    Windows,
    /// Browser wasm profile; raw UDP is unavailable.
    Wasm,
    /// Any other target family.
    Other,
}

impl UdpPlatform {
    /// Return the compile-time platform family for this build.
    #[inline]
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_arch = "wasm32") {
            Self::Wasm
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_vendor = "apple") {
            Self::Darwin
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

/// Tri-state socket capability report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCapability {
    /// Capability is available on this socket/profile.
    Supported,
    /// Capability is not available on this socket/profile.
    Unsupported,
    /// The portable std/socket2 layer cannot prove availability.
    Unknown,
}

/// Socket address family observed for a bound socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAddressFamily {
    /// IPv4 socket.
    Ipv4,
    /// IPv6 socket.
    Ipv6,
    /// Address family is not observable.
    Unknown,
}

impl From<SocketAddr> for UdpAddressFamily {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        if addr.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }
}

/// UDP batching support exposed by this portable abstraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpBatchCapabilities {
    /// OS-native multi-message send batching is exposed.
    pub native_send_batch: bool,
    /// OS-native multi-message receive batching is exposed.
    pub native_recv_batch: bool,
    /// Portable send batching falls back to a cancel-checked loop.
    pub portable_send_batch: bool,
    /// Portable receive batching drains the socket after one readiness wait.
    pub portable_recv_batch: bool,
    /// Maximum fallback batch used by default by ATP/QUIC callers.
    pub default_fallback_batch: usize,
}

impl Default for UdpBatchCapabilities {
    #[inline]
    fn default() -> Self {
        Self::for_platform(UdpPlatform::current())
    }
}

impl UdpBatchCapabilities {
    /// Return batching capabilities exposed by this build target.
    #[inline]
    #[must_use]
    pub const fn for_platform(platform: UdpPlatform) -> Self {
        let native_send_batch = matches!(platform, UdpPlatform::Linux);
        Self {
            native_send_batch,
            native_recv_batch: false,
            portable_send_batch: true,
            portable_recv_batch: true,
            default_fallback_batch: 32,
        }
    }
}

/// Native send-side acceleration visible to the UDP planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSendAccelerationCapabilities {
    /// Linux-style sendmmsg multi-message batching availability.
    pub sendmmsg: UdpCapability,
    /// UDP Generic Segmentation Offload availability.
    pub gso: UdpCapability,
    /// Default maximum datagrams per sendmmsg batch.
    pub max_sendmmsg_batch: usize,
    /// Default maximum segments per GSO super-packet.
    pub max_gso_segments: usize,
}

impl Default for UdpSendAccelerationCapabilities {
    #[inline]
    fn default() -> Self {
        match UdpPlatform::current() {
            UdpPlatform::Linux => Self {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            _ => Self {
                sendmmsg: UdpCapability::Unsupported,
                gso: UdpCapability::Unsupported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
        }
    }
}

/// Send-side batch path selected for a datagram set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSendBatchPath {
    /// No packets were supplied.
    Empty,
    /// Portable cancel-checked loop over send_to.
    PortableLoop,
    /// OS-native sendmmsg batching.
    Sendmmsg,
    /// UDP GSO super-packets, one send syscall per super-packet.
    Gso,
    /// UDP GSO super-packets batched with sendmmsg.
    GsoSendmmsg,
}

/// Tuning knobs for selecting a send-side batch path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSendBatchStrategy {
    /// Prefer sendmmsg when the platform reports support.
    pub prefer_sendmmsg: bool,
    /// Prefer GSO when eligible.
    pub prefer_gso: bool,
    /// Allow planning GSO when the platform capability is unknown.
    pub allow_unknown_gso: bool,
    /// Segment size for GSO super-packets.
    pub gso_segment_bytes: usize,
    /// Maximum datagrams per sendmmsg syscall.
    pub max_sendmmsg_batch: usize,
    /// Maximum GSO segments per super-packet.
    pub max_gso_segments: usize,
}

impl Default for UdpSendBatchStrategy {
    #[inline]
    fn default() -> Self {
        Self {
            prefer_sendmmsg: true,
            prefer_gso: true,
            allow_unknown_gso: false,
            gso_segment_bytes: UDP_DEFAULT_GSO_SEGMENT_BYTES,
            max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
            max_gso_segments: UDP_MAX_GSO_SEGMENTS,
        }
    }
}

/// Deterministic plan for a UDP send batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpSendBatchPlan {
    /// Selected send path.
    pub path: UdpSendBatchPath,
    /// Number of input datagrams represented by this plan.
    pub datagrams: usize,
    /// Total payload bytes represented by this plan.
    pub payload_bytes: usize,
    /// Estimated send syscalls needed by the selected path.
    pub estimated_syscalls: usize,
    /// Planned GSO segment size when GSO is selected.
    pub gso_segment_bytes: Option<usize>,
    /// Number of datagrams packed into each GSO super-packet.
    pub gso_segments_per_packet: Option<usize>,
}

/// UDP socket capability and tuning report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpSocketCapabilities {
    /// Compile-time platform family.
    pub platform: UdpPlatform,
    /// Bound socket address family.
    pub address_family: UdpAddressFamily,
    /// Dual-stack support for this socket.
    pub dual_stack: UdpCapability,
    /// ECN packet metadata availability.
    pub ecn: UdpCapability,
    /// Send/receive batching capabilities.
    pub batching: UdpBatchCapabilities,
    /// Observed receive buffer size, if the platform reports it.
    pub observed_recv_buffer_bytes: Option<usize>,
    /// Observed send buffer size, if the platform reports it.
    pub observed_send_buffer_bytes: Option<usize>,
}

/// UDP rendezvous candidate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRendezvousCandidateKind {
    /// Local LAN or directly bound UDP endpoint.
    LocalUdp,
    /// Public UDP endpoint observed by a rendezvous/STUN-like service.
    ObservedUdp,
    /// Relay UDP endpoint offered as a fallback candidate.
    RelayUdp,
}

/// One signed UDP rendezvous candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpRendezvousCandidate {
    /// Candidate endpoint.
    pub endpoint: SocketAddr,
    /// Candidate source/type.
    pub kind: UdpRendezvousCandidateKind,
    /// Higher values are preferred when other path facts are equal.
    pub priority: u16,
    /// Candidate expiry in caller-defined monotonic milliseconds.
    pub expires_at_millis: u64,
}

impl UdpRendezvousCandidate {
    /// Construct a UDP rendezvous candidate.
    #[inline]
    #[must_use]
    pub const fn new(
        endpoint: SocketAddr,
        kind: UdpRendezvousCandidateKind,
        priority: u16,
        expires_at_millis: u64,
    ) -> Self {
        Self {
            endpoint,
            kind,
            priority,
            expires_at_millis,
        }
    }
}

/// Detached signature metadata for a UDP rendezvous candidate set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRendezvousSignature {
    /// Signing key or device id.
    pub key_id: String,
    /// Detached signature bytes supplied by the caller's identity layer.
    pub bytes: Vec<u8>,
}

impl UdpRendezvousSignature {
    /// Construct detached UDP rendezvous signature metadata.
    #[inline]
    #[must_use]
    pub fn new(key_id: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id: key_id.into(),
            bytes: bytes.into(),
        }
    }
}

/// Signed UDP rendezvous candidate set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRendezvousCandidateSet {
    /// Peer id that owns the candidate set.
    pub peer_id: String,
    /// Transfer/session nonce used for replay protection.
    pub nonce: [u8; UDP_RENDEZVOUS_NONCE_BYTES],
    /// Offer expiry in caller-defined monotonic milliseconds.
    pub expires_at_millis: u64,
    /// Bounded number of coordinated probe attempts permitted by this offer.
    pub attempt_budget: u8,
    /// Candidate endpoints.
    pub candidates: Vec<UdpRendezvousCandidate>,
    /// Detached signature metadata supplied by the identity layer.
    pub signature: Option<UdpRendezvousSignature>,
}

impl UdpRendezvousCandidateSet {
    /// Construct a UDP rendezvous candidate set.
    #[inline]
    #[must_use]
    pub fn new(
        peer_id: impl Into<String>,
        nonce: [u8; UDP_RENDEZVOUS_NONCE_BYTES],
        expires_at_millis: u64,
        attempt_budget: u8,
        candidates: Vec<UdpRendezvousCandidate>,
        signature: Option<UdpRendezvousSignature>,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            nonce,
            expires_at_millis,
            attempt_budget,
            candidates,
            signature,
        }
    }
}

/// UDP rendezvous candidate validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRendezvousValidationError {
    /// Peer id is empty.
    EmptyPeerId,
    /// Peer id exceeds the bounded metadata length.
    PeerIdTooLong,
    /// Peer id contains a byte outside the stable portable id grammar.
    InvalidPeerId,
    /// Nonce is all zero bytes.
    ZeroNonce,
    /// Nonce was already seen by the caller.
    ReplayedNonce,
    /// The whole candidate set is expired.
    ExpiredOffer,
    /// No candidates were supplied.
    EmptyCandidates,
    /// Candidate count exceeds the bounded quota.
    TooManyCandidates,
    /// Attempt budget is zero.
    EmptyAttemptBudget,
    /// Attempt budget exceeds the bounded quota.
    AttemptBudgetTooLarge,
    /// Candidate endpoint is unspecified or has port zero.
    InvalidCandidateEndpoint,
    /// Candidate is already expired.
    ExpiredCandidate,
    /// Candidate expiry exceeds the signed offer expiry.
    CandidateOutlivesOffer,
    /// Detached signature metadata is missing.
    MissingSignature,
    /// Signature key id is empty, too long, or malformed.
    InvalidSignatureKeyId,
    /// Signature bytes are empty or all zero.
    InvalidSignatureBytes,
}

/// Validate a signed UDP rendezvous candidate set before path racing.
///
/// This is intentionally a structural validation boundary. Cryptographic
/// signature verification belongs to the caller's identity layer; this function
/// rejects unsigned, expired, replayed, malformed, and unbounded metadata before
/// any socket probes are scheduled.
pub fn validate_udp_rendezvous_candidates(
    set: &UdpRendezvousCandidateSet,
    now_millis: u64,
    seen_nonces: &[[u8; UDP_RENDEZVOUS_NONCE_BYTES]],
) -> Result<(), UdpRendezvousValidationError> {
    validate_rendezvous_peer_id(&set.peer_id)?;
    if set.nonce.iter().all(|byte| *byte == 0) {
        return Err(UdpRendezvousValidationError::ZeroNonce);
    }
    if seen_nonces.iter().any(|nonce| nonce == &set.nonce) {
        return Err(UdpRendezvousValidationError::ReplayedNonce);
    }
    if set.expires_at_millis <= now_millis {
        return Err(UdpRendezvousValidationError::ExpiredOffer);
    }
    if set.candidates.is_empty() {
        return Err(UdpRendezvousValidationError::EmptyCandidates);
    }
    if set.candidates.len() > UDP_RENDEZVOUS_MAX_CANDIDATES {
        return Err(UdpRendezvousValidationError::TooManyCandidates);
    }
    if set.attempt_budget == 0 {
        return Err(UdpRendezvousValidationError::EmptyAttemptBudget);
    }
    if set.attempt_budget > UDP_RENDEZVOUS_MAX_ATTEMPTS {
        return Err(UdpRendezvousValidationError::AttemptBudgetTooLarge);
    }
    validate_rendezvous_signature(set.signature.as_ref())?;

    for candidate in &set.candidates {
        if candidate.endpoint.port() == 0 || candidate.endpoint.ip().is_unspecified() {
            return Err(UdpRendezvousValidationError::InvalidCandidateEndpoint);
        }
        if candidate.expires_at_millis <= now_millis {
            return Err(UdpRendezvousValidationError::ExpiredCandidate);
        }
        if candidate.expires_at_millis > set.expires_at_millis {
            return Err(UdpRendezvousValidationError::CandidateOutlivesOffer);
        }
    }

    Ok(())
}

fn validate_rendezvous_signature(
    signature: Option<&UdpRendezvousSignature>,
) -> Result<(), UdpRendezvousValidationError> {
    let Some(signature) = signature else {
        return Err(UdpRendezvousValidationError::MissingSignature);
    };
    if !rendezvous_id_is_valid(&signature.key_id) {
        return Err(UdpRendezvousValidationError::InvalidSignatureKeyId);
    }
    if signature.bytes.is_empty() || signature.bytes.iter().all(|byte| *byte == 0) {
        return Err(UdpRendezvousValidationError::InvalidSignatureBytes);
    }
    Ok(())
}

fn validate_rendezvous_peer_id(peer_id: &str) -> Result<(), UdpRendezvousValidationError> {
    if peer_id.is_empty() {
        return Err(UdpRendezvousValidationError::EmptyPeerId);
    }
    if peer_id.len() > UDP_RENDEZVOUS_MAX_ID_BYTES {
        return Err(UdpRendezvousValidationError::PeerIdTooLong);
    }
    if !peer_id.bytes().all(rendezvous_id_byte_is_valid) {
        return Err(UdpRendezvousValidationError::InvalidPeerId);
    }
    Ok(())
}

fn rendezvous_id_is_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= UDP_RENDEZVOUS_MAX_ID_BYTES
        && id.bytes().all(rendezvous_id_byte_is_valid)
}

fn rendezvous_id_byte_is_valid(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
}

/// UDP NAT/path shape inferred from endpoint observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpNatKind {
    /// No successful UDP endpoint observation was recorded.
    UdpBlocked,
    /// Observed public IPv6 endpoint matches the local IPv6 endpoint.
    Ipv6Direct,
    /// Observed public IPv4 endpoint matches the local IPv4 endpoint.
    PublicIpv4Direct,
    /// A stable public mapping was observed, but it differs from the local endpoint.
    LikelyEasyNat,
    /// Multiple public mappings were observed for the same local UDP endpoint.
    HardOrSymmetricNat,
    /// Observations were insufficient or contradictory.
    Unknown,
}

/// Hairpin capability inferred from explicitly measured probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpHairpinSupport {
    /// Hairpin probes succeeded at least once.
    Supported,
    /// Hairpin probes were measured and failed.
    Unsupported,
    /// Hairpin behavior was not measured.
    Unknown,
}

/// Confidence attached to a UDP NAT/path assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpNatConfidence {
    /// One or more observations are missing, so callers should treat the result as a hint.
    Low,
    /// A single successful observation supports the assessment.
    Medium,
    /// Multiple observations or a conclusive blocked/direct result support the assessment.
    High,
}

/// One rendezvous/STUN-like UDP endpoint observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpEndpointObservation {
    /// Local UDP endpoint used for the probe.
    pub local_addr: SocketAddr,
    /// Rendezvous server that reported the observed endpoint.
    pub rendezvous_addr: SocketAddr,
    /// Public endpoint observed by the rendezvous server.
    pub observed_addr: Option<SocketAddr>,
    /// Whether the UDP probe reached the rendezvous server.
    pub probe_succeeded: bool,
    /// Optional hairpin result measured for the observed endpoint.
    pub hairpin_succeeded: Option<bool>,
}

impl UdpEndpointObservation {
    /// Construct a successful endpoint observation.
    #[inline]
    #[must_use]
    pub const fn observed(
        local_addr: SocketAddr,
        rendezvous_addr: SocketAddr,
        observed_addr: SocketAddr,
    ) -> Self {
        Self {
            local_addr,
            rendezvous_addr,
            observed_addr: Some(observed_addr),
            probe_succeeded: true,
            hairpin_succeeded: None,
        }
    }

    /// Construct a failed UDP probe observation.
    #[inline]
    #[must_use]
    pub const fn blocked(local_addr: SocketAddr, rendezvous_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            rendezvous_addr,
            observed_addr: None,
            probe_succeeded: false,
            hairpin_succeeded: None,
        }
    }

    /// Attach a measured hairpin result to this observation.
    #[inline]
    #[must_use]
    pub const fn with_hairpin_result(mut self, succeeded: bool) -> Self {
        self.hairpin_succeeded = Some(succeeded);
        self
    }
}

/// NAT/path assessment derived from rendezvous endpoint observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpNatAssessment {
    /// Inferred NAT/path kind.
    pub kind: UdpNatKind,
    /// Inferred hairpin behavior.
    pub hairpin: UdpHairpinSupport,
    /// Confidence in the inferred kind.
    pub confidence: UdpNatConfidence,
    /// Stable observed public endpoint, if there is exactly one.
    pub observed_public_addr: Option<SocketAddr>,
    /// Stable machine-readable caveat for logs and path-doctor output.
    pub caveat: &'static str,
}

/// Classify UDP NAT/path behavior from STUN-like endpoint observations.
#[must_use]
pub fn classify_udp_nat(observations: &[UdpEndpointObservation]) -> UdpNatAssessment {
    if observations.is_empty() {
        return UdpNatAssessment {
            kind: UdpNatKind::Unknown,
            hairpin: UdpHairpinSupport::Unknown,
            confidence: UdpNatConfidence::Low,
            observed_public_addr: None,
            caveat: "missing_endpoint_observation",
        };
    }

    let hairpin = classify_udp_hairpin(observations);
    let successful = observations
        .iter()
        .filter(|obs| obs.probe_succeeded)
        .filter_map(|obs| obs.observed_addr.map(|public_addr| (*obs, public_addr)))
        .collect::<Vec<_>>();

    if successful.is_empty() {
        return UdpNatAssessment {
            kind: UdpNatKind::UdpBlocked,
            hairpin,
            confidence: UdpNatConfidence::High,
            observed_public_addr: None,
            caveat: "no_udp_probe_reached_rendezvous",
        };
    }

    if successful
        .iter()
        .all(|(obs, public_addr)| obs.local_addr.is_ipv6() && obs.local_addr == *public_addr)
    {
        return UdpNatAssessment {
            kind: UdpNatKind::Ipv6Direct,
            hairpin,
            confidence: confidence_for_success_count(successful.len()),
            observed_public_addr: successful.first().map(|(_, public_addr)| *public_addr),
            caveat: "ipv6_endpoint_observed_directly",
        };
    }

    let mut unique_observed = Vec::new();
    for (_, public_addr) in &successful {
        if !unique_observed.contains(public_addr) {
            unique_observed.push(*public_addr);
        }
    }

    let same_local_endpoint = successful.first().is_some_and(|(first, _)| {
        successful
            .iter()
            .all(|(obs, _)| obs.local_addr == first.local_addr)
    });

    if unique_observed.len() > 1 && same_local_endpoint {
        return UdpNatAssessment {
            kind: UdpNatKind::HardOrSymmetricNat,
            hairpin,
            confidence: UdpNatConfidence::High,
            observed_public_addr: None,
            caveat: "multiple_public_mappings_observed",
        };
    }

    if unique_observed.len() > 1 {
        return UdpNatAssessment {
            kind: UdpNatKind::Unknown,
            hairpin,
            confidence: UdpNatConfidence::Low,
            observed_public_addr: None,
            caveat: "multiple_local_endpoints_observed",
        };
    }

    let Some(observed) = unique_observed.first().copied() else {
        return UdpNatAssessment {
            kind: UdpNatKind::Unknown,
            hairpin,
            confidence: UdpNatConfidence::Low,
            observed_public_addr: None,
            caveat: "missing_public_mapping_after_success",
        };
    };
    let direct = successful.iter().any(|(obs, _)| obs.local_addr == observed);
    let kind = if direct {
        UdpNatKind::PublicIpv4Direct
    } else {
        UdpNatKind::LikelyEasyNat
    };
    let caveat = if direct {
        "ipv4_endpoint_observed_directly"
    } else {
        "stable_public_mapping_observed"
    };

    UdpNatAssessment {
        kind,
        hairpin,
        confidence: confidence_for_success_count(successful.len()),
        observed_public_addr: Some(observed),
        caveat,
    }
}

fn classify_udp_hairpin(observations: &[UdpEndpointObservation]) -> UdpHairpinSupport {
    let mut measured_failure = false;
    for obs in observations {
        match obs.hairpin_succeeded {
            Some(true) => return UdpHairpinSupport::Supported,
            Some(false) => measured_failure = true,
            None => {}
        }
    }
    if measured_failure {
        UdpHairpinSupport::Unsupported
    } else {
        UdpHairpinSupport::Unknown
    }
}

#[inline]
const fn confidence_for_success_count(count: usize) -> UdpNatConfidence {
    if count > 1 {
        UdpNatConfidence::High
    } else {
        UdpNatConfidence::Medium
    }
}

/// Requested UDP socket buffer sizes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpBufferConfig {
    /// Desired receive buffer size.
    pub recv_buffer_bytes: Option<usize>,
    /// Desired send buffer size.
    pub send_buffer_bytes: Option<usize>,
}

impl UdpBufferConfig {
    /// Clamp requested buffer sizes to a bounded cross-platform range.
    #[inline]
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            recv_buffer_bytes: self.recv_buffer_bytes.map(clamp_udp_buffer_size),
            send_buffer_bytes: self.send_buffer_bytes.map(clamp_udp_buffer_size),
        }
    }
}

impl UdpSendBatchStrategy {
    /// Return a strategy with bounded planner knobs.
    #[inline]
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            gso_segment_bytes: self.gso_segment_bytes.clamp(1, UDP_MAX_PACKET_SIZE),
            max_sendmmsg_batch: self.max_sendmmsg_batch.clamp(1, UDP_MAX_SENDMMSG_BATCH),
            max_gso_segments: self.max_gso_segments.clamp(1, UDP_MAX_GSO_SEGMENTS),
            ..self
        }
    }
}

impl UdpSendBatchPlan {
    /// Build a deterministic send-batch plan for the supplied packets.
    #[must_use]
    pub fn for_packets(
        packets: &[UdpOutboundDatagram<'_>],
        capabilities: UdpSendAccelerationCapabilities,
        strategy: UdpSendBatchStrategy,
    ) -> Self {
        let strategy = strategy.clamped();
        let max_sendmmsg_batch = strategy
            .max_sendmmsg_batch
            .min(capabilities.max_sendmmsg_batch.max(1));
        let max_gso_segments = strategy
            .max_gso_segments
            .min(capabilities.max_gso_segments.max(1));
        let datagrams = packets.len();
        let payload_bytes = packets.iter().map(|packet| packet.payload.len()).sum();

        if packets.is_empty() {
            return Self {
                path: UdpSendBatchPath::Empty,
                datagrams,
                payload_bytes,
                estimated_syscalls: 0,
                gso_segment_bytes: None,
                gso_segments_per_packet: None,
            };
        }

        let gso_segment_bytes = if datagrams > 1
            && strategy.prefer_gso
            && capability_permits_gso(capabilities.gso, strategy.allow_unknown_gso)
            && packets_share_destination(packets)
        {
            fixed_gso_segment_bytes(packets, strategy.gso_segment_bytes)
        } else {
            None
        };

        if let Some(gso_segment_bytes) = gso_segment_bytes {
            let segments_per_packet = datagrams.min(max_gso_segments);
            let super_packets = div_ceil_usize(datagrams, segments_per_packet);
            let can_sendmmsg = strategy.prefer_sendmmsg
                && matches!(capabilities.sendmmsg, UdpCapability::Supported)
                && super_packets > 1;
            let path = if can_sendmmsg {
                UdpSendBatchPath::GsoSendmmsg
            } else {
                UdpSendBatchPath::Gso
            };
            let estimated_syscalls = if can_sendmmsg {
                div_ceil_usize(super_packets, max_sendmmsg_batch)
            } else {
                super_packets
            };

            return Self {
                path,
                datagrams,
                payload_bytes,
                estimated_syscalls,
                gso_segment_bytes: Some(gso_segment_bytes),
                gso_segments_per_packet: Some(segments_per_packet),
            };
        }

        if strategy.prefer_sendmmsg && matches!(capabilities.sendmmsg, UdpCapability::Supported) {
            return Self {
                path: UdpSendBatchPath::Sendmmsg,
                datagrams,
                payload_bytes,
                estimated_syscalls: div_ceil_usize(datagrams, max_sendmmsg_batch),
                gso_segment_bytes: None,
                gso_segments_per_packet: None,
            };
        }

        Self {
            path: UdpSendBatchPath::PortableLoop,
            datagrams,
            payload_bytes,
            estimated_syscalls: datagrams,
            gso_segment_bytes: None,
            gso_segments_per_packet: None,
        }
    }

    /// Build a deterministic send-batch plan for payloads sent on an already
    /// connected UDP socket.
    #[must_use]
    pub fn for_connected_payloads(
        payloads: &[&[u8]],
        capabilities: UdpSendAccelerationCapabilities,
        strategy: UdpSendBatchStrategy,
    ) -> Self {
        let strategy = strategy.clamped();
        let max_sendmmsg_batch = strategy
            .max_sendmmsg_batch
            .min(capabilities.max_sendmmsg_batch.max(1));
        let max_gso_segments = strategy
            .max_gso_segments
            .min(capabilities.max_gso_segments.max(1));
        let datagrams = payloads.len();
        let payload_bytes = payloads.iter().map(|payload| payload.len()).sum();

        if payloads.is_empty() {
            return Self {
                path: UdpSendBatchPath::Empty,
                datagrams,
                payload_bytes,
                estimated_syscalls: 0,
                gso_segment_bytes: None,
                gso_segments_per_packet: None,
            };
        }

        let gso_segment_bytes = if datagrams > 1
            && strategy.prefer_gso
            && capability_permits_gso(capabilities.gso, strategy.allow_unknown_gso)
        {
            fixed_gso_payload_segment_bytes(payloads, strategy.gso_segment_bytes)
        } else {
            None
        };

        if let Some(gso_segment_bytes) = gso_segment_bytes {
            let segments_per_packet = datagrams.min(max_gso_segments);
            let super_packets = div_ceil_usize(datagrams, segments_per_packet);
            let can_sendmmsg = strategy.prefer_sendmmsg
                && matches!(capabilities.sendmmsg, UdpCapability::Supported)
                && super_packets > 1;
            let path = if can_sendmmsg {
                UdpSendBatchPath::GsoSendmmsg
            } else {
                UdpSendBatchPath::Gso
            };
            let estimated_syscalls = if can_sendmmsg {
                div_ceil_usize(super_packets, max_sendmmsg_batch)
            } else {
                super_packets
            };

            return Self {
                path,
                datagrams,
                payload_bytes,
                estimated_syscalls,
                gso_segment_bytes: Some(gso_segment_bytes),
                gso_segments_per_packet: Some(segments_per_packet),
            };
        }

        if strategy.prefer_sendmmsg && matches!(capabilities.sendmmsg, UdpCapability::Supported) {
            return Self {
                path: UdpSendBatchPath::Sendmmsg,
                datagrams,
                payload_bytes,
                estimated_syscalls: div_ceil_usize(datagrams, max_sendmmsg_batch),
                gso_segment_bytes: None,
                gso_segments_per_packet: None,
            };
        }

        Self {
            path: UdpSendBatchPath::PortableLoop,
            datagrams,
            payload_bytes,
            estimated_syscalls: datagrams,
            gso_segment_bytes: None,
            gso_segments_per_packet: None,
        }
    }
}

#[inline]
#[must_use]
fn capability_permits_gso(capability: UdpCapability, allow_unknown: bool) -> bool {
    matches!(capability, UdpCapability::Supported)
        || (allow_unknown && matches!(capability, UdpCapability::Unknown))
}

#[inline]
#[must_use]
fn packets_share_destination(packets: &[UdpOutboundDatagram<'_>]) -> bool {
    packets.first().is_some_and(|first| {
        packets
            .iter()
            .all(|packet| packet.dst_addr == first.dst_addr)
    })
}

#[inline]
#[must_use]
fn fixed_gso_segment_bytes(
    packets: &[UdpOutboundDatagram<'_>],
    max_segment_bytes: usize,
) -> Option<usize> {
    let segment_bytes = packets.first()?.payload.len();
    if segment_bytes == 0
        || segment_bytes > max_segment_bytes
        || segment_bytes > usize::from(u16::MAX)
    {
        return None;
    }

    packets
        .iter()
        .all(|packet| packet.payload.len() == segment_bytes)
        .then_some(segment_bytes)
}

#[inline]
#[must_use]
fn fixed_gso_payload_segment_bytes(payloads: &[&[u8]], max_segment_bytes: usize) -> Option<usize> {
    let segment_bytes = payloads.first()?.len();
    if segment_bytes == 0
        || segment_bytes > max_segment_bytes
        || segment_bytes > usize::from(u16::MAX)
    {
        return None;
    }

    payloads
        .iter()
        .all(|payload| payload.len() == segment_bytes)
        .then_some(segment_bytes)
}

#[inline]
#[must_use]
fn div_ceil_usize(value: usize, divisor: usize) -> usize {
    value.div_ceil(divisor.max(1))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct UdpGsoSuperPacket {
    dst_addr: SocketAddr,
    datagram_count: usize,
    payload_bytes: usize,
    buffer: Vec<u8>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl UdpGsoSuperPacket {
    fn from_packets(packets: &[UdpOutboundDatagram<'_>]) -> Self {
        let first = packets
            .first()
            .expect("GSO super-packet requires at least one datagram");
        let payload_bytes = packets.iter().map(|packet| packet.payload.len()).sum();
        let mut buffer = Vec::with_capacity(payload_bytes);
        for packet in packets {
            buffer.extend_from_slice(packet.payload);
        }

        Self {
            dst_addr: first.dst_addr,
            datagram_count: packets.len(),
            payload_bytes,
            buffer,
        }
    }

    fn from_connected_payloads(payloads: &[&[u8]], dst_addr: SocketAddr) -> Self {
        let _ = payloads
            .first()
            .expect("GSO super-packet requires at least one datagram");
        let payload_bytes = payloads.iter().map(|payload| payload.len()).sum();
        let mut buffer = Vec::with_capacity(payload_bytes);
        for payload in payloads {
            buffer.extend_from_slice(payload);
        }

        Self {
            dst_addr,
            datagram_count: payloads.len(),
            payload_bytes,
            buffer,
        }
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
fn native_sendmmsg_addrs_for_packets(
    packets: &[UdpOutboundDatagram<'_>],
    connected_peer: Option<SocketAddr>,
) -> Vec<Option<nix::sys::socket::SockaddrStorage>> {
    if connected_peer.is_some() {
        vec![None; packets.len()]
    } else {
        packets
            .iter()
            .map(|packet| Some(nix::sys::socket::SockaddrStorage::from(packet.dst_addr)))
            .collect()
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
type NativeSendmmsgAddr = nix::sys::socket::SockaddrStorage;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
type NativeSendmmsgAddrList = SmallVec<[Option<NativeSendmmsgAddr>; UDP_MAX_GSO_SEGMENTS]>;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
fn native_sendmmsg_none_addrs(len: usize) -> NativeSendmmsgAddrList {
    std::iter::repeat_with(|| None).take(len).collect()
}

#[cfg(not(target_arch = "wasm32"))]
// `Sent` and `WouldBlock` are only constructed inside the
// `cfg(any(target_os = "linux", target_os = "android"))` native sendmmsg/GSO
// batch paths; on other Unix targets (e.g. macOS) the batch send falls back to
// `Unavailable`, so those variants are unconstructed there. Without this the
// crate-level `deny(dead_code)` (non-Windows) turns that into a hard error and
// breaks the apple-darwin build. Matches the existing
// `cfg_attr(target_arch = "wasm32", allow(dead_code))` precedent in this file.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
#[derive(Debug)]
enum NativeSendBatchAttempt {
    Sent(UdpBatchIoReport),
    Unavailable,
    WouldBlock,
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    )
))]
#[inline]
#[must_use]
fn native_send_error_would_block(error: nix::errno::Errno) -> bool {
    error == nix::errno::Errno::EAGAIN
        || error == nix::errno::Errno::EWOULDBLOCK
        || error == nix::errno::Errno::ENOBUFS
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn native_sendmmsg_addrs_for_gso_packets(
    packets: &[UdpGsoSuperPacket],
    connected_peer: Option<SocketAddr>,
) -> Vec<Option<nix::sys::socket::SockaddrStorage>> {
    if connected_peer.is_some() {
        vec![None; packets.len()]
    } else {
        packets
            .iter()
            .map(|packet| Some(nix::sys::socket::SockaddrStorage::from(packet.dst_addr)))
            .collect()
    }
}

#[inline]
#[must_use]
fn clamp_udp_buffer_size(size: usize) -> usize {
    size.clamp(UDP_MIN_SOCKET_BUFFER_BYTES, UDP_MAX_SOCKET_BUFFER_BYTES)
}

/// Result of applying UDP socket buffer tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpBufferTuneReport {
    /// Requested receive buffer size after abstraction-level clamping.
    pub requested_recv_buffer_bytes: Option<usize>,
    /// Requested send buffer size after abstraction-level clamping.
    pub requested_send_buffer_bytes: Option<usize>,
    /// Platform-reported receive buffer size after tuning.
    pub applied_recv_buffer_bytes: Option<usize>,
    /// Platform-reported send buffer size after tuning.
    pub applied_send_buffer_bytes: Option<usize>,
}

/// Datagram scheduled for portable UDP batch send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpOutboundDatagram<'a> {
    /// Datagram destination.
    pub dst_addr: SocketAddr,
    /// Datagram payload.
    pub payload: &'a [u8],
}

/// Datagram received by portable UDP batch receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInboundDatagram {
    /// Datagram source.
    pub src_addr: SocketAddr,
    /// Datagram payload bytes copied from the socket.
    pub payload: Vec<u8>,
    /// True when the receive buffer may have truncated the datagram.
    pub possibly_truncated: bool,
}

/// Result summary for portable UDP batch I/O.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpBatchIoReport {
    /// Number of packets processed before completion or first error.
    pub packets_processed: usize,
    /// Total payload bytes processed.
    pub bytes_processed: usize,
    /// True when this operation used the portable loop fallback.
    pub fallback_used: bool,
    /// True when this operation used an OS-native send batching syscall.
    pub native_send_batch_used: bool,
    /// True when this operation used UDP Generic Segmentation Offload.
    pub gso_send_used: bool,
    /// Stringified error that stopped a partial batch.
    pub error: Option<String>,
}

/// Portable UDP receive batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpRecvBatch {
    /// Received datagrams.
    pub packets: Vec<UdpInboundDatagram>,
    /// Batch summary.
    pub report: UdpBatchIoReport,
}

impl UdpRecvBatch {
    /// Move packet payload buffers into `spare_payloads` for reuse by the next
    /// portable receive batch. This avoids one heap allocation per datagram on
    /// high-throughput callers while preserving the owned-batch API.
    pub fn recycle_payloads_into(
        &mut self,
        spare_payloads: &mut Vec<Vec<u8>>,
        max_spare_payloads: usize,
    ) {
        for mut packet in self.packets.drain(..) {
            if spare_payloads.len() >= max_spare_payloads {
                break;
            }
            if packet.payload.capacity() <= UDP_MAX_PACKET_SIZE {
                packet.payload.clear();
                spare_payloads.push(packet.payload);
            }
        }
        self.report = UdpBatchIoReport::default();
    }
}

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_udp_unsupported(op: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{op} is unavailable in wasm-browser profiles; use browser transport bindings"),
    )
}

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_udp_unsupported_result<T>(op: &str) -> io::Result<T> {
    Err(browser_udp_unsupported(op))
}

#[cfg(target_arch = "wasm32")]
#[inline]
fn browser_udp_poll_unsupported<T>(op: &str) -> Poll<io::Result<T>> {
    Poll::Ready(Err(browser_udp_unsupported(op)))
}

#[cfg(not(target_arch = "wasm32"))]
#[inline]
fn empty_udp_receive_buffer_error(op: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("UdpSocket::{op} requires a non-empty buffer"),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn recv_batch_payload_buffer(spare_payloads: &mut Vec<Vec<u8>>, packet_size: usize) -> Vec<u8> {
    let mut buf = spare_payloads
        .pop()
        .unwrap_or_else(|| Vec::with_capacity(packet_size));
    // A recycled scratch buffer keeps its previous length so reuse avoids
    // re-zeroing `packet_size` bytes on every receive; only fresh or
    // shorter-than-requested buffers pay the one-time zero fill. Stale
    // contents are never observed: receives overwrite `[..n]` and only
    // `[..n]` is copied out.
    if buf.len() < packet_size {
        buf.resize(packet_size, 0);
    } else {
        buf.truncate(packet_size);
    }
    buf
}

#[cfg(not(target_arch = "wasm32"))]
fn recycle_unused_recv_batch_payload(spare_payloads: &mut Vec<Vec<u8>>, buf: Vec<u8>) {
    if buf.capacity() <= UDP_MAX_PACKET_SIZE {
        spare_payloads.push(buf);
    }
}

/// A UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    registration: Option<IoRegistration>,
    inner: Arc<StdUdpSocket>,
    gso_demoted: bool,
}

impl UdpSocket {
    /// Bind to the given address.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = addr;
            browser_udp_unsupported_result("UdpSocket::bind")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let addrs = lookup_all(addr).await?;
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no socket addresses found",
                ));
            }

            let mut last_err = None;
            for addr in addrs {
                match StdUdpSocket::bind(addr) {
                    Ok(socket) => {
                        socket.set_nonblocking(true)?;
                        return Ok(Self {
                            inner: Arc::new(socket),
                            registration: None,
                            gso_demoted: false,
                        });
                    }
                    Err(err) => last_err = Some(err),
                }
            }

            Err(last_err.unwrap_or_else(|| io::Error::other("failed to bind any address")))
        }
    }

    /// Connect to a remote address (for send/recv).
    pub async fn connect<A: ToSocketAddrs + Send + 'static>(&self, addr: A) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = addr;
            browser_udp_unsupported_result("UdpSocket::connect")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let addrs = lookup_all(addr).await?;
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no socket addresses found",
                ));
            }

            let mut last_err = None;
            for addr in addrs {
                if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                match self.inner.connect(addr) {
                    Ok(()) => return Ok(()),
                    Err(err) => last_err = Some(err),
                }
            }

            Err(last_err.unwrap_or_else(|| io::Error::other("failed to connect to any address")))
        }
    }

    /// Send a datagram to the specified target.
    pub async fn send_to<A: ToSocketAddrs + Send + 'static>(
        &mut self,
        buf: &[u8],
        target: A,
    ) -> io::Result<usize> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (buf, target);
            browser_udp_unsupported_result("UdpSocket::send_to")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let addrs = lookup_all(target).await?;
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no socket addresses found",
                ));
            }

            std::future::poll_fn(|cx| self.poll_send_to(cx, buf, &addrs)).await
        }
    }

    /// Poll for send_to readiness.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn poll_send_to(
        &mut self,
        cx: &Context<'_>,
        buf: &[u8],
        addrs: &[SocketAddr],
    ) -> Poll<io::Result<usize>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (self, cx, buf, addrs);
            browser_udp_poll_unsupported("UdpSocket::poll_send_to")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut last_err = None;
            for addr in addrs {
                if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "cancelled",
                    )));
                }
                match self.inner.send_to(buf, addr) {
                    Ok(n) => return Poll::Ready(Ok(n)),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Socket not ready; register and wait.
                        if let Err(err) = self.register_interest(cx, Interest::WRITABLE) {
                            return Poll::Ready(Err(err));
                        }
                        return Poll::Pending;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            // All addresses failed with non-WouldBlock errors; return last error.
            Poll::Ready(Err(last_err.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "no addresses to send to")
            })))
        }
    }

    /// Receive a datagram and its source address.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = buf;
            browser_udp_unsupported_result("UdpSocket::recv_from")
        }

        #[cfg(not(target_arch = "wasm32"))]
        std::future::poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    /// Poll for recv_from readiness.
    pub fn poll_recv_from(
        &mut self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (self, cx, buf);
            browser_udp_poll_unsupported("UdpSocket::poll_recv_from")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if buf.is_empty() {
                return Poll::Ready(Err(empty_udp_receive_buffer_error("recv_from")));
            }

            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            match self.inner.recv_from(buf) {
                Ok(res) => Poll::Ready(Ok(res)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(err) = self.register_interest(cx, Interest::READABLE) {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
    }

    /// Send a datagram to the connected peer.
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = buf;
            browser_udp_unsupported_result("UdpSocket::send")
        }

        #[cfg(not(target_arch = "wasm32"))]
        std::future::poll_fn(|cx| self.poll_send(cx, buf)).await
    }

    /// Poll for send readiness.
    pub fn poll_send(&mut self, cx: &Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (self, cx, buf);
            browser_udp_poll_unsupported("UdpSocket::poll_send")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            match self.inner.send(buf) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(err) = self.register_interest(cx, Interest::WRITABLE) {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
    }

    /// Receive a datagram from the connected peer.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = buf;
            browser_udp_unsupported_result("UdpSocket::recv")
        }

        #[cfg(not(target_arch = "wasm32"))]
        std::future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    /// Poll for recv readiness.
    pub fn poll_recv(&mut self, cx: &Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (self, cx, buf);
            browser_udp_poll_unsupported("UdpSocket::poll_recv")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if buf.is_empty() {
                return Poll::Ready(Err(empty_udp_receive_buffer_error("recv")));
            }

            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            match self.inner.recv(buf) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(err) = self.register_interest(cx, Interest::READABLE) {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
    }

    /// Peek at the next datagram without consuming it.
    pub async fn peek_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = buf;
            browser_udp_unsupported_result("UdpSocket::peek_from")
        }

        #[cfg(not(target_arch = "wasm32"))]
        std::future::poll_fn(|cx| self.poll_peek_from(cx, buf)).await
    }

    /// Poll for peek_from readiness.
    pub fn poll_peek_from(
        &mut self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (self, cx, buf);
            browser_udp_poll_unsupported("UdpSocket::poll_peek_from")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if buf.is_empty() {
                return Poll::Ready(Err(empty_udp_receive_buffer_error("peek_from")));
            }

            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            match self.inner.peek_from(buf) {
                Ok(res) => Poll::Ready(Ok(res)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(err) = self.register_interest(cx, Interest::READABLE) {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
    }

    /// Returns the local address of this socket.
    #[inline]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the peer address, if connected.
    #[inline]
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Sets the broadcast option.
    #[inline]
    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.inner.set_broadcast(on)
    }

    /// Sets the multicast loopback option for IPv4.
    #[inline]
    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.inner.set_multicast_loop_v4(on)
    }

    /// Join an IPv4 multicast group.
    #[inline]
    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.inner.join_multicast_v4(&multiaddr, &interface)
    }

    /// Leave an IPv4 multicast group.
    #[inline]
    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.inner.leave_multicast_v4(&multiaddr, &interface)
    }

    /// Set the time-to-live for this socket.
    #[inline]
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Join an IPv6 multicast group.
    #[inline]
    pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner.join_multicast_v6(multiaddr, interface)
    }

    /// Leave an IPv6 multicast group.
    #[inline]
    pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner.leave_multicast_v6(multiaddr, interface)
    }

    /// Set the IPv4 multicast TTL.
    #[inline]
    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_multicast_ttl_v4(ttl)
    }

    /// Returns a stream of incoming datagrams.
    #[must_use]
    pub fn recv_stream(&mut self, buf_size: usize) -> RecvStream<'_> {
        RecvStream::new(self, buf_size)
    }

    /// Returns a sink-like wrapper for sending datagrams.
    #[must_use]
    pub fn send_sink(&mut self) -> SendSink<'_> {
        SendSink::new(self)
    }

    /// Report socket capabilities visible through the portable UDP layer.
    pub fn capabilities(&self) -> io::Result<UdpSocketCapabilities> {
        #[cfg(target_arch = "wasm32")]
        {
            browser_udp_unsupported_result("UdpSocket::capabilities")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let local_addr = self.local_addr().ok();
            let sock = socket2::SockRef::from(&*self.inner);
            let observed_recv_buffer_bytes = sock.recv_buffer_size().ok();
            let observed_send_buffer_bytes = sock.send_buffer_size().ok();
            let address_family =
                local_addr.map_or(UdpAddressFamily::Unknown, UdpAddressFamily::from);
            let dual_stack = match address_family {
                UdpAddressFamily::Ipv6 => UdpCapability::Unknown,
                UdpAddressFamily::Ipv4 => UdpCapability::Unsupported,
                UdpAddressFamily::Unknown => UdpCapability::Unknown,
            };

            Ok(UdpSocketCapabilities {
                platform: UdpPlatform::current(),
                address_family,
                dual_stack,
                ecn: UdpCapability::Unknown,
                batching: UdpBatchCapabilities::default(),
                observed_recv_buffer_bytes,
                observed_send_buffer_bytes,
            })
        }
    }

    /// Report send-side acceleration capabilities visible to the planner.
    #[must_use]
    pub fn send_acceleration_capabilities(&self) -> UdpSendAccelerationCapabilities {
        let mut capabilities = UdpSendAccelerationCapabilities::default();
        if self.gso_demoted {
            capabilities.gso = UdpCapability::Unsupported;
        }
        capabilities
    }

    /// Plan the send-side path for a datagram batch without sending it.
    #[must_use]
    pub fn plan_send_batch(
        &self,
        packets: &[UdpOutboundDatagram<'_>],
        strategy: UdpSendBatchStrategy,
    ) -> UdpSendBatchPlan {
        UdpSendBatchPlan::for_packets(packets, self.send_acceleration_capabilities(), strategy)
    }

    /// Plan the send-side path for payloads sent to this socket's connected
    /// peer.
    #[must_use]
    pub fn plan_connected_send_batch(
        &self,
        payloads: &[&[u8]],
        strategy: UdpSendBatchStrategy,
    ) -> UdpSendBatchPlan {
        UdpSendBatchPlan::for_connected_payloads(
            payloads,
            self.send_acceleration_capabilities(),
            strategy,
        )
    }

    /// Apply bounded receive/send buffer tuning and report platform-applied sizes.
    pub fn tune_buffers(&self, config: UdpBufferConfig) -> io::Result<UdpBufferTuneReport> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = config;
            browser_udp_unsupported_result("UdpSocket::tune_buffers")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let requested = config.clamped();
            let sock = socket2::SockRef::from(&*self.inner);

            if let Some(size) = requested.recv_buffer_bytes {
                sock.set_recv_buffer_size(size)?;
            }
            if let Some(size) = requested.send_buffer_bytes {
                sock.set_send_buffer_size(size)?;
            }

            Ok(UdpBufferTuneReport {
                requested_recv_buffer_bytes: requested.recv_buffer_bytes,
                requested_send_buffer_bytes: requested.send_buffer_bytes,
                applied_recv_buffer_bytes: sock.recv_buffer_size().ok(),
                applied_send_buffer_bytes: sock.send_buffer_size().ok(),
            })
        }
    }

    /// Send a portable batch of datagrams with a cancel checkpoint between packets.
    pub async fn send_batch_to(
        &mut self,
        packets: &[UdpOutboundDatagram<'_>],
    ) -> io::Result<UdpBatchIoReport> {
        self.send_batch_to_with_strategy(packets, UdpSendBatchStrategy::default())
            .await
    }

    /// Send a batch of payloads to this socket's connected peer.
    pub async fn send_connected_batch(
        &mut self,
        payloads: &[&[u8]],
    ) -> io::Result<UdpBatchIoReport> {
        self.send_connected_batch_with_strategy(payloads, UdpSendBatchStrategy::default())
            .await
    }

    /// Send a batch of datagrams using an explicit send-acceleration strategy.
    pub async fn send_batch_to_with_strategy(
        &mut self,
        packets: &[UdpOutboundDatagram<'_>],
        strategy: UdpSendBatchStrategy,
    ) -> io::Result<UdpBatchIoReport> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = packets;
            let _ = strategy;
            browser_udp_unsupported_result("UdpSocket::send_batch_to")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let strategy = strategy.clamped();
            loop {
                match self.try_send_batch_to_native(packets, strategy)? {
                    NativeSendBatchAttempt::Sent(native_report) => {
                        if native_report.packets_processed == packets.len() {
                            return Ok(native_report);
                        }

                        let tail = &packets[native_report.packets_processed..];
                        return self
                            .finish_send_batch_after_native_partial(native_report, tail)
                            .await;
                    }
                    NativeSendBatchAttempt::WouldBlock => {
                        self.wait_writable_for_native_batch().await?;
                    }
                    NativeSendBatchAttempt::Unavailable => break,
                }
            }

            self.send_batch_to_portable(packets, packets.len() > 1)
                .await
        }
    }

    /// Send connected payloads using an explicit send-acceleration strategy.
    pub async fn send_connected_batch_with_strategy(
        &mut self,
        payloads: &[&[u8]],
        strategy: UdpSendBatchStrategy,
    ) -> io::Result<UdpBatchIoReport> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = payloads;
            let _ = strategy;
            browser_udp_unsupported_result("UdpSocket::send_connected_batch")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner.peer_addr()?;
            let strategy = strategy.clamped();
            loop {
                match self.try_send_connected_batch_to_native(payloads, strategy)? {
                    NativeSendBatchAttempt::Sent(native_report) => {
                        if native_report.packets_processed == payloads.len() {
                            return Ok(native_report);
                        }

                        let tail = &payloads[native_report.packets_processed..];
                        return self
                            .finish_connected_batch_after_native_partial(native_report, tail)
                            .await;
                    }
                    NativeSendBatchAttempt::WouldBlock => {
                        self.wait_writable_for_native_batch().await?;
                    }
                    NativeSendBatchAttempt::Unavailable => break,
                }
            }

            self.send_connected_batch_portable(payloads, payloads.len() > 1)
                .await
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn wait_writable_for_native_batch(&mut self) -> io::Result<()> {
        // Keep native sendmmsg/GSO eligible after transient UDP backpressure.
        // Falling straight through to the portable loop would reintroduce one
        // syscall per datagram on the connected ATP-RQ spray path.
        let mut armed = false;
        std::future::poll_fn(|cx| {
            if armed {
                return Poll::Ready(Ok(()));
            }
            armed = true;
            match self.register_interest(cx, Interest::WRITABLE) {
                Ok(()) => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            }
        })
        .await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn finish_send_batch_after_native_partial(
        &mut self,
        mut report: UdpBatchIoReport,
        tail: &[UdpOutboundDatagram<'_>],
    ) -> io::Result<UdpBatchIoReport> {
        if tail.is_empty() {
            return Ok(report);
        }

        match self.send_batch_to_portable(tail, true).await {
            Ok(tail_report) => {
                report.packets_processed += tail_report.packets_processed;
                report.bytes_processed += tail_report.bytes_processed;
                report.fallback_used |= tail_report.fallback_used;
                report.native_send_batch_used |= tail_report.native_send_batch_used;
                report.gso_send_used |= tail_report.gso_send_used;
                report.error = tail_report.error;
                Ok(report)
            }
            Err(err) if report.packets_processed > 0 => {
                report.fallback_used = true;
                report.error = Some(err.to_string());
                Ok(report)
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn finish_connected_batch_after_native_partial(
        &mut self,
        mut report: UdpBatchIoReport,
        tail: &[&[u8]],
    ) -> io::Result<UdpBatchIoReport> {
        if tail.is_empty() {
            return Ok(report);
        }

        match self.send_connected_batch_portable(tail, true).await {
            Ok(tail_report) => {
                report.packets_processed += tail_report.packets_processed;
                report.bytes_processed += tail_report.bytes_processed;
                report.fallback_used |= tail_report.fallback_used;
                report.native_send_batch_used |= tail_report.native_send_batch_used;
                report.gso_send_used |= tail_report.gso_send_used;
                report.error = tail_report.error;
                Ok(report)
            }
            Err(err) if report.packets_processed > 0 => {
                report.fallback_used = true;
                report.error = Some(err.to_string());
                Ok(report)
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn send_batch_to_portable(
        &mut self,
        packets: &[UdpOutboundDatagram<'_>],
        fallback_used: bool,
    ) -> io::Result<UdpBatchIoReport> {
        let mut report = UdpBatchIoReport {
            fallback_used,
            ..UdpBatchIoReport::default()
        };

        for packet in packets {
            match self.send_to(packet.payload, packet.dst_addr).await {
                Ok(sent) => {
                    report.packets_processed += 1;
                    report.bytes_processed += sent;
                }
                Err(err) if report.packets_processed == 0 => return Err(err),
                Err(err) => {
                    report.error = Some(err.to_string());
                    break;
                }
            }
        }

        Ok(report)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn send_connected_batch_portable(
        &mut self,
        payloads: &[&[u8]],
        fallback_used: bool,
    ) -> io::Result<UdpBatchIoReport> {
        let mut report = UdpBatchIoReport {
            fallback_used,
            ..UdpBatchIoReport::default()
        };

        for payload in payloads {
            match self.send(payload).await {
                Ok(sent) => {
                    report.packets_processed += 1;
                    report.bytes_processed += sent;
                }
                Err(err) if report.packets_processed == 0 => return Err(err),
                Err(err) => {
                    report.error = Some(err.to_string());
                    break;
                }
            }
        }

        Ok(report)
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd"
        )
    ))]
    fn try_send_batch_to_native(
        &mut self,
        packets: &[UdpOutboundDatagram<'_>],
        strategy: UdpSendBatchStrategy,
    ) -> io::Result<NativeSendBatchAttempt> {
        if packets.len() <= 1 {
            return Ok(NativeSendBatchAttempt::Unavailable);
        }
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }

        let connected_peer = self.inner.peer_addr().ok();
        if let Some(peer_addr) = connected_peer {
            if !packets.iter().all(|packet| packet.dst_addr == peer_addr) {
                return Ok(NativeSendBatchAttempt::Unavailable);
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let plan = self.plan_send_batch(packets, strategy);
            if matches!(
                plan.path,
                UdpSendBatchPath::Gso | UdpSendBatchPath::GsoSendmmsg
            ) {
                match self.try_send_gso_batch_to_native(packets, &plan, connected_peer)? {
                    NativeSendBatchAttempt::Sent(report) => {
                        return Ok(NativeSendBatchAttempt::Sent(report));
                    }
                    NativeSendBatchAttempt::WouldBlock => {
                        return Ok(NativeSendBatchAttempt::WouldBlock);
                    }
                    NativeSendBatchAttempt::Unavailable => {
                        self.gso_demoted = true;
                    }
                }
            }
        }

        self.try_sendmmsg_batch_to_native(packets, connected_peer)
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd"
        )
    ))]
    fn try_send_connected_batch_to_native(
        &mut self,
        payloads: &[&[u8]],
        strategy: UdpSendBatchStrategy,
    ) -> io::Result<NativeSendBatchAttempt> {
        if payloads.len() <= 1 {
            return Ok(NativeSendBatchAttempt::Unavailable);
        }
        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }

        let connected_peer = self.inner.peer_addr()?;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let plan = self.plan_connected_send_batch(payloads, strategy);
            if matches!(
                plan.path,
                UdpSendBatchPath::Gso | UdpSendBatchPath::GsoSendmmsg
            ) {
                match self.try_send_connected_gso_batch_to_native(
                    payloads,
                    &plan,
                    connected_peer,
                )? {
                    NativeSendBatchAttempt::Sent(report) => {
                        return Ok(NativeSendBatchAttempt::Sent(report));
                    }
                    NativeSendBatchAttempt::WouldBlock => {
                        return Ok(NativeSendBatchAttempt::WouldBlock);
                    }
                    NativeSendBatchAttempt::Unavailable => {
                        self.gso_demoted = true;
                    }
                }
            }
        }

        self.try_send_connected_sendmmsg_batch_to_native(payloads)
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(target_os = "linux", target_os = "android")
    ))]
    fn try_send_gso_batch_to_native(
        &mut self,
        packets: &[UdpOutboundDatagram<'_>],
        plan: &UdpSendBatchPlan,
        connected_peer: Option<SocketAddr>,
    ) -> io::Result<NativeSendBatchAttempt> {
        let Some(segment_bytes) = plan
            .gso_segment_bytes
            .and_then(|bytes| u16::try_from(bytes).ok())
        else {
            return Ok(NativeSendBatchAttempt::Unavailable);
        };
        let Some(segments_per_packet) = plan.gso_segments_per_packet else {
            return Ok(NativeSendBatchAttempt::Unavailable);
        };
        if segments_per_packet == 0 {
            return Ok(NativeSendBatchAttempt::Unavailable);
        }

        let super_packets = packets
            .chunks(segments_per_packet)
            .map(UdpGsoSuperPacket::from_packets)
            .collect::<Vec<_>>();

        let mut report = UdpBatchIoReport {
            native_send_batch_used: true,
            gso_send_used: true,
            ..UdpBatchIoReport::default()
        };
        for chunk in super_packets.chunks(UDP_MAX_SENDMMSG_BATCH) {
            let iovs = chunk
                .iter()
                .map(|packet| [IoSlice::new(packet.buffer.as_slice())])
                .collect::<Vec<_>>();
            let addrs = native_sendmmsg_addrs_for_gso_packets(chunk, connected_peer);
            let mut headers = nix::sys::socket::MultiHeaders::<NativeSendmmsgAddr>::preallocate(
                chunk.len(),
                Some(nix::cmsg_space!(u16)),
            );
            let cmsgs = [nix::sys::socket::ControlMessage::UdpGsoSegments(
                &segment_bytes,
            )];
            let results = match nix::sys::socket::sendmmsg(
                self.inner.as_raw_fd(),
                &mut headers,
                &iovs,
                addrs,
                cmsgs,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(results) => results,
                Err(err) if native_send_error_would_block(err) && report.packets_processed == 0 => {
                    return Ok(NativeSendBatchAttempt::WouldBlock);
                }
                Err(_) if report.packets_processed == 0 => {
                    return Ok(NativeSendBatchAttempt::Unavailable);
                }
                Err(err) => {
                    report.error = Some(err.to_string());
                    return Ok(NativeSendBatchAttempt::Sent(report));
                }
            };

            let mut sent_in_chunk = 0usize;
            for (result, super_packet) in results.zip(chunk.iter()) {
                if result.bytes != super_packet.payload_bytes {
                    report.error = Some(format!(
                        "native UDP GSO sendmmsg sent {} bytes for {} byte super-packet",
                        result.bytes, super_packet.payload_bytes
                    ));
                    return Ok(NativeSendBatchAttempt::Sent(report));
                }
                sent_in_chunk += 1;
                report.packets_processed += super_packet.datagram_count;
                report.bytes_processed += result.bytes;
            }
            if sent_in_chunk < chunk.len() {
                if sent_in_chunk == 0 && report.packets_processed == 0 {
                    return Ok(NativeSendBatchAttempt::WouldBlock);
                }
                if sent_in_chunk == 0 {
                    report.error = Some("native sendmmsg made no progress".to_string());
                }
                return Ok(NativeSendBatchAttempt::Sent(report));
            }
        }

        Ok(NativeSendBatchAttempt::Sent(report))
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(target_os = "linux", target_os = "android")
    ))]
    fn try_send_connected_gso_batch_to_native(
        &mut self,
        payloads: &[&[u8]],
        plan: &UdpSendBatchPlan,
        connected_peer: SocketAddr,
    ) -> io::Result<NativeSendBatchAttempt> {
        let Some(segment_bytes) = plan
            .gso_segment_bytes
            .and_then(|bytes| u16::try_from(bytes).ok())
        else {
            return Ok(NativeSendBatchAttempt::Unavailable);
        };
        let Some(segments_per_packet) = plan.gso_segments_per_packet else {
            return Ok(NativeSendBatchAttempt::Unavailable);
        };
        if segments_per_packet == 0 {
            return Ok(NativeSendBatchAttempt::Unavailable);
        }

        let super_packets = payloads
            .chunks(segments_per_packet)
            .map(|chunk| UdpGsoSuperPacket::from_connected_payloads(chunk, connected_peer))
            .collect::<Vec<_>>();

        let mut report = UdpBatchIoReport {
            native_send_batch_used: true,
            gso_send_used: true,
            ..UdpBatchIoReport::default()
        };
        for chunk in super_packets.chunks(UDP_MAX_SENDMMSG_BATCH) {
            let iovs = chunk
                .iter()
                .map(|packet| [IoSlice::new(packet.buffer.as_slice())])
                .collect::<Vec<_>>();
            let addrs = native_sendmmsg_none_addrs(chunk.len());
            let mut headers = nix::sys::socket::MultiHeaders::<NativeSendmmsgAddr>::preallocate(
                chunk.len(),
                Some(nix::cmsg_space!(u16)),
            );
            let cmsgs = [nix::sys::socket::ControlMessage::UdpGsoSegments(
                &segment_bytes,
            )];
            let results = match nix::sys::socket::sendmmsg(
                self.inner.as_raw_fd(),
                &mut headers,
                &iovs,
                addrs,
                cmsgs,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(results) => results,
                Err(err) if native_send_error_would_block(err) && report.packets_processed == 0 => {
                    return Ok(NativeSendBatchAttempt::WouldBlock);
                }
                Err(_) if report.packets_processed == 0 => {
                    return Ok(NativeSendBatchAttempt::Unavailable);
                }
                Err(err) => {
                    report.error = Some(err.to_string());
                    return Ok(NativeSendBatchAttempt::Sent(report));
                }
            };

            let mut sent_in_chunk = 0usize;
            for (result, super_packet) in results.zip(chunk.iter()) {
                if result.bytes != super_packet.payload_bytes {
                    report.error = Some(format!(
                        "native connected UDP GSO sendmmsg sent {} bytes for {} byte super-packet",
                        result.bytes, super_packet.payload_bytes
                    ));
                    return Ok(NativeSendBatchAttempt::Sent(report));
                }
                sent_in_chunk += 1;
                report.packets_processed += super_packet.datagram_count;
                report.bytes_processed += result.bytes;
            }
            if sent_in_chunk < chunk.len() {
                if sent_in_chunk == 0 && report.packets_processed == 0 {
                    return Ok(NativeSendBatchAttempt::WouldBlock);
                }
                if sent_in_chunk == 0 {
                    report.error = Some("native connected sendmmsg made no progress".to_string());
                }
                return Ok(NativeSendBatchAttempt::Sent(report));
            }
        }

        Ok(NativeSendBatchAttempt::Sent(report))
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd"
        )
    ))]
    fn try_sendmmsg_batch_to_native(
        &mut self,
        packets: &[UdpOutboundDatagram<'_>],
        connected_peer: Option<SocketAddr>,
    ) -> io::Result<NativeSendBatchAttempt> {
        let mut report = UdpBatchIoReport {
            native_send_batch_used: true,
            ..UdpBatchIoReport::default()
        };
        for chunk in packets.chunks(UDP_MAX_SENDMMSG_BATCH) {
            let iovs = chunk
                .iter()
                .map(|packet| [IoSlice::new(packet.payload)])
                .collect::<Vec<_>>();
            let addrs = native_sendmmsg_addrs_for_packets(chunk, connected_peer);
            let mut headers = nix::sys::socket::MultiHeaders::<NativeSendmmsgAddr>::preallocate(
                chunk.len(),
                None,
            );
            let cmsgs: &[nix::sys::socket::ControlMessage<'_>] = &[];
            let results = match nix::sys::socket::sendmmsg(
                self.inner.as_raw_fd(),
                &mut headers,
                &iovs,
                addrs,
                cmsgs,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(results) => results,
                Err(err) if native_send_error_would_block(err) && report.packets_processed == 0 => {
                    return Ok(NativeSendBatchAttempt::WouldBlock);
                }
                Err(_) if report.packets_processed == 0 => {
                    return Ok(NativeSendBatchAttempt::Unavailable);
                }
                Err(err) => {
                    report.error = Some(err.to_string());
                    return Ok(NativeSendBatchAttempt::Sent(report));
                }
            };

            let mut sent_in_chunk = 0usize;
            for result in results {
                sent_in_chunk += 1;
                report.packets_processed += 1;
                report.bytes_processed += result.bytes;
            }
            if sent_in_chunk < chunk.len() {
                if sent_in_chunk == 0 && report.packets_processed == 0 {
                    return Ok(NativeSendBatchAttempt::WouldBlock);
                }
                if sent_in_chunk == 0 {
                    report.error = Some("native sendmmsg made no progress".to_string());
                }
                return Ok(NativeSendBatchAttempt::Sent(report));
            }
        }

        Ok(NativeSendBatchAttempt::Sent(report))
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd"
        )
    ))]
    fn try_send_connected_sendmmsg_batch_to_native(
        &mut self,
        payloads: &[&[u8]],
    ) -> io::Result<NativeSendBatchAttempt> {
        let mut report = UdpBatchIoReport {
            native_send_batch_used: true,
            ..UdpBatchIoReport::default()
        };
        for chunk in payloads.chunks(UDP_MAX_SENDMMSG_BATCH) {
            let iovs = chunk
                .iter()
                .map(|payload| [IoSlice::new(payload)])
                .collect::<Vec<_>>();
            let addrs = native_sendmmsg_none_addrs(chunk.len());
            let mut headers = nix::sys::socket::MultiHeaders::<NativeSendmmsgAddr>::preallocate(
                chunk.len(),
                None,
            );
            let cmsgs: &[nix::sys::socket::ControlMessage<'_>] = &[];
            let results = match nix::sys::socket::sendmmsg(
                self.inner.as_raw_fd(),
                &mut headers,
                &iovs,
                addrs,
                cmsgs,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(results) => results,
                Err(err) if native_send_error_would_block(err) && report.packets_processed == 0 => {
                    return Ok(NativeSendBatchAttempt::WouldBlock);
                }
                Err(_) if report.packets_processed == 0 => {
                    return Ok(NativeSendBatchAttempt::Unavailable);
                }
                Err(err) => {
                    report.error = Some(err.to_string());
                    return Ok(NativeSendBatchAttempt::Sent(report));
                }
            };

            let mut sent_in_chunk = 0usize;
            for result in results {
                sent_in_chunk += 1;
                report.packets_processed += 1;
                report.bytes_processed += result.bytes;
            }
            if sent_in_chunk < chunk.len() {
                if sent_in_chunk == 0 && report.packets_processed == 0 {
                    return Ok(NativeSendBatchAttempt::WouldBlock);
                }
                if sent_in_chunk == 0 {
                    report.error = Some("native connected sendmmsg made no progress".to_string());
                }
                return Ok(NativeSendBatchAttempt::Sent(report));
            }
        }

        Ok(NativeSendBatchAttempt::Sent(report))
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd"
        ))
    ))]
    fn try_send_batch_to_native(
        &mut self,
        packets: &[UdpOutboundDatagram<'_>],
        strategy: UdpSendBatchStrategy,
    ) -> io::Result<NativeSendBatchAttempt> {
        let _ = packets;
        let _ = strategy;
        Ok(NativeSendBatchAttempt::Unavailable)
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd"
        ))
    ))]
    fn try_send_connected_batch_to_native(
        &mut self,
        payloads: &[&[u8]],
        strategy: UdpSendBatchStrategy,
    ) -> io::Result<NativeSendBatchAttempt> {
        let _ = payloads;
        let _ = strategy;
        Ok(NativeSendBatchAttempt::Unavailable)
    }

    /// Receive one readiness-driven packet, then drain any immediately-ready packets.
    pub async fn recv_batch_from(
        &mut self,
        max_packets: usize,
        packet_size: usize,
    ) -> io::Result<UdpRecvBatch> {
        let mut spare_payloads = Vec::new();
        self.recv_batch_from_reusing(max_packets, packet_size, &mut spare_payloads)
            .await
    }

    /// Receive one readiness-driven packet, then drain immediately-ready
    /// packets, reusing packet payload buffers supplied by the caller.
    pub async fn recv_batch_from_reusing(
        &mut self,
        max_packets: usize,
        packet_size: usize,
        spare_payloads: &mut Vec<Vec<u8>>,
    ) -> io::Result<UdpRecvBatch> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (max_packets, packet_size, spare_payloads);
            browser_udp_unsupported_result("UdpSocket::recv_batch_from")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if max_packets == 0 {
                return Ok(UdpRecvBatch::default());
            }
            if packet_size == 0 {
                return Err(empty_udp_receive_buffer_error("recv_batch_from"));
            }

            // Prevent DoS via unbounded memory allocation (asupersync-z30chg)
            if max_packets > UDP_MAX_BATCH_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "max_packets ({}) exceeds UDP_MAX_BATCH_SIZE ({})",
                        max_packets, UDP_MAX_BATCH_SIZE
                    ),
                ));
            }
            if packet_size > UDP_MAX_PACKET_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "packet_size ({}) exceeds UDP_MAX_PACKET_SIZE ({})",
                        packet_size, UDP_MAX_PACKET_SIZE
                    ),
                ));
            }

            // One reusable scratch buffer serves every receive in the batch;
            // each datagram is copied out into an exactly-sized payload Vec.
            // This replaces the old per-datagram `packet_size` (up to 64 KiB)
            // allocation + zero fill with an `n`-byte allocation + copy, and
            // keeps downstream zero-copy consumers (which hold the payload
            // alive as shared `Bytes` backing) from pinning oversized buffers.
            let mut scratch = recv_batch_payload_buffer(spare_payloads, packet_size);
            let (bytes_read, src_addr) = match self.recv_from(&mut scratch).await {
                Ok(received) => received,
                Err(err) => {
                    recycle_unused_recv_batch_payload(spare_payloads, scratch);
                    return Err(err);
                }
            };

            let mut batch = UdpRecvBatch {
                packets: Vec::with_capacity(max_packets),
                report: UdpBatchIoReport {
                    packets_processed: 1,
                    bytes_processed: bytes_read,
                    fallback_used: max_packets > 1,
                    native_send_batch_used: false,
                    gso_send_used: false,
                    error: None,
                },
            };
            batch.packets.push(UdpInboundDatagram {
                src_addr,
                payload: scratch[..bytes_read].to_vec(),
                possibly_truncated: bytes_read == packet_size,
            });

            for _ in 1..max_packets {
                if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                    batch.report.error = Some("cancelled".to_string());
                    break;
                }

                match self.inner.recv_from(&mut scratch) {
                    Ok((n, addr)) => {
                        batch.report.packets_processed += 1;
                        batch.report.bytes_processed += n;
                        batch.packets.push(UdpInboundDatagram {
                            src_addr: addr,
                            payload: scratch[..n].to_vec(),
                            possibly_truncated: n == packet_size,
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(err) => {
                        batch.report.error = Some(err.to_string());
                        break;
                    }
                }
            }
            recycle_unused_recv_batch_payload(spare_payloads, scratch);

            Ok(batch)
        }
    }

    /// Clone this socket via the underlying OS handle.
    ///
    /// The new socket gets its own reactor registration.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: Arc::new(self.inner.try_clone()?),
            registration: None,
            gso_demoted: self.gso_demoted,
        })
    }

    /// Consume this wrapper and return the underlying std socket if unique.
    pub fn into_std(self) -> io::Result<StdUdpSocket> {
        match Arc::try_unwrap(self.inner) {
            Ok(socket) => Ok(socket),
            Err(shared) => shared.try_clone(),
        }
    }

    /// Creates an async `UdpSocket` from a standard library socket.
    ///
    /// The socket will be set to non-blocking mode to preserve async
    /// readiness semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if setting non-blocking mode fails.
    pub fn from_std(socket: StdUdpSocket) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = socket;
            browser_udp_unsupported_result("UdpSocket::from_std")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            socket.set_nonblocking(true)?;
            Ok(Self {
                inner: Arc::new(socket),
                registration: None,
                gso_demoted: false,
            })
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let _ = (cx, interest);
        browser_udp_unsupported_result("UdpSocket::register_interest")
    }

    /// Register interest with the reactor.
    #[cfg(not(target_arch = "wasm32"))]
    fn register_interest(&mut self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let target_interest = interest;
        if let Some(registration) = &mut self.registration {
            // Re-arm reactor interest and conditionally update the waker in a
            // single lock acquisition (will_wake guard skips the clone).
            match registration.rearm(target_interest, cx.waker()) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    self.registration = None;
                }
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    self.registration = None;
                    crate::net::tcp::stream::fallback_rewake(cx);
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }

        let Some(current) = Cx::current() else {
            crate::net::tcp::stream::fallback_rewake(cx);
            return Ok(());
        };
        let Some(driver) = current.io_driver_handle() else {
            crate::net::tcp::stream::fallback_rewake(cx);
            return Ok(());
        };

        match driver.register(&*self.inner, target_interest, cx.waker().clone()) {
            Ok(registration) => {
                self.registration = Some(registration);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                crate::net::tcp::stream::fallback_rewake(cx);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

/// Stream of incoming datagrams.
#[derive(Debug)]
pub struct RecvStream<'a> {
    socket: &'a mut UdpSocket,
    buf: Vec<u8>,
}

impl<'a> RecvStream<'a> {
    /// Create a new datagram stream with the given buffer size.
    #[must_use]
    pub fn new(socket: &'a mut UdpSocket, buf_size: usize) -> Self {
        // A zero-length UDP receive buffer can consume and discard a queued
        // datagram while yielding an empty payload. Clamp to one byte so
        // callers never silently drop the entire datagram body by accident.
        // Also clamp to UDP_MAX_PACKET_SIZE to prevent DoS via unbounded allocation.
        let clamped_size = buf_size.clamp(1, UDP_MAX_PACKET_SIZE);
        Self {
            socket,
            buf: vec![0u8; clamped_size],
        }
    }
}

impl Stream for RecvStream<'_> {
    type Item = io::Result<(Vec<u8>, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.socket.poll_recv_from(cx, &mut this.buf) {
            Poll::Ready(Ok((n, addr))) => Poll::Ready(Some(Ok((this.buf[..n].to_vec(), addr)))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Sink-like wrapper for sending datagrams.
#[derive(Debug)]
pub struct SendSink<'a> {
    socket: &'a mut UdpSocket,
}

impl<'a> SendSink<'a> {
    /// Create a new send sink for the given socket.
    #[must_use]
    pub fn new(socket: &'a mut UdpSocket) -> Self {
        Self { socket }
    }

    /// Send a datagram to the specified target.
    pub async fn send_to<A: ToSocketAddrs + Send + 'static>(
        &mut self,
        buf: &[u8],
        target: A,
    ) -> io::Result<usize> {
        self.socket.send_to(buf, target).await
    }

    /// Send a datagram tuple.
    pub async fn send_datagram(&mut self, datagram: (Vec<u8>, SocketAddr)) -> io::Result<usize> {
        self.socket.send_to(&datagram.0, datagram.1).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::stream::StreamExt;
    use crate::types::{Budget, RegionId, TaskId};
    use futures_lite::future;
    #[cfg(unix)]
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::sync::Arc;
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[test]
    fn udp_buffer_config_clamps_to_cross_platform_bounds() {
        let config = UdpBufferConfig {
            recv_buffer_bytes: Some(1),
            send_buffer_bytes: Some(usize::MAX),
        }
        .clamped();

        assert_eq!(config.recv_buffer_bytes, Some(UDP_MIN_SOCKET_BUFFER_BYTES));
        assert_eq!(config.send_buffer_bytes, Some(UDP_MAX_SOCKET_BUFFER_BYTES));
    }

    #[test]
    fn udp_capabilities_report_portable_batching() {
        future::block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let capabilities = socket.capabilities().unwrap();

            assert_eq!(capabilities.platform, UdpPlatform::current());
            assert_eq!(capabilities.address_family, UdpAddressFamily::Ipv4);
            assert!(capabilities.batching.portable_send_batch);
            assert!(capabilities.batching.portable_recv_batch);
            assert_eq!(
                capabilities.batching.native_send_batch,
                matches!(UdpPlatform::current(), UdpPlatform::Linux)
            );
            assert!(!capabilities.batching.native_recv_batch);
        });
    }

    #[test]
    fn udp_send_batch_plan_prefers_gso_sendmmsg_when_supported() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; 130];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy {
                max_sendmmsg_batch: 2,
                max_gso_segments: 64,
                ..UdpSendBatchStrategy::default()
            },
        );

        assert_eq!(plan.path, UdpSendBatchPath::GsoSendmmsg);
        assert_eq!(plan.datagrams, 130);
        assert_eq!(plan.payload_bytes, 130 * UDP_DEFAULT_GSO_SEGMENT_BYTES);
        assert_eq!(plan.estimated_syscalls, 2);
        assert_eq!(plan.gso_segment_bytes, Some(UDP_DEFAULT_GSO_SEGMENT_BYTES));
        assert_eq!(plan.gso_segments_per_packet, Some(64));
    }

    #[test]
    fn udp_send_batch_plan_keeps_default_rq_datagrams_gso_eligible() {
        const DEFAULT_RQ_SYMBOL_BYTES: usize = 1400;
        const RQ_DATAGRAM_HEADER_BYTES: usize = 24;
        const RQ_AUTH_TAG_BYTES: usize = 32;
        let unauthenticated_rq_datagram_bytes = DEFAULT_RQ_SYMBOL_BYTES + RQ_DATAGRAM_HEADER_BYTES;
        let authenticated_rq_datagram_bytes =
            DEFAULT_RQ_SYMBOL_BYTES + RQ_DATAGRAM_HEADER_BYTES + RQ_AUTH_TAG_BYTES;
        assert_eq!(
            UDP_DEFAULT_GSO_SEGMENT_BYTES,
            authenticated_rq_datagram_bytes
        );

        let dst = socket_addr("127.0.0.1:9000");
        for rq_datagram_bytes in [
            unauthenticated_rq_datagram_bytes,
            authenticated_rq_datagram_bytes,
        ] {
            let payloads = vec![vec![7; rq_datagram_bytes]; 4];
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: dst,
                    payload,
                })
                .collect::<Vec<_>>();

            let plan = UdpSendBatchPlan::for_packets(
                &packets,
                UdpSendAccelerationCapabilities {
                    sendmmsg: UdpCapability::Supported,
                    gso: UdpCapability::Supported,
                    max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                    max_gso_segments: UDP_MAX_GSO_SEGMENTS,
                },
                UdpSendBatchStrategy::default(),
            );

            assert_eq!(plan.path, UdpSendBatchPath::Gso);
            assert_eq!(plan.gso_segment_bytes, Some(rq_datagram_bytes));
            assert_eq!(plan.estimated_syscalls, 1);
        }
    }

    #[test]
    fn udp_connected_send_batch_plan_keeps_rq_gso_window_eligible() {
        let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; UDP_MAX_GSO_SEGMENTS];
        let payload_refs = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_connected_payloads(
            &payload_refs,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Gso);
        assert_eq!(plan.datagrams, UDP_MAX_GSO_SEGMENTS);
        assert_eq!(
            plan.payload_bytes,
            UDP_MAX_GSO_SEGMENTS * UDP_DEFAULT_GSO_SEGMENT_BYTES
        );
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, Some(UDP_DEFAULT_GSO_SEGMENT_BYTES));
        assert_eq!(plan.gso_segments_per_packet, Some(UDP_MAX_GSO_SEGMENTS));
    }

    #[test]
    fn udp_connected_send_batch_plan_batches_multiple_gso_windows() {
        let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; UDP_MAX_GSO_SEGMENTS * 2 + 1];
        let payload_refs = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_connected_payloads(
            &payload_refs,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::GsoSendmmsg);
        assert_eq!(plan.datagrams, UDP_MAX_GSO_SEGMENTS * 2 + 1);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, Some(UDP_DEFAULT_GSO_SEGMENT_BYTES));
        assert_eq!(plan.gso_segments_per_packet, Some(UDP_MAX_GSO_SEGMENTS));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn native_connected_sendmmsg_addrs_stay_inline_for_rq_window() {
        let addrs = native_sendmmsg_none_addrs(UDP_MAX_GSO_SEGMENTS);

        assert_eq!(addrs.len(), UDP_MAX_GSO_SEGMENTS);
        assert!(addrs.iter().all(Option::is_none));
        assert!(!addrs.spilled());
    }

    #[test]
    fn udp_send_batch_plan_demotes_gso_after_socket_rejection() {
        future::block_on(async {
            let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.gso_demoted = true;

            let dst = socket_addr("127.0.0.1:9000");
            let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; 4];
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: dst,
                    payload,
                })
                .collect::<Vec<_>>();

            let capabilities = socket.send_acceleration_capabilities();
            assert_eq!(capabilities.gso, UdpCapability::Unsupported);

            let plan = socket.plan_send_batch(&packets, UdpSendBatchStrategy::default());
            assert_ne!(plan.path, UdpSendBatchPath::Gso);
            assert_ne!(plan.path, UdpSendBatchPath::GsoSendmmsg);
            assert_eq!(plan.gso_segment_bytes, None);
            assert_eq!(plan.gso_segments_per_packet, None);
        });
    }

    #[test]
    fn udp_send_batch_plan_honors_capability_gso_segment_limit() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; UDP_DEFAULT_GSO_SEGMENT_BYTES]; 9];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: 2,
                max_gso_segments: 3,
            },
            UdpSendBatchStrategy {
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
                ..UdpSendBatchStrategy::default()
            },
        );

        assert_eq!(plan.path, UdpSendBatchPath::GsoSendmmsg);
        assert_eq!(plan.datagrams, 9);
        assert_eq!(plan.estimated_syscalls, 2);
        assert_eq!(plan.gso_segment_bytes, Some(UDP_DEFAULT_GSO_SEGMENT_BYTES));
        assert_eq!(plan.gso_segments_per_packet, Some(3));
    }

    #[test]
    fn udp_send_batch_plan_honors_capability_sendmmsg_batch_limit() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; 64]; 9];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Unsupported,
                max_sendmmsg_batch: 4,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy {
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                ..UdpSendBatchStrategy::default()
            },
        );

        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.datagrams, 9);
        assert_eq!(plan.estimated_syscalls, 3);
        assert_eq!(plan.gso_segment_bytes, None);
        assert_eq!(plan.gso_segments_per_packet, None);
    }

    #[test]
    fn udp_send_batch_plan_uses_fixed_payload_size_for_gso_segment() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; 900]; 4];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Gso);
        assert_eq!(plan.gso_segment_bytes, Some(900));
        assert_eq!(plan.gso_segments_per_packet, Some(4));
        assert_eq!(plan.estimated_syscalls, 1);
    }

    #[test]
    fn udp_send_batch_plan_accepts_large_quic_gso_segment_when_strategy_raises_limit() {
        let dst = socket_addr("127.0.0.1:9000");
        let payloads = vec![vec![7; 65_000]; 4];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy {
                gso_segment_bytes: 65_000,
                max_gso_segments: 4,
                ..UdpSendBatchStrategy::default()
            },
        );

        assert_eq!(plan.path, UdpSendBatchPath::Gso);
        assert_eq!(plan.datagrams, 4);
        assert_eq!(plan.payload_bytes, 260_000);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, Some(65_000));
        assert_eq!(plan.gso_segments_per_packet, Some(4));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn native_send_backpressure_keeps_native_batch_path_retryable() {
        assert!(native_send_error_would_block(nix::errno::Errno::EAGAIN));
        assert!(native_send_error_would_block(
            nix::errno::Errno::EWOULDBLOCK
        ));
        assert!(native_send_error_would_block(nix::errno::Errno::ENOBUFS));
        assert!(!native_send_error_would_block(nix::errno::Errno::EINVAL));
    }

    #[test]
    fn udp_send_batch_plan_falls_back_to_sendmmsg_for_mixed_destinations() {
        let payload = [3u8; 64];
        let packets = [
            UdpOutboundDatagram {
                dst_addr: socket_addr("127.0.0.1:9001"),
                payload: &payload,
            },
            UdpOutboundDatagram {
                dst_addr: socket_addr("127.0.0.1:9002"),
                payload: &payload,
            },
        ];

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, None);
    }

    #[test]
    fn udp_send_batch_plan_rejects_variable_payload_gso_boundaries() {
        let dst = socket_addr("127.0.0.1:9004");
        let large = [4u8; UDP_DEFAULT_GSO_SEGMENT_BYTES];
        let small = [5u8; UDP_DEFAULT_GSO_SEGMENT_BYTES / 2];
        let packets = [
            UdpOutboundDatagram {
                dst_addr: dst,
                payload: &large,
            },
            UdpOutboundDatagram {
                dst_addr: dst,
                payload: &small,
            },
        ];

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Supported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.estimated_syscalls, 1);
        assert_eq!(plan.gso_segment_bytes, None);
        assert_eq!(plan.gso_segments_per_packet, None);
    }

    #[test]
    fn udp_send_batch_plan_chunks_large_sendmmsg_batches() {
        let dst = socket_addr("127.0.0.1:9003");
        let payloads = vec![vec![1u8; 16]; UDP_MAX_SENDMMSG_BATCH + 7];
        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: dst,
                payload,
            })
            .collect::<Vec<_>>();

        let plan = UdpSendBatchPlan::for_packets(
            &packets,
            UdpSendAccelerationCapabilities {
                sendmmsg: UdpCapability::Supported,
                gso: UdpCapability::Unsupported,
                max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
                max_gso_segments: UDP_MAX_GSO_SEGMENTS,
            },
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Sendmmsg);
        assert_eq!(plan.datagrams, UDP_MAX_SENDMMSG_BATCH + 7);
        assert_eq!(plan.estimated_syscalls, 2);
        assert_eq!(plan.gso_segment_bytes, None);
    }

    #[test]
    fn udp_send_batch_plan_empty_batch_has_no_syscalls() {
        let plan = UdpSendBatchPlan::for_packets(
            &[],
            UdpSendAccelerationCapabilities::default(),
            UdpSendBatchStrategy::default(),
        );

        assert_eq!(plan.path, UdpSendBatchPath::Empty);
        assert_eq!(plan.datagrams, 0);
        assert_eq!(plan.payload_bytes, 0);
        assert_eq!(plan.estimated_syscalls, 0);
    }

    #[test]
    fn udp_buffer_tuning_reports_observed_sizes() {
        future::block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let report = socket
                .tune_buffers(UdpBufferConfig {
                    recv_buffer_bytes: Some(16 * 1024),
                    send_buffer_bytes: Some(16 * 1024),
                })
                .unwrap();

            assert_eq!(report.requested_recv_buffer_bytes, Some(16 * 1024));
            assert_eq!(report.requested_send_buffer_bytes, Some(16 * 1024));
            assert!(report.applied_recv_buffer_bytes.is_some());
            assert!(report.applied_send_buffer_bytes.is_some());
        });
    }

    fn socket_addr(value: &str) -> SocketAddr {
        value.parse().expect("valid socket addr")
    }

    fn rendezvous_candidate() -> UdpRendezvousCandidate {
        UdpRendezvousCandidate::new(
            socket_addr("198.51.100.20:62000"),
            UdpRendezvousCandidateKind::ObservedUdp,
            100,
            2_000,
        )
    }

    fn rendezvous_signature() -> UdpRendezvousSignature {
        UdpRendezvousSignature::new("device-1", vec![7; 64])
    }

    fn rendezvous_set() -> UdpRendezvousCandidateSet {
        UdpRendezvousCandidateSet::new(
            "peer.alpha",
            [1; UDP_RENDEZVOUS_NONCE_BYTES],
            2_000,
            4,
            vec![rendezvous_candidate()],
            Some(rendezvous_signature()),
        )
    }

    #[test]
    fn udp_rendezvous_validation_accepts_signed_bounded_candidates() {
        let set = rendezvous_set();

        let result = validate_udp_rendezvous_candidates(&set, 1_000, &[]);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn udp_rendezvous_validation_rejects_malformed_peer_id() {
        let mut set = rendezvous_set();
        set.peer_id = "peer with spaces".to_string();

        let result = validate_udp_rendezvous_candidates(&set, 1_000, &[]);

        assert_eq!(result, Err(UdpRendezvousValidationError::InvalidPeerId));
    }

    #[test]
    fn udp_rendezvous_validation_rejects_replayed_nonce() {
        let set = rendezvous_set();

        let result = validate_udp_rendezvous_candidates(&set, 1_000, &[set.nonce]);

        assert_eq!(result, Err(UdpRendezvousValidationError::ReplayedNonce));
    }

    #[test]
    fn udp_rendezvous_validation_rejects_expired_offer_and_candidate() {
        let mut expired_offer = rendezvous_set();
        expired_offer.expires_at_millis = 1_000;

        let offer_result = validate_udp_rendezvous_candidates(&expired_offer, 1_000, &[]);

        assert_eq!(
            offer_result,
            Err(UdpRendezvousValidationError::ExpiredOffer)
        );

        let mut expired_candidate = rendezvous_set();
        expired_candidate.candidates[0].expires_at_millis = 1_000;

        let candidate_result = validate_udp_rendezvous_candidates(&expired_candidate, 1_000, &[]);

        assert_eq!(
            candidate_result,
            Err(UdpRendezvousValidationError::ExpiredCandidate)
        );
    }

    #[test]
    fn udp_rendezvous_validation_rejects_unbounded_candidate_and_attempt_budgets() {
        let mut too_many_candidates = rendezvous_set();
        too_many_candidates.candidates =
            vec![rendezvous_candidate(); UDP_RENDEZVOUS_MAX_CANDIDATES + 1];

        let candidates_result =
            validate_udp_rendezvous_candidates(&too_many_candidates, 1_000, &[]);

        assert_eq!(
            candidates_result,
            Err(UdpRendezvousValidationError::TooManyCandidates)
        );

        let mut too_many_attempts = rendezvous_set();
        too_many_attempts.attempt_budget = UDP_RENDEZVOUS_MAX_ATTEMPTS + 1;

        let attempts_result = validate_udp_rendezvous_candidates(&too_many_attempts, 1_000, &[]);

        assert_eq!(
            attempts_result,
            Err(UdpRendezvousValidationError::AttemptBudgetTooLarge)
        );
    }

    #[test]
    fn udp_rendezvous_validation_rejects_unsigned_or_zero_signature() {
        let mut unsigned = rendezvous_set();
        unsigned.signature = None;

        let unsigned_result = validate_udp_rendezvous_candidates(&unsigned, 1_000, &[]);

        assert_eq!(
            unsigned_result,
            Err(UdpRendezvousValidationError::MissingSignature)
        );

        let mut zero_signature = rendezvous_set();
        zero_signature.signature = Some(UdpRendezvousSignature::new("device-1", vec![0; 64]));

        let zero_result = validate_udp_rendezvous_candidates(&zero_signature, 1_000, &[]);

        assert_eq!(
            zero_result,
            Err(UdpRendezvousValidationError::InvalidSignatureBytes)
        );
    }

    #[test]
    fn udp_nat_classifier_reports_missing_observations_as_unknown() {
        let assessment = classify_udp_nat(&[]);

        assert_eq!(assessment.kind, UdpNatKind::Unknown);
        assert_eq!(assessment.hairpin, UdpHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, UdpNatConfidence::Low);
        assert_eq!(assessment.observed_public_addr, None);
        assert_eq!(assessment.caveat, "missing_endpoint_observation");
    }

    #[test]
    fn udp_nat_classifier_reports_blocked_when_probes_fail() {
        let assessment = classify_udp_nat(&[UdpEndpointObservation::blocked(
            socket_addr("10.0.0.10:49152"),
            socket_addr("203.0.113.7:3478"),
        )]);

        assert_eq!(assessment.kind, UdpNatKind::UdpBlocked);
        assert_eq!(assessment.hairpin, UdpHairpinSupport::Unknown);
        assert_eq!(assessment.confidence, UdpNatConfidence::High);
        assert_eq!(assessment.observed_public_addr, None);
        assert_eq!(assessment.caveat, "no_udp_probe_reached_rendezvous");
    }

    #[test]
    fn udp_nat_classifier_distinguishes_ipv6_direct_path() {
        let local = socket_addr("[2001:db8::10]:49152");
        let assessment = classify_udp_nat(&[UdpEndpointObservation::observed(
            local,
            socket_addr("[2001:db8::1]:3478"),
            local,
        )]);

        assert_eq!(assessment.kind, UdpNatKind::Ipv6Direct);
        assert_eq!(assessment.confidence, UdpNatConfidence::Medium);
        assert_eq!(assessment.observed_public_addr, Some(local));
        assert_eq!(assessment.caveat, "ipv6_endpoint_observed_directly");
    }

    #[test]
    fn udp_nat_classifier_reports_stable_mapping_as_likely_easy_nat() {
        let public = socket_addr("198.51.100.20:62000");
        let observations = [
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.7:3478"),
                public,
            )
            .with_hairpin_result(true),
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.8:3478"),
                public,
            ),
        ];

        let assessment = classify_udp_nat(&observations);

        assert_eq!(assessment.kind, UdpNatKind::LikelyEasyNat);
        assert_eq!(assessment.hairpin, UdpHairpinSupport::Supported);
        assert_eq!(assessment.confidence, UdpNatConfidence::High);
        assert_eq!(assessment.observed_public_addr, Some(public));
        assert_eq!(assessment.caveat, "stable_public_mapping_observed");
    }

    #[test]
    fn udp_nat_classifier_reports_multiple_mappings_as_hard_or_symmetric_nat() {
        let observations = [
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.7:3478"),
                socket_addr("198.51.100.20:62000"),
            )
            .with_hairpin_result(false),
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.8:3478"),
                socket_addr("198.51.100.21:62001"),
            ),
        ];

        let assessment = classify_udp_nat(&observations);

        assert_eq!(assessment.kind, UdpNatKind::HardOrSymmetricNat);
        assert_eq!(assessment.hairpin, UdpHairpinSupport::Unsupported);
        assert_eq!(assessment.confidence, UdpNatConfidence::High);
        assert_eq!(assessment.observed_public_addr, None);
        assert_eq!(assessment.caveat, "multiple_public_mappings_observed");
    }

    #[test]
    fn udp_nat_classifier_treats_multiple_local_endpoints_as_unknown() {
        let observations = [
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.10:49152"),
                socket_addr("203.0.113.7:3478"),
                socket_addr("198.51.100.20:62000"),
            ),
            UdpEndpointObservation::observed(
                socket_addr("10.0.0.11:49153"),
                socket_addr("203.0.113.8:3478"),
                socket_addr("198.51.100.21:62001"),
            ),
        ];

        let assessment = classify_udp_nat(&observations);

        assert_eq!(assessment.kind, UdpNatKind::Unknown);
        assert_eq!(assessment.confidence, UdpNatConfidence::Low);
        assert_eq!(assessment.observed_public_addr, None);
        assert_eq!(assessment.caveat, "multiple_local_endpoints_observed");
    }

    #[test]
    fn udp_portable_batch_send_receive() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let packets = [
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"one",
                },
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"two",
                },
            ];
            let sent = sender
                .send_batch_to_with_strategy(
                    &packets,
                    UdpSendBatchStrategy {
                        prefer_sendmmsg: false,
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, 2);
            assert_eq!(sent.bytes_processed, 6);
            assert!(sent.fallback_used);

            let received = receiver.recv_batch_from(2, 16).await.unwrap();
            assert_eq!(received.report.packets_processed, 2);
            assert_eq!(
                received
                    .packets
                    .iter()
                    .map(|packet| packet.payload.as_slice())
                    .collect::<Vec<_>>(),
                vec![b"one".as_slice(), b"two".as_slice()]
            );
        });
    }

    #[test]
    fn udp_unconnected_batch_send_prefers_native_sendmmsg_on_linux() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let packets = [
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"native-one",
                },
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"native-two",
                },
            ];
            let sent = sender
                .send_batch_to_with_strategy(
                    &packets,
                    UdpSendBatchStrategy {
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, 2);
            assert_eq!(
                sent.bytes_processed,
                b"native-one".len() + b"native-two".len()
            );

            if matches!(UdpPlatform::current(), UdpPlatform::Linux) {
                assert!(sent.native_send_batch_used);
                assert!(!sent.gso_send_used);
                assert!(!sent.fallback_used);
            } else {
                assert!(!sent.native_send_batch_used);
                assert!(sent.fallback_used);
            }

            let received = receiver.recv_batch_from(2, 32).await.unwrap();
            assert_eq!(received.report.packets_processed, 2);
            assert_eq!(
                received
                    .packets
                    .iter()
                    .map(|packet| packet.payload.as_slice())
                    .collect::<Vec<_>>(),
                vec![b"native-one".as_slice(), b"native-two".as_slice()]
            );
        });
    }

    #[test]
    fn udp_connected_batch_send_prefers_native_sendmmsg_on_linux() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();

            let packets = [
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"native-one",
                },
                UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload: b"native-two",
                },
            ];
            let sent = sender
                .send_batch_to_with_strategy(
                    &packets,
                    UdpSendBatchStrategy {
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, 2);
            assert_eq!(
                sent.bytes_processed,
                b"native-one".len() + b"native-two".len()
            );

            if matches!(UdpPlatform::current(), UdpPlatform::Linux) {
                assert!(sent.native_send_batch_used);
                assert!(!sent.gso_send_used);
                assert!(!sent.fallback_used);
            } else {
                assert!(!sent.native_send_batch_used);
                assert!(sent.fallback_used);
            }

            let received = receiver.recv_batch_from(2, 32).await.unwrap();
            assert_eq!(received.report.packets_processed, 2);
            assert_eq!(
                received
                    .packets
                    .iter()
                    .map(|packet| packet.payload.as_slice())
                    .collect::<Vec<_>>(),
                vec![b"native-one".as_slice(), b"native-two".as_slice()]
            );
        });
    }

    #[test]
    fn udp_connected_batch_send_strategy_can_disable_gso() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();

            let payloads = (0..4)
                .map(|_| vec![7u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload,
                })
                .collect::<Vec<_>>();
            let sent = sender
                .send_batch_to_with_strategy(
                    &packets,
                    UdpSendBatchStrategy {
                        prefer_gso: false,
                        ..UdpSendBatchStrategy::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, packets.len());
            assert_eq!(
                sent.bytes_processed,
                packets
                    .iter()
                    .map(|packet| packet.payload.len())
                    .sum::<usize>()
            );

            if matches!(UdpPlatform::current(), UdpPlatform::Linux) {
                assert!(sent.native_send_batch_used);
                assert!(!sent.gso_send_used);
                assert!(!sent.fallback_used);
            } else {
                assert!(!sent.native_send_batch_used);
                assert!(sent.fallback_used);
            }

            let received = receiver
                .recv_batch_from(packets.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                .await
                .unwrap();
            assert_eq!(received.report.packets_processed, packets.len());
        });
    }

    #[test]
    fn udp_unconnected_batch_send_uses_gso_for_fixed_size_payloads_on_linux() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let payloads = (0..4)
                .map(|idx| vec![idx as u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload,
                })
                .collect::<Vec<_>>();

            let sent = sender.send_batch_to(&packets).await.unwrap();
            assert_eq!(sent.packets_processed, packets.len());
            assert_eq!(
                sent.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * packets.len()
            );

            if matches!(UdpPlatform::current(), UdpPlatform::Linux) {
                assert!(sent.native_send_batch_used);
                assert!(sent.gso_send_used);
                assert!(!sent.fallback_used);
            } else {
                assert!(!sent.native_send_batch_used);
                assert!(sent.fallback_used);
            }

            let received = receiver
                .recv_batch_from(packets.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                .await
                .unwrap();
            assert_eq!(received.report.packets_processed, packets.len());
            assert_eq!(
                received.report.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * packets.len()
            );

            let mut received_payloads = received
                .packets
                .iter()
                .map(|packet| packet.payload.clone())
                .collect::<Vec<_>>();
            received_payloads.sort_by_key(|payload| payload[0]);
            assert_eq!(received_payloads, payloads);
        });
    }

    #[test]
    fn udp_connected_batch_send_uses_gso_for_fixed_size_payloads_on_linux() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();

            let payloads = (0..4)
                .map(|idx| vec![idx as u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let packets = payloads
                .iter()
                .map(|payload| UdpOutboundDatagram {
                    dst_addr: receiver_addr,
                    payload,
                })
                .collect::<Vec<_>>();

            let sent = sender.send_batch_to(&packets).await.unwrap();
            assert_eq!(sent.packets_processed, packets.len());
            assert_eq!(
                sent.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * packets.len()
            );

            if matches!(UdpPlatform::current(), UdpPlatform::Linux) {
                assert!(sent.native_send_batch_used);
                assert!(sent.gso_send_used);
                assert!(!sent.fallback_used);
            } else {
                assert!(!sent.native_send_batch_used);
                assert!(sent.fallback_used);
            }

            let received = receiver
                .recv_batch_from(packets.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                .await
                .unwrap();
            assert_eq!(received.report.packets_processed, packets.len());
            assert_eq!(
                received.report.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * packets.len()
            );

            let mut received_payloads = received
                .packets
                .iter()
                .map(|packet| packet.payload.clone())
                .collect::<Vec<_>>();
            received_payloads.sort_by_key(|payload| payload[0]);
            assert_eq!(received_payloads, payloads);
        });
    }

    #[test]
    fn udp_connected_payload_batch_send_uses_gso_for_fixed_size_payloads_on_linux() {
        future::block_on(async {
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_addr = receiver.local_addr().unwrap();
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.connect(receiver_addr).await.unwrap();

            let payloads = (0..4)
                .map(|idx| vec![idx as u8; UDP_DEFAULT_GSO_SEGMENT_BYTES])
                .collect::<Vec<_>>();
            let payload_refs = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();

            let sent = sender.send_connected_batch(&payload_refs).await.unwrap();
            assert_eq!(sent.packets_processed, payload_refs.len());
            assert_eq!(
                sent.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * payload_refs.len()
            );

            if matches!(UdpPlatform::current(), UdpPlatform::Linux) {
                assert!(sent.native_send_batch_used);
                assert!(sent.gso_send_used);
                assert!(!sent.fallback_used);
            } else {
                assert!(!sent.native_send_batch_used);
                assert!(sent.fallback_used);
            }

            let received = receiver
                .recv_batch_from(payload_refs.len(), UDP_DEFAULT_GSO_SEGMENT_BYTES)
                .await
                .unwrap();
            assert_eq!(received.report.packets_processed, payload_refs.len());
            assert_eq!(
                received.report.bytes_processed,
                UDP_DEFAULT_GSO_SEGMENT_BYTES * payload_refs.len()
            );

            let mut received_payloads = received
                .packets
                .iter()
                .map(|packet| packet.payload.clone())
                .collect::<Vec<_>>();
            received_payloads.sort_by_key(|payload| payload[0]);
            assert_eq!(received_payloads, payloads);
        });
    }

    #[test]
    fn udp_send_recv_from() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let payload = b"ping";

            let sent = client.send_to(payload, server_addr).await.unwrap();
            assert_eq!(sent, payload.len());

            let mut buf = [0u8; 16];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], payload);
            assert_eq!(peer, client.local_addr().unwrap());
        });
    }

    #[test]
    fn udp_connected_send_recv() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            server.connect(client_addr).await.unwrap();
            client.connect(server_addr).await.unwrap();

            let sent = client.send(b"hello").await.unwrap();
            assert_eq!(sent, 5);

            let mut buf = [0u8; 16];
            let n = server.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello");

            let sent = server.send(b"world").await.unwrap();
            assert_eq!(sent, 5);

            let n = client.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"world");
        });
    }

    #[test]
    fn udp_recv_stream_yields_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"stream", server_addr).await.unwrap();

            let mut stream = server.recv_stream(32);
            let item = stream.next().await.unwrap().unwrap();
            assert_eq!(item.0, b"stream");
        });
    }

    #[test]
    fn udp_recv_stream_zero_buffer_does_not_drop_nonempty_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"stream", server_addr).await.unwrap();

            let mut stream = server.recv_stream(0);
            let item = stream.next().await.unwrap().unwrap();
            assert_eq!(item.0, b"s");
        });
    }

    #[test]
    fn udp_peek_does_not_consume() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            client.send_to(b"peek", server_addr).await.unwrap();

            let mut buf = [0u8; 16];
            let (n, _) = server.peek_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"peek");

            let (n, _) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"peek");
        });
    }

    #[test]
    fn udp_recv_from_rejects_empty_buffer_without_consuming_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            client.send_to(b"ping", server_addr).await.unwrap();

            let mut empty = [];
            let err = server.recv_from(&mut empty).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

            let mut buf = [0u8; 16];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            assert_eq!(peer, client_addr);
        });
    }

    #[test]
    fn udp_mdns_multicast_tuple_matches_rfc6762() {
        let std_socket = StdUdpSocket::bind("0.0.0.0:0").expect("bind socket");
        let socket = UdpSocket::from_std(std_socket).expect("wrap socket");

        let mdns_group = Ipv4Addr::new(224, 0, 0, 251);
        let mdns_interface = Ipv4Addr::UNSPECIFIED;
        socket
            .join_multicast_v4(mdns_group, mdns_interface)
            .expect("join mDNS group");
        socket
            .leave_multicast_v4(mdns_group, mdns_interface)
            .expect("leave mDNS group");

        let mdns_socket = std::net::SocketAddrV4::new(mdns_group, 5353);
        assert_eq!(mdns_socket.to_string(), "224.0.0.251:5353");
    }

    #[test]
    fn udp_socket_registers_on_wouldblock() {
        // Create a socket pair
        let std_server = StdUdpSocket::bind("127.0.0.1:0").expect("bind server");
        std_server.set_nonblocking(true).expect("nonblocking");

        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut socket = UdpSocket::from_std(std_server).expect("wrap socket");
        let waker = noop_waker();
        let cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];

        // poll_recv_from should return Pending and register with reactor
        let poll = socket.poll_recv_from(&cx, &mut buf);
        assert!(matches!(poll, Poll::Pending));
        assert!(socket.registration.is_some());
    }

    #[test]
    fn udp_try_clone_creates_independent_socket() {
        future::block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let cloned = socket.try_clone().unwrap();

            // Both should have same local address
            assert_eq!(socket.local_addr().unwrap(), cloned.local_addr().unwrap());

            // Cloned socket should have no registration
            assert!(cloned.registration.is_none());
        });
    }

    #[cfg(unix)]
    #[test]
    fn udp_from_std_forces_nonblocking_mode() {
        let std_socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind socket");
        let socket = UdpSocket::from_std(std_socket).expect("wrap socket");
        let flags = fcntl(socket.inner.as_ref(), FcntlArg::F_GETFL).expect("read socket flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        assert!(
            is_nonblocking,
            "UdpSocket::from_std should force nonblocking mode"
        );
    }

    #[test]
    fn udp_large_datagram() {
        future::block_on(async {
            let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let mut client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Send a larger datagram (8KB)
            let payload = vec![0xAB; 8192];
            let sent = client.send_to(&payload, server_addr).await.unwrap();
            assert_eq!(sent, 8192);

            let mut buf = vec![0u8; 16384];
            let (n, _) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 8192);
            assert!(buf[..n].iter().all(|&b| b == 0xAB));
        });
    }

    #[test]
    fn udp_cancelled_operations_return_interrupted_without_registration() {
        future::block_on(async {
            let mut poll_recv_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let poll_recv_addr = poll_recv_socket.local_addr().unwrap();

            let mut poll_send_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let poll_send_addr = poll_send_socket.local_addr().unwrap();

            poll_send_socket.connect(poll_recv_addr).await.unwrap();
            poll_recv_socket.connect(poll_send_addr).await.unwrap();

            let mut send_to_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_addr = peer_socket.local_addr().unwrap();

            let connect_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let cx = Cx::for_testing();
            cx.set_cancel_requested(true);
            let _guard = Cx::set_current(Some(cx));

            let waker = noop_waker();
            let task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 16];

            let connect_err = connect_socket.connect(peer_addr).await.unwrap_err();
            assert_eq!(connect_err.kind(), io::ErrorKind::Interrupted);
            assert!(connect_socket.peer_addr().is_err());

            let send_to =
                send_to_socket.poll_send_to(&task_cx, b"ping", std::slice::from_ref(&peer_addr));
            assert!(matches!(
                send_to,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(send_to_socket.registration.is_none());

            let recv_from = poll_recv_socket.poll_recv_from(&task_cx, &mut buf);
            assert!(matches!(
                recv_from,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(poll_recv_socket.registration.is_none());

            let send = poll_send_socket.poll_send(&task_cx, b"hello");
            assert!(matches!(
                send,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(poll_send_socket.registration.is_none());

            let recv = poll_recv_socket.poll_recv(&task_cx, &mut buf);
            assert!(matches!(
                recv,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(poll_recv_socket.registration.is_none());

            let peek_from = poll_recv_socket.poll_peek_from(&task_cx, &mut buf);
            assert!(matches!(
                peek_from,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ));
            assert!(poll_recv_socket.registration.is_none());
        });
    }

    #[test]
    fn udp_dos_prevention() {
        future::block_on(async {
            let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Test recv_batch_from DoS prevention - packet_size limit
            let result = socket.recv_batch_from(1, UDP_MAX_PACKET_SIZE + 1).await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("packet_size"));
            assert!(err.to_string().contains("UDP_MAX_PACKET_SIZE"));

            // Test recv_batch_from DoS prevention - max_packets limit
            let result = socket.recv_batch_from(UDP_MAX_BATCH_SIZE + 1, 1024).await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("max_packets"));
            assert!(err.to_string().contains("UDP_MAX_BATCH_SIZE"));

            // Test RecvStream DoS prevention - buffer size is clamped
            let mut socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let stream = RecvStream::new(&mut socket, usize::MAX);
            // Buffer should be clamped to UDP_MAX_PACKET_SIZE, not usize::MAX
            assert_eq!(stream.buf.len(), UDP_MAX_PACKET_SIZE);

            let stream_small = RecvStream::new(&mut socket, 0);
            // Buffer should be at least 1 byte
            assert_eq!(stream_small.buf.len(), 1);

            let stream_normal = RecvStream::new(&mut socket, 512);
            // Normal size should pass through unchanged
            assert_eq!(stream_normal.buf.len(), 512);
        });
    }
}
