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
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
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
pub const UDP_MAX_BATCH_SIZE: usize = 1000;

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
        Self {
            native_send_batch: false,
            native_recv_batch: false,
            portable_send_batch: true,
            portable_recv_batch: true,
            default_fallback_batch: 32,
        }
    }
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

/// A UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    registration: Option<IoRegistration>,
    inner: Arc<StdUdpSocket>,
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
        #[cfg(target_arch = "wasm32")]
        {
            let _ = packets;
            browser_udp_unsupported_result("UdpSocket::send_batch_to")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut report = UdpBatchIoReport {
                fallback_used: packets.len() > 1,
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
    }

    /// Receive one readiness-driven packet, then drain any immediately-ready packets.
    pub async fn recv_batch_from(
        &mut self,
        max_packets: usize,
        packet_size: usize,
    ) -> io::Result<UdpRecvBatch> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (max_packets, packet_size);
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

            let mut first = vec![0u8; packet_size];
            let (bytes_read, src_addr) = self.recv_from(&mut first).await?;
            first.truncate(bytes_read);

            let mut batch = UdpRecvBatch {
                packets: vec![UdpInboundDatagram {
                    src_addr,
                    payload: first,
                    possibly_truncated: bytes_read == packet_size,
                }],
                report: UdpBatchIoReport {
                    packets_processed: 1,
                    bytes_processed: bytes_read,
                    fallback_used: max_packets > 1,
                    error: None,
                },
            };

            for _ in 1..max_packets {
                if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                    batch.report.error = Some("cancelled".to_string());
                    break;
                }

                let mut buf = vec![0u8; packet_size];
                match self.inner.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        buf.truncate(n);
                        batch.report.packets_processed += 1;
                        batch.report.bytes_processed += n;
                        batch.packets.push(UdpInboundDatagram {
                            src_addr: addr,
                            payload: buf,
                            possibly_truncated: n == packet_size,
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => {
                        batch.report.error = Some(err.to_string());
                        break;
                    }
                }
            }

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
            assert!(!capabilities.batching.native_send_batch);
            assert!(!capabilities.batching.native_recv_batch);
        });
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
            let sent = sender.send_batch_to(&packets).await.unwrap();
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
            RegionId::new_for_test(0, 0),
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
