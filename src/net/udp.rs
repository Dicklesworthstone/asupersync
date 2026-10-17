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
#[cfg(not(target_arch = "wasm32"))]
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
#[cfg(not(target_arch = "wasm32"))]
use crate::runtime::reactor::create_reactor;
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
#[cfg(not(target_arch = "wasm32"))]
use std::sync::OnceLock;
use std::task::{Context, Poll};

/// Linux launch-time sends and error-queue reads (GH #73).
#[cfg(target_os = "linux")]
mod txtime;
#[cfg(target_os = "linux")]
pub use txtime::{
    UdpErrorOrigin, UdpErrorReport, UdpTxTimeClock, UdpTxTimeConfig, UdpTxTimeError,
    UdpTxTimeErrorKind,
};

#[cfg(windows)]
#[allow(unsafe_code)]
fn suppress_windows_udp_connection_reset(socket: &StdUdpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, SOCKET_ERROR, WSAIoctl};

    let report_connection_reset: windows_sys::core::BOOL = 0;
    let mut bytes_returned = 0_u32;
    let raw_socket = usize::try_from(socket.as_raw_socket()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "raw socket handle does not fit the Windows SOCKET type",
        )
    })?;
    // SAFETY: The socket handle is live for the call, the input points to a
    // correctly sized BOOL, and this synchronous ioctl uses no output or
    // overlapped buffers. Disabling SIO_UDP_CONNRESET keeps an ICMP error from
    // terminating a reusable unconnected ATP receiver socket.
    let result = unsafe {
        WSAIoctl(
            raw_socket,
            SIO_UDP_CONNRESET,
            std::ptr::from_ref(&report_connection_reset).cast(),
            u32::try_from(std::mem::size_of_val(&report_connection_reset))
                .expect("BOOL size fits in u32"),
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
// The native socket-setup path needs no Windows-specific control on other OSes; wasm
// never opens raw UDP sockets, matching this file's wasm precedent.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
fn suppress_windows_udp_connection_reset(_socket: &StdUdpSocket) -> io::Result<()> {
    Ok(())
}

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
///
/// A super-packet is also limited to `UDP_GSO_MAX_SUPER_PACKET_BYTES` of
/// payload, so full-size segments fit fewer than this many.
pub const UDP_MAX_GSO_SEGMENTS: usize = 64;
/// Largest payload the planner puts in one UDP GSO super-packet.
///
/// The kernel refuses a UDP send whose payload exceeds one IP datagram with
/// `EMSGSIZE`, GSO included: 65,535 bytes less the 20-byte IPv4 header and the
/// 8-byte UDP header. IPv6 allows 20 bytes more; the planner uses the smaller
/// limit for both.
const UDP_GSO_MAX_SUPER_PACKET_BYTES: usize = 65_507;
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

#[inline]
const fn build_supports_native_sendmmsg() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    ))
}

#[inline]
const fn build_supports_udp_gso() -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
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
        Self::for_target_support(build_supports_native_sendmmsg())
    }
}

impl UdpBatchCapabilities {
    const fn for_target_support(native_send_batch: bool) -> Self {
        Self {
            native_send_batch,
            native_recv_batch: false,
            portable_send_batch: true,
            portable_recv_batch: true,
            default_fallback_batch: 32,
        }
    }

    /// Return batching capabilities exposed by this build target.
    #[inline]
    #[must_use]
    pub const fn for_platform(platform: UdpPlatform) -> Self {
        Self::for_target_support(matches!(platform, UdpPlatform::Linux))
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
        Self::for_target_support(build_supports_native_sendmmsg(), build_supports_udp_gso())
    }
}

impl UdpSendAccelerationCapabilities {
    const fn for_target_support(sendmmsg: bool, gso: bool) -> Self {
        Self {
            sendmmsg: if sendmmsg {
                UdpCapability::Supported
            } else {
                UdpCapability::Unsupported
            },
            gso: if gso {
                UdpCapability::Supported
            } else {
                UdpCapability::Unsupported
            },
            max_sendmmsg_batch: UDP_MAX_SENDMMSG_BATCH,
            max_gso_segments: UDP_MAX_GSO_SEGMENTS,
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
                .filter(|&bytes| gso_segments_within_datagram_limit(bytes) >= 2)
        } else {
            None
        };

        if let Some(gso_segment_bytes) = gso_segment_bytes {
            let segments_per_packet = datagrams
                .min(max_gso_segments)
                .min(gso_segments_within_datagram_limit(gso_segment_bytes));
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
                .filter(|&bytes| gso_segments_within_datagram_limit(bytes) >= 2)
        } else {
            None
        };

        if let Some(gso_segment_bytes) = gso_segment_bytes {
            let segments_per_packet = datagrams
                .min(max_gso_segments)
                .min(gso_segments_within_datagram_limit(gso_segment_bytes));
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

/// Segments of `segment_bytes` that fit in one GSO super-packet. The planner
/// does not use GSO when fewer than two fit.
#[inline]
#[must_use]
fn gso_segments_within_datagram_limit(segment_bytes: usize) -> usize {
    UDP_GSO_MAX_SUPER_PACKET_BYTES / segment_bytes.max(1)
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
// `Sent` and `WouldBlock` are only constructed on targets with a native
// sendmmsg/GSO batch path; on other Unix targets (e.g. macOS) the batch send
// falls back to `Unavailable`, so those variants are unconstructed there.
// Without this the crate-level `deny(dead_code)` (non-Windows) turns that into
// a hard error and breaks the apple-darwin build. Matches the existing
// `cfg_attr(target_arch = "wasm32", allow(dead_code))` precedent in this file.
#[cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    )),
    allow(dead_code)
)]
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

/// Whether a refused GSO send means GSO cannot work on this socket: a kernel
/// without `UDP_SEGMENT`, a device without checksum offload, or a segment the
/// path refuses. Any other error, such as `ECONNREFUSED` left by an earlier
/// ICMP error on a connected socket, concerns that one send. The batch then
/// falls back for that send only and GSO stays enabled.
#[cfg(all(
    not(target_arch = "wasm32"),
    any(target_os = "linux", target_os = "android")
))]
#[inline]
#[must_use]
fn gso_send_error_disables_gso(error: nix::errno::Errno) -> bool {
    matches!(
        error,
        nix::errno::Errno::EINVAL
            | nix::errno::Errno::EIO
            | nix::errno::Errno::EMSGSIZE
            | nix::errno::Errno::EOPNOTSUPP
            | nix::errno::Errno::ENOPROTOOPT
    )
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
#[inline]
fn is_wsaemsgsize(err: &io::Error) -> bool {
    #[cfg(windows)]
    {
        err.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE)
    }
    #[cfg(not(windows))]
    {
        let _ = err;
        false
    }
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
    if buf.capacity() <= UDP_MAX_PACKET_SIZE.saturating_add(1) {
        spare_payloads.push(buf);
    }
}

/// Whether a `connect(2)` failure means the UDP socket is already connected
/// to another peer (`EISCONN`).
///
/// The BSD refusal that [`UdpSocket::connect`] resolves by dissolving the
/// association first.
#[cfg(all(unix, not(target_arch = "wasm32")))]
fn udp_already_connected(err: &io::Error) -> bool {
    err.raw_os_error() == Some(nix::errno::Errno::EISCONN as i32)
}

/// Windows replaces the peer of a connected UDP socket directly; there is no
/// `EISCONN` to translate.
#[cfg(all(not(unix), not(target_arch = "wasm32")))]
fn udp_already_connected(_err: &io::Error) -> bool {
    false
}

/// Dissolve a connected UDP socket's peer association.
///
/// Connects to the null address of the same family as `next_peer`
/// (unspecified address, port 0). BSD documents this as the way to
/// disconnect a datagram socket and may "harmlessly" answer `EAFNOSUPPORT`;
/// such a benign refusal is treated as success and the caller's real
/// re-connect decides the outcome.
#[cfg(not(target_arch = "wasm32"))]
fn dissolve_udp_association(socket: &StdUdpSocket, next_peer: SocketAddr) -> io::Result<()> {
    let null_address = if next_peer.is_ipv4() {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    };
    match socket.connect(null_address) {
        Ok(()) => Ok(()),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::Unsupported
                    | io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::InvalidInput
            ) =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Process-global fallback I/O driver for sockets polled with no ambient
/// reactor (GH#67 / asupersync-t64ggs).
///
/// `UdpSocket`'s low-level polling API selects its reactor from the current
/// `Cx`. The documented caller-driven composition — a plain executor such as
/// `futures_lite::block_on` plus an explicit capability context, no runtime
/// turning a reactor — therefore reaches `register_interest` with no I/O
/// driver at all. That path used to fall back to an immediate self-wake
/// (`fallback_rewake` without a timer driver), so a bounded receive wait such
/// as `NativeQuicUdpConnection::drive_io_once` re-polled the socket in a hot
/// loop and burned a full core until its timeout fired.
///
/// This shared driver mirrors the process-global fallback timer in
/// `time::sleep` (br-asupersync-runtime-cpu-overhaul-5vt09v.3.5): ONE
/// process-lifetime pump thread owns a standard reactor, sockets without an
/// ambient driver register their readiness interest here, and the pump blocks
/// in the reactor until an fd becomes ready and wakes the registered waker.
/// A `block_on` caller then parks on its own waker for the whole wait instead
/// of spinning. The pump is started lazily on the first driverless registration
/// and never joined; `IoDriverHandle::register`/`IoRegistration::rearm` wake
/// the reactor before every mutation, so registrations made while the pump is
/// blocked take effect immediately.
///
/// A socket parked here migrates back to the ambient driver as soon as it is
/// polled under a `Cx` that carries one (see `register_interest`), so the
/// fallback never captures a socket that a runtime later adopts.
#[cfg(not(target_arch = "wasm32"))]
struct GlobalFallbackIoDriver {
    driver: IoDriverHandle,
}

#[cfg(not(target_arch = "wasm32"))]
static GLOBAL_FALLBACK_IO: OnceLock<GlobalFallbackIoDriver> = OnceLock::new();

/// Failed attempts to start the fallback driver. A failure is retried rather
/// than remembered for the life of the process: a transient one at the first
/// driverless poll (`EMFILE` creating the reactor, `EAGAIN` spawning the
/// pump) left every driverless socket on the self-wake hot loop for good
/// (br-asupersync-reactor-audit-dofi11 LOW 4). Retries are spaced by calls,
/// doubling up to [`FALLBACK_IO_MAX_RETRY_SPACING`], so a target without a
/// reactor backend pays one attempt per that many polls.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Default)]
struct FallbackIoStart {
    failures: u32,
    calls_since_failure: u64,
}

#[cfg(not(target_arch = "wasm32"))]
const FALLBACK_IO_MAX_RETRY_SPACING: u64 = 4096;

#[cfg(not(target_arch = "wasm32"))]
impl FallbackIoStart {
    /// Whether this call may try to start the driver again.
    fn attempt_due(&mut self) -> bool {
        if self.failures == 0 {
            return true;
        }
        self.calls_since_failure = self.calls_since_failure.saturating_add(1);
        let spacing = 1_u64
            .checked_shl(self.failures)
            .map_or(FALLBACK_IO_MAX_RETRY_SPACING, |spacing| {
                spacing.min(FALLBACK_IO_MAX_RETRY_SPACING)
            });
        self.calls_since_failure >= spacing
    }

    fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.calls_since_failure = 0;
    }
}

#[cfg(not(target_arch = "wasm32"))]
static FALLBACK_IO_START: FallbackIoStarter = FallbackIoStarter::new();

/// The start state of a fallback driver cell, plus a lock-free verdict for a
/// target with no reactor backend at all.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct FallbackIoStarter {
    /// Set when a start failed with `Unsupported` (no backend, or the
    /// syscall is missing): no later start can succeed, so callers return
    /// `None` without taking the lock or counting.
    unsupported: std::sync::atomic::AtomicBool,
    state: parking_lot::Mutex<FallbackIoStart>,
}

#[cfg(not(target_arch = "wasm32"))]
impl FallbackIoStarter {
    const fn new() -> Self {
        Self {
            unsupported: std::sync::atomic::AtomicBool::new(false),
            state: parking_lot::Mutex::new(FallbackIoStart {
                failures: 0,
                calls_since_failure: 0,
            }),
        }
    }
}

/// Park applied by the fallback pump after a reactor error other than `EINTR`
/// so a persistently failing backend cannot turn the pump into a hot loop.
#[cfg(not(target_arch = "wasm32"))]
const FALLBACK_IO_PUMP_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

/// Returns the process-global fallback I/O driver, starting its pump thread on
/// first use. `None` when no reactor backend could be created on this target
/// (or the pump thread could not be spawned); callers then keep the legacy
/// self-wake path so progress is still made, and a later call tries to start
/// the driver again ([`FallbackIoStart`]).
#[cfg(not(target_arch = "wasm32"))]
fn global_fallback_io_driver() -> Option<&'static IoDriverHandle> {
    fallback_io_driver_from(
        &GLOBAL_FALLBACK_IO,
        &FALLBACK_IO_START,
        start_global_fallback_io,
    )
}

/// [`global_fallback_io_driver`] over the given cell, start state and
/// starter, which a test can replace.
#[cfg(not(target_arch = "wasm32"))]
fn fallback_io_driver_from(
    cell: &'static OnceLock<GlobalFallbackIoDriver>,
    starter_state: &FallbackIoStarter,
    starter: impl FnOnce() -> io::Result<GlobalFallbackIoDriver>,
) -> Option<&'static IoDriverHandle> {
    if let Some(global) = cell.get() {
        return Some(&global.driver);
    }
    if starter_state
        .unsupported
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return None;
    }
    let mut start = starter_state.state.lock();
    // Another caller may have started it while this one waited for the lock.
    if let Some(global) = cell.get() {
        return Some(&global.driver);
    }
    if !start.attempt_due() {
        return None;
    }
    match starter() {
        Ok(global) => Some(&cell.get_or_init(|| global).driver),
        Err(err) => {
            if start.failures == 0 {
                crate::tracing_compat::warn!(
                    target: "asupersync::net::udp",
                    error = %err,
                    "GH#67: the process-global fallback I/O driver did not start (no reactor \
                     backend, or no pump thread); driverless UDP polls keep the immediate \
                     self-wake path, and the start is retried unless it is unsupported here"
                );
            }
            if err.kind() == io::ErrorKind::Unsupported {
                starter_state
                    .unsupported
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            start.record_failure();
            None
        }
    }
}

/// Creates the fallback driver's reactor and spawns its pump thread.
#[cfg(not(target_arch = "wasm32"))]
fn start_global_fallback_io() -> io::Result<GlobalFallbackIoDriver> {
    let reactor = create_reactor()?;
    let driver = IoDriverHandle::new(reactor);
    let pump_driver = driver.clone();
    // ubs:ignore - intentional process-lifetime daemon reactor pump shared by all driverless UDP polls
    match std::thread::Builder::new()
        .name("asupersync-fallback-io".to_string())
        .spawn(move || fallback_io_pump_loop(&pump_driver))
    {
        Ok(_handle) => Ok(GlobalFallbackIoDriver { driver }),
        Err(err) => Err(io::Error::new(
            err.kind(),
            format!("spawning the fallback I/O pump thread: {err}"),
        )),
    }
}

/// The shared fallback pump loop: block in the reactor until at least one
/// registered fd is ready (or a registration mutation wakes the reactor), fire
/// the ready wakers, repeat. With no registrations the reactor wait is
/// indefinite, so an idle pump costs nothing.
#[cfg(not(target_arch = "wasm32"))]
fn fallback_io_pump_loop(driver: &IoDriverHandle) -> ! {
    loop {
        // A panic inside a reactor turn must not silently end the only thread
        // that wakes driverless sockets (every such socket would park forever
        // with no self-wake fallback): report it, back off, and keep pumping.
        let turned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            driver.turn_with(None, |_, _| {})
        }));
        match turned {
            Ok(Ok(_)) => {}
            Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => {}
            Ok(Err(_)) => std::thread::park_timeout(FALLBACK_IO_PUMP_ERROR_BACKOFF),
            Err(_panic) => {
                crate::tracing_compat::warn!(
                    target: "asupersync::net::udp",
                    "GH#67: the fallback I/O pump caught a panic in a reactor turn; continuing"
                );
                std::thread::park_timeout(FALLBACK_IO_PUMP_ERROR_BACKOFF);
            }
        }
    }
}

/// Socket-side counters for the fallback I/O driver so a test can prove
/// whether a driverless socket asked to be parked and whether the pump
/// dispatched its wake (GH#67 follow-up, asupersync-t64ggs). Compiled only
/// for tests and `test-internals`; production builds carry no counters.
#[cfg(all(not(target_arch = "wasm32"), any(test, feature = "test-internals")))]
mod fallback_io_probe {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Registrations accepted by the fallback driver.
    pub(super) static REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
    /// Re-arms of a registration living on the fallback driver (one per
    /// `Pending` poll of such a socket).
    pub(super) static REARMS: AtomicU64 = AtomicU64::new(0);
    /// Fallback registrations dropped because an ambient driver appeared.
    pub(super) static MIGRATIONS: AtomicU64 = AtomicU64::new(0);
    /// Legacy immediate self-wakes taken instead of parking.
    pub(super) static SELF_WAKES: AtomicU64 = AtomicU64::new(0);

    pub(super) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn bump_if(condition: bool, counter: &AtomicU64) {
        if condition {
            bump(counter);
        }
    }

    pub(super) fn load(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Snapshot of the process-global fallback I/O driver (GH#67).
///
/// The pump's reactor statistics plus the socket-side counters from
/// `fallback_io_probe`. Tests use it to tell "no datagram reached the
/// socket" from "the socket was never re-polled after its wake".
#[cfg(all(not(target_arch = "wasm32"), any(test, feature = "test-internals")))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FallbackIoDriverProbe {
    /// Reactor turns completed by the pump thread.
    pub polls: u64,
    /// Readiness events the reactor reported to the pump.
    pub events_received: u64,
    /// Wakers the pump fired for those events.
    pub wakers_dispatched: u64,
    /// Events whose token no longer had a waker.
    pub unknown_tokens: u64,
    /// Waker registrations the driver has accepted.
    pub registrations: u64,
    /// Waker deregistrations.
    pub deregistrations: u64,
    /// Sockets that registered on the fallback driver (socket-side count).
    pub fallback_registrations: u64,
    /// Re-arms of fallback registrations (one per `Pending` poll).
    pub fallback_rearms: u64,
    /// Fallback registrations dropped in favour of an ambient driver.
    pub fallback_migrations: u64,
    /// Legacy immediate self-wakes taken instead of parking.
    pub fallback_self_wakes: u64,
}

/// Returns a snapshot of the fallback I/O driver's counters.
///
/// `None` when the driver was never started (no driverless socket poll
/// happened yet) or could not be created. Never starts the driver as a side
/// effect.
#[cfg(all(not(target_arch = "wasm32"), any(test, feature = "test-internals")))]
#[must_use]
pub fn fallback_io_driver_probe() -> Option<FallbackIoDriverProbe> {
    let driver = &GLOBAL_FALLBACK_IO.get()?.driver;
    let stats = driver.stats();
    Some(FallbackIoDriverProbe {
        polls: stats.polls,
        events_received: stats.events_received,
        wakers_dispatched: stats.wakers_dispatched,
        unknown_tokens: stats.unknown_tokens,
        registrations: stats.registrations,
        deregistrations: stats.deregistrations,
        fallback_registrations: fallback_io_probe::load(&fallback_io_probe::REGISTRATIONS),
        fallback_rearms: fallback_io_probe::load(&fallback_io_probe::REARMS),
        fallback_migrations: fallback_io_probe::load(&fallback_io_probe::MIGRATIONS),
        fallback_self_wakes: fallback_io_probe::load(&fallback_io_probe::SELF_WAKES),
    })
}

/// A socket's reactor registration, aware of the process-global fallback I/O
/// driver (GH#67, asupersync-tx9j0f).
///
/// Every socket that selects its reactor from the current `Cx` (UDP, TCP and
/// Unix sockets alike) keeps one of these instead of a bare
/// `Option<IoRegistration>`. [`arm`](Self::arm) is the single authoritative
/// implementation of the registration dance:
///
/// 1. a registration parked on the fallback driver is dropped as soon as the
///    socket is polled under a `Cx` that carries an ambient driver, so the
///    fallback never captures a socket that a runtime later adopts;
/// 2. an existing registration is re-armed in place (oneshot reactor
///    interest is re-armed per poll; the `will_wake` guard skips the clone).
///    The socket has one waiter, so a read wait and a write wait in the same
///    poll both stay armed until the next event
///    (`IoRegistration::rearm_accumulating`);
/// 3. otherwise the fd is registered on the ambient driver when present,
///    else on the fallback driver, and only when neither exists (or the
///    reactor refuses the fd) does the caller take the legacy self-wake.
#[derive(Debug, Default)]
pub struct ReactorRegistration {
    registration: Option<IoRegistration>,
    /// Whether `registration` lives on the process-global fallback driver
    /// rather than an ambient `Cx` driver. Such a registration is dropped and
    /// re-made on the ambient driver the next time the socket is polled under
    /// a `Cx` that carries one.
    on_fallback: bool,
    /// Waiters of the socket's `&self` methods, made on the first
    /// [`arm_shared`](Self::arm_shared).
    #[cfg(unix)]
    shared_waiters: Option<Arc<SharedWaiters>>,
}

/// Tasks parked in a socket's `&self` methods, which several tasks can call
/// at once (br-asupersync-unix-socket-audit-alx18f). The reactor holds one
/// waker per registration, so the registration is armed with this list
/// instead: a readiness event wakes every waiter, and each one re-polls and
/// re-arms if it is still blocked. The listeners' `AcceptWaiters` work the
/// same way.
#[cfg(unix)]
#[derive(Debug, Default)]
struct SharedWaiters {
    /// One entry per waiting call future, keyed by its owner id
    /// ([`next_shared_waiter_owner`]).
    waiters: parking_lot::Mutex<Vec<(u64, std::task::Waker)>>,
}

/// A fresh owner id for one call future's entry in a socket's shared waiter
/// list ([`ReactorRegistration::arm_shared`]).
#[cfg(unix)]
pub fn next_shared_waiter_owner() -> u64 {
    static NEXT_OWNER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT_OWNER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(unix)]
impl SharedWaiters {
    /// Stores `waker` as `owner`'s entry, replacing the waker it held. The
    /// call future that owns the entry removes it when dropped
    /// ([`Self::forget`]), so the list holds one entry per waiting call and
    /// nothing is evicted. A 32-entry cap that woke the evicted waiter made
    /// 33 or more waiting tasks wake each other forever
    /// (br-asupersync-reactor-audit-dofi11).
    ///
    /// Returns the waker it replaced, for the caller to drop after releasing
    /// its own locks: a waker can own the last reference to a task, and
    /// dropping that task can run code that takes them (br-asupersync-9kb866).
    fn register(&self, owner: u64, waker: &std::task::Waker) -> Option<std::task::Waker> {
        let mut waiters = self.waiters.lock();
        if let Some((_, existing)) = waiters.iter_mut().find(|(id, _)| *id == owner) {
            (!existing.will_wake(waker)).then(|| std::mem::replace(existing, waker.clone()))
        } else {
            waiters.push((owner, waker.clone()));
            None
        }
    }

    /// Removes `owner`'s entry, returning its waker for the caller to drop
    /// after releasing its own locks.
    fn forget(&self, owner: u64) -> Option<std::task::Waker> {
        let mut waiters = self.waiters.lock();
        let position = waiters.iter().position(|(id, _)| *id == owner)?;
        Some(waiters.swap_remove(position).1)
    }

    /// Removes every waiter and returns all but `current`'s.
    fn take_others(&self, current: u64) -> Vec<std::task::Waker> {
        let waiters = std::mem::take(&mut *self.waiters.lock());
        waiters
            .into_iter()
            .filter(|(id, _)| *id != current)
            .map(|(_, waker)| waker)
            .collect()
    }

    fn wake_all(&self) {
        let waiters = std::mem::take(&mut *self.waiters.lock());
        for (_, waiter) in waiters {
            waiter.wake();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.waiters.lock().len()
    }
}

#[cfg(unix)]
impl std::task::Wake for SharedWaiters {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

/// Outcome of [`ReactorRegistration::arm`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Armed {
    /// The fd is registered with a reactor that wakes the waker on readiness;
    /// the caller returns `Pending` without waking anything.
    Parked,
    /// No reactor could take the fd; the caller must schedule its own re-poll
    /// (`fallback_rewake`) so progress is still made.
    SelfWake,
}

impl ReactorRegistration {
    /// No registration yet (made lazily on the first `Pending` poll).
    pub(crate) const fn new() -> Self {
        Self {
            registration: None,
            on_fallback: false,
            #[cfg(unix)]
            shared_waiters: None,
        }
    }

    /// Adopts a registration handed over by another owner of the same fd (a
    /// completed connect). It is treated as living on an ambient driver: it is
    /// re-armed in place and never migrated. Only Unix stream sockets hand a
    /// registration over this way since TCP reunite moved to `from_parts`, so
    /// it is Unix-only (it was dead code that broke the wasm32 build).
    #[cfg(unix)]
    pub(crate) const fn from_registration(registration: Option<IoRegistration>) -> Self {
        Self {
            registration,
            on_fallback: false,
            #[cfg(unix)]
            shared_waiters: None,
        }
    }

    /// Adopts a registration and its fallback flag, as
    /// [`take_parts`](Self::take_parts) hands them over (split halves
    /// reuniting). A registration on the fallback driver still migrates to an
    /// ambient driver later. Through `from_registration` it stayed on the
    /// fallback driver for good (br-asupersync-8vrx8q).
    pub(crate) fn from_parts(parts: (Option<IoRegistration>, bool)) -> Self {
        let (registration, on_fallback) = parts;
        Self {
            registration,
            on_fallback,
            #[cfg(unix)]
            shared_waiters: None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn is_some(&self) -> bool {
        self.registration.is_some()
    }

    /// The live registration, for tests that inspect its interest.
    #[cfg(test)]
    pub(crate) const fn as_ref(&self) -> Option<&IoRegistration> {
        self.registration.as_ref()
    }

    #[cfg(test)]
    pub(crate) const fn is_none(&self) -> bool {
        self.registration.is_none()
    }

    /// Whether the live registration is parked on the fallback driver.
    #[cfg(test)]
    pub(crate) const fn on_fallback(&self) -> bool {
        self.on_fallback
    }

    /// Drops the registration (deregistering the fd from its reactor).
    pub(crate) fn clear(&mut self) {
        self.registration = None;
        self.on_fallback = false;
    }

    /// Arms readiness `interest` for `source` on behalf of `waker`; see the
    /// type docs for the three steps. `Ok(Armed::SelfWake)` means no reactor
    /// took the fd and the caller must re-poll on its own.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn arm(
        &mut self,
        source: &dyn crate::runtime::reactor::Source,
        interest: Interest,
        waker: &std::task::Waker,
    ) -> io::Result<Armed> {
        // Step 1: migrate a fallback registration to a newly present ambient
        // driver. Dropping it deregisters the fd from the fallback reactor
        // before the ambient one registers it.
        if self.on_fallback
            && Cx::current()
                .and_then(|current| current.io_driver_handle())
                .is_some()
        {
            #[cfg(any(test, feature = "test-internals"))]
            fallback_io_probe::bump(&fallback_io_probe::MIGRATIONS);
            self.clear();
        }

        // Step 2: re-arm in place.
        if let Some(registration) = &mut self.registration {
            #[cfg(any(test, feature = "test-internals"))]
            fallback_io_probe::bump_if(self.on_fallback, &fallback_io_probe::REARMS);
            match registration.rearm_accumulating(interest, waker) {
                Ok(true) => return Ok(Armed::Parked),
                // Slab slot gone: fall through to a fresh registration.
                Ok(false) => self.clear(),
                Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                    self.clear();
                    #[cfg(any(test, feature = "test-internals"))]
                    fallback_io_probe::bump(&fallback_io_probe::SELF_WAKES);
                    return Ok(Armed::SelfWake);
                }
                Err(err) => return Err(err),
            }
        }

        // Step 3: fresh registration on the ambient driver, else the fallback.
        match fresh_reactor_registration(source, interest, waker.clone())? {
            FreshRegistration::Registered {
                registration,
                on_fallback,
            } => {
                self.registration = Some(registration);
                self.on_fallback = on_fallback;
                Ok(Armed::Parked)
            }
            FreshRegistration::SelfWake => Ok(Armed::SelfWake),
        }
    }

    /// Like [`arm`](Self::arm), for a `&self` socket method that several
    /// tasks can wait in at once (br-asupersync-unix-socket-audit-alx18f).
    /// `waker` joins the shared waiter list and the registration is armed
    /// with the list, so arming for one caller never drops another caller's
    /// wakeup. When no reactor will deliver a wake (`SelfWake` or an error),
    /// the other listed waiters are returned: the caller wakes them after
    /// releasing the lock that guards `self`, so each re-polls on its own.
    ///
    /// `owner` ([`next_shared_waiter_owner`]) names the calling future's one
    /// entry in the list; the future removes it with
    /// [`forget_shared`](Self::forget_shared) when dropped. The third value
    /// is the waker that entry held before, if this call replaced it; the
    /// caller drops it after releasing the lock that guards `self`.
    #[cfg(unix)]
    pub(crate) fn arm_shared(
        &mut self,
        source: &dyn crate::runtime::reactor::Source,
        interest: Interest,
        owner: u64,
        waker: &std::task::Waker,
    ) -> (
        io::Result<Armed>,
        Vec<std::task::Waker>,
        Option<std::task::Waker>,
    ) {
        let waiters = Arc::clone(self.shared_waiters.get_or_insert_with(Default::default));
        let displaced = waiters.register(owner, waker);
        let dispatch = std::task::Waker::from(Arc::clone(&waiters));
        let armed = self.arm(source, interest, &dispatch);
        let stranded = if matches!(armed, Ok(Armed::Parked)) {
            Vec::new()
        } else {
            waiters.take_others(owner)
        };
        (armed, stranded, displaced)
    }

    /// Removes `owner`'s entry from the shared waiter list, returning its
    /// waker for the caller to drop after releasing the lock guarding `self`.
    #[cfg(unix)]
    pub(crate) fn forget_shared(&self, owner: u64) -> Option<std::task::Waker> {
        self.shared_waiters
            .as_ref()
            .and_then(|waiters| waiters.forget(owner))
    }

    /// How many call futures are listed as shared waiters.
    #[cfg(all(unix, test))]
    pub(crate) fn shared_waiter_count(&self) -> usize {
        self.shared_waiters.as_deref().map_or(0, SharedWaiters::len)
    }

    /// Hands the live registration and its fallback flag to another owner of
    /// the fd (owned split halves keep their own state), leaving this slot
    /// empty.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub fn take_parts(&mut self) -> (Option<IoRegistration>, bool) {
        let on_fallback = std::mem::replace(&mut self.on_fallback, false);
        (self.registration.take(), on_fallback)
    }
}

/// Outcome of [`fresh_reactor_registration`].
#[cfg(not(target_arch = "wasm32"))]
pub enum FreshRegistration {
    /// The fd is registered; `on_fallback` says whether it sits on the
    /// process-global fallback driver rather than an ambient `Cx` driver.
    Registered {
        registration: IoRegistration,
        on_fallback: bool,
    },
    /// No reactor could take the fd (no driver at all, or the reactor refused
    /// it); the caller must schedule its own re-poll.
    SelfWake,
}

/// Whether the current `Cx` carries an ambient I/O driver (the signal for a
/// fallback registration to migrate).
#[cfg(not(target_arch = "wasm32"))]
pub fn ambient_io_driver_present() -> bool {
    Cx::current()
        .and_then(|current| current.io_driver_handle())
        .is_some()
}

/// Test-only switch that makes the process-global fallback driver look absent
/// on the current thread, so a test can exercise the legacy self-wake path
/// (`FreshRegistration::SelfWake`) that production still takes when no reactor
/// backend can be started. Since GH#67 the fallback driver takes every fd in
/// an ordinary test process, which would otherwise leave that path untested.
/// Unit tests only: nothing outside this crate needs it, and compiling it into
/// a `test-internals` library build would leave it unconstructed (dead code).
/// Native tests only: the Cell hooks are not valid on wasm32.
#[cfg(all(not(target_arch = "wasm32"), test))]
pub(super) mod fallback_io_test_hooks {
    use std::cell::Cell;

    thread_local! {
        static WITHHOLD_FALLBACK_DRIVER: Cell<bool> = const { Cell::new(false) };
    }

    /// While alive, `fresh_reactor_registration` on this thread behaves as if
    /// no fallback driver could be started.
    ///
    /// Thread-bound (`!Send`, `!Sync`): `Drop` restores the flag of the thread
    /// that created the guard, so moving it elsewhere would leave that thread
    /// withholding forever and clobber an unrelated thread's flag instead.
    pub struct WithholdFallbackDriver {
        previous: bool,
        _thread_bound: std::marker::PhantomData<*mut ()>,
    }

    impl WithholdFallbackDriver {
        #[must_use]
        pub fn new() -> Self {
            let previous = WITHHOLD_FALLBACK_DRIVER.with(|flag| flag.replace(true));
            Self {
                previous,
                _thread_bound: std::marker::PhantomData,
            }
        }
    }

    impl Default for WithholdFallbackDriver {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for WithholdFallbackDriver {
        fn drop(&mut self) {
            WITHHOLD_FALLBACK_DRIVER.with(|flag| flag.set(self.previous));
        }
    }

    pub(super) fn withheld() -> bool {
        WITHHOLD_FALLBACK_DRIVER.with(Cell::get)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::marker::PhantomData;

        /// Autoref probe: `(&Probe::<T>(..)).is_send()` resolves to the
        /// `Send`-bounded impl when `T: Send`, else to the reference impl.
        struct Probe<T>(PhantomData<T>);
        trait SendProbe {
            fn is_send(&self) -> bool {
                true
            }
        }
        impl<T: Send> SendProbe for Probe<T> {}
        trait NotSendProbe {
            fn is_send(&self) -> bool {
                false
            }
        }
        impl<T> NotSendProbe for &Probe<T> {}

        #[test]
        fn withhold_guard_is_thread_bound_and_restores_only_its_thread() {
            // Keep the same explicit autoref expression as the negative
            // probe, so this control checks the same method-resolution path.
            #[allow(clippy::needless_borrow)]
            let send_control = (&Probe::<u8>(PhantomData)).is_send();
            assert!(send_control, "probe control");
            assert!(
                !(&Probe::<WithholdFallbackDriver>(PhantomData)).is_send(),
                "the guard restores thread-local state on drop and must not be Send"
            );

            assert!(!withheld());
            {
                let _outer = WithholdFallbackDriver::new();
                assert!(withheld());
                {
                    let _inner = WithholdFallbackDriver::new();
                    assert!(withheld());
                }
                assert!(withheld(), "inner drop restores the outer guard's state");
            }
            assert!(!withheld());
            let other = std::thread::spawn(|| {
                let _guard = WithholdFallbackDriver::new();
                withheld()
            })
            .join()
            .expect("probe thread");
            assert!(other);
            assert!(
                !withheld(),
                "another thread's guard never touches this thread"
            );
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), test))]
fn fallback_driver_withheld() -> bool {
    fallback_io_test_hooks::withheld()
}

#[cfg(all(not(target_arch = "wasm32"), not(test)))]
const fn fallback_driver_withheld() -> bool {
    false
}

/// Registers `source` on the ambient `Cx` driver when one is present, else on
/// the process-global fallback driver (GH#67), for callers that keep their own
/// registration state (owned split halves). Probe counters are bumped here so
/// every socket type reports through the same [`fallback_io_driver_probe`].
#[cfg(not(target_arch = "wasm32"))]
pub fn fresh_reactor_registration(
    source: &dyn crate::runtime::reactor::Source,
    interest: Interest,
    waker: std::task::Waker,
) -> io::Result<FreshRegistration> {
    let ambient = Cx::current().and_then(|current| current.io_driver_handle());
    let (driver, on_fallback): (&IoDriverHandle, bool) = match &ambient {
        Some(driver) => (driver, false),
        None => match global_fallback_io_driver().filter(|_| !fallback_driver_withheld()) {
            Some(driver) => (driver, true),
            None => {
                #[cfg(any(test, feature = "test-internals"))]
                fallback_io_probe::bump(&fallback_io_probe::SELF_WAKES);
                return Ok(FreshRegistration::SelfWake);
            }
        },
    };
    match driver.register(source, interest, waker) {
        Ok(registration) => {
            #[cfg(any(test, feature = "test-internals"))]
            fallback_io_probe::bump_if(on_fallback, &fallback_io_probe::REGISTRATIONS);
            Ok(FreshRegistration::Registered {
                registration,
                on_fallback,
            })
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::Unsupported | io::ErrorKind::NotConnected
            ) =>
        {
            #[cfg(any(test, feature = "test-internals"))]
            fallback_io_probe::bump(&fallback_io_probe::SELF_WAKES);
            Ok(FreshRegistration::SelfWake)
        }
        Err(err) => Err(err),
    }
}

/// Test support shared by the driverless-poll tests of every socket type: a
/// waker that counts wakes and signals a channel, so a test can wait (bounded)
/// for the wake the fallback reactor pump delivers.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub mod fallback_io_test_support {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Arc, Mutex};
    use std::task::{Wake, Waker};

    pub struct SignalWaker {
        pub hits: AtomicUsize,
        tx: Mutex<Sender<()>>,
    }

    impl Wake for SignalWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.hits.fetch_add(1, Ordering::SeqCst);
            let _ = self
                .tx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .send(());
        }
    }

    pub fn signal_waker() -> (Arc<SignalWaker>, Waker, Receiver<()>) {
        let (tx, rx) = channel();
        let signal = Arc::new(SignalWaker {
            hits: AtomicUsize::new(0),
            tx: Mutex::new(tx),
        });
        let waker = Waker::from(Arc::clone(&signal));
        (signal, waker, rx)
    }
}

/// A UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    /// Reactor registration, fallback-driver aware (GH#67).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    registration: ReactorRegistration,
    inner: Arc<StdUdpSocket>,
    gso_demoted: bool,
    /// `SO_TXTIME` set through this handle: plain sends are refused (GH #73).
    #[cfg(target_os = "linux")]
    txtime: Option<UdpTxTimeConfig>,
    /// `IP_RECVERR` / `IPV6_RECVERR` set through this handle.
    #[cfg(target_os = "linux")]
    recverr: std::sync::atomic::AtomicBool,
}

impl UdpSocket {
    /// Bind to the given address.
    ///
    /// Refuses with [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied)
    /// when the calling task's `Cx` lacks the IO capability. `connect` and
    /// `send_to` refuse the same way, through address resolution.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = addr;
            browser_udp_unsupported_result("UdpSocket::bind")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::cx::io_gate::require_ambient_io("net::UdpSocket::bind")?;
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
                        suppress_windows_udp_connection_reset(&socket)?;
                        socket.set_nonblocking(true)?;
                        return Ok(Self {
                            inner: Arc::new(socket),
                            registration: ReactorRegistration::new(),
                            gso_demoted: false,
                            #[cfg(target_os = "linux")]
                            txtime: None,
                            #[cfg(target_os = "linux")]
                            recverr: std::sync::atomic::AtomicBool::new(false),
                        });
                    }
                    Err(err) => last_err = Some(err),
                }
            }

            Err(last_err.unwrap_or_else(|| io::Error::other("failed to bind any address")))
        }
    }

    /// Connect to a remote address (for send/recv).
    ///
    /// Re-connecting an already-connected socket to a different peer is
    /// supported on every platform: Linux and Windows replace the peer
    /// directly, and on BSD-derived stacks (macOS, iOS, FreeBSD), which
    /// answer `EISCONN`, the existing association is dissolved first by
    /// connecting to the null address of the same family (the documented BSD
    /// idiom) and the connect is retried once.
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
                    Err(err) if udp_already_connected(&err) => {
                        // BSD-derived stacks (macOS, iOS, FreeBSD) refuse to
                        // re-target a connected UDP socket with EISCONN
                        // where Linux and Windows simply replace the peer.
                        // Dissolve the association first, then re-connect
                        // (br-asupersync-bi2462.21.2).
                        dissolve_udp_association(&self.inner, addr)?;
                        match self.inner.connect(addr) {
                            Ok(()) => return Ok(()),
                            Err(err) => last_err = Some(err),
                        }
                    }
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
            if let Err(err) = self.ensure_plain_send_allowed() {
                return Poll::Ready(Err(err));
            }
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
            if let Err(err) = self.ensure_plain_send_allowed() {
                return Poll::Ready(Err(err));
            }
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
                // IPV6_V6ONLY off means the socket also carries IPv4 traffic.
                UdpAddressFamily::Ipv6 => match sock.only_v6() {
                    Ok(false) => UdpCapability::Supported,
                    Ok(true) => UdpCapability::Unsupported,
                    Err(_) => UdpCapability::Unknown,
                },
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
            self.ensure_plain_send_allowed()?;
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

    /// Poll one bounded send batch, returning every committed send before waiting.
    ///
    /// Unlike the all-packets async helper, this may return a successful prefix
    /// without an error. Its caller owns and retries the unsent suffix. No
    /// datagram has been sent when this returns Pending.
    // Native-only callers (the QUIC endpoint); wasm32 explicitly returns Unsupported.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn poll_send_batch_to_with_strategy(
        &mut self,
        cx: &Context<'_>,
        packets: &[UdpOutboundDatagram<'_>],
        strategy: UdpSendBatchStrategy,
    ) -> Poll<io::Result<UdpBatchIoReport>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (cx, packets, strategy);
            browser_udp_poll_unsupported("UdpSocket::poll_send_batch_to_with_strategy")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Err(err) = self.ensure_plain_send_allowed() {
                return Poll::Ready(Err(err));
            }
            if packets.len() > UDP_MAX_BATCH_SIZE {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP send batch exceeds UDP_MAX_BATCH_SIZE",
                )));
            }
            match self.try_send_batch_to_native(packets, strategy.clamped())? {
                NativeSendBatchAttempt::Sent(report) => return Poll::Ready(Ok(report)),
                NativeSendBatchAttempt::WouldBlock => {
                    self.register_interest(cx, Interest::WRITABLE)?;
                    return Poll::Pending;
                }
                NativeSendBatchAttempt::Unavailable => {}
            }
            let mut report = UdpBatchIoReport {
                fallback_used: packets.len() > 1,
                ..UdpBatchIoReport::default()
            };
            let connected_peer = self.inner.peer_addr().ok();
            for packet in packets {
                let result = if connected_peer == Some(packet.dst_addr) {
                    self.inner.send(packet.payload)
                } else {
                    self.inner.send_to(packet.payload, packet.dst_addr)
                };
                match result {
                    Ok(bytes) => {
                        report.packets_processed += 1;
                        report.bytes_processed += bytes;
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        if report.packets_processed > 0 {
                            return Poll::Ready(Ok(report));
                        }
                        self.register_interest(cx, Interest::WRITABLE)?;
                        return Poll::Pending;
                    }
                    Err(err) if report.packets_processed == 0 => {
                        return Poll::Ready(Err(err));
                    }
                    // Report the committed prefix first. The next poll of the
                    // unchanged tail retains the concrete I/O error kind.
                    Err(_) => break,
                }
            }
            Poll::Ready(Ok(report))
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
            self.ensure_plain_send_allowed()?;
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

        // BSD stacks (macOS) refuse `sendto` with an explicit destination on
        // a connected UDP socket (EISCONN); Linux accepts it. Send to the
        // connected peer without an address (br-asupersync-bi2462.21.2).
        let connected_peer = self.inner.peer_addr().ok();
        for packet in packets {
            let outcome = if connected_peer == Some(packet.dst_addr) {
                self.send(packet.payload).await
            } else {
                self.send_to(packet.payload, packet.dst_addr).await
            };
            match outcome {
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
                    // The attempt demoted GSO itself if the error showed GSO
                    // cannot work here; either way this batch falls back.
                    NativeSendBatchAttempt::Unavailable => {}
                }
            }
        }

        if !strategy.prefer_sendmmsg
            || !matches!(
                self.send_acceleration_capabilities().sendmmsg,
                UdpCapability::Supported
            )
        {
            return Ok(NativeSendBatchAttempt::Unavailable);
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
                    // The attempt demoted GSO itself if the error showed GSO
                    // cannot work here; either way this batch falls back.
                    NativeSendBatchAttempt::Unavailable => {}
                }
            }
        }

        if !strategy.prefer_sendmmsg
            || !matches!(
                self.send_acceleration_capabilities().sendmmsg,
                UdpCapability::Supported
            )
        {
            return Ok(NativeSendBatchAttempt::Unavailable);
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
                Err(err) if report.packets_processed == 0 => {
                    if gso_send_error_disables_gso(err) {
                        self.gso_demoted = true;
                    }
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
                Err(err) if report.packets_processed == 0 => {
                    if gso_send_error_disables_gso(err) {
                        self.gso_demoted = true;
                    }
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
        std::future::poll_fn(|cx| {
            self.poll_recv_batch_from_reusing(cx, max_packets, packet_size, spare_payloads)
        })
        .await
    }

    /// Poll one receive batch without consuming any packet on Pending.
    pub(crate) fn poll_recv_batch_from_reusing(
        &mut self,
        cx: &Context<'_>,
        max_packets: usize,
        packet_size: usize,
        spare_payloads: &mut Vec<Vec<u8>>,
    ) -> Poll<io::Result<UdpRecvBatch>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (cx, max_packets, packet_size, spare_payloads);
            browser_udp_poll_unsupported("UdpSocket::recv_batch_from")
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if max_packets == 0 {
                return Poll::Ready(Ok(UdpRecvBatch::default()));
            }
            if packet_size == 0 {
                return Poll::Ready(Err(empty_udp_receive_buffer_error("recv_batch_from")));
            }

            // Prevent DoS via unbounded memory allocation (asupersync-z30chg)
            if max_packets > UDP_MAX_BATCH_SIZE {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "max_packets ({}) exceeds UDP_MAX_BATCH_SIZE ({})",
                        max_packets, UDP_MAX_BATCH_SIZE
                    ),
                )));
            }
            if packet_size > UDP_MAX_PACKET_SIZE {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "packet_size ({}) exceeds UDP_MAX_PACKET_SIZE ({})",
                        packet_size, UDP_MAX_PACKET_SIZE
                    ),
                )));
            }

            // One reusable scratch buffer serves every receive in the batch;
            // each datagram is copied out into an exactly-sized payload Vec.
            // Sizing scratch with a guard byte (`packet_size + 1`) allows unambiguous
            // detection of truncated datagrams (`bytes_read > packet_size`) while
            // avoiding false positives for exact MTU-sized packets (`bytes_read == packet_size`).
            let guard_size = packet_size.saturating_add(1);
            let mut scratch = recv_batch_payload_buffer(spare_payloads, guard_size);
            let (bytes_read, src_addr) = loop {
                match self.poll_recv_from(cx, &mut scratch) {
                    Poll::Ready(Ok(received)) => break received,
                    Poll::Ready(Err(err)) if is_wsaemsgsize(&err) => {
                        // Winsock reports datagrams larger than the buffer as WSAEMSGSIZE (10040)
                        // rather than truncating into the buffer. Skip the oversized datagram and
                        // poll again so a stray oversized packet does not kill the batch.
                    }
                    Poll::Ready(Err(err)) => {
                        recycle_unused_recv_batch_payload(spare_payloads, scratch);
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending => {
                        recycle_unused_recv_batch_payload(spare_payloads, scratch);
                        return Poll::Pending;
                    }
                }
            };

            let (stored_len, possibly_truncated) = if bytes_read > packet_size {
                (packet_size, true)
            } else {
                (bytes_read, false)
            };

            let mut batch = UdpRecvBatch {
                packets: Vec::with_capacity(max_packets),
                report: UdpBatchIoReport {
                    packets_processed: 1,
                    bytes_processed: stored_len,
                    fallback_used: max_packets > 1,
                    native_send_batch_used: false,
                    gso_send_used: false,
                    error: None,
                },
            };
            batch.packets.push(UdpInboundDatagram {
                src_addr,
                payload: scratch[..stored_len].to_vec(),
                possibly_truncated,
            });

            for _ in 1..max_packets {
                if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                    batch.report.error = Some("cancelled".to_string());
                    break;
                }

                match self.inner.recv_from(&mut scratch) {
                    Ok((n, addr)) => {
                        let (stored_len, possibly_truncated) = if n > packet_size {
                            (packet_size, true)
                        } else {
                            (n, false)
                        };
                        batch.report.packets_processed += 1;
                        batch.report.bytes_processed += stored_len;
                        batch.packets.push(UdpInboundDatagram {
                            src_addr: addr,
                            payload: scratch[..stored_len].to_vec(),
                            possibly_truncated,
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(err) if is_wsaemsgsize(&err) => {
                        // Winsock oversized datagram: skip and continue receiving remaining packets.
                    }
                    Err(err) => {
                        batch.report.error = Some(err.to_string());
                        break;
                    }
                }
            }
            recycle_unused_recv_batch_payload(spare_payloads, scratch);

            Poll::Ready(Ok(batch))
        }
    }

    /// Clone this socket via the underlying OS handle.
    ///
    /// The new socket gets its own reactor registration.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: Arc::new(self.inner.try_clone()?),
            registration: ReactorRegistration::new(),
            gso_demoted: self.gso_demoted,
            #[cfg(target_os = "linux")]
            txtime: self.txtime,
            #[cfg(target_os = "linux")]
            recverr: std::sync::atomic::AtomicBool::new(
                self.recverr.load(std::sync::atomic::Ordering::Relaxed),
            ),
        })
    }

    /// Release readiness ownership without requiring a live cancellation context.
    // Native-only callers (the QUIC endpoint).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn clear_registration(&mut self) {
        self.registration.clear();
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
            suppress_windows_udp_connection_reset(&socket)?;
            socket.set_nonblocking(true)?;
            Ok(Self {
                inner: Arc::new(socket),
                registration: ReactorRegistration::new(),
                gso_demoted: false,
                #[cfg(target_os = "linux")]
                txtime: None,
                #[cfg(target_os = "linux")]
                recverr: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    fn register_interest(&self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        let _ = (cx, interest);
        browser_udp_unsupported_result("UdpSocket::register_interest")
    }

    /// Refuses a send without a launch time once `SO_TXTIME` is on: the ETF
    /// qdisc would drop that datagram while the send reports `Ok` (GH #73).
    #[cfg(not(target_arch = "wasm32"))]
    #[inline]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(clippy::unused_self, clippy::unnecessary_wraps)
    )]
    fn ensure_plain_send_allowed(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if self.txtime.is_some() {
            return Err(txtime::plain_send_refused());
        }
        Ok(())
    }

    /// Register interest with the reactor.
    ///
    /// The reactor is selected from the current `Cx`. With no ambient I/O
    /// driver (the caller-driven composition: a plain executor plus an explicit
    /// `Cx`) the socket registers with the process-global fallback I/O driver
    /// so the caller parks until the fd is ready instead of self-waking into a
    /// hot loop (GH#67); see [`ReactorRegistration::arm`].
    #[cfg(not(target_arch = "wasm32"))]
    fn register_interest(&mut self, cx: &Context<'_>, interest: Interest) -> io::Result<()> {
        if self.registration.arm(&*self.inner, interest, cx.waker())? == Armed::SelfWake {
            crate::net::tcp::stream::fallback_rewake(cx);
        }
        Ok(())
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
#[path = "udp_inline_tests.rs"]
mod tests;
