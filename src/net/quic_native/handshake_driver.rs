//! Real QUIC/TLS-1.3 handshake driver wrapping `rustls::quic`.
//!
//! # Why this exists
//!
//! Until this module, the native QUIC stack had **no real handshake driver**:
//! the `QuicFrame::Crypto` handler was a no-op, keys were installed out-of-band,
//! and every "loopback e2e" used deterministic in-process transitions
//! ([`super::endpoint_api::establish_loopback`]) rather than a TLS exchange over a
//! socket. That made cross-machine ATP-over-QUIC impossible — there was no way to
//! reach the `Established` state from two endpoints that only share a UDP path.
//!
//! This driver fills exactly that gap. It owns a [`rustls::quic::Connection`] and
//! runs the canonical QUIC/TLS-1.3 drive loop: pull outbound handshake bytes with
//! [`rustls::quic::Connection::write_hs`] (to be carried as CRYPTO frames),
//! feed received CRYPTO bytes with [`rustls::quic::Connection::read_hs`], and
//! install each [`rustls::quic::KeyChange`] into the existing
//! [`RustlsQuicCryptoProvider`] as the Initial → Handshake → 1-RTT encryption
//! levels become available. Server-certificate verification is performed by
//! rustls inside the client config's verifier (wire in
//! [`super::tls::QuicServerIdentityVerifier`]'s WebPKI verifier — no insecure
//! skip-verify path).
//!
//! # Scope boundary
//!
//! `write_hs`/`read_hs` operate on **plaintext** TLS handshake bytes. The packet
//! AEAD/header-protection (Initial/Handshake long-header and 1-RTT short-header)
//! is a *separate* layer ([`super::connection_manager::ConnectionRouter`]) that
//! *consumes* the keys this driver installs. This module is therefore the
//! TLS-key-agreement half and is unit-testable in isolation (two drivers pumping
//! handshake bytes between each other, no packets, no socket). Wiring it into the
//! CRYPTO frame handler + long-header packet I/O + connect/accept is tracked
//! separately (P1/P2 of the ATP-over-QUIC plan).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::quic::{ClientConnection, Connection, KeyChange, ServerConnection, Version};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    ServerConfig, SignatureScheme,
};

use super::tls::{
    PacketProtectionRequest, PacketProtectionSpace, ProtectedPacket, ProtectionProof,
    QuicHandshakeTranscript, QuicPacketProtectionProvider, QuicTlsError, RustlsQuicCryptoProvider,
    RustlsQuicProviderSide, TranscriptHash,
};
use crate::bytes::{Bytes, BytesMut};
use crate::cx::Cx;
use crate::net::atp::protocol::quic_frames::QuicFrame;
use crate::net::atp::protocol::varint::VarInt;
use crate::net::quic_core::{
    ConnectionId, LongHeader, LongPacketType, PacketHeader, ProtectedHeaderPrefix,
    ProtectedLongHeaderPrefix, apply_header_protection, decode_packet_number_reconstruct,
    header_protection_sample, remove_header_protection,
};
use crate::net::quic_native::endpoint::{OutgoingPacket, QuicUdpEndpoint, ReceivedPacket};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Handshake PTO while driving the QUIC/TLS handshake over UDP. A timeout
/// retransmits the last handshake flight instead of aborting immediately.
const HANDSHAKE_PTO: Duration = Duration::from_millis(1_500);
/// Bound on handshake round trips before giving up (defends against a peer that
/// never converges).
const HANDSHAKE_MAX_FLIGHTS: usize = 64;
/// Maximum datagrams accepted from one endpoint receive operation.
const HANDSHAKE_RECEIVE_BATCH_SIZE: usize = 16;
/// Bound exact packet-number history by the maximum number of datagrams the
/// handshake drive loop can accept. Unlike a largest-seen watermark, exact
/// membership permits legitimate packet reordering.
const MAX_SEEN_HANDSHAKE_PACKETS: usize = HANDSHAKE_MAX_FLIGHTS * HANDSHAKE_RECEIVE_BATCH_SIZE;
/// Bound authenticated-peer application packets retained while the server is
/// still consuming the client's final handshake flight.
const MAX_EARLY_ONE_RTT_PACKETS: usize = HANDSHAKE_MAX_FLIGHTS * HANDSHAKE_RECEIVE_BATCH_SIZE;
/// Bound CRYPTO data held behind a gap so an unauthenticated peer cannot grow
/// handshake memory without limit.
const MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES: usize = 1024 * 1024;
/// Bound metadata as well as payload bytes. Without a range-count cap, a peer
/// can spend very little of the byte budget on thousands of one-byte ranges
/// while forcing substantially larger `BTreeMap` node allocations.
const MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES: usize = 4096;
const HANDSHAKE_SERVER_NO_PEER_IDLE_LIMIT: usize = 8;

/// AEAD authentication tag length for the QUIC AES-128-GCM suite.
const QUIC_AEAD_TAG_LEN: usize = 16;
/// RFC 9000 §14.1: a UDP datagram carrying an Initial packet is expanded to at
/// least this many bytes (clients for every Initial, servers for ack-eliciting
/// ones). Compliant peers drop smaller Initial datagrams (GH#68).
const MIN_INITIAL_DATAGRAM_BYTES: usize = 1200;
/// Fixed packet-number length used for handshake packets (4 bytes).
const HANDSHAKE_PACKET_NUMBER_LEN: u8 = 4;

/// ALPN protocol identifier for the ATP-over-QUIC transport. QUIC mandates ALPN,
/// and both peers must advertise a common protocol or the handshake fails closed.
pub const ATP_QUIC_ALPN: &[u8] = b"atpq/1";

fn handshake_failure(code: &'static str) -> QuicTlsError {
    QuicTlsError::CryptoProviderFailure {
        provider: "rustls-quic-handshake",
        code,
    }
}

/// Failure code: authentication failed under live keys.
///
/// A packet in a space with *live* keys failed header-protection removal or
/// AEAD authentication in [`QuicHandshakeDriver::recv_handshake_packet`].
/// This is never stale traffic.
pub(crate) const PACKET_UNPROTECT_CODE: &str = "packet_unprotect";
/// Failure code: the packet's space keys were already discarded.
///
/// Old traffic, e.g. an Initial arriving after Initial keys were dropped.
pub(crate) const PACKET_KEYS_DISCARDED_CODE: &str = "packet_keys_discarded";
/// Failure code: the packet's space keys are not derived yet.
///
/// Traffic ahead of this endpoint's handshake progress, e.g. a Handshake
/// packet whose Initial predecessor was lost.
pub(crate) const PACKET_KEYS_UNAVAILABLE_CODE: &str = "packet_keys_unavailable";

/// True for long-header traffic this driver holds no live keys for.
///
/// That is keys already discarded ([`PACKET_KEYS_DISCARDED_CODE`]) or not yet
/// derived ([`PACKET_KEYS_UNAVAILABLE_CODE`]). The drive loops drop such a
/// packet and re-offer their last flight so the peer can catch up.
///
/// An authentication failure under live keys ([`PACKET_UNPROTECT_CODE`]) is
/// deliberately *not* stale: it is a real crypto/protocol error and surfaces
/// to the caller. GH#70: classifying every unprotect failure as stale made the
/// loops silently retransmit forever, which is how the missing header
/// protection of GH#69 stayed invisible.
pub(crate) fn is_stale_handshake_packet_error(error: &QuicTlsError) -> bool {
    matches!(
        error,
        QuicTlsError::CryptoProviderFailure { provider, code }
            if *provider == "rustls-quic-handshake"
                && (*code == PACKET_KEYS_DISCARDED_CODE || *code == PACKET_KEYS_UNAVAILABLE_CODE)
    )
}

fn invalid_certificate(error: CertificateError) -> RustlsError {
    RustlsError::InvalidCertificate(error)
}

fn is_unknown_issuer(error: &RustlsError) -> bool {
    matches!(
        error,
        RustlsError::InvalidCertificate(CertificateError::UnknownIssuer)
    )
}

fn san_matches_server_name(
    san: &x509_parser::extensions::SubjectAlternativeName<'_>,
    server_name: &ServerName<'_>,
) -> bool {
    san.general_names
        .iter()
        .any(|name| match (name, server_name) {
            (
                x509_parser::extensions::GeneralName::DNSName(presented),
                ServerName::DnsName(expected),
            ) => presented.eq_ignore_ascii_case(expected.as_ref()),
            (
                x509_parser::extensions::GeneralName::IPAddress(presented),
                ServerName::IpAddress(expected),
            ) => {
                let expected: std::net::IpAddr = (*expected).into();
                match expected {
                    std::net::IpAddr::V4(addr) => *presented == addr.octets().as_slice(),
                    std::net::IpAddr::V6(addr) => *presented == addr.octets().as_slice(),
                }
            }
            _ => false,
        })
}

fn verify_pinned_end_entity_shape(
    end_entity: &CertificateDer<'_>,
    server_name: &ServerName<'_>,
    now: UnixTime,
) -> Result<(), RustlsError> {
    let (remaining, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref())
        .map_err(|_| invalid_certificate(CertificateError::BadEncoding))?;
    if !remaining.is_empty() {
        return Err(invalid_certificate(CertificateError::BadEncoding));
    }

    let now = i64::try_from(now.as_secs())
        .map_err(|_| invalid_certificate(CertificateError::BadEncoding))?;
    let validity = parsed.validity();
    if now < validity.not_before.timestamp() {
        return Err(invalid_certificate(CertificateError::NotValidYet));
    }
    if now > validity.not_after.timestamp() {
        return Err(invalid_certificate(CertificateError::Expired));
    }

    match parsed
        .extended_key_usage()
        .map_err(|_| invalid_certificate(CertificateError::BadEncoding))?
    {
        Some(usage) if usage.value.server_auth => {}
        _ => return Err(invalid_certificate(CertificateError::InvalidPurpose)),
    }

    if parsed
        .key_usage()
        .map_err(|_| invalid_certificate(CertificateError::BadEncoding))?
        .is_some_and(|usage| !usage.value.digital_signature())
    {
        return Err(invalid_certificate(CertificateError::InvalidPurpose));
    }

    let san = parsed
        .subject_alternative_name()
        .map_err(|_| invalid_certificate(CertificateError::BadEncoding))?
        .ok_or_else(|| invalid_certificate(CertificateError::NotValidForName))?;
    if !san_matches_server_name(san.value, server_name) {
        return Err(invalid_certificate(CertificateError::NotValidForName));
    }

    Ok(())
}

#[derive(Debug)]
struct WebPkiOrPinnedEndEntityVerifier {
    webpki: Arc<rustls::client::WebPkiServerVerifier>,
    pinned_end_entities: Vec<CertificateDer<'static>>,
}

/// Wrap a standard WebPKI verifier with a narrowly scoped exact-leaf fallback.
///
/// WebPKI always runs first. The fallback is considered only when WebPKI
/// returns [`CertificateError::UnknownIssuer`] and the complete presented leaf
/// DER exactly matches a configured pin. It then preserves the accepted pinned
/// leaf policy: full DER consumption, validity, explicit `serverAuth` EKU,
/// `digitalSignature` when KeyUsage is present, and exact DNS/IP SAN matching.
/// TLS 1.2/1.3 handshake signatures and supported schemes remain delegated to
/// the supplied WebPKI verifier.
///
/// A pin deliberately replaces issuer-path trust only. It does not turn other
/// WebPKI failures (bad signature, wrong name/purpose, critical extensions,
/// constraints, or revocation failures) into successful verification.
#[must_use]
pub fn webpki_server_verifier_with_exact_leaf_fallback(
    webpki: Arc<rustls::client::WebPkiServerVerifier>,
    pinned_end_entities: Vec<CertificateDer<'static>>,
) -> Arc<dyn ServerCertVerifier> {
    if pinned_end_entities.is_empty() {
        webpki
    } else {
        Arc::new(WebPkiOrPinnedEndEntityVerifier {
            webpki,
            pinned_end_entities,
        })
    }
}

impl ServerCertVerifier for WebPkiOrPinnedEndEntityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        match self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(error)
                if is_unknown_issuer(&error)
                    && self
                        .pinned_end_entities
                        .iter()
                        .any(|pinned| pinned.as_ref() == end_entity.as_ref()) =>
            {
                verify_pinned_end_entity_shape(end_entity, server_name, now)?;
                Ok(ServerCertVerified::assertion())
            }
            Err(error) => Err(error),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.webpki.root_hint_subjects()
    }
}

/// Encryption level a chunk of handshake (CRYPTO) data belongs to. The packet
/// layer maps these to QUIC packet number spaces (Initial/Handshake/1-RTT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeLevel {
    /// Initial packet number space (CRYPTO carried in long-header Initial packets).
    Initial,
    /// Handshake packet number space (long-header Handshake packets).
    Handshake,
    /// Application (1-RTT) packet number space (short-header packets).
    OneRtt,
}

/// A contiguous run of outbound handshake bytes at a single encryption level.
#[derive(Debug, Clone)]
pub struct HandshakeSegment {
    /// Encryption level these bytes must be sent at.
    pub level: HandshakeLevel,
    /// Plaintext TLS handshake bytes to carry in CRYPTO frames at `level`.
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
struct HandshakeCryptoReassembler {
    next_offset: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    pending_bytes: usize,
}

impl HandshakeCryptoReassembler {
    fn push(&mut self, mut offset: u64, mut data: &[u8]) -> Result<Vec<Vec<u8>>, QuicTlsError> {
        let data_len =
            u64::try_from(data.len()).map_err(|_| handshake_failure("crypto_offset_overflow"))?;
        let end = offset
            .checked_add(data_len)
            .ok_or_else(|| handshake_failure("crypto_offset_overflow"))?;
        if end <= self.next_offset {
            return Ok(Vec::new());
        }
        if offset < self.next_offset {
            let delivered = usize::try_from(self.next_offset - offset)
                .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
            data = &data[delivered..];
            offset = self.next_offset;
        }
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Build the merged candidate transactionally. Overlapping ranges are
        // removed temporarily so transitive adjacency remains easy to detect,
        // but every error path restores the exact accepted state. In
        // particular, a conflicting or oversized fragment must not erase
        // bytes that authenticated packets already contributed.
        let original_pending_bytes = self.pending_bytes;
        let mut removed = Vec::new();
        let candidate = (|| {
            let mut merged_start = offset;
            let mut merged = data.to_vec();
            loop {
                let merged_len = u64::try_from(merged.len())
                    .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
                let merged_end = merged_start
                    .checked_add(merged_len)
                    .ok_or_else(|| handshake_failure("crypto_offset_overflow"))?;
                let overlapping = self.pending.iter().find_map(|(&start, bytes)| {
                    let len = u64::try_from(bytes.len()).ok()?;
                    let end = start.checked_add(len)?;
                    (start <= merged_end && end >= merged_start).then_some(start)
                });
                let Some(existing_start) = overlapping else {
                    break;
                };
                let Some(existing) = self.pending.remove(&existing_start) else {
                    return Err(handshake_failure("crypto_reassembly_state"));
                };
                let existing_len = existing.len();
                let merged_range =
                    merge_crypto_ranges(merged_start, &merged, existing_start, &existing);
                removed.push((existing_start, existing));
                self.pending_bytes = self
                    .pending_bytes
                    .checked_sub(existing_len)
                    .ok_or_else(|| handshake_failure("crypto_reassembly_state"))?;
                (merged_start, merged) = merged_range?;
            }

            let new_pending_bytes = self
                .pending_bytes
                .checked_add(merged.len())
                .ok_or_else(|| handshake_failure("crypto_buffer_limit"))?;
            // A range beginning at the current receive head is removed again
            // immediately below and fed to rustls. Rejecting that range merely
            // because either retained-data budget is full would let a peer fill
            // the cap behind a gap and make the one fragment capable of
            // advancing the stream permanently inadmissible. The wire packet
            // already bounds immediately deliverable input; these limits bound
            // only bytes and tree nodes retained behind a gap.
            let drains_from_head = merged_start == self.next_offset;
            if !drains_from_head && new_pending_bytes > MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES {
                return Err(handshake_failure("crypto_buffer_limit"));
            }
            if !drains_from_head && self.pending.len() >= MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES {
                return Err(handshake_failure("crypto_range_limit"));
            }
            Ok((merged_start, merged, new_pending_bytes))
        })();
        let (merged_start, merged, new_pending_bytes) = match candidate {
            Ok(candidate) => candidate,
            Err(err) => {
                for (start, bytes) in removed {
                    let displaced = self.pending.insert(start, bytes);
                    debug_assert!(displaced.is_none(), "removed CRYPTO range key was reused");
                }
                self.pending_bytes = original_pending_bytes;
                return Err(err);
            }
        };
        self.pending.insert(merged_start, merged);
        self.pending_bytes = new_pending_bytes;

        let mut ready = Vec::new();
        while let Some(bytes) = self.pending.remove(&self.next_offset) {
            self.pending_bytes = self
                .pending_bytes
                .checked_sub(bytes.len())
                .ok_or_else(|| handshake_failure("crypto_reassembly_state"))?;
            let len = u64::try_from(bytes.len())
                .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
            self.next_offset = self
                .next_offset
                .checked_add(len)
                .ok_or_else(|| handshake_failure("crypto_offset_overflow"))?;
            ready.push(bytes);
        }
        Ok(ready)
    }
}

fn merge_crypto_ranges(
    first_start: u64,
    first: &[u8],
    second_start: u64,
    second: &[u8],
) -> Result<(u64, Vec<u8>), QuicTlsError> {
    let first_end = first_start
        .checked_add(
            u64::try_from(first.len()).map_err(|_| handshake_failure("crypto_offset_overflow"))?,
        )
        .ok_or_else(|| handshake_failure("crypto_offset_overflow"))?;
    let second_end = second_start
        .checked_add(
            u64::try_from(second.len()).map_err(|_| handshake_failure("crypto_offset_overflow"))?,
        )
        .ok_or_else(|| handshake_failure("crypto_offset_overflow"))?;
    let merged_start = first_start.min(second_start);
    let merged_end = first_end.max(second_end);
    let merged_len = usize::try_from(merged_end - merged_start)
        .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
    let mut merged = vec![0; merged_len];

    let first_at = usize::try_from(first_start - merged_start)
        .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
    merged[first_at..first_at + first.len()].copy_from_slice(first);

    let second_at = usize::try_from(second_start - merged_start)
        .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
    let overlap_start = first_start.max(second_start);
    let overlap_end = first_end.min(second_end);
    if overlap_start < overlap_end {
        let overlap_len = usize::try_from(overlap_end - overlap_start)
            .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
        let first_overlap = usize::try_from(overlap_start - first_start)
            .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
        let second_overlap = usize::try_from(overlap_start - second_start)
            .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
        if first[first_overlap..first_overlap + overlap_len]
            != second[second_overlap..second_overlap + overlap_len]
        {
            return Err(handshake_failure("crypto_overlap_conflict"));
        }
    }
    merged[second_at..second_at + second.len()].copy_from_slice(second);
    Ok((merged_start, merged))
}

/// Drives a real QUIC/TLS-1.3 handshake via rustls, installing the derived AEAD
/// keys into the packet-protection provider as each level becomes available.
pub struct QuicHandshakeDriver {
    tls: Connection,
    provider: RustlsQuicCryptoProvider,
    transcript: QuicHandshakeTranscript,
    write_level: HandshakeLevel,
    handshake_keys_installed: bool,
    one_rtt_keys_installed: bool,
    /// Exact transport parameters offered to rustls for this endpoint. Kept so
    /// the wire owner can bind its application flow-control state to the same
    /// authenticated parameters rather than a parallel caller-only config.
    local_transport_parameters: Vec<u8>,
    /// Authenticated source connection ID learned from the peer's first
    /// protected handshake packet. Kept with the TLS state so application-data
    /// handoff cannot silently invent an unrelated post-handshake CID.
    peer_connection_id: Option<ConnectionId>,
    /// Per-level cumulative CRYPTO send offset (indexed Initial=0/Handshake=1/OneRtt=2).
    crypto_send_offset: [u64; 3],
    /// Exact authenticated packet numbers already accepted for Initial/Handshake.
    handshake_recv_packet_numbers: [BTreeSet<u64>; 2],
    /// Largest authenticated packet number per Initial/Handshake space: the
    /// reference for reconstructing truncated packet numbers (RFC 9000 §A.3).
    handshake_recv_largest_packet_number: [Option<u64>; 2],
    /// Per-level QUIC CRYPTO stream reassembly for reordered packets.
    handshake_crypto_reassembly: [HandshakeCryptoReassembler; 2],
    /// Outbound segments produced while installing keys *between* the packets
    /// of one coalesced datagram.
    ///
    /// RFC 9000 §12.2: the server's Initial unlocks the Handshake keys its own
    /// coalesced Handshake packet needs. [`Self::pump_outbound`] hands these
    /// out ahead of fresh TLS output so no flight is lost.
    staged_segments: Vec<HandshakeSegment>,
    /// The last handshake flight this side sent before completing, retained so
    /// the data plane can re-send it if the peer provably never finished. A
    /// TLS 1.3 client completes upon *sending* Finished; if that flight is
    /// lost, the server retransmits its own flight forever while the
    /// already-complete client drops those long-header packets — a mutual
    /// wedge until both idle timeouts (br-asupersync-jmri58).
    final_flight: Vec<OutgoingPacket>,
    /// Wall-clock path round-trip measured during the handshake (client side:
    /// flight sent → first response batch received; re-stamped on handshake
    /// retransmits, so loss inflates rather than deflates the sample). The
    /// data plane's transport RTT estimator is fed by the app-data path's
    /// synthetic clock and reads nonsense (~1 ms on a 50 ms path, MATRIX-225),
    /// so consumers needing a real RTprop — the source-stream BDP admission
    /// cap — take this instead.
    pub path_rtt_estimate_micros: Option<u64>,
}

fn level_index(level: HandshakeLevel) -> usize {
    match level {
        HandshakeLevel::Initial => 0,
        HandshakeLevel::Handshake => 1,
        HandshakeLevel::OneRtt => 2,
    }
}

fn level_protection_space(level: HandshakeLevel) -> PacketProtectionSpace {
    match level {
        HandshakeLevel::Initial => PacketProtectionSpace::Initial,
        HandshakeLevel::Handshake => PacketProtectionSpace::Handshake,
        HandshakeLevel::OneRtt => PacketProtectionSpace::OneRtt,
    }
}

fn handshake_packet_space_index(space: PacketProtectionSpace) -> Option<usize> {
    match space {
        PacketProtectionSpace::Initial => Some(0),
        PacketProtectionSpace::Handshake => Some(1),
        PacketProtectionSpace::ZeroRtt | PacketProtectionSpace::OneRtt => None,
    }
}

fn long_packet_type_space(packet_type: LongPacketType) -> Option<PacketProtectionSpace> {
    match packet_type {
        LongPacketType::Initial => Some(PacketProtectionSpace::Initial),
        LongPacketType::Handshake => Some(PacketProtectionSpace::Handshake),
        _ => None,
    }
}

impl QuicHandshakeDriver {
    /// The actual TLS role, used before admitting a managed server handshake.
    pub(crate) fn is_server(&self) -> bool {
        matches!(self.tls, Connection::Server(_))
    }

    /// Start a client handshake against `server_name`, advertising `transport_params`.
    pub fn client(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        let local_transport_parameters = transport_params.clone();
        let conn = ClientConnection::new(config, Version::V1, server_name, transport_params)
            .map_err(|_| handshake_failure("client_connection_init"))?;
        let provider = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Client)?;
        Ok(Self::new(
            Connection::Client(conn),
            provider,
            local_transport_parameters,
        ))
    }

    /// Start a server handshake, advertising `transport_params`.
    pub fn server(
        config: Arc<ServerConfig>,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        let local_transport_parameters = transport_params.clone();
        let conn = ServerConnection::new(config, Version::V1, transport_params)
            .map_err(|_| handshake_failure("server_connection_init"))?;
        let provider = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Server)?;
        Ok(Self::new(
            Connection::Server(conn),
            provider,
            local_transport_parameters,
        ))
    }

    fn new(
        tls: Connection,
        provider: RustlsQuicCryptoProvider,
        local_transport_parameters: Vec<u8>,
    ) -> Self {
        Self {
            tls,
            provider,
            transcript: QuicHandshakeTranscript::new(),
            write_level: HandshakeLevel::Initial,
            handshake_keys_installed: false,
            one_rtt_keys_installed: false,
            local_transport_parameters,
            peer_connection_id: None,
            crypto_send_offset: [0; 3],
            handshake_recv_packet_numbers: [BTreeSet::new(), BTreeSet::new()],
            handshake_recv_largest_packet_number: [None, None],
            handshake_crypto_reassembly: [
                HandshakeCryptoReassembler::default(),
                HandshakeCryptoReassembler::default(),
            ],
            staged_segments: Vec::new(),
            final_flight: Vec::new(),
            path_rtt_estimate_micros: None,
        }
    }

    /// Take the retained final handshake flight for data-plane loss recovery
    /// (see the `final_flight` field docs). Empty when the handshake needed no
    /// retained flight (server role) or when already taken.
    pub fn take_final_flight(&mut self) -> Vec<OutgoingPacket> {
        std::mem::take(&mut self.final_flight)
    }

    /// Mutable access to the packet-protection provider holding the installed
    /// keys (used to protect/unprotect handshake packets, and to hand off the
    /// established keys to the connection's data-plane protection).
    pub fn provider_mut(&mut self) -> &mut RustlsQuicCryptoProvider {
        &mut self.provider
    }

    /// Assemble a protected long-header (Initial/Handshake) QUIC packet
    /// carrying `segment`'s CRYPTO bytes.
    ///
    /// The long header is authenticated as AEAD associated data, then header
    /// protection masks the first byte's low bits and the packet number (RFC
    /// 9001 §5.4, GH#69), so the datagram is `protected-header || ciphertext
    /// || tag` as any RFC 9000 peer expects.
    pub fn assemble_handshake_packet(
        &mut self,
        segment: &HandshakeSegment,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: u64,
    ) -> Result<Vec<u8>, QuicTlsError> {
        let packet_type = match segment.level {
            HandshakeLevel::Initial => LongPacketType::Initial,
            HandshakeLevel::Handshake => LongPacketType::Handshake,
            HandshakeLevel::OneRtt => return Err(handshake_failure("onertt_is_not_long_header")),
        };
        let space = level_protection_space(segment.level);
        let offset = self.crypto_send_offset[level_index(segment.level)];

        let mut payload = BytesMut::new();
        QuicFrame::Crypto {
            offset: VarInt::from_u64_unchecked(offset),
            data: Bytes::copy_from_slice(&segment.data),
        }
        .encode(&mut payload)
        .map_err(|_| handshake_failure("crypto_frame_encode"))?;
        let mut plaintext = payload.to_vec();

        if matches!(packet_type, LongPacketType::Initial) {
            // RFC 9000 §14.1 (GH#68): every Initial packet leaves here as its
            // own datagram, so expand the packet itself to the 1200-byte
            // minimum with PADDING frames inside the AEAD envelope. The header
            // is sized with a placeholder length of the same varint width the
            // final length lands in, so the padded packet is exactly 1200 bytes.
            let probe = PacketHeader::Long(LongHeader {
                packet_type,
                version: 1,
                dst_cid,
                src_cid,
                token: Vec::new(),
                payload_length: MIN_INITIAL_DATAGRAM_BYTES as u64,
                packet_number,
                packet_number_len: HANDSHAKE_PACKET_NUMBER_LEN,
            });
            let mut probe_bytes = Vec::new();
            probe
                .encode(&mut probe_bytes)
                .map_err(|_| handshake_failure("long_header_encode"))?;
            // `probe_bytes` already includes the packet number.
            let unpadded = probe_bytes.len() + plaintext.len() + QUIC_AEAD_TAG_LEN;
            if unpadded < MIN_INITIAL_DATAGRAM_BYTES {
                plaintext.resize(
                    plaintext.len() + (MIN_INITIAL_DATAGRAM_BYTES - unpadded),
                    0x00,
                );
            }
        }

        // payload_length covers the packet number + AEAD ciphertext + tag.
        let payload_length = u64::from(HANDSHAKE_PACKET_NUMBER_LEN)
            + plaintext.len() as u64
            + QUIC_AEAD_TAG_LEN as u64;
        let header = PacketHeader::Long(LongHeader {
            packet_type,
            version: 1,
            dst_cid,
            src_cid,
            token: Vec::new(),
            payload_length,
            packet_number,
            packet_number_len: HANDSHAKE_PACKET_NUMBER_LEN,
        });
        let mut header_bytes = Vec::new();
        header
            .encode(&mut header_bytes)
            .map_err(|_| handshake_failure("long_header_encode"))?;

        let packet =
            self.protect_long_header_packet(space, &header_bytes, packet_number, &plaintext)?;

        self.crypto_send_offset[level_index(segment.level)] += segment.data.len() as u64;
        Ok(packet)
    }

    /// Protect one long-header packet exactly as RFC 9001 §5 describes.
    ///
    /// AEAD-seal `plaintext` under `space` keys with `header_bytes` (an
    /// unprotected long header whose packet-number width is announced by its
    /// first byte) as associated data, then apply header protection with the
    /// mask sampled from the ciphertext (§5.4.2). The result is
    /// `protected-header || ciphertext || tag`.
    pub(crate) fn protect_long_header_packet(
        &mut self,
        space: PacketProtectionSpace,
        header_bytes: &[u8],
        packet_number: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, QuicTlsError> {
        let first = *header_bytes
            .first()
            .ok_or_else(|| handshake_failure("long_header_encode"))?;
        let packet_number_len = usize::from(first & 0x03) + 1;
        let packet_number_offset = header_bytes
            .len()
            .checked_sub(packet_number_len)
            .ok_or_else(|| handshake_failure("long_header_encode"))?;

        let protected = self.provider.protect_packet(PacketProtectionRequest {
            space,
            key_phase: false,
            packet_number,
            associated_data: header_bytes,
            payload: plaintext,
        })?;

        let mut packet = Vec::with_capacity(
            header_bytes.len() + protected.ciphertext.len() + protected.tag.len(),
        );
        packet.extend_from_slice(header_bytes);
        packet.extend_from_slice(&protected.ciphertext);
        packet.extend_from_slice(&protected.tag);

        let sample = header_protection_sample(&packet, packet_number_offset)
            .map_err(|_| handshake_failure("header_protection_sample"))?;
        let mask = self.provider.header_protection_mask(space, &sample)?;
        apply_header_protection(&mut packet, packet_number_offset, mask.bytes)
            .map_err(|_| handshake_failure("header_protection_apply"))?;
        Ok(packet)
    }

    /// Process one UDP datagram of protected long-header (Initial/Handshake)
    /// packets.
    ///
    /// Separates the coalesced packets by their Length fields (RFC 9000
    /// §12.2), removes header protection and AEAD-unprotects each with the
    /// installed keys for its space, and feeds the CRYPTO bytes to the TLS
    /// state machine. Returns the peer's source connection ID (so a server can
    /// address its replies to the client's chosen CID). CRYPTO data is
    /// reassembled by offset within each packet-number space, so reordered
    /// packets are fed to TLS only after every preceding byte is available.
    ///
    /// Keys unlocked by one packet are installed before the next coalesced
    /// packet is tried (the server's Initial carries the ServerHello that
    /// derives the Handshake keys its coalesced Handshake packet needs);
    /// segments TLS emits meanwhile are staged for [`Self::pump_outbound`].
    ///
    /// Trailing datagram padding and a coalesced 1-RTT short-header packet end
    /// processing (the latter belongs to the data plane). A packet for a space
    /// without live keys is skipped with a stale classification
    /// ([`is_stale_handshake_packet_error`]); an authentication failure under
    /// live keys fails the call with [`PACKET_UNPROTECT_CODE`]. The result is
    /// `Ok` when at least one packet authenticated, otherwise the first
    /// packet's error.
    pub fn recv_handshake_packet(&mut self, datagram: &[u8]) -> Result<ConnectionId, QuicTlsError> {
        if datagram.is_empty() {
            return Err(handshake_failure("packet_header_decode"));
        }
        let mut offset = 0usize;
        let mut accepted: Option<ConnectionId> = None;
        let mut skipped: Option<QuicTlsError> = None;
        while offset < datagram.len() {
            let rest = &datagram[offset..];
            if rest[0] & 0x80 == 0 {
                if offset == 0 {
                    return Err(handshake_failure("expected_long_header"));
                }
                // Datagram padding or a coalesced 1-RTT packet: not handshake input.
                break;
            }
            let prefix = match ProtectedHeaderPrefix::decode(rest, 0) {
                Ok(ProtectedHeaderPrefix::Long(prefix)) => prefix,
                Ok(ProtectedHeaderPrefix::Retry(_)) if offset == 0 => {
                    return Err(handshake_failure("unexpected_long_packet_type"));
                }
                Err(_) if offset == 0 => return Err(handshake_failure("packet_header_decode")),
                // A malformed trailer after an authenticated packet is dropped,
                // not fatal: the authenticated part already advanced TLS.
                Ok(ProtectedHeaderPrefix::Retry(_) | ProtectedHeaderPrefix::Short { .. })
                | Err(_) => break,
            };
            let packet_len = match prefix.packet_len(rest.len()) {
                Ok(len) => len,
                Err(_) if offset == 0 => return Err(handshake_failure("packet_length_overrun")),
                Err(_) => break,
            };
            match self.process_long_header_packet(&prefix, &rest[..packet_len]) {
                Ok(peer_cid) => accepted = Some(peer_cid),
                Err(err) if is_stale_handshake_packet_error(&err) => {
                    if skipped.is_none() {
                        skipped = Some(err);
                    }
                }
                Err(err) => return Err(err),
            }
            offset += packet_len;
            if accepted.is_some() && datagram.get(offset).is_some_and(|byte| byte & 0x80 != 0) {
                // Install any keys the packet just fed to TLS unlocked before
                // the coalesced follower that needs them is tried.
                self.stage_outbound()?;
            }
        }
        match (accepted, skipped) {
            (Some(peer_cid), _) => Ok(peer_cid),
            (None, Some(err)) => Err(err),
            (None, None) => Err(handshake_failure("expected_long_header")),
        }
    }

    /// Unprotect exactly one long-header packet (`packet` is
    /// `protected-header || ciphertext || tag`, already bounded by its Length
    /// field) and feed its CRYPTO frames to TLS.
    fn process_long_header_packet(
        &mut self,
        prefix: &ProtectedLongHeaderPrefix,
        packet: &[u8],
    ) -> Result<ConnectionId, QuicTlsError> {
        let peer_src_cid = prefix.src_cid;
        let (header, plaintext) = self.unprotect_long_header_packet(prefix, packet)?;
        let space = long_packet_type_space(header.packet_type)
            .ok_or_else(|| handshake_failure("unexpected_long_packet_type"))?;
        let space_index = handshake_packet_space_index(space)
            .ok_or_else(|| handshake_failure("unexpected_crypto_packet_space"))?;

        match self.peer_connection_id {
            None => self.peer_connection_id = Some(peer_src_cid),
            Some(expected) if expected == peer_src_cid => {}
            Some(_) => return Err(handshake_failure("peer_connection_id_changed")),
        }

        // A packet number is only a replay key after the packet authenticates.
        // Returning before AEAD verification would let an attacker forge the
        // cleartext long header of a previously seen packet number and have the
        // receive loop treat it as successful handshake traffic (including RTT
        // sampling) without possessing the packet-protection key.
        if self.handshake_recv_packet_numbers[space_index].contains(&header.packet_number) {
            return Ok(peer_src_cid);
        }
        if self.handshake_recv_packet_numbers[space_index].len() >= MAX_SEEN_HANDSHAKE_PACKETS {
            // The packet number and therefore the history-cap decision are
            // authoritative only after packet authentication. Keeping this
            // check below unprotection prevents a forged cleartext header from
            // turning an otherwise ignorable packet into a fatal exhaustion
            // result.
            return Err(handshake_failure("handshake_packet_history_exhausted"));
        }

        // asupersync's frame codec decodes over a `&[u8]` (which implements the
        // crate `Buf`), advancing the slice; mirror `NativeQuicConnection::decode_frames`.
        let mut buf: &[u8] = &plaintext;
        while !buf.is_empty() {
            match QuicFrame::decode(&mut buf).map_err(|_| handshake_failure("frame_decode"))? {
                Some(QuicFrame::Crypto { offset, data }) => {
                    let ready = self.handshake_crypto_reassembly[space_index]
                        .push(offset.value(), data.as_ref())?;
                    for contiguous in ready {
                        self.read_handshake(&contiguous)?;
                    }
                }
                // ACK/PADDING/PING and any other handshake-coalesced frames carry
                // no TLS data; ignore them here (loss recovery handled elsewhere).
                Some(_) => {}
                None => break,
            }
        }
        self.handshake_recv_packet_numbers[space_index].insert(header.packet_number);
        let largest = &mut self.handshake_recv_largest_packet_number[space_index];
        *largest =
            Some(largest.map_or(header.packet_number, |seen| seen.max(header.packet_number)));
        Ok(peer_src_cid)
    }

    /// Remove header protection from one long-header packet and authenticate
    /// it.
    ///
    /// RFC 9001 §5.4.1 receiver order: classify the key state for the
    /// packet's space, sample the ciphertext, unmask the first byte and the
    /// packet number, reconstruct the full packet number, AEAD-open with the
    /// unmasked header as associated data, and only then validate the
    /// reserved bits (RFC 9000 §17.2 checks them after packet protection is
    /// removed, so a forgery cannot trigger a protocol violation).
    ///
    /// Returns the authenticated header (with the reconstructed packet
    /// number) and the plaintext payload.
    pub(crate) fn unprotect_long_header_packet(
        &mut self,
        prefix: &ProtectedLongHeaderPrefix,
        packet: &[u8],
    ) -> Result<(LongHeader, Vec<u8>), QuicTlsError> {
        let space = long_packet_type_space(prefix.packet_type)
            .ok_or_else(|| handshake_failure("unexpected_long_packet_type"))?;
        let space_index = handshake_packet_space_index(space)
            .ok_or_else(|| handshake_failure("unexpected_crypto_packet_space"))?;
        match self.provider.key_snapshot(space, false) {
            Ok(_) => {}
            Err(QuicTlsError::KeyDiscarded { .. }) => {
                return Err(handshake_failure(PACKET_KEYS_DISCARDED_CODE));
            }
            Err(QuicTlsError::MissingKeys { .. }) => {
                return Err(handshake_failure(PACKET_KEYS_UNAVAILABLE_CODE));
            }
            Err(_) => return Err(handshake_failure(PACKET_UNPROTECT_CODE)),
        }

        let packet_number_offset = prefix.packet_number_offset;
        let sample = header_protection_sample(packet, packet_number_offset)
            .map_err(|_| handshake_failure("packet_body_too_short"))?;
        let mask = self
            .provider
            .header_protection_mask_remote(space, &sample)
            .map_err(|_| handshake_failure(PACKET_UNPROTECT_CODE))?;
        let mut unmasked = packet.to_vec();
        let packet_number_len =
            remove_header_protection(&mut unmasked, packet_number_offset, mask.bytes)
                .map_err(|_| handshake_failure(PACKET_UNPROTECT_CODE))?;
        let header_len = packet_number_offset + usize::from(packet_number_len);
        if unmasked.len() < header_len + QUIC_AEAD_TAG_LEN {
            return Err(handshake_failure("packet_body_too_short"));
        }
        let truncated = unmasked[packet_number_offset..header_len]
            .iter()
            .fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte));
        let largest = self.handshake_recv_largest_packet_number[space_index].unwrap_or(0);
        let packet_number = decode_packet_number_reconstruct(truncated, packet_number_len, largest)
            .map_err(|_| handshake_failure(PACKET_UNPROTECT_CODE))?;

        let tag_offset = unmasked.len() - QUIC_AEAD_TAG_LEN;
        let mut tag = [0u8; QUIC_AEAD_TAG_LEN];
        tag.copy_from_slice(&unmasked[tag_offset..]);
        let protected = ProtectedPacket {
            space,
            key_phase: false,
            packet_number,
            ciphertext: unmasked[header_len..tag_offset].to_vec(),
            tag,
            proof: ProtectionProof {
                provider_kind: self.provider.provider_kind(),
                space,
                key_phase: false,
                generation: 0,
                transcript_hash: TranscriptHash::from_bytes([0; 32]),
                failure_code: None,
            },
        };
        let unprotected = self
            .provider
            .unprotect_packet(&protected, &unmasked[..header_len])
            .map_err(|_| handshake_failure(PACKET_UNPROTECT_CODE))?;

        // The header is authentic now: reserved bits and the Length/packet
        // number consistency are validated on the unmasked bytes.
        let (PacketHeader::Long(mut header), consumed) =
            PacketHeader::decode(&unmasked[..header_len], 0)
                .map_err(|_| handshake_failure("packet_header_invalid"))?
        else {
            return Err(handshake_failure("expected_long_header"));
        };
        if consumed != header_len {
            return Err(handshake_failure("packet_header_invalid"));
        }
        header.packet_number = packet_number;
        Ok((header, unprotected.plaintext))
    }

    /// Install Initial-space packet-protection keys derived from the client's
    /// chosen Destination Connection ID (RFC 9001 §5.2). The packet layer needs
    /// these to protect/unprotect Initial packets; the TLS exchange itself does
    /// not (it operates on plaintext), so the in-isolation handshake test can
    /// skip this.
    pub fn install_initial_keys(&mut self, dcid: &[u8]) -> Result<(), QuicTlsError> {
        self.provider
            .derive_keys(PacketProtectionSpace::Initial, &self.transcript, dcid)
            .map(|_| ())
    }

    /// Drain all currently-available outbound handshake bytes, installing each
    /// key change into the provider and advancing the write level as the
    /// handshake crosses encryption boundaries. Returns one segment per level
    /// that produced data.
    pub fn pump_outbound(&mut self) -> Result<Vec<HandshakeSegment>, QuicTlsError> {
        let mut segments = std::mem::take(&mut self.staged_segments);
        self.pump_outbound_into(&mut segments)?;
        Ok(segments)
    }

    /// Install newly available keys between the packets of one coalesced
    /// datagram, keeping any TLS output for the next [`Self::pump_outbound`].
    fn stage_outbound(&mut self) -> Result<(), QuicTlsError> {
        let mut staged = std::mem::take(&mut self.staged_segments);
        let result = self.pump_outbound_into(&mut staged);
        self.staged_segments = staged;
        result
    }

    fn pump_outbound_into(
        &mut self,
        segments: &mut Vec<HandshakeSegment>,
    ) -> Result<(), QuicTlsError> {
        loop {
            let mut buf = Vec::new();
            let key_change = self.tls.write_hs(&mut buf);
            let produced = !buf.is_empty();
            if produced {
                // The data emitted alongside a KeyChange belongs to the level in
                // effect *before* the change, so record it before advancing.
                segments.push(HandshakeSegment {
                    level: self.write_level,
                    data: buf,
                });
            }
            match key_change {
                Some(KeyChange::Handshake { keys }) => {
                    self.provider
                        .install_key_change(KeyChange::Handshake { keys }, &self.transcript)?;
                    self.handshake_keys_installed = true;
                    self.write_level = HandshakeLevel::Handshake;
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    self.provider
                        .install_key_change(KeyChange::OneRtt { keys, next }, &self.transcript)?;
                    self.one_rtt_keys_installed = true;
                    self.write_level = HandshakeLevel::OneRtt;
                }
                None => {
                    if !produced {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Feed received plaintext handshake bytes (the payload of CRYPTO frames) to
    /// the TLS state machine. Bytes from different encryption levels must be
    /// supplied in separate calls (rustls requirement); the packet layer already
    /// delivers them per-space, so callers pass one space's CRYPTO data per call.
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<(), QuicTlsError> {
        self.tls.read_hs(data).map_err(|_| {
            // Surface a fatal alert as a redacted, stable code if one arose.
            if self.tls.alert().is_some() {
                handshake_failure("read_hs_fatal_alert")
            } else {
                handshake_failure("read_hs_failed")
            }
        })
    }

    /// True once the TLS handshake has fully completed for this endpoint.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.tls.is_handshaking()
    }

    /// True once 1-RTT (application) keys have been installed.
    #[must_use]
    pub fn one_rtt_keys_installed(&self) -> bool {
        self.one_rtt_keys_installed
    }

    /// True once Handshake-space keys have been installed.
    #[must_use]
    pub fn handshake_keys_installed(&self) -> bool {
        self.handshake_keys_installed
    }

    /// The peer's TLS-encoded QUIC transport parameters, once received.
    #[must_use]
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.tls.quic_transport_parameters()
    }

    /// This endpoint's exact TLS-authenticated QUIC transport-parameter offer.
    #[must_use]
    pub fn local_transport_parameters(&self) -> &[u8] {
        &self.local_transport_parameters
    }

    /// Authenticated source connection ID learned from the peer.
    #[must_use]
    pub fn peer_connection_id(&self) -> Option<ConnectionId> {
        self.peer_connection_id
    }

    /// ALPN selected by the completed TLS handshake.
    #[must_use]
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.tls.alpn_protocol()
    }

    /// Borrow the packet-protection provider holding the installed keys.
    #[must_use]
    pub fn provider(&self) -> &RustlsQuicCryptoProvider {
        &self.provider
    }

    /// Consume the driver, yielding the provider for use by the packet layer.
    #[must_use]
    pub fn into_provider(self) -> RustlsQuicCryptoProvider {
        self.provider
    }

    /// Pump pending outbound handshake segments, assemble + protect each as a
    /// long-header packet to `peer`, and send them over `endpoint`. OneRtt-level
    /// segments (post-handshake tickets) belong to the 1-RTT data plane and are
    /// skipped. Returns the sent packet flight so the caller can retransmit it on
    /// a handshake PTO.
    async fn send_pending_flight(
        &mut self,
        cx: &Cx,
        endpoint: &mut QuicUdpEndpoint,
        peer: SocketAddr,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: &mut u64,
    ) -> Result<Vec<OutgoingPacket>, QuicTlsError> {
        let segments = self.pump_outbound()?;
        let mut packets = Vec::new();
        for segment in segments {
            if segment.level == HandshakeLevel::OneRtt {
                continue;
            }
            let data =
                self.assemble_handshake_packet(&segment, dst_cid, src_cid, *packet_number)?;
            *packet_number += 1;
            packets.push(OutgoingPacket {
                dst_addr: peer,
                data,
                send_time: None,
            });
        }
        if !packets.is_empty() {
            endpoint
                .send_batch(cx, &packets)
                .await
                .map_err(|_| handshake_failure("udp_send"))?;
        }
        Ok(packets)
    }
}

async fn retransmit_handshake_flight(
    cx: &Cx,
    endpoint: &mut QuicUdpEndpoint,
    packets: &[OutgoingPacket],
) -> Result<bool, QuicTlsError> {
    if packets.is_empty() {
        return Ok(false);
    }
    endpoint
        .send_batch(cx, packets)
        .await
        .map_err(|_| handshake_failure("udp_send"))?;
    Ok(true)
}

/// Drive a client QUIC/TLS-1.3 handshake to completion over `endpoint`.
///
/// This talks to `server_addr`. The connect-side handshake derives Initial keys from
/// the client's original `dcid`, sends the ClientHello, and exchanges flights until
/// the handshake completes. On success the driver holds 1-RTT keys ready to be
/// handed to the data plane.
pub async fn client_handshake_over_udp(
    cx: &Cx,
    endpoint: &mut QuicUdpEndpoint,
    server_addr: SocketAddr,
    driver: &mut QuicHandshakeDriver,
    dcid: ConnectionId,
    client_scid: ConnectionId,
) -> Result<(), QuicTlsError> {
    driver.install_initial_keys(dcid.as_bytes())?;
    let mut packet_number = 0u64;
    let mut last_flight = driver
        .send_pending_flight(
            cx,
            endpoint,
            server_addr,
            dcid,
            client_scid,
            &mut packet_number,
        )
        .await?;
    // Wall-clock path RTT: first flight out → first response batch in.
    // Re-stamped on every retransmit so a lost flight inflates (never
    // deflates) the sample; consumers min-fold or treat it as an upper
    // bound, which is the safe direction for an in-flight cap.
    let mut flight_sent_at = Instant::now();

    for _ in 0..HANDSHAKE_MAX_FLIGHTS {
        if driver.is_complete() {
            // Retain the final flight (client Finished): if it was lost on the
            // wire the server cannot complete, and only the data plane will
            // observe the evidence (the server's retransmitted long-header
            // flight). See `QuicHandshakeDriver::final_flight`.
            driver.final_flight = last_flight;
            return Ok(());
        }
        let received = match crate::time::timeout(
            cx.now(),
            HANDSHAKE_PTO,
            endpoint.receive_batch(cx, HANDSHAKE_RECEIVE_BATCH_SIZE),
        )
        .await
        {
            Ok(Ok(packets)) => packets,
            Ok(Err(_)) => return Err(handshake_failure("udp_recv")),
            Err(_) => {
                if retransmit_handshake_flight(cx, endpoint, &last_flight).await? {
                    flight_sent_at = Instant::now();
                    continue;
                }
                return Err(handshake_failure("client_handshake_recv_timeout"));
            }
        };
        // Pump after EACH packet: e.g. after the server's Initial (ServerHello)
        // the client must pump to install Handshake keys BEFORE it can unprotect
        // the server's Handshake-level flight that may arrive in the same batch.
        for packet in &received {
            let peer_dcid = match driver.recv_handshake_packet(&packet.data) {
                Ok(peer_scid) => {
                    // RFC 9000 section 7.2: after authenticating the server's
                    // first flight, address subsequent client handshake packets
                    // to the server-selected source CID, not the original DCID.
                    // Only authenticated handshake traffic may establish the
                    // path RTT used by the source-stream BDP admission cap.
                    if driver.path_rtt_estimate_micros.is_none() {
                        driver.path_rtt_estimate_micros = Some(
                            u64::try_from(flight_sent_at.elapsed().as_micros()).unwrap_or(u64::MAX),
                        );
                    }
                    peer_scid
                }
                Err(err) if is_stale_handshake_packet_error(&err) => {
                    let _ = retransmit_handshake_flight(cx, endpoint, &last_flight).await?;
                    continue;
                }
                Err(err) => return Err(err),
            };
            let sent = driver
                .send_pending_flight(
                    cx,
                    endpoint,
                    server_addr,
                    peer_dcid,
                    client_scid,
                    &mut packet_number,
                )
                .await?;
            if !sent.is_empty() {
                last_flight = sent;
            } else if !driver.is_complete() {
                let _ = retransmit_handshake_flight(cx, endpoint, &last_flight).await?;
            }
        }
    }

    if driver.is_complete() {
        driver.final_flight = last_flight;
        Ok(())
    } else {
        Err(handshake_failure("client_handshake_incomplete"))
    }
}

/// Drive a server QUIC/TLS-1.3 handshake to completion over `endpoint`.
///
/// The accept-side handshake derives Initial keys from the client's original `dcid`
/// (read from the first Initial packet by the caller), learns the client's address
/// and source CID from the first received packet, and exchanges flights until the
/// handshake completes. Returns the validated client peer address.
pub async fn server_handshake_over_udp(
    cx: &Cx,
    endpoint: &mut QuicUdpEndpoint,
    driver: &mut QuicHandshakeDriver,
    dcid: ConnectionId,
    server_scid: ConnectionId,
) -> Result<SocketAddr, QuicTlsError> {
    let (peer_addr, early_one_rtt) =
        server_handshake_over_udp_with_early_data(cx, endpoint, driver, dcid, server_scid).await?;
    if !early_one_rtt.is_empty() {
        return Err(handshake_failure("unexpected_early_one_rtt"));
    }
    Ok(peer_addr)
}

/// Drive a server handshake while retaining bounded early 1-RTT packets for
/// the application-data owner that will consume the completed driver.
pub(crate) async fn server_handshake_over_udp_with_early_data(
    cx: &Cx,
    endpoint: &mut QuicUdpEndpoint,
    driver: &mut QuicHandshakeDriver,
    dcid: ConnectionId,
    server_scid: ConnectionId,
) -> Result<(SocketAddr, Vec<ReceivedPacket>), QuicTlsError> {
    driver.install_initial_keys(dcid.as_bytes())?;
    let mut packet_number = 0u64;
    let mut peer: Option<(SocketAddr, ConnectionId)> = None;
    let mut last_flight = Vec::new();
    let mut early_one_rtt = Vec::new();
    let mut last_early_data_resend: Option<Instant> = None;
    let mut no_peer_idle_timeouts = 0usize;

    for _ in 0..HANDSHAKE_MAX_FLIGHTS {
        if driver.is_complete() {
            return peer
                .map(|(addr, _)| (addr, early_one_rtt))
                .ok_or_else(|| handshake_failure("server_handshake_no_peer"));
        }
        let received = match crate::time::timeout(
            cx.now(),
            HANDSHAKE_PTO,
            endpoint.receive_batch(cx, HANDSHAKE_RECEIVE_BATCH_SIZE),
        )
        .await
        {
            Ok(Ok(packets)) => packets,
            Ok(Err(_)) => return Err(handshake_failure("udp_recv")),
            Err(_) => {
                if peer.is_none() {
                    no_peer_idle_timeouts = no_peer_idle_timeouts.saturating_add(1);
                    if no_peer_idle_timeouts >= HANDSHAKE_SERVER_NO_PEER_IDLE_LIMIT {
                        return Err(handshake_failure("server_handshake_recv_timeout"));
                    }
                    continue;
                }
                if retransmit_handshake_flight(cx, endpoint, &last_flight).await? {
                    continue;
                }
                return Err(handshake_failure("server_handshake_recv_timeout"));
            }
        };
        if !received.is_empty() {
            no_peer_idle_timeouts = 0;
        }
        // Pump after EACH packet so newly-derived keys are installed before the
        // next packet is processed (symmetry with the client side).
        for packet in received {
            if packet.data.first().is_none_or(|byte| byte & 0x80 == 0) {
                let Some((peer_addr, _)) = peer else {
                    continue;
                };
                if packet.src_addr != peer_addr {
                    continue;
                }
                if early_one_rtt.len() >= MAX_EARLY_ONE_RTT_PACKETS {
                    return Err(handshake_failure("early_one_rtt_queue_exhausted"));
                }
                early_one_rtt.push(packet);
                if !driver.is_complete()
                    && !last_flight.is_empty()
                    && last_early_data_resend.is_none_or(|at| at.elapsed() >= HANDSHAKE_PTO)
                {
                    last_early_data_resend = Some(Instant::now());
                    let _ = retransmit_handshake_flight(cx, endpoint, &last_flight).await?;
                }
                continue;
            }
            let peer_scid = match driver.recv_handshake_packet(&packet.data) {
                Ok(peer_scid) => peer_scid,
                Err(err) if is_stale_handshake_packet_error(&err) => {
                    if peer.is_some() {
                        let _ = retransmit_handshake_flight(cx, endpoint, &last_flight).await?;
                    }
                    continue;
                }
                Err(err) => return Err(err),
            };
            if peer.is_none() {
                peer = Some((packet.src_addr, peer_scid));
            }
            if let Some((addr, client_cid)) = peer {
                let sent = driver
                    .send_pending_flight(
                        cx,
                        endpoint,
                        addr,
                        client_cid,
                        server_scid,
                        &mut packet_number,
                    )
                    .await?;
                if !sent.is_empty() {
                    last_flight = sent;
                } else if !driver.is_complete() {
                    let _ = retransmit_handshake_flight(cx, endpoint, &last_flight).await?;
                }
            }
        }
    }

    if driver.is_complete() {
        peer.map(|(addr, _)| (addr, early_one_rtt))
            .ok_or_else(|| handshake_failure("server_handshake_no_peer"))
    } else {
        Err(handshake_failure("server_handshake_incomplete"))
    }
}

/// Build a TLS-1.3-only client config for QUIC that verifies the server chain
/// against `roots` (WebPKI) and advertises `alpn`. No insecure skip-verify path.
pub fn client_config(
    roots: Vec<CertificateDer<'static>>,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<ClientConfig>, QuicTlsError> {
    let pinned_end_entities = roots.clone();
    let mut root_store = RootCertStore::empty();
    for cert in roots {
        root_store
            .add(cert)
            .map_err(|_| handshake_failure("client_root_add_failed"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| handshake_failure("client_protocol_versions"))?;
    let mut config = if pinned_end_entities.is_empty() {
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store),
            provider,
        )
        .build()
        .map_err(|_| handshake_failure("client_verifier_build"))?;
        let verifier = webpki_server_verifier_with_exact_leaf_fallback(webpki, pinned_end_entities);
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    };
    config.alpn_protocols = alpn;
    Ok(Arc::new(config))
}

/// Build a TLS-1.3-only server config for QUIC presenting `cert_chain`/`key` and
/// advertising `alpn`.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<ServerConfig>, QuicTlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| handshake_failure("server_protocol_versions"))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|_| handshake_failure("server_single_cert"))?;
    config.alpn_protocols = alpn;
    Ok(Arc::new(config))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Canonical CA + leaf chain (P-256), valid ~100 years, generated with openssl
    // for the in-process handshake test. The leaf carries SAN DNS:localhost /
    // IP:127.0.0.1 and the serverAuth EKU that rustls-webpki requires; the client
    // trusts the CA, so this exercises the REAL WebPKI verifier path end-to-end
    // (no insecure skip-verify).
    pub const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwTCCAWigAwIBAgIUTQyiZ96ufyKHVqRYRZBXpRQABGMwCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAUMRIwEAYDVQQDDAlhdHBxLXRlc3QwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBbxlDvlrJDWhuXLXcrwcK4\n\
eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hdo4GSMIGPMBoGA1UdEQQTMBGCCWxv\n\
Y2FsaG9zdIcEfwAAATATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA\n\
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUTWWIxYJyvXlJNVcDd8An36rhuMQw\n\
HwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNzvtYwCgYIKoZIzj0EAwIDRwAw\n\
RAIgOkNWPyvljX7zxCWN9sJ/rpX7XV5ubXvNrPdV70sF8oECIGtMuJr6XEmcump1\n\
YuX2YYZ2gAU6aNU/up/PediXcN5u\n\
-----END CERTIFICATE-----\n";

    const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpE59cRbMDhBIZaha\n\
UPAvB8O86PWbkhxy/8cx/FrSa1ShRANCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBb\n\
xlDvlrJDWhuXLXcrwcK4eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hd\n\
-----END PRIVATE KEY-----\n";

    pub const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBlDCCATugAwIBAgIUYOTxo/FMMZjqCnJT+IDmJ2BNux0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAXMRUwEwYDVQQDDAxhdHBxLXRlc3QtY2EwWTATBgcqhkjOPQIB\n\
BggqhkjOPQMBBwNCAASAsNg5paEJFgZwYGu7aCzsZYPyDyjzzcT7fi3O5JHGW0xA\n\
pTqjgqykWTDkyfwdITXWXIfrx2D2+QwoGXOV4OFSo2MwYTAdBgNVHQ4EFgQUG872\n\
eUJJNl9C6SZHmR9sCRNzvtYwHwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNz\n\
vtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID\n\
RwAwRAIgFLcs0Qdsy190QfKzpvLj28srfpw6wZ2PURF20N+twm8CIFZMWnG65VsE\n\
WkX8ykcdUfalGtZ1XFOTo+aaWs+3gyI1\n\
-----END CERTIFICATE-----\n";

    pub fn parse_one_cert(pem: &str) -> CertificateDer<'static> {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        rustls_pemfile::certs(&mut reader)
            .next()
            .expect("one cert")
            .expect("valid cert pem")
    }

    fn leaf_cert() -> CertificateDer<'static> {
        parse_one_cert(LEAF_CERT_PEM)
    }

    fn ca_cert() -> CertificateDer<'static> {
        parse_one_cert(CA_CERT_PEM)
    }

    fn cert_without_eku() -> CertificateDer<'static> {
        let mut reader = std::io::BufReader::new(
            include_bytes!("../../../tests/fixtures/tls/server.crt").as_slice(),
        );
        rustls_pemfile::certs(&mut reader)
            .next()
            .expect("one cert")
            .expect("valid cert pem")
    }

    fn fixture_valid_time() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000))
    }

    fn test_server_verifier(
        roots: Vec<CertificateDer<'static>>,
        pins: Vec<CertificateDer<'static>>,
    ) -> Arc<dyn ServerCertVerifier> {
        let mut root_store = RootCertStore::empty();
        for root in roots {
            root_store.add(root).expect("valid test root");
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store),
            provider,
        )
        .build()
        .expect("test WebPKI verifier");
        webpki_server_verifier_with_exact_leaf_fallback(webpki, pins)
    }

    fn mutate_extension_value(
        cert: CertificateDer<'static>,
        oid: &str,
        mutate: impl FnOnce(&mut [u8]),
    ) -> CertificateDer<'static> {
        let mut der = cert.as_ref().to_vec();
        let (offset, len) = {
            let (remaining, parsed) =
                x509_parser::parse_x509_certificate(&der).expect("parse test certificate");
            assert!(
                remaining.is_empty(),
                "test certificate must consume full DER"
            );
            let extension = parsed
                .extensions()
                .iter()
                .find(|extension| extension.oid.to_id_string() == oid)
                .expect("test extension");
            let offset = extension.value.as_ptr() as usize - der.as_ptr() as usize;
            (offset, extension.value.len())
        };
        mutate(&mut der[offset..offset + len]);
        CertificateDer::from(der)
    }

    pub fn leaf_key() -> PrivateKeyDer<'static> {
        let mut reader = std::io::BufReader::new(LEAF_KEY_PEM.as_bytes());
        rustls_pemfile::private_key(&mut reader)
            .expect("read key pem")
            .expect("one key")
    }

    fn drive_to_completion(client: &mut QuicHandshakeDriver, server: &mut QuicHandshakeDriver) {
        for _ in 0..16 {
            for seg in client.pump_outbound().expect("client pump") {
                server.read_handshake(&seg.data).expect("server read");
            }
            for seg in server.pump_outbound().expect("server pump") {
                client.read_handshake(&seg.data).expect("client read");
            }
            if client.is_complete() && server.is_complete() {
                return;
            }
        }
        panic!("handshake did not converge within bound");
    }

    fn client_rejects_server(
        client: &mut QuicHandshakeDriver,
        server: &mut QuicHandshakeDriver,
    ) -> bool {
        'drive: for _ in 0..16 {
            for seg in client.pump_outbound().expect("client pump") {
                let _ = server.read_handshake(&seg.data);
            }
            for seg in server.pump_outbound().expect("server pump") {
                if client.read_handshake(&seg.data).is_err() {
                    return true;
                }
            }
            if client.is_complete() {
                break 'drive;
            }
        }
        false
    }

    // Client's original Destination CID; both sides derive Initial keys from it.
    const DCID_BYTES: &[u8] = &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];

    #[test]
    fn crypto_reassembler_waits_for_gaps_and_rejects_conflicting_overlap() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        assert!(
            reassembler.push(4, b"ef").expect("buffer tail").is_empty(),
            "a tail beyond the receive offset must remain buffered"
        );
        assert_eq!(
            reassembler.push(0, b"abcd").expect("fill gap"),
            vec![b"abcdef".to_vec()],
            "filling the gap must release one contiguous CRYPTO stream chunk"
        );
        assert!(
            reassembler
                .push(2, b"cdef")
                .expect("duplicate delivered range")
                .is_empty(),
            "already delivered CRYPTO bytes must be idempotent"
        );

        let mut conflicting = HandshakeCryptoReassembler::default();
        assert!(
            conflicting
                .push(2, b"cd")
                .expect("buffer first range")
                .is_empty()
        );
        assert!(matches!(
            conflicting.push(1, b"XX"),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_overlap_conflict",
            })
        ));
    }

    #[test]
    fn crypto_reassembler_bounds_disjoint_range_metadata() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        for index in 0..MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES {
            let offset = 1 + u64::try_from(index).expect("range index fits u64") * 2;
            assert!(
                reassembler
                    .push(offset, b"x")
                    .expect("range below metadata cap")
                    .is_empty()
            );
        }

        assert!(matches!(
            reassembler.push(
                1 + u64::try_from(MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES)
                    .expect("range limit fits u64")
                    * 2,
                b"x",
            ),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_range_limit",
            })
        ));
        assert_eq!(
            reassembler.pending.len(),
            MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES,
            "rejecting excess metadata must leave the accepted range set bounded"
        );

        assert_eq!(
            reassembler
                .push(0, b"x")
                .expect("receive-head data must remain admissible at the metadata cap"),
            vec![b"xx".to_vec()],
            "receive-head data and its adjacent successor are delivered immediately"
        );
        assert_eq!(
            reassembler.pending.len(),
            MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES - 1,
            "delivering the receive head must remove its adjacent retained range"
        );
        assert_eq!(
            reassembler
                .push(2, b"x")
                .expect("filling the remaining head gap must drain its successor"),
            vec![b"xx".to_vec()]
        );
        assert_eq!(
            reassembler.pending.len(),
            MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES - 2,
            "closing the head gap must reduce retained metadata"
        );
    }

    #[test]
    fn crypto_reassembler_rejection_preserves_accepted_ranges() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        reassembler
            .push(1, b"accepted")
            .expect("buffer accepted range behind initial gap");
        let accepted = reassembler.pending.clone();
        let accepted_bytes = reassembler.pending_bytes;

        assert!(matches!(
            reassembler.push(2, b"conflict"),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_overlap_conflict",
            })
        ));
        assert_eq!(reassembler.pending, accepted);
        assert_eq!(reassembler.pending_bytes, accepted_bytes);

        let mut oversized = vec![0_u8; MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES + 1];
        oversized[..8].copy_from_slice(b"accepted");
        assert!(matches!(
            reassembler.push(1, &oversized),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "crypto_buffer_limit",
            })
        ));
        assert_eq!(reassembler.pending, accepted);
        assert_eq!(reassembler.pending_bytes, accepted_bytes);
    }

    #[test]
    fn crypto_reassembler_byte_cap_does_not_block_receive_head() {
        let mut reassembler = HandshakeCryptoReassembler::default();
        assert!(
            reassembler
                .push(2, &vec![0_u8; MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES])
                .expect("fill retained byte budget behind a gap")
                .is_empty()
        );
        assert_eq!(
            reassembler.pending_bytes,
            MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES
        );

        assert_eq!(
            reassembler
                .push(0, b"x")
                .expect("isolated receive-head byte must bypass retained byte cap"),
            vec![b"x".to_vec()]
        );
        let ready = reassembler
            .push(1, b"x")
            .expect("closing the final gap must drain byte-capped successor");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].len(), MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES + 1);
        assert_eq!(&ready[0][..2], b"x\0");
        assert!(reassembler.pending.is_empty());
        assert_eq!(reassembler.pending_bytes, 0);
    }

    #[test]
    fn protected_crypto_packets_reassemble_when_lower_packet_number_arrives_late() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client initial keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server initial keys");

        let mut flight = client.pump_outbound().expect("client initial flight");
        assert_eq!(flight.len(), 1, "test expects one Initial CRYPTO segment");
        let client_hello = flight.pop().expect("ClientHello segment");
        assert_eq!(client_hello.level, HandshakeLevel::Initial);
        let split = client_hello.data.len() / 2;
        assert!(split > 0, "ClientHello must be splittable");

        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let first = client
            .assemble_handshake_packet(
                &HandshakeSegment {
                    level: HandshakeLevel::Initial,
                    data: client_hello.data[..split].to_vec(),
                },
                dcid,
                client_scid,
                0,
            )
            .expect("assemble first ClientHello half");
        let second = client
            .assemble_handshake_packet(
                &HandshakeSegment {
                    level: HandshakeLevel::Initial,
                    data: client_hello.data[split..].to_vec(),
                },
                dcid,
                client_scid,
                1,
            )
            .expect("assemble second ClientHello half");

        server
            .recv_handshake_packet(&second)
            .expect("buffer higher packet number first");
        assert!(
            server
                .pump_outbound()
                .expect("pump while ClientHello has a gap")
                .is_empty(),
            "TLS must not observe a CRYPTO suffix before its missing prefix"
        );
        server
            .recv_handshake_packet(&first)
            .expect("accept reordered lower packet number");
        assert!(
            !server
                .pump_outbound()
                .expect("pump complete ClientHello")
                .is_empty(),
            "filling the CRYPTO gap must let TLS produce the server flight"
        );
        server
            .recv_handshake_packet(&second)
            .expect("exact packet-number duplicate must be idempotent");

        let mut forged_duplicate = second;
        let final_byte = forged_duplicate
            .last_mut()
            .expect("protected packet includes an authentication tag");
        *final_byte ^= 1;
        assert!(matches!(
            server.recv_handshake_packet(&forged_duplicate),
            Err(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "packet_unprotect",
            })
        ));
    }

    /// GH#68 / RFC 9000 §14.1: an Initial packet leaves as a datagram of at
    /// least 1200 bytes, and the padded packet still authenticates and feeds
    /// TLS on the receiving side. Handshake-level packets are not expanded.
    #[test]
    fn initial_packets_are_padded_to_the_rfc_minimum_and_still_parse() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client initial keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server initial keys");

        let mut flight = client.pump_outbound().expect("client initial flight");
        assert_eq!(flight.len(), 1, "test expects one Initial CRYPTO segment");
        let client_hello = flight.pop().expect("ClientHello segment");
        assert!(
            client_hello.data.len() < MIN_INITIAL_DATAGRAM_BYTES / 2,
            "a bare ClientHello is far below the datagram minimum: {}",
            client_hello.data.len()
        );

        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let initial = client
            .assemble_handshake_packet(&client_hello, dcid, client_scid, 0)
            .expect("assemble ClientHello Initial");
        assert_eq!(
            initial.len(),
            MIN_INITIAL_DATAGRAM_BYTES,
            "the Initial datagram is expanded to exactly the RFC minimum"
        );
        // The packet is header-protected (GH#69), so only the invariant prefix
        // is readable on the wire; its Length field covers the packet number,
        // the padded ciphertext and the tag.
        let ProtectedHeaderPrefix::Long(header) =
            ProtectedHeaderPrefix::decode(&initial, 0).expect("padded Initial prefix")
        else {
            panic!("Initial packets use the long header");
        };
        assert_eq!(header.packet_type, LongPacketType::Initial);
        assert_eq!(
            header.payload_length as usize,
            initial.len() - header.packet_number_offset,
            "the Length field accounts for the padding inside the AEAD envelope"
        );
        assert_eq!(
            header
                .packet_len(initial.len())
                .expect("Length bounds the packet"),
            initial.len()
        );

        // The padded packet authenticates, and TLS consumes the ClientHello
        // through the PADDING frames.
        server
            .recv_handshake_packet(&initial)
            .expect("padded Initial authenticates and parses");
        let server_flight = server
            .pump_outbound()
            .expect("server flight after ClientHello");
        assert!(
            !server_flight.is_empty(),
            "TLS must have consumed the ClientHello behind the padding"
        );

        // Handshake-level packets are not expanded: header + CRYPTO frame
        // framing + tag stay well under 64 bytes of overhead.
        if let Some(segment) = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Handshake)
        {
            let server_scid = ConnectionId::new(&[0x55, 0x66]).expect("server scid");
            let packet = server
                .assemble_handshake_packet(segment, client_scid, server_scid, 0)
                .expect("assemble Handshake packet");
            assert!(
                packet.len() <= segment.data.len() + 64,
                "Handshake packets carry no padding: {} bytes for a {}-byte segment",
                packet.len(),
                segment.data.len()
            );
        }
    }

    #[test]
    fn real_tls13_handshake_completes_over_protected_packets() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        // RFC 9001 §5.2: Initial keys are derived from the client's original DCID
        // on BOTH sides (the server reads the DCID from the first Initial packet).
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client initial keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server initial keys");

        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        // Per-sender packet-number counter (unique-within-space suffices).
        let mut client_pn = 0u64;
        let mut server_pn = 0u64;

        // Pump-after-each-recv is REQUIRED: e.g. the client must process the
        // server's Initial (ServerHello) and pump to install Handshake keys
        // BEFORE it can unprotect the server's Handshake-level flight. Batch
        // recv-then-pump would fail on the second packet.
        // OneRtt-level segments (e.g. post-handshake NewSessionTicket) belong to
        // the 1-RTT short-header data plane, not the handshake; they are optional
        // and not needed to prove the handshake completes, so skip them here.
        let assemble_client =
            |c: &mut QuicHandshakeDriver, pn: &mut u64, out: &mut Vec<Vec<u8>>| {
                for seg in c.pump_outbound().expect("client pump") {
                    if seg.level == HandshakeLevel::OneRtt {
                        continue;
                    }
                    out.push(
                        c.assemble_handshake_packet(&seg, dcid, client_scid, *pn)
                            .expect("client assemble"),
                    );
                    *pn += 1;
                }
            };
        let assemble_server =
            |s: &mut QuicHandshakeDriver, pn: &mut u64, out: &mut Vec<Vec<u8>>| {
                for seg in s.pump_outbound().expect("server pump") {
                    if seg.level == HandshakeLevel::OneRtt {
                        continue;
                    }
                    out.push(
                        s.assemble_handshake_packet(&seg, client_scid, server_scid, *pn)
                            .expect("server assemble"),
                    );
                    *pn += 1;
                }
            };

        // Seed: the client's first flight (ClientHello over Initial).
        let mut client_to_server: Vec<Vec<u8>> = Vec::new();
        assemble_client(&mut client, &mut client_pn, &mut client_to_server);

        for _ in 0..16 {
            let mut server_to_client: Vec<Vec<u8>> = Vec::new();
            for packet in client_to_server.drain(..) {
                server.recv_handshake_packet(&packet).expect("server recv");
                assemble_server(&mut server, &mut server_pn, &mut server_to_client);
            }

            let mut next_client_to_server: Vec<Vec<u8>> = Vec::new();
            for packet in server_to_client.drain(..) {
                client.recv_handshake_packet(&packet).expect("client recv");
                assemble_client(&mut client, &mut client_pn, &mut next_client_to_server);
            }
            client_to_server = next_client_to_server;

            if client.is_complete() && server.is_complete() {
                break;
            }
        }

        assert!(
            client.is_complete() && server.is_complete(),
            "handshake over real protected packets did not complete"
        );
        assert!(
            client.one_rtt_keys_installed() && server.one_rtt_keys_installed(),
            "1-RTT keys not installed after packet handshake"
        );
        // Real AEAD keys agreed over the wire: the client decrypted the server's
        // Handshake-level Certificate flight (protected with Handshake keys), which
        // only succeeds if both sides derived matching keys from the transcript.
        assert_eq!(
            client.peer_transport_parameters(),
            Some(b"server-params".as_slice())
        );
    }

    #[test]
    fn real_tls13_handshake_completes_and_installs_one_rtt_keys() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");

        // Distinct, non-empty transport-parameter blobs prove they cross.
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        assert!(!client.is_complete());
        assert!(!server.is_complete());

        drive_to_completion(&mut client, &mut server);

        // Both sides reached a verified, completed TLS-1.3 handshake.
        assert!(client.is_complete(), "client handshake incomplete");
        assert!(server.is_complete(), "server handshake incomplete");

        // 1-RTT (application) keys were derived from the wire transcript on both.
        assert!(client.one_rtt_keys_installed(), "client missing 1-RTT keys");
        assert!(server.one_rtt_keys_installed(), "server missing 1-RTT keys");

        // Transport parameters were exchanged in both directions.
        assert_eq!(
            client.peer_transport_parameters(),
            Some(b"server-params".as_slice())
        );
        assert_eq!(
            server.peer_transport_parameters(),
            Some(b"client-params".as_slice())
        );
    }

    #[test]
    fn real_tls13_handshake_completes_with_exact_pinned_leaf() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![leaf_cert()], alpn).expect("client config");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        drive_to_completion(&mut client, &mut server);

        assert!(client.is_complete(), "client handshake incomplete");
        assert!(server.is_complete(), "server handshake incomplete");
        assert!(client.one_rtt_keys_installed() && server.one_rtt_keys_installed());
    }

    #[test]
    fn exact_leaf_shape_enforces_validity_bounds() {
        let leaf = leaf_cert();
        let server_name = ServerName::try_from("localhost").expect("server name");

        let not_yet_valid = verify_pinned_end_entity_shape(
            &leaf,
            &server_name,
            UnixTime::since_unix_epoch(Duration::from_secs(1)),
        )
        .expect_err("future certificate must fail");
        assert!(matches!(
            not_yet_valid,
            RustlsError::InvalidCertificate(CertificateError::NotValidYet)
        ));

        let expired = verify_pinned_end_entity_shape(
            &leaf,
            &server_name,
            UnixTime::since_unix_epoch(Duration::from_secs(5_000_000_000)),
        )
        .expect_err("expired certificate must fail");
        assert!(matches!(
            expired,
            RustlsError::InvalidCertificate(CertificateError::Expired)
        ));
    }

    #[test]
    fn exact_leaf_shape_requires_server_auth_and_digital_signature() {
        let server_name = ServerName::try_from("localhost").expect("server name");

        let wrong_eku = mutate_extension_value(leaf_cert(), "2.5.29.37", |value| {
            let final_oid_byte = value.last_mut().expect("EKU value");
            assert_eq!(*final_oid_byte, 1, "fixture must carry serverAuth");
            *final_oid_byte = 2;
        });
        let wrong_eku_error =
            verify_pinned_end_entity_shape(&wrong_eku, &server_name, fixture_valid_time())
                .expect_err("clientAuth-only leaf must fail");
        assert!(matches!(
            wrong_eku_error,
            RustlsError::InvalidCertificate(CertificateError::InvalidPurpose)
        ));

        let wrong_ku = mutate_extension_value(leaf_cert(), "2.5.29.15", |value| {
            *value.last_mut().expect("KeyUsage value") = 0;
        });
        let wrong_ku_error =
            verify_pinned_end_entity_shape(&wrong_ku, &server_name, fixture_valid_time())
                .expect_err("leaf without digitalSignature must fail");
        assert!(matches!(
            wrong_ku_error,
            RustlsError::InvalidCertificate(CertificateError::InvalidPurpose)
        ));
    }

    #[test]
    fn exact_leaf_shape_rejects_missing_eku_and_trailing_der() {
        let server_name = ServerName::try_from("localhost").expect("server name");

        let missing_eku_error =
            verify_pinned_end_entity_shape(&cert_without_eku(), &server_name, fixture_valid_time())
                .expect_err("pinned leaf without explicit serverAuth must fail");
        assert!(matches!(
            missing_eku_error,
            RustlsError::InvalidCertificate(CertificateError::InvalidPurpose)
        ));

        let mut trailing = leaf_cert().as_ref().to_vec();
        trailing.push(0);
        let trailing_error = verify_pinned_end_entity_shape(
            &CertificateDer::from(trailing),
            &server_name,
            fixture_valid_time(),
        )
        .expect_err("trailing DER must fail");
        assert!(matches!(
            trailing_error,
            RustlsError::InvalidCertificate(CertificateError::BadEncoding)
        ));
    }

    #[test]
    fn exact_leaf_fallback_never_overrides_standard_signature_or_name_errors() {
        let mut bad_signature = leaf_cert().as_ref().to_vec();
        let final_signature_byte = bad_signature.last_mut().expect("certificate byte");
        *final_signature_byte ^= 1;
        let bad_signature = CertificateDer::from(bad_signature);
        let verifier = test_server_verifier(vec![ca_cert()], vec![bad_signature.clone()]);
        let server_name = ServerName::try_from("localhost").expect("server name");
        let signature_error = verifier
            .verify_server_cert(&bad_signature, &[], &server_name, &[], fixture_valid_time())
            .expect_err("exact pin must not bypass bad chain signature");
        assert!(matches!(
            signature_error,
            RustlsError::InvalidCertificate(CertificateError::BadSignature)
        ));

        let leaf = leaf_cert();
        let verifier = test_server_verifier(vec![ca_cert()], vec![leaf.clone()]);
        let wrong_name = ServerName::try_from("not-localhost.example").expect("server name");
        let name_error = verifier
            .verify_server_cert(&leaf, &[], &wrong_name, &[], fixture_valid_time())
            .expect_err("exact pin must not bypass standard name rejection");
        assert!(matches!(
            name_error,
            RustlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            )
        ));
    }

    #[test]
    fn exact_pinned_leaf_still_rejects_wrong_server_name() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![leaf_cert()], alpn).expect("client config");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("not-localhost.example").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        assert!(
            client_rejects_server(&mut client, &mut server),
            "client must reject a pinned leaf with the wrong SAN"
        );
        assert!(
            !client.is_complete(),
            "client must not complete against a wrong-name pinned leaf"
        );
    }

    #[test]
    fn handshake_fails_closed_when_client_does_not_trust_server() {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        // Client trusts NO roots: the config still builds, but verification of the
        // server's certificate must fail during the handshake (fail-closed), and
        // the client must never reach completion.
        let client_cfg = client_config(Vec::new(), alpn).expect("client config builds w/o roots");

        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");

        assert!(
            client_rejects_server(&mut client, &mut server),
            "client must reject the untrusted server certificate"
        );
        assert!(
            !client.is_complete(),
            "client must not complete against an untrusted server"
        );
    }

    // -----------------------------------------------------------------------
    // GH#69 / GH#70: header protection and coalesced datagrams.
    // -----------------------------------------------------------------------

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// RFC 9001 Appendix A: the client-chosen Destination Connection ID both
    /// sides derive Initial keys from.
    const RFC9001_DCID: &str = "8394c8f03e515708";
    /// RFC 9001 A.2: unprotected client Initial header (packet number 2, 4 bytes).
    const RFC9001_A2_HEADER: &str = "c300000001088394c8f03e5157080000449e00000002";
    /// RFC 9001 A.2: the CRYPTO frame; PADDING frames fill the payload to 1162 bytes.
    const RFC9001_A2_CRYPTO_FRAME: &str = concat!(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113",
        "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1",
        "5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806",
        "048000ffff",
    );
    /// RFC 9001 A.2: the complete protected client Initial (1200 bytes).
    const RFC9001_A2_PROTECTED_PACKET: &str = concat!(
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c",
        "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89",
        "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e",
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7",
        "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7",
        "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf",
        "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2",
        "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd",
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07",
        "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d",
        "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723",
        "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd",
        "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934",
    );
    /// RFC 9001 A.3: unprotected server Initial header (packet number 1, 2 bytes).
    const RFC9001_A3_HEADER: &str = "c1000000010008f067a5502a4262b50040750001";
    /// RFC 9001 A.3: ACK + CRYPTO payload, no padding.
    const RFC9001_A3_PAYLOAD: &str = concat!(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200",
        "130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00",
        "020304",
    );
    /// RFC 9001 A.3: the complete protected server Initial (135 bytes).
    const RFC9001_A3_PROTECTED_PACKET: &str = concat!(
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3",
        "8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84",
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee",
    );

    fn rfc9001_client() -> QuicHandshakeDriver {
        let client_cfg =
            client_config(vec![ca_cert()], vec![ATP_QUIC_ALPN.to_vec()]).expect("client config");
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            Vec::new(),
        )
        .expect("client driver");
        client
            .install_initial_keys(&hex(RFC9001_DCID))
            .expect("client initial keys");
        client
    }

    fn rfc9001_server() -> QuicHandshakeDriver {
        let server_cfg = server_config(vec![leaf_cert()], leaf_key(), vec![ATP_QUIC_ALPN.to_vec()])
            .expect("server config");
        let mut server =
            QuicHandshakeDriver::server(server_cfg, Vec::new()).expect("server driver");
        server
            .install_initial_keys(&hex(RFC9001_DCID))
            .expect("server initial keys");
        server
    }

    fn long_prefix(packet: &[u8]) -> ProtectedLongHeaderPrefix {
        match ProtectedHeaderPrefix::decode(packet, 0).expect("protected prefix") {
            ProtectedHeaderPrefix::Long(prefix) => prefix,
            other => panic!("expected a long header, got {other:?}"),
        }
    }

    fn failure_code(error: &QuicTlsError) -> &'static str {
        match error {
            QuicTlsError::CryptoProviderFailure { provider, code } => {
                assert_eq!(*provider, "rustls-quic-handshake");
                code
            }
            other => panic!("expected a handshake failure code, got {other:?}"),
        }
    }

    #[test]
    fn rfc9001_a2_client_initial_protects_to_the_published_packet() {
        let mut client = rfc9001_client();
        let header = hex(RFC9001_A2_HEADER);
        let mut payload = hex(RFC9001_A2_CRYPTO_FRAME);
        payload.resize(1162, 0x00);
        let packet = client
            .protect_long_header_packet(PacketProtectionSpace::Initial, &header, 2, &payload)
            .expect("protect A.2");
        let expected = hex(RFC9001_A2_PROTECTED_PACKET);
        assert_eq!(packet.len(), 1200);
        assert_eq!(&packet[..22], &expected[..22], "protected header bytes");
        assert_eq!(packet, expected, "RFC 9001 A.2 protected client Initial");

        // The server removes header protection with the client's hp key,
        // reconstructs the packet number and authenticates the payload.
        let mut server = rfc9001_server();
        let prefix = long_prefix(&packet);
        assert_eq!(prefix.payload_length, 1182);
        assert_eq!(prefix.packet_number_offset, 18);
        assert_eq!(prefix.packet_len(packet.len()).expect("bounded"), 1200);
        let (recovered, plaintext) = server
            .unprotect_long_header_packet(&prefix, &packet)
            .expect("server unprotects A.2");
        assert_eq!(recovered.packet_type, LongPacketType::Initial);
        assert_eq!(recovered.packet_number, 2);
        assert_eq!(recovered.packet_number_len, 4);
        assert_eq!(recovered.dst_cid.as_bytes(), &hex(RFC9001_DCID)[..]);
        assert!(recovered.src_cid.is_empty());
        assert_eq!(plaintext, payload);
    }

    #[test]
    fn rfc9001_a3_server_initial_protects_to_the_published_packet() {
        let mut server = rfc9001_server();
        let header = hex(RFC9001_A3_HEADER);
        let payload = hex(RFC9001_A3_PAYLOAD);
        let packet = server
            .protect_long_header_packet(PacketProtectionSpace::Initial, &header, 1, &payload)
            .expect("protect A.3");
        assert_eq!(
            packet,
            hex(RFC9001_A3_PROTECTED_PACKET),
            "RFC 9001 A.3 protected server Initial"
        );

        let mut client = rfc9001_client();
        let prefix = long_prefix(&packet);
        assert_eq!(prefix.payload_length, 0x75);
        assert_eq!(
            prefix.packet_len(packet.len()).expect("bounded"),
            packet.len()
        );
        let (recovered, plaintext) = client
            .unprotect_long_header_packet(&prefix, &packet)
            .expect("client unprotects A.3");
        assert_eq!(
            recovered.packet_number, 1,
            "2-byte packet number reconstructed"
        );
        assert_eq!(recovered.packet_number_len, 2);
        assert!(recovered.dst_cid.is_empty());
        assert_eq!(recovered.src_cid.as_bytes(), &hex("f067a5502a4262b5")[..]);
        assert_eq!(plaintext, payload);
    }

    /// Planted negatives: every protected bit is bound to the AEAD.
    ///
    /// Flipping a masked first-byte bit, a protected packet-number byte, a
    /// ciphertext byte or a tag byte must fail authentication — and that
    /// failure is a live-key failure, never "stale".
    #[test]
    fn rfc9001_a2_planted_bit_flips_fail_authentication_and_are_not_stale() {
        let mut server = rfc9001_server();
        let packet = hex(RFC9001_A2_PROTECTED_PACKET);
        let prefix = long_prefix(&packet);
        let cases: [(&str, usize, u8); 5] = [
            ("masked packet-number-length bit", 0, 0x01),
            ("masked reserved bit", 0, 0x08),
            ("protected packet-number byte", 21, 0x80),
            ("ciphertext byte", 400, 0x01),
            ("authentication tag byte", packet.len() - 1, 0x01),
        ];
        for (label, index, bit) in cases {
            let mut tampered = packet.clone();
            tampered[index] ^= bit;
            let err = server
                .unprotect_long_header_packet(&prefix, &tampered)
                .expect_err(label);
            assert_eq!(failure_code(&err), PACKET_UNPROTECT_CODE, "{label}");
            assert!(
                !is_stale_handshake_packet_error(&err),
                "{label}: a live-key authentication failure is not stale traffic"
            );
            let err = server
                .recv_handshake_packet(&tampered)
                .expect_err("datagram entry point rejects it too");
            assert_eq!(failure_code(&err), PACKET_UNPROTECT_CODE, "{label}");
            assert!(!is_stale_handshake_packet_error(&err), "{label}");
        }
        let (recovered, _) = server
            .unprotect_long_header_packet(&prefix, &packet)
            .expect("the untampered packet still authenticates afterwards");
        assert_eq!(recovered.packet_number, 2);
    }

    fn protected_pair() -> (QuicHandshakeDriver, QuicHandshakeDriver) {
        let alpn = vec![ATP_QUIC_ALPN.to_vec()];
        let server_cfg =
            server_config(vec![leaf_cert()], leaf_key(), alpn.clone()).expect("server config");
        let client_cfg = client_config(vec![ca_cert()], alpn).expect("client config");
        let mut client = QuicHandshakeDriver::client(
            client_cfg,
            ServerName::try_from("localhost").expect("server name"),
            b"client-params".to_vec(),
        )
        .expect("client driver");
        let mut server = QuicHandshakeDriver::server(server_cfg, b"server-params".to_vec())
            .expect("server driver");
        client
            .install_initial_keys(DCID_BYTES)
            .expect("client initial keys");
        server
            .install_initial_keys(DCID_BYTES)
            .expect("server initial keys");
        (client, server)
    }

    /// GH#70 / RFC 9000 §12.2: a coalesced Initial + Handshake datagram is
    /// processed completely.
    ///
    /// Each packet is bounded by its own Length field, the Handshake keys the
    /// first packet unlocks are installed before the second is tried, and
    /// output TLS emits mid-datagram is not lost.
    #[test]
    fn coalesced_initial_and_handshake_datagram_is_fully_processed() {
        let (mut client, mut server) = protected_pair();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        let mut client_flight = client.pump_outbound().expect("client flight");
        assert_eq!(client_flight.len(), 1);
        let client_initial = client
            .assemble_handshake_packet(&client_flight.remove(0), dcid, client_scid, 0)
            .expect("client Initial");
        server
            .recv_handshake_packet(&client_initial)
            .expect("server accepts ClientHello");

        let server_flight = server.pump_outbound().expect("server flight");
        let mut datagram = Vec::new();
        let mut boundaries = Vec::new();
        let mut handshake_packets = 0usize;
        for (packet_number, segment) in server_flight
            .iter()
            .filter(|segment| segment.level != HandshakeLevel::OneRtt)
            .enumerate()
        {
            handshake_packets += usize::from(segment.level == HandshakeLevel::Handshake);
            let packet = server
                .assemble_handshake_packet(segment, client_scid, server_scid, packet_number as u64)
                .expect("server packet");
            datagram.extend_from_slice(&packet);
            boundaries.push(datagram.len());
        }
        assert!(
            boundaries.len() >= 2 && handshake_packets >= 1,
            "the server flight must span Initial and Handshake packets: {boundaries:?}"
        );
        // A duplicate of the Initial after the Handshake flight forces the
        // driver to stage TLS output (the client Finished) mid-datagram.
        let duplicate_start = datagram.len();
        let duplicate_initial = datagram[..boundaries[0]].to_vec();
        datagram.extend_from_slice(&duplicate_initial);
        // Trailing datagram padding must be ignored.
        datagram.extend_from_slice(&[0u8; 7]);

        // Each coalesced packet is bounded by its own Length field, not the
        // datagram end.
        let first = long_prefix(&datagram);
        assert_eq!(first.packet_type, LongPacketType::Initial);
        assert_eq!(
            first.packet_len(datagram.len()).expect("first bound"),
            boundaries[0]
        );
        let second = long_prefix(&datagram[boundaries[0]..]);
        assert_eq!(second.packet_type, LongPacketType::Handshake);
        assert_eq!(
            second
                .packet_len(datagram.len() - boundaries[0])
                .expect("second bound")
                + boundaries[0],
            boundaries[1]
        );
        let duplicate = long_prefix(&datagram[duplicate_start..]);
        assert_eq!(duplicate.packet_type, LongPacketType::Initial);

        assert!(!client.handshake_keys_installed());
        let peer = client
            .recv_handshake_packet(&datagram)
            .expect("coalesced datagram");
        assert_eq!(peer, server_scid);
        assert!(
            client.handshake_keys_installed(),
            "the ServerHello in the first packet installed Handshake keys mid-datagram"
        );
        assert!(
            client.handshake_recv_packet_numbers[0].contains(&0),
            "Initial packet 0 authenticated"
        );
        assert_eq!(
            client.handshake_recv_packet_numbers[1].len(),
            handshake_packets,
            "every coalesced Handshake packet authenticated"
        );
        assert!(
            client.is_complete(),
            "the client read the server Finished from the coalesced Handshake packet"
        );
        assert!(
            client
                .staged_segments
                .iter()
                .any(|segment| segment.level == HandshakeLevel::Handshake),
            "the client Finished emitted between coalesced packets is staged, not dropped"
        );
        let client_flight = client.pump_outbound().expect("client pump");
        assert!(
            client_flight
                .iter()
                .any(|segment| segment.level == HandshakeLevel::Handshake),
            "pump_outbound hands out the staged Finished"
        );
        assert!(client.staged_segments.is_empty());

        // The staged flight is a real Finished: the server completes on it.
        for (client_pn, segment) in (1u64..).zip(
            client_flight
                .iter()
                .filter(|segment| segment.level != HandshakeLevel::OneRtt),
        ) {
            let packet = client
                .assemble_handshake_packet(segment, server_scid, client_scid, client_pn)
                .expect("client packet");
            server
                .recv_handshake_packet(&packet)
                .expect("server accepts client Finished");
        }
        assert!(server.is_complete());
    }

    /// GH#70: `recv_handshake_packet` failures are classified by key state.
    /// Only traffic this driver holds no live keys for is stale; a bad tag
    /// under live keys surfaces as `packet_unprotect`.
    #[test]
    fn handshake_unprotect_failures_are_classified_by_key_state() {
        let (mut client, mut server) = protected_pair();
        let dcid = ConnectionId::new(DCID_BYTES).expect("dcid");
        let client_scid = ConnectionId::new(&[0x11, 0x22, 0x33, 0x44]).expect("client scid");
        let server_scid = ConnectionId::new(&[0x55, 0x66, 0x77, 0x88]).expect("server scid");

        let mut client_flight = client.pump_outbound().expect("client flight");
        let client_initial = client
            .assemble_handshake_packet(&client_flight.remove(0), dcid, client_scid, 0)
            .expect("client Initial");
        server
            .recv_handshake_packet(&client_initial)
            .expect("server accepts ClientHello");
        let server_flight = server.pump_outbound().expect("server flight");
        let server_initial_segment = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Initial)
            .expect("ServerHello segment");
        let server_handshake_segment = server_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Handshake)
            .expect("server Handshake segment");
        let server_initial = server
            .assemble_handshake_packet(server_initial_segment, client_scid, server_scid, 0)
            .expect("server Initial");
        let server_handshake = server
            .assemble_handshake_packet(server_handshake_segment, client_scid, server_scid, 1)
            .expect("server Handshake");

        // (1) Keys not derived yet: a Handshake packet before the ServerHello
        // was processed. Stale-class (ignorable), TLS state untouched.
        let err = client
            .recv_handshake_packet(&server_handshake)
            .expect_err("no Handshake keys yet");
        assert_eq!(failure_code(&err), PACKET_KEYS_UNAVAILABLE_CODE);
        assert!(is_stale_handshake_packet_error(&err));
        assert!(client.handshake_recv_packet_numbers[1].is_empty());

        // (2) Live keys, corrupted tag: a real authentication failure.
        let mut forged = server_initial.clone();
        *forged.last_mut().expect("tag byte") ^= 0x01;
        let err = client
            .recv_handshake_packet(&forged)
            .expect_err("bad tag under live Initial keys");
        assert_eq!(failure_code(&err), PACKET_UNPROTECT_CODE);
        assert!(
            !is_stale_handshake_packet_error(&err),
            "a live-key authentication failure must surface, not retry"
        );
        assert!(client.handshake_recv_packet_numbers[0].is_empty());

        // (3) The same packets in order authenticate once the keys exist.
        client
            .recv_handshake_packet(&server_initial)
            .expect("ServerHello");
        let _ = client.pump_outbound().expect("install Handshake keys");
        assert!(client.handshake_keys_installed());
        client
            .recv_handshake_packet(&server_handshake)
            .expect("Handshake packet after keys exist");

        // (4) Keys discarded: a retransmitted client Initial after the server
        // dropped its Initial keys is stale-class.
        server
            .provider_mut()
            .discard_keys(PacketProtectionSpace::Initial)
            .expect("discard Initial keys");
        let err = server
            .recv_handshake_packet(&client_initial)
            .expect_err("Initial after Initial keys were discarded");
        assert_eq!(failure_code(&err), PACKET_KEYS_DISCARDED_CODE);
        assert!(is_stale_handshake_packet_error(&err));

        // (5) A coalesced datagram whose first packet is stale but whose second
        // authenticates is a success; one that only contains stale packets
        // reports the first packet's classification.
        let mut mixed = client_initial.clone();
        let client_flight = client.pump_outbound().expect("client Finished");
        let finished = client_flight
            .iter()
            .find(|segment| segment.level == HandshakeLevel::Handshake)
            .expect("client Finished segment");
        let client_handshake = client
            .assemble_handshake_packet(finished, server_scid, client_scid, 1)
            .expect("client Handshake");
        mixed.extend_from_slice(&client_handshake);
        assert_eq!(
            server
                .recv_handshake_packet(&mixed)
                .expect("stale Initial + live Handshake"),
            client_scid
        );
        assert!(server.is_complete());
        let mut only_stale = client_initial.clone();
        only_stale.extend_from_slice(&client_initial);
        let err = server
            .recv_handshake_packet(&only_stale)
            .expect_err("two stale packets");
        assert_eq!(failure_code(&err), PACKET_KEYS_DISCARDED_CODE);
        assert!(is_stale_handshake_packet_error(&err));
    }
}
