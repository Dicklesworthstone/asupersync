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
use crate::net::quic_core::{ConnectionId, LongHeader, LongPacketType, PacketHeader};
use crate::net::quic_native::endpoint::{OutgoingPacket, QuicUdpEndpoint};
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

pub(crate) fn is_stale_handshake_packet_error(error: &QuicTlsError) -> bool {
    matches!(
        error,
        QuicTlsError::CryptoProviderFailure { provider, code }
            if *provider == "rustls-quic-handshake" && *code == "packet_unprotect"
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
            if new_pending_bytes > MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES {
                return Err(handshake_failure("crypto_buffer_limit"));
            }
            if self.pending.len() >= MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES {
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
    /// Per-level cumulative CRYPTO send offset (indexed Initial=0/Handshake=1/OneRtt=2).
    crypto_send_offset: [u64; 3],
    /// Exact authenticated packet numbers already accepted for Initial/Handshake.
    handshake_recv_packet_numbers: [BTreeSet<u64>; 2],
    /// Per-level QUIC CRYPTO stream reassembly for reordered packets.
    handshake_crypto_reassembly: [HandshakeCryptoReassembler; 2],
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
    /// Start a client handshake against `server_name`, advertising `transport_params`.
    pub fn client(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        let conn = ClientConnection::new(config, Version::V1, server_name, transport_params)
            .map_err(|_| handshake_failure("client_connection_init"))?;
        let provider = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Client)?;
        Ok(Self::new(Connection::Client(conn), provider))
    }

    /// Start a server handshake, advertising `transport_params`.
    pub fn server(
        config: Arc<ServerConfig>,
        transport_params: Vec<u8>,
    ) -> Result<Self, QuicTlsError> {
        let conn = ServerConnection::new(config, Version::V1, transport_params)
            .map_err(|_| handshake_failure("server_connection_init"))?;
        let provider = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Server)?;
        Ok(Self::new(Connection::Server(conn), provider))
    }

    fn new(tls: Connection, provider: RustlsQuicCryptoProvider) -> Self {
        Self {
            tls,
            provider,
            transcript: QuicHandshakeTranscript::new(),
            write_level: HandshakeLevel::Initial,
            handshake_keys_installed: false,
            one_rtt_keys_installed: false,
            crypto_send_offset: [0; 3],
            handshake_recv_packet_numbers: [BTreeSet::new(), BTreeSet::new()],
            handshake_crypto_reassembly: [
                HandshakeCryptoReassembler::default(),
                HandshakeCryptoReassembler::default(),
            ],
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

    /// Assemble a protected long-header (Initial/Handshake) QUIC packet carrying
    /// `segment`'s CRYPTO bytes. Mirrors the data-plane 1-RTT assembly pattern:
    /// the long header is sent in the clear and authenticated as AEAD associated
    /// data; this implementation does not apply QUIC header protection (both ends
    /// are asupersync), so a packet is `header || ciphertext || tag`.
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
        let plaintext = payload.to_vec();

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

        let protected = self.provider.protect_packet(PacketProtectionRequest {
            space,
            key_phase: false,
            packet_number,
            associated_data: &header_bytes,
            payload: &plaintext,
        })?;

        let mut packet = Vec::with_capacity(
            header_bytes.len() + protected.ciphertext.len() + protected.tag.len(),
        );
        packet.extend_from_slice(&header_bytes);
        packet.extend_from_slice(&protected.ciphertext);
        packet.extend_from_slice(&protected.tag);

        self.crypto_send_offset[level_index(segment.level)] += segment.data.len() as u64;
        Ok(packet)
    }

    /// Parse a received protected long-header (Initial/Handshake) packet, unprotect
    /// it with the installed keys for its space, and feed its CRYPTO bytes to the
    /// TLS state machine. Returns the peer's source connection ID (so a server can
    /// address its replies to the client's chosen CID). CRYPTO data is reassembled
    /// by offset within each packet-number space, so reordered packets are fed to
    /// TLS only after every preceding byte is available.
    pub fn recv_handshake_packet(&mut self, packet: &[u8]) -> Result<ConnectionId, QuicTlsError> {
        let (header, consumed) = PacketHeader::decode(packet, 0)
            .map_err(|_| handshake_failure("packet_header_decode"))?;
        let PacketHeader::Long(long_header) = header else {
            return Err(handshake_failure("expected_long_header"));
        };
        let peer_src_cid = long_header.src_cid;
        let Some(space) = long_packet_type_space(long_header.packet_type) else {
            return Err(handshake_failure("unexpected_long_packet_type"));
        };
        let space_index = handshake_packet_space_index(space)
            .ok_or_else(|| handshake_failure("unexpected_crypto_packet_space"))?;
        let already_seen =
            self.handshake_recv_packet_numbers[space_index].contains(&long_header.packet_number);
        if consumed > packet.len() {
            return Err(handshake_failure("packet_header_overrun"));
        }
        let header_bytes = &packet[..consumed];
        let body = &packet[consumed..];
        if body.len() < QUIC_AEAD_TAG_LEN {
            return Err(handshake_failure("packet_body_too_short"));
        }
        let tag_offset = body.len() - QUIC_AEAD_TAG_LEN;
        let mut tag = [0u8; QUIC_AEAD_TAG_LEN];
        tag.copy_from_slice(&body[tag_offset..]);
        let protected = ProtectedPacket {
            space,
            key_phase: false,
            packet_number: long_header.packet_number,
            ciphertext: body[..tag_offset].to_vec(),
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
            .unprotect_packet(&protected, header_bytes)
            .map_err(|_| handshake_failure("packet_unprotect"))?;

        // A packet number is only a replay key after the packet authenticates.
        // Returning before AEAD verification would let an attacker forge the
        // cleartext long header of a previously seen packet number and have the
        // receive loop treat it as successful handshake traffic (including RTT
        // sampling) without possessing the packet-protection key.
        if already_seen {
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
        let mut buf: &[u8] = &unprotected.plaintext;
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
        self.handshake_recv_packet_numbers[space_index].insert(long_header.packet_number);
        Ok(peer_src_cid)
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
        let mut segments = Vec::new();
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
        Ok(segments)
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
            match driver.recv_handshake_packet(&packet.data) {
                Ok(_) => {
                    // Only authenticated handshake traffic may establish the
                    // path RTT used by the source-stream BDP admission cap.
                    if driver.path_rtt_estimate_micros.is_none() {
                        driver.path_rtt_estimate_micros = Some(
                            u64::try_from(flight_sent_at.elapsed().as_micros()).unwrap_or(u64::MAX),
                        );
                    }
                }
                Err(err) if is_stale_handshake_packet_error(&err) => {
                    let _ = retransmit_handshake_flight(cx, endpoint, &last_flight).await?;
                    continue;
                }
                Err(err) => return Err(err),
            }
            let sent = driver
                .send_pending_flight(
                    cx,
                    endpoint,
                    server_addr,
                    dcid,
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
    driver.install_initial_keys(dcid.as_bytes())?;
    let mut packet_number = 0u64;
    let mut peer: Option<(SocketAddr, ConnectionId)> = None;
    let mut last_flight = Vec::new();
    let mut no_peer_idle_timeouts = 0usize;

    for _ in 0..HANDSHAKE_MAX_FLIGHTS {
        if driver.is_complete() {
            return peer
                .map(|(addr, _)| addr)
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
        for packet in &received {
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
        peer.map(|(addr, _)| addr)
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
mod tests {
    use super::*;

    // Canonical CA + leaf chain (P-256), valid ~100 years, generated with openssl
    // for the in-process handshake test. The leaf carries SAN DNS:localhost /
    // IP:127.0.0.1 and the serverAuth EKU that rustls-webpki requires; the client
    // trusts the CA, so this exercises the REAL WebPKI verifier path end-to-end
    // (no insecure skip-verify).
    const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
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

    const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
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

    fn parse_one_cert(pem: &str) -> CertificateDer<'static> {
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

    fn leaf_key() -> PrivateKeyDer<'static> {
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
}
