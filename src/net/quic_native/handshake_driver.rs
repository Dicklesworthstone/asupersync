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

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
use crate::net::atp::protocol::varint::{VARINT_MAX, VarInt};
use crate::net::quic_core::{
    ConnectionId, LongHeader, LongPacketType, PacketHeader, ProtectedHeaderPrefix,
    ProtectedLongHeaderPrefix, RetryHeader, TransportParameters, apply_header_protection,
    decode_packet_number_reconstruct, header_protection_sample, remove_header_protection,
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
/// Ceiling for the server's handshake PTO, which doubles on each timeout
/// without progress.
const HANDSHAKE_MAX_PTO: Duration = Duration::from_millis(12_000);
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

/// A datagram's first packet declared a Length past the datagram's end.
pub(crate) const PACKET_LENGTH_OVERRUN_CODE: &str = "packet_length_overrun";
/// A packet's Source Connection ID is not the one the peer's first accepted
/// packet carried. RFC 9000 section 7.2 says such a packet is discarded.
pub(crate) const PEER_CONNECTION_ID_CHANGED_CODE: &str = "peer_connection_id_changed";
/// An Initial packet held a frame that does not decode.
pub(crate) const INITIAL_FRAME_DECODE_CODE: &str = "initial_frame_decode";
/// CRYPTO reassembly refused an Initial packet's bytes: they differ from
/// bytes already buffered at the same offsets, or exceed the offset, byte or
/// range limits.
pub(crate) const INITIAL_CRYPTO_REJECTED_CODE: &str = "initial_crypto_rejected";
/// Failure code: the peer closed the connection with CRYPTO_ERROR during the
/// handshake, i.e. its TLS stack sent an alert (RFC 9001 section 4.8).
/// [`QuicHandshakeDriver::peer_close_error_code`] has the exact code.
pub(crate) const PEER_CRYPTO_ERROR_CLOSE_CODE: &str = "peer_closed_crypto_error";
/// Failure code: the peer closed the connection during the handshake with an
/// error code other than CRYPTO_ERROR.
pub(crate) const PEER_CLOSE_CODE: &str = "peer_closed";
/// RFC 9001 section 4.8: CRYPTO_ERROR codes are this base plus the TLS alert.
const CRYPTO_ERROR_BASE: u64 = 0x0100;

/// True for a packet that failed to authenticate under live keys or was not
/// even well-formed enough to try: a forgery from anyone who saw the
/// cleartext Initial, a bit-flipped datagram, or a stray. RFC 9000 §12.2
/// requires such packets to be discarded; they must never end a handshake
/// that an authenticated peer is still driving.
///
/// Anyone who saw the client's first Initial can derive the Initial keys from
/// its Destination Connection ID, so an Initial that authenticates can still
/// be forged. Such a packet is discarded too when it has a frame that does
/// not decode (none of its frames takes effect) or CRYPTO bytes reassembly
/// refuses (the packet ends at that frame). So is a packet in any space whose
/// Source Connection ID changed.
pub(crate) fn is_unauthenticated_handshake_packet_error(error: &QuicTlsError) -> bool {
    matches!(
        error,
        QuicTlsError::CryptoProviderFailure { provider, code }
            if *provider == "rustls-quic-handshake"
                && matches!(*code,
                    PACKET_UNPROTECT_CODE | PACKET_LENGTH_OVERRUN_CODE
                        | PEER_CONNECTION_ID_CHANGED_CODE | INITIAL_FRAME_DECODE_CODE
                        | INITIAL_CRYPTO_REJECTED_CODE
                        | "packet_header_decode" | "packet_body_too_short"
                        | "expected_long_header" | "unexpected_long_packet_type"
                        | "unexpected_crypto_packet_space")
    )
}

/// RFC 9001 §5.8 QUIC v1 Retry integrity key and nonce.
const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// The RFC 9001 §5.8 pseudo-packet: the original DCID, then the Retry packet
/// without its integrity tag.
fn retry_pseudo_packet(original_dcid: ConnectionId, retry_without_tag: &[u8]) -> Option<Vec<u8>> {
    let mut pseudo_packet = Vec::with_capacity(1 + original_dcid.len() + retry_without_tag.len());
    pseudo_packet.push(u8::try_from(original_dcid.len()).ok()?);
    pseudo_packet.extend_from_slice(original_dcid.as_bytes());
    pseudo_packet.extend_from_slice(retry_without_tag);
    Some(pseudo_packet)
}

/// Integrity tag for a Retry the server sends in answer to an Initial that
/// carried `original_dcid`.
pub(crate) fn retry_integrity_tag(
    original_dcid: ConnectionId,
    retry_without_tag: &[u8],
) -> Option<[u8; QUIC_AEAD_TAG_LEN]> {
    use aes_gcm::aead::{AeadInOut, KeyInit};
    use aes_gcm::{Aes128Gcm, Nonce};

    let pseudo_packet = retry_pseudo_packet(original_dcid, retry_without_tag)?;
    let cipher = Aes128Gcm::new_from_slice(&RETRY_INTEGRITY_KEY).ok()?;
    let nonce = Nonce::try_from(RETRY_INTEGRITY_NONCE.as_slice()).ok()?;
    let mut plaintext = [];
    let tag = cipher
        .encrypt_inout_detached(&nonce, &pseudo_packet, plaintext.as_mut_slice().into())
        .ok()?;
    tag.as_slice().try_into().ok()
}

/// Verify the RFC 9001 §5.8 Retry pseudo-packet with the QUIC v1 fixed key.
/// Verify the bytes as received: the Retry header's unused bits participate in
/// the integrity tag even though their value has no protocol meaning.
/// Whether `datagram` starts with a short-header packet addressed to `cid`.
fn is_short_header_for(datagram: &[u8], cid: ConnectionId) -> bool {
    matches!(
        ProtectedHeaderPrefix::decode(datagram, cid.len()),
        Ok(ProtectedHeaderPrefix::Short { dst_cid, .. }) if dst_cid == cid
    )
}

fn validated_client_retry(
    datagram: &[u8],
    original_dcid: ConnectionId,
    client_scid: ConnectionId,
) -> Option<RetryHeader> {
    use aes_gcm::aead::{AeadInOut, KeyInit};
    use aes_gcm::{Aes128Gcm, Nonce, Tag};

    let ProtectedHeaderPrefix::Retry(header) = ProtectedHeaderPrefix::decode(datagram, 0).ok()?
    else {
        return None;
    };
    if header.version != 1
        || header.dst_cid != client_scid
        || header.src_cid == original_dcid
        || header.token.is_empty()
    {
        return None;
    }

    let tag_offset = datagram.len().checked_sub(QUIC_AEAD_TAG_LEN)?;
    let pseudo_packet = retry_pseudo_packet(original_dcid, &datagram[..tag_offset])?;

    let cipher = Aes128Gcm::new_from_slice(&RETRY_INTEGRITY_KEY).ok()?;
    let nonce = Nonce::try_from(RETRY_INTEGRITY_NONCE.as_slice()).ok()?;
    let tag = Tag::try_from(header.integrity_tag.as_slice()).ok()?;
    let mut plaintext = [];
    // The AEAD implementation verifies the tag in constant time; do not
    // substitute a comparison against a locally generated tag.
    cipher
        .decrypt_inout_detached(
            &nonce,
            &pseudo_packet,
            plaintext.as_mut_slice().into(),
            &tag,
        )
        .ok()?;
    Some(header)
}

fn validate_retry_transport_parameters(
    encoded: &[u8],
    original_dcid: ConnectionId,
    retry_scid: ConnectionId,
    server_scid: ConnectionId,
) -> Result<(), QuicTlsError> {
    let parameters = TransportParameters::decode(encoded)
        .map_err(|_| handshake_failure("retry_transport_parameters_decode"))?;
    for (id, expected, code) in [
        (
            0x00,
            original_dcid,
            "retry_original_destination_cid_mismatch",
        ),
        (0x0f, server_scid, "retry_initial_source_cid_mismatch"),
        (0x10, retry_scid, "retry_source_cid_mismatch"),
    ] {
        if !parameters.unknown.iter().any(|parameter| {
            parameter.id == id && parameter.value.as_slice() == expected.as_bytes()
        }) {
            return Err(handshake_failure(code));
        }
    }
    Ok(())
}

/// Leave room for the largest legal varint widths in both the Initial header
/// and CRYPTO frame. Normally Initials fit 1200 bytes. A Retry token already
/// carried in a larger peer datagram can require a larger Initial; cap that
/// case at the configured datagram limit and the IPv4 UDP payload maximum.
/// Prefer room for 128 CRYPTO bytes when the configured limit permits it, and
/// refuse a token that leaves less: a near-maximum Retry token would otherwise
/// split every retransmitted ClientHello into hundreds of datagrams.
fn initial_crypto_chunk_size(
    token_len: usize,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    max_packet_size: usize,
) -> Option<usize> {
    const MIN_INITIAL_CRYPTO_CHUNK: usize = 128;
    let overhead = token_len
        .checked_add(dst_cid.len())?
        .checked_add(src_cid.len())?
        .checked_add(64)?;
    let datagram_budget = MIN_INITIAL_DATAGRAM_BYTES
        .max(overhead.checked_add(MIN_INITIAL_CRYPTO_CHUNK)?)
        .min(max_packet_size)
        .min(65_507);
    let chunk = datagram_budget.checked_sub(overhead)?;
    if datagram_budget < MIN_INITIAL_DATAGRAM_BYTES || chunk < MIN_INITIAL_CRYPTO_CHUNK {
        return None;
    }
    Some(chunk)
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
    // Ranges are disjoint and non-adjacent. A deque lets a range grow in either
    // direction without copying its accepted prefix/suffix on every packet.
    pending: BTreeMap<u64, VecDeque<u8>>,
    pending_bytes: usize,
}

impl HandshakeCryptoReassembler {
    fn push(&mut self, mut offset: u64, mut data: &[u8]) -> Result<Vec<Vec<u8>>, QuicTlsError> {
        let data_len =
            u64::try_from(data.len()).map_err(|_| handshake_failure("crypto_offset_overflow"))?;
        let end = offset
            .checked_add(data_len)
            .ok_or_else(|| handshake_failure("crypto_offset_overflow"))?;
        if !data.is_empty() && end > VARINT_MAX {
            return Err(handshake_failure("crypto_offset_overflow"));
        }
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

        // There is at most one predecessor intersecting this fragment. All
        // other affected ranges start inside it, or exactly at its end. Since
        // accepted ranges are already coalesced, no full-map scan or repeated
        // search for transitive adjacency is necessary.
        let mut merged_start = offset;
        if let Some((&start, bytes)) = self.pending.range(..offset).next_back() {
            let existing_end = start
                .checked_add(
                    u64::try_from(bytes.len())
                        .map_err(|_| handshake_failure("crypto_offset_overflow"))?,
                )
                .ok_or_else(|| handshake_failure("crypto_offset_overflow"))?;
            if existing_end >= offset {
                merged_start = start;
            }
        }

        // Preflight every overlap and both retention budgets before changing
        // the accepted state or allocating a merged payload. The prefix and
        // suffix lengths name existing bytes *outside* the incoming fragment;
        // its matching interior can replace all smaller interior ranges.
        let mut affected = Vec::new();
        let mut merged_end = end;
        let mut replaced_bytes = 0_usize;
        let mut largest = None;
        for (&start, bytes) in self.pending.range(merged_start..=end) {
            let existing_end = start
                .checked_add(
                    u64::try_from(bytes.len())
                        .map_err(|_| handshake_failure("crypto_offset_overflow"))?,
                )
                .ok_or_else(|| handshake_failure("crypto_offset_overflow"))?;
            let overlap_start = offset.max(start);
            let overlap_end = end.min(existing_end);
            if overlap_start < overlap_end {
                let overlap_len = usize::try_from(overlap_end - overlap_start)
                    .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
                let data_at = usize::try_from(overlap_start - offset)
                    .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
                let existing_at = usize::try_from(overlap_start - start)
                    .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
                if !bytes
                    .range(existing_at..existing_at + overlap_len)
                    .eq(data[data_at..data_at + overlap_len].iter())
                {
                    return Err(handshake_failure("crypto_overlap_conflict"));
                }
            }
            let prefix_len = usize::try_from(offset.saturating_sub(start))
                .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
            let suffix_at = usize::try_from(end.min(existing_end) - start)
                .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
            affected.push((start, prefix_len, suffix_at));
            replaced_bytes = replaced_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| handshake_failure("crypto_buffer_limit"))?;
            merged_end = merged_end.max(existing_end);
            if largest.is_none_or(|(_, _, len)| bytes.len() > len) {
                largest = Some((start, existing_end, bytes.len()));
            }
        }
        let merged_len = usize::try_from(merged_end - merged_start)
            .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
        let new_pending_bytes = self
            .pending_bytes
            .checked_sub(replaced_bytes)
            .ok_or_else(|| handshake_failure("crypto_reassembly_state"))?
            .checked_add(merged_len)
            .ok_or_else(|| handshake_failure("crypto_buffer_limit"))?;
        // These budgets cover data retained behind a gap. Receive-head data
        // must remain admissible when either budget is full, so filling the
        // gap can release the accepted data to TLS immediately.
        let drains_from_head = merged_start == self.next_offset;
        if !drains_from_head && new_pending_bytes > MAX_BUFFERED_HANDSHAKE_CRYPTO_BYTES {
            return Err(handshake_failure("crypto_buffer_limit"));
        }
        if !drains_from_head
            && self.pending.len() - affected.len() >= MAX_BUFFERED_HANDSHAKE_CRYPTO_RANGES
        {
            return Err(handshake_failure("crypto_range_limit"));
        }
        if merged_len == replaced_bytes {
            // A contained retransmission adds nothing. In particular, it must
            // not clone or replace a large accepted range for one repeated byte.
            return Ok(Vec::new());
        }

        let merged = if let Some((largest_start, largest_end, _)) = largest {
            let data_prefix_len = usize::try_from(largest_start.saturating_sub(offset))
                .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
            let data_suffix_at = usize::try_from(end.min(largest_end) - offset)
                .map_err(|_| handshake_failure("crypto_offset_overflow"))?;
            let mut merged = self
                .pending
                .remove(&largest_start)
                .ok_or_else(|| handshake_failure("crypto_reassembly_state"))?;
            // Reuse the largest allocation. Adjacent append/prepend arrivals
            // are amortized linear; a surviving smaller exterior range is
            // copied into a range at least as large. Overlap comparison and
            // interior replacement visit at most the incoming fragment's bytes.
            merged.reserve(merged_len - merged.len());
            for &byte in data[..data_prefix_len].iter().rev() {
                merged.push_front(byte);
            }
            merged.extend(data[data_suffix_at..].iter().copied());
            for (start, prefix_len, suffix_at) in affected {
                if start == largest_start {
                    continue;
                }
                let existing = self
                    .pending
                    .remove(&start)
                    .expect("preflight retained every affected CRYPTO range");
                for &byte in existing.range(..prefix_len).rev() {
                    merged.push_front(byte);
                }
                merged.extend(existing.range(suffix_at..).copied());
            }
            debug_assert_eq!(merged.len(), merged_len);
            merged
        } else {
            VecDeque::from(data.to_vec())
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
            ready.push(Vec::from(bytes));
        }
        Ok(ready)
    }
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
    /// A validated Retry token is repeated in every subsequent client Initial.
    initial_token: Vec<u8>,
    /// Source connection ID of the Retry this client accepted, if any.
    retry_source_cid: Option<ConnectionId>,
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
    /// The error code of a CONNECTION_CLOSE the peer sent in an Initial or
    /// Handshake packet, which ended this handshake.
    peer_close_error_code: Option<u64>,
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
            initial_token: Vec::new(),
            retry_source_cid: None,
            handshake_recv_packet_numbers: [BTreeSet::new(), BTreeSet::new()],
            handshake_recv_largest_packet_number: [None, None],
            handshake_crypto_reassembly: [
                HandshakeCryptoReassembler::default(),
                HandshakeCryptoReassembler::default(),
            ],
            staged_segments: Vec::new(),
            final_flight: Vec::new(),
            peer_close_error_code: None,
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
        let offset = self.next_crypto_offset(segment.level);
        let packet =
            self.assemble_handshake_packet_at(segment, offset, dst_cid, src_cid, packet_number)?;
        self.crypto_send_offset[level_index(segment.level)] += segment.data.len() as u64;
        Ok(packet)
    }

    /// The CRYPTO offset the next `level` segment is sent at.
    pub(crate) fn next_crypto_offset(&self, level: HandshakeLevel) -> u64 {
        self.crypto_send_offset[level_index(level)]
    }

    /// Packet numbers authenticated so far in an Initial or Handshake space.
    #[cfg(test)]
    pub(crate) fn received_handshake_packet_numbers(&self, level: HandshakeLevel) -> Vec<u64> {
        self.handshake_recv_packet_numbers
            .get(level_index(level))
            .map(|numbers| numbers.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Protect CRYPTO bytes already sent at `offset` again, under a new packet
    /// number. A PTO retransmission resends the same data, but RFC 9000 section
    /// 12.3 forbids reusing a packet number within its space.
    pub(crate) fn assemble_handshake_packet_at(
        &mut self,
        segment: &HandshakeSegment,
        offset: u64,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: u64,
    ) -> Result<Vec<u8>, QuicTlsError> {
        let mut payload = BytesMut::new();
        QuicFrame::Crypto {
            offset: VarInt::from_u64_unchecked(offset),
            data: Bytes::copy_from_slice(&segment.data),
        }
        .encode(&mut payload)
        .map_err(|_| handshake_failure("crypto_frame_encode"))?;
        self.assemble_long_header_packet(
            segment.level,
            payload.to_vec(),
            true,
            dst_cid,
            src_cid,
            packet_number,
        )
    }

    /// Protect `plaintext` (encoded frames) as one Initial or Handshake packet.
    /// With `pad_initial`, an Initial packet is padded to the RFC 9000 section
    /// 14.1 minimum datagram size.
    fn assemble_long_header_packet(
        &mut self,
        level: HandshakeLevel,
        mut plaintext: Vec<u8>,
        pad_initial: bool,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: u64,
    ) -> Result<Vec<u8>, QuicTlsError> {
        let packet_type = match level {
            HandshakeLevel::Initial => LongPacketType::Initial,
            HandshakeLevel::Handshake => LongPacketType::Handshake,
            HandshakeLevel::OneRtt => return Err(handshake_failure("onertt_is_not_long_header")),
        };
        let space = level_protection_space(level);

        if pad_initial && matches!(packet_type, LongPacketType::Initial) {
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
                token: self.initial_token.clone(),
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
            token: if packet_type == LongPacketType::Initial {
                self.initial_token.clone()
            } else {
                Vec::new()
            },
            payload_length,
            packet_number,
            packet_number_len: HANDSHAKE_PACKET_NUMBER_LEN,
        });
        let mut header_bytes = Vec::new();
        header
            .encode(&mut header_bytes)
            .map_err(|_| handshake_failure("long_header_encode"))?;
        if pad_initial && packet_type == LongPacketType::Initial && payload_length < 64 {
            // A long Retry token can leave fewer than 64 bytes for the
            // Length-covered payload. Keep the two-byte Length width used by
            // the padding probe: minimal encoding would shrink the datagram
            // to 1199 bytes, and adding padding can jump straight to 1201 at
            // the 63/64 boundary. QUIC explicitly permits wider varints.
            let length_at = header_bytes.len() - usize::from(HANDSHAKE_PACKET_NUMBER_LEN) - 1;
            header_bytes.insert(length_at, 0x40);
        }

        self.protect_long_header_packet(space, &header_bytes, packet_number, &plaintext)
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
    /// (`is_stale_handshake_packet_error`), and a packet that fails
    /// authentication under live keys (`PACKET_UNPROTECT_CODE` and the other
    /// `is_unauthenticated_handshake_packet_error` codes) is discarded: either
    /// way the rest of the datagram is still processed (RFC 9000 section 12.2).
    /// The result is `Ok` when at least one packet authenticated, otherwise the
    /// first unauthenticated packet's error, else the first stale one.
    pub fn recv_handshake_packet(&mut self, datagram: &[u8]) -> Result<ConnectionId, QuicTlsError> {
        self.recv_handshake_packet_with_consumed(datagram)
            .map(|(cid, _)| cid)
    }

    /// Feed one received UDP datagram to the handshake, returning the authenticated
    /// peer CID and the byte count of long-header packets consumed from `datagram`.
    /// Any unconsumed trailing bytes (e.g. coalesced 1-RTT packet) can be handed off
    /// to the data plane by the caller.
    pub fn recv_handshake_packet_with_consumed(
        &mut self,
        datagram: &[u8],
    ) -> Result<(ConnectionId, usize), QuicTlsError> {
        if datagram.is_empty() {
            return Err(handshake_failure("packet_header_decode"));
        }
        let mut offset = 0usize;
        let mut accepted: Option<ConnectionId> = None;
        let mut skipped: Option<QuicTlsError> = None;
        let mut unauthenticated: Option<QuicTlsError> = None;
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
                Err(_) if offset == 0 => return Err(handshake_failure(PACKET_LENGTH_OVERRUN_CODE)),
                Err(_) => break,
            };
            match self.process_long_header_packet(&prefix, &rest[..packet_len]) {
                Ok(peer_cid) => accepted = Some(peer_cid),
                Err(err) if is_stale_handshake_packet_error(&err) => {
                    if skipped.is_none() {
                        skipped = Some(err);
                    }
                }
                // An unauthenticated or invalid packet is discarded and the rest
                // are still processed, wherever it sits in the datagram (RFC 9000
                // section 12.2). A TLS refusal, a peer close or a Handshake-space
                // protocol error stays fatal.
                Err(err) if is_unauthenticated_handshake_packet_error(&err) => {
                    if unauthenticated.is_none() {
                        unauthenticated = Some(err);
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
        match (accepted, unauthenticated.or(skipped)) {
            (Some(peer_cid), _) => Ok((peer_cid, offset)),
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

        // RFC 9000 section 7.2: a packet whose Source Connection ID is not the
        // one the peer's first accepted packet carried is discarded. The ID is
        // pinned only when a packet is accepted, so a refused forgery cannot
        // pin its own.
        if self
            .peer_connection_id
            .is_some_and(|expected| expected != peer_src_cid)
        {
            return Err(handshake_failure(PEER_CONNECTION_ID_CHANGED_CODE));
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
        // Every frame decodes before any takes effect. Anyone can derive the
        // Initial keys, so a malformed Initial is discarded; under Handshake
        // keys it is the peer's protocol error.
        let initial = matches!(space, PacketProtectionSpace::Initial);
        let mut crypto = Vec::new();
        let mut peer_close = None;
        let mut buf: &[u8] = &plaintext;
        while !buf.is_empty() {
            match QuicFrame::decode(&mut buf) {
                Ok(Some(QuicFrame::Crypto { offset, data })) => crypto.push((offset, data)),
                Ok(Some(QuicFrame::ConnectionClose { error_code, .. })) => {
                    peer_close = Some(error_code.value());
                }
                // ACK/PADDING/PING and any other handshake-coalesced frames carry
                // no TLS data; ignore them here (loss recovery handled elsewhere).
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) if initial => return Err(handshake_failure(INITIAL_FRAME_DECODE_CODE)),
                Err(_) => return Err(handshake_failure("frame_decode")),
            }
        }
        // RFC 9000 section 10.2: a peer that closed answers no further flight,
        // so the handshake ends now instead of retransmitting until its flight
        // budget runs out. A TLS refusal arrives this way (RFC 9001 section
        // 4.8), usually in an Initial packet, because the refusing server has
        // no Handshake keys yet.
        if let Some(code) = peer_close {
            self.peer_close_error_code = Some(code);
            let crypto_error = (CRYPTO_ERROR_BASE..CRYPTO_ERROR_BASE + 0x100).contains(&code);
            return Err(handshake_failure(if crypto_error {
                PEER_CRYPTO_ERROR_CLOSE_CODE
            } else {
                PEER_CLOSE_CODE
            }));
        }
        for (offset, data) in crypto {
            let ready = match self.handshake_crypto_reassembly[space_index]
                .push(offset.value(), data.as_ref())
            {
                Ok(ready) => ready,
                // A refused Initial CRYPTO frame ends the packet there. Bytes
                // its earlier frames added are bytes a forger could have sent
                // in a packet of their own. A broken reassembly invariant
                // still fails the handshake.
                Err(QuicTlsError::CryptoProviderFailure { code, .. })
                    if initial && code != "crypto_reassembly_state" =>
                {
                    return Err(handshake_failure(INITIAL_CRYPTO_REJECTED_CODE));
                }
                Err(err) => return Err(err),
            };
            for contiguous in ready {
                if let Err(err) = self.read_handshake(&contiguous) {
                    // The CONNECTION_CLOSE reporting a TLS alert goes to the
                    // packet that drew it, and the handshake ends here.
                    self.peer_connection_id.get_or_insert(peer_src_cid);
                    return Err(err);
                }
            }
        }
        if self.peer_connection_id.is_none() {
            self.peer_connection_id = Some(peer_src_cid);
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

    fn restart_initial_after_retry(
        &mut self,
        retry: RetryHeader,
        initial_segments: &[HandshakeSegment],
    ) {
        self.provider
            .install_retry_initial_keys(retry.src_cid.as_bytes(), &self.transcript);
        self.retry_source_cid = Some(retry.src_cid);
        self.initial_token = retry.token;
        // TLS has already consumed the ClientHello through write_hs. Re-send
        // the exact saved bytes without creating another TLS connection or
        // feeding them through TLS again. Only the CRYPTO stream's send cursor
        // is rewound; packet numbers are owned by the caller and never reset.
        self.crypto_send_offset[level_index(HandshakeLevel::Initial)] = 0;
        self.staged_segments = initial_segments.to_vec();
    }

    fn verify_completed_retry(
        &self,
        original_dcid: ConnectionId,
        retry_scid: Option<ConnectionId>,
    ) -> Result<(), QuicTlsError> {
        let Some(retry_scid) = retry_scid else {
            return Ok(());
        };
        let encoded = self
            .peer_transport_parameters()
            .ok_or_else(|| handshake_failure("retry_transport_parameters_missing"))?;
        let server_scid = self
            .peer_connection_id
            .ok_or_else(|| handshake_failure("retry_server_cid_missing"))?;
        validate_retry_transport_parameters(encoded, original_dcid, retry_scid, server_scid)
    }

    /// RFC 9000 section 7.3 for a client whose peer uses the standard
    /// transport-parameter encoding: a server's original_destination_connection_id
    /// must be this client's first Destination Connection ID, and its
    /// retry_source_connection_id is legal only after an accepted Retry
    /// ([`Self::verify_completed_retry`] matches it then). Both are checked when
    /// present, not required: asupersync servers through 0.5.0 send neither.
    pub(crate) fn verify_server_connection_ids(
        &self,
        original_dcid: ConnectionId,
    ) -> Result<(), QuicTlsError> {
        let encoded = self
            .peer_transport_parameters()
            .ok_or_else(|| handshake_failure("transport_parameters_missing"))?;
        let parameters = TransportParameters::decode(encoded)
            .map_err(|_| handshake_failure("transport_parameters_decode"))?;
        for parameter in &parameters.unknown {
            let code = match parameter.id {
                0x00 if parameter.value.as_slice() != original_dcid.as_bytes() => {
                    "original_destination_cid_mismatch"
                }
                0x10 if self.retry_source_cid.is_none() => "retry_source_cid_without_retry",
                _ => continue,
            };
            return Err(handshake_failure(code));
        }
        Ok(())
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

    /// The error code of the CONNECTION_CLOSE that ended this handshake, when
    /// the peer sent one in an Initial or Handshake packet.
    ///
    /// The handshake then failed with the stable code
    /// `peer_closed_crypto_error` (a code in `0x0100..=0x01ff`: the peer's TLS
    /// stack sent the alert `code - 0x0100`, RFC 9001 section 4.8) or
    /// `peer_closed` (any other code).
    #[must_use]
    pub fn peer_close_error_code(&self) -> Option<u64> {
        self.peer_close_error_code
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
    /// skipped. Returns the sent flight so the caller can retransmit it on a
    /// handshake PTO.
    async fn send_pending_flight(
        &mut self,
        cx: &Cx,
        endpoint: &mut QuicUdpEndpoint,
        peer: SocketAddr,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: &mut u64,
    ) -> Result<SentHandshakeFlight, QuicTlsError> {
        let flight = self.assemble_pending_flight(
            endpoint.config().max_packet_size,
            peer,
            dst_cid,
            src_cid,
            packet_number,
        )?;
        if !flight.packets.is_empty() {
            endpoint
                .send_batch(cx, &flight.packets)
                .await
                .map_err(|_| handshake_failure("udp_send"))?;
        }
        Ok(flight)
    }

    /// Protects the pending outbound flight without sending it: the server
    /// sends it within its anti-amplification budget.
    fn assemble_pending_flight(
        &mut self,
        max_packet_size: usize,
        peer: SocketAddr,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: &mut u64,
    ) -> Result<SentHandshakeFlight, QuicTlsError> {
        let segments = self.pump_outbound()?;
        let mut packets = Vec::new();
        let mut crypto = Vec::new();
        for segment in segments {
            if segment.level == HandshakeLevel::OneRtt {
                continue;
            }
            let chunk_size = if segment.level == HandshakeLevel::Initial {
                initial_crypto_chunk_size(
                    self.initial_token.len(),
                    dst_cid,
                    src_cid,
                    max_packet_size,
                )
                .ok_or_else(|| handshake_failure("initial_token_too_large"))?
            } else {
                // Handshake-level CRYPTO (a certificate chain) is split into
                // datagram-sized packets, as managed admission does: leave
                // room for full 20-byte CIDs, maximal CRYPTO varints, the
                // long-header length, packet number and AEAD tag. One datagram
                // per segment exceeded the endpoint's packet size for any chain
                // over ~1.3 KB, and send_batch refused it
                // (br-asupersync-5f1fcj).
                max_packet_size
                    .checked_sub(128)
                    .filter(|size| *size != 0)
                    .ok_or_else(|| handshake_failure("datagram_bound_too_small"))?
            };
            for chunk in segment.data.chunks(chunk_size) {
                let chunk = HandshakeSegment {
                    level: segment.level,
                    data: chunk.to_vec(),
                };
                let offset = self.next_crypto_offset(chunk.level);
                let data =
                    self.assemble_handshake_packet(&chunk, dst_cid, src_cid, *packet_number)?;
                *packet_number += 1;
                packets.push(OutgoingPacket {
                    dst_addr: peer,
                    data,
                    send_time: None,
                });
                crypto.push((chunk, offset));
            }
        }
        Ok(SentHandshakeFlight {
            packets,
            crypto,
            dst_cid,
            src_cid,
        })
    }

    /// Resend a flight's CRYPTO offsets and bytes in new packets. RFC 9000
    /// section 12.3 forbids reusing a packet number, and a peer that already
    /// processed the first copy suppresses an exact duplicate.
    async fn retransmit_flight(
        &mut self,
        cx: &Cx,
        endpoint: &mut QuicUdpEndpoint,
        flight: &mut SentHandshakeFlight,
        packet_number: &mut u64,
    ) -> Result<bool, QuicTlsError> {
        let Some(packets) = self.assemble_retransmit(flight, packet_number)? else {
            return Ok(false);
        };
        endpoint
            .send_batch(cx, &packets)
            .await
            .map_err(|_| handshake_failure("udp_send"))?;
        Ok(true)
    }

    /// Protects the flight's CRYPTO again in new packets without sending them;
    /// `None` when there is no flight to resend.
    fn assemble_retransmit(
        &mut self,
        flight: &mut SentHandshakeFlight,
        packet_number: &mut u64,
    ) -> Result<Option<Vec<OutgoingPacket>>, QuicTlsError> {
        let Some(peer) = flight.packets.first().map(|packet| packet.dst_addr) else {
            return Ok(None);
        };
        let mut packets = Vec::with_capacity(flight.crypto.len());
        for (segment, offset) in &flight.crypto {
            let data = self.assemble_handshake_packet_at(
                segment,
                *offset,
                flight.dst_cid,
                flight.src_cid,
                *packet_number,
            )?;
            *packet_number += 1;
            packets.push(OutgoingPacket {
                dst_addr: peer,
                data,
                send_time: None,
            });
        }
        flight.packets.clone_from(&packets);
        Ok(Some(packets))
    }

    /// Whether a Handshake-space packet from the peer has authenticated. For
    /// a server this validates the client's address (RFC 9000 section 8.1):
    /// only a client that received the server's Initial can protect one.
    pub(crate) fn has_authenticated_handshake_packet(&self) -> bool {
        !self.handshake_recv_packet_numbers[1].is_empty()
    }

    /// Protect the final Handshake ACK without transferring its ownership to
    /// an I/O future. Managed admissions retain it until the socket confirms
    /// transmission, before exposing the completed application-data route.
    pub(crate) fn assemble_final_handshake_ack(
        &mut self,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: u64,
    ) -> Result<Vec<u8>, QuicTlsError> {
        let frame = handshake_ack_frame(&self.handshake_recv_packet_numbers[1])
            .ok_or_else(|| handshake_failure("completed_handshake_without_received_packet"))?;
        let mut payload = BytesMut::new();
        frame
            .encode(&mut payload)
            .map_err(|_| handshake_failure("handshake_ack_encode"))?;
        let header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Handshake,
            version: 1,
            dst_cid,
            src_cid,
            token: Vec::new(),
            payload_length: u64::from(HANDSHAKE_PACKET_NUMBER_LEN)
                + payload.len() as u64
                + QUIC_AEAD_TAG_LEN as u64,
            packet_number,
            packet_number_len: HANDSHAKE_PACKET_NUMBER_LEN,
        });
        let mut header_bytes = Vec::new();
        header
            .encode(&mut header_bytes)
            .map_err(|_| handshake_failure("long_header_encode"))?;
        self.protect_long_header_packet(
            PacketProtectionSpace::Handshake,
            &header_bytes,
            packet_number,
            &payload,
        )
    }

    /// The CONNECTION_CLOSE packets that tell the peer this endpoint's TLS
    /// stack raised an alert.
    ///
    /// The error code is CRYPTO_ERROR, `0x0100` plus the alert (RFC 9001
    /// section 4.8). It travels in a transport close (type 0x1c, the only one
    /// RFC 9000 section 10.2.3 allows before 1-RTT) that names the CRYPTO
    /// frame. Empty when TLS raised no alert.
    ///
    /// RFC 9000 section 10.2.3 picks the spaces. A client sends in the
    /// highest space it has keys for: a client with Handshake keys has the
    /// server's Initial, so the server has them too. A server whose client may
    /// still lack Handshake keys sends in Initial and Handshake. Only a
    /// client's Initial is padded (RFC 9000 section 14.1); a close is not
    /// ack-eliciting.
    pub(crate) fn assemble_crypto_error_close(
        &mut self,
        peer: SocketAddr,
        src_cid: ConnectionId,
        packet_number: &mut u64,
    ) -> Vec<OutgoingPacket> {
        let (Some(alert), Some(dst_cid)) = (self.tls.alert(), self.peer_connection_id) else {
            return Vec::new();
        };
        let mut payload = BytesMut::new();
        let encoded = QuicFrame::ConnectionClose {
            error_code: VarInt::from_u64_unchecked(CRYPTO_ERROR_BASE + u64::from(u8::from(alert))),
            // The CRYPTO frame type: its data drew the alert.
            frame_type: Some(VarInt::from_u64_unchecked(0x06)),
            reason_phrase: Bytes::new(),
        }
        .encode(&mut payload);
        if encoded.is_err() {
            return Vec::new();
        }
        let server = self.is_server();
        let mut levels = Vec::with_capacity(2);
        if !self.handshake_keys_installed || (server && !self.has_authenticated_handshake_packet())
        {
            levels.push(HandshakeLevel::Initial);
        }
        if self.handshake_keys_installed {
            levels.push(HandshakeLevel::Handshake);
        }
        let mut packets = Vec::with_capacity(levels.len());
        for level in levels {
            // A space whose keys are gone is skipped; the other can still
            // reach the peer.
            if let Ok(data) = self.assemble_long_header_packet(
                level,
                payload.to_vec(),
                !server,
                dst_cid,
                src_cid,
                *packet_number,
            ) {
                *packet_number += 1;
                packets.push(OutgoingPacket {
                    dst_addr: peer,
                    data,
                    send_time: None,
                });
            }
        }
        packets
    }

    /// Send [`Self::assemble_crypto_error_close`]'s packets. The handshake has
    /// already failed, so a send error changes nothing and is not reported.
    pub(crate) async fn send_crypto_error_close(
        &mut self,
        cx: &Cx,
        endpoint: &mut QuicUdpEndpoint,
        peer: SocketAddr,
        src_cid: ConnectionId,
        packet_number: &mut u64,
    ) {
        let packets = self.assemble_crypto_error_close(peer, src_cid, packet_number);
        if !packets.is_empty() {
            let _ = endpoint.send_batch(cx, &packets).await;
        }
    }

    /// Acknowledge authenticated client Finished packets before handing the
    /// server's completed handshake to the application-data owner.
    async fn send_final_handshake_ack(
        &mut self,
        cx: &Cx,
        endpoint: &mut QuicUdpEndpoint,
        peer: SocketAddr,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: u64,
    ) -> Result<(), QuicTlsError> {
        let data = self.assemble_final_handshake_ack(dst_cid, src_cid, packet_number)?;
        let report = endpoint
            .send_batch(
                cx,
                &[OutgoingPacket {
                    dst_addr: peer,
                    data,
                    send_time: None,
                }],
            )
            .await
            .map_err(|_| handshake_failure("udp_send"))?;
        if report.packets_processed != 1 || report.error.is_some() {
            return Err(handshake_failure("udp_send"));
        }
        Ok(())
    }
}

fn handshake_ack_frame(received: &BTreeSet<u64>) -> Option<QuicFrame> {
    use crate::net::atp::protocol::quic_frames::AckRange;

    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for &number in received.iter().rev() {
        if let Some((_, smallest)) = ranges.last_mut() {
            if number.checked_add(1) == Some(*smallest) {
                *smallest = number;
                continue;
            }
        }
        // Bound the ACK packet even when authenticated receive history has
        // many gaps. Older ranges can be omitted; missing packets never can
        // be represented as received by bridging a gap.
        if ranges.len() == 32 {
            break;
        }
        ranges.push((number, number));
    }
    let &(largest, smallest) = ranges.first()?;
    let ack_ranges: Vec<_> = ranges
        .windows(2)
        .map(|pair| AckRange {
            gap: VarInt::from_u64_unchecked(pair[0].1 - pair[1].0 - 2),
            ack_range_length: VarInt::from_u64_unchecked(pair[1].0 - pair[1].1),
        })
        .collect();
    Some(QuicFrame::Ack {
        largest_acknowledged: VarInt::from_u64_unchecked(largest),
        ack_delay: VarInt::from_u64_unchecked(0),
        ack_range_count: VarInt::from_u64_unchecked(ack_ranges.len() as u64),
        first_ack_range: VarInt::from_u64_unchecked(largest - smallest),
        ack_ranges,
        ecn_counts: None,
    })
}

/// A sent handshake flight and the CRYPTO data behind each packet, so a
/// retransmission resends the same offsets and bytes under new packet numbers.
#[derive(Debug, Default)]
struct SentHandshakeFlight {
    packets: Vec<OutgoingPacket>,
    crypto: Vec<(HandshakeSegment, u64)>,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
}

/// Drive a client QUIC/TLS-1.3 handshake to completion over `endpoint`.
///
/// This talks to `server_addr`. The connect-side handshake derives Initial keys from
/// the client's original `dcid`, sends the ClientHello, and exchanges flights until
/// the handshake completes.
///
/// A TLS refusal on either side ends the handshake at once: this side's alert
/// is sent to the server as CONNECTION_CLOSE with CRYPTO_ERROR, and a
/// CONNECTION_CLOSE from the server fails the handshake with
/// `peer_closed_crypto_error` or `peer_closed`
/// ([`QuicHandshakeDriver::peer_close_error_code`] has the code).
///
/// 1-RTT packets that arrive before the handshake completes are dropped, as
/// in v0.5.0. [`client_handshake_over_udp_with_early_data`] returns them.
pub async fn client_handshake_over_udp(
    cx: &Cx,
    endpoint: &mut QuicUdpEndpoint,
    server_addr: SocketAddr,
    driver: &mut QuicHandshakeDriver,
    dcid: ConnectionId,
    client_scid: ConnectionId,
) -> Result<(), QuicTlsError> {
    client_handshake_over_udp_with_early_data(cx, endpoint, server_addr, driver, dcid, client_scid)
        .await
        .map(|_early_one_rtt_packets| ())
}

/// Like [`client_handshake_over_udp`], and returns the 1-RTT packets that
/// arrived before the handshake completed, so the application-data
/// connection can process them.
pub async fn client_handshake_over_udp_with_early_data(
    cx: &Cx,
    endpoint: &mut QuicUdpEndpoint,
    server_addr: SocketAddr,
    driver: &mut QuicHandshakeDriver,
    dcid: ConnectionId,
    client_scid: ConnectionId,
) -> Result<Vec<ReceivedPacket>, QuicTlsError> {
    driver.install_initial_keys(dcid.as_bytes())?;
    // Retry changes packet protection, not the TLS handshake message. Keep the
    // first flight's plaintext until the server's Initial rules out Retry.
    let initial_segments = driver.pump_outbound()?;
    driver.staged_segments.clone_from(&initial_segments);
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
    let mut early_one_rtt = Vec::new();
    let mut accepted_retry = None;
    let mut flights = 0usize;
    let mut receive_deadline = cx.now() + HANDSHAKE_PTO;
    // A packet for a key space without keys cannot be authenticated. It may
    // mean our flight was lost, or it may be spoofed, so it earns at most one
    // extra flight per PTO instead of amplifying every datagram.
    let mut stale_resend_at = None;

    while flights < HANDSHAKE_MAX_FLIGHTS {
        if driver.is_complete() {
            driver.verify_completed_retry(dcid, accepted_retry)?;
            // Retain the final flight (client Finished): if it was lost on the
            // wire the server cannot complete, and only the data plane will
            // observe the evidence (the server's retransmitted long-header
            // flight). See `QuicHandshakeDriver::final_flight`.
            driver.final_flight = last_flight.packets;
            return Ok(early_one_rtt);
        }
        let received = match crate::time::timeout_at(
            receive_deadline,
            endpoint.receive_batch(cx, HANDSHAKE_RECEIVE_BATCH_SIZE),
        )
        .await
        {
            Ok(Ok(packets)) => packets,
            Ok(Err(_)) => return Err(handshake_failure("udp_recv")),
            Err(_) => {
                flights += 1;
                if driver
                    .retransmit_flight(cx, endpoint, &mut last_flight, &mut packet_number)
                    .await?
                {
                    flight_sent_at = Instant::now();
                    receive_deadline = cx.now() + HANDSHAKE_PTO;
                    continue;
                }
                return Err(handshake_failure("client_handshake_recv_timeout"));
            }
        };
        let mut accepted_batch = false;
        // Pump after EACH packet: e.g. after the server's Initial (ServerHello)
        // the client must pump to install Handshake keys BEFORE it can unprotect
        // the server's Handshake-level flight that may arrive in the same batch.
        for packet in received {
            if packet.src_addr != server_addr {
                continue;
            }
            if packet.data.first().is_none_or(|byte| byte & 0x80 == 0) {
                // Unauthenticated short-header traffic must not fill an early
                // application queue before the server has even sent Initial,
                // and only a packet addressed to this client is kept. It
                // authenticates in the data plane only, so a full queue drops
                // it instead of ending the handshake (br-asupersync-2eqmd2
                // L2); the server's loss recovery resends a real one.
                if driver.peer_connection_id.is_some()
                    && is_short_header_for(&packet.data, client_scid)
                    && early_one_rtt.len() < MAX_EARLY_ONE_RTT_PACKETS
                {
                    early_one_rtt.push(packet);
                }
                continue;
            }
            let prefix = match ProtectedHeaderPrefix::decode(&packet.data, 0) {
                Ok(prefix) => prefix,
                Err(_) => continue,
            };
            if let ProtectedHeaderPrefix::Retry(_) = prefix {
                if accepted_retry.is_some() || driver.peer_connection_id.is_some() {
                    continue;
                }
                let Some(retry) = validated_client_retry(&packet.data, dcid, client_scid) else {
                    continue;
                };
                if initial_crypto_chunk_size(
                    retry.token.len(),
                    retry.src_cid,
                    client_scid,
                    endpoint.config().max_packet_size,
                )
                .is_none()
                {
                    continue;
                }
                let retry_scid = retry.src_cid;
                driver.restart_initial_after_retry(retry, &initial_segments);
                accepted_retry = Some(retry_scid);
                last_flight = driver
                    .send_pending_flight(
                        cx,
                        endpoint,
                        server_addr,
                        retry_scid,
                        client_scid,
                        &mut packet_number,
                    )
                    .await?;
                flight_sent_at = Instant::now();
                receive_deadline = cx.now() + HANDSHAKE_PTO;
                accepted_batch = true;
                continue;
            }
            if !matches!(prefix, ProtectedHeaderPrefix::Long(ref header)
                if header.version == 1 && header.dst_cid == client_scid)
            {
                continue;
            }
            let (peer_dcid, consumed) = match driver
                .recv_handshake_packet_with_consumed(&packet.data)
            {
                Ok(res) => {
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
                    res
                }
                Err(err) if is_stale_handshake_packet_error(&err) => {
                    let now = cx.now();
                    if stale_resend_at.is_none_or(|at| now >= at) {
                        stale_resend_at = Some(now + HANDSHAKE_PTO);
                        let _ = driver
                            .retransmit_flight(cx, endpoint, &mut last_flight, &mut packet_number)
                            .await?;
                    }
                    continue;
                }
                // A forged, corrupted or stray datagram is discarded (RFC
                // 9000 §12.2) without a retransmit: the PTO clock below still
                // bounds a handshake the real peer stopped driving.
                Err(err) if is_unauthenticated_handshake_packet_error(&err) => continue,
                Err(err) => {
                    // A TLS refusal tells the server, which would otherwise
                    // retransmit to a client that has stopped listening.
                    driver
                        .send_crypto_error_close(
                            cx,
                            endpoint,
                            server_addr,
                            client_scid,
                            &mut packet_number,
                        )
                        .await;
                    return Err(err);
                }
            };
            accepted_batch = true;
            // Only a coalesced 1-RTT packet addressed to this client is handed
            // to the data plane: padding, a malformed long-header trailer or
            // a packet for another connection is not.
            if consumed < packet.data.len()
                && packet.src_addr == server_addr
                && is_short_header_for(&packet.data[consumed..], client_scid)
                && early_one_rtt.len() < MAX_EARLY_ONE_RTT_PACKETS
            {
                early_one_rtt.push(ReceivedPacket {
                    src_addr: packet.src_addr,
                    data: packet.data[consumed..].to_vec(),
                    receive_time: packet.receive_time,
                    transmit_time: packet.transmit_time,
                });
            }
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
            if !sent.packets.is_empty() {
                last_flight = sent;
                receive_deadline = cx.now() + HANDSHAKE_PTO;
            } else if !driver.is_complete() {
                let _ = driver
                    .retransmit_flight(cx, endpoint, &mut last_flight, &mut packet_number)
                    .await?;
            }
        }
        // Stray datagrams neither spend the flight budget nor extend the PTO.
        // Otherwise a burst of malformed packets can end a healthy handshake,
        // or an endless trickle can keep it alive indefinitely.
        if accepted_batch {
            flights += 1;
        }
    }

    if driver.is_complete() {
        driver.verify_completed_retry(dcid, accepted_retry)?;
        driver.final_flight = last_flight.packets;
        Ok(early_one_rtt)
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
///
/// A TLS refusal on either side ends the handshake at once: this side's alert
/// is sent to the client as CONNECTION_CLOSE with CRYPTO_ERROR (within the
/// anti-amplification limit), and a CONNECTION_CLOSE from the client fails the
/// handshake with `peer_closed_crypto_error` or `peer_closed`.
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
/// RFC 9000 section 8.1: until the client's address is validated (a Handshake
/// packet from it authenticated), a server sends at most three times the
/// bytes it received from that address. Packets past the limit are held back
/// until more bytes arrive, so a forged Initial carrying a victim's address
/// cannot make the server reflect more than three times its size
/// (br-asupersync-5f1fcj).
#[derive(Default)]
struct AmplificationBudget {
    received: usize,
    sent: usize,
    validated: bool,
    held: Vec<OutgoingPacket>,
}

impl AmplificationBudget {
    /// Queues a flight's packets and resends nothing while an earlier flight
    /// is still held back: that flight has not reached the peer yet, so a
    /// copy would only wait behind it. Returns false when there is no flight
    /// to resend.
    fn queue_retransmit(
        &mut self,
        driver: &mut QuicHandshakeDriver,
        flight: &mut SentHandshakeFlight,
        packet_number: &mut u64,
    ) -> Result<bool, QuicTlsError> {
        if !self.held.is_empty() {
            return Ok(true);
        }
        match driver.assemble_retransmit(flight, packet_number)? {
            Some(packets) => {
                self.held.extend(packets);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Sends the held packets that fit the budget, in order.
    async fn flush(&mut self, cx: &Cx, endpoint: &mut QuicUdpEndpoint) -> Result<(), QuicTlsError> {
        let limit = if self.validated {
            usize::MAX
        } else {
            self.received.saturating_mul(3)
        };
        let mut sent = self.sent;
        let mut count = 0;
        for packet in &self.held {
            let next = sent.saturating_add(packet.data.len());
            if next > limit {
                break;
            }
            sent = next;
            count += 1;
        }
        if count == 0 {
            return Ok(());
        }
        let batch: Vec<OutgoingPacket> = self.held.drain(..count).collect();
        endpoint
            .send_batch(cx, &batch)
            .await
            .map_err(|_| handshake_failure("udp_send"))?;
        self.sent = sent;
        Ok(())
    }
}

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
    let mut last_flight = SentHandshakeFlight::default();
    let mut early_one_rtt = Vec::new();
    let mut last_early_data_resend: Option<Instant> = None;
    // Unauthenticated stale-key packets, and authenticated ones that produce
    // no new output (a replayed or forged Initial), earn at most one flight
    // per PTO.
    let mut stale_resend_at = None;
    let mut no_peer_idle_timeouts = 0usize;
    let mut budget = AmplificationBudget::default();
    let mut pto = HANDSHAKE_PTO;
    // As on the client, stray datagrams neither spend the flight budget nor
    // move the receive deadline: a burst of them used to end a healthy
    // handshake after 64 receive batches (br-asupersync-2eqmd2 L1), and with
    // a relative timeout an endless trickle would keep it alive forever.
    let mut flights = 0usize;
    let mut receive_deadline = cx.now() + pto;

    while flights < HANDSHAKE_MAX_FLIGHTS {
        if driver.is_complete() {
            break;
        }
        let received = match crate::time::timeout_at(
            receive_deadline,
            endpoint.receive_batch(cx, HANDSHAKE_RECEIVE_BATCH_SIZE),
        )
        .await
        {
            Ok(Ok(packets)) => packets,
            Ok(Err(_)) => return Err(handshake_failure("udp_recv")),
            Err(_) => {
                flights += 1;
                if peer.is_none() {
                    no_peer_idle_timeouts = no_peer_idle_timeouts.saturating_add(1);
                    if no_peer_idle_timeouts >= HANDSHAKE_SERVER_NO_PEER_IDLE_LIMIT {
                        return Err(handshake_failure("server_handshake_recv_timeout"));
                    }
                    receive_deadline = cx.now() + pto;
                    continue;
                }
                // Each PTO without progress doubles the next one.
                pto = pto.saturating_mul(2).min(HANDSHAKE_MAX_PTO);
                receive_deadline = cx.now() + pto;
                if budget.queue_retransmit(driver, &mut last_flight, &mut packet_number)? {
                    budget.flush(cx, endpoint).await?;
                    continue;
                }
                return Err(handshake_failure("server_handshake_recv_timeout"));
            }
        };
        if !received.is_empty() {
            no_peer_idle_timeouts = 0;
        }
        let mut accepted_batch = false;
        // Pump after EACH packet so newly-derived keys are installed before the
        // next packet is processed (symmetry with the client side).
        for packet in received {
            let from_peer = peer.is_some_and(|(addr, _)| addr == packet.src_addr);
            if from_peer {
                budget.received = budget.received.saturating_add(packet.data.len());
            }
            if packet.data.first().is_none_or(|byte| byte & 0x80 == 0) {
                // Only the client's packets addressed to this server are kept,
                // and a full queue drops one instead of ending the handshake
                // (br-asupersync-2eqmd2 L2): it authenticates in the data
                // plane only.
                if !from_peer || !is_short_header_for(&packet.data, server_scid) {
                    continue;
                }
                if early_one_rtt.len() < MAX_EARLY_ONE_RTT_PACKETS {
                    early_one_rtt.push(packet);
                }
                if !driver.is_complete()
                    && !last_flight.packets.is_empty()
                    && last_early_data_resend.is_none_or(|at| at.elapsed() >= HANDSHAKE_PTO)
                {
                    last_early_data_resend = Some(Instant::now());
                    let _ =
                        budget.queue_retransmit(driver, &mut last_flight, &mut packet_number)?;
                }
                budget.flush(cx, endpoint).await?;
                continue;
            }
            // Once the client is known, long-header packets from any other
            // address are not part of this handshake. Before that, an Initial
            // in a datagram under 1200 bytes is discarded (RFC 9000 section
            // 14.1): it would let a small forged packet buy a full flight.
            if peer.is_some() && !from_peer {
                continue;
            }
            if peer.is_none() && packet.data.len() < MIN_INITIAL_DATAGRAM_BYTES {
                continue;
            }
            let (peer_scid, consumed) =
                match driver.recv_handshake_packet_with_consumed(&packet.data) {
                    Ok(res) => res,
                    Err(err) if is_stale_handshake_packet_error(&err) => {
                        let now = cx.now();
                        if peer.is_some() && stale_resend_at.is_none_or(|at| now >= at) {
                            stale_resend_at = Some(now + HANDSHAKE_PTO);
                            let _ = budget.queue_retransmit(
                                driver,
                                &mut last_flight,
                                &mut packet_number,
                            )?;
                        }
                        budget.flush(cx, endpoint).await?;
                        continue;
                    }
                    // A forged, corrupted or stray datagram is discarded (RFC
                    // 9000 §12.2) without a retransmit: the PTO clock still
                    // bounds a handshake the real peer stopped driving.
                    Err(err) if is_unauthenticated_handshake_packet_error(&err) => {
                        budget.flush(cx, endpoint).await?;
                        continue;
                    }
                    Err(err) => {
                        // Only a datagram that authenticated reaches this arm, so
                        // its bytes fund the close that reports a TLS refusal,
                        // which replaces any flight still held back.
                        if !from_peer {
                            budget.received = budget.received.saturating_add(packet.data.len());
                        }
                        budget.held = driver.assemble_crypto_error_close(
                            packet.src_addr,
                            server_scid,
                            &mut packet_number,
                        );
                        let _ = budget.flush(cx, endpoint).await;
                        return Err(err);
                    }
                };
            // As on the client: only a coalesced 1-RTT packet addressed to
            // this server is kept.
            if consumed < packet.data.len()
                && is_short_header_for(&packet.data[consumed..], server_scid)
                && early_one_rtt.len() < MAX_EARLY_ONE_RTT_PACKETS
            {
                early_one_rtt.push(ReceivedPacket {
                    src_addr: packet.src_addr,
                    data: packet.data[consumed..].to_vec(),
                    receive_time: packet.receive_time,
                    transmit_time: packet.transmit_time,
                });
            }
            if peer.is_none() {
                peer = Some((packet.src_addr, peer_scid));
                budget.received = budget.received.saturating_add(packet.data.len());
            }
            if driver.has_authenticated_handshake_packet() {
                budget.validated = true;
            }
            accepted_batch = true;
            pto = HANDSHAKE_PTO;
            receive_deadline = cx.now() + pto;
            if let Some((addr, client_cid)) = peer {
                let flight = driver.assemble_pending_flight(
                    endpoint.config().max_packet_size,
                    addr,
                    client_cid,
                    server_scid,
                    &mut packet_number,
                )?;
                if !flight.packets.is_empty() {
                    budget.held.extend(flight.packets.iter().cloned());
                    last_flight = flight;
                } else if !driver.is_complete() {
                    let now = cx.now();
                    if stale_resend_at.is_none_or(|at| now >= at) {
                        stale_resend_at = Some(now + HANDSHAKE_PTO);
                        let _ = budget.queue_retransmit(
                            driver,
                            &mut last_flight,
                            &mut packet_number,
                        )?;
                    }
                }
            }
            budget.flush(cx, endpoint).await?;
        }
        if accepted_batch {
            flights += 1;
        }
    }

    if driver.is_complete() {
        let (addr, client_cid) =
            peer.ok_or_else(|| handshake_failure("server_handshake_no_peer"))?;
        driver
            .send_final_handshake_ack(cx, endpoint, addr, client_cid, server_scid, packet_number)
            .await?;
        Ok((addr, early_one_rtt))
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
    let provider = crate::tls::resolve_crypto_provider(None)
        .map_err(|_| handshake_failure("client_crypto_provider_unavailable"))?;
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
    let provider = crate::tls::resolve_crypto_provider(None)
        .map_err(|_| handshake_failure("server_crypto_provider_unavailable"))?;
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
#[path = "handshake_driver_inline_tests.rs"]
pub(crate) mod tests;
