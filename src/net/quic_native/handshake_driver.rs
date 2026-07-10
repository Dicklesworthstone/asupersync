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
    let (_, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref())
        .map_err(|_| invalid_certificate(CertificateError::BadEncoding))?;

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
        Some(usage) if usage.value.server_auth || usage.value.any => {}
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
    /// Largest inbound packet number already fed into rustls for Initial/Handshake.
    handshake_recv_largest_packet_number: [Option<u64>; 2],
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
            handshake_recv_largest_packet_number: [None, None],
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
    /// address its replies to the client's chosen CID). Assumes in-order,
    /// contiguous CRYPTO delivery (true over a reliable loopback); offset-based
    /// reassembly for lossy paths is a follow-up.
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
        if let Some(index) = handshake_packet_space_index(space)
            && self.handshake_recv_largest_packet_number[index]
                .is_some_and(|largest| long_header.packet_number <= largest)
        {
            return Ok(peer_src_cid);
        }
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

        // asupersync's frame codec decodes over a `&[u8]` (which implements the
        // crate `Buf`), advancing the slice; mirror `NativeQuicConnection::decode_frames`.
        let mut buf: &[u8] = &unprotected.plaintext;
        while !buf.is_empty() {
            match QuicFrame::decode(&mut buf).map_err(|_| handshake_failure("frame_decode"))? {
                Some(QuicFrame::Crypto { data, .. }) => self.read_handshake(data.as_ref())?,
                // ACK/PADDING/PING and any other handshake-coalesced frames carry
                // no TLS data; ignore them here (loss recovery handled elsewhere).
                Some(_) => {}
                None => break,
            }
        }
        if let Some(index) = handshake_packet_space_index(space) {
            self.handshake_recv_largest_packet_number[index] = Some(long_header.packet_number);
        }
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
        let received =
            match crate::time::timeout(cx.now(), HANDSHAKE_PTO, endpoint.receive_batch(cx, 16))
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
        if driver.path_rtt_estimate_micros.is_none() && !received.is_empty() {
            driver.path_rtt_estimate_micros =
                Some(u64::try_from(flight_sent_at.elapsed().as_micros()).unwrap_or(u64::MAX));
        }
        // Pump after EACH packet: e.g. after the server's Initial (ServerHello)
        // the client must pump to install Handshake keys BEFORE it can unprotect
        // the server's Handshake-level flight that may arrive in the same batch.
        for packet in &received {
            match driver.recv_handshake_packet(&packet.data) {
                Ok(_) => {}
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
        let received =
            match crate::time::timeout(cx.now(), HANDSHAKE_PTO, endpoint.receive_batch(cx, 16))
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
        let verifier = WebPkiOrPinnedEndEntityVerifier {
            webpki,
            pinned_end_entities,
        };
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
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
